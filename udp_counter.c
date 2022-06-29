#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <stdbool.h>
#include <mqueue.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>

#ifdef DEBUG
#include <time.h>
#endif

#include "pac_stat.h"

#define COUNTER_QUEUE_NAME_IN  "/udp_counter_queue"
#define COUNTER_QUEUE_NAME_OUT  "/stat_print"

#define PAC_LIMIT 10000

#define QUEUE_PERMS ((int)(0666))
#define QUEUE_MAXMSG 126
#define QUEUE_MSGSIZE 2048
#define QUEUE_ATTR_INITIALIZER ((struct mq_attr){0, QUEUE_MAXMSG, QUEUE_MSGSIZE, 0, {0}})

#define MESSAGE_PRIO 1
#define CLOSE_QUEUE_PRIO 2

enum ipc_method {
    MQ_REQ,
    UBUS_REQ
};

enum stat_thread {
    FIRST_STAT_THREAD,
    SECOND_STAT_THREAD
};

int sockfd;
mqd_t mq_in, mq_out;
int th_pipe_fd[2];
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
struct pac_stat all_pac_stat;
#ifdef PAC_LIMIT
clock_t start_time = 0, finish_time = 0;
#endif
//флаги выхода из циклов в потоках
bool th_mq_running = true;
bool th_sniffer_running = true;

//params
char device_name[IFNAMSIZ];
int stat_req_mode = MQ_REQ;
int stat_collect_thread = FIRST_STAT_THREAD;
int port_src = -1;
int port_dst = -1;
struct in_addr *ip_src = NULL;
struct in_addr *ip_dst = NULL;

struct option opts[] = {
    {"interface", required_argument, 0, 'd'},
    {"ubus", no_argument, 0, 'u'},
    {"thread-stat", no_argument, 0, 't'},
    {"ip-src", required_argument, 0, 'i'},
    {"ip-dst", required_argument, 0, 'I'},
    {"port-src", required_argument, 0, 'p'},
    {"port-dst", required_argument, 0, 'P'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0},
};

void exit_all_threads()
{
    th_mq_running = false;
    th_sniffer_running = false;
}

void signal_handler(int signum)
{
    const char close_str[] = "Close";
#ifdef DEBUG
    fprintf(stderr, "Stopping threads...\n");
#endif

    if (mq_send(mq_out, close_str, sizeof(close_str), CLOSE_QUEUE_PRIO) == -1)
        perror("mq_send");

#ifdef PAC_LIMIT
    finish_time = clock();
    fprintf(stderr, "Подсчет производился %f процессорного времени\n", (double)(finish_time - start_time));
#endif
    close(STDOUT_FILENO);
    close(STDIN_FILENO);
    close(STDERR_FILENO);
    exit_all_threads();
}

static void usage(void)
{
    printf(
        "Использование: udp-counter [ПАРАМЕТР]\n"
        "Мультипоточная утилита, для обработки и фильтрации пакетов сетевого устройства.\n"
        "Статистика по пакетам выводится командой stat-print.\n"
        "\n"
        "Аргументы:\n"
        "\t-d, --interface=ИНТЕРФЕЙС\tслушать только прописанное сетевое устройство\n"
        "\t-u, --ubus               \tзапросить статистику через ubus. По умолчанию POSIX Message Queues\n"
        "\t-t, --thread_stat        \tзапустить счетчик в другом потоке\n"
        "\t-i, --ip-src=АДРЕС       \tфильтровать пакеты по IP источника. Вводится в формате a.b.c.d\n"
        "\t-I, --ip-dst=АДРЕС       \tфильтровать пакеты по IP назначения. Вводится в формате a.b.c.d\n"
        "\t-p, --port-src=ПОРТ      \tфильтровать по порту источника. \n"
        "\t-P, --port-dst=ПОРТ      \tфильтровать по порту назначения. \n"
        "\t-h, --help               \tпоказать справку\n"
    );
}

static int parse_opts(int argc, char **argv)
{
    int opchar = 0;
    int port_num;
    while (-1 != (opchar = getopt_long(argc, argv,
        "ud:ti:I:p:P:h", opts, NULL))) {
        switch (opchar) {
            case 'u':
                stat_req_mode = UBUS_REQ;
                break;
            case 'd':
                strcpy(device_name, optarg);
                break;
            case 't':
                stat_collect_thread = SECOND_STAT_THREAD;
                break;
            case 'i':
                ip_src = (struct in_addr *)malloc(sizeof(struct in_addr));
                if (inet_aton(optarg, ip_src) == 0)
                    return -1;
                break;
            case 'I':
                ip_dst = (struct in_addr *)malloc(sizeof(struct in_addr));
                if (inet_aton(optarg, ip_dst) == 0)
                    return -1;
                break;
            case 'p':
                port_num = atoi(optarg);
                if ((port_num <= 0) && (port_num > 65535))
                    return -1;
                port_src = htons(port_num);
                break;
            case 'P':
                port_num = atoi(optarg);
                if ((port_num <= 0) && (port_num > 65535))
                    return -1;
                port_dst = htons(port_num);
                break;
            case 'h':
                usage();
                exit(1);
            default:
                usage();
                return -1;
        }
    }

    return 0;
}

void *first_thread_func()
{
    char buffer[BUFSIZ];
    struct iphdr *ip;
    struct udphdr *udp;

    while (th_sniffer_running) {
        int n = recvfrom(sockfd, buffer, BUFSIZ, 0, NULL, NULL);
        if (n == -1) {
            if (errno != EAGAIN) {
                perror("recvfrom");
                goto err;
            }

            continue;
        }

        ip = (struct iphdr *) (buffer + sizeof(struct ethhdr));
        udp = (struct udphdr *) (buffer + sizeof(struct ethhdr) + ip->ihl * 4);

        if (ip->version == 4 && ip->protocol == IPPROTO_UDP) {
            if (((NULL == ip_src) || (ip->saddr == ip_src->s_addr)) &&
                ((NULL == ip_dst) || (ip->daddr == ip_dst->s_addr)) &&
                ((port_src < 0) || (port_src == udp->source)) &&
                ((port_dst < 0) || (port_dst == udp->dest))) {

#ifdef DEBUG
                char source_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip->saddr,
                          source_ip_str, sizeof(source_ip_str));
                printf("source ip: %s %x, ", source_ip_str, ip->saddr);

                char dest_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip->daddr,
                          dest_ip_str, sizeof(dest_ip_str));
                printf("destination: %s %x\n", dest_ip_str, ip->daddr);

                printf("source port: %d, dest port: %d\n\n",
                       ntohs(udp->source), ntohs(udp->dest));
#endif
                switch (stat_collect_thread) {
                    case FIRST_STAT_THREAD: ;
                        struct pac new_pac;
                        new_pac.pac_mem_num = n;
                        pthread_mutex_lock(&lock);
                        sum_pac_stat(&all_pac_stat, &new_pac);
#ifdef DEBUG
                        if (all_pac_stat.pac_counter == PAC_LIMIT) {
                            finish_time = clock();
                            kill(getpid(), SIGINT);
                        }
#endif
                        pthread_mutex_unlock(&lock);
                        break;
                    case SECOND_STAT_THREAD: ;
                        struct pac pac_data;
                        int bytes;
                        pac_data.pac_mem_num = n;
                        bytes = write(th_pipe_fd[1],
                                      &pac_data,
                                      sizeof(pac_data));
                        if (bytes == -1 && errno != EAGAIN) {
                            perror("write");
                            goto err;
                        }
                        break;
                }
            }
        }
    }

err:
#ifdef DEBUG
    printf("first_thread_func: Cleanup...\n");
#endif

    return NULL;
}

void *second_thread_func()
{
    struct mq_attr attr = QUEUE_ATTR_INITIALIZER;
    char buffer[QUEUE_MSGSIZE + 1];
    unsigned int prio = 0;

    mq_in = mq_open(COUNTER_QUEUE_NAME_IN,
                          O_CREAT | O_RDONLY | O_NONBLOCK,
                          QUEUE_PERMS,
                          &attr);
    if (mq_in < 0) {
        fprintf(stderr,
                "second_thread_func: Error, cannot open the input queue: %s.\n",
                strerror(errno));
        return NULL;
    }

    mq_out = mq_open(COUNTER_QUEUE_NAME_OUT,
                           O_CREAT | O_WRONLY | O_NONBLOCK,
                           QUEUE_PERMS,
                           &attr);
    if (mq_out < 0) {
        fprintf(stderr,
                "second_thread_func: Error, cannot open the output queue: %s.\n",
                strerror(errno));
        goto err1;
    }

#ifdef DEBUG
    printf("second_thread_func: Queues opened,"
           "input queue descriptor: %d,"
           "output queue descriptor: %d.\n", mq_in, mq_out);
#endif

    while (th_mq_running) {
        ssize_t bytes_read = mq_receive(mq_in, buffer, QUEUE_MSGSIZE, &prio);

        if (errno != EAGAIN) {
            perror ("mq_receive()");
            goto err;
        }
#ifdef DEBUG
        if (bytes_read > 0)
            printf("second_thread_func: Received message: \"%s\", %ld bytes\n",
                   buffer, bytes_read);
#endif
        switch (stat_collect_thread) {
            case FIRST_STAT_THREAD:
                if (bytes_read > 0) {
                    pthread_mutex_lock(&lock);
                    if (mq_send(mq_out,
                                (const char *)&all_pac_stat,
                                sizeof(all_pac_stat),
                                MESSAGE_PRIO) == -1) {
                        perror("mq_send");
                        goto err;
                    }
                    pthread_mutex_unlock(&lock);
                }
                break;
            case SECOND_STAT_THREAD: ;
                struct pac pac_data;
                if (bytes_read > 0) {
                    if (mq_send(mq_out,
                                (const char *)&all_pac_stat,
                                sizeof(all_pac_stat),
                                MESSAGE_PRIO) == -1) {
                        perror("mq_send");
                        goto err;
                    }
                }

                int bytes = read(th_pipe_fd[0], &pac_data, sizeof(pac_data));
                if (bytes == -1 && errno != EAGAIN) {
                    perror("read");
                    goto err;
                }

                if (bytes > 0) {
                    sum_pac_stat(&all_pac_stat, &pac_data);
#ifdef DEBUG
                    if (all_pac_stat.pac_counter == PAC_LIMIT) {
                        finish_time = clock();
                        kill(getpid(), SIGINT);
                    }
#endif
//                    printf("Количество пакетов: %lu, суммарное количество байт: %lu\n", all_pac_stat.pac_counter, all_pac_stat.pac_bytes_counter);
                }
                break;
        }
    }

err:
#ifdef DEBUG
    printf("second_thread_func: Cleanup...\n");
#endif
    exit_all_threads();
    mq_close(mq_out);
    mq_unlink(COUNTER_QUEUE_NAME_OUT);

err1:
    mq_close(mq_in);
    mq_unlink(COUNTER_QUEUE_NAME_IN);

    return NULL;
}

int threads_init()
{
    pthread_t first_thread;
    pthread_t second_thread;

    if (pthread_create(&first_thread, 0, &first_thread_func, 0) != 0)
        return -1;

    if (pthread_create(&second_thread, 0, &second_thread_func, 0) != 0)
        return -1;

    if (pthread_join(first_thread, 0) != 0)
        return -1;

    if (pthread_join(second_thread, 0) != 0)
        return -1;

    return 0;
}

void clean_all()
{
    free(ip_src);
    free(ip_dst);
}

int create_device_socket(char *name)
{
    struct sockaddr_ll sll = {0};
    struct ifreq ifr;
    struct packet_mreq mreq = {0};
    int ret = 0;
    int fd = -1;

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket");
        return -1;
    }

    int flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);

    strncpy((char *)ifr.ifr_name, name, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        perror("Error getting Interface index");
        ret = -1;
        goto close_sock;
    }

    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(fd, (const struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("Error binding raw socket to interface");
        ret = -1;
        goto close_sock;
    }

    mreq.mr_ifindex = ifr.ifr_ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
        perror("setsockopt");
        ret = -1;
        goto close_sock;
    }

    goto ret;

close_sock:
    close(fd);

ret:
    if (ret == 0)
        return fd;
    else
        return ret;
}

int main(int argc, char *argv[])
{
    struct sigaction sa = {0};
    sa.sa_handler = signal_handler;

    sigaction(SIGINT, &sa, NULL);

    all_pac_stat.pac_counter = 0;
    all_pac_stat.pac_bytes_counter = 0;

    if (parse_opts(argc, argv) < 0) {
        fprintf(stderr, "%s\n", "Invalid argument");
        goto ret;
    }

    if ((sockfd = create_device_socket(device_name)) == -1) {
        goto ret;
    }

    if (pipe(th_pipe_fd) == -1) {
        perror("pipe");
        goto close_pipes;
    }

    if (fcntl(th_pipe_fd[0], F_SETFL, O_NONBLOCK) < 0) {
        perror("pipe");
        goto close_pipes;
    }

#ifdef DEBUG
    start_time = clock();
#endif
    if (threads_init() < 0) {
        perror("threads_init");
        goto close_pipes;
    }

#ifdef DEBUG
    printf("main: Cleanup...\n");
#endif
    clean_all();
close_pipes:
    close(th_pipe_fd[0]);
    close(th_pipe_fd[1]);

    close(sockfd);
    pthread_mutex_destroy(&lock);

ret:
    return 0;
}
