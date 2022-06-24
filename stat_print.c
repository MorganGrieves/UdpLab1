#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "pac_stat.h"

#define MQMESG "Results, please!"

#define PRINT_QUEUE_NAME_IN  "/stat_print"
#define PRINT_QUEUE_NAME_OUT  "/udp_counter_queue"
#define QUEUE_MSGSIZE 2048

enum ipc_method {
    MQ_REQ,
    UBUS_REQ
};

bool mq_running = true;

//params
int stat_req_mode = MQ_REQ;

static struct option opts[] = {
    {"ubus", no_argument, 0, 'u'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0},
};

void signal_handler(int signum)
{
#ifdef DEBUG
    fprintf(stderr, "Получен сигнал: %d.\n", signum);
#endif
    mq_running = false;
}

static void usage(void)
{
    printf(
        "Использование: stat-print [ПАРАМЕТР]\n"
        "Утилита для вывода общей суммы пакетов и памяти в байтах\n"
        "\n"
        "Аргументы:\n"
        "\t-u, --ubus \tзапросить статистику через ubus. По умолчанию POSIX Message Queues\n"
        "\t-h, --help \tзапросить справку\n"
    );
}

static int parse_opts(int argc, char **argv)
{
    int opchar = 0;
    while (-1 != (opchar = getopt_long(argc, argv, "uh", opts, NULL))) {
        switch (opchar) {
            case 'u':
                stat_req_mode = UBUS_REQ;
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

int main(int argc, char *argv[])
{
    struct sigaction sa;
    mqd_t mq_out;
    mqd_t mq_in;

    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);

    if (parse_opts(argc, argv) < 0) {
        fprintf(stderr, "%s\n", "Invalid argument");
        return 0;
    }

    do {
        mq_in = mq_open(PRINT_QUEUE_NAME_IN, O_RDONLY);
        if (mq_in < 0) {
            printf("The input queue is not created yet. Waiting...\n");
            sleep(1);
        }
    } while (mq_in == -1);

    do {
        mq_out = mq_open(PRINT_QUEUE_NAME_OUT, O_WRONLY);
        if (mq_out < 0) {
            printf("The output queue is not created yet. Waiting...\n");
            sleep(1);
        }
    } while (mq_out == -1);

    char buffer[2048];
    unsigned int prio = 0;
    while (mq_running) {
        printf("Чтобы получить результаты, введите любое сообщение:\n");
        fgets(buffer, sizeof(buffer), stdin);
        if (mq_send(mq_out,
                    (const char *)&buffer,
                    sizeof(buffer),
                    prio) == -1) {
            perror("mq_send");
            goto err;
        }
        if (mq_receive(mq_in,
                       buffer,
                       sizeof(buffer),
                       0) != -1) {
            struct pac_stat *msg = (struct pac_stat *)buffer;
            printf("Количество пакетов: %lu, суммарное количество байт: %lu\n", msg->pac_counter, msg->pac_bytes_counter);
        } else {
            perror("mq_receive");
            goto err;
        }
    }

err:
#ifdef DEBUG
    printf("stat_print: Cleanup...\n");
#endif
    mq_close (mq_in);
    mq_close (mq_out);

    return 0;
}
