#ifndef PAC_STAT_H
#define PAC_STAT_H
struct pac_stat {
    unsigned long pac_bytes_counter;
    unsigned long pac_counter;
};

struct pac {
    int pac_mem_num;
};

void sum_pac_stat(struct pac_stat *, struct pac *);
#endif
