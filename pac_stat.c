#include "pac_stat.h"

void sum_pac_stat(struct pac_stat *pi, struct pac *p)
{
    pi->pac_counter++;
    pi->pac_bytes_counter += p->pac_mem_num;
}
