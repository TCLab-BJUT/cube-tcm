#ifndef VTCM_UTILS_H
#define VTCM_UTILS_H

int vtcm_utils_init(void * sub_proc,void * para);
int vtcm_utils_start(void * sub_proc,void * para);

struct vtcm_utils_init_para
{
     char * channel_name;
}__attribute__((packed));

#endif
