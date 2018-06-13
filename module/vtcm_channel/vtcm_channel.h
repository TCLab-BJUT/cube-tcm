#ifndef VTCM_CHANNEL_H
#define VTCM_CHANNEL_H
int vtcm_channel_init(void * sub_proc,void * para);
int vtcm_channel_start(void * sub_proc,void * para);

struct vtcm_channel_init_para
{
     char * channel_name;
}__attribute__((packed));
#endif
