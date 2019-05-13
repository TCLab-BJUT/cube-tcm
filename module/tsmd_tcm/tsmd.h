#ifndef TCM_TSMD_H
#define TCM_TSMD_H

int tsmd_init(void * sub_proc,void * para);
int tsmd_start(void * sub_proc,void * para);

struct tsmd_init_para
{
     char * channel_name;
}__attribute__((packed));


struct context_init
{
	int count;
	UINT32 handle;
}__attribute__((packed));
#endif
