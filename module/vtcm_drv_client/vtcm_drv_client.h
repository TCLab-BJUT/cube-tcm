#ifndef VTCM_DRV_CLIENT_H
#define VTCM_DRV_CLIENT_H

int vtcm_drv_client_init(void * sub_proc,void * para);
int vtcm_drv_client_start(void * sub_proc,void * para);

struct drv_init_para
{
	char * dev_name;
	char * channel_name;
}__attribute__((packed));

#endif
