#ifndef VTCM_TDDL_CLIENT_H
#define VTCM_TDDL_CLIENT_H

int vtcm_tddl_client_init(void * sub_proc,void * para);
int vtcm_tddl_client_start(void * sub_proc,void * para);

struct drv_init_para
{
	char * dev_name;
	char * channel_name;
	char * channel_type;
	char * trans_type;    
}__attribute__((packed));

#endif
