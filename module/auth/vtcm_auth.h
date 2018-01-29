#ifndef VTCM_AUTH_H
#define VTCM_AUTH_H

int vtcm_auth_init(void * sub_proc,void * para);
int vtcm_auth_start(void * sub_proc,void * para);

const int tcm_key_size=20;
const int tcm_key_index=24;
static int vtcm_scene_num=3;


struct vtcm_auth_scene
{
	int index_num;
	int key_size;
	BYTE  * key;	
}__attribute__((packed));

#endif
