#ifndef VTCM_KEY_H
#define VTCM_KEY_H

int vtcm_key_init(void * sub_proc,void * para);
int vtcm_key_start(void * sub_proc,void * para);

const int tcm_key_size=20;
const int tcm_key_index=24;
static int vtcm_scene_num=3;

struct vtcm_key_scene
{
	int index_num;
	int key_size;
	BYTE  * key;	
}__attribute__((packed));

#endif
