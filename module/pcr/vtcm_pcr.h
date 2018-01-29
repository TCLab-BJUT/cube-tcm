#ifndef VTCM_PCR_H
#define VTCM_PCR_H

int vtcm_pcr_init(void * sub_proc,void * para);
int vtcm_pcr_start(void * sub_proc,void * para);

const int tcm_pcr_size=20;
const int tcm_pcr_index=24;
static int vtcm_scene_num=3;


struct vtcm_pcr_scene
{
	int index_num;
	int pcr_size;
	BYTE  * pcr;	
}__attribute__((packed));

#endif
