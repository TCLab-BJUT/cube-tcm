#ifndef VTCM_STATE_H
#define VTCM_STATE_H

int vtcm_state_init(void * sub_proc,void * para);
int vtcm_state_start(void * sub_proc,void * para);

const int tcm_state_size=20;
const int tcm_state_index=24;
static int vtcm_scene_num=3;


struct vtcm_state_scene
{
    int index_num;
    int state_size;
    BYTE  * state;
}__attribute__((packed));

#endif
