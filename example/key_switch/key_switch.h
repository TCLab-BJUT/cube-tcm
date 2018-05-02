#ifndef KEY_SWITCH_H
#define KEY_SWITCH_H


// plugin's init func and kickstart func
int key_switch_init(void * sub_proc,void * para);
int key_switch_start(void * sub_proc,void * para);
struct timeval time_val={0,50*1000};

#endif
