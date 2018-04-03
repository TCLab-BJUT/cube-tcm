#ifndef VTCM_MANAGER_H
#define VTCM_MANAGER_H

int vtcm_manager_init(void * sub_proc,void * para);
int vtcm_manager_start(void * sub_proc,void * para);


struct vtcm_msg_buffer
{
	struct vtcm_instance vtcm_instance;
	void * in_msg;
	void * out_msg;
};


struct curr_vtcm_list
{
	int vtcm_copy_num;
	struct vtcm_copy * vtcm_copy; 
};

struct manager_vtcm_buffer
{
	int instance_num;
	Record_List msg_buffer;
	struct curr_vtcm_list vtcm_list;
};


int vtcm_add_msg(void * sub_proc,void * msg,BYTE * uuid);
int vtcm_select(void * sub_proc);
int vtcm_msg_dispatch();

#endif
