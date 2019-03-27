#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <stdarg.h> 

#include "data_type.h"
#include "alloc.h"
#include "json.h"
#include "memfunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "basefunc.h"
#include "memdb.h"
#include "message.h"
#include "connector.h"
//#include "sys_func.h"
#include "ex_module.h"

#include "main_proc_func.h"
/*
void * main_read_func(char * libname,char * sym)
{
    void * handle;	
    int (*func)(void *,void *);
    char * error;
    handle=dlopen(libname,RTLD_NOW);
     if(handle == NULL)		
     {
    	print_cubeerr("Failed to open library %s error:%s\n", libname, dlerror());
    	return NULL;
     }
     func=dlsym(handle,sym);
     if(func == NULL)		
     {
    	print_cubeerr("Failed to open func %s error:%s\n", sym, dlerror());
    	return NULL;
     }
     return func;
}     	
*/
int read_sys_cfg(void ** lib_para_struct,void * root_node,char * plugin_dir)
{
    struct lib_para_struct * lib_para;
    int json_offset;	
    int ret;
    char filename[DIGEST_SIZE*8];
     void * struct_template=memdb_get_template(DTYPE_EXMODULE,SUBTYPE_LIB_PARA);
	
    lib_para=Salloc0(sizeof(*lib_para));
    if(lib_para==NULL)
	return -ENOMEM;

    ret=json_2_struct(root_node,lib_para,struct_template);
    if(ret<0)
    {
	print_cubeerr("sys config file format error!\n");
	return -EINVAL;
     }
 
    char * define_path=getenv("CUBE_DEFINE_PATH");	

    void * define_node=json_find_elem("define_file",root_node);	    
    if(define_node!=NULL)
    {
	if(json_get_type(define_node)==JSON_ELEM_STRING)
	{
		ret=read_json_file(json_get_valuestr(define_node));
		if(ret<0)
		{
			Strcpy(filename,define_path);
			Strcat(filename,"/");
			Strcat(filename,json_get_valuestr(define_node));					
			ret=read_json_file(filename);
			if(ret<0)
			{
				print_cubeerr("read define file  %s failed!\n",json_get_valuestr(define_node));
			}
		}
		if(ret>=0)
			print_cubeaudit("read %d elem from file %s!\n",ret,json_get_valuestr(define_node));
	}
	else if(json_get_type(define_node)==JSON_ELEM_ARRAY)
	{
		void * define_file=json_get_first_child(define_node);
		while(define_file!=NULL)
		{
			ret=read_json_file(json_get_valuestr(define_file));
			if(ret<0)
			{
				Strcpy(filename,define_path);
				Strcat(filename,"/");
				Strcat(filename,json_get_valuestr(define_file));					
				ret=read_json_file(filename);
				if(ret<0)
				{
					print_cubeerr("read define file  %s failed!\n",json_get_valuestr(define_file));
				}
			}
			if(ret>=0)
				print_cubeaudit("read %d elem from file %s!\n",ret,json_get_valuestr(define_file));
			define_file=json_get_next_child(define_node);
		}
	}	
    }

    *lib_para_struct=lib_para;

    return ret;
}


int read_main_cfg(void * lib_para_struct,void * root_node)
{
    struct lib_para_struct * lib_para=lib_para_struct;
    int ret;
    void * temp_node;
    int (*init) (void *,void *);
    temp_node=json_find_elem("proc_name",root_node);
    if(temp_node==NULL)
	return -EINVAL;
    
    void * init_para;
    	
    if(lib_para==NULL)
	return 0;	
    ret=0;

    void * record_list=json_find_elem("record_file",root_node);
    if(record_list!=NULL)
    {
	if(json_get_type(record_list)==JSON_ELEM_STRING)
	{
		ret=read_record_file(json_get_valuestr(record_list));
		if(ret>0)
			print_cubeaudit("read %d elem from file %s!\n",ret,json_get_valuestr(record_list));
	}
	else if(json_get_type(record_list)==JSON_ELEM_ARRAY)
	{
		void * record_file=json_get_first_child(record_list);
		while(record_file!=NULL)
		{
			ret=read_record_file(json_get_valuestr(record_file));
			if(ret>0)
				print_cubeaudit("read %d elem from file %s!\n",ret,json_get_valuestr(record_file));
			record_file=json_get_next_child(record_list);
		}
	}	
    }		
    return ret;
}
