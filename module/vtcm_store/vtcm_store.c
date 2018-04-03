#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "data_type.h"
#include "errno.h"
#include "alloc.h"
#include "string.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "ex_module.h"
#include "sys_func.h"

#include "file_struct.h"
#include "tesi_key.h"
#include "tesi_aik_struct.h"
#include "vtcm_store.h"

#include "app_struct.h"
#include "tcm_global.h"
#include "tcm_error.h"
#include "vtcm_struct.h"
#include "tcm_authlib.h"
#include "tcm_iolib.h"

char*  host_permanent_file="lib/permanent.";
/*
int vtcm_instance_export(void * instance, BYTE * buf,int storetype);
int vtcm_instance_import(void * instance, BYTE * buf,int storetype);
int vtcm_export_permanent_flags(void * instance,BYTE * buf,int storetype);
int vtcm_export_stclear_flags(void * instance,BYTE * buf, int storetype);

int vtcm_export_stany_flags(void * instance,BYTE *buf, int storetype);

int vtcm_export_permanent_data(void * instance,BYTE * buf, int storetype);

int vtcm_export_stclear_data(instance,buf+offset);
int vtcm_export_stany_data(instance,buf+offset);
int vtcm_export_key_handle(instance,buf+offset);
int vtcm_export_transport_handle(instance,buf+offset);
int vtcm_import_permanent_flags(instance,buf+offset);
int vtcm_import_stclear_flags(instance,buf+offset);
int vtcm_import_stany_flags(instance,buf+offset);
int vtcm_import_permanentstany_flags(instance,buf+offset);
int vtcm_import_stclear_data(instance,buf+offset);
int vtcm_import_stany_data(instance,buf+offset);
int vtcm_import_key_handle(instance,buf+offset);
int vtcm_import_transport_handle(instance,buf+offset);
int vtcm_export_nv_data(void * instance, BYTE * buf, int storetype);
int vtcm_import_nv_data(void * instance, BYTE * buf, int storetype);
*/
static BYTE buffer[DIGEST_SIZE*128];

int vtcm_store_init(void * sub_proc ,void * para)
{
    int i;
    int fd;
    int ret;
    char filename[DIGEST_SIZE*4];

    printf("vtcm_store_init :\n") ;

    tcm_state_t * tcm_instances = proc_share_data_getpointer();


    for(i = 0 ;i < 3 ; i++)//分配存储空间
    {
        tcm_instances[i].tcm_number = i;
//      tcm_instances[i].key = tcm_instances[i].tcm_stclear_data.PCRS ;

	Strcpy(filename,host_permanent_file);
	ret=Strlen(filename);
	filename[ret]='0';
	filename[ret+1]='0'+i;
	filename[ret+2]=0;
	
    	fd=open(filename,O_RDONLY);
    	if(fd<0)
            	return 0;
    	ret=read(fd,buffer,DIGEST_SIZE*128);
    	if(ret==DIGEST_SIZE*128)
        	return -EINVAL;
    	close(fd);

    	ret=vtcm_instance_import(&tcm_instances[i],buffer,VTCM_IO_STATIC);
    	if(ret<0)
        	return ret;
    // prepare the slot sock

    }
    ex_module_setpointer(sub_proc,&tcm_instances[0]);
    return 0;
}

int vtcm_store_start(void * sub_proc,void * para)
{
    int ret;
    int retval;
    void * recv_msg;
    void * context;
    int i;
    int type;
    int subtype;
    void * sock;
    BYTE uuid[DIGEST_SIZE];
    char filename[DIGEST_SIZE*4];
    int vtcm_no=0;
    int fd;

    printf("vtcm_store module start!\n");
    
    tcm_state_t * tcm_instances = proc_share_data_getpointer();

    while(1)
    {
        usleep(time_val.tv_usec);
        ret=ex_module_recvmsg(sub_proc,&recv_msg);
        if(ret<0)
            continue;
        if(recv_msg==NULL)
            continue;

        type=message_get_type(recv_msg) ;
        subtype=message_get_subtype(recv_msg) ;

 	// set vtcm instance
     	vtcm_no = vtcm_setscene(sub_proc,recv_msg);
     	if(vtcm_no<0)
     	{
 		printf("Non_exist vtcm copy!\n");
     	}
	Strcpy(filename,host_permanent_file);
	ret=Strlen(filename);
	filename[ret]='0';
	filename[ret+1]='0'+vtcm_no;
	filename[ret+2]=0;
	
    	fd=open(filename,O_RDONLY);
        if(type==DTYPE_VTCM_OUT)
        {
            // host's change-permanent command
            ret=vtcm_instance_export(&tcm_instances[vtcm_no],buffer,VTCM_IO_STATIC);
            if(ret<0)
                return ret;
            int fd=open(filename,O_WRONLY|O_CREAT|O_TRUNC,0666);
            if(fd<0)
                return -EIO;
            write(fd,buffer,ret);
            close(fd);
        }
    }
    return 0;
}
