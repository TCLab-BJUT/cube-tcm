#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <dlfcn.h>

#include <sys/ipc.h>
#include <sys/shm.h>


#include "data_type.h"
#include "alloc.h"
#include "memfunc.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "channel.h"
#include "memdb.h"
#include "message.h"
#include "connector.h"
#include "ex_module.h"

typedef struct proc_init_parameter
{
	char * name;
	int type;
	int (* init) (void *,void *);
	int (* start) (void *,void *);
}PROC_INIT;

static char main_config_file[DIGEST_SIZE*2]="./main_config.cfg";
static char sys_config_file[DIGEST_SIZE*2]="./sys_config.cfg";

int lib_read(int fd,int type,int subtype,void ** record);
int lib_write(int fd, int type,int subtype, void * record);

int lib_gettype(char * libname, int * typeno,int * subtypeno)
{
		char buffer[DIGEST_SIZE*3];
		char typename[DIGEST_SIZE];
		char subtypename[DIGEST_SIZE];
		int ret;
		int offset=0;

		Strncpy(buffer,libname,DIGEST_SIZE*3);
		ret=Getfiledfromstr(typename,buffer+offset,'-',DIGEST_SIZE*2);
		if(ret<=0)
			return -EINVAL;
		*typeno=memdb_get_typeno(typename);
		if(*typeno<=0)
			return -EINVAL;
		offset+=ret;
		offset++;
		ret=Getfiledfromstr(subtypename,buffer+offset,'.',DIGEST_SIZE*2);
		*subtypeno=memdb_get_subtypeno(*typeno,subtypename);
		if(*subtypeno<0)
			return -EINVAL;
		return 0;
};

int main(int argc,char **argv)
{

    int ret;
    int retval;
    int i,j;
    int argv_offset;	
    char namebuffer[DIGEST_SIZE*4];
    void * main_proc; // point to the main proc's subject struct
    char * sys_plugin;		
    char * app_plugin;		
    char * base_define;

    char json_buffer[4096];
    char print_buffer[4096];
    int readlen;
    int json_offset;
    void * memdb_template ;
    BYTE uuid[DIGEST_SIZE];
    char local_uuid[DIGEST_SIZE*2];

    FILE * fp;
    char audit_text[4096];
    char buffer[4096];
    void * root_node;
    void * temp_node;
    PROC_INIT plugin_proc; 
    int fd;	

    char * baseconfig[] =
    {
	"namelist.json",
	"dispatchnamelist.json",
	"typelist.json",
	"subtypelist.json",
	"memdb.json",
	"msghead.json",
	"msgrecord.json",
	"expandrecord.json",
	"base_msg.json",
	"dispatchrecord.json",
	"exmoduledefine.json",
	 NULL
    };

    struct start_para start_para;

    start_para.argc=argc;
    start_para.argv=argv;	

    sys_plugin=getenv("CUBE_SYS_PLUGIN");
//    if(sys_plugin==NULL)
//	return -EINVAL;		
//    app_plugin=getenv("CUBE_APP_PLUGIN");
    // process the command argument

   int ifmerge=0;

    if(argc>=2)
    {
	argv_offset=1;
	if(strcmp(argv[1],"merge")==0)
	{
		ifmerge=1;
		if(argc<=3)
		{
			printf("error lib_tool merge format! should be %s merge destlibname [srclibname1|srclibdir1]"
				"[srclibname2|srclibdir2] ...\n",argv[0]);
		}
	}
	else if(strcmp(argv[1],"show"))
	{
		if(argc<2)
		printf("error format! should be %s show libname ...\n",argv[0]);
		return -EINVAL;
	}
    }

      
//	alloc_init(alloc_buffer);
	struct_deal_init();
	memdb_init();

    	base_define=getenv("CUBE_BASE_DEFINE");
	for(i=0;baseconfig[i]!=NULL;i++)
	{
		Strcpy(namebuffer,base_define);
		Strcat(namebuffer,"/");
		Strcat(namebuffer,baseconfig[i]);
		ret=read_json_file(namebuffer);
		if(ret<0)
			return ret;
		printf("read %d elem from file %s!\n",ret,namebuffer);
	}


	msgfunc_init();


    struct lib_para_struct * lib_para=NULL;
    fd=open(sys_config_file,O_RDONLY);
    if(fd>0)
    {

   	 ret=read_json_node(fd,&root_node);
  	 if(ret<0)
		return ret;	
    	 close(fd);
	

    	 ret=read_sys_cfg(&lib_para,root_node,NULL);
    	 if(ret<0)
		return ret;
    }	 		
    fd=open(main_config_file,O_RDONLY);
    if(fd<0)
	return -EINVAL;

    ret=read_json_node(fd,&root_node);
    if(ret<0)
	return ret;	
    close(fd);
	
    ret=read_main_cfg(lib_para,root_node);
    if(ret<0)
	return ret; 		

    ret=get_local_uuid(local_uuid);
    printf("this machine's local uuid is %s\n",local_uuid);

// main proc 

    static key_t sem_key;
    static int semid;

    static key_t shm_share_key;
    static int shm_share_id;
    static int shm_size;
    static void * shm_share_addr;

    static CHANNEL * shm_channel;
    char * pathname="/tmp";
    sem_key = ftok(pathname,0x01);

    if(sem_key==-1)

    {
        printf("ftok sem_key error");
        return -1;
    }

    printf("sem_key=%d\n",sem_key) ;
    semid=semget(sem_key,1,IPC_EXCL|0666);
    if(semid<0)
    {
	printf("open share semaphore failed!\n");
	return -EINVAL;
    }		

    return ret;
}
