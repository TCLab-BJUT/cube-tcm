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
#include <sys/sem.h>


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
#include "tcm_constants.h"
#include "app_struct.h"
#include "pik_struct.h"
#include "sm3.h"
#include "sm4.h"

typedef struct proc_init_parameter
{
	char * name;
	int type;
	int (* init) (void *,void *);
	int (* start) (void *,void *);
}PROC_INIT;
struct context_init
{
        int count;
        UINT32 handle;
}__attribute__((packed));


enum tsmd_context_state
{       
        TSMD_CONTEXT_INIT=0x01,
        TSMD_CONTEXT_BUILD,
        TSMD_CONTEXT_APICALL,
        TSMD_CONTEXT_SENDDATA,
        TSMD_CONTEXT_RECVDATA,
        TSMD_CONTEXT_APIRETURN,
        TSMD_CONTEXT_CLOSE,
        TSMD_CONTEXT_ERROR
};

typedef struct tsmd_context_struct
{
        int count;
        UINT32 handle;
        int shmid;
        enum tsmd_context_state state;

        int tsmd_API;
        int curr_step;
        void * tsmd_context;
        BYTE * tsmd_send_buf;
        BYTE * tsmd_recv_buf;
        CHANNEL * tsmd_API_channel;
}__attribute__((packed)) TSMD_CONTEXT;

TSMD_CONTEXT this_context={0,0,0,0,0,0,NULL,NULL,NULL,NULL};


static char main_config_file[DIGEST_SIZE*2]="./main_config.cfg";
static char sys_config_file[DIGEST_SIZE*2]="./sys_config.cfg";

int main(int argc,char **argv)
{

    int ret;
	
    _TSMD_Init();


    ret=Tspi_Context_Create();     
    return ret;
}

