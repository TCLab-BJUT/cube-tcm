#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>

#include "data_type.h"
#include "alloc.h"
#include "string.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "message.h"
#include "connector.h"
#include "tcm_global.h"
#include "tcm_error.h"

struct init_struct
{
    char * name;
};

tcm_state_t * tcm_instances;
const int tcm_num=3;

int vtcm_init(void * main_proc,void * init_para)
{
    printf("vtcm init !\n");
    if (init_para) {
        struct init_struct * para=(struct init_struct *)init_para;
        printf("vtcm init init para is %s!\n",para->name);
    }

    int i;
    tcm_instances=malloc(sizeof(tcm_state_t )*tcm_num);
    for(i=0;i<tcm_num;i++)
    {
        TCM_Global_Init(tcm_instances+i);
    }
    proc_share_data_setpointer(tcm_instances);

    return 0;
}

TCM_RESULT    TCM_Global_Init( tcm_state_t * tcm_instances)
{
    Memset(tcm_instances,0,sizeof(tcm_state_t));
    return TCM_SUCCESS;
}

