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
#include "sm4.h"
#include "tcmfunc.h"
#include "vtcm_alg.h"

char * prikeyfile="CApri.key";
char * pubkeyfile="CApub.key";

int main(int argc,char **argv)
{

    int ret;
   
    int i,j;


    ret=_TSMD_Init();

    ret= TCM_LibInit(); 


    ret=TCM_ExCreateCAKey();
    if(ret!=0)
    {
		printf("TCM_ExCreateCAKey failed!\n");
		return -EINVAL;	
    }	

    ret=TCM_ExSaveCAPriKey(prikeyfile);
    if(ret!=0)
    {
		printf("TCM_ExSaveCAPriKey failed!\n");
		return -EINVAL;	
    }	
		
    ret=TCM_ExSaveCAPubKey(pubkeyfile);
    if(ret!=0)
    {
		printf("TCM_ExSaveCAPubKey failed!\n");
		return -EINVAL;	
    }	

    return ret;	

}

