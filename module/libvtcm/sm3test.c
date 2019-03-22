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

int main(int argc,char **argv)
{

    int ret;
   
    UINT32 handle;
    int PcrLength;
    BYTE * PcrValue;
    BYTE *Buf;
    int  Buflen;

    BYTE inDigest[DIGEST_SIZE];
    BYTE outDigest[DIGEST_SIZE];
    int i;

    struct timeval start, end;
    int hashtime;
    int repeattime=3;
    int hash_len=384;
    float hash_speed;

    ret=_TSMD_Init();

    ret= TCM_LibInit(); 

    Memset(inDigest,'A',DIGEST_SIZE);

    Buf=malloc(DIGEST_SIZE*256);
    if(Buf==NULL)
	return -ENOMEM;
    Memset(Buf,DIGEST_SIZE*16,'A');

    gettimeofday( &start, NULL );
   
    ret=TCM_SM3Start( );
    if(ret<0)
    {
	printf("TCM_SM3Start failed!\n");
	return -EINVAL;	
    }	
	
    for(i=0;i<repeattime;i++)
    {
    	ret=TCM_SM3Update(Buf,hash_len );
    	if(ret<0)
    	{
		printf("TCM_SM3Update failed!\n");
		return -EINVAL;	
    	}	
    }

    ret=TCM_SM3Complete(Buf,hash_len,outDigest);
    if(ret<0)
    {
	printf("TCM_SM3Complete failed!\n");
	return -EINVAL;	
    }	

    gettimeofday( &end, NULL );
    hashtime = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec;

    hash_speed = (float)(hash_len*repeattime)*1000 /hashtime;

    printf(" SM3 algorithm's speed is %f KB/s\n",hash_speed); 

    return ret;	

}

