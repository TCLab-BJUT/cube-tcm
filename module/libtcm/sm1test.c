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
    BYTE *CryptBuf;
    BYTE *OutBuf;
    int  Buflen;
    int CryptBuflen;	
    int  OutBuflen;
    UINT32 authHandle;
    UINT32 keyHandle;
    UINT32 keyAuthHandle;

    BYTE inDigest[DIGEST_SIZE];
    BYTE outDigest[DIGEST_SIZE];
    int i;

    struct timeval start, end;
    int crypttime,decrypttime;

    ret=_TSMD_Init();

    ret= TCM_LibInit(); 

//   ret= TCM_CreateEndorsementKeyPair(Buf,&Buflen); 

    Buf=malloc(DIGEST_SIZE*256);
    if(Buf==NULL)
	return -ENOMEM;
    CryptBuf=Buf+DIGEST_SIZE*72;
    OutBuf=CryptBuf+DIGEST_SIZE*72;  

    Memset(Buf,'A',DIGEST_SIZE*16);

    ret=TCM_APCreate(TCM_ET_SMK, NULL, "sss", &authHandle);
    printf("authHandle is : %x\n",authHandle);
    if(ret<0)
    {
	printf("TCM_APCreate failed!\n");
	return -EINVAL;	
    }	
    ret=TCM_LoadKey(authHandle,"sm4.key",&keyHandle);
    if(ret<0)
    {
	printf("TCM_LoadKey failed!\n");
	return -EINVAL;	
    }	
    ret=TCM_APCreate(TCM_ET_KEYHANDLE, keyHandle, "sm4", &keyAuthHandle);
    if(ret<0)
    {
	printf("TCM_APCreate %dfailed!\n",12);
	return -EINVAL;	
    }	
    printf("keyAuthHandle is : %x\n",keyAuthHandle);
    	
    gettimeofday( &start, NULL );
    ret=TCM_SM1Encrypt(keyHandle,keyAuthHandle,CryptBuf,&CryptBuflen,Buf,DIGEST_SIZE*8);
    gettimeofday( &end, NULL );
    crypttime = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec;

    gettimeofday( &start, NULL );
    ret=TCM_SM1Decrypt(keyHandle,keyAuthHandle,OutBuf,&OutBuflen,CryptBuf,CryptBuflen);
    gettimeofday( &end, NULL );
    decrypttime = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec;
    printf("crypt time %d us decrypt time: %d us\n", crypttime,decrypttime);
    ret=TCM_APTerminate(authHandle);
    if(ret<0)
    {
	printf("TCM_APTerminate %x failed!\n",authHandle);
	return -EINVAL;	
    }	
    ret=TCM_APTerminate(keyAuthHandle);
    if(ret<0)
    {
	printf("TCM_APTerminate %x failed!\n",keyAuthHandle);
	return -EINVAL;	
    }	
    ret=TCM_EvictKey(keyHandle);
    if(ret<0)
    {
	printf("TCM_APTerminate %x failed!\n",keyHandle);
	return -EINVAL;	
    }	

    return ret;	

}

