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
    BYTE Buf[DIGEST_SIZE*64];
    BYTE CryptBuf[DIGEST_SIZE*64];
    BYTE OutBuf[DIGEST_SIZE*64];
    int  Buflen;
    int CryptBuflen;	
    int  OutBuflen;
    UINT32 authHandle;
    UINT32 keyHandle;
    UINT32 keyAuthHandle;

    BYTE inDigest[DIGEST_SIZE];
    BYTE outDigest[DIGEST_SIZE];

    ret=_TSMD_Init();

    ret= TCM_LibInit(); 

    BYTE * RandomData;
    int RandomDataLength;

    TCM_KEY * tcmkey;

    tcmkey=malloc(sizeof(*tcmkey));
    if(tcmkey==NULL)
	return -ENOMEM;

    TCM_PUBKEY * pubkey;
    pubkey=malloc(sizeof(*pubkey));
    if(pubkey==NULL)
	return -ENOMEM;


    ret=TCM_APCreate(TCM_ET_SMK, NULL, "sss", &authHandle);
    printf("authHandle is : %x\n",authHandle);
    if(ret<0)
    {
	printf("TCM_APCreate failed!\n");
	return -EINVAL;	
    }	

    ret=TCM_CreateWrapKey(tcmkey,0x40000000,authHandle,
	TCM_SM2KEY_STORAGE,TCM_ISVOLATILE|TCM_PCRIGNOREDONREAD, "kkk");
    if(ret<0)
    {
	printf("TCM_CreateWrapKey failed!\n");
	return -EINVAL;	
    }	

    ret = TCM_ExGetPubkeyFromTcmkey(pubkey,tcmkey);
    if(ret<0)
    {
	printf("TCM_ExGetPubkeyFromTcmkey failed!\n");
	return -EINVAL;	
    }	

    TCM_ExSaveTcmKey(tcmkey,"sm2store.key");
	
    TCM_ExSaveTcmPubKey(pubkey,"sm2storepub.key");

    ret=TCM_CreateWrapKey(tcmkey,0x40000000,authHandle,
	TCM_SM2KEY_SIGNING,TCM_ISVOLATILE|TCM_PCRIGNOREDONREAD, "kkk");
    if(ret<0)
    {
	printf("TCM_CreateWrapKey failed!\n");
	return -EINVAL;	
    }	

    ret=TCM_APTerminate(authHandle);
    printf("Terminate authHandle %x\n",authHandle);
    if(ret<0)
    {
	printf("TCM_APCreate failed!\n");
	return -EINVAL;	
    }	

    TCM_ExSaveTcmKey(tcmkey,"sm2sign.key");
	
    TCM_ExSaveTcmPubKey(pubkey,"sm2signpub.key");

    return ret;	
}

