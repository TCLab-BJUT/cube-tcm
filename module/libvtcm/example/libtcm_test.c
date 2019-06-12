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

   ret=TCM_GetRandom(800,&RandomData,&RandomDataLength);
   if(ret<0)
   {
	printf("TCM GetRandom failed!\n");
	return ret;
   }

//   ret= TCM_CreateEndorsementKeyPair(Buf,&Buflen); 

    Memset(inDigest,'A',DIGEST_SIZE);

    ret=TCM_Extend(0,inDigest,outDigest);

    if(ret==0)
    	ret=TCM_PcrRead(0,outDigest);

    TCM_PUBKEY * pubek;
    pubek=malloc(sizeof(*pubek));
    if(pubek==NULL)
	return -ENOMEM;

    ret=TCM_ReadPubek(pubek);

    BYTE pubkey[DIGEST_SIZE*8];
    int pubkey_len;    
 
    ret=TCM_SM2LoadPubkey("sm2.key",pubkey, &pubkey_len);

    Memset(Buf,DIGEST_SIZE*16,'A');

    ret=TCM_SM2Encrypt(pubkey,pubkey_len,CryptBuf,&CryptBuflen,Buf,DIGEST_SIZE*9);

    ret=TCM_APCreate(TCM_ET_SMK, NULL, "sss", &authHandle);
    printf("authHandle is : %x\n",authHandle);
    if(ret<0)
    {
	printf("TCM_APCreate failed!\n");
	return -EINVAL;	
    }	
    ret=TCM_LoadKey(0x40000000,authHandle,"sm2.key",&keyHandle);
    if(ret<0)
    {
	printf("TCM_LoadKey failed!\n");
	return -EINVAL;	
    }	
    ret=TCM_APCreate(TCM_ET_KEYHANDLE, keyHandle, "sm2", &keyAuthHandle);
    if(ret<0)
    {
	printf("TCM_APCreate %dfailed!\n",12);
	return -EINVAL;	
    }	
    printf("keyAuthHandle is : %x\n",keyAuthHandle);
    	
    ret=TCM_SM2Decrypt(keyHandle,keyAuthHandle,OutBuf,&OutBuflen,CryptBuf,CryptBuflen);

    return ret;	

}

