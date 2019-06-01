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
    BYTE *SignBuf;
    int  Buflen;
    int SignLen;
    UINT32 authHandle;
    UINT32 pikHandle;
    UINT32 signkeyHandle;

    BYTE nonce[DIGEST_SIZE];
    BYTE inDigest[DIGEST_SIZE];
    BYTE outDigest[DIGEST_SIZE];
    int i,j;

    struct timeval start, end;
    int crypttime,decrypttime;
    float encrypt_speed, decrypt_speed;
    int  encrypt_len=DIGEST_SIZE*8;

    ret=_TSMD_Init();

    ret= TCM_LibInit(); 

    Buf=malloc(DIGEST_SIZE*128);
    if(Buf==NULL)
	return -ENOMEM;
    SignBuf=Buf+DIGEST_SIZE*96;

    TCM_KEY * verifykey;
    TCM_KEY * verifiedkey;
    TCM_PUBKEY * pubkey;
    TCM_PUBKEY * signpubkey;
    Memset(nonce,'A',DIGEST_SIZE);

    verifykey=malloc(sizeof(*verifykey));
    if(verifykey==NULL)
	return -EINVAL;

    verifiedkey=malloc(sizeof(*verifiedkey));
    if(verifiedkey==NULL)
	return -EINVAL;
    // load verify key
    // load verify key
    ret = TCM_ExLoadTcmKey(verifykey, "pik.key");
    if(ret!=0)
    {
	printf("ExLoadTcmKey error!\n");
	return -EINVAL;	
    }

    // load verified key
    ret = TCM_ExLoadTcmKey(verifiedkey, "sm2sign.key");
    if(ret!=0)
    {
	printf("ExLoadTcmKey error!\n");
	return -EINVAL;	
    }

    // Load pik 
    ret=TCM_APCreate(TCM_ET_SMK, NULL, "sss", &authHandle);
    printf("authHandle is : %x\n",authHandle);
    if(ret<0)
    {
	printf("TCM_APCreate failed!\n");
	return -EINVAL;	
    }	
    ret=TCM_LoadKey(0x40000000,authHandle,verifykey,&pikHandle);
    if(ret<0)
    {
	printf("TCM_LoadKey failed!\n");
	return -EINVAL;	
    }	

    // Load signkey 
    ret=TCM_LoadKey(0x40000000,authHandle,verifiedkey,&signkeyHandle);
    if(ret<0)
    {
	printf("TCM_LoadKey failed!\n");
	return -EINVAL;	
    }	

    ret=TCM_CertifyKey(pikHandle,signkeyHandle,nonce,
	Buf,&Buflen,SignBuf,&SignLen);
    if(ret<0)
    {
	printf("TCM_CertifyKey failed!\n");
	return -EINVAL;	
    }	

    ret=TCM_APTerminate(authHandle);
    if(ret<0)
    {
	printf("TCM_APTerminate %x failed!\n",authHandle);
	return -EINVAL;	
    }	

    ret=TCM_EvictKey(pikHandle);
    if(ret<0)
    {
	printf("TCM_EvictKey %x failed!\n",pikHandle);
	return -EINVAL;	
    }	

    ret=TCM_EvictKey(signkeyHandle);
    if(ret<0)
    {
	printf("TCM_EvictKey %x failed!\n",signkeyHandle);
	return -EINVAL;	
    }	

  

    // cert Verify

    pubkey=malloc(sizeof(*pubkey));
    if(pubkey==NULL)
	return -EINVAL;
    ret = TCM_ExLoadTcmPubKey(pubkey, "pik_pub.key");
    if(ret!=0)
    {
	printf("ExLoadTcmPubKey error!\n");
	return -EINVAL;	
    }

    ret=TCM_ExSM2Verify(pubkey,SignBuf,SignLen,Buf,Buflen);
    printf("TCM_ExSM2Verify verify result is %d!\n",ret);

    TCM_CERTIFY_INFO certinfo;
    ret = TCM_ExLoadTcmPubKey(pubkey, "sm2signpub.key");
    if(ret!=0)
    {
	printf("ExLoadTcmPubKey error!\n");
	return -EINVAL;	
    }
	
    ret=TCM_ExCertifyKeyVerify(pubkey,&certinfo,Buf,Buflen);
    printf("TCM_ExCertifyKeyVerify result is %d!\n",ret);
    return ret;	

}

