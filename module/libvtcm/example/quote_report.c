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
    BYTE *Buf;
    BYTE *SignBuf;
    int  BufLen;
    int SignLen;
    UINT32 authHandle;
    UINT32 pikHandle;

    BYTE nonce[DIGEST_SIZE];
    BYTE pcrValue[DIGEST_SIZE];
    BYTE inDigest[DIGEST_SIZE];
    BYTE outDigest[DIGEST_SIZE];
    int i,j;

    TCM_PCR_COMPOSITE * pcrComp;
    TCM_QUOTE_INFO * quoteInfo;	

    ret=_TSMD_Init();

    ret= TCM_LibInit(); 

    Buf=malloc(DIGEST_SIZE*128);
    if(Buf==NULL)
	return -ENOMEM;
    SignBuf=Buf+DIGEST_SIZE*96;	

    TCM_KEY * pikey;
    TCM_PUBKEY * pubkey;
    Memset(nonce,'A',DIGEST_SIZE);

    pikey=malloc(sizeof(*pikey));
    if(pikey==NULL)
	return -EINVAL;

    // load pik
    ret = TCM_Extend(1,nonce,inDigest);
    if(ret!=0)
    {
	printf("TCM_Extend error!\n");
	return -EINVAL;	
    }
    // load pik
    ret = TCM_ExLoadTcmKey(pikey, "pik.key");
    if(ret!=0)
    {
	printf("ExLoadTcmKey error!\n");
	return -EINVAL;	
    }


    // Build pcr Composite
    pcrComp=malloc(sizeof(*pcrComp));
    if(pcrComp==NULL)
	return -ENOMEM;

    ret=TCM_ExInitPcrComposite(pcrComp);
    if(ret<0)
    {
	printf("Init PcrComp failed!\n");
	return ret;
    }			 

    // set pcr 1
    ret=TCM_PcrRead(1,pcrValue);
    if(ret!=0)
    {
	printf("Tcm PcrRead error!\n");
	return ret;
    }
    
    TCM_ExDupPcrComposite(pcrComp,1,pcrValue);
	
    // Load pik 
    ret=TCM_APCreate(TCM_ET_SMK, NULL, "sss", &authHandle);
    printf("authHandle is : %x\n",authHandle);
    if(ret<0)
    {
	printf("TCM_APCreate failed!\n");
	return -EINVAL;	
    }	
    ret=TCM_LoadKey(0x40000000,authHandle,pikey,&pikHandle);
    if(ret<0)
    {
	printf("TCM_LoadKey failed!\n");
	return -EINVAL;	
    }	
    ret=TCM_APTerminate(authHandle);
    if(ret<0)
    {
	printf("TCM_APTerminate %x failed!\n",authHandle);
	return -EINVAL;	
    }	

    // Quote the data
    ret=TCM_APCreate(TCM_ET_KEYHANDLE, pikHandle, "kkk", &authHandle);
    printf("pik authHandle is : %x\n",authHandle);
    if(ret<0)
    {
	printf("TCM_APCreate failed!\n");
	return -EINVAL;	
    }	

    ret=TCM_Quote(pikHandle,authHandle,nonce,pcrComp,
	SignBuf,&SignLen);

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

    // quote Verify
    // load pik_pub

    pubkey=malloc(sizeof(*pubkey));
    if(pubkey==NULL)
	return -EINVAL;
    ret = TCM_ExLoadTcmPubKey(pubkey, "pik_pub.key");
    if(ret!=0)
    {
	printf("ExLoadTcmPubKey error!\n");
	return -EINVAL;	
    }
    // Create TCM_QUOTE_INFO
    quoteInfo=malloc(sizeof(*quoteInfo));
    if(quoteInfo==NULL)
	return -ENOMEM;

    ret=TCM_ExCreateQuoteInfo(quoteInfo,pcrComp,nonce);
    if(ret!=0)
    {
	printf("Create Quote Info succeed!\n");
	return ret;
    }

    // Verify Quote Info

    BufLen=memdb_output_blob(quoteInfo,Buf,DTYPE_VTCM_PCR,SUBTYPE_TCM_QUOTE_INFO);
    if(BufLen<0)
	return BufLen;	
  
    print_bin_data(SignBuf,SignLen,16);
    print_bin_data(Buf,BufLen,16);
    ret=TCM_ExSM2Verify(pubkey,SignBuf,SignLen,Buf,BufLen);
    printf("TCM_ExSM2Verify verify result is %d!\n",ret);

    ret=TCM_ExCheckQuotePcr(pcrComp,quoteInfo); 
    printf("TCM_ExCheckQuotePcr result is %d!\n",ret);
    return ret;	

}

