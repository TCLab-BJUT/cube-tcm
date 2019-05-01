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

char * pubkeyfile="CApub.key";
char * pikreqfile="pikreq.blob";
char * pikfile="pik.key";
char * pik_pubfile = "pik_pub.key";
char * ek_pubfile = "ek_pub.key";

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
    UINT32 smkHandle;
    UINT32 ownerHandle;
    UINT32 keyHandle;
    UINT32 keyAuthHandle;

     int userinfolen=10;
    BYTE * userinfo = "for test!";	

    BYTE inDigest[DIGEST_SIZE];
    BYTE outDigest[DIGEST_SIZE];

    ret=_TSMD_Init();

    ret= TCM_LibInit(); 

    TCM_PUBKEY * pubek;
    pubek=malloc(sizeof(*pubek));
    if(pubek==NULL)
	return -ENOMEM;

    ret=TCM_ReadPubek(pubek);
    if(ret<0)
    {
	printf("TCM_ReadPubek failed!\n");
	return -EINVAL;	
    }	

    ret=TCM_ExLoadCAPubKey(pubkeyfile);
    if(ret<0)
    {
	printf("TCM_ExLoadCAPubKey failed!\n");
	return -EINVAL;	
    }	


    ret=TCM_APCreate(TCM_ET_OWNER, NULL, "ooo", &ownerHandle);
    printf("ownerHandle is : %x\n",ownerHandle);
    if(ret<0)
    {
	printf("TCM_APCreate failed!\n");
	return -EINVAL;	
    }	

    ret=TCM_APCreate(TCM_ET_SMK, NULL, "sss", &smkHandle);
    printf("smkHandle is : %x\n",smkHandle);
    if(ret<0)
    {
	printf("TCM_APCreate failed!\n");
	return -EINVAL;	
    }	

    TCM_KEY pik;
    TCM_PUBKEY pik_pub;
    BYTE * req;
    int reqlen;	
    int fd;
   
    ret = TCM_MakeIdentity(ownerHandle, smkHandle,
	userinfolen,userinfo,"kkk",
	&pik, &req, &reqlen);
    if(ret<0)
    {
	printf("TCM_MakeIdentity failed!\n");
	return -EINVAL;	
    }	
    ret=TCM_APTerminate(ownerHandle);
    if(ret<0)
    {
	printf("TCM_APTerminate failed!\n");
	return -EINVAL;	
    }	

    ret=TCM_APTerminate(smkHandle);
    if(ret<0)
    {
	printf("TCM_APTerminate failed!\n");
	return -EINVAL;	
    }	


    fd=open(pikreqfile,O_CREAT|O_TRUNC|O_WRONLY,0666);
    if(fd<0)
	  return -EIO;	
    ret=write(fd,req,reqlen);
    if(ret<0)
    {
		printf("write pik req file error!\n");
		return -EIO;	
    }

    close(fd);

    ret=TCM_ExGetPubkeyFromTcmkey(&pik_pub,&pik);
    if(ret<0)
    {
	printf("get pubkey from pik error!\n");
	return ret;	
    }	

    ret=TCM_ExSaveTcmKey(&pik,pikfile);
    if(ret<0)
    {
	printf("save pik error!\n");
	return ret;	
    }	

    ret=TCM_ExSaveTcmPubKey(&pik_pub,pik_pubfile);
    if(ret<0)
    {
	printf("save pik_pub error!\n");
	return ret;	
    }	

    ret=TCM_ExSaveTcmPubKey(pubek,ek_pubfile);
    if(ret<0)
    {
	printf("save pik_pub error!\n");
	return ret;	
    }	


    return ret;	

}

