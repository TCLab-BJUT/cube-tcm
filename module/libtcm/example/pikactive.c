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
char * pikfile="pik.key";
char * pik_pubfile = "pik_pub.key";
char * certblobfile = "pikcert.blob";
char * certfile = "pik.cert";
char * symmkeyblobfile="symmkey.blob";

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
    TCM_SYMMETRIC_KEY symmkey;

     int userinfolen=10;
    BYTE * userinfo = "for test!";	

    BYTE inDigest[DIGEST_SIZE];
    BYTE outDigest[DIGEST_SIZE];

    ret=_TSMD_Init();

    ret= TCM_LibInit(); 

    TCM_PUBKEY ek_pub;

    ret=TCM_ReadPubek(&ek_pub);
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
    if(ret!=0)
    {
	printf("TCM_APCreate failed!\n");
	return -EINVAL;	
    }	

    ret=TCM_APCreate(TCM_ET_SMK, NULL, "sss", &smkHandle);
    printf("smkHandle is : %x\n",smkHandle);
    if(ret!=0)
    {
	printf("TCM_APCreate failed!\n");
	return -EINVAL;	
    }	

    TCM_KEY pik;

    ret=TCM_ExLoadTcmKey(&pik,pikfile);
    if(ret!=0)
    {
	printf("read pik from file failed!\n");
	return ret;	
    }	
  
    ret=TCM_LoadKey(0x40000000,smkHandle,pikfile,&keyHandle);
    if(ret!=0)
    {
	printf("TCM_LoadKey failed!\n");
	return ret;	
    }	
    ret=TCM_APTerminate(smkHandle);
    if(ret!=0)
    {
	printf("TCM_APTerminate failed!\n");
	return ret;	
    }	

    ret=TCM_APCreate(TCM_ET_KEYHANDLE,keyHandle, "kkk", &keyAuthHandle);
    printf("pikHandle is : %x\n",keyAuthHandle);
    if(ret!=0)
    {
	printf("TCM_APCreate failed!\n");
	return -EINVAL;	
    }	


    BYTE * symmkeyblob;
    int symmkeybloblen;	
    int fd;
  
    fd=open(symmkeyblobfile,O_RDONLY);
    if(fd<=0)
    {
	printf("open symmkeyblobfile failed\n");
	return -EIO;
    }	
	
    symmkeybloblen=read(fd,Buf,DIGEST_SIZE*32);
    if(symmkeybloblen<=0)
    {
	printf("read symmkeyblobfile failed\n");
	return -EIO;
    }	

    ret=TCM_ActivateIdentity(keyHandle,keyAuthHandle,ownerHandle,
	symmkeybloblen,Buf,&symmkey,"ooo","kkk");	
    if(ret!=0)
    {
	printf("TCM_ActivateIdentity failed!\n");
	return -EINVAL;	
    }	
    ret=TCM_APTerminate(ownerHandle);
    if(ret<0)
    {
	printf("TCM_APTerminate failed!\n");
	return -EINVAL;	
    }	

    ret=TCM_APTerminate(keyAuthHandle);
    if(ret<0)
    {
	printf("TCM_APTerminate failed!\n");
	return -EINVAL;	
    }	

    ret=TCM_EvictKey(keyHandle);
    if(ret<0)
    {
	printf("TCM_APTerminate failed!\n");
	return -EINVAL;	
    }	

    // decrypt cert blob
    int blobsize;
    BYTE * cert;
    int certsize;
    fd=open(certblobfile,O_RDONLY);
    if(fd<0)
	  return -EIO;	
    ret=read(fd,Buf,DIGEST_SIZE*63+1);
    if(ret<0)
    {
	printf("read cert blob file error!\n");
	return -EINVAL;	
    }
    if(ret==DIGEST_SIZE*63+1)
    {
	printf("cert blob file too large!\n");
	return -EINVAL;	
    }		
    close(fd);
    blobsize=ret;

    ret=TCM_ExSymmkeyDecrypt(&symmkey,Buf,blobsize,&cert,&certsize);
    if(ret!=0)
    {
	printf("decrypt cert blob file error!\n");
	return -EINVAL;	
    }

    // write cert file
    fd = open (certfile,O_WRONLY|O_TRUNC|O_CREAT,0666);
    if(fd<0)
 	return -EIO;

    int i;
    for(i=0;(cert[i]==0) && (i<certsize);i++);	
		
    ret=write(fd,cert+i,certsize-i);
    if(ret!=certsize-i)
    {
	printf("write cert failed!\n");
	return -EIO;	
    }			

    close(fd);

    return 0;	
/*
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
*/

    return ret;	

}

