#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/ioctl.h>


#include "data_type.h"
#include "alloc.h"
#include "list.h"
#include "attrlist.h"
#include "memfunc.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "channel.h"
#include "memdb.h"
#include "message.h"
#include "connector.h"
#include "ex_module.h"
#include "sys_func.h"
#include "tcm_constants.h"
#include "app_struct.h"
#include "pik_struct.h"
#include "tcm_global.h"
#include "tcm_authlib.h"
#include "sm4.h"
#include "vtcm_alg.h"

#include "tcmfunc.h"

extern TCM_PUBKEY * pubEK;
BYTE ExBuf[DIGEST_SIZE*32];

BYTE * CAprikey=NULL;
unsigned long CAprilen;
BYTE * CApubkey=NULL;

UINT32 TCM_SM2LoadPubkey(char *keyfile,BYTE * key, int *keylen )
{
  TCM_KEY *keyOut;
  int ret=0;
  int keyLength=0;
  void * vtcm_template;
  int fd;
  int datasize;

  // read file
  fd=open(keyfile,O_RDONLY);
  if(fd<0)
      return -EIO;
  ret=read(fd,ExBuf,DIGEST_SIZE*32+1);
  if(ret<0)
      return -EIO;
  if(ret>DIGEST_SIZE*32)
  {
      printf("key file too large!\n");
      return -EINVAL;
  }
  close(fd);
  int length=512;
  BYTE * keyFile=(BYTE*)malloc(sizeof(BYTE)*keyLength);

  //  load key

  vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_PUBKEY);
  if(vtcm_template==NULL)
      return -EINVAL;

  datasize=ret;

  keyOut=Talloc0(sizeof(*keyOut));
  if(keyOut==NULL)
    return -ENOMEM;

  ret=blob_2_struct(ExBuf,keyOut,vtcm_template);
  if(ret<0||ret>datasize){
       printf("read key file error!\n");
       return -EINVAL;
  }

  *keylen=keyOut->pubKey.keyLength;
  Memcpy(key,keyOut->pubKey.key,*keylen);
  return 0;
}

UINT32 TCM_SM2Encrypt(BYTE * pubkey, int pubkey_len, BYTE * out, int * out_len,BYTE * in ,int in_len)
{
  int i=1;
  int ret=0;
  int fd;
  int datasize;

  //  load key

  // proc_vtcmutils_ReadFile(keyLength,keyFile);
  // read data

  *out_len=in_len+65+32+4;
  ret = GM_SM2Encrypt(out,out_len,in,in_len,pubkey,pubkey_len);
  if(ret!=0){
      printf("SM2Encrypt is fail\n");
      return -EINVAL;
  }
  return 0;
}

int TCM_ExCreateSm2Key(BYTE ** privkey,int * privkey_len,BYTE ** pubkey)
{
	int ret=0;
	int i;

    	printf("Begin ex Create sm2 key:\n");
	
	BYTE prikey[DIGEST_SIZE*2];
	BYTE pubkey_XY[64];
	unsigned long prilen=DIGEST_SIZE*2;

	ret=GM_GenSM2keypair(prikey,&prilen,pubkey_XY);	
	if(ret!=0)
		return -EINVAL;
	*privkey_len=prilen;
	
	*privkey=malloc(prilen);
	if(*privkey==NULL)
		return -ENOMEM;
	Memcpy(*privkey,prikey,prilen);
	*pubkey=malloc(64);
	if(*pubkey==NULL)
		return -ENOMEM;
	Memcpy(*pubkey,pubkey_XY,64);
	return 0;
}

int TCM_ExCreateCAKey()
{
	return TCM_ExCreateSm2Key(&CAprikey,&CAprilen,&CApubkey);
}

int TCM_ExSaveCAPriKey(char * prikeyfile)
{
	int fd;
	int ret;
	if(CAprikey==NULL)
		return -EINVAL;	
	
	fd=open(prikeyfile,O_CREAT|O_TRUNC|O_WRONLY,0666);
	if(fd<0)
		return -EIO;	
	ret=write(fd,CAprikey,CAprilen);
	if(ret<0)
	{
		printf("write prikey file error!\n");
		return -EIO;	
	}

	close(fd);
	
	return 0;
}

int TCM_ExLoadCAPriKey(char * prikeyfile)
{
	int fd;
	int ret;
	fd=open(prikeyfile,O_RDONLY);
        if(fd<0)
		return -EIO;	
	
	ret=read(fd,ExBuf,DIGEST_SIZE*16+1);
	if(ret<0)
	{
		printf("read  privkey file error!\n");
		return -EIO;	
	}
	if(ret>DIGEST_SIZE*16)
	{
		printf("privkey is too long!\n");
		return -EIO;
	}
	CAprilen=ret;
	CAprikey=malloc(ret);
	if(CAprikey==NULL)
		return -ENOMEM;
	Memcpy(CAprikey,ExBuf,ret);
	close(fd);
	return 0;
}

int TCM_ExSaveCAPubKey(char * pubkeyfile)
{
	int fd;
	int ret;
	if(CApubkey==NULL)
		return -EINVAL;	
	
	fd=open(pubkeyfile,O_CREAT|O_TRUNC|O_WRONLY,0666);
	if(fd<0)
		return -EIO;	
	ret=write(fd,CApubkey,64);
	if(ret<0)
	{
		printf("write pubkey file error!\n");
		return -EIO;	
	}

	close(fd);
	return 0;
}

int TCM_ExLoadCAPubKey(char * pubkeyfile)
{
	int fd;
	int ret;
	fd=open(pubkeyfile,O_RDONLY);
	if(fd<0)
		return -EIO;	
	
	ret=read(fd,ExBuf,DIGEST_SIZE*16+1);
	if(ret<0)
	{
		printf("read  pubkey file error!\n");
		return -EIO;	
	}
	if(ret>DIGEST_SIZE*16)
	{
		printf("pubkey is too long!\n");
		return -EIO;
	}
	CApubkey=malloc(ret);
	if(CApubkey==NULL)
		return -ENOMEM;
	Memcpy(CApubkey,ExBuf,ret);
	close(fd);
	return 0;
}
