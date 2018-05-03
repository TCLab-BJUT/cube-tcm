#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "data_type.h"
#include "errno.h"
#include "alloc.h"
#include "list.h"
#include "attrlist.h"
#include "memfunc.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "ex_module.h"
#include "tcm_constants.h"
#include "vtcm_utils.h"
#include "app_struct.h"
#include "pik_struct.h"
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"

static BYTE Buf[DIGEST_SIZE*32];

extern Record_List sessions_list;
extern TCM_PUBKEY *pubEK;
extern TCM_SECRET ownerAuth;
extern TCM_SECRET smkAuth;
extern Record_List entitys_list;
extern void * curr_recv_msg;

// Ex CA Module

BYTE * CAprikey=NULL;
unsigned long CAprilen=0;
BYTE * CApubkey=NULL;
unsigned long CApublen=64;
 
int proc_vtcmutils_ExCreateSm2Key(void * sub_proc,void * para);
int proc_vtcmutils_ExLoadCAKey(void * sub_proc,void * para);
int proc_vtcmutils_ExCaSign(void * sub_proc,void * para);
int proc_vtcmutils_ExCAVerify(void * sub_proc,void * para);
int proc_vtcmutils_ExVerify(void * sub_proc,void * para);
int proc_vtcmutils_ExVerifyQuote(void * sub_proc, void * para);
int proc_vtcmutils_ExCheckQuotePCR(void * sub_proc, void * para);
int proc_vtcmutils_ExDecryptPikCert(void * sub_proc,void * para);

void * vtcm_auto_build_outputmsg(char * out_line, void * active_msg);


int proc_vtcmutils_ExCreateSm2Key(void * sub_proc,void * para)
{
	int ret=0;
    	struct tcm_utils_input * input_para=para;
	char * index_para;
	char * value_para;
	int i;

	//  cmd's params
	char * pubkey_file=NULL;
	char * privkey_file=NULL;
	char * passwd=NULL;
    	printf("Begin ex Create sm2 key:\n");
	
	if((input_para->param_num>0)&&
		(input_para->param_num%2==1))
	{
		for(i=1;i<input_para->param_num;i+=2)
		{
        		index_para=input_para->params+i*DIGEST_SIZE;
        		value_para=index_para+DIGEST_SIZE;
			if(!Strcmp("-pubkey",index_para))
			{
        			pubkey_file=value_para;
			}	
			else if(!Strcmp("-prikey",index_para))
			{
				privkey_file=value_para;
			}
			else if(!Strcmp("-pwd",index_para))
			{
				passwd=value_para;
			}
			else
			{
				printf("Error cmd format! should be %s -pubkey pubkeyfile -prikey prikeyfile"
					"[-pwd passwd]",input_para->params);
				return -EINVAL;
			}
		}
	}	
	
	BYTE prikey[DIGEST_SIZE*2];
	BYTE pubkey_XY[64];
	unsigned long prilen=DIGEST_SIZE*2;
	int fd;

	ret=GM_GenSM2keypair(prikey,&prilen,pubkey_XY);	
	if(ret!=0)
		return -EINVAL;
	fd=open(pubkey_file,O_CREAT|O_TRUNC|O_WRONLY,0666);
	if(fd<0)
		return -EIO;	
	
	ret=write(fd,pubkey_XY,64);
	if(ret<0)
	{
		printf("write pubkey file error!\n");
		return -EIO;	
	}
	close(fd);

	fd=open(privkey_file,O_CREAT|O_TRUNC|O_WRONLY,0666);
	if(fd<0)
		return -EIO;	
	
	ret=write(fd,prikey,prilen);
	if(ret<0)
	{
		printf("write prikey file error!\n");
		return -EIO;	
	}

	close(fd);
	ret=0;
	printf("proceed  create Sm2 key succeed!\n");
    	sprintf(Buf,"%d \n",ret);
   	void * send_msg =vtcm_auto_build_outputmsg(Buf,curr_recv_msg);
   	if(send_msg==NULL)
		return -EINVAL;
   	ex_module_sendmsg(sub_proc,send_msg);		

	return ret;
}

int proc_vtcmutils_ExLoadCAKey(void * sub_proc,void * para)
{
	int ret=0;
    	struct tcm_utils_input * input_para=para;
	char * index_para;
	char * value_para;
	int i;

	//  cmd's params
	char * pubkey_file=NULL;
	char * privkey_file=NULL;
	char * passwd=NULL;
    	printf("Begin ex Load CA Key:\n");
	
	if((input_para->param_num>0)&&
		(input_para->param_num%2==1))
	{
		for(i=1;i<input_para->param_num;i+=2)
		{
        		index_para=input_para->params+i*DIGEST_SIZE;
        		value_para=index_para+DIGEST_SIZE;
			if(!Strcmp("-pubkey",index_para))
			{
        			pubkey_file=value_para;
			}	
			else if(!Strcmp("-prikey",index_para))
			{
				privkey_file=value_para;
			}
			else if(!Strcmp("-pwd",index_para))
			{
				passwd=value_para;
			}
			else
			{
				printf("Error cmd format! should be %s -pubkey pubkeyfile -prikey prikeyfile"
					"[-pwd passwd]",input_para->params);
				return -EINVAL;
			}
		}
	}	
	
	int fd;

	if(pubkey_file!=NULL)
	{
		fd=open(pubkey_file,O_RDONLY);
		if(fd<0)
			return -EIO;	
	
		ret=read(fd,Buf,DIGEST_SIZE*16+1);
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
		Memcpy(CApubkey,Buf,ret);
		close(fd);
	}
	if(privkey_file!=NULL)
	{
		fd=open(privkey_file,O_RDONLY);
		if(fd<0)
			return -EIO;	
	
		ret=read(fd,Buf,DIGEST_SIZE*16+1);
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
		Memcpy(CAprikey,Buf,ret);
		close(fd);
	}

	printf("proceed  load ca key succeed!\n");

	ret=0;
    	sprintf(Buf,"%d \n",ret);
   	void * send_msg =vtcm_auto_build_outputmsg(Buf,curr_recv_msg);
   	if(send_msg==NULL)
		return -EINVAL;
   	ex_module_sendmsg(sub_proc,send_msg);		

	return ret;
}


int proc_vtcmutils_ExCaSign(void * sub_proc,void * para)
{
	int ret=0;
    	struct tcm_utils_input * input_para=para;
	char * index_para;
	char * value_para;
	int i;
	TCM_KEY pik;
	TCM_PUBKEY ekpub;
	TCM_ASYM_CA_CONTENTS ca_conts;
	TCM_SYMMETRIC_KEY * symm_key=&ca_conts.sessionKey;
	TCM_PIK_CERT * pik_cert;
	void * vtcm_template;
	

	//  cmd's params
	char * user_file=NULL;
	char * pik_file=NULL;
	char * ek_file=NULL;
	char * req_file=NULL;
	char * cert_file=NULL;
	char * symmkey_file=NULL;
    	printf("Begin ex CA Sign:\n");
	
	if((input_para->param_num>0)&&
		(input_para->param_num%2==1))
	{
		for(i=1;i<input_para->param_num;i+=2)
		{
        		index_para=input_para->params+i*DIGEST_SIZE;
        		value_para=index_para+DIGEST_SIZE;
			if(!Strcmp("-user",index_para))
			{
        			user_file=value_para;
			}	
			else if(!Strcmp("-pik",index_para))
			{
				pik_file=value_para;
			}
			else if(!Strcmp("-ek",index_para))
			{
				ek_file=value_para;
			}
			else if(!Strcmp("-req",index_para))
			{
				req_file=value_para;
			}
			else if(!Strcmp("-cert",index_para))
			{
				cert_file=value_para;
			}
			else if(!Strcmp("-symm",index_para))
			{
				symmkey_file=value_para;
			}
			else
			{
				printf("Error cmd format! should be %s -user user_info_file -pik pik_file -ek ek.file"
					" -req req_file -cert cert_file -symm symmkey_file",input_para->params);
				return -EINVAL;
			}
		}
	}	
	
	BYTE prikey[DIGEST_SIZE*2];
	BYTE pubkey_XY[64];
	unsigned long prilen=DIGEST_SIZE*2;
	int fd;

	// malloc space for pik
	pik_cert=Talloc0(sizeof(*pik_cert));
	if(pik_cert==NULL)
		return -ENOMEM;

	pik_cert->payLoad=0x19;   // add pik_cert's payload
	//  compute  userinfo's digest
    	fd=open(user_file,O_RDONLY);
    	if(fd<0)
    	{
  		printf("No userinfo file %s!\n",user_file);
		return -EINVAL;
    	}
    
    	ret=read(fd,Buf,DIGEST_SIZE*31+1);
    	if(ret<0)
    	{
		printf("can't read userinfo data!\n");
		return -EINVAL;
    	}
    	if(ret>DIGEST_SIZE*31)
    	{
		printf("user info too long!\n");
		return -EINVAL;
    	}
    	sm3(Buf,ret,pik_cert->userDigest); 	

	// read pik file 
    	fd=open(pik_file,O_RDONLY);
    	if(fd<0)
    	{
  		printf("No pik file %s!\n",pik_file);
		return -EINVAL;
    	}
    
    	ret=read(fd,Buf,DIGEST_SIZE*31+1);
    	if(ret<0)
    	{
		printf("can't read pik data!\n");
		return -EINVAL;
    	}
    	if(ret>DIGEST_SIZE*31)
    	{
		printf("pik data too long!\n");
		return -EINVAL;
	}

	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
	if(vtcm_template==NULL)
		return -EINVAL;

	ret=blob_2_struct(Buf, &pik,vtcm_template);
	if(ret<0)
		return ret;
		
        // compute pik's digest

       vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_STORE_PUBKEY);
       if(vtcm_template==NULL)
		return -EINVAL;
       ret=struct_2_blob(&pik.pubKey,Buf,vtcm_template);
       if(ret<0)
		return ret;
	sm3(Buf,ret,pik_cert->pubDigest);		
	Memcpy(&ca_conts.idDigest,pik_cert->pubDigest,DIGEST_SIZE);
   
       // Read ek's pubkey
    	fd=open(ek_file,O_RDONLY);
    	if(fd<0)
    	{
  		printf("No ek file %s!\n",pik_file);
		return -EINVAL;
    	}
    	ret=read(fd,Buf,DIGEST_SIZE*31+1);
    	if(ret<0)
    	{
		printf("can't read ek data!\n");
		return -EINVAL;
    	}
    	if(ret>DIGEST_SIZE*31)
    	{
		printf("pik data too long!\n");
		return -EINVAL;
	}

	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_PUBKEY);
	if(vtcm_template==NULL)
		return -EINVAL;

	ret=blob_2_struct(Buf, &ekpub,vtcm_template);
	if(ret<0)
		return ret;
    

       // sign data with CAprikey

    	if(CAprikey==NULL)
    	{
		printf("can't find CA's private key!\n");
		return -EINVAL;
    	}
	
	BYTE SignBuf[DIGEST_SIZE*4];	
    	BYTE UserID[DIGEST_SIZE];
    	unsigned long lenUID = DIGEST_SIZE;
    	Memset(UserID, 'A', 32);

	Memcpy(Buf,pik_cert->userDigest,DIGEST_SIZE);
	Memcpy(Buf+DIGEST_SIZE,pik_cert->pubDigest,DIGEST_SIZE);
	
	pik_cert->signLen=DIGEST_SIZE*4;

	GM_SM2Sign(SignBuf,&pik_cert->signLen,
		Buf,DIGEST_SIZE*2,
		UserID,lenUID,
		CAprikey,CAprilen);	

	pik_cert->signData=Talloc0(pik_cert->signLen);
	Memcpy(pik_cert->signData,SignBuf,pik_cert->signLen);
   	
	// Create symmetric key
	Memset(symm_key,0,sizeof(*symm_key));
        symm_key->algId=TCM_ALG_SM4;
        symm_key->encScheme=TCM_ES_SM4_CBC;
	symm_key->size=0x80/8;
	symm_key->data=Talloc0(symm_key->size);
	RAND_bytes(symm_key->data,symm_key->size);

	// Convert cert to blob 
	vtcm_template=memdb_get_template(DTYPE_VTCM_UTILS,SUBTYPE_TCM_PIK_CERT);
	if(vtcm_template==NULL)
		return -EINVAL;
	Memset(Buf,0,DIGEST_SIZE/2);
	ret=struct_2_blob(pik_cert,Buf+DIGEST_SIZE/2,vtcm_template);
	if(ret<0)
		return ret;
	//Crypt the cert blob with symm_key and write it 
	int offset=DIGEST_SIZE/2;
	int blobsize=ret;
    	sm4_context ctx;
	BYTE EncBuf[512];
	int Enclen=512;

	ret=blobsize%(DIGEST_SIZE/2);
	offset-=ret;
	blobsize+=offset;	
    	sm4_setkey_enc(&ctx, symm_key->data);
    	sm4_crypt_ecb(&ctx, 1, blobsize, Buf+ret,EncBuf);

    	fd=open(cert_file,O_CREAT|O_TRUNC|O_WRONLY,0666);
    	if(fd<0){
        	printf("cert file open error!\n");
        	return -EIO;     
    	}
    	print_bin_data(EncBuf,blobsize,8);
    	write(fd,EncBuf,blobsize);
    	close(fd);
		
	// Convert ca_conts to blob 
	vtcm_template=memdb_get_template(DTYPE_VTCM_IDENTITY,SUBTYPE_TCM_ASYM_CA_CONTENTS);
	if(vtcm_template==NULL)
		return -EINVAL;
	ret=struct_2_blob(&ca_conts,Buf,vtcm_template);
	if(ret<0)
		return ret;

	ret=GM_SM2Encrypt(EncBuf,&Enclen,Buf,ret,ekpub.pubKey.key,ekpub.pubKey.keyLength);
	if(ret!=0)	
	{
        	printf("pubek's SM2Encrypt is fail\n");
		return -EINVAL;	
	}

    	fd=open(symmkey_file,O_CREAT|O_TRUNC|O_WRONLY,0666);
    	if(fd<0){
        	printf("symmkey file open error!\n");
        	return -EIO;     
    	}
    	print_bin_data(EncBuf,Enclen,8);
    	write(fd,EncBuf,Enclen);
    	close(fd);

    	sprintf(Buf,"%d \n",ret);
   	void * send_msg =vtcm_auto_build_outputmsg(Buf,curr_recv_msg);
   	if(send_msg==NULL)
		return -EINVAL;
   	ex_module_sendmsg(sub_proc,send_msg);		

	return ret;
}

int proc_vtcmutils_ExDecryptPikCert(void * sub_proc, void * para){
  int i=1;
  int ret=0;
  char *keyfile=NULL;
  char *certfile=NULL;
  void * vtcm_template;
  struct tcm_utils_input * input_para=para;
  char * index_para;
  char * value_para;
  int returnCode=0;

  TCM_ASYM_CA_CONTENTS ca_conts;
  TCM_SYMMETRIC_KEY symmkey;
  TCM_PIK_CERT pik_cert;

  if((input_para->param_num>0) &&
	(input_para->param_num%2==1))
 {
	for(i=1;i<input_para->param_num;i+=2)
	{
        	index_para=input_para->params+i*DIGEST_SIZE;
        	value_para=index_para+DIGEST_SIZE;
		if(!Strcmp("-kf",index_para))
		{
			keyfile=value_para;
		}
		else if(!Strcmp("-cf",index_para))
		{
			certfile=value_para;
		}
		else
		{
			printf("Error cmd format! should be %s -kf keyfile -cf certfile",input_para->params);
			return -EINVAL;
		}
      } 
  }
  int fd;
  int keysize;

  int certsize;
  int offset;

  // readkey
  fd=open(keyfile,O_RDONLY);
  if(fd<0)
    return -EIO;
  ret=read(fd,Buf,DIGEST_SIZE*32+1);
  if(ret<0)
    return -EIO;
  if(ret>DIGEST_SIZE*32)
  {
    printf("key file too large!\n");
    return -EINVAL;
  }
  close(fd);

  //  load key
  vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_SYMMETRIC_KEY);
  if(vtcm_template==NULL)
      return -EINVAL;

  keysize=ret;

  ret=blob_2_struct(Buf,&symmkey,vtcm_template);
  if(ret<0||ret>keysize){
      printf("read key file error!\n");
      return -EINVAL;
  }
  // read cert
  fd=open(certfile,O_RDONLY);
  if(fd<0)
    return -EIO;

  ret=read(fd,Buf+DIGEST_SIZE*16,DIGEST_SIZE*16+1);
  if(ret<0)
    return -EIO;
  if(ret>DIGEST_SIZE*16)
  {
    printf("cert file too large!\n");
    return -EINVAL;
  }
  close(fd);
  certsize=ret;
  //  decrypt cert
  sm4_context ctx;
  
  sm4_setkey_dec(&ctx,symmkey.data);
  sm4_crypt_ecb(&ctx,0,certsize,Buf+DIGEST_SIZE*16,Buf);

  for(offset=0;offset<TCM_HASH_SIZE/2;offset++)
  {	
 	if(Buf[offset]!=0)
		break;
  }
  if(offset==TCM_HASH_SIZE)
	returnCode= -EINVAL;

  fd=open(certfile,O_CREAT|O_TRUNC|O_WRONLY,0666);
  if(fd<0){
          printf("cert file open error!\n");
          return -EIO;
  }
  write(fd,Buf+offset,certsize-offset);
  close(fd); 

    sprintf(Buf,"%d \n",returnCode);
    printf("Output para: %s\n",Buf);

    void * send_msg =vtcm_auto_build_outputmsg(Buf,curr_recv_msg);

  if(send_msg==NULL)
    return -EINVAL;

  ex_module_sendmsg(sub_proc,send_msg);		
  return ret;
}

int proc_vtcmutils_ExCAVerify(void * sub_proc, void * para){
  int i=1;
  int ret=0;
  char *certfile=NULL;
  void * vtcm_template;
  struct tcm_utils_input * input_para=para;
  char * index_para;
  char * value_para;

  TCM_KEY pik;
  TCM_ASYM_CA_CONTENTS ca_conts;
  TCM_PIK_CERT pik_cert;

  if((input_para->param_num>0) &&
	(input_para->param_num%2==1))
 {
	for(i=1;i<input_para->param_num;i+=2)
	{
        	index_para=input_para->params+i*DIGEST_SIZE;
        	value_para=index_para+DIGEST_SIZE;
		if(!Strcmp("-cf",index_para))
		{
			certfile=value_para;
		}
		else
		{
			printf("Error cmd format! should be %s -cf certfile",input_para->params);
			return -EINVAL;
		}
      } 
  }
  int fd;
  int keysize;

  int certsize;
  int signsize;

  // read cert
  fd=open(certfile,O_RDONLY);
  if(fd<0)
    return -EIO;

  ret=read(fd,Buf+DIGEST_SIZE*16,DIGEST_SIZE*16+1);
  if(ret<0)
    return -EIO;
  if(ret>DIGEST_SIZE*16)
  {
    printf("key file too large!\n");
    return -EINVAL;
  }
  close(fd);

  //  load cert

	vtcm_template=memdb_get_template(DTYPE_VTCM_UTILS,SUBTYPE_TCM_PIK_CERT);
	if(vtcm_template==NULL)
		return -EINVAL;

  certsize=ret;

  ret=blob_2_struct(Buf+DIGEST_SIZE*16,&pik_cert,vtcm_template);
  if(ret<0||ret>certsize){
      printf("read key file error!\n");
      return -EINVAL;
  }

  //  load key
  // proc_vtcmutils_ReadFile(keyLength,keyFile);
  // read data

    BYTE UserID[DIGEST_SIZE];
    unsigned long lenUID = DIGEST_SIZE;
    memset(UserID, 'A', 32);

    Memcpy(Buf,pik_cert.userDigest,DIGEST_SIZE);
    Memcpy(Buf+DIGEST_SIZE,pik_cert.pubDigest,DIGEST_SIZE);
    ret=GM_SM2VerifySig(pik_cert.signData,pik_cert.signLen,
		Buf,DIGEST_SIZE*2,
		UserID,lenUID,
		CApubkey, CApublen);

    sprintf(Buf,"%d \n",ret);
    printf("Output para: %s\n",Buf);

    void * send_msg =vtcm_auto_build_outputmsg(Buf,curr_recv_msg);

    if(send_msg==NULL)
        return -EINVAL;

    ex_module_sendmsg(sub_proc,send_msg);		
    return ret;
}

int proc_vtcmutils_ExVerify(void * sub_proc, void * para){
  TCM_KEY *keyOut;
  unsigned char *encData=NULL;
  int i=1;
  int ret=0;
  char *keyfile=NULL;
  char *datafile=NULL;
  char *signfile=NULL;
  void * vtcm_template;
  struct tcm_utils_input * input_para=para;
  char * index_para;
  char * value_para;

  if((input_para->param_num>0) &&
	(input_para->param_num%2==1))
 {
	for(i=1;i<input_para->param_num;i+=2)
	{
        	index_para=input_para->params+i*DIGEST_SIZE;
        	value_para=index_para+DIGEST_SIZE;
		if(!Strcmp("-kf",index_para))
		{
        		keyfile=value_para;
		}	
		else if(!Strcmp("-rf",index_para))
		{
			datafile=value_para;
		}
		else if(!Strcmp("-sf",index_para))
		{
			signfile=value_para;
		}
		else
		{
			printf("Error cmd format! should be %s -kf keyfile -rf datafile -sf signfile",input_para->params);
			return -EINVAL;
		}
      } 
  }
  int fd;
  int datasize;
  int signsize;
  fd=open(keyfile,O_RDONLY);
  if(fd<0)
    return -EIO;
  ret=read(fd,Buf,DIGEST_SIZE*32+1);
  if(ret<0)
    return -EIO;
  if(ret>DIGEST_SIZE*32)
  {
    printf("key file too large!\n");
    return -EINVAL;
  }
  close(fd);
  encData=(BYTE*)malloc(sizeof(BYTE)*512);
  int length=512;

  //  load key

  vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
  if(vtcm_template==NULL)
    return -EINVAL;

  datasize=ret;

  keyOut=Talloc0(sizeof(*keyOut));
  if(keyOut==NULL)
    return -ENOMEM;

  ret=blob_2_struct(Buf,keyOut,vtcm_template);
  if(ret<0||ret>datasize){
    printf("read key file error!\n");
    return -EINVAL;
  }

  // proc_vtcmutils_ReadFile(keyLength,keyFile);
  // read data
  fd=open(datafile,O_RDONLY);
  if(fd<0)
    return -EIO;
  ret=read(fd,Buf,DIGEST_SIZE*32+1);
  if(ret<0)
    return -EIO;
  if(ret>DIGEST_SIZE*32)
  {
    printf("read file too large!\n");
    return -EINVAL;     
  }
  close(fd);
  datasize=ret;

  // read sig
  fd=open(signfile,O_RDONLY);
  if(fd<0)
    return -EIO;
  BYTE * SignData=Buf+datasize+DIGEST_SIZE;
  ret=read(fd,SignData,DIGEST_SIZE*8+1);
  if(ret<0)
    return -EIO;
  if(ret>DIGEST_SIZE*8)
  {
    printf("read file too large!\n");
    return -EINVAL;     
  }
  close(fd);
  signsize=ret;
  // proc_vtcmutils_ReadFile(keyLength,keyFile);
  // read data

    BYTE UserID[DIGEST_SIZE];
    unsigned long lenUID = DIGEST_SIZE;
    memset(UserID, 'A', 32);

  ret=GM_SM2VerifySig(SignData,signsize,
		Buf,datasize,
		UserID,lenUID,
		keyOut->pubKey.key, keyOut->pubKey.keyLength);
  sprintf(Buf,"%d \n",ret);
  printf("Output para: %s\n",Buf);

  void * send_msg =vtcm_auto_build_outputmsg(Buf,curr_recv_msg);

  if(send_msg==NULL)
    return -EINVAL;

  ex_module_sendmsg(sub_proc,send_msg);		
  return ret;
}

int proc_vtcmutils_ExVerifyQuote(void * sub_proc, void * para){
  TCM_KEY *keyOut;
  unsigned char *encData=NULL;
  int i=1;
  int ret=0;
  char *keyfile=NULL;
  char *reportfile=NULL;
  TCM_QUOTE_INFO quoteinfo;
  void * vtcm_template;
  struct tcm_utils_input * input_para=para;
  char * index_para;
  char * value_para;

  if((input_para->param_num>0) &&
	(input_para->param_num%2==1))
 {
	for(i=1;i<input_para->param_num;i+=2)
	{
        	index_para=input_para->params+i*DIGEST_SIZE;
        	value_para=index_para+DIGEST_SIZE;
		if(!Strcmp("-kf",index_para))
		{
        		keyfile=value_para;
		}	
		else if(!Strcmp("-rf",index_para))
		{
			reportfile=value_para;
		}
		else
		{
			printf("Error cmd format! should be %s -kf keyfile -rf reportfile",input_para->params);
			return -EINVAL;
		}
      } 
  }
  int fd;
  int datasize;
  fd=open(keyfile,O_RDONLY);
  if(fd<0)
    return -EIO;
  ret=read(fd,Buf,DIGEST_SIZE*32+1);
  if(ret<0)
    return -EIO;
  if(ret>DIGEST_SIZE*32)
  {
    printf("key file too large!\n");
    return -EINVAL;
  }
  close(fd);
  encData=(BYTE*)malloc(sizeof(BYTE)*512);
  int length=512;

  //  load key

  vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
  if(vtcm_template==NULL)
    return -EINVAL;

  datasize=ret;

  keyOut=Talloc0(sizeof(*keyOut));
  if(keyOut==NULL)
    return -ENOMEM;

  ret=blob_2_struct(Buf,keyOut,vtcm_template);
  if(ret<0||ret>datasize){
    printf("read key file error!\n");
    return -EINVAL;
  }

  // read report data
  fd=open(reportfile,O_RDONLY);
  if(fd<0)
    return -EIO;
  ret=read(fd,Buf,DIGEST_SIZE*32+1);
  if(ret<0)
    return -EIO;
  if(ret>DIGEST_SIZE*32)
  {
    printf("read file too large!\n");
    return -EINVAL;     
  }
  close(fd);

  datasize=ret;

   // read quote info

   vtcm_template=memdb_get_template(DTYPE_VTCM_PCR,SUBTYPE_TCM_QUOTE_INFO);
   if(vtcm_template==NULL)
         return -EINVAL;
   ret=blob_2_struct(Buf,&quoteinfo,vtcm_template);
   if(ret<0)
	return ret;

   // get sign data
   
   int signsize;
   BYTE * signdata;
 
   signsize=*(int *)(Buf+ret);
   if(datasize-signsize!=ret+sizeof(int))
	return -EINVAL;
   signdata=Buf+ret+sizeof(int);  
   datasize=ret;	
  // verify signdata 

    BYTE UserID[DIGEST_SIZE];
    unsigned long lenUID = DIGEST_SIZE;
    memset(UserID, 'A', 32);

   

  ret=GM_SM2VerifySig(signdata,signsize,
		Buf,datasize,
		UserID,lenUID,
		keyOut->pubKey.key, keyOut->pubKey.keyLength);
  sprintf(Buf,"%d \n",ret);
  printf("Output para: %s\n",Buf);

  void * send_msg =vtcm_auto_build_outputmsg(Buf,curr_recv_msg);

  if(send_msg==NULL)
    return -EINVAL;

  ex_module_sendmsg(sub_proc,send_msg);		
  return ret;
}

int proc_vtcmutils_ExCheckQuotePCR(void * sub_proc, void * para){

  int i=1;
  int ret=0;
  char *pcrfile=NULL;
  char *quoteinfofile=NULL;
  TCM_QUOTE_INFO quoteinfo;
  TCM_PCR_COMPOSITE pcrinfo;
  BYTE checkdata[TCM_HASH_SIZE];
  void * vtcm_template;
  struct tcm_utils_input * input_para=para;
  char * index_para;
  char * value_para;

  if((input_para->param_num>0) &&
	(input_para->param_num%2==1))
 {
	for(i=1;i<input_para->param_num;i+=2)
	{
        	index_para=input_para->params+i*DIGEST_SIZE;
        	value_para=index_para+DIGEST_SIZE;
		if(!Strcmp("-pf",index_para))
		{
        		pcrfile=value_para;
		}	
		else if(!Strcmp("-rf",index_para))
		{
			quoteinfofile=value_para;
		}
		else
		{
			printf("Error cmd format! should be %s -kf keyfile -rf reportfile",input_para->params);
			return -EINVAL;
		}
      } 
  }
  int fd;
  int datasize;

  // read pcr info
  fd=open(pcrfile,O_RDONLY);
  if(fd<0)
    return -EIO;
  ret=read(fd,Buf,DIGEST_SIZE*32+1);
  if(ret<0)
    return -EIO;
  if(ret>DIGEST_SIZE*32)
  {
    printf("key file too large!\n");
    return -EINVAL;
  }
  close(fd);

  vtcm_template=memdb_get_template(DTYPE_VTCM_PCR,SUBTYPE_TCM_PCR_COMPOSITE);
  if(vtcm_template==NULL)
    return -EINVAL;

  ret=blob_2_struct(Buf,&pcrinfo,vtcm_template);
  if(ret<0)
	return ret;
  sm3(Buf,ret,checkdata);

  // read report data
  fd=open(quoteinfofile,O_RDONLY);
  if(fd<0)
    return -EIO;
  ret=read(fd,Buf,DIGEST_SIZE*32+1);
  if(ret<0)
    return -EIO;
  if(ret>DIGEST_SIZE*32)
  {
    printf("read file too large!\n");
    return -EINVAL;     
  }
  close(fd);

   // read quote info

   vtcm_template=memdb_get_template(DTYPE_VTCM_PCR,SUBTYPE_TCM_QUOTE_INFO);
   if(vtcm_template==NULL)
         return -EINVAL;
   ret=blob_2_struct(Buf,&quoteinfo,vtcm_template);
   if(ret<0)
	return ret;

   // compare checkdata and digest in report

   if(Memcmp(checkdata,&quoteinfo.info.digestAtCreation,TCM_HASH_SIZE)==0)
	ret=0;
   else
	ret=1;
   
  sprintf(Buf,"%d \n",ret);
  printf("Output para: %s\n",Buf);

  void * send_msg =vtcm_auto_build_outputmsg(Buf,curr_recv_msg);

  if(send_msg==NULL)
    return -EINVAL;

  ex_module_sendmsg(sub_proc,send_msg);		
  return ret;
}
