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
#include "tcm_error.h"
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

UINT32 TCM_ExSM2Encrypt(TCM_PUBKEY * pubkey,BYTE * out, int * out_len,BYTE * in ,int in_len)
{
  int i=1;
  int ret=0;
  int fd;
  int datasize;

  //  load key

  // proc_vtcmutils_ReadFile(keyLength,keyFile);
  // read data

  *out_len=in_len+65+32+4;
  ret = GM_SM2Encrypt(out,out_len,in,in_len,pubkey->pubKey.key,pubkey->pubKey.keyLength);
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

int TCM_ExCAPikReqVerify(TCM_PUBKEY * pik, BYTE * userinfo,int userinfolen,
	 BYTE * reqdata, int reqdatalen)
{
	int ret;
	TCM_IDENTITY_CONTENTS ca_contents;
	void * vtcm_template;


	//  cmd's params
    	printf("Begin ex CA Pik Req Verify:\n");
	// build TCM_IDENTITY_CONTENTS struct
	
	Memset(&ca_contents,0,sizeof(ca_contents));
	ca_contents.ver.major=1;
	ca_contents.ver.minor=1;
	ca_contents.ordinal = SUBTYPE_MAKEIDENTITY_IN;
	Memcpy(ExBuf,userinfo,userinfolen);
	Memcpy(ExBuf+userinfolen,CApubkey,64);
//	print_bin_data(ExBuf,userinfolen+64,16);

	calculate_context_sm3(ExBuf,userinfolen+64,ca_contents.labelPrivCADigest.digest);
//	print_bin_data(ca_contents.labelPrivCADigest.digest,32,16);
	
	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_PUBKEY);
	if(vtcm_template==NULL)
		return -EINVAL;	

        ret=struct_clone(pik,&ca_contents.identityPubKey,vtcm_template);
	if(ret<0)
		return ret;

        //compute cert blob 
        vtcm_template=memdb_get_template(DTYPE_VTCM_IDENTITY,SUBTYPE_TCM_IDENTITY_CONTENTS);
        if(vtcm_template==NULL)
                return -EINVAL;
        ret=struct_2_blob(&ca_contents,ExBuf,vtcm_template);
        if(ret<0)
                return -EINVAL;

	// Verify with CA
	BYTE UserID[DIGEST_SIZE];
        unsigned long lenUID=DIGEST_SIZE;
        Memset(UserID,'A',32);

//	print_bin_data(ExBuf,ret,16);
//	print_bin_data(reqdata,reqdatalen,16);
//	print_bin_data(pik->pubKey.key,pik->pubKey.keyLength,16);

	ret=GM_SM2VerifySig(reqdata,(UINT64)reqdatalen,ExBuf,(UINT64)ret,
		UserID,(UINT64)lenUID,pik->pubKey.key,(UINT64)pik->pubKey.keyLength);
	if(ret<0)
	{
		printf("Verify Sig Data failed!\n");
		return TCM_BAD_SIGNATURE;
	}	
	
	return 0;
}

int TCM_ExGetPubkeyFromTcmkey(TCM_PUBKEY * pubkey,TCM_KEY * tcmkey)
{
	int ret;
	void * tcm_key_template;

	tcm_key_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY_PARMS);
	ret=struct_clone(&tcmkey->algorithmParms,&pubkey->algorithmParms,tcm_key_template);
	if(ret<0)
		return TCM_BAD_PARAMETER;

	tcm_key_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_STORE_PUBKEY);
	ret=struct_clone(&tcmkey->pubKey,&pubkey->pubKey,tcm_key_template);
	if(ret<0)
		return TCM_BAD_PARAMETER;
	return 0;
}

int TCM_ExSaveTcmKey(TCM_KEY * tcmkey,char * keyfile)
{
	int fd;
	int ret;
	int keylen;
	void * tcm_key_template;
	if(tcmkey==NULL)
		return TCM_BAD_PARAMETER;


	tcm_key_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
	if(tcm_key_template ==NULL)
		return TCM_BAD_PARAMETER;

	ret=struct_2_blob(tcmkey,ExBuf,tcm_key_template);
	if(ret<0)
		return TCM_BAD_PARAMETER;
	keylen=ret;

	fd=open(keyfile,O_CREAT|O_TRUNC|O_WRONLY,0666);
	if(fd<0)
		return -EIO;	

	ret=write(fd,ExBuf,keylen);
	if(ret!=keylen)
	{
		printf("write prikey file error!\n");
		return -EIO;	
	}

	close(fd);
	
	return 0;
}

int TCM_ExSaveTcmPubKey(TCM_PUBKEY * pubkey,char * keyfile)
{
	int fd;
	int ret;
	int keylen;
	void * tcm_key_template;
	if(pubkey==NULL)
		return TCM_BAD_PARAMETER;


	tcm_key_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_PUBKEY);
	if(tcm_key_template ==NULL)
		return TCM_BAD_PARAMETER;

	ret=struct_2_blob(pubkey,ExBuf,tcm_key_template);
	if(ret<0)
		return TCM_BAD_PARAMETER;
	keylen=ret;

	fd=open(keyfile,O_CREAT|O_TRUNC|O_WRONLY,0666);
	if(fd<0)
		return -EIO;	

	ret=write(fd,ExBuf,keylen);
	if(ret!=keylen)
	{
		printf("write tcm pubkey file error!\n");
		return -EIO;	
	}

	close(fd);
	
	return 0;
}

int TCM_ExLoadTcmKey(TCM_KEY * tcmkey, char * keyfile)
{
	int fd;
	int ret;
	int keylen;
	void * tcm_key_template;


	fd=open(keyfile,O_RDONLY);
        if(fd<0)
		return -EIO;	
	
	ret=read(fd,ExBuf,DIGEST_SIZE*32+1);
	if(ret<0)
	{
		printf("read  tcm key file error!\n");
		return -EIO;	
	}
	close(fd);
	keylen=ret;

	tcm_key_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
	if(tcm_key_template ==NULL)
		return TCM_BAD_PARAMETER;

	ret=blob_2_struct(ExBuf,tcmkey,tcm_key_template);
	if(ret<0)
		return TCM_BAD_PARAMETER;
	if(ret>keylen)
	{
		printf("tcm key convert failed!\n");
		return TCM_BAD_PARAMETER;
	}

	return 0;
}

int TCM_ExLoadTcmPubKey(TCM_PUBKEY * pubkey, char * keyfile)
{
	int fd;
	int ret;
	int keylen;
	void * tcm_key_template;


	fd=open(keyfile,O_RDONLY);
        if(fd<0)
		return -EIO;	
	
	ret=read(fd,ExBuf,DIGEST_SIZE*32+1);
	if(ret<0)
	{
		printf("read  tcm key file error!\n");
		return -EIO;	
	}
	close(fd);
	keylen=ret;

	tcm_key_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_PUBKEY);
	if(tcm_key_template ==NULL)
		return TCM_BAD_PARAMETER;

	ret=blob_2_struct(ExBuf,pubkey,tcm_key_template);
	if(ret<0)
		return TCM_BAD_PARAMETER;
	if(ret>keylen)
	{
		printf("tcm pubkey convert failed!\n");
		return TCM_BAD_PARAMETER;
	}

	return 0;
}

int TCM_ExCAPikCertSign(TCM_PUBKEY * pubek, TCM_PUBKEY * pik, BYTE * certdata,int certdatalen,
	 BYTE ** cert,int * certlen,BYTE ** symmkeyblob, int * symmkeybloblen)
{
	int ret;
	int i;
	void * vtcm_template;
	TCM_ASYM_CA_CONTENTS ca_conts;
	TCM_SYMMETRIC_KEY * symm_key=&ca_conts.sessionKey;
	TCM_PIK_CERT * pik_cert;


	//  cmd's params
    	printf("Begin ex CA Pik Cert Sign:\n");
	// build TCM_IDENTITY_CONTENTS struct
	
    	if(CAprikey==NULL)
    	{
		printf("can't find CA's private key!\n");
		return -EINVAL;
    	}
	
	BYTE SignBuf[DIGEST_SIZE*4];	
    	BYTE UserID[DIGEST_SIZE];
    	unsigned long lenUID = DIGEST_SIZE;
    	Memset(UserID, 'A', 32);
	
	pik_cert=Talloc0(sizeof(*pik_cert));
	if(pik_cert==NULL)
		return -ENOMEM;
	pik_cert->payLoad=0x19;   // add pik_cert's payload

	calculate_context_sm3(certdata,certdatalen,pik_cert->userDigest);
	
        // compute pik's digest

	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_STORE_PUBKEY);
	if(vtcm_template==NULL)
		return -EINVAL;	
       ret=struct_2_blob(&pik->pubKey,ExBuf,vtcm_template);
       if(ret<0)
		return ret;
	calculate_context_sm3(ExBuf,ret,pik_cert->pubDigest);		
	Memcpy(ca_conts.idDigest.digest,pik_cert->pubDigest,DIGEST_SIZE);

	// Sign the pik_cert
	Memcpy(ExBuf,pik_cert->userDigest,DIGEST_SIZE);
	Memcpy(ExBuf+DIGEST_SIZE,pik_cert->pubDigest,DIGEST_SIZE);
	
	pik_cert->signLen=DIGEST_SIZE*4;

	GM_SM2Sign(SignBuf,&pik_cert->signLen,
		ExBuf,DIGEST_SIZE*2,
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
	Memset(ExBuf,0,DIGEST_SIZE/2);
	ret=struct_2_blob(pik_cert,ExBuf+DIGEST_SIZE/2,vtcm_template);
	if(ret<0)
		return ret;
	//Crypt the cert blob with symm_key and duplicate it 
	int offset=DIGEST_SIZE/2;
	int blobsize=ret;
    	sm4_context ctx;
	int Enclen=512;

	BYTE EncBuf[512];

	ret=blobsize%(DIGEST_SIZE/2);
	offset-=ret;
	blobsize+=offset;	
    	sm4_setkey_enc(&ctx, symm_key->data);
    	sm4_crypt_ecb(&ctx, 1, blobsize, ExBuf+ret,EncBuf);

	*cert=Talloc0(blobsize);
	if(*cert==NULL)
		return -ENOMEM;
	Memcpy(*cert,EncBuf,blobsize);
	*certlen=blobsize;

	// Convert ca_conts to blob 
	vtcm_template=memdb_get_template(DTYPE_VTCM_IDENTITY,SUBTYPE_TCM_ASYM_CA_CONTENTS);
	if(vtcm_template==NULL)
		return -EINVAL;
	ret=struct_2_blob(&ca_conts,ExBuf,vtcm_template);
	if(ret<0)
		return ret;
	int plainlen=ret;
  	Enclen=512;
	//Memset(EncBuf,0,Enclen);
	ret=GM_SM2Encrypt(EncBuf,&Enclen,ExBuf,ret,pubek->pubKey.key,pubek->pubKey.keyLength);
	if(ret!=0)	
	{
        	printf("pubek's SM2Encrypt is fail\n");
		return -EINVAL;	
	}
	blobsize=Enclen;
/*
 // for test
       int datalen=DIGEST_SIZE*16;
// decrypt the encData 
       BYTE ekpri[32] = {
		0xd4,0xea,0xec,0x69,0xd5,0x44,0xbb,0x48, 
		0xf3,0x64,0x1a,0xc3,0x12,0xc6,0x31,0xa7, 
		0xc4,0x91,0x72,0xd0,0xe6,0xf7,0xa8,0x7c, 
		0x81,0x15,0x4a,0x7e,0x55,0x9d,0x17,0xa0
	};

        BYTE TestBuf1[DIGEST_SIZE*16];
        BYTE TestBuf2[DIGEST_SIZE*16];
        BYTE TestBuf3[DIGEST_SIZE*16];
        int cryptlen,decryptlen;
        Memset(TestBuf1,'A',plainlen);
        Memset(TestBuf1,0,3);
        cryptlen=DIGEST_SIZE*16;
        decryptlen=DIGEST_SIZE*16;
        print_bin_data(pubek->pubKey.key,pubek->pubKey.keyLength,16);

        //ret=GM_SM2Encrypt(TestBuf2,&cryptlen,TestBuf1,plainlen,pubek->pubKey.key,pubek->pubKey.keyLength);
        ret=GM_SM2Encrypt(TestBuf2,&cryptlen,ExBuf,plainlen,pubek->pubKey.key,pubek->pubKey.keyLength);
        if(ret!=0)
        {
                printf("pubek's SM2Encrypt test is fail %d\n",ret);
                return -EINVAL;
        }

       ret=GM_SM2Decrypt(TestBuf3,&decryptlen, TestBuf2,cryptlen,ekpri,32);
        if(ret!=0)
        {
                printf("pubek's SM2Decrypt test is fail %d\n",ret);
                return -EINVAL;
        }



	BYTE TestBuf[DIGEST_SIZE*16];	
       //ret=GM_SM2Decrypt(TestBuf3,&datalen, TestBuf2,blobsize,  ekpri,32);
        ret=GM_SM2Decrypt(TestBuf3,&datalen, EncBuf,blobsize,ekpri,32);
	if(ret!=0)	
	{
        	printf("Test symmkey decrypt failed %d!\n",ret);
		return ret;	
	}
*/

	*symmkeyblob=Talloc0(blobsize);
	if(*symmkeyblob==NULL)
		return -ENOMEM;
	Memcpy(*symmkeyblob,EncBuf,blobsize);
	*symmkeybloblen=blobsize;

	return 0;
}

int TCM_ExSymmkeyDecrypt(TCM_SYMMETRIC_KEY * symmkey, BYTE * blob,int blobsize,
	BYTE ** output, int * outputsize)
{

    	sm4_context ctx;
    	sm4_setkey_dec(&ctx, symmkey->data);
    	sm4_crypt_ecb(&ctx, 0, blobsize, blob,ExBuf);

        
	*output=Talloc0(blobsize);
	if(*output==NULL)
		return -ENOMEM;
	Memcpy(*output,ExBuf,blobsize);
	*outputsize=blobsize;
	return 0;
}

int TCM_ExCAPubKeyVerify(BYTE * signData, int signdatalen,
	BYTE *verifydata, int datalen)
{
    BYTE UserID[DIGEST_SIZE];
    unsigned long lenUID = DIGEST_SIZE;
    memset(UserID, 'A', 32);
    BYTE VerifyBuf[DIGEST_SIZE*2];
    if(CApubkey==NULL)
	return -EINVAL;

    return GM_SM2VerifySig(signData,signdatalen,
		verifydata,datalen,
		UserID,lenUID,
		CApubkey, 64);
    // check user Digest
	
}
