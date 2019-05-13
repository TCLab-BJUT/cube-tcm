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
#include "sm2.h"
#include "tcmfunc.h"
#include "tcm_error.h"
#include "vtcm_alg.h"

char * pubkeyfile="CApub.key";
char * pik_pubfile = "pik_pub.key";
char * certfile = "pik.cert";

int main(int argc,char **argv)
{

    int ret;
    int fd;	   

    int i,j;
    TCM_PUBKEY pik_pub;	
    TCM_PIK_CERT pik_cert;
    void * vtcm_template;

    char * certdata = "test cert data, only for test, it should has user info, pik info and signature \n";
    int certdatalen=Strlen(certdata);

    BYTE Buf[DIGEST_SIZE*64];
    BYTE comp_Digest[DIGEST_SIZE];


    ret=_TSMD_Init();

    ret= TCM_LibInit(); 

    ret=TCM_ExLoadCAPubKey(pubkeyfile);
    if(ret!=0)
    {
		printf("TCM_ExLoadCAPubKey failed!\n");
		return -EINVAL;	
    }	

    ret=TCM_ExLoadTcmPubKey(&pik_pub,pik_pubfile);
    if(ret!=0)
    {
		printf("TCM_ExLoadTcmPubKey failed!\n");
		return -EINVAL;	
    }	

    // read pik_cert data
    // TCM_PIK_CERT's type&subtype :( VTCM_UTILS","TCM_PIK_CERT")
    // struct_element:
    // [
    //      {"name":"payload","type":"UCHAR"},
    //      {"name":"userDigest","type":"BINDATA","size":"32"},
    //      {"name":"pubDigest","type":"BINDATA","size":"32"},
    //      {"name":"signLen","type":"INT"},
    //      {"name":"signData","type":"DEFINE","def":"signLen"}
    // ]                                                                                                                                                            ]
    Memset(Buf,0,DIGEST_SIZE*16);
    fd=open(certfile,O_RDONLY);
    if(fd<0)
	  return -EIO;	
    ret=read(fd,Buf,DIGEST_SIZE*16);
    if(ret<0)
    {
		printf("read pik cert file error!\n");
		return -EIO;	
    }

    vtcm_template=memdb_get_template(DTYPE_VTCM_UTILS,SUBTYPE_TCM_PIK_CERT);
    if(vtcm_template==NULL)
	return -EINVAL;
    ret=blob_2_struct(Buf,&pik_cert,vtcm_template);
    if(ret<0)
	return ret;

    // verify pik cert data

    Memcpy(Buf,pik_cert.userDigest,DIGEST_SIZE);
    Memcpy(Buf+DIGEST_SIZE,pik_cert.pubDigest,DIGEST_SIZE);

    ret=TCM_ExCAPubKeyVerify(pik_cert.signData,pik_cert.signLen,
		Buf,DIGEST_SIZE*2);
    if(ret!=0)
    {
	printf("verify pik_cert's sign  failed!\n");
    }

    // check user Digest

    calculate_context_sm3(certdata,certdatalen,comp_Digest);

    if(Memcmp(comp_Digest,pik_cert.userDigest,DIGEST_SIZE)!=0)
    {	
	printf("check user info failed!\n");
	return -EINVAL;
    }
    // check pubkey digest
    vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_STORE_PUBKEY);
    if(vtcm_template==NULL)
	return -EINVAL;	
    ret=struct_2_blob(&pik_pub.pubKey,Buf,vtcm_template);
    if(ret<0)
	return ret;
    calculate_context_sm3(Buf,ret,comp_Digest);		
    if(Memcmp(comp_Digest,pik_cert.pubDigest,DIGEST_SIZE)!=0)
    {
	printf("check pik's pubkey digest failed!\n");
	return -EINVAL;
    }

    printf("Verify pik cert success!\n");
    
    return ret;	

}

