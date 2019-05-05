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

char * prikeyfile="CApri.key";
char * pubkeyfile="CApub.key";
char * pikreqfile="pikreq.blob";
char * pikfile = "pik.key";
char * pik_pubfile = "pik_pub.key";
char * ek_pubfile = "ek_pub.key";
char * certblobfile = "pikcert.blob";
char * symmkeyblobfile="symmkey.blob";

BYTE ekpri[32] = {16,32,245,89,177,94,69,158,235,23,43,169,102,90,59,242,70,130,186,125,69,
			101,179,249,202,33,64,52,1,83,88,223};

int main(int argc,char **argv)
{

    int ret;
    int fd;	   

    int i,j;
    TCM_PUBKEY pik_pub;	
    TCM_PUBKEY ek_pub;	
     int userinfolen=10;
    BYTE * userinfo = "for test!";	
    int reqlen;	
    BYTE Buf[DIGEST_SIZE*64];


    ret=_TSMD_Init();

    ret= TCM_LibInit(); 


    ret=TCM_ExLoadCAPriKey(prikeyfile);
    if(ret!=0)
    {
		printf("TCM_ExLoadCAPriKey failed!\n");
		return -EINVAL;	
    }	
		
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

    ret=TCM_ExLoadTcmPubKey(&ek_pub,ek_pubfile);
    if(ret!=0)
    {
		printf("TCM_ExLoadTcmPubKey failed!\n");
		return -EINVAL;	
    }	

    fd=open(pikreqfile,O_RDONLY);
    if(fd<0)
	  return -EIO;	
    ret=read(fd,Buf,DIGEST_SIZE*16);
    if(ret<0)
    {
		printf("read pik req file error!\n");
		return -EIO;	
    }
    reqlen=ret;

    ret=TCM_ExCAPikReqVerify(&pik_pub,userinfo,userinfolen,
	Buf,reqlen);
    if(ret<0)
    {
		printf("verify pik req error!\n");
		return TCM_BAD_SIGNATURE;	
    }
   
    char * certdata = "test cert data, only for test, it should has user info, pik info and signature \n";
    int certdatalen=Strlen(certdata);
    BYTE * cert;
    int certlen;
    BYTE * symmkeyblob;
    int symmkeybloblen;	 
	
    ret= TCM_ExCAPikCertSign(&ek_pub,&pik_pub, certdata, certdatalen,
	&cert,&certlen,&symmkeyblob,&symmkeybloblen);
    if(ret<0)
    {
		printf("CA sign cert failed!\n");
		return TCM_BAD_SIGNATURE;	
    }

    fd=open(certblobfile,O_CREAT|O_TRUNC|O_WRONLY,0666);
    if(fd<0)
	  return -EIO;	
    ret=write(fd,cert,certlen);
    if(ret<0)
    {
		printf("write pik cert file error!\n");
		return ret;	
    }

    close(fd);

    int datalen=DIGEST_SIZE*16;
// decrypt the encData 
    ret=GM_SM2Decrypt(Buf,&datalen, symmkeyblob,symmkeybloblen,
	ekpri,32);



    fd=open(symmkeyblobfile,O_CREAT|O_TRUNC|O_WRONLY,0666);
    if(fd<0)
	  return -EIO;	
    ret=write(fd,symmkeyblob,symmkeybloblen);
    if(ret<0)
    {
		printf("write symm key blob len error!\n");
		return ret;	
    }

    close(fd);

    return ret;	

}

