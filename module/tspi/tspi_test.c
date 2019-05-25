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
#include "tsm_structs.h"
//#include "sm3.h"
//#include "sm4.h"
#include "tspi.h"

int main(int argc,char **argv)
{

    int ret;
    int i;
    TSM_HCONTEXT hContext;
    TSM_HTCM hTCM;
    TSM_HPCRS hPcrComposite;
    TSM_HKEY hSMK;
    TSM_HKEY hKey;
    TSM_HPOLICY hPolicy;
    TSM_HPOLICY hSmkPolicy;

    int PcrLength;
    BYTE * PcrValue;

	
    ret=Tspi_Context_Create(&hContext);     
    if(ret!=TSM_SUCCESS)
    {
	printf("Tspi_Context_Create Error!\n");
	return ret;
    }

    printf("hContext is %x!\n",hContext);

    ret= Tspi_Context_GetTcmObject(hContext,&hTCM);
    if(ret!=TSM_SUCCESS)
    {
	printf("Tspi_Context_GetTcmObject Error!\n");
	return ret;
    }
    printf("hTCM is %x!\n",hTCM);

    BYTE * RandomData;

    ret= Tspi_TCM_GetRandom(hTCM,16,&RandomData);
    if(ret!=TSM_SUCCESS)
    {
	printf("Tspi_Context_GetRandom Error!\n");
	return ret;
    }

    printf("Random Data is :");
    for(i=0;i<16;i++)
    	printf("%2.2x ",RandomData[i]);
    printf("\n");
   
    ret=Tspi_Context_LoadKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,TSM_UUID_SMK,&hSMK);
    if(ret!=TSM_SUCCESS)
    {     
      printf("Tspi_Context_LoadKeyByUUID Error!\n");
        return ret;
    }
    printf("start Load SMK !\n");

    ret=Tspi_GetPolicyObject(hSMK,0,&hSmkPolicy);
    if(ret!=TSM_SUCCESS)
    {
        printf("Tspi_Context_LoadKeyByUUID Error!\n");
        return ret;
    }
    printf("start GetPolicyObject !\n");

    ret=Tspi_Policy_SetSecret(hSmkPolicy,TSM_SECRET_MODE_NONE,0,"sss");
    if(ret!=TSM_SUCCESS)
    {
	printf("Tspi_Policy_SetSecret Error!\n");
	return ret;
    }
    printf("start setSecret for SMK\n");

    ret=Tspi_Context_CreateObject(hContext,TSM_OBJECT_TYPE_KEY,0,&hKey);
    if(ret!=TSM_SUCCESS)
    {
	printf("Tspi_TCM_Context_CreateObject Error!\n");
	return ret;
    }
    printf("start createObject_KEY for coming createKey\n");
    
    ret=Tspi_Context_CreateObject(hContext,TSM_OBJECT_TYPE_POLICY,0,&hPolicy);
    if(ret!=TSM_SUCCESS)
    {
	printf("Tspi_TCM_Context_CreateObject Error!\n");
	return ret;
    }
    printf("start createObject_POLICY for coming createKey\n");

    ret=Tspi_Policy_SetSecret(hPolicy,TSM_SECRET_MODE_NONE,0,"kkk");
    if(ret!=TSM_SUCCESS)
    {
	printf("Tspi_Policy_SetSecret Error!\n");
	return ret;
    }
    printf("start setSecret\n");

    ret=Tspi_Policy_AssignToObject(hPolicy,hKey);
    if(ret!=TSM_SUCCESS)
    {
	printf("Tspi_Policy_AssignToObject Error!\n");
	return ret;
    }
    printf("start AssignToObject\n");
   
    ret=Tspi_Key_CreateKey(hKey,hSMK,0);
    if(ret!=TSM_SUCCESS)
    {
	printf("Tspi_Key_CreateKey Error!\n");
	return ret;
    }
    printf("start createKey\n");

    return 0;	
}


