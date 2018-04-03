#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "data_type.h"
#include "errno.h"
#include "alloc.h"
#include "string.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "ex_module.h"
#include "sys_func.h"
 
#include "file_struct.h"
#include "vtcm_nv.h"

#include "app_struct.h"
#include "tcm_global.h"
#include "tcm_error.h"


#define TCM_TAG_NV_DATA_PUBLIC 0x0018
#define TCM_TAG_NV_DATA_SENSITIVE 0x0019
#define TCM_NV_INDEX_COUNT 20
#define TCM_NV_INDEX_LOCK 0xFFFFFFFF

static BYTE Buf[DIGEST_SIZE*32];
//int TCM_NVIndexEntries_GetEntry(TCM_NV_DATA_SENSITIVE **tcm_nv_data_sensitive, struct vtcm_nv_scene *nv_scene, int index);
//void TCM_NVDataSensitive_Delete(TCM_NV_DATA_SENSITIVE *tcm_nv_data_sensitive);

int vtcm_nv_init(void * sub_proc,void * para){

    tcm_state_t *tcm_instances = proc_share_data_getpointer();

    ex_module_setpointer(sub_proc, &tcm_instances[0]);

    return 0;
}

int vtcm_nv_start(void * sub_proc,void * para)
{

	int ret;
	void * recv_msg;
	void * context;
	int i;
    	int type, subtype;
    	BYTE uuid[DIGEST_SIZE];
    	int vtcm_no; 
 
	printf("vtcm_nv module start!\n");
 
	for(i=0;i<300*1000;i++)
	{
        	usleep(time_val.tv_usec);
        	ret = ex_module_recvmsg(sub_proc, &recv_msg);
        	if (ret < 0 || recv_msg == NULL)
            		continue;

        	type = message_get_type(recv_msg);
        	subtype = message_get_subtype(recv_msg);
 		// set vtcm instance
     		vtcm_no = vtcm_setscene(sub_proc,recv_msg);
     		if(vtcm_no<0)
     		{
 			printf("Non_exist vtcm copy!\n");
     		}

		if((type==DTYPE_VTCM_IN)&&(subtype==SUBTYPE_NV_DEFINESPACE_IN))
		{
			proc_vtcm_NvDefinespace(sub_proc,recv_msg);
		}
		else if((type==DTYPE_VTCM_IN)&&(subtype==SUBTYPE_NV_WRITEVALUE_IN))
		{
			proc_vtcm_writevalue(sub_proc,recv_msg);
		}
		else if((type==DTYPE_VTCM_IN)&&(subtype==SUBTYPE_NV_READVALUE_IN))
		{
			proc_vtcm_readvalue(sub_proc,recv_msg);
		}
	}
	return 0;
}

int vtcm_Authdata_Check(struct vtcm_nv_scene *nv_scene, 
                        TCM_SECRET hmacKey,
                        TCM_DIGEST inParamDigest,
                        TCM_SESSION_DATA *tcm_session_data,
                        BYTE ownerAuth
                       )
{
    TCM_RESULT rc = 0;
    TCM_BOOL valid;
    int result;

    printf("TCM_Authdata_Check:");

    result = memcmp(ownerAuth, hmacKey, TCM_DIGEST_SIZE);
     if(result == 0){
            valid = TRUE;
            
    }
     else{
             valid = FALSE;
       
    }

    if(rc ==0){
        if(!valid){
            printf(" Error, authorization failed!");
            rc = TCM_AUTHFAIL;
        }
    }
    printf("\n");
    return rc;
}

int proc_vtcm_NvDefinespace(void *sub_proc, void *recv_msg)
{
	printf("proc_vtcm_definespace: Start\n");
	int ret = 0;
 	int i = 0;
        TCM_SESSION_DATA *authSession;
	tcm_state_t *curr_tcm = ex_module_getpointer(sub_proc);
	struct tcm_in_NV_DefineSpace *vtcm_in;
	struct tcm_out_NV_DefineSpace *vtcm_out;
	void *send_msg;	
        TCM_BOOL ignore_auth = FALSE;
        TCM_BOOL done = FALSE;
        TCM_RESULT returnCode = TCM_SUCCESS;
        TCM_BOOL foundOld = FALSE;
        TCM_SECRET *hmacKey = NULL;
        TCM_DIGEST inParamDigest;
        TCM_BOOL physicalPresence;
        TCM_BOOL nv1Incremented;
        int nv1 = curr_tcm->tcm_permanent_data.noOwnerNVWrite;
        TCM_NV_DATA_SENSITIVE *nv_sens;
        TCM_BOOL writeAllNV = FALSE;
        TCM_BOOL writeLocalities = FALSE;
        TCM_DIGEST nvAuth;
        BYTE CheckData[TCM_HASH_SIZE];
	void * vtcm_template;

    /*
     * Get input params
     */
	ret = message_get_record(recv_msg,&vtcm_in,0);
	if(ret < 0)
		return ret;
	if(vtcm_in == NULL)
		return -EINVAL;	
	int index = vtcm_in->pubInfo.nvIndex;
	int size = vtcm_in->pubInfo.dataSize;
	int tag = vtcm_in->pubInfo.tag;

	/*
     * processing
     */
    // 1
	printf("======Processing DefineSpace=========\n");
    if((returnCode == TCM_SUCCESS) && (vtcm_in->pubInfo.nvIndex == TCM_NV_INDEX_LOCK) && (vtcm_in->tag == TCM_TAG_RQU_COMMAND)){
        curr_tcm->tcm_permanent_flags.nvLocked = TRUE;
        printf("Set nvLocked to TRUE\n");
        /*return TCM_SUCESS*/
        done = TRUE;
    }

    // 2
     
    if((curr_tcm->tcm_permanent_flags.nvLocked == FALSE)){
        printf("nvLocked is FLASE, checks except for the Max NV writes are ignored");
        ignore_auth = TRUE;
    }

    if(vtcm_in->pubInfo.nvIndex == TCM_NV_INDEX0){
        printf("Error, bad index %d\n",index);
        returnCode = TCM_BADINDEX;
	goto nv_definespace_out;
    }

    // 3 
    if( !done && !ignore_auth){
        if(vtcm_in->pubInfo.nvIndex & TCM_NV_INDEX_D_BIT){
            printf("Error, bad index %d\n",vtcm_in->pubInfo.nvIndex);
            returnCode = TCM_BADINDEX;
	    goto nv_definespace_out;
        }
    }
    // 4 a.Validate ownerAuth
    if (ret == TCM_SUCCESS) 
    {
      ret = vtcm_Compute_AuthCode(vtcm_in, 
                                  DTYPE_VTCM_IN, 
                                  SUBTYPE_NV_DEFINESPACE_IN, 
                                  authSession, 
                                  CheckData);
    }
    if(ret == TCM_SUCCESS) 
    {
      if(memcmp(CheckData, vtcm_in->ownerAuth, TCM_HASH_SIZE) != 0)
      {
        ret = TCM_AUTHFAIL;
        printf("\nerror! compare authcode error\n");
      }
    }
    if(vtcm_in->tag == TCM_TAG_RQU_AUTH1_COMMAND)
    {
        returnCode = vtcm_AuthSessions_GetEntry(&authSession, curr_tcm->tcm_stany_data.sessions, vtcm_in->authHandle);
    }
    /*
    if((returnCode == TCM_SUCCESS) && (tag == TCM_TAG_RQU_AUTH1_COMMAND) && !done){
        hmacKey = auth_session_data->sharedSecret;
        returnCode = vtcm_Authdata_Check(nv_scene, *hmacKey, inParamDigest, auth_session_data, vtcm_in->ownerAuth);
    }
    if((returnCode == TCM_SUCCESS) && (tag == TCM_TAG_RQU_AUTH1_COMMAND) && !done){
        returnCode = vtcm_AuthSessionData_Decrypt(a1Auth, auth_session_data, vtcm_in->encAuth);
    }
    */
    
    //  4.b.Validate the assertion of physical presence
    if ((tag == TCM_TAG_RQU_COMMAND) && !ignore_auth){
            if(! curr_tcm->tcm_stclear_flags.physicalPresence)
	    {
                  printf("Error, physicalPresence is FALSE\n");
                  returnCode = TCM_BAD_PRESENCE;
		  goto nv_definespace_out;
            }
    }
    //  4.c. Validate max NV writes without an owner 
    if (tag == TCM_TAG_RQU_COMMAND) {
            // i. Set NV1 to TCM_PERMANENT_DATA -> noOwnerNVWrite 
            nv1 = curr_tcm->tcm_permanent_data.noOwnerNVWrite;
                // ii. Increment NV1 by 1 
           nv1++;
                    // iii. If NV1 > TCM_MAX_NV_WRITE_NOOWNER return TCM_MAXNVWRITES 
           if (nv1 > TCM_MAX_NV_WRITE_NOOWNER) {
                    printf("Error, max NV writes %d w/o owner reached\n",
                    curr_tcm->tcm_permanent_data.noOwnerNVWrite);
                    returnCode = TCM_MAXNVWRITES;
		    goto nv_definespace_out;
                                        
           }
           else {
                            // iv. Set NV1_INCREMENTED to TRUE 
                      nv1Incremented = TRUE;
                                
           }
                    
    }

    if(ret == TCM_SUCCESS)
    {
      ret = vtcm_Compute_AuthCode(vtcm_out,
                                  DTYPE_VTCM_OUT,
                                  SUBTYPE_NV_DEFINESPACE_OUT,
                                  authSession,
                                  vtcm_out->ownerAuth
                                 );
    }
    // 5) 
        // a. Create D1
       returnCode = vtcm_NVIndexEntries_GetEntry(&nv_sens, &curr_tcm->tcm_nv_index_entries, vtcm_in->pubInfo.nvIndex);
       if (returnCode == TCM_SUCCESS) {
                printf("NV index %08x exists\n", index);
                        foundOld = TRUE;
                            
       }
       else if (returnCode == TCM_BADINDEX) {
                returnCode = TCM_SUCCESS;   // non-existant index is not an error 
                foundOld = FALSE;
                printf("Index %08x is new\n", vtcm_in->pubInfo.nvIndex);
		// should add a new TCM_NV_DATA_SENSITIVE in nv_scene
		
                                    
		vtcm_NVIndexEntries_GetFreeEntry(&nv_sens,
                                &curr_tcm->tcm_nv_index_entries);
		vtcm_template=memdb_get_template(DTYPE_VTCM_NV,SUBTYPE_TCM_NV_DATA_PUBLIC);
		if(vtcm_template==NULL)
			return -EINVAL;
		struct_clone(&vtcm_in->pubInfo,&nv_sens->pubInfo,vtcm_template);	
       }
    
       if (!ignore_auth && foundOld) {
            // b. If D1 -> attributes specifies TCM_NV_PER_GLOBALLOCK then 
           if (nv_sens->pubInfo.permission.attributes & TCM_NV_PER_GLOBALLOCK) {
                    // i. If TCM_STCLEAR_FLAGS -> bGlobalLock is TRUE then return TCM_AREA_LOCKED 
               if (curr_tcm->tcm_stclear_flags.bGlobalLock) {
                        printf("Error, index %08x (bGlobalLock) locked\n",
                                           vtcm_in->pubInfo.nvIndex);
                        returnCode = TCM_AREA_LOCKED;
			goto  nv_definespace_out;
               }
                
           }       
       }
       if (!ignore_auth && foundOld) {
            // c. If D1 -> attributes specifies TCM_NV_PER_WRITE_STCLEAR 
           if (nv_sens->pubInfo.permission.attributes & TCM_NV_PER_WRITE_STCLEAR) {
                    // i. If D1 -> pubInfo -> bWriteSTClear is TRUE then return TCM_AREA_LOCKED 
               if (nv_sens->pubInfo.bWriteSTClear) {
                        printf("Error, area locked by bWriteSTClear\n");
                        returnCode = TCM_AREA_LOCKED;
			goto nv_definespace_out;
               }
           }
       }
    
    // d. Delete D1 area and session
    if (foundOld) {
        // vtcm_AuthSessions_TerminateHandle(curr_tcm->tcm_stany_data.sessions, vtcm_in->authHandle);
            // Invalidate the data area currently pointed to by D1 and ensure that if the area is
             //     reallocated no residual information is left 
       printf("Deleting index %08x\n", index);
       vtcm_NVDataSensitive_Delete(nv_sens);
                    // must write deleted space back to NVRAM 
       writeAllNV = TRUE;
       goto nv_definespace_out;
    }

    // 6
 /*
        if (vtcm_in->pubInfo.pcrInfoRead.localityAtRelease != TCM_LOC_ALL) {
                    writeLocalities = TRUE;
        }
        else {
                    writeLocalities = FALSE;                   
        }
*/

    // 7
        if ((vtcm_in->pubInfo.permission.attributes & TCM_NV_PER_OWNERWRITE) &&
              (vtcm_in->pubInfo.permission.attributes & TCM_NV_PER_AUTHWRITE)) {
                      printf("Error, write authorization conflict\n");
                      returnCode = TCM_AUTH_CONFLICT;                               
        }
        // If TCM_NV_PER_OWNERREAD is TRUE and TCM_NV_PER_AUTHREAD is TRUE return TCM_AUTH_CONFLICT
         
        if ((vtcm_in->pubInfo.permission.attributes & TCM_NV_PER_OWNERREAD) &&
              (vtcm_in->pubInfo.permission.attributes & TCM_NV_PER_AUTHREAD)) {
                     printf("Error, read authorization conflict\n");
                     returnCode = TCM_AUTH_CONFLICT;
        }
        // If TCM_NV_PER_OWNERWRITE and TCM_NV_PER_AUTHWRITE and TCM_NV_PER_WRITEDEFINE and
        //  TCM_NV_PER_PPWRITE and writeLocalities are all FALSE 
	/*
        if (!(vtcm_in->pubInfo.permission.attributes & TCM_NV_PER_OWNERWRITE) &&
         	!(vtcm_in->pubInfo.permission.attributes & TCM_NV_PER_AUTHWRITE) &&
           	!(vtcm_in->pubInfo.permission.attributes & TCM_NV_PER_WRITEDEFINE) &&
          	!(vtcm_in->pubInfo.permission.attributes & TCM_NV_PER_PPWRITE) &&
                !writeLocalities) {
                        // i. Return TCM_PER_NOWRITE 
                        printf("Error, no write\n");
                        returnCode = TCM_PER_NOWRITE;
			goto nv_definespace_out;
            }
	*/
        // Validate pubInfo -> nvIndex 
        // Make sure that the index is applicable for this TCM return TCM_BADINDEX on error 
           returnCode = TCM_NVDataSensitive_IsValidIndex(index);
	  if(returnCode!=TCM_SUCCESS)
	  {
		goto nv_definespace_out;
	  }
        // f. If dataSize is 0 return TCM_BAD_PARAM_SIZE 
        if (vtcm_in->pubInfo.dataSize == 0) {
                printf("Error, New index data size is zero\n");
                returnCode = TCM_BAD_PARAM_SIZE;
		goto nv_definespace_out;
        }


    // 8) 
	ret = TCM_NV_DefineSpace(index, size, nv_sens);
	if(ret != 0)
	{
		returnCode=ret;
		goto nv_definespace_out;
	}
 /*
       memcpy(&nv_scene[0].nv[index].authValue, &a1Auth, TCM_DIGEST_SIZE);
    printf("nvIndex: %d\n", nv_scene[0].nv[index].pubInfo.nvIndex);
    printf("Data erea size: %d\n",nv_scene[0].nv[index].pubInfo.dataSize);
	printf("======DefineSpace Done=========\n");
    }

*/
nv_definespace_out:

     // Output
     
	vtcm_out = Talloc(sizeof(*vtcm_out));
	if(vtcm_out == NULL)
		return -ENOMEM;

	if(vtcm_in->tag==htons(TCM_TAG_RQU_COMMAND))
	{
		vtcm_out->tag = 0xC400;
		vtcm_out->paramSize = sizeof(*vtcm_out)-32;
		vtcm_out->returnCode = returnCode;
	}
	else if(vtcm_in->tag==htons(TCM_TAG_RQU_AUTH1_COMMAND))
	{
		vtcm_out->tag = htons(TCM_TAG_RSP_AUTH1_COMMAND);
		vtcm_out->paramSize = sizeof(*vtcm_out);
		vtcm_out->returnCode = returnCode;
	}
	send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_NV_DEFINESPACE_OUT,recv_msg);
	if(send_msg == NULL)
		return -EINVAL;
	message_add_record(send_msg,vtcm_out);

      // add vtcm's expand info	
     ret=vtcm_addcmdexpand(send_msg,recv_msg);
     if(ret<0)
     {
 	  printf("fail to add vtcm copy info!\n");
     }	
	ret = ex_module_sendmsg(sub_proc,send_msg);

	return ret;
}
/*
void TCM_NVDataSensitive_Delete(TCM_NV_DATA_SENSITIVE *tcm_nv_data_sensitive){
    int i;
    if (tcm_nv_data_sensitive != NULL){
        // Delete pubInfo
        for(i=0; i<TCM_NUM_PCR/CHAR_BIT; i++){
            tcm_nv_data_sensitive->pubInfo.pcrInfoRead.creationPCRSelection.pcrSelect[i] = 0;
            tcm_nv_data_sensitive->pubInfo.pcrInfoWrite.creationPCRSelection.pcrSelect[i] = 0;
        }
        tcm_nv_data_sensitive->pubInfo.pcrInfoRead.creationPCRSelection.sizeOfSelect = TCM_NUM_PCR/CHAR_BIT;
        tcm_nv_data_sensitive->pubInfo.pcrInfoWrite.creationPCRSelection.sizeOfSelect = TCM_NUM_PCR/CHAR_BIT;
        tcm_nv_data_sensitive->pubInfo.pcrInfoWrite.localityAtRelease = TCM_LOC_ALL;
        tcm_nv_data_sensitive->pubInfo.pcrInfoRead.localityAtRelease = TCM_LOC_ALL;
        memset(tcm_nv_data_sensitive->pubInfo.pcrInfoRead.digestAtRelease.digest, 0, TCM_DIGEST_SIZE);
        memset(tcm_nv_data_sensitive->pubInfo.pcrInfoWrite.digestAtRelease.digest, 0, TCM_DIGEST_SIZE);
        tcm_nv_data_sensitive->pubInfo.nvIndex = TCM_NV_INDEX_LOCK;
        tcm_nv_data_sensitive->pubInfo.permission.attributes = 0;
        tcm_nv_data_sensitive->pubInfo.bReadSTClear = FALSE;
        tcm_nv_data_sensitive->pubInfo.bWriteSTClear = FALSE;
        tcm_nv_data_sensitive->pubInfo.bWriteDefine = FALSE;
        tcm_nv_data_sensitive->pubInfo.dataSize = 0;

        // Delete secret
        memset(tcm_nv_data_sensitive->authValue.authdata, 0, TCM_SECRET_SIZE);

        free(tcm_nv_data_sensitive->data);

        // Sensitive Init
        tcm_nv_data_sensitive->data = NULL;
        memset(tcm_nv_data_sensitive->digest.digest, 0, TCM_DIGEST_SIZE);

    }
}
*/


/*
int TCM_NVIndexEntries_GetEntry(TCM_NV_DATA_SENSITIVE **tcm_nv_data_sensitive, struct vtcm_nv_scene *nv_scene, int index){
    TCM_RESULT rc = 0;
    TCM_BOOL found;
    int i;
    
    if(index == TCM_NV_INDEX_LOCK){
        rc = TCM_BADINDEX;
    }
    for(i = 0, found = FALSE; (rc == 0) && (i < nv_scene[0].nv_count) && !found; i++){
        *tcm_nv_data_sensitive = &(nv_scene[0].nv[i]);
        if(nv_scene[0].nv[i].pubInfo.nvIndex == index){
            found = TRUE;
        }
    }
    if(rc == 0){
        if(!found){
            printf("NV index not found\n");
            rc = TCM_BADINDEX;
        }
    }
    return rc;
}
*/

int TCM_NV_DefineSpace(int index,int size, TCM_NV_DATA_SENSITIVE * nv_sens)
{
        //printf("================In DefineSpace===============\n");
	//if(index > TCM_NV_INDEX_COUNT) return 1;
	nv_sens->data =(BYTE*)Dalloc0(sizeof(BYTE)*size,nv_sens);
	nv_sens->pubInfo.nvIndex = index;
        nv_sens->pubInfo.dataSize = size;
        //printf("nvIndex: %d\n", nv_scene[0].nv[index].pubInfo.nvIndex);
	//printf("dataSize: %d\n",nv_scene[0].nv[index].pubInfo.dataSize);
	//printf("================DefineSpace done==================\n");
	return 0;
}


int proc_vtcm_writevalue(void *sub_proc, void *recv_msg)
{
	printf("proc_vtcm_writevalue: Start\n");
	int ret = 0;
 	int i = 0;
        TCM_SESSION_DATA *authSession;
	tcm_state_t *curr_tcm = ex_module_getpointer(sub_proc);
	struct tcm_in_NV_WriteValue *vtcm_in;
	struct tcm_out_NV_WriteValue *vtcm_out;
	void *send_msg;
	
        int nv1 = curr_tcm->tcm_permanent_data.noOwnerNVWrite;
        TCM_BOOL ignore_auth = FALSE;
        TCM_RESULT returnCode = TCM_SUCCESS;
        TCM_NV_DATA_SENSITIVE *nv_sens;
        TCM_DIGEST nvAuth;
	void * vtcm_template;

	/*Get input params*/
	ret = message_get_record(recv_msg,&vtcm_in,0);
	if(ret < 0)
		return ret;
	if(vtcm_in == NULL)
		return -EINVAL;	
	
	/*processing*/

	//1 
        if((curr_tcm->tcm_permanent_flags.nvLocked == FALSE)){
              printf("nvLocked is FLASE, only check the Max NV writes");
              ignore_auth = TRUE;
        }
	
        //2 
    	if(vtcm_in->nvIndex == TCM_NV_INDEX0){
		if(vtcm_in->dataSize!=0)
		{
        		printf("Error, bad index %d\n",index);
        		returnCode = TCM_BADINDEX;
			goto nv_writevalue_out;
		}
		curr_tcm->tcm_stclear_flags.bGlobalLock=TRUE;
		returnCode=TCM_SUCCESS;
		goto nv_writevalue_out;
    	}
        //3 
       returnCode = vtcm_NVIndexEntries_GetEntry(&nv_sens, &curr_tcm->tcm_nv_index_entries, vtcm_in->nvIndex);
       if (returnCode != TCM_SUCCESS) {
                printf("NV index %08x do not exists\n", index);
		goto nv_writevalue_out;
       }
       if(vtcm_in->tag==htons(TCM_TAG_RQU_COMMAND))
       {
	/*
	      if(!(nv_sens->pubInfo.permission.attributes & TCM_NV_PER_OWNERWRITE))
	      {
		    returnCode=TCM_AUTH_CONFLICT;
		    goto nv_writevalue_out;
              }
	*/				
              nv1 = curr_tcm->tcm_permanent_data.noOwnerNVWrite;
                // ii. Increment NV1 by 1 
              nv1++;
                    // iii. If NV1 > TCM_MAX_NV_WRITE_NOOWNER return TCM_MAXNVWRITES 
              if (nv1 > TCM_MAX_NV_WRITE_NOOWNER) {
                    printf("Error, max NV writes %d w/o owner reached\n",
                    	  curr_tcm->tcm_permanent_data.noOwnerNVWrite);
                    returnCode = TCM_MAXNVWRITES;
		    goto nv_writevalue_out;
              }
       }
       else
       {
	      if(!(nv_sens->pubInfo.permission.attributes & TCM_NV_PER_OWNERWRITE))
	      {
		    returnCode=TCM_AUTH_CONFLICT;
		    goto nv_writevalue_out;
              }			
	    //3-1.b: check owner auth

       }	
	
       // 4: check NV attributes
	/*
        if (!(nv_sens->pubInfo.permission.attributes & TCM_NV_PER_OWNERWRITE) &&
          	!(nv_sens->pubInfo.permission.attributes & TCM_NV_PER_PPWRITE))
	  {
                        // i. Return TCM_PER_NOWRITE 
                        printf("Error, no write\n");
                        returnCode = TCM_PER_NOWRITE;
			goto nv_writevalue_out;
          }
  	*/
        //5 check pcr value
  
        //6  Write Data to NV space
	printf("======Processing WriteValue=========\n");
	ret = TCM_NV_WriteValue(vtcm_in->offset, vtcm_in->data,vtcm_in->dataSize, nv_sens);
	if(ret != 0)
		return ret;
	printf("======WriteValue Done=========\n");

	/*Output*/

nv_writevalue_out:
	vtcm_out = Talloc(sizeof(*vtcm_out));
	if(vtcm_out == NULL)
		return -ENOMEM;


	if(vtcm_in->tag==htons(TCM_TAG_RQU_COMMAND))
	{
		vtcm_out->tag = 0xC400;
		vtcm_out->paramSize = sizeof(*vtcm_out)-32;
		vtcm_out->returnCode = returnCode;
	}
	else if(vtcm_in->tag==htons(TCM_TAG_RQU_AUTH1_COMMAND))
	{
		vtcm_out->tag = htons(TCM_TAG_RSP_AUTH1_COMMAND);
		vtcm_out->paramSize = sizeof(*vtcm_out);
		vtcm_out->returnCode = returnCode;
	}
	
	send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_NV_WRITEVALUE_OUT,recv_msg);
	if(send_msg == NULL)
		return -EINVAL;
	message_add_record(send_msg,vtcm_out);
      // add vtcm's expand info	
     ret=vtcm_addcmdexpand(send_msg,recv_msg);
     if(ret<0)
     {
 	  printf("fail to add vtcm copy info!\n");
     }	
	ret = ex_module_sendmsg(sub_proc,send_msg);

	return ret;
}

int proc_vtcm_readvalue(void *sub_proc, void *recv_msg)
{
	printf("proc_vtcm_readvalue: Start\n");
	int ret = 0;
 	int i = 0;
        TCM_SESSION_DATA *authSession;
	tcm_state_t *curr_tcm = ex_module_getpointer(sub_proc);
	struct tcm_in_NV_ReadValue *vtcm_in;
	struct tcm_out_NV_ReadValue *vtcm_out;
	void *send_msg;
	
        int nv1 = curr_tcm->tcm_permanent_data.noOwnerNVWrite;
        TCM_BOOL ignore_auth = FALSE;
        TCM_RESULT returnCode = TCM_SUCCESS;
        TCM_NV_DATA_SENSITIVE *nv_sens;
        TCM_DIGEST nvAuth;
	void * vtcm_template;

	// Get input params 
	ret = message_get_record(recv_msg,&vtcm_in,0);
	if(ret < 0)
		return ret;
	if(vtcm_in == NULL)
		return -EINVAL;	

	// processing

	//1 
        if((curr_tcm->tcm_permanent_flags.nvLocked == FALSE)){
              printf("nvLocked is FLASE, only check the Max NV writes");
              ignore_auth = TRUE;
        }
        returnCode = vtcm_NVIndexEntries_GetEntry(&nv_sens, &curr_tcm->tcm_nv_index_entries, vtcm_in->nvIndex);
         if (returnCode != TCM_SUCCESS) {
                printf("NV index %08x do not exists\n", index);
		goto nv_readvalue_out;
        }
       
        
       if(vtcm_in->tag==htons(TCM_TAG_RQU_AUTH1_COMMAND))
	{
		// 5-i-a
	      if(!(nv_sens->pubInfo.permission.attributes & TCM_NV_PER_OWNERREAD))
	      {
		    returnCode=TCM_AUTH_CONFLICT;
		    goto nv_readvalue_out;
              }			
              nv1 = curr_tcm->tcm_permanent_data.noOwnerNVWrite;
                // ii. Increment NV1 by 1 
              nv1++;
                    // iii. If NV1 > TCM_MAX_NV_WRITE_NOOWNER return TCM_MAXNVWRITES 
              if (nv1 > TCM_MAX_NV_WRITE_NOOWNER) {
                    printf("Error, max NV writes %d w/o owner reached\n",
                    	  curr_tcm->tcm_permanent_data.noOwnerNVWrite);
                    returnCode = TCM_MAXNVWRITES;
		    goto nv_readvalue_out;
              }
	    //5-i-b: check owner auth
		

	}
       else if(vtcm_in->tag==htons(TCM_TAG_RQU_COMMAND))
       {
	//  5-ii-a
	/*
	      if(!(nv_sens->pubInfo.permission.attributes & TCM_NV_PER_AUTHREAD))
	      {
		    returnCode=TCM_AUTH_CONFLICT;
		    goto nv_readvalue_out;
              }
	*/	
	//5-ii-b		
	/*
	      if(!(nv_sens->pubInfo.permission.attributes & TCM_NV_PER_OWNERREAD))
	      {
		    returnCode=TCM_AUTH_CONFLICT;
		    goto nv_readvalue_out;
              }	
	*/
         }	
	
       else
       {
		    returnCode=TCM_BAD_PARAMETER;
		    goto nv_readvalue_out;

       }	
       // 6: check NV attributes
	/*
        if (!(nv_sens->pubInfo.permission.attributes & TCM_NV_PER_PPREAD) &&
          	!(nv_sens->pubInfo.permission.attributes & TCM_NV_PER_READ_STCLEAR))
	  {
                        // i. Return TCM_PER_NOWRITE 
                        printf("Error, no read\n");
                        returnCode = TCM_DISABLED_CMD;
			goto nv_readvalue_out;
          }
	*/
        //7 check pcr value


	ret = TCM_NV_ReadValue(vtcm_in->offset, Buf,vtcm_in->dataSize, nv_sens);
	if(ret != 0)
	{
		returnCode=ret;
		goto nv_readvalue_out;
	}
nv_readvalue_out:
	// Output
	vtcm_out = Talloc(sizeof(*vtcm_out));
	if(vtcm_out == NULL)
		return -ENOMEM;
	vtcm_out->dataSize = vtcm_in->dataSize;
	if(vtcm_out->dataSize>0)
	{
		vtcm_out->data = Talloc(sizeof(BYTE)*vtcm_out->dataSize);
		Memcpy(vtcm_out->data,Buf,vtcm_out->dataSize);
	}

	if(vtcm_in->tag==htons(TCM_TAG_RQU_COMMAND))
	{
		vtcm_out->tag = htons(TCM_TAG_RSP_COMMAND);
		vtcm_out->paramSize = sizeof(*vtcm_out)-sizeof(BYTE *)+vtcm_out->dataSize-DIGEST_SIZE;
		vtcm_out->returnCode = returnCode;
	}
	else if(vtcm_in->tag==htons(TCM_TAG_RQU_AUTH1_COMMAND))
	{
		vtcm_out->tag = htons(TCM_TAG_RSP_AUTH1_COMMAND);
		vtcm_out->paramSize = sizeof(*vtcm_out)-sizeof(BYTE *)+vtcm_out->dataSize;
		vtcm_out->returnCode = returnCode;
	}
	
	send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_NV_READVALUE_OUT,recv_msg);
	if(send_msg == NULL)
	{
		printf("sdfsdfsdfsdfsdf");
		return -EINVAL;
	}
	message_add_record(send_msg,vtcm_out);
      // add vtcm's expand info	
     ret=vtcm_addcmdexpand(send_msg,recv_msg);
     if(ret<0)
     {
 	  printf("fail to add vtcm copy info!\n");
     }	
	ret = ex_module_sendmsg(sub_proc,send_msg);

	return ret;
}

int TCM_NV_WriteValue(uint32_t offset,unsigned char *data, uint32_t datalen, 
	TCM_NV_DATA_SENSITIVE *nv_sens)
{
//	printf("================In WriteValue===============\n");
   
        if(offset+datalen>nv_sens->pubInfo.dataSize)
		return TCM_NOSPACE;        	 
        
	Memcpy(nv_sens->data+offset,data,datalen);
//	printf("==============WriteValue donw=================\n");	
    	return 0;
}


int TCM_NV_ReadValue(uint32_t offset,unsigned char * data, uint32_t datalen,
	TCM_NV_DATA_SENSITIVE *nv_sens)
{
        if(offset+datalen>nv_sens->pubInfo.dataSize)
		return TCM_NOSPACE;        	 
        
	Memcpy(data,nv_sens->data+offset,datalen);
	return 0;
}



