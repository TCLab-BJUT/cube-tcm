#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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
#include "tesi_key.h"
#include "tesi_aik_struct.h"
#include "vtcm_auth.h"
#include "app_struct.h"
#include "pik_struct.h"
#include "tcm_global.h"
#include "tcm_error.h"
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"
#include "tcm_authlib.h"

static BYTE Buf[DIGEST_SIZE*64];

static int proc_vtcm_TakeOwnership(void* sub_proc, void* recv_msg);
static int proc_vtcm_MakeIdentity(void* sub_proc, void* recv_msg);
static int proc_vtcm_ActivateIdentity(void* sub_proc, void* recv_msg);
static int proc_vtcm_Quote(void* sub_proc, void* recv_msg);

int vtcm_auth_init(void* sub_proc, void* para)
{
    printf("vtcm_auth_init :\n");
    tcm_state_t* tcm_instances = proc_share_data_getpointer();

    ex_module_setpointer(sub_proc, &tcm_instances[0]);
    return 0;
}

int vtcm_auth_start(void* sub_proc, void* para)
{
    int ret;
    void* recv_msg, *context, *sock;
    int type, subtype;
    BYTE uuid[DIGEST_SIZE];
    int vtcm_no; 

    printf("vtcm_auth module start!\n");

    for (int i = 0; i < 300 * 1000; i++) {
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

        if ((type == DTYPE_VTCM_IN) && (subtype == SUBTYPE_TAKEOWNERSHIP_IN)) {
            proc_vtcm_TakeOwnership(sub_proc,recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN) && (subtype == SUBTYPE_MAKEIDENTITY_IN)) {
            proc_vtcm_MakeIdentity(sub_proc,recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN) && (subtype == SUBTYPE_ACTIVATEIDENTITY_IN)) {
            proc_vtcm_ActivateIdentity(sub_proc,recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN) && (subtype == SUBTYPE_QUOTE_IN)) {
            proc_vtcm_Quote(sub_proc,recv_msg);
        }
    }
    return 0;
};

static int proc_vtcm_TakeOwnership(void* sub_proc, void* recv_msg)
{

    int ret = 0;
    int i = 0;
    int offset=0;
    int keylen;
    int datalen;
    int got_handle;
    uint32_t            entityValue = 0;        /* The selection value based on entityType, e.g. a
                                                   keyHandle # */
    TCM_ENTITY_TYPE     entityType;             /* The type of entity in use */
    uint32_t authHandle = 0;
    TCM_SESSION_DATA *authSession;
    TCM_DIGEST  *entityDigest = NULL;   /* digest of the entity establishing the OSAP
                                                   session, initialize to silence compiler */
    TCM_SECRET          *authData;              /* usageAuth for the entity */
    TCM_COUNTER_VALUE   *counterValue;          /* associated with entityValue */


    TCM_KEY * eKey;
    TCM_KEY * smk;
    TCM_SYMMETRIC_KEY_PARMS * sm4_parms;

    //input process
    struct tcm_in_TakeOwnership *vtcm_in;
    struct tcm_out_TakeOwnership *vtcm_out;
    void *vtcm_template;
    uint32_t returnCode=0;
    BYTE ownerauth[TCM_HASH_SIZE];
    BYTE smkauth[TCM_HASH_SIZE];
    BYTE CheckData[TCM_HASH_SIZE];
    
    printf("proc_vtcm_TakeOwnership : Start\n");
    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0); // get structure 
    if(ret < 0) 
        return ret;
    if(vtcm_in == NULL)
        return -EINVAL;
    
    tcm_state_t* curr_tcm = ex_module_getpointer(sub_proc);

    smk = &(curr_tcm->tcm_permanent_data.smk);
    ret=vtcm_AuthSessions_GetEntry(&authSession,curr_tcm->tcm_stany_data.sessions,vtcm_in->authHandle);
 


   if(curr_tcm->tcm_permanent_flags.ownership!=0)
   {
	print_cubeerr("TAKEOWNERSHIP:This tcm already has the ownership!\n");
	returnCode=-TCM_OWNER_SET;	
	goto takeown_out;
   }    
   else
   {
  	eKey=&curr_tcm->tcm_permanent_data.endorsementKey;
   	datalen=DIGEST_SIZE*16;
	// decrypt the ownerAuth data
	ret=GM_SM2Decrypt(Buf,&datalen, vtcm_in->encOwnerAuth,vtcm_in->encOwnerAuthSize,
		eKey->encData,eKey->encDataSize);
  	if(ret<0)
		return ret;
	if(datalen>TCM_HASH_SIZE)
		return -EINVAL;
	Memset(ownerauth,0,TCM_HASH_SIZE);
	Memcpy(ownerauth,Buf,datalen);
    	// Check command's auth code
    	vtcm_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_TAKEOWNERSHIP_IN);
    	if(vtcm_template==NULL)
    		return -EINVAL;
    	offset = struct_2_blob(vtcm_in,Buf,vtcm_template);
    	if(offset<0)
    		return offset;
	
    	// compute authCode
        memcpy(CheckData, ownerauth, TCM_HASH_SIZE);
        if(ret == TCM_SUCCESS) {
          ret = vtcm_Compute_AuthCode(vtcm_in,
                                      DTYPE_VTCM_IN,
                                      SUBTYPE_TAKEOWNERSHIP_IN,
                                      NULL,
                                      CheckData);
        }
        if(memcmp(CheckData, vtcm_in->authCode, TCM_HASH_SIZE) != 0)
        {
          ret = TCM_AUTHFAIL;
          printf("\ncompare authcode in failed\n");
          goto takeown_out;
        }
        // copy ownerAuth data to permanent_data struct
	Memcpy(curr_tcm->tcm_permanent_data.ownerAuth,ownerauth,TCM_SECRET_SIZE);

        //check the SMK params
	if(vtcm_in->smkParams.algorithmParms.algorithmID!=TCM_ALG_SM4)
	{
		returnCode = TCM_BAD_KEY_PROPERTY;
		goto takeown_out;
	}
	else
	{
    		sm4_parms=Talloc0(sizeof(*sm4_parms));
    		if(sm4_parms==NULL)
			return -ENOMEM;
    		vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_SYMMETRIC_KEY_PARMS);
    		if(vtcm_template==NULL)
			return -EINVAL;
    		ret=blob_2_struct(vtcm_in->smkParams.algorithmParms.parms,sm4_parms,vtcm_template);
    		if(ret<0)
			return ret;	
    		if(sm4_parms->keyLength!=0x80)
		{
			returnCode=TCM_BAD_KEY_PROPERTY;
			goto takeown_out;
		}
		else
		{
			// Generate SMK 
			vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
			if(vtcm_template==NULL)
				return -EINVAL;
			
			ret=struct_clone(&vtcm_in->smkParams,smk,vtcm_template);
			if(ret<0)
				return ret;
			// decrypt the smkAuth data
			ret=GM_SM2Decrypt(Buf,&datalen, vtcm_in->encSmkAuth,vtcm_in->encSmkAuthSize,
				eKey->encData,eKey->encDataSize);
  			if(ret<0)
				return ret;
				
			ret=vtcm_Keystruct_GenerateSM4(smk,Buf,NULL);
			if(ret<0)
				return ret;
		}
			
	}
    }

   takeown_out:

    vtcm_out=Talloc0(sizeof(*vtcm_out));
    if(vtcm_out==NULL)
	return -ENOMEM;
    vtcm_out->tag=0xC500;
    vtcm_out->returnCode=ret;

    // duplicate the vtcm key params
    ret=struct_clone(&vtcm_in->smkParams,&vtcm_out->smkPub,vtcm_template);
    if(ret<0)
	return -EINVAL;
    	

    memcpy(vtcm_out->resAuth, ownerauth, TCM_HASH_SIZE);
    if(ret == TCM_SUCCESS) 
    {
     ret = vtcm_Compute_AuthCode(vtcm_out,
                                 DTYPE_VTCM_OUT,
                                 SUBTYPE_TAKEOWNERSHIP_OUT,
                                 NULL,
                                 vtcm_out->resAuth);
   }
    vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
    if(vtcm_template==NULL)
	return -EINVAL;
			
    void *send_msg = message_create(DTYPE_VTCM_OUT ,SUBTYPE_TAKEOWNERSHIP_OUT ,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n");
        return -EINVAL;      
    }
    int responseSize = 0;
    vtcm_template=memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_TAKEOWNERSHIP_OUT);
    responseSize = struct_2_blob(vtcm_out, Buf, vtcm_template);
    if(responseSize<0)
	return responseSize;

    vtcm_out->paramSize = responseSize;
    message_add_record(send_msg, vtcm_out);
 
      // add vtcm's expand info	
     ret=vtcm_addcmdexpand(send_msg,recv_msg);
     if(ret<0)
     {
 	  printf("fail to add vtcm copy info!\n");
     }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
	
}

static int proc_vtcm_MakeIdentity(void* sub_proc, void* recv_msg)
{

    int ret = 0;
    int i = 0;
    int offset=0;
    int keylen;
    int datalen;
    int got_handle;

    uint32_t authHandle = 0;
    TCM_SESSION_DATA *ownerauthSession;
    TCM_SESSION_DATA *smkauthSession;
    TCM_DIGEST  *entityDigest = NULL;   /* digest of the entity establishing the OSAP
                                                   session, initialize to silence compiler */
    TCM_SECRET          *authData;              /* usageAuth for the entity */
    TCM_COUNTER_VALUE   *counterValue;          /* associated with entityValue */


    TCM_KEY * eKey;
    TCM_KEY * smk;
    TCM_KEY * pik;
    TCM_SM2_ASYMKEY_PARAMETERS * pik_parms;
    TCM_SYMMETRIC_KEY_PARMS * sm4_parms;
    TCM_STORE_SYMKEY * sm4_key; 
    TCM_IDENTITY_CONTENTS * identity_data;

    //input process
    struct tcm_in_MakeIdentity *vtcm_in;
    struct tcm_out_MakeIdentity *vtcm_out;
    void *vtcm_template;
    uint32_t returnCode=0;
    BYTE ownerauth[TCM_HASH_SIZE];
    BYTE smkauth[TCM_HASH_SIZE];
    BYTE pikauth[TCM_HASH_SIZE];
    BYTE cmdHash[TCM_HASH_SIZE];
    BYTE CheckData[TCM_HASH_SIZE];
    BYTE CheckData2[TCM_HASH_SIZE];
    
    printf("proc_vtcm_MakeIdentity : Start\n");
    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0); // get structure 
    if(ret < 0) 
        return ret;
    if(vtcm_in == NULL)
        return -EINVAL;
    vtcm_out=Talloc0(sizeof(*vtcm_out));
    if(vtcm_out==NULL)
	return -ENOMEM;
    
    // get tcm structure
    tcm_state_t* curr_tcm = ex_module_getpointer(sub_proc);

    eKey=&curr_tcm->tcm_permanent_data.endorsementKey;
    smk = &(curr_tcm->tcm_permanent_data.smk);
   
    // get ownerauthsession and smkauthsession
    ret=vtcm_AuthSessions_GetEntry(&smkauthSession,curr_tcm->tcm_stany_data.sessions,vtcm_in->smkHandle);
    if(ret<0)
    {
	returnCode=-TCM_INVALID_AUTHHANDLE;
	goto makeidentity_out;	
    }
    ret=vtcm_AuthSessions_GetEntry(&ownerauthSession,curr_tcm->tcm_stany_data.sessions,vtcm_in->ownerHandle);
    if(ret<0)
    {
	returnCode=-TCM_INVALID_AUTHHANDLE;
	goto makeidentity_out;	
    }

   
    // generate command's bin blob
    	vtcm_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_MAKEIDENTITY_IN);
    	if(vtcm_template==NULL)
    		return -EINVAL;
    	offset = struct_2_blob(vtcm_in,Buf,vtcm_template);
    	if(offset<0)
    		return offset;

        if(ret == TCM_SUCCESS)
        {
          ret = vtcm_Compute_AuthCode(vtcm_in,
                                      DTYPE_VTCM_IN,
                                      SUBTYPE_MAKEIDENTITY_IN,
                                      smkauthSession,
                                      CheckData);
        }
    if(Memcmp(CheckData,vtcm_in->smkAuth,TCM_HASH_SIZE)!=0)
    {
	returnCode=TCM_AUTHFAIL;
    printf("\nerror, smkauth compare in failed\n");
	goto makeidentity_out;
    }
        if(ret == TCM_SUCCESS)
        {
          ret = vtcm_Compute_AuthCode(vtcm_in,
                                      DTYPE_VTCM_IN,
                                      SUBTYPE_MAKEIDENTITY_IN,
                                      ownerauthSession,
                                      CheckData2);
        }
    if(Memcmp(CheckData2,vtcm_in->ownerAuth,TCM_HASH_SIZE)!=0)
    {
	returnCode=TCM_AUTH2FAIL;
    printf("\nownerauth compare in failed\n");
	goto makeidentity_out;
    }	

        //check the PIK params
	if((vtcm_in->pikParams.algorithmParms.algorithmID!=TCM_ALG_SM2)
		||(vtcm_in->pikParams.keyUsage!=TCM_SM2KEY_IDENTITY))
	{
		returnCode = TCM_BAD_KEY_PROPERTY;
		goto makeidentity_out;
	}
    	pik_parms=Talloc0(sizeof(*pik_parms));

    	if(pik_parms==NULL)
		return -ENOMEM;
    	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_SM2_ASYMKEY_PARAMETERS);
    	if(vtcm_template==NULL)
		return -EINVAL;
    	ret=blob_2_struct(vtcm_in->pikParams.algorithmParms.parms,pik_parms,vtcm_template);
    	if(ret<0)
		return ret;	
    	if(pik_parms->keyLength!=0x80)
	{
		returnCode=TCM_BAD_KEY_PROPERTY;
		goto makeidentity_out;
	}
	// Generate pik 
	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
	if(vtcm_template==NULL)
		return -EINVAL;

	pik=&(vtcm_out->pik);
	ret=struct_clone(&vtcm_in->pikParams,pik,vtcm_template);
	if(ret<0)
		return ret;
//        vtcm_Key_Init(pik);
	// decrypt the pikAuth data

	TCM_STORE_ASYMKEY * privpik;
				
	ret=vtcm_Key_GenerateSM2(pik,curr_tcm,NULL,curr_tcm->tcm_stclear_data.PCRS,
		vtcm_in->pikParams.keyUsage,
		vtcm_in->pikParams.keyFlags,
		vtcm_in->pikParams.authDataUsage,
                &(vtcm_in->pikParams.algorithmParms),
		NULL,
		NULL);
	if(ret!=TCM_SUCCESS)
	{
		returnCode=ret;
		goto makeidentity_out;
	}

	privpik=Talloc0(sizeof(*privpik));
	if(privpik==NULL)
	return -EINVAL;
	
	// fill the privpik's auth data
	privpik->payload=TCM_PT_ASYM;

	for(i=0;i<TCM_HASH_SIZE;i++)
	{
		privpik->usageAuth[i]=vtcm_in->pikAuth[i]^ownerauthSession->sharedSecret[i];
	}	
        Memcpy(privpik->migrationAuth, curr_tcm->tcm_permanent_data.tcmProof,TCM_SECRET_SIZE);

	// compute pubkey's digest

	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_STORE_PUBKEY);
	if(vtcm_template==NULL)
		return -EINVAL;		
	ret=struct_2_blob(&pik->pubKey,Buf,vtcm_template);
	if(ret<0)
	{
		returnCode=-TCM_BAD_DATASIZE;
		goto makeidentity_out;
	}
	sm3(Buf,ret,&privpik->pubDataDigest);
	privpik->privKey.keyLength=pik->encDataSize;
	privpik->privKey.key=pik->encData;

	// output the pik's encdata blob
	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_STORE_ASYMKEY);
	if(vtcm_template==NULL)
		return -EINVAL;

	ret=struct_2_blob(privpik,Buf+DIGEST_SIZE,vtcm_template);
	if(ret<0)
	{
		returnCode=-TCM_BAD_DATASIZE;
		goto makeidentity_out;
	}
	Memset(Buf,0,DIGEST_SIZE);
	offset=ret%DIGEST_SIZE;
	
	if(offset==0)
		offset=DIGEST_SIZE;	


	// ignore the smk crypt for debug, should add crypt later
	
	pik->encDataSize=ret+DIGEST_SIZE-offset;
	pik->encData=Talloc0(pik->encDataSize);
	if(pik->encData==NULL)
		return -EINVAL;
	Memcpy(pik->encData,Buf+offset,pik->encDataSize);
	
        //create Cert Info
	identity_data=Talloc0(sizeof(*identity_data));
	identity_data->ver.major=1;
	identity_data->ver.minor=1;
	identity_data->ordinal=vtcm_in->ordinal;

	Memcpy(&identity_data->labelPrivCADigest,&vtcm_in->pubDigest,TCM_HASH_SIZE);
	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY_PARMS);
	struct_clone(&pik->algorithmParms,&identity_data->identityPubKey.algorithmParms,vtcm_template);
	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_STORE_PUBKEY);
	struct_clone(&pik->pubKey,&identity_data->identityPubKey.pubKey,vtcm_template);

	//compute cert blob 
	vtcm_template=memdb_get_template(DTYPE_VTCM_IDENTITY,SUBTYPE_TCM_IDENTITY_CONTENTS);
	if(vtcm_template==NULL)
		return -EINVAL;
	ret=struct_2_blob(identity_data,Buf,vtcm_template);
	if(ret<0)
		return -EINVAL;

	// compute cert data

	offset=ret;
	BYTE * signedData=Buf+ret+1;
	unsigned long pulSigLen=512;
	BYTE UserID[DIGEST_SIZE];
	unsigned long lenUID=DIGEST_SIZE;
	Memset(UserID,"A",32);	

	
	ret=GM_SM2Sign(signedData,&pulSigLen,Buf,ret,UserID,lenUID,privpik->privKey.key,privpik->privKey.keyLength);	
	if(ret!=0)
	{
		returnCode=-TCM_BAD_SIGNATURE;
		goto makeidentity_out;	
	}
	vtcm_out->CertSize=pulSigLen;
	vtcm_out->CertData=Talloc0(vtcm_out->CertSize);

	Memcpy(vtcm_out->CertData,signedData,vtcm_out->CertSize);
/*
    }
*/
makeidentity_out:

    vtcm_out->tag=0xC600;
    vtcm_out->returnCode=returnCode;

    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_Compute_AuthCode(vtcm_out,
                                    DTYPE_VTCM_OUT,
                                    SUBTYPE_MAKEIDENTITY_OUT,
                                    smkauthSession,
                                    vtcm_out->smkAuth);
    }
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_Compute_AuthCode2(vtcm_out,
                                    DTYPE_VTCM_OUT,
                                    SUBTYPE_MAKEIDENTITY_OUT,
                                    ownerauthSession,
                                    vtcm_out->ownerAuth);
    }
    void *send_msg = message_create(DTYPE_VTCM_OUT ,SUBTYPE_MAKEIDENTITY_OUT ,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n");
        return -EINVAL;      
    }
    int responseSize = 0;
    vtcm_template=memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_MAKEIDENTITY_OUT);
    responseSize = struct_2_blob(vtcm_out, Buf, vtcm_template);
    if(responseSize<0)
	return responseSize;

    vtcm_out->paramSize = responseSize;
    message_add_record(send_msg, vtcm_out);
 
      // add vtcm's expand info	
     ret=vtcm_addcmdexpand(send_msg,recv_msg);
     if(ret<0)
     {
 	  printf("fail to add vtcm copy info!\n");
     }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}

static int proc_vtcm_ActivateIdentity(void* sub_proc, void* recv_msg)
{

    int ret = 0;
    int i = 0;
    int offset=0;
    int keylen;
    int datalen;
    int got_handle;

    uint32_t authHandle = 0;
    TCM_SESSION_DATA *ownerauthSession;
    TCM_SESSION_DATA *pikauthSession;

    TCM_SECRET          *authData;              /* usageAuth for the entity */
    TCM_COUNTER_VALUE   *counterValue;          /* associated with entityValue */

    TCM_KEY * eKey;
    TCM_KEY * pik;
    TCM_ASYM_CA_CONTENTS ca_conts;	

    TCM_BOOL parentPCRStatus;

    //input process
    struct tcm_in_ActivateIdentity *vtcm_in;
    struct tcm_out_ActivateIdentity *vtcm_out;
    struct vtcm_external_output_command *vtcm_err_out;  // err output data
    void *vtcm_template;
    uint32_t returnCode=0;
    BYTE ownerauth[TCM_HASH_SIZE];
    BYTE pikauth[TCM_HASH_SIZE];
    BYTE cmdHash[TCM_HASH_SIZE];
    BYTE pubDigest[TCM_HASH_SIZE];
    BYTE CheckData[TCM_HASH_SIZE];
    BYTE CheckData2[TCM_HASH_SIZE];
    
    printf("proc_vtcm_MakeIdentity : Start\n");
    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0); // get structure 
    if(ret < 0) 
        return ret;
    if(vtcm_in == NULL)
        return -EINVAL;
    vtcm_out=Talloc0(sizeof(*vtcm_out));
    if(vtcm_out==NULL)
	return -ENOMEM;
    
    // get tcm structure
    tcm_state_t* curr_tcm = ex_module_getpointer(sub_proc);

    eKey=&curr_tcm->tcm_permanent_data.endorsementKey;
   
    // get ownerauthsession and pikauthsession
    ret=vtcm_AuthSessions_GetEntry(&pikauthSession,curr_tcm->tcm_stany_data.sessions,vtcm_in->pikAuthHandle);
    if(ret<0)
    {
	returnCode=-TCM_INVALID_AUTHHANDLE;
	goto activateidentity_out;	
    }
    ret=vtcm_AuthSessions_GetEntry(&ownerauthSession,curr_tcm->tcm_stany_data.sessions,vtcm_in->ownerAuthHandle);
    if(ret<0)
    {
	returnCode=-TCM_INVALID_AUTHHANDLE;
	goto activateidentity_out;	
    }

   // get pik
    ret = vtcm_KeyHandleEntries_GetKey(&pik,&parentPCRStatus, 
                                       curr_tcm,vtcm_in->pikHandle,
                                       FALSE,     // not r/o, using to encrypt
                                       FALSE,     // do not ignore PCRs
                                       FALSE);    // cannot use EK
  
        // 2 check the PIK params
	if((pik->algorithmParms.algorithmID!=TCM_ALG_SM2)
		||(pik->keyUsage!=TCM_SM2KEY_IDENTITY))
	{
		returnCode = TCM_BAD_KEY_PROPERTY;
		goto activateidentity_out;
	}
   
        // check authcode
      
   	vtcm_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_ACTIVATEIDENTITY_IN);
    	if(vtcm_template==NULL)
    		return -EINVAL;
    	offset = struct_2_blob(vtcm_in,Buf,vtcm_template);
    	if(offset<0)
    		return offset;

        if(ret == TCM_SUCCESS)
        {
          ret = vtcm_Compute_AuthCode(vtcm_in,
                                      DTYPE_VTCM_IN,
                                      SUBTYPE_ACTIVATEIDENTITY_IN,
                                      pikauthSession,
                                      CheckData);
        }
    	if(Memcmp(CheckData,vtcm_in->pikAuth,TCM_HASH_SIZE)!=0)
    	{
		returnCode=TCM_AUTHFAIL;
    		printf("\nerror, smkauth compare in failed\n");
		goto activateidentity_out;
    	}
        if(ret == TCM_SUCCESS)
        {
          	ret = vtcm_Compute_AuthCode2(vtcm_in,
                                      	DTYPE_VTCM_IN,
                                     	SUBTYPE_ACTIVATEIDENTITY_IN,
                                      	ownerauthSession,
                                      	CheckData2);
        }
    	if(Memcmp(CheckData2,vtcm_in->ownerAuth,TCM_HASH_SIZE)!=0)
    	{
		returnCode=TCM_AUTH2FAIL;
    		printf("\nownerauth compare in failed\n");
		goto activateidentity_out;
    	}	
/*
    // check pikkAuth
    uint32_t temp_int;
    // compute smkauthCode
    sm3(Buf+6,offset-6-36*2,cmdHash);

    Memcpy(Buf,cmdHash,DIGEST_SIZE);
    temp_int=htonl(vtcm_in->pikAuthHandle);
    Memcpy(Buf+DIGEST_SIZE,&temp_int,sizeof(uint32_t));
    
    sm3_hmac(pikauthSession->sharedSecret,TCM_HASH_SIZE,
	Buf,DIGEST_SIZE+sizeof(uint32_t),
	pikauth);

    if(Memcmp(pikauth,vtcm_in->pikAuth,TCM_HASH_SIZE)!=0)
    {
	returnCode=TCM_AUTHFAIL;
	goto activateidentity_out;
    }	

    // compute ownerauthCode

    Memcpy(Buf,cmdHash,DIGEST_SIZE);
    temp_int=htonl(vtcm_in->ownerAuthHandle);
    Memcpy(Buf+DIGEST_SIZE,&temp_int,sizeof(uint32_t));
    
    sm3_hmac(ownerauthSession->sharedSecret,TCM_HASH_SIZE,
	Buf,DIGEST_SIZE+sizeof(uint32_t),
	ownerauth);

    if(Memcmp(ownerauth,vtcm_in->ownerAuth,TCM_HASH_SIZE)!=0)
    {
	returnCode=TCM_AUTH2FAIL;
	goto activateidentity_out;
    }	
*/
    //  decrypt ca_conts 
	datalen=DIGEST_SIZE*16;
	// decrypt the encData 
	ret=GM_SM2Decrypt(Buf,&datalen, vtcm_in->encData,vtcm_in->encDataSize,
		eKey->encData,eKey->encDataSize);
  	if(ret<0)
	{
		returnCode=TCM_DECRYPT_ERROR;
		goto activateidentity_out;
	}
	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_SYMMETRIC_KEY);
	if(vtcm_template==NULL)
	{
		returnCode=TCM_BADINDEX;
		goto activateidentity_out;
	}
        ret=blob_2_struct(Buf,&vtcm_out->symmkey,vtcm_template);
	
	if(ret<0)
	{
		returnCode=TCM_BAD_PARAMETER;
		goto activateidentity_out;
	}	
	
	Memcpy(&ca_conts.idDigest,Buf+ret,DIGEST_SIZE);

	// compute pubkey's digest

	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_STORE_PUBKEY);
	if(vtcm_template==NULL)
		return -EINVAL;		
	ret=struct_2_blob(&pik->pubKey,Buf,vtcm_template);
	if(ret<0)
	{
		returnCode=-TCM_BAD_DATASIZE;
		goto activateidentity_out;
	}

	sm3(Buf,ret,pubDigest);

	if(Memcmp(pubDigest,&ca_conts.idDigest,DIGEST_SIZE)!=0)
	{
		returnCode=TCM_AUTHFAIL;
		goto activateidentity_out;
	}

activateidentity_out:

    vtcm_out->tag=0xC600;
    vtcm_out->returnCode=returnCode;
    void *send_msg;
    if(returnCode!=0)
    {
    	// error output process
	Free(vtcm_out);
	vtcm_err_out=Talloc(sizeof(*vtcm_err_out));
	if(vtcm_err_out==NULL)
		return -ENOMEM;
    	vtcm_err_out->tag = 0xC400;
    	vtcm_err_out->paramSize = sizeof(*vtcm_err_out);
    	vtcm_err_out->returnCode = returnCode;
    	send_msg = message_create(DTYPE_VTCM_EXTERNAL ,SUBTYPE_RETURN_DATA_EXTERNAL,recv_msg);
    	if(send_msg == NULL)
    	{
        	printf("send_msg == NULL\n");
        	return -EINVAL;      
    	}
    	message_add_record(send_msg, vtcm_out);
    }
    else
    {  	
       	ret = vtcm_Compute_AuthCode(vtcm_out,
                               	        DTYPE_VTCM_OUT,
                                    	SUBTYPE_ACTIVATEIDENTITY_OUT,
                                    	pikauthSession,
                                    	vtcm_out->pikAuth);
    	if(ret == TCM_SUCCESS)
    	{
        	ret = vtcm_Compute_AuthCode2(vtcm_out,
                                    	DTYPE_VTCM_OUT,
                                    	SUBTYPE_ACTIVATEIDENTITY_OUT,
                                    	ownerauthSession,
                                    	vtcm_out->ownerAuth);
    	}
    	vtcm_template=memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_ACTIVATEIDENTITY_OUT);
	if(vtcm_template==NULL)
		return -EINVAL;
    	vtcm_out->paramSize = struct_2_blob(vtcm_out, Buf, vtcm_template);


      	send_msg = message_create(DTYPE_VTCM_OUT ,SUBTYPE_ACTIVATEIDENTITY_OUT ,recv_msg);
    	if(send_msg == NULL)
    	{
        	printf("send_msg == NULL\n");
        	return -EINVAL;      
    	}
   	message_add_record(send_msg, vtcm_out);
    }	
 
      // add vtcm's expand info	
     ret=vtcm_addcmdexpand(send_msg,recv_msg);
     if(ret<0)
     {
 	    printf("fail to add vtcm copy info!\n");
     }	
     ret = ex_module_sendmsg(sub_proc, send_msg);
     return ret;
}

static int proc_vtcm_Quote(void* sub_proc, void* recv_msg)
{

    int ret = 0;
    int i = 0;
    int offset=0;
    int keylen;
    int datalen;
    int got_handle;
    uint32_t            entityValue = 0;        /* The selection value based on entityType, e.g. a
                                                   keyHandle # */
    TCM_ENTITY_TYPE     entityType;             /* The type of entity in use */
    uint32_t authHandle = 0;
    TCM_SESSION_DATA *authSession;
    TCM_DIGEST  *entityDigest = NULL;   /* digest of the entity establishing the OSAP
                                                   session, initialize to silence compiler */
    TCM_SECRET          *authData;              /* usageAuth for the entity */


    TCM_BOOL parentPCRStatus; 
    TCM_KEY * pik;
    TCM_QUOTE_INFO quoteinfo;
    BYTE * signdata;
    BYTE cmdHash[DIGEST_SIZE];
    BYTE CheckData[TCM_HASH_SIZE];

    //input process
    struct tcm_in_Quote *vtcm_in;
    struct tcm_out_Quote *vtcm_out;
    void *vtcm_template;
    uint32_t returnCode=0;
    BYTE pikauth[TCM_HASH_SIZE];
    
    printf("proc_vtcm_TakeOwnership : Start\n");
    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0); // get structure 
    if(ret < 0) 
        return ret;
    if(vtcm_in == NULL)
        return -EINVAL;
    vtcm_out=Talloc0(sizeof(*vtcm_out));
    if(vtcm_out==NULL)
	return -ENOMEM;
    
    //get auth session
    tcm_state_t* curr_tcm = ex_module_getpointer(sub_proc);

    ret=vtcm_AuthSessions_GetEntry(&authSession,curr_tcm->tcm_stany_data.sessions,vtcm_in->authHandle);
    if(ret<0)
    {
	returnCode=-TCM_INVALID_AUTHHANDLE;
	goto quote_out;	
    }

    // Get the pik
        ret = vtcm_KeyHandleEntries_GetKey(&pik, 
                                           &parentPCRStatus, 
                                           curr_tcm, 
                                           vtcm_in->keyHandle,
                                           FALSE,     // not r/o, using to encrypt
                                           FALSE,     // do not ignore PCRs
                                           FALSE);    // cannot use EK

    if(ret != TCM_SUCCESS)
    {
	returnCode=-TCM_INVALID_KEYHANDLE;
	goto quote_out;

    }
    // generate command's bin blob
    	vtcm_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_QUOTE_IN);
    	if(vtcm_template==NULL)
    		return -EINVAL;
    	offset = struct_2_blob(vtcm_in,Buf,vtcm_template);
    	if(offset<0)
    		return offset;

    // check privAuth
    uint32_t temp_int;
    // compute authCode

    if(ret == TCM_SUCCESS)
    {
      ret = vtcm_Compute_AuthCode(vtcm_in,
                                  DTYPE_VTCM_IN,
                                  SUBTYPE_QUOTE_IN,
                                  authSession,
                                  CheckData);
    }
    if(Memcmp(CheckData, vtcm_in->privAuth, TCM_HASH_SIZE)!=0)
    {
	returnCode=TCM_AUTHFAIL;
	goto quote_out;
    }	
 
    // Build TCM_PCR_COMPOSITE 
    Memcpy(&vtcm_out->pcrData.select,&vtcm_in->targetPCR,sizeof(TCM_PCR_SELECTION));
    ret=vtcm_Fill_PCRComposite(&vtcm_out->pcrData,curr_tcm);
    if(ret<0)
    {
	returnCode=-TCM_BADINDEX;
	goto quote_out;
    }	  
    // Build TCM_PCR_INFO_LONG
   
    Memset(&quoteinfo,0,sizeof(TCM_QUOTE_INFO));
    quoteinfo.info.tag=TCM_TAG_PCR_INFO;
    quoteinfo.info.localityAtCreation=0;
    quoteinfo.info.localityAtRelease=TCM_LOC_ONE|TCM_LOC_TWO|TCM_LOC_THREE|TCM_LOC_FOUR;

    Memcpy(&quoteinfo.info.creationPCRSelection,&vtcm_in->targetPCR,sizeof(TCM_PCR_SELECTION));
      
    vtcm_template=memdb_get_template(DTYPE_VTCM_PCR,SUBTYPE_TCM_PCR_COMPOSITE);
    if(vtcm_template==NULL)
    	return -EINVAL;
    ret=struct_2_blob(&vtcm_out->pcrData,Buf,vtcm_template);	

    sm3(Buf,ret,&quoteinfo.info.digestAtCreation);

    quoteinfo.tag=TCM_TAG_QUOTE_INFO;
    Memcpy(quoteinfo.fixed,"QUOT",4);
    Memcpy(quoteinfo.externalData,vtcm_in->externalData,DIGEST_SIZE);
	
    // load signature key
  /* 
       ret = vtcm_KeyHandleEntries_GetKey(&pik,
                 &parentPCRStatus,
                 curr_tcm,
                 vtcm_in->keyHandle,
                 TRUE,          // read only 
                 TRUE,          // ignore PCRs 
                 FALSE);        // cannot use EK 
        if(ret<0)
        {
		returnCode=-TCM_KEYNOTFOUND;
		goto quote_out;
        }
*/
	TCM_STORE_ASYMKEY * privpik;
        ret = vtcm_Key_GetStoreAsymkey(&privpik, pik);
        if(ret != TCM_SUCCESS)
        {
		returnCode=-TCM_KEYNOTFOUND;
		goto quote_out;
        }

     // compute sig data

    vtcm_template=memdb_get_template(DTYPE_VTCM_PCR,SUBTYPE_TCM_QUOTE_INFO);
    if(vtcm_template==NULL)
	return -EINVAL;
    ret=struct_2_blob(&quoteinfo,Buf,vtcm_template);

	offset=ret;
	BYTE * signedData=Buf+ret+1;
	unsigned long pulSigLen=512;
	BYTE UserID[DIGEST_SIZE];
	int datasize=ret;
	unsigned long lenUID=DIGEST_SIZE;
	Memset(UserID,'A',32);	

	
	ret=GM_SM2Sign(signedData,&pulSigLen,Buf,ret,UserID,lenUID,privpik->privKey.key,privpik->privKey.keyLength);	
	if(ret!=0)
	{
		returnCode=-TCM_BAD_SIGNATURE;
		goto quote_out;	
	}

	vtcm_out->sigSize=pulSigLen;
	vtcm_out->sig=Talloc0(vtcm_out->sigSize);
	Memcpy(vtcm_out->sig,signedData,vtcm_out->sigSize);

quote_out:

    vtcm_out->tag=0xC500;
    vtcm_out->returnCode=returnCode;

    if(ret == TCM_SUCCESS)
    {
      ret = vtcm_Compute_AuthCode(vtcm_out,
                                  DTYPE_VTCM_OUT,
                                  SUBTYPE_QUOTE_OUT,
                                  authSession,
                                  vtcm_out->resAuth);
    }
    void *send_msg = message_create(DTYPE_VTCM_OUT ,SUBTYPE_QUOTE_OUT ,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n");
        return -EINVAL;      
    }
    int responseSize = 0;
    vtcm_template=memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_QUOTE_OUT);
    responseSize = struct_2_blob(vtcm_out, Buf, vtcm_template);
    if(responseSize<0)
	return responseSize;

    vtcm_out->paramSize = responseSize;
    message_add_record(send_msg, vtcm_out);
 
      // add vtcm's expand info	
     ret=vtcm_addcmdexpand(send_msg,recv_msg);
     if(ret<0)
     {
 	  printf("fail to add vtcm copy info!\n");
     }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
	
}

