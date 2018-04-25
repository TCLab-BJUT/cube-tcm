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
#include "auth_func.h"
#include "app_struct.h"
#include "tcm_global.h"
#include "tcm_error.h"
#include "sm2.h"
#include "sm3.h"
#include "vtcm_struct.h"

static BYTE Buf[DIGEST_SIZE*64];

void print_bin_data(BYTE * data,int len,int width)
{
    int i;
    for(i=0;i<len;i++){
        printf("%.2x ",data[i]);
        if (width>0)
        { 	
            if((i+1)%width==0)
                printf("\n");
        }
    }
    printf("\n");
}

int vtcm_setscene(void * sub_proc,void * recv_msg)
{
	int ret;
	int type=DTYPE_VTCM_STRUCT;	
	int subtype=SUBTYPE_VTCM_CMD_HEAD;
	MSG_EXPAND * msg_expand;
	struct vtcm_manage_cmd_head * cmd_head;
	struct vtcm_manage_return_head * return_head;
    	tcm_state_t * tcm_instances = proc_share_data_getpointer();

	ret=message_get_define_expand(recv_msg,&msg_expand,DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_CMD_HEAD);
	if(ret<0)
		return ret;
	if(msg_expand==NULL)
        {
		ret=message_get_define_expand(recv_msg,&msg_expand,DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_RETURN_HEAD);
		if(ret<0)
			return ret;
		if(msg_expand==NULL)
			return 0;
        }
	cmd_head=msg_expand->expand;
	if(cmd_head==NULL)
	{
    		ex_module_setpointer(sub_proc,&tcm_instances[0]);
		return 0;
	}
	else
	{
    		ex_module_setpointer(sub_proc,&tcm_instances[cmd_head->vtcm_no]);
	}
	return cmd_head->vtcm_no;
}

int vtcm_addcmdexpand(void * send_msg,void * recv_msg)
{
	int ret;
	int type=DTYPE_VTCM_STRUCT;	
	int subtype=SUBTYPE_VTCM_CMD_HEAD;
	struct vtcm_manage_cmd_head * cmd_head;
	struct vtcm_manage_return_head * return_head;
	MSG_EXPAND * msg_expand;

	ret=message_get_define_expand(recv_msg,&msg_expand,DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_CMD_HEAD);
	if(ret<0)
		return ret;
	if(msg_expand==NULL)
		return 0;
	cmd_head=msg_expand->expand;
	if(cmd_head==NULL)
	{
		return 0;
	}
	else
	{
		return_head=Talloc0(sizeof(*return_head));
		return_head->tag=TCM_TAG_RSP_VTCM_COMMAND;
		return_head->paramSize=0;
		return_head->vtcm_no=cmd_head->vtcm_no;
		return_head->returnCode=VTCM_RETURN_TRANS;
	}
	message_add_expand_data(send_msg,DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_RETURN_HEAD,return_head);
	return cmd_head->vtcm_no;
}

int RAND_bytes(unsigned char *buffer, size_t len) 
{
    int ret, fd;
    const char * randomfile = "/dev/urandom";
    fd = open(randomfile, O_RDONLY);
    if (fd < 0) { 
        perror("open urandom device:");
        return fd;
    }    
    int readn = 0; 
    while (readn != len) {
        ret = read(fd, buffer + readn, len - readn);
        if (ret < 0) { 
            perror("read urandom device:");
            return ret; 
        }    
        readn += ret; 
    }    
    return 0;
}                                                                                                                                                                                                                

/***
    TCM_KEY_PARMS init
***/
void vtcm_KeyParms_Init(TCM_KEY_PARMS* tcm_key_parms)
{
    printf("vtcm_KeyParms_Init:\n");
    tcm_key_parms->algorithmID = 0;
    tcm_key_parms->encScheme = TCM_ES_NONE;
    tcm_key_parms->sigScheme = TCM_SS_NONE;
    tcm_key_parms->parmSize = 0;
    tcm_key_parms->parms = NULL;
}

/***
    vtcm_StorePubKey_Init

***/

void vtcm_StorePubKey_Init(TCM_STORE_PUBKEY* tcm_pubKey)
{
    printf("vtcm_StorePubKey_Init :\n");
    tcm_pubKey->keyLength = 0;
    tcm_pubKey->key = NULL;
}

/***
    vtcm_StoreAsyKey_Init
***/

void vtcm_StoreAsymKey_Init(TCM_STORE_ASYMKEY* tcm_store_asymkey)
{
    printf(" vtcm_StoreAsymkey_Init:\n");

    tcm_store_asymkey->payload = TCM_PT_ASYM;
    memset(tcm_store_asymkey->usageAuth, 0, TCM_SECRET_SIZE);
    memset(tcm_store_asymkey->migrationAuth, 0, TCM_SECRET_SIZE);
    memset(tcm_store_asymkey->pubDataDigest.digest, 0, TCM_DIGEST_SIZE);
    tcm_store_asymkey->privKey.keyLength = 0;
    tcm_store_asymkey->privKey.key = NULL;
}


/***
    vtcm_Key_Init

***/
void vtcm_Key_Init(TCM_KEY* tcm_key)
{
    printf("vtcm_Key_Init:\n");
    tcm_key->tag = htons(TCM_TAG_KEY);
    tcm_key->fill = 0x0000;
    tcm_key->keyUsage = TCM_KEY_UNINITIALIZED; // TCM_KEY_USAGE
    tcm_key->keyFlags = 0; // TCM_KEY_FLAGS
    tcm_key->authDataUsage = 0; // TCM_AUTHDATA_USAGE
    vtcm_KeyParms_Init(&(tcm_key->algorithmParms)); // TCM_KEY_PARMS
    tcm_key->PCRInfoSize = 0;
    tcm_key->PCRInfo = NULL;
    vtcm_StorePubKey_Init(&(tcm_key->pubKey));
    tcm_key->encDataSize = 0;
    tcm_key->encData = NULL;
}

/***
    vtcm_KeyParms_Copy

***/

int vtcm_KeyParms_Copy(TCM_KEY_PARMS* tcm_key_parms_dest,
    TCM_KEY_PARMS* tcm_key_parms)
{
    printf("vtcm_KeyParms_Copy :\n");

    int ret = 0;

    tcm_key_parms_dest->algorithmID = tcm_key_parms->algorithmID;
    tcm_key_parms_dest->encScheme = tcm_key_parms->encScheme;
    tcm_key_parms_dest->sigScheme = tcm_key_parms->sigScheme;

    tcm_key_parms_dest->parmSize = tcm_key_parms->parmSize;
    tcm_key_parms_dest->parms = malloc(sizeof(unsigned char) * tcm_key_parms->parmSize);
    memcpy(tcm_key_parms_dest->parms, tcm_key_parms->parms,
        tcm_key_parms->parmSize);
    return ret;
}

/***
    vtcm_Key_Set
***/
int vtcm_Key_Set(TCM_KEY* tcm_key, TCM_KEY_USAGE keyUsage,
    TCM_KEY_FLAGS keyFlags, TCM_AUTH_DATA_USAGE authDataUsage,
    TCM_KEY_PARMS* tcm_key_parms, uint32_t keyLength,
    BYTE* pubKey)
{
    int ret = 0;
    printf("vtcm_Key_Set :\n");

    if (ret == 0) {
        vtcm_Key_Init(tcm_key);
        // TCM_KEY_USAGE
        tcm_key->keyUsage = keyUsage;
        // TCM_KEY_FLAGS
        tcm_key->keyFlags = keyFlags;
        // TCM_AUTH_DATA_USAGE
        tcm_key->authDataUsage = authDataUsage;
        // TCM_KEY_PARMS
        vtcm_KeyParms_Copy(&(tcm_key->algorithmParms), tcm_key_parms);
        // TCM_STORE_PUBKEY
        tcm_key->pubKey.keyLength = keyLength;
        tcm_key->pubKey.key = malloc(tcm_key->pubKey.keyLength);
        memcpy(tcm_key->pubKey.key, pubKey, keyLength);
    }
    return ret;
}

void vtcm_Fill_PubKey(TCM_PUBKEY* pubEndorsementKey, TCM_KEY_PARMS* keyInfo,
    TCM_STORE_PUBKEY* pre_pubKey)
{
    printf("vtcm_Fill_PubKey : Start\n");
    // Filling TCM_KEY_PARMS
    TCM_KEY_PARMS* algorithmParms = &(pubEndorsementKey->algorithmParms);
    algorithmParms->algorithmID = keyInfo->algorithmID;
    algorithmParms->encScheme = keyInfo->encScheme;
    algorithmParms->sigScheme = keyInfo->sigScheme;
    algorithmParms->parmSize = keyInfo->parmSize;
    algorithmParms->parms = keyInfo->parms;

    // Filling TCM_STORE_PUBKEY
    TCM_SIZED_BUFFER* pubKey = &(pubEndorsementKey->pubKey);
    pubKey->size = pre_pubKey->keyLength;
    pubKey->buffer = pre_pubKey->key;
}

/***
    vtcm_KeyParms_GetSM2KeyParms

***/

int vtcm_Key_GetSM2KeyParms(TCM_SM2_ASYMKEY_PARAMETERS** tcm_sm2_asymkey_parameters,
    TCM_KEY_PARMS* tcm_key_parms)
{
    printf("vtcm_KeyParms_GetSM2KeyParms :\n");
    int ret = 0;
    // Get the entire command template
    void* command_template = memdb_get_template(
        DTYPE_VTCM_IN_KEY, SUBTYPE_TCM_BIN_SM2_ASYMKEY_PARAMETERS);
    if (command_template == NULL) {
        printf("can't solve this command!\n");
    }
    *tcm_sm2_asymkey_parameters = malloc(struct_size(command_template));
    ret = blob_2_struct(tcm_key_parms->parms, *tcm_sm2_asymkey_parameters,
        command_template);
    if (ret >= 0) {
        ret = 0;
    }
    return ret;
}

int vtcm_Key_GenerateSM2(TCM_KEY* tcm_key, tcm_state_t* tcm_state,
    TCM_KEY* parent_key,
    TCM_PCRVALUE* tcm_pcrs,
    TCM_KEY_USAGE keyUsage,
    TCM_KEY_FLAGS keyFlags,
    TCM_AUTH_DATA_USAGE authDataUsage,
    TCM_KEY_PARMS* tcm_key_parms,
    TCM_PCR_INFO* tcm_pcr_info,
    TCM_PCR_INFO_LONG* tcm_pcr_info_long)
{
    int ret = 0;
    printf("vtcm_Key_GenerateSM2 :Start\n");

    TCM_STORE_PUBKEY* pubKey = &(tcm_key->pubKey);
    TCM_SM2_ASYMKEY_PARAMETERS* tcm_sm2_asymkey_parameters = NULL;

    unsigned char prikey[200];
    unsigned long pulPriLen = 200;
    unsigned char pubkey_XY[64];
    if (ret == 0) {
        ret = vtcm_Key_GetSM2KeyParms(&tcm_sm2_asymkey_parameters, tcm_key_parms);
    }
    uint32_t nbytes = tcm_sm2_asymkey_parameters->keyLength / 8;
    if (ret == 0) {
        ret = GM_GenSM2keypair(prikey, &pulPriLen, pubkey_XY);
    }

    vtcm_Key_Set(tcm_key, keyUsage, keyFlags, authDataUsage, tcm_key_parms,
        64, pubkey_XY);

    if (ret == 0) {
        tcm_key->encDataSize = pulPriLen;
        tcm_key->encData = malloc(sizeof(unsigned char) * pulPriLen);
        memcpy(tcm_key->encData, prikey, pulPriLen);
    }

    free(tcm_sm2_asymkey_parameters);
    return ret;
}

int vtcm_IsSymKey (TCM_KEY * tcm_key)
{
	if(tcm_key==NULL)
		return -EINVAL;
	switch(tcm_key->algorithmParms.algorithmID)
	{
		case TCM_ALG_KDF:
		case TCM_ALG_XOR:
		case TCM_ALG_SM2:
		case TCM_ALG_SM3:
		case TCM_ALG_HMAC:
			return 0;
		case TCM_ALG_SM4:
			return 1;
		default:
			return -EINVAL;
	}
}
			
int vtcm_IsAsymKey (TCM_KEY * tcm_key)
{
	if(tcm_key==NULL)
		return -EINVAL;
	switch(tcm_key->algorithmParms.algorithmID)
	{
		case TCM_ALG_KDF:
		case TCM_ALG_XOR:
		case TCM_ALG_SM4:
		case TCM_ALG_SM3:
		case TCM_ALG_HMAC:
			return 0;
		case TCM_ALG_SM2:
			return 1;
		default:
			return -EINVAL;
	}
}

int vtcm_SM4Key_To_Blob(TCM_STORE_SYMKEY * sym_key, BYTE * blob)
{
	int ret;
	void * vtcm_template;
    	vtcm_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_STORE_SYMKEY);
	if(vtcm_template==NULL)
		return -EINVAL;

	ret=struct_2_blob(sym_key,blob,vtcm_template);
	return ret;
}

int vtcm_Keystruct_GenerateSM4(TCM_KEY* tcm_key,TCM_SECRET * usageAuth,TCM_SECRET * migrationAuth)
{

   int ret;
   TCM_STORE_SYMKEY * sym_key;	
   BYTE * temp_blob;
   
   if(tcm_key==NULL)
	return -EINVAL; 	
   if((ret=vtcm_IsSymKey(tcm_key))<=0)
		return NULL;

    sym_key=Talloc0(sizeof(*sym_key));
    sym_key->payload=TCM_PT_SYM;
    if(usageAuth!=NULL)
    	Memcpy(sym_key->usageAuth,usageAuth,sizeof(*usageAuth));
    if(migrationAuth!=NULL)
    	Memcpy(sym_key->migrationAuth,migrationAuth,sizeof(*migrationAuth));
	
    sym_key->size=32;	
    sym_key->data=Talloc0(sym_key->size);
    if(sym_key->data==NULL)
    	return -ENOMEM;
    RAND_bytes(sym_key->data,sym_key->size);

    temp_blob=Talloc0(1024);
    ret=vtcm_SM4Key_To_Blob(sym_key,temp_blob);
    if(ret<0)
	return ret;
    tcm_key->encDataSize=ret;
    tcm_key->encData=Dalloc0(tcm_key->encDataSize,tcm_key);
    if(tcm_key->encData==NULL)
	return -ENOMEM;
    Memcpy(tcm_key->encData,temp_blob,tcm_key->encDataSize);	   	
    return 0;   
}

int vtcm_Random(BYTE* buffer, size_t bytes)
{
    printf("vtcm_Random : Start\n");

    int ret = 0;

    if (ret == 0) { /* openSSL call */
        ret = RAND_bytes(buffer, bytes);
        if (ret < 0) { 
            printf("TCM_Random: Error (fatal) calling RAND_bytes()\n");
            ret = -TCM_FAIL;
        }
    }
    return ret;
}
/*
int vtcm_SHA1(void* input, unsigned int len, unsigned char* output)
{
    printf("vtcm_SHA1 : Start\n");
    int ret = 0;

    SHA_CTX sha;
    SHA1_Init(&sha);
    SHA1_Update(&sha, input, len);
    SHA1_Final(output, &sha);

    return ret;
}
*/
int vtcm_SM3(BYTE* checksum, unsigned char* buffer, int size)
{
    printf("vtcm_SM3: Start\n");
    int ret = 0;
    sm3_context ctx;
    sm3_starts(&ctx);
    sm3_update(&ctx, buffer, size);
    sm3_finish(&ctx, checksum);
    return ret;
}

int vtcm_HMAC_SM3(BYTE *key, int keylen, BYTE *buffer, int size, BYTE *output)
{
    printf("vtcm_HMAC_SM3 : Start\n");
    int ret = 0;
    sm3_context ctx;
    sm3_hmac_starts(&ctx, key, keylen);
    sm3_hmac_update(&ctx, buffer, size);
    sm3_hmac_finish(&ctx, output);
    return ret;
}

int vtcm_Create_Checksum(BYTE* checksum, TCM_PUBKEY* pubEndorsementKey,
    BYTE* antiReplay)
{
    printf("vtcm_Create_checksum : Start\n");

    int ret = 0;
    int buflen = 0;
    int binsize = 0;
    BYTE* buffer = (BYTE*)malloc(sizeof(BYTE) * 512);

    // pubEndorsementKey to blob
    if (ret == 0) {
        void* template_tcm_pubkey = memdb_get_template(DTYPE_VTCM_IN_KEY, SUBTYPE_TCM_BIN_PUBKEY);
        if (template_tcm_pubkey == NULL) {
            printf("can't solve this command!\n");
            return -1;
        }
        binsize = struct_2_blob(pubEndorsementKey, buffer, template_tcm_pubkey);
        if (binsize <= 0) {
            printf("error : ret = %d\n", ret);
            ret = binsize;
        }
        else {
            buflen = binsize;
        }
    }

    // add antiReplay to buffer
    memcpy(buffer + buflen, antiReplay, 32);
    buflen += 32;

    // get checksum
    if (ret == 0) {
        ret = vtcm_SM3(checksum, buffer, buflen);
    }
    return ret;
}

int vtcm_PubKey_Copy(TCM_SIZED_BUFFER* pubkey_des, TCM_STORE_PUBKEY* pubkey_src)
{
    int ret = 0;
    pubkey_des->size = pubkey_src->keyLength;
    pubkey_des->buffer = (unsigned char*)malloc(sizeof(unsigned char*) * pubkey_src->keyLength);
    memcpy(pubkey_des->buffer, pubkey_src->key, pubkey_src->keyLength);
    return ret;
}
/*
int vtcm_CreateEndorsementKeyPair_Common(TCM_KEY* endorsementKey,
    TCM_PUBKEY* pubEndorsementKey,
    BYTE* checksum,
    tcm_state_t* tcm_state,
    TCM_KEY_PARMS* keyInfo,
    BYTE* antiReplay)
{
    int ret = 0;
    TCM_SM2_ASYMKEY_PARAMETERS tcm_sm2_asymkey_parameters;

    // 1. If an EK already exists, return TCM_DISABLED_CMD 
    if (ret == 0) {
        if (endorsementKey->keyUsage != TCM_KEY_UNINITIALIZED) {
            printf("vtcm_CreateEndorsementKeyPair: Error, key already initialized\n");
            ret = TCM_DISABLED_CMD;
        }
    }
    // 2. Validate the keyInfo parameters for the key description 
    if (ret == 0) {
        if (keyInfo->algorithmID == TCM_ALG_SM2) {

            void* command_template_sm2 = memdb_get_template(DTYPE_VTCM_IN_KEY,
                SUBTYPE_TCM_BIN_SM2_ASYMKEY_PARAMETERS);
            if (command_template_sm2 == NULL) {
                printf("miss sm2 asymkey_parameters!\n");
            }
            ret = blob_2_struct(keyInfo->parms, &tcm_sm2_asymkey_parameters, command_template_sm2);
            if (ret <= 0) {
                printf("sm2 params error! b2s : ret = %d\n", ret);
            }
            else {
                ret = 0;
            }
            if (tcm_sm2_asymkey_parameters.keyLength != 256) {
                printf("TCM_CreateEndorsementKeyPair_Common: Error, Bad keyLength should "
                       "be %u, was %u\n",
                    256, tcm_sm2_asymkey_parameters.keyLength);
                ret = TCM_BAD_KEY_PROPERTY;
            }
        }
        else {
            printf("vtcm_CreateEndorsementKeyPair_Common: Error, "
                   "algorithmID %08x not supported\n",
                keyInfo->algorithmID);
            ret = TCM_BAD_KEY_PROPERTY;
        }
    }

    if (ret == 0) {
        if (keyInfo->encScheme != TCM_ES_SM2) {
            ret = TCM_BAD_KEY_PROPERTY;
        }
    }

    if (ret == 0) {
        keyInfo->sigScheme = TCM_ES_NONE;
        ret = vtcm_Key_GenerateSM2(endorsementKey,
            tcm_state,
            NULL,
            tcm_state->tcm_stclear_data.PCRS,
            TCM_KEY_STORAGE,
            0,
            TCM_AUTH_ALWAYS,
            keyInfo,
            NULL,
            NULL);
    }

    // copy key parameters
    if (ret == 0) {
        ret = vtcm_KeyParms_Copy(&(pubEndorsementKey->algorithmParms), keyInfo);
    }

    // copy pubEk info
    if (ret == 0) {
        ret = vtcm_PubKey_Copy(&(pubEndorsementKey->pubKey), &(endorsementKey->pubKey));
    }

    // create checksum
    if (ret == 0) {
        ret = vtcm_Create_Checksum(checksum, pubEndorsementKey, antiReplay);
    }

    if (ret == 0) {
        tcm_state->tcm_permanent_flags.enableRevokeEK = FALSE;
    }
    return ret;
}
*/
int vtcm_Nonce_Generate(TCM_NONCE tcm_nonce)
{
    printf("vtcm_Nonce_Generate :\n");

    int ret = 0;

    /* openSSL call */
    ret = RAND_bytes(tcm_nonce, TCM_NONCE_SIZE);

    return ret;
}

int vtcm_Nonce_Compare(TCM_NONCE expect, const TCM_NONCE actual)
{
    int ret = 0;
    printf("Nonce_Compare:\n");
    ret = memcmp(expect, actual, TCM_NONCE_SIZE);
    if(ret != 0) {
        printf("vtcm_Nonce_Compare: Error comparing nonce\n");
        ret = TCM_AUTHFAIL;
    }
    return ret;
}
/* TCM_AuthSessions_IsSpace() returns 'isSpace' TRUE if an entry is available,
   FALSE if not.

   If TRUE, 'index' holds the first free position.
*/

void vtcm_AuthSessions_IsSpace(TCM_BOOL* isSpace, uint32_t* index,
    TCM_SESSION_DATA* sessions)
{
    printf(" vtcm_AuthSessions_IsSpace :\n");

    for (*index = 0, * isSpace = FALSE; *index < TCM_MIN_AUTH_SESSIONS;
         (*index)++) {
        if (!((sessions[*index]).valid)) {
            printf("  vtcm_AuthSessions_IsSpace: Found space at %u\n", *index);
            *isSpace = TRUE;
            break;
        }
    }
    return;
}
/*
void vtcm_KeyHandleEntries_IsSpace(TCM_BOOL* isSpace, uint32_t* index,
    TCM_KEY_HANDLE_ENTRY* entries)
{
    printf(" vtcm_KeyHandleEntries_IsSpace :\n");

    for (*index = 0, * isSpace = FALSE; *index < TCM_KEY_HANDLES;
         (*index)++) {
        if (!((entries[*index]).key)) {
            printf("  vtcm_KeyHandleEntries_IsSpace: Found space at %u\n", *index);
            *isSpace = TRUE;
            break;
        }
    }
    return;
}
*/
/* TCM_AuthSessions_GetEntry() searches all entries for the entry matching the
   handle, and
   returns the TCM_SESSION_DATA entry associated with the handle.

   Returns
        0 for success
        TCM_INVALID_AUTHHANDLE if the handle is not found
*/

int vtcm_AuthSessions_GetEntry(
    TCM_SESSION_DATA** tcm_session_data, /* session for authHandle */
    TCM_SESSION_DATA* sessions, /* points to first session */
    TCM_AUTHHANDLE authHandle) /* input */
{
    int ret = 0;
    TCM_BOOL found=FALSE;

    printf(" vtcm_AuthSessions_GetEntry: authHandle %08x\n", authHandle);

    for (int i = 0; (i < TCM_MIN_AUTH_SESSIONS) && !found; i++) {
        if ((sessions[i].valid) && (sessions[i].handle == authHandle)) { /* found */
            found = TRUE;
            *tcm_session_data = &(sessions[i]);
        }
    }
    if (!found) {
        printf("  vtcm_AuthSessions_GetEntry: session handle %08x not found\n",
            authHandle);
        ret = TCM_INVALID_AUTHHANDLE;
    }
    return ret;
}


int vtcm_AuthSessionData_Decrypt(BYTE *retData,
                                 TCM_SESSION_DATA *authSession,
                                 BYTE *encData
                                )
{
    int ret = TCM_SUCCESS;
     int i;
    
    BYTE *sessionKey = authSession->sharedSecret;
    for(i=0;i<TCM_HASH_SIZE;i++)
	retData[i]=encData[i]^sessionKey[i];
    return ret;
}

int vtcm_AuthSessionData_Encrypt(BYTE *retData,
                                 TCM_SESSION_DATA *authSession,
                                 BYTE *plainData)
{
    int ret = TCM_SUCCESS;
     int i;
    
    BYTE *sessionKey = authSession->sharedSecret;
    for(i=0;i<TCM_HASH_SIZE;i++)
	retData[i]=plainData[i]^sessionKey[i];
    return ret;
}

int vtcm_KeyHandle_Entries_GetEntry(
    TCM_KEY_HANDLE_ENTRY** tcm_key_handle_entry, /* session for authHandle */
    TCM_KEY_HANDLE_ENTRY* entries, /* points to first session */
    TCM_AUTHHANDLE authHandle) /* input */
{
    int ret = 0;
    TCM_BOOL found=FALSE;

    printf(" vtcm_KeyHandleEntries_GetEntry: authHandle %08x\n", authHandle);

    for (int i = 0; (i < TCM_KEY_HANDLES) && !found; i++) {
        if ((entries[i].key) && (entries[i].handle == authHandle)) { /* found */
            found = TRUE;
            *tcm_key_handle_entry = &(entries[i]);
        }
    }
    if (!found) {
        printf("  vtcm_KeyHandleEntries_GetEntry: key handle %08x not found\n",
            authHandle);
        ret = TCM_INVALID_AUTHHANDLE;
    }
    return ret;
}

/*
  TCM_Handle_GenerateHandle() is a utility function that returns an unused
  handle.

  It's really not an initialization function, but as the handle arrays are
  typically in
  TCM_STCLEAR_DATA, it's a reasonable home.

  If 'tcm_handle' is non-zero, it is the first value tried.  If 'keepHandle' is
  TRUE, it is the only
  value tried.

  If 'tcm_handle' is zero, a random value is assigned.  If 'keepHandle' is TRUE,
  an error returned,
  as zero is an illegal handle value.

  If 'isKeyHandle' is TRUE, special checking is performed to avoid reserved
  values.

  'getEntryFunction' is a function callback to check whether the handle has
  already been assigned to
  an entry in the appropriate handle list.
*/

int vtcm_Handle_GenerateHandle(TCM_HANDLE* tcm_handle, TCM_SESSION_DATA* tcm_handle_entries,
    TCM_BOOL keepHandle, TCM_BOOL isKeyHandle)
{
    int ret = 0;
    int getRc = 0;
    unsigned int timeout; /* collision timeout */
    TCM_SESSION_DATA* used_handle_entry; /* place holder for discarded entry */
    TCM_BOOL done;

    printf(" vtcm_Handle_GenerateHandle : handle %08x, keepHandle %u\n",
        *tcm_handle, keepHandle);

    /* if the input value must be used */
    if (keepHandle) {
        /* 0 is illegal and cannot be kept */
        if (ret == 0) {
            if (*tcm_handle == 0) {
                printf("TCM_Handle_GenerateHandle: Error, cannot keep handle 0\n");
                ret = TCM_BAD_HANDLE;
            }
        }
        /* key handles beginning with 0x40 are reserved special values */
        if (ret == 0) {
            if (isKeyHandle) {
                if ((*tcm_handle & 0xff000000) == 0x40000000) {
                    printf("TCM_Handle_GenerateHandle: Error, cannot keep reserved key "
                           "handle\n");
                    ret = TCM_BAD_HANDLE;
                }
            }
        }
        /* check if the handle is already used */
        if (ret == 0) {
            getRc = vtcm_AuthSessions_GetEntry(&used_handle_entry, /* discarded entry */
                tcm_handle_entries, /* handle array */
                *tcm_handle); /* search for handle */
            /* success mean the handle has already been assigned */
            if (getRc == 0) {
                printf("TCM_Handle_GenerateHandle: Error handle already in use\n");
                ret = TCM_BAD_HANDLE;
            }
        }
    }
    /* input value is recommended but not required */
    else {
        /* implement a crude timeout in case the random number generator fails and
       there are too
       many collisions */
        done = FALSE;
        for (timeout = 0; (ret == 0) && !done && (timeout < 1000);
             timeout++) {
            /* If no handle has been assigned, try a random value.  If a handle has
         been assigned,
         try it first */
            if (ret == 0) {
                if (*tcm_handle == 0) {
                    RAND_bytes((unsigned char*)tcm_handle, sizeof(uint32_t));
                }
            }
            /* if the random value is 0, reject it immediately */
            if (ret == 0) {
                if (*tcm_handle == 0) {
                    printf("  vtcm_Handle_GenerateHandle: Random value 0 rejected\n");
                    continue;
                }
            }
            /* if the value is a reserved key handle, reject it immediately */
            if (ret == 0) {
                if (isKeyHandle) {
                    if ((*tcm_handle & 0xff000000) == 0x40000000) {
                        printf("  TCM_Handle_GenerateHandle: Random value %08x rejected\n",
                            *tcm_handle);
                        *tcm_handle = 0; /* ignore the assigned value */
                        continue;
                    }
                }
            }
            /* test if the handle has already been used */
            if (ret == 0) {
                getRc = vtcm_AuthSessions_GetEntry(&used_handle_entry, /* discarded entry */
                    tcm_handle_entries, /* handle array */
                    *tcm_handle); /* search for handle */
                if (getRc != 0) { /* not found, done */
                    printf("  vtcm_Handle_GenerateHandle: Assigned Handle %08x\n",
                        *tcm_handle);
                    done = TRUE;
                }
                else { /* found, try again */
                    *tcm_handle = 0; /* ignore the assigned value */
                    printf("  vtcm_Handle_GenerateHandle: Handle %08x already used\n",
                        *tcm_handle);
                }
            }
        }
        if (!done) {
            printf("vtcm_Handle_GenerateHandle: Error (fatal), random number "
                   "generator failed\n");
            ret = TCM_FAIL;
        }
    }
    return ret;
}

/***
   TCM_AuthSessions_GetNewHandle() checks for space in the authorization
sessions table.

   If there is space, it returns a TCM_SESSION_DATA entry in
'tcm_session_data' and its
   handle in 'authHandle'.  The entry is marked 'valid'.

   If *authHandle non-zero, the suggested value is tried first.

   Returns TCM_RESOURCES if there is no space in the sessions table.
***/

int vtcm_AuthSessions_GetNewHandle(
    TCM_SESSION_DATA** tcm_session_data, TCM_AUTHHANDLE* authHandle,
    TCM_SESSION_DATA* sessions)
{
    int ret = 0;
    uint32_t index;
    TCM_BOOL isSpace;

    printf(" vtcm_AuthSessions_GetNewHandle:\n");

    /* is there an empty entry, get the location index */
    if (ret == 0) {
        vtcm_AuthSessions_IsSpace(&isSpace, &index, sessions);
        if (!isSpace) {
            printf("TCM_AuthSessions_GetNewHandle: Error, no space in sessions "
                   "table\n");
            ret = TCM_RESOURCES;
        }
    }
    if (ret == 0) {
        ret = vtcm_Handle_GenerateHandle(authHandle, /* I/O */
                                         sessions, /* handle array */
                                         FALSE, /* keepHandle */
                                         FALSE /* isKeyHandle */
                                        );
    }
    if (ret == 0) {
        printf("  TCM_AuthSessions_GetNewHandle: Assigned handle %08x\n",
            *authHandle);
        *tcm_session_data = &(sessions[index]);
        /* assign the handle */
        (*tcm_session_data)->handle = *authHandle;
        (*tcm_session_data)->valid = TRUE;
    }
    return ret;
}

void vtcm_Generate_Random(int *dest, int num)
{
    printf("  vtcm_Generate_Random : Start\n") ;

    BYTE *response = (BYTE *)malloc(sizeof(BYTE)*num);
    vtcm_Random(response, num);
    *dest = atoi(response)/2; 
}

/* TCM_NVDataPublic_Init()

   sets members to default values
   sets all pointers to NULL and sizes to 0
   always succeeds - no return code
*/

void TCM_NVDataPublic_Init(TCM_NV_DATA_PUBLIC *nv_data)
{
    printf(" TCM_NVDataPublic_Init:\n");
    Memset(nv_data,0,sizeof(*nv_data));
    nv_data->tag=TCM_TAG_NV_DATA_PUBLIC;
    nv_data->nvIndex = TCM_NV_INDEX_LOCK;	/* mark unused */
    vtcm_Init_PcrInfo(&(nv_data->pcrInfoRead));
    vtcm_Init_PcrInfo(&(nv_data->pcrInfoWrite));
    nv_data->permission.tag=TCM_TAG_NV_ATTRIBUTES;
    nv_data->bReadSTClear = FALSE;
    nv_data->bWriteSTClear = FALSE;
    nv_data->bWriteDefine = FALSE; 
    nv_data->dataSize = 0;
    return;
}


/* TCM_NVDataSensitive_Init()

   sets members to default values
   sets all pointers to NULL and sizes to 0
   always succeeds - no return code
*/

void TCM_NVDataSensitive_Init(TCM_NV_DATA_SENSITIVE *nv_sens)
{
    printf(" TCM_NVDataSensitive_Init:\n");
    Memset(nv_sens,0,sizeof(*nv_sens));
    nv_sens->tag=TCM_TAG_NV_DATA_SENSITIVE;
    TCM_NVDataPublic_Init(&(nv_sens->pubInfo));
    return;
}

void vtcm_NVDataSensitive_Delete(TCM_NV_DATA_SENSITIVE *nv_sens)
{
    printf(" TCM_NVDataSensitive_Delete:\n");
    if (nv_sens != NULL) {
	Free(nv_sens->data);
	TCM_NVDataSensitive_Init(nv_sens);
    }
    return;
}
/* TCM_NVIndexEntries_GetEntry() gets the TCM_NV_DATA_SENSITIVE entry corresponding to nvIndex.
 *  Returns TCM_BADINDEX on non-existent nvIndex
 */
int vtcm_NVIndexEntries_GetEntry(TCM_NV_DATA_SENSITIVE **tcm_nv_data_sensitive,
                                 TCM_NV_INDEX_ENTRIES *tcm_nv_index_entries,
                                 TCM_NV_INDEX nvIndex)
{
    printf("vtcm_NVIndexEntries_GetEntry : Start\n");

    int ret = 0; 
    size_t i;   
    TCM_BOOL found;
    printf(" TCM_NVIndexEntries_GetEntry: Getting NV index %08x in %u slots\n",
                      nvIndex, tcm_nv_index_entries->nvIndexCount);
    /* for debug tracing */
    for (i = 0 ; i < tcm_nv_index_entries->nvIndexCount ; i++) 
    {
        *tcm_nv_data_sensitive = &(tcm_nv_index_entries->tcm_nvindex_entry[i]);
        printf("   TCM_NVIndexEntries_GetEntry: slot %lu entry %08x\n",
              (unsigned long)i, (*tcm_nv_data_sensitive)->pubInfo.nvIndex);              
    }    
    /* check for the special index that indicates an empty entry */
    if (ret == 0) 
    { 
        if (nvIndex == TCM_NV_INDEX_LOCK) 
        {
            ret = TCM_BADINDEX;                      
        }    
    }
    for (i = 0 , found = FALSE ;
                  (ret == 0) && (i < tcm_nv_index_entries->nvIndexCount) && !found ;
                  i++) 
    {
        *tcm_nv_data_sensitive = &(tcm_nv_index_entries->tcm_nvindex_entry[i]);
        if ((*tcm_nv_data_sensitive)->pubInfo.nvIndex == nvIndex)
        {
            printf("  TCM_NVIndexEntries_GetEntry: Found NV index at slot %lu\n", (unsigned long)i);
            printf("  TCM_NVIndexEntries_GetEntry: permission %08x dataSize %u\n",
                  (*tcm_nv_data_sensitive)->pubInfo.permission.attributes,
                  (*tcm_nv_data_sensitive)->pubInfo.dataSize);
            printf("  TCM_NVIndexEntries_GetEntry: "
                   "bReadSTClear %02x bWriteSTClear %02x bWriteDefine %02x\n",
                   (*tcm_nv_data_sensitive)->pubInfo.bReadSTClear,
                   (*tcm_nv_data_sensitive)->pubInfo.bWriteSTClear,
                   (*tcm_nv_data_sensitive)->pubInfo.bWriteDefine);
            found = TRUE;
                                                                            
        }    
                    
    }    
    if (ret == 0) 
    { 
        if (!found) 
        {
            printf("  TCM_NVIndexEntries_GetEntry: NV index not found\n");
            ret = TCM_BADINDEX;                                 
        }
    }
    return ret;
}

/* TCM_NVIndexEntries_GetFreeEntry() gets a free entry in the TCM_NV_INDEX_ENTRIES array.

   If a free entry exists, it it returned.  It should already be initialized.

   If a free entry does not exist, it it created and initialized.

   If a slot cannot be created, tcm_nv_data_sensitive returns NULL, so a subsequent free is safe.
*/

TCM_RESULT vtcm_NVIndexEntries_GetFreeEntry(TCM_NV_DATA_SENSITIVE **nv_sens,
					   TCM_NV_INDEX_ENTRIES *nv_entries)
{
    TCM_RESULT		rc = 0;
    TCM_BOOL		done = FALSE;
    size_t 		i;

    printf(" TCM_NVIndexEntries_GetFreeEntry: Searching %u slots\n",
	   nv_entries->nvIndexCount);
    /* for debug - trace the entire TCM_NV_INDEX_ENTRIES array */
    for (i = 0 ; i < nv_entries->nvIndexCount ; i++) {
	*nv_sens = &(nv_entries->tcm_nvindex_entry[i]);
	printf("   TCM_NVIndexEntries_GetFreeEntry: slot %lu entry %08x\n",
	       (unsigned long)i, (*nv_sens)->pubInfo.nvIndex);
    }    
    /* search the existing array for a free entry */
    for (i = 0 ; (rc == 0) && (i < nv_entries->nvIndexCount) && !done ; i++) {
	*nv_sens = &(nv_entries->tcm_nvindex_entry[i]);
	/* if the entry is not used */
	if ((*nv_sens)->pubInfo.nvIndex == TCM_NV_INDEX_LOCK) {
	    printf("  TCM_NVIndexEntries_GetFreeEntry: Found free slot %lu\n", (unsigned long)i);
	    done = TRUE;
	}
    }
    /* need to expand the array */
    if ((rc == 0) && !done) {
	*nv_sens = NULL;
        TCM_NV_DATA_SENSITIVE * temp_nv_entries = Dalloc0(sizeof(TCM_NV_DATA_SENSITIVE)*(i+1),NULL);
	if(temp_nv_entries==NULL)
        {
		rc=TCM_NOSPACE;
		return rc;
        }
	if(nv_entries->tcm_nvindex_entry !=NULL)
	{
		void * vtcm_template=memdb_get_template(DTYPE_VTCM_NV,SUBTYPE_TCM_NV_DATA_SENSITIVE);
		if(vtcm_template==NULL)
			return TCM_BAD_PARAMETER;
		for(i=0;i<nv_entries->nvIndexCount;i++)
		{
			struct_clone(&nv_entries->tcm_nvindex_entry[i],&temp_nv_entries[i],vtcm_template);
		}
		Free(nv_entries->tcm_nvindex_entry);
		nv_entries->tcm_nvindex_entry=NULL;
	}	 
        
	nv_entries->tcm_nvindex_entry=temp_nv_entries;	
    }
    /* initialize the new entry in the array */
	printf("  TCM_NVIndexEntries_GetFreeEntry: Created new slot at index %lu\n",
	       (unsigned long)i);
	*nv_sens = &(nv_entries->tcm_nvindex_entry[i]);
	TCM_NVDataSensitive_Init(*nv_sens);
	nv_entries->nvIndexCount++;
    return rc;
}

TCM_RESULT TCM_NVDataSensitive_IsGPIO(TCM_BOOL *isGPIO, TCM_NV_INDEX nvIndex)
{
    TCM_RESULT		rc = 0;

    printf("  TCM_NVDataSensitive_IsGPIO: nvIndex %08x\n", nvIndex);
    *isGPIO = FALSE;
#if defined TCM_PCCLIENT
    if (rc == 0) {
	/* GPIO space allowed for PC Client */
	if ((nvIndex >= TCM_NV_INDEX_GPIO_START) &&
	    (nvIndex <= TCM_NV_INDEX_GPIO_END)) {
	    printf("   TCM_NVDataSensitive_IsGPIO: nvIndex is GPIO space\n");
	    *isGPIO = TRUE;
	}	
    }
    /* #elif */
#else
    if (rc == 0) {
	/* GPIO space cannot be defined in platforms with no GPIO */
	if ((nvIndex >= TCM_NV_INDEX_GPIO_START) &&
	    (nvIndex <= TCM_NV_INDEX_GPIO_END)) {
	    printf("TCM_NVDataSensitive_IsGPIO: Error, illegal index\n");
	    rc = TCM_BADINDEX;
	}	
    }
#endif
    return rc;
} 

TCM_RESULT TCM_NVDataSensitive_IsValidPlatformIndex(TCM_NV_INDEX nvIndex)
{
    TCM_RESULT		rc = 0;

    printf(" TCM_NVDataSensitive_IsValidPlatformIndex: nvIndex %08x\n", nvIndex);
#ifndef TCM_PCCLIENT
    if (rc == 0) {
	if (((nvIndex & TCM_NV_INDEX_PURVIEW_MASK) >> TCM_NV_INDEX_PURVIEW_BIT) == TCM_PC) {
	    printf("  TCM_NVDataSensitive_IsValidPlatformIndex: Error, PC Client index\n");
	    rc = TCM_BADINDEX;
	}
    }
#endif 
    return rc;
}

TCM_RESULT TCM_NVDataSensitive_IsValidIndex(TCM_NV_INDEX nvIndex)
{
    TCM_RESULT		rc = 0;
    TCM_BOOL		isGPIO;

    printf(" TCM_NVDataSensitive_IsValidIndex: nvIndex %08x\n", nvIndex);
    if (rc == 0) {
	if ((nvIndex == TCM_NV_INDEX_LOCK) ||
	    (nvIndex == TCM_NV_INDEX0) ||
	    (nvIndex == TCM_NV_INDEX_DIR)) {
	    printf("TCM_NVDataSensitive_IsValidIndex: Error, illegal special index\n");
	    rc = TCM_BADINDEX;
	}
    }
    if (rc == 0) {
	if ((nvIndex & TCM_NV_INDEX_RESVD) != 0) {
	    printf("TCM_NVDataSensitive_IsValidIndex: Error, illegal reserved index\n");
	    rc = TCM_BADINDEX;
	}
    }
    if (rc == 0) {
	rc = TCM_NVDataSensitive_IsValidPlatformIndex(nvIndex);
    }
    /* The GPIO range validity is platform dependent */
    if (rc == 0) {
	rc = TCM_NVDataSensitive_IsGPIO(&isGPIO, nvIndex);
    }
    return rc;
}

/* vtcm_Key_GetStoreAsymkey() gets the TCM_STORE_ASYMKEY from a TCM_KEY cache.
 *  */

int vtcm_Key_GetStoreAsymkey(TCM_STORE_ASYMKEY **tcm_store_asymkey,
                             TCM_KEY *tcm_key)
{
    int ret = TCM_SUCCESS;
    int offset=0;
    printf(" vtcm_Key_GetStoreAsymkey:\n");
    if (ret == 0) 
    {
        // Get the entire command template
        void* template_store_asymkey = memdb_get_template(DTYPE_VTCM_IN_KEY, SUBTYPE_TCM_BIN_STORE_ASYMKEY);
        if (template_store_asymkey == NULL) 
        {
            printf("can't solve this command!\n");
        }
        *tcm_store_asymkey = malloc(struct_size(template_store_asymkey));

        while(tcm_key->encData[offset]!=TCM_PT_ASYM)
        {
		offset++;
		if(offset>=tcm_key->encDataSize)
			return -EINVAL;
        }
        ret = blob_2_struct(tcm_key->encData+offset, *tcm_store_asymkey, template_store_asymkey);
        if (ret >= 0) 
        {
            ret = 0;
        }
        else
        {
            printf(" vtcm_Key_GetStoreAsymkey: Error (fatal), no cache\n");
            ret = TCM_FAIL;      /* indicate no cache */                                      
        }                  
    }
    return ret;
}

int vtcm_Key_GetStoreSymkey(TCM_STORE_SYMKEY **tcm_store_symkey,
                             TCM_KEY *tcm_key)
{
    int ret = 0;
    printf(" vtcm_Key_GetStoreSymkey:\n");
    if (ret == 0) 
    {
        // Get the entire command template
        void* template_store_symkey = memdb_get_template(DTYPE_VTCM_IN_KEY, SUBTYPE_TCM_BIN_STORE_SYMKEY);
        if (template_store_symkey == NULL) 
        {
            printf("can't solve this command!\n");
        }
        *tcm_store_symkey = Dalloc0(struct_size(template_store_symkey),tcm_store_symkey);
        ret = blob_2_struct(tcm_key->encData, *tcm_store_symkey, template_store_symkey);
        if (ret >= 0) 
        {
            ret = 0;
        }
        else
        {
            printf(" vtcm_Key_GetStoreSymkey: Error (fatal), no cache\n");
            ret = TCM_FAIL;      /* indicate no cache */                                      
        }                  
    }
    return ret;
}


/* vtcm_Key_GetMigrateAsymkey() gets the TCM_MIGRATE_ASYMKEY from a TCM_KEY cache.
 *  */

int vtcm_Key_GetMigrateAsymkey(TCM_MIGRATE_ASYMKEY **tcm_migrate_asymkey,
                               TCM_KEY *tcm_key)
{
    int ret = 0;
    printf(" vtcm_Key_GetMigrateAsymkey:\n");
    if (ret == 0) 
    {
        // Get the entire command template
        void* template_migrate_asymkey = memdb_get_template(DTYPE_VTCM_IN_KEY, SUBTYPE_TCM_BIN_STORE_ASYMKEY);
        if (template_migrate_asymkey == NULL) 
        {
            printf("can't solve this command!\n");
        }
        *tcm_migrate_asymkey = malloc(struct_size(template_migrate_asymkey));
        ret = blob_2_struct(tcm_key->encData, *tcm_migrate_asymkey, template_migrate_asymkey);
        if (ret >= 0) 
        {
            ret = 0;
        }
        else
        {
            printf(" vtcm_Key_GetMigrateAsymkey: Error (fatal), no cache\n");
            ret = TCM_FAIL;      /* indicate no cache */                                      
        }                  
    }
    return ret;
}


/* vtcm_Key_GetUsageAuth() 
 * gets the usageAuth from the TCM_STORE_ASYMKEY or TCM_MIGRATE_ASYMKEY
 * contained in a TCM_KEY
 */

int vtcm_Key_GetUsageAuth(BYTE **usageAuth, TCM_KEY *tcm_key)
{
    int ret = 0; 
    TCM_STORE_ASYMKEY *tcm_store_asymkey = NULL;
    TCM_STORE_SYMKEY *tcm_store_symkey = NULL;
     
    printf(" vtcm_Key_GetUsageAuth:\n");
    /* check that the TCM_KEY_USAGE indicates a valid key */ 
    if (ret == 0) 
    { 
        if ((tcm_key == NULL) || (tcm_key->keyUsage == TCM_KEY_UNINITIALIZED)) 
        {
            printf("vtcm_Key_GetUsageAuth: Error, key not initialized\n");
            ret = TCM_INVALID_KEYUSAGE;
        }    
    } 
    /* get the TCM_STORE_ASYMKEY object */
    if (ret == TCM_SUCCESS) 
    {
        if(tcm_key->algorithmParms.algorithmID == TCM_ALG_SM2)
        {
            printf("TCM_KEY   TCM_ALG_SM2\n");
            ret = vtcm_Key_GetStoreAsymkey(&tcm_store_asymkey, tcm_key);
            /* found a TCM_STORE_ASYMKEY */
            if (ret == TCM_SUCCESS) 
            { 
                *usageAuth = &(tcm_store_asymkey->usageAuth);
            }    
        }
        /* get the TCM_STORE_SYMKEY object */
        else if(tcm_key->algorithmParms.algorithmID == TCM_ALG_SM4)
        {
            printf("TCM_KEY   TCM_ALG_SM4\n");
            ret = vtcm_Key_GetStoreSymkey(&tcm_store_symkey, tcm_key);
            /* found a TCM_MIGRATE_ASYMKEY */
            if (ret == TCM_SUCCESS) 
            { 
                *usageAuth = &(tcm_store_symkey->usageAuth);
            }                                            
        }
        else 
        {
            printf("TCM_KEY is not TCM_ALG_SM2 or TCM_ALG_SM4\n");
            ret = -1;
        }
    }   
    if (ret != TCM_SUCCESS) 
    { 
        printf(" vtcm_Key_GetUsageAuth: Error (fatal), "
               "could not get TCM_STORE_ASYMKEY or TCM_STORE_SYMKEY\n");
        ret = TCM_FAIL;  /* should never occur */
    }    
    /* get the usageAuth element */
    if (ret == TCM_SUCCESS) 
    {
        printf("Key_GetUsageAuth Success!\n");
        //TCM_PrintFour("  TCM_Key_GetUsageAuth: Auth", **usageAuth);
    }    
    return ret;      
}



/* vtcm_Counters_IsValidId() verifies that countID is in range and a created counter
 *  */

int vtcm_Counters_IsValidId(TCM_COUNTER_VALUE *monotonicCounters,
                            TCM_COUNT_ID countID)
{
    int ret = 0;
    printf(" vtcm_Counters_IsValidId: countID %u\n", countID);
    /* range check */
    if (ret == 0) 
    {
        if (countID >= TCM_MIN_COUNTERS) 
        {
            printf(" vtcm_Counters_IsValidId: Error countID %u out of range\n", countID);
            ret = TCM_BAD_COUNTER ;                                        
        }
    }
    /* validity (creation) check */
    if (ret == 0) 
    {
        if (!(monotonicCounters[countID].valid)) 
        {
            printf(" vtcm_Counters_IsValidId: Error countID %u invalid\n", countID);
            ret = TCM_BAD_COUNTER;                                        
        }           
    }
    return ret;
}




/* vtcm_Counters_GetCounterValue() gets the TCM_COUNTER_VALUE associated with the countID.
 *
 */

int vtcm_Counters_GetCounterValue(TCM_COUNTER_VALUE **tcm_counter_value,
                                  TCM_COUNTER_VALUE *monotonicCounters,
                                  TCM_COUNT_ID countID)
{
    int ret = 0;    
    printf(" vtcm_Counters_GetCounterValue: countID %u\n", countID);
    /* valid counter check */
    if (ret == 0) 
    { 
        ret = vtcm_Counters_IsValidId(monotonicCounters, countID);
    }    
    if (ret == 0) 
    { 
        *tcm_counter_value = &(monotonicCounters[countID]);
    }    
    return ret;
}


/* vtcm_AuthSessionData_CheckEncScheme() checks that the encryption scheme specified by
 * TCM_ENTITY_TYPE is supported by the TCM (by TCM_AuthSessionData_Decrypt)
 */

int vtcm_AuthSessionData_CheckEncScheme(TCM_ADIP_ENC_SCHEME adipEncScheme,
                                        TCM_BOOL FIPS)
{
    int ret = 0;
    printf(" vtcm_AuthSessionData_CheckEncScheme: adipEncScheme %02x\n", adipEncScheme);
    switch (adipEncScheme) 
    {
        case TCM_ET_XOR:
            /* i.If TCM_PERMANENT_FLAGS -> FIPS is TRUE */
            /* (1) All encrypted authorizations MUST use a symmetric key encryption scheme. */
            if (FIPS) 
            {
                ret = TCM_INAPPROPRIATE_ENC;       
            }
            break;
        case TCM_ET_AES128_CTR:
            break;
        default:
            printf("vtcm_AuthSessionData_CheckEncScheme: Error, unsupported adipEncScheme\n");
            ret = TCM_INAPPROPRIATE_ENC;
            break;                                                          
    }
    return ret;
}


int vtcm_Key_GetpubDigest(TCM_DIGEST **entityDigest, TCM_KEY *tcm_key)
{
    printf("  vtcm_Key_GetpubDigest : Start\n");

    int ret = 0;
    TCM_STORE_ASYMKEY *tcm_store_asymkey;
    /* check that the TCM_KEY_USAGE indicates a valid key */ 
    if (ret == 0) 
    { 
        if (tcm_key == NULL)  
        {
            printf("vtcm_Key_GetpubDigest: Error\n");
            ret = TCM_INVALID_KEYUSAGE;                                         
        }    
    } 
    /* get the TCM_STORE_ASYMKEY object */
    if (ret == 0) 
    { 
        ret = vtcm_Key_GetStoreAsymkey(&tcm_store_asymkey, tcm_key);
        /* found a TCM_STORE_ASYMKEY */
        if (ret == 0) 
        { 
            *entityDigest = &(tcm_store_asymkey->pubDataDigest);
        }   
    }
    return ret;
}


/* vtcm_KeyHandleEntries_GetEntry() searches all entries for the entry matching the handle, and
 *    returns that entry */

int vtcm_KeyHandleEntries_GetEntry(TCM_KEY_HANDLE_ENTRY **tcm_key_handle_entry,
                                   TCM_KEY_HANDLE_ENTRY *tcm_key_handle_entries,
                                   TCM_KEY_HANDLE tcm_key_handle)
{
    int ret = 0; 
    size_t i;   
    TCM_BOOL found;
    printf(" TCM_KeyHandleEntries_GetEntry: Get entry for handle %08x\n", tcm_key_handle);
    for (i = 0, found = FALSE ; (i < TCM_KEY_HANDLES) && !found ; i++) 
    {
        /* first test for matching handle.  Then check for non-NULL to insure that entry is valid */
        if ((tcm_key_handle_entries[i].handle == tcm_key_handle) &&
             tcm_key_handle_entries[i].key != NULL) 
        {    /* found */
            found = TRUE;
            *tcm_key_handle_entry = &(tcm_key_handle_entries[i]);
        }                 
     }    
    if (!found) 
    {
        printf("  vtcm_KeyHandleEntries_GetEntry: key handle %08x not found\n", tcm_key_handle);
        ret = TCM_INVALID_KEYHANDLE;                    
    }    
    else 
    {
        printf("  vtcm_KeyHandleEntries_GetEntry: key handle %08x found\n", tcm_key_handle);             
    }    
    return ret;
}
/* vtcm_KeyHandleEntries_GetKey() gets the TCM_KEY associated with the handle.
 *
 * If the key has PCR usage (size is non-zero and one or more mask bits are set), PCR's have been
 * specified.  It computes a PCR digest based on the TCM PCR's and verifies it against the key
 * digestAtRelease.
 *             
 * Exceptions: readOnly is TRUE when the caller is indicating that only the public key is being read
 * (e.g. TCM_GetPubKey).  In this case, if keyFlags TCM_PCRIGNOREDONREAD is also TRUE, the PCR
 * digest and locality must not be checked.
 *
 * If ignorePCRs is TRUE, the PCR digest is also ignored.  A typical case is during OSAP and DSAP
 * session setup.
 */

int vtcm_KeyHandleEntries_GetKey(TCM_KEY **tcm_key,
                                 TCM_BOOL *parentPCRStatus,
                                 tcm_state_t *tcm_state,
                                 TCM_KEY_HANDLE tcm_key_handle,
                                 TCM_BOOL readOnly,
                                 TCM_BOOL ignorePCRs,
                                 TCM_BOOL allowEK)
{
    int ret = 0;
    TCM_BOOL found = FALSE;  /* found a special handle key */
    TCM_BOOL validatePcrs = TRUE;
    TCM_KEY_HANDLE_ENTRY *tcm_key_handle_entry;
    printf(" vtcm_KeyHandleEntries_GetKey: For handle %08x\n", tcm_key_handle);
    /* If it's one of the special handles, return the TCM_KEY */
    if (ret == 0) 
    {
        switch (tcm_key_handle) 
        {
            case TCM_KH_SRK:      /* The handle points to the SRK */
                //if (tcm_state->tcm_permanent_data.ownerInstalled) 
               // {
               //     *tcm_key = &(tcm_state->tcm_permanent_data.srk);
               //     *parentPCRStatus = FALSE;       /* storage root key (SRK) has no parent */
               //     found = TRUE;
               // }
               // else 
               // {
               //     printf(" vtcm_KeyHandleEntries_GetKey: Error, SRK handle with no owner\n");
               //     ret = TCM_KEYNOTFOUND;                                
               // }
                break;
            case TCM_KH_EK:       /* The handle points to the PUBEK, only usable with
                                     TCM_OwnerReadInternalPub */
                if (ret == 0) 
                {
                    if (!allowEK) 
                    {
                        printf(" vtcm_KeyHandleEntries_GetKey: Error, EK handle not allowed\n");
                        ret = TCM_KEYNOTFOUND;                                                        
                    }
                }
                if (ret == 0) 
                {
                    if (tcm_state->tcm_permanent_data.endorsementKey.keyUsage == TCM_KEY_UNINITIALIZED) 
                    {
                        printf(" vtcm_KeyHandleEntries_GetKey: Error, EK handle but no EK\n");
                        ret = TCM_KEYNOTFOUND;                                                               
                    }                            
                }
                if (ret == 0) 
                {
                    *tcm_key = &(tcm_state->tcm_permanent_data.endorsementKey);
                    *parentPCRStatus = FALSE;       /* endorsement key (EK) has no parent */
                    found = TRUE;                                                            
                }
                break;
             case TCM_KH_OWNER:    /* handle points to the TCM Owner */
             case TCM_KH_REVOKE:   /* handle points to the RevokeTrust value */
             case TCM_KH_TRANSPORT: /* handle points to the EstablishTransport static authorization */
             case TCM_KH_OPERATOR: /* handle points to the Operator auth */
             case TCM_KH_ADMIN:    /* handle points to the delegation administration auth */
                printf("vtcm_KeyHandleEntries_GetKey: Error, Unsupported key handle %08x\n",
                                       tcm_key_handle);
                ret = TCM_INVALID_RESOURCE;
                break;
             default:
                /* continue searching */
                break;
        }
    }
    /* If not one of the special key handles, search for the handle in the list */
    if ((ret == 0) && !found) 
    {
        ret = vtcm_KeyHandleEntries_GetEntry(&tcm_key_handle_entry,
                                             tcm_state->tcm_key_handle_entries,
                                             tcm_key_handle);
        if (ret != 0) 
        {
            printf("TCM_KeyHandleEntries_GetKey: Error, key handle %08x not found\n", tcm_key_handle);
        }           
        if(ret == TCM_SUCCESS)
        {
            *tcm_key = tcm_key_handle_entry->key; 
        }
    }

    return ret;

}

void vtcm_KeyHandleEntries_IsSpace(TCM_BOOL *isSpace,
                                   int * index,
                                   const TCM_KEY_HANDLE_ENTRY *tcm_key_handle_entries)
{
    printf("vtcm_KeyHandleEntries_IsSpace:\n");
    for(*index = 0, *isSpace = FALSE; *index < TCM_KEY_HANDLES; (*index)++) {
        if(tcm_key_handle_entries[*index].key == NULL) {
            printf("vtcm_KeyHandleEntries_IsSpace: Found space at %u\n", *index);
            *isSpace = TRUE;
            break;
        }
    }
    return;
}

int vtcm_Handle_GenerateHandle2(TCM_HANDLE* tcm_handle,
                                TCM_KEY_HANDLE_ENTRY *tcm_key_handle_entries,
    TCM_BOOL keepHandle, TCM_BOOL isKeyHandle)
{
    int ret = 0;
    int getRc = 0;
    unsigned int timeout; /* collision timeout */
    TCM_KEY_HANDLE_ENTRY *used_handle_entry; /* place holder for discarded entry */
    TCM_BOOL done;

    printf(" vtcm_Handle_GenerateHandle2 : handle %08x, keepHandle %u\n",
        *tcm_handle, keepHandle);

    /* if the input value must be used */
    if (keepHandle) {
        /* 0 is illegal and cannot be kept */
        if (ret == 0) {
            if (*tcm_handle == 0) {
                printf("TCM_Handle_GenerateHandle: Error, cannot keep handle 0\n");
                ret = TCM_BAD_HANDLE;
            }
        }
        /* key handles beginning with 0x40 are reserved special values */
        if (ret == 0) {
            if (isKeyHandle) {
                if ((*tcm_handle & 0xff000000) == 0x40000000) {
                    printf("TCM_Handle_GenerateHandle: Error, cannot keep reserved key "
                           "handle\n");
                    ret = TCM_BAD_HANDLE;
                }
            }
        }
        /* check if the handle is already used */
        if (ret == 0) {
            getRc = vtcm_KeyHandleEntries_GetEntry(&used_handle_entry, /* discarded entry */
                tcm_key_handle_entries, /* handle array */
                *tcm_handle); /* search for handle */
            /* success mean the handle has already been assigned */
            if (getRc == 0) {
                printf("TCM_Handle_GenerateHandle: Error handle already in use\n");
                ret = TCM_BAD_HANDLE;
            }
        }
    }
    /* input value is recommended but not required */
    else {
        /* implement a crude timeout in case the random number generator fails and
       there are too
       many collisions */
        done = FALSE;
        for (timeout = 0; (ret == 0) && !done && (timeout < 1000);
             timeout++) {
            /* If no handle has been assigned, try a random value.  If a handle has
         been assigned,
         try it first */
            if (ret == 0) {
                if (*tcm_handle == 0) {
                    RAND_bytes((unsigned char*)tcm_handle, sizeof(uint32_t));
                }
            }
            /* if the random value is 0, reject it immediately */
            if (ret == 0) {
                if (*tcm_handle == 0) {
                    printf("  vtcm_Handle_GenerateHandle2: Random value 0 rejected\n");
                    continue;
                }
            }
            /* if the value is a reserved key handle, reject it immediately */
            if (ret == 0) {
                if (isKeyHandle) {
                    if ((*tcm_handle & 0xff000000) == 0x40000000) {
                        printf("  TCM_Handle_GenerateHandle: Random value %08x rejected\n",
                            *tcm_handle);
                        *tcm_handle = 0; /* ignore the assigned value */
                        continue;
                    }
                }
            }
            /* test if the handle has already been used */
            if (ret == 0) {
                getRc = vtcm_KeyHandleEntries_GetEntry(&used_handle_entry, /* discarded entry */
                    tcm_key_handle_entries, /* handle array */
                    *tcm_handle); /* search for handle */
                if (getRc != 0) { /* not found, done */
                    printf("  vtcm_Handle_GenerateHandle2: Assigned Handle %08x\n",
                        *tcm_handle);
                    done = TRUE;
                }
                else { /* found, try again */
                    *tcm_handle = 0; /* ignore the assigned value */
                    printf("  vtcm_Handle_GenerateHandle2: Handle %08x already used\n",
                        *tcm_handle);
                }
            }
        }
        if (!done) {
            printf("vtcm_Handle_GenerateHandle2: Error (fatal), random number "
                   "generator failed\n");
            ret = TCM_FAIL;
        }
    }
    return ret;
}

int vtcm_KeyHandleEntries_AddEntry(TCM_KEY_HANDLE *tcm_key_handle,
                                   TCM_BOOL keepHandle,
                                   TCM_KEY_HANDLE_ENTRY *tcm_key_handle_entries,
                                   TCM_KEY_HANDLE_ENTRY *tcm_key_handle_entry)
{
    int ret = 0;
    int index;
    TCM_BOOL isSpace;

    printf("vtcm_KeyHandleEntries_AddEntry: handle %08x, keepHandle %u\n",
           *tcm_key_handle, keepHandle);
    if(ret == 0) {
        if(tcm_key_handle_entry->key == NULL) {
            printf("vtcm_KeyHandleEntries_AddEntry: Error(fatal), NULL TCM_KEY\n");
            ret = TCM_FAIL;
        }
    }
    if(ret == 0) {
        vtcm_KeyHandleEntries_IsSpace(&isSpace, &index, tcm_key_handle_entries);
        if(!isSpace) {
            printf("vtcm_KeyHandleEntries_AddEntry: Error, key handle entries full\n");
            ret = TCM_NOSPACE;
        }
    }
    if(ret == 0) {
        ret = vtcm_Handle_GenerateHandle2(tcm_key_handle,
                                         tcm_key_handle_entries,
                                         keepHandle,
                                         TRUE);
    }
    if(ret == 0) {
        tcm_key_handle_entries[index].handle = *tcm_key_handle;
        tcm_key_handle_entries[index].key = tcm_key_handle_entry->key;
        printf("vtcm_KeyHandleEntries_AddEntry: Index %u key handle %08x key pointer %p\n",
               index, tcm_key_handle_entries[index].handle, tcm_key_handle_entries[index].key);
    }
    return ret;

}

int vtcm_KeyHandleEntries_AddKeyEntry(TCM_KEY_HANDLE *tcm_key_handle,
                                      TCM_KEY_HANDLE_ENTRY *tcm_key_handle_entries,
                                      TCM_KEY *tcm_key)
{
    int ret = 0;
    TCM_KEY_HANDLE_ENTRY tcm_key_handle_entry;
    printf("vtcm_KeyHandleEntries_AddKeyEntry:\n");
    tcm_key_handle_entry.key = tcm_key;
    ret = vtcm_KeyHandleEntries_AddEntry(tcm_key_handle,
                                         FALSE,
                                         tcm_key_handle_entries,
                                         &tcm_key_handle_entry);
    return ret;
}

//All those Pcr Functions

// Init a pcr selection struct
int vtcm_Init_PcrSelection(TCM_PCR_SELECTION * pcr_select)
{
	Memset(pcr_select,0,sizeof(*pcr_select));
	pcr_select->sizeOfSelect=TCM_NUM_PCR/8;
	return 0;
}

// Init a pcr selection struct
int vtcm_Init_PcrComposite(TCM_PCR_COMPOSITE * pcr_comp)
{
	Memset(pcr_comp,0,sizeof(*pcr_comp));
	vtcm_Init_PcrSelection(&pcr_comp->select);
	return 0;
}
// Init a pcr info struct 
int vtcm_Init_PcrInfo(TCM_PCR_INFO_LONG * pcr_info)
{
	Memset(pcr_info,0,sizeof(*pcr_info));
	pcr_info->tag=htons(TCM_TAG_PCR_INFO);
	vtcm_Init_PcrSelection(&pcr_info->creationPCRSelection);
	vtcm_Init_PcrSelection(&pcr_info->releasePCRSelection);
	return 0;
}

int vtcm_Set_PcrInfo(TCM_PCR_INFO_LONG * pcr_info, TCM_PCR_COMPOSITE * pcr_comp)
{
	Memcpy(&pcr_info->creationPCRSelection,&pcr_comp->select,sizeof(TCM_PCR_SELECTION));
	return vtcm_Comp_PcrsDigest(pcr_comp, pcr_info->digestAtCreation);
	
}

// Set an index in pcr selection
int vtcm_Set_PcrSelection(TCM_PCR_SELECTION * pcr_select,int index)
{
	int pcr_select_offset;
	BYTE select_value;
	if((index<0) || (index>=TCM_NUM_PCR))
		return -EINVAL;
	pcr_select_offset=index/8;
	select_value=1<<(index%8);
	pcr_select->pcrSelect[pcr_select_offset] |=select_value;
	return 0;
}

// clean an index in pcr selection
int vtcm_Clear_PcrSelection(TCM_PCR_SELECTION * pcr_select,int index)
{
	int pcr_select_offset;
	BYTE select_value;
	if((index<0) || (index>=TCM_NUM_PCR))
		return -EINVAL;
	pcr_select_offset=index/8;
	select_value=1<<(index%8);
	pcr_select->pcrSelect[pcr_select_offset] &=~select_value;
	return 0;
}

// in tcm emulator function: fill a pcr_composite struct with tcm instance's curr pcr valur
int vtcm_Fill_PCRComposite(TCM_PCR_COMPOSITE * pcr_comp,tcm_state_t * curr_tcm)
{
	TCM_PCR_SELECTION * pcr_select=&(pcr_comp->select);
	int pcr_select_offset;
	int pcr_value_offset;
	int index;
	BYTE select_value;
	BYTE * pcrs =curr_tcm->tcm_stclear_data.PCRS;
        pcr_comp->valueSize=0;
	if(pcr_comp->pcrValue!=NULL)
        {
		Free(pcr_comp->pcrValue);
        }

	for(index=0;index<pcr_select->sizeOfSelect *CHAR_BIT;index++)
	{
		pcr_select_offset=index/8;
		select_value=1<<(index%8);
	        if(select_value&pcr_select->pcrSelect[pcr_select_offset])
		{
			Memcpy(Buf+pcr_comp->valueSize,pcrs+index*DIGEST_SIZE,DIGEST_SIZE);
			pcr_comp->valueSize+=DIGEST_SIZE;
		}
	}
	pcr_comp->pcrValue=Talloc0(pcr_comp->valueSize);
	if(pcr_comp->pcrValue==NULL)
		return -ENOMEM;
	Memcpy(pcr_comp->pcrValue,Buf,pcr_comp->valueSize);
	return pcr_comp->valueSize;	
}

// out tcm emulator function: add value to pcr_composite

int vtcm_Add_PCRComposite(TCM_PCR_COMPOSITE * pcr_comp,int index,BYTE * value)
{
	TCM_PCR_COMPOSITE * pcr_set=(TCM_PCR_COMPOSITE *)pcr_comp;
	TCM_PCR_SELECTION * pcr_select;
	int pcr_select_offset;
	BYTE select_value;
	BYTE digest[DIGEST_SIZE];
	int i;
	int pcr_value_offset;
	if((index<0) || (index>=TCM_NUM_PCR))
		return -EINVAL;
		
	pcr_select=&(pcr_set->select);
	pcr_select_offset=index/8;
	select_value=1<<(index%8);
	if(select_value&pcr_select->pcrSelect[pcr_select_offset])
		// this pcr index is already be selected by this pcr set
	{
		pcr_value_offset=0;
		for(i=0;i<index;i++)
		{
			pcr_select_offset=i/8;
			select_value=1<<(i%8);
			if(select_value&pcr_select->pcrSelect[pcr_select_offset])
				pcr_value_offset+=DIGEST_SIZE;
		}		
		// do the pcr extend
		Memcpy(Buf,pcr_set->pcrValue+pcr_value_offset,DIGEST_SIZE);
		Memcpy(Buf+DIGEST_SIZE,value,DIGEST_SIZE);
		sm3(Buf,DIGEST_SIZE*2,pcr_set->pcrValue+pcr_value_offset);
	}
	else
	{
		pcr_set->valueSize+=DIGEST_SIZE;
		char * buffer=Talloc0(pcr_set->valueSize);
		Memset(buffer,0,pcr_set->valueSize);
		pcr_value_offset=0;
		for(i=0;i<TCM_NUM_PCR;i++)
		{
			if(i<index)
			{
				pcr_select_offset=i/8;
				select_value=1<<(i%8);
				if(select_value&pcr_select->pcrSelect[pcr_select_offset])
				{
					Memcpy(buffer+pcr_value_offset,pcr_set->pcrValue+pcr_value_offset,DIGEST_SIZE);
					pcr_value_offset+=DIGEST_SIZE;
				}
			}
			else if(i==index)
			{
				pcr_select_offset=i/8;
				select_value=1<<(i%8);
				if(select_value&pcr_select->pcrSelect[pcr_select_offset])
				{
					Memcpy(Buf,buffer+pcr_value_offset,DIGEST_SIZE);
					Memcpy(Buf+DIGEST_SIZE,value,DIGEST_SIZE);
					sm3(Buf,DIGEST_SIZE*2,buffer+pcr_value_offset);
				}
				else
				{
					Memset(Buf,0,DIGEST_SIZE);
					Memcpy(Buf+DIGEST_SIZE,value,DIGEST_SIZE);
					sm3(Buf,DIGEST_SIZE*2,buffer+pcr_value_offset);
					pcr_select->pcrSelect[pcr_select_offset]|=select_value;
				}
	
				// do the pcr extend
				pcr_value_offset+=DIGEST_SIZE;
			}
			else 
			{
				pcr_select_offset=i/8;
				select_value=1<<(i%8);
				if(select_value&pcr_select->pcrSelect[pcr_select_offset])
				{
					Memcpy(buffer+pcr_value_offset,pcr_set->pcrValue+pcr_value_offset-DIGEST_SIZE,DIGEST_SIZE);
					pcr_value_offset+=DIGEST_SIZE;
				}
			}
		}
		if(pcr_set->pcrValue!=NULL)
			Free(pcr_set->pcrValue);
		pcr_set->pcrValue=buffer;
	}
	return 0;
}

// out tcm emulator function: duplicate  value to pcr_composite

int vtcm_Dup_PCRComposite(TCM_PCR_COMPOSITE * pcr_comp,int index,BYTE * value)
{
	TCM_PCR_COMPOSITE * pcr_set=(TCM_PCR_COMPOSITE *)pcr_comp;
	TCM_PCR_SELECTION * pcr_select;
	int pcr_select_offset;
	BYTE select_value;
	BYTE digest[DIGEST_SIZE];
	int i;
	int pcr_value_offset;
	if((index<0) || (index>=TCM_NUM_PCR))
		return -EINVAL;
		
	pcr_select=&(pcr_set->select);
	pcr_select_offset=index/8;
	select_value=1<<(index%8);
	if(select_value&pcr_select->pcrSelect[pcr_select_offset])
		// this pcr index is already be selected by this pcr set
	{
		pcr_value_offset=0;
		for(i=0;i<index;i++)
		{
			pcr_select_offset=i/8;
			select_value=1<<(i%8);
			if(select_value&pcr_select->pcrSelect[pcr_select_offset])
				pcr_value_offset+=DIGEST_SIZE;
		}		
		// do the pcr duplicate
		Memcpy(pcr_set->pcrValue+pcr_value_offset,value,DIGEST_SIZE);
	}
	else
	{
		pcr_set->valueSize+=DIGEST_SIZE;
		char * buffer=Talloc0(pcr_set->valueSize);
		Memset(buffer,0,pcr_set->valueSize);
		pcr_value_offset=0;
		for(i=0;i<TCM_NUM_PCR;i++)
		{
			if(i<index)
			{
				pcr_select_offset=i/8;
				select_value=1<<(i%8);
				if(select_value&pcr_select->pcrSelect[pcr_select_offset])
				{
					Memcpy(buffer+pcr_value_offset,pcr_set->pcrValue+pcr_value_offset,DIGEST_SIZE);
					pcr_value_offset+=DIGEST_SIZE;
				}
			}
			else if(i==index)
			{
				pcr_select_offset=i/8;
				select_value=1<<(i%8);
				pcr_select->pcrSelect[pcr_select_offset]|=select_value;
	
				// do the pcr duplicate
				Memcpy(buffer+pcr_value_offset,value,DIGEST_SIZE);
				pcr_value_offset+=DIGEST_SIZE;
			}
			else 
			{
				pcr_select_offset=i/8;
				select_value=1<<(i%8);
				if(select_value&pcr_select->pcrSelect[pcr_select_offset])
				{
					Memcpy(buffer+pcr_value_offset,pcr_set->pcrValue+pcr_value_offset-DIGEST_SIZE,DIGEST_SIZE);
					pcr_value_offset+=DIGEST_SIZE;
				}
			}
		}
		if(pcr_set->pcrValue!=NULL)
			Free(pcr_set->pcrValue);
		pcr_set->pcrValue=buffer;
	}
	return 0;
}
/*
void * vtcm_Read_PcrComposite(TCM_PCR_COMPOSITE * pcrs,int index)
{
	TCM_PCR_COMPOSITE * pcr_set=(TCM_PCR_COMPOSITE *)pcrs;
	TCM_PCR_SELECTION * pcr_select;
	int pcr_select_offset;
	TCM_PCR_COMPOSITE * single_pcr;
	BYTE select_value;
	BYTE digest[DIGEST_SIZE];
	int i;
	int pcr_value_offset;
	char *buffer;
	if((index<0) || (index>=TCM_NUM_PCR))
		return NULL;
		
	pcr_select=&(pcr_set->select);
	pcr_select_offset=index/8;
	select_value=1<<(index%8);
	if(!(select_value&pcr_select->pcrSelect[pcr_select_offset]))
		// this pcr index is not selected by this pcr set
		return NULL;
	single_pcr=build_empty_pcr_set();
	pcr_value_offset=0;
	for(i=0;i<index;i++)
	{
		pcr_select_offset=i/8;
		select_value=1<<(i%8);
		if(select_value&pcr_select->pcrSelect[pcr_select_offset])
			pcr_value_offset+=DIGEST_SIZE;
	}	
	if(pcr_value_offset+DIGEST_SIZE>pcr_set->valueSize)
		return NULL;
	buffer=Talloc0(DIGEST_SIZE);
	if(buffer==NULL)
		return NULL;
	Memcpy(buffer,pcr_set->pcrValue+pcr_value_offset,DIGEST_SIZE);	
	single_pcr->valueSize=DIGEST_SIZE;
	single_pcr->pcrValue=buffer;
	pcr_select_offset=index/8;
	select_value=1<<(index%8);
	single_pcr->select.pcrSelect[pcr_select_offset]=select_value;
	return single_pcr;
}
*/
int vtcm_Comp_PcrsDigest(TCM_PCR_COMPOSITE * pcrs, BYTE * digest)
{
	BYTE * buffer;
	int blobsize;
	TCM_PCR_COMPOSITE * pcr_set=pcrs;
	void * template=memdb_get_template(DTYPE_VTCM_PCR,SUBTYPE_TCM_PCR_COMPOSITE);
	if((template==NULL) || IS_ERR(template))
		return -EINVAL;
	buffer=Talloc0(DIGEST_SIZE*25);
	if(buffer==NULL)
	{
		return -ENOMEM;
	}
	blobsize=struct_2_blob(pcr_set,buffer,template);
	if(blobsize<=0)
	{
		Free(buffer);
		return -EINVAL;
	}
	sm3(buffer,blobsize,digest);
	Free(buffer);
	return 0;
}

int vtcm_Compute_AuthCode(void * vtcm_data,
	                      int type,
                          int subtype,
	                      TCM_SESSION_DATA * authsession,
                          BYTE * AuthCode)
{
	int offset;
	void * vtcm_template;
	struct vtcm_external_input_command * cmd_head=vtcm_data;
	struct vtcm_external_output_command * return_head=vtcm_data;
	BYTE AuthBuf[DIGEST_SIZE*4];
	TCM_HANDLE * auth1handle;
	TCM_HANDLE * auth2handle;
    uint32_t sernum;
	int ret;

        // Compute command parameter's hash

	vtcm_template=memdb_get_template(type,subtype);	
	if(vtcm_template==NULL)
		return -EINVAL;

	if((type==DTYPE_VTCM_IN) ||(type==DTYPE_VTCM_IN_AUTH1))
	{
		// input command hash value compute	
    		offset = struct_2_part_blob(vtcm_data,Buf,vtcm_template,CUBE_ELEM_FLAG_KEY);
    		if(offset<0)
    			return offset;
	}
	else if(type==DTYPE_VTCM_OUT)
	{
    		offset = struct_2_part_blob(vtcm_data,Buf+8,vtcm_template,CUBE_ELEM_FLAG_KEY);
		*(int *)Buf=htonl(return_head->returnCode);
		Memcpy(Buf+sizeof(return_head->returnCode),&subtype,sizeof(subtype));
		offset+=8;
	}
	else
		return -EINVAL;

	sm3(Buf,offset,AuthBuf);
	offset=TCM_HASH_SIZE;

	if(cmd_head->tag== htons(TCM_TAG_RQU_AUTH1_COMMAND))
	{
		switch(subtype)
		{
			case SUBTYPE_APCREATE_IN:
    				ret = struct_2_part_blob(vtcm_data,AuthBuf+offset,vtcm_template,CUBE_ELEM_FLAG_INPUT);
    				if(ret<0)
    					return ret;
    				sm3_hmac(AuthCode,TCM_HASH_SIZE,
					AuthBuf,DIGEST_SIZE+ret,
					AuthCode);
				break;			
			case SUBTYPE_SM4ENCRYPT_IN:
			case SUBTYPE_SEAL_IN:
			case SUBTYPE_CREATEWRAPKEY_IN:
            case SUBTYPE_SM4DECRYPT_IN:
            case SUBTYPE_SIGN_IN:
            case SUBTYPE_OWNERCLEAR_IN:
            case SUBTYPE_DISABLEOWNERCLEAR_IN:
            case SUBTYPE_NV_DEFINESPACE_IN:
            case SUBTYPE_SM2DECRYPT_IN:
            case SUBTYPE_LOADKEY_IN:
            case SUBTYPE_QUOTE_IN:
                    sernum = htonl(authsession->SERIAL);
                    Memcpy(AuthBuf+offset, &sernum, sizeof(uint32_t));
    				sm3_hmac(authsession->sharedSecret,TCM_HASH_SIZE,
					         AuthBuf,DIGEST_SIZE+sizeof(uint32_t),
					         AuthCode);
				break;	
            case SUBTYPE_TAKEOWNERSHIP_IN:
    				sm3_hmac(AuthCode,TCM_HASH_SIZE,
					AuthBuf,DIGEST_SIZE,
					AuthCode);
                    break;
			default:
				return -EINVAL;
				
		}
	}
	else if(cmd_head->tag == htons(TCM_TAG_RSP_AUTH1_COMMAND))
	{
		switch(subtype)
		{
			case SUBTYPE_APCREATE_OUT:
    				ret = struct_2_part_blob(vtcm_data,AuthBuf+offset,vtcm_template,CUBE_ELEM_FLAG_INPUT);
    				if(ret<0)
    					return ret;
    				sm3_hmac(authsession->sharedSecret,TCM_HASH_SIZE,
					AuthBuf,DIGEST_SIZE+ret,AuthCode);
				break;			
			case SUBTYPE_SM4ENCRYPT_OUT:
			case SUBTYPE_SEAL_OUT:
			case SUBTYPE_CREATEWRAPKEY_OUT:
            case SUBTYPE_SM4DECRYPT_OUT:
            case SUBTYPE_SIGN_OUT:
            case SUBTYPE_OWNERCLEAR_OUT:
            case SUBTYPE_DISABLEOWNERCLEAR_OUT:
            case SUBTYPE_NV_DEFINESPACE_OUT:
            case SUBTYPE_SM2DECRYPT_OUT:
            case SUBTYPE_LOADKEY_OUT:
            case SUBTYPE_QUOTE_OUT:
            case SUBTYPE_UNSEAL_OUT:
                    sernum = htonl(authsession->SERIAL);
                    Memcpy(AuthBuf+offset, &sernum, sizeof(uint32_t));
    				sm3_hmac(authsession->sharedSecret,TCM_HASH_SIZE,
					         AuthBuf,DIGEST_SIZE+sizeof(uint32_t),
					         AuthCode);
				break;
            case SUBTYPE_TAKEOWNERSHIP_OUT:
                sm3_hmac(AuthCode, TCM_HASH_SIZE,
                         AuthBuf,DIGEST_SIZE,AuthCode);
                break;
			default:
				return -EINVAL;
				
		}

	}
	else if(cmd_head->tag == htons(TCM_TAG_RQU_AUTH2_COMMAND))
	{
      switch(subtype)
      {
      case SUBTYPE_UNSEAL_IN:
      case SUBTYPE_MAKEIDENTITY_IN:
      case SUBTYPE_ACTIVATEIDENTITY_IN:
                    sernum = htonl(authsession->SERIAL);
                    Memcpy(AuthBuf+offset, &sernum, sizeof(uint32_t));
    				sm3_hmac(authsession->sharedSecret,TCM_HASH_SIZE,
					         AuthBuf,DIGEST_SIZE+sizeof(uint32_t),
					         AuthCode);
        break;

      default:
        return -EINVAL;
      }
	}
	else if(cmd_head->tag == htons(TCM_TAG_RSP_AUTH2_COMMAND))
	{
      switch(subtype)
      {
      	case SUBTYPE_MAKEIDENTITY_OUT:
      	case SUBTYPE_ACTIVATEIDENTITY_OUT:
                    sernum = htonl(authsession->SERIAL);
                    Memcpy(AuthBuf+offset, &sernum, sizeof(uint32_t));
    				sm3_hmac(authsession->sharedSecret,TCM_HASH_SIZE,
					         AuthBuf,DIGEST_SIZE+sizeof(uint32_t),
					         AuthCode);
        break;
      default:
        return -EINVAL;
      }
	}
	else
	{
		return -EINVAL;
	}
	return 0;
}

int vtcm_Compute_AuthCode2(void * vtcm_data,
	                      int type,
                          int subtype,
	                      TCM_SESSION_DATA * authsession,
                          BYTE * AuthCode)
{
	int offset;
	void * vtcm_template;
	struct vtcm_external_input_command * cmd_head=vtcm_data;
	struct vtcm_external_output_command * return_head=vtcm_data;
	BYTE AuthBuf[DIGEST_SIZE*4];
	TCM_HANDLE * auth1handle;
	TCM_HANDLE * auth2handle;
    uint32_t sernum;
	int ret;

        // Compute command parameter's hash

	vtcm_template=memdb_get_template(type,subtype);	
	if(vtcm_template==NULL)
		return -EINVAL;

	if(type==DTYPE_VTCM_IN)
	{
		// input command hash value compute	
    		offset = struct_2_part_blob(vtcm_data,Buf,vtcm_template,CUBE_ELEM_FLAG_KEY);
    		if(offset<0)
    			return offset;
	}
	else if(type==DTYPE_VTCM_OUT)
	{
    		offset = struct_2_part_blob(vtcm_data,Buf+8,vtcm_template,CUBE_ELEM_FLAG_KEY);
		*(int *)Buf=htonl(return_head->returnCode);
		Memcpy(Buf+sizeof(return_head->returnCode),&subtype,sizeof(subtype));
		offset+=8;
	}
	else
		return -EINVAL;

	sm3(Buf,offset,AuthBuf);
	offset=TCM_HASH_SIZE;

	if(cmd_head->tag== htons(TCM_TAG_RQU_AUTH1_COMMAND))
        return -EINVAL;
	else if(cmd_head->tag == htons(TCM_TAG_RSP_AUTH1_COMMAND))
        return -EINVAL;
	else if(cmd_head->tag == htons(TCM_TAG_RQU_AUTH2_COMMAND))
	{
      switch(subtype)
      {
      	    case SUBTYPE_UNSEAL_IN:
            case SUBTYPE_MAKEIDENTITY_IN:
            case SUBTYPE_ACTIVATEIDENTITY_IN:
                    sernum = htonl(authsession->SERIAL);
                    Memcpy(AuthBuf+offset, &sernum, sizeof(uint32_t));
    		    sm3_hmac(authsession->sharedSecret,TCM_HASH_SIZE,
				AuthBuf,DIGEST_SIZE+sizeof(uint32_t),
				AuthCode);
        		break;


                  default:
           return -EINVAL;
      }
	}
	else if(cmd_head->tag == htons(TCM_TAG_RSP_AUTH2_COMMAND))
	{
      switch(subtype)
      {
          case SUBTYPE_MAKEIDENTITY_OUT:
      	  case SUBTYPE_ACTIVATEIDENTITY_OUT:
                  sernum = htonl(authsession->SERIAL);
                  Memcpy(AuthBuf+offset, &sernum, sizeof(uint32_t));
    				sm3_hmac(authsession->sharedSecret,TCM_HASH_SIZE,
					    AuthBuf,DIGEST_SIZE+sizeof(uint32_t),
					    AuthCode);
				break;			
          default:
              return -EINVAL;
      }
	}
	else
	{
		return -EINVAL;
	}
	return 0;
}
int vtcm_Build_CmdBlob(void * vtcm_data,
	int type,int subtype,
	BYTE * blob)
{
	int offset;
	void * vtcm_template;
	struct vtcm_external_input_command * cmd_head=vtcm_data;
	int ret;
	unsigned int tempint=0;

	vtcm_template=memdb_get_template(type,subtype);	
	if(vtcm_template==NULL)
		return -EINVAL;
			
    	offset = struct_2_blob(vtcm_data,blob,vtcm_template);
    	if(offset<0)
    		return offset;

	cmd_head->paramSize=offset;

	tempint=htonl(cmd_head->paramSize);

	Memcpy(blob+2,&tempint,sizeof(cmd_head->paramSize));

	return offset;
}

void sm4_cbc_data_prepare(int input_len,BYTE * input_data,int * output_len,BYTE * output_data)
{
	int pad_len;
	BYTE pad_value;
        int block_size=16;   

	pad_len=block_size-(input_len%block_size);
	pad_value=(BYTE)pad_len;

	*output_len=input_len+pad_len;
	Memcpy(output_data,input_data,input_len);
	Memset(output_data+input_len,pad_value,pad_len);
	return;
}

int sm4_cbc_data_recover(int input_len,BYTE * input_data,int * output_len,BYTE * output_data)
{
	int pad_len;
	BYTE pad_value;
        int block_size=16;  

	pad_value=input_data[input_len-1];
        if(pad_value>=block_size)
		return -EINVAL;
	pad_len=(int)pad_value; 
             

	*output_len=input_len-pad_len;
	
	Memcpy(output_data,input_data,*output_len);
	return *output_len;
}
