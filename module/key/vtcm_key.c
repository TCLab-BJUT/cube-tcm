#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdbool.h>

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
#include "vtcm_key.h"
#include "app_struct.h"
#include "tcm_global.h"
#include "tcm_constants.h"
#include "tcm_error.h"
#include "sm2.h"
#include "sm4.h"
#include "tcm_authlib.h"

static BYTE Buf[DIGEST_SIZE*64];

static int process_Vtcm_CreateEndorsementKeyPair(void* sub_proc, void* recv_msg);
static int proc_vtcm_ReadPubek(void* sub_proc, void* recv_msg);
static int proc_vtcm_APCreate(void* sub_proc, void* recv_msg);
static int proc_vtcm_APTerminate(void *sub_proc, void* recv_msg);
static int proc_vtcm_CreateWrapKey(void *sub_proc, void* recv_msg);
static int proc_vtcm_SM2Decrypt(void *sub_proc, void* recv_msg);
static int proc_vtcm_WrapKey(void *sub_proc, void* recv_msg);
static int proc_vtcm_Sm4Decrypt(void *sub_proc, void *recv_msg);
static int proc_vtcm_Sm4Encrypt(void *sub_proc, void *recv_msg);
static int proc_vtcm_Seal(void *sub_proc, void *recv_msg);
static int proc_vtcm_UnSeal(void *sub_proc, void *recv_msg);
static int proc_vtcm_Sign(void *sub_proc, void *recv_msg);
int vtcm_key_init(void* sub_proc, void* para)
{
    printf("vtcm_key_init :\n");
    tcm_state_t* tcm_instances = proc_share_data_getpointer();

    ex_module_setpointer(sub_proc, &tcm_instances[0]);
    return 0;
}

int vtcm_key_start(void* sub_proc, void* para)
{
    int ret;
    void* recv_msg, *context, *sock;
    int type, subtype;
    BYTE uuid[DIGEST_SIZE];

    int vtcm_no; 
    printf("vtcm_key module start!\n");

    while(1){
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
 
        if ((type == DTYPE_VTCM_IN) && (subtype == SUBTYPE_CREATEEKPAIR_IN)) {
            process_Vtcm_CreateEndorsementKeyPair(sub_proc, recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN) && (subtype == SUBTYPE_READPUBEK_IN)) {
            proc_vtcm_ReadPubek(sub_proc, recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN_AUTH1) && (subtype == SUBTYPE_APCREATE_IN)) {
             proc_vtcm_APCreate(sub_proc,recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN_AUTH1) && (subtype == SUBTYPE_CREATEWRAPKEY_IN)) {
             proc_vtcm_CreateWrapKey(sub_proc,recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN_AUTH1) && (subtype == SUBTYPE_LOADKEY_IN)) {
             proc_vtcm_LoadKey(sub_proc,recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN) && (subtype == SUBTYPE_EVICTKEY_IN)) {
             proc_vtcm_EvictKey(sub_proc,recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN_AUTH1) && (subtype == SUBTYPE_APTERMINATE_IN)) {
             proc_vtcm_APTerminate(sub_proc,recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN) && (subtype == SUBTYPE_SM3START_IN)) {
            proc_vtcm_Sm3Start(sub_proc, recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN) && (subtype == SUBTYPE_SM3UPDATE_IN)) {
            proc_vtcm_Sm3Update(sub_proc, recv_msg);
        }
//        else if ((type == DTYPE_VTCM_IN) && (subtype == SUBTYPE_SM3COMPLETEEXTEND_IN)) {
//            proc_vtcm_Sm3CompleteExtend(sub_proc, recv_msg);
//        }
        else if ((type == DTYPE_VTCM_IN) && (subtype == SUBTYPE_SM3COMPLETE_IN)) {
            proc_vtcm_Sm3Complete(sub_proc, recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN_AUTH1) && (subtype == SUBTYPE_SM4ENCRYPT_IN)) {
            proc_vtcm_Sm4Encrypt(sub_proc, recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN_AUTH1) && (subtype == SUBTYPE_SM4DECRYPT_IN)) {
            proc_vtcm_Sm4Decrypt(sub_proc, recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN_AUTH1) && (subtype == SUBTYPE_SM2DECRYPT_IN)) {
            proc_vtcm_SM2Decrypt(sub_proc, recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN_AUTH1) && (subtype == SUBTYPE_SIGN_IN)) {
            proc_vtcm_Sign(sub_proc, recv_msg);
        }
        else if ((type == DTYPE_VTCM_IN_AUTH1) && (subtype == SUBTYPE_SEAL_IN)) {
             proc_vtcm_Seal(sub_proc, recv_msg);
         }
        else if ((type == DTYPE_VTCM_IN_AUTH2) && (subtype == SUBTYPE_UNSEAL_IN)) {
             proc_vtcm_UnSeal(sub_proc, recv_msg);
         }
        else if ((type == DTYPE_VTCM_IN) && (subtype == SUBTYPE_OWNERREADINTERNALPUB_IN)) {
            proc_vtcm_OwnerReadInternalPub(sub_proc, recv_msg);
        }
    }
    return 0;
};


int vtcm_Init_Buffer(TCM_SIZED_BUFFER* Buffer)
{
    printf("vtcm_Init_Buffer : Start\n");
    int ret = 0;
    Buffer->size = 0;
    Buffer->buffer = NULL;
    return ret;
}


int vtcm_SM3_2_Buffer(BYTE* checksum, unsigned char* buffer_1, int size_1, unsigned char *buffer_2, int size_2)
{
    printf("vtcm_SM3_2_Buffer: Start\n");
    int ret = 0;
    sm3_context ctx;
    SM3_init(&ctx);
    SM3_update(&ctx, buffer_1, size_1);
    SM3_update(&ctx, buffer_2, size_2);
    SM3_final(&ctx, checksum);
    return ret;
}



int vtcm_HMAC_SM3(BYTE *key, int keylen, BYTE *buffer, int size, BYTE *output)
{
    printf("vtcm_HMAC_SM3 : Start\n");
    int ret = 0;
    sm3_context ctx;
    SM3_hmac_init(&ctx, key, keylen);
    SM3_hmac_update(&ctx, buffer, size);
    SM3_hmac_finish(&ctx, output);
    return ret;
}

int vtcm_CreateEndorsementKeyPair_Common(TCM_KEY* endorsementKey,
    TCM_PUBKEY* pubEndorsementKey,
    BYTE* checksum,
    tcm_state_t* tcm_state,
    TCM_KEY_PARMS* keyInfo,
    BYTE* antiReplay)
{
    int ret = 0;
    TCM_SM2_ASYMKEY_PARAMETERS tcm_sm2_asymkey_parameters;

    /* 1. If an EK already exists, return TCM_DISABLED_CMD */
    if (ret == 0) {
        if (endorsementKey->keyUsage != TCM_KEY_UNINITIALIZED) {
            printf("vtcm_CreateEndorsementKeyPair: Error, key already initialized\n");
            ret = TCM_DISABLED_CMD;
        }
    }
    /* 2. Validate the keyInfo parameters for the key description */
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

/***
    vtcm_Process_CreateEndorsementKeyPair
***/

int process_Vtcm_CreateEndorsementKeyPair(void* sub_proc, void* recv_msg)
{
    printf(" proc_vtcm_CreateEndorsementKeyPair :\n");

    int ret = 0;

    /* input process */
   
    BYTE *antiReplay;         //new define
    TCM_KEY_PARMS* keyInfo = NULL;

    /* process parameters */
    TCM_KEY* endorsementKey = NULL; /* EK object from permanent store */

    /* output process */
    void* template_CreateEKPair_out = memdb_get_template(
        DTYPE_VTCM_OUT,
        SUBTYPE_CREATEEKPAIR_OUT); /* Get the entire command template */
    if (template_CreateEKPair_out == NULL) {
        printf("can't solve this command!\n");
    }
    struct tcm_out_CreateEKPair* vtcm_out = malloc(struct_size(template_CreateEKPair_out));

    // get parameters
    struct tcm_in_CreateEKPair* vtcm_in;
    ret = message_get_record(recv_msg, (void**)&vtcm_in, 0);
    if (ret < 0)
        return ret;
    if (vtcm_in == NULL)
        return -EINVAL;

    keyInfo = &(vtcm_in->keyInfo);
    antiReplay = vtcm_in->antiReplay;

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);
    endorsementKey = &(tcm_state->tcm_permanent_data.endorsementKey);
    TCM_SM2_ASYMKEY_PARAMETERS* tcm_sm2_asymkey_parameters;

    // processing
    if (ret == 0) {
        ret = vtcm_CreateEndorsementKeyPair_Common(endorsementKey,
            &(vtcm_out->pubEndorsementKey),
            vtcm_out->checksum.digest,
            tcm_state,
            keyInfo,
            antiReplay);
    }

    if (ret == 0) {
        tcm_state->tcm_permanent_flags.CEKPUsed = TRUE;
    }

    // processing response
    printf("proc_vtcm_CreateEndorsementKeyPair: resposne\n");
    int responseSize = 0;
    BYTE* response = (BYTE*)malloc(sizeof(BYTE) * 512);

    vtcm_out->tag = 0xC400;
    vtcm_out->returnCode = ret;
    responseSize = struct_2_blob(vtcm_out, response, template_CreateEKPair_out);
    printf("struct_2_blob size = %d\n", responseSize);
    for (int i = 0; i < responseSize; ++i) {
        printf("%02x ", response[i]);
    }
    printf("\n");
    vtcm_out->paramSize = responseSize;

    void* send_msg = message_create(DTYPE_VTCM_OUT, SUBTYPE_CREATEEKPAIR_OUT, recv_msg);
    if (send_msg == NULL) {
        printf("send_msg == NULL\n");
        return -EINVAL;
    }
    message_add_record(send_msg, vtcm_out);
 
      // add vtcm's expand info	
     ret=vtcm_addcmdexpand(send_msg,recv_msg);
     if(ret<0)
     {
 	  printf("fail to add vtcm copy info!\n");
     }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    printf("Create EKPair Final ret = %d\n", ret);
    return ret;
}

/***
    vtcm_Process_ReadPubek
***/

int proc_vtcm_ReadPubek(void* sub_proc, void* recv_msg)
{
    printf("proc_vtcm_ReadPubek : Start\n");

    int ret = 0;

    TCM_KEY* endorsementKey = NULL;
    TCM_PUBKEY pubEndorsementKey;
    BYTE checksum[32];

    struct tcm_in_ReadPubek* vtcm_in;

    ret = message_get_record(recv_msg, (void**)&vtcm_in, 0); // get structure
    if (ret < 0)
        return ret;
    if (vtcm_in == NULL)
        return -EINVAL;

    // output process
    void* template_ReadPubek_out = memdb_get_template(
        DTYPE_VTCM_OUT, SUBTYPE_READPUBEK_OUT); // Get the entire command template
    if (template_ReadPubek_out == NULL) {
        printf("can't solve this command!\n");
    }
    struct tcm_out_ReadPubek* vtcm_out = malloc(struct_size(template_ReadPubek_out));

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    endorsementKey = &(tcm_state->tcm_permanent_data.endorsementKey);

    /*
   Processing
  */

    /* 1. If TCM_PERMANENT_FLAGS -> readPubek is FALSE return TCM_DISABLED_CMD. */
    if (!tcm_state->tcm_permanent_flags.readPubek) {
        printf("TCM_Process_ReadPubek: Error, readPubek is FALSE\n");
        ret = TCM_DISABLED_CMD;
    }

    /* 2. If no EK is present the TCM MUST return TCM_NO_ENDORSEMENT */
    if (tcm_state->tcm_permanent_data.endorsementKey.keyUsage == TCM_KEY_UNINITIALIZED) {
        printf("TCM_Process_ReadPubek: Error, no EK is present\n");
        ret = TCM_NO_ENDORSEMENT;
    }

    /* 3. Create checksum by performing SHA-1 on the concatenation of
     (pubEndorsementKey ||
        antiReplay). */
    vtcm_Fill_PubKey(&(vtcm_out->pubEndorsementKey), &(endorsementKey->algorithmParms),
        &(endorsementKey->pubKey));
    /* 4. Export the PUBKE and checksum */
    vtcm_Create_Checksum(vtcm_out->checksum.digest, &(vtcm_out->pubEndorsementKey), vtcm_in->antiReplay);

    char * pwdo="ooo";
    BYTE ownerauth[TCM_HASH_SIZE];
    BYTE cipher[1024];
    BYTE output[1024];
    int plain_len=1000;
    int cipher_len=512;
    int output_len;
    calculate_context_sm3(pwdo,Strlen(pwdo),ownerauth);

    ret=GM_SM2Encrypt(cipher,&cipher_len,ownerauth,TCM_HASH_SIZE,endorsementKey->pubKey.key,endorsementKey->pubKey.keyLength);
    output_len=512;
    ret=GM_SM2Decrypt(output,&output_len,cipher,cipher_len,endorsementKey->encData,endorsementKey->encDataSize);
    // Response
    printf("proc_vtcm_CreateEndorsementKeyPair :\n");

    vtcm_out->tag = 0xC400;
    vtcm_out->returnCode = 0;

    vtcm_out->paramSize = 0;
    int responseSize = 0;
    BYTE* response = (BYTE*)malloc(sizeof(BYTE) * 700);
    responseSize = struct_2_blob(vtcm_out, response, template_ReadPubek_out);
    vtcm_out->paramSize = responseSize;
    
    void* send_msg = message_create(DTYPE_VTCM_OUT, SUBTYPE_READPUBEK_OUT, recv_msg);
    if (send_msg == NULL) {
        printf("send_msg == NULL\n");
        return -EINVAL;
    }
    message_add_record(send_msg, vtcm_out);

    message_add_record(send_msg, vtcm_out);
 
      // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
 	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    char* buf = send_msg;
    for (int i = 0; i < 29; ++i) {
        printf("%02x  ", buf[i]);
    }
    printf("Final ret = %d\n", ret);

    return ret;
}

/* TPM_DelegateTable_GetRow() maps 'rowIndex' to a TPM_DELEGATE_TABLE_ROW in the delegate table.
 *
 *    The row may not have valid data.
 *     */

int vtcm_DelegateTable_GetRow(TCM_DELEGATE_TABLE_ROW **delegateTableRow,
                              TCM_DELEGATE_TABLE *tcm_delegate_table,
                              uint32_t rowIndex)
{
    int ret = 0;
    printf(" vtcm_DelegateTable_GetRow: index %u\n", rowIndex);
    if (ret == 0) 
    {
        if (rowIndex >= TCM_NUM_DELEGATE_TABLE_ENTRY_MIN) 
        {
            printf("TCM_DelegateTable_GetRow: index %u out of range\n", rowIndex);
            ret = TCM_BADINDEX;                                        
        }          
    }
    if (ret == 0) 
    {
        *delegateTableRow = &(tcm_delegate_table->delRow[rowIndex]);  
    }
    return ret;
}





/* TPM_DelegateTable_GetValidRow() maps 'rowIndex' to a TPM_DELEGATE_TABLE_ROW in the delegate
 *    table.
 *
 *       The row must have valid data.
 *        */

int vtcm_DelegateTable_GetValidRow(TCM_DELEGATE_TABLE_ROW **delegateTableRow,
                                   TCM_DELEGATE_TABLE *tcm_delegate_table,
                                   uint32_t rowIndex)
{
    int ret = 0; 
    if (ret == 0) 
    { 
        ret = vtcm_DelegateTable_GetRow(delegateTableRow,
                                        tcm_delegate_table,
                                        rowIndex);
    }    
    if (ret == 0) 
    { 
        *delegateTableRow = &(tcm_delegate_table->delRow[rowIndex]);
        if (!(*delegateTableRow)->valid) 
        {
            printf(" vtcm_DelegateTable_GetValidRow: index %u invalid\n", rowIndex);
            ret = TCM_BADINDEX;                                        
        }    
    }    
    return ret;
}


/* vtcm_FamilyTable_GetEntry() searches all entries for the entry matching the familyID, and returns
 * the TPM_FAMILY_TABLE_ENTRY associated with the familyID.
 *
 * Returns 0 for success
 * TCM_BADINDEX if the familyID is not found
*/

int vtcm_FamilyTable_GetEntry(TCM_FAMILY_TABLE_ENTRY **tcm_family_table_entry, /* output */
                              TCM_FAMILY_TABLE *tcm_family_table,
                              TCM_FAMILY_ID familyID)
{
    int ret = 0;
    size_t i;
    TCM_BOOL found;
    printf(" vtcm_FamilyTable_GetEntry: familyID %08x\n", familyID);
    for (i = 0, found = FALSE ; (i < TCM_NUM_FAMILY_TABLE_ENTRY_MIN) && !found ; i++) 
    {
        if (tcm_family_table->famTableRow[i].valid && (tcm_family_table->famTableRow[i].familyID == familyID)) 
        {   /* found */
            found = TRUE;
            *tcm_family_table_entry = &(tcm_family_table->famTableRow[i]);
        }                            
    }
    if (!found) 
    {
        printf(" vtcm_FamilyTable_GetEntry: Error, familyID %08x not found\n", familyID);
        ret = TCM_BADINDEX;                            
    }
    return ret;
}





/* vtcm_FamilyTable_GetEnabledEntry() searches all entries for the entry matching the familyID, and
 * returns the TPM_FAMILY_TABLE_ENTRY associated with the familyID.
 *
 * Similar to TPM_FamilyTable_GetEntry() but returns an error if the entry is disabled.
 *         
 * Returns 0 for success
 * TCM_BADINDEX if the familyID is not found
 * TCM_DISABLED_CMD if the TCM_FAMILY_TABLE_ENTRY -> TPM_FAMFLAG_ENABLED is FALSE 
 */

int vtcm_FamilyTable_GetEnabledEntry(TCM_FAMILY_TABLE_ENTRY **tcm_family_table_entry,
                                     TCM_FAMILY_TABLE *tcm_family_table,
                                     TCM_FAMILY_ID familyID)
{
    int ret = 0; 
    printf(" vtcm_FamilyTable_GetEnabledEntry: familyID %08x\n", familyID);
    if (ret == 0) 
    { 
        ret = vtcm_FamilyTable_GetEntry(tcm_family_table_entry,
                                       tcm_family_table,
                                       familyID);
    }    
    if (ret == 0) 
    { 
        if (!((*tcm_family_table_entry)->flags & TCM_FAMFLAG_ENABLED)) 
        {
            printf(" vtcm_FamilyTable_GetEnabledEntry: Error, family %08x disabled\n", familyID);
            ret = TCM_DISABLED_CMD;                                       
        }    
    }    
    return ret;
}



/* vtcm_Delegations_Copy() copies the source to the destination
 *  */

void vtcm_Delegations_Copy(TCM_DELEGATIONS *dest,
                           TCM_DELEGATIONS *src)
{
    dest->delegateType = src->delegateType;
    dest->per1 = src->per1;
    dest->per2 = src->per2;
    return;
}



/* vtcm_PCRSelection_CheckRange() checks the sizeOfSelect index
*/

int vtcm_PCRSelection_CheckRange(const TCM_PCR_SELECTION *tcm_pcr_selection)
{
    int ret = 0;
    if (tcm_pcr_selection->sizeOfSelect > (TCM_NUM_PCR/CHAR_BIT)) 
    {
        printf("vtcm_PCRSelection_CheckRange: Error, sizeOfSelect %u must be 0 - %u\n",
                tcm_pcr_selection->sizeOfSelect, TCM_NUM_PCR/CHAR_BIT);
        ret = TCM_INVALID_PCR_INFO;                        
    }
    return ret;
}




/* vtcm_PCRSelection_Copy() copies the source to the destination
 *
 * It returns an error if the source -> sizeOfSelect is too large.  If the source is smaller than
 * the internally defined, fixed size of the destination, the remainder of the destination is filled
 *  with 0's.
 */

int vtcm_PCRSelection_Copy(TCM_PCR_SELECTION *destination, TCM_PCR_SELECTION *source)
{
    int ret = 0;
    size_t i;
    printf(" vtcm_PCRSelection_Copy:\n");
    if (ret == 0) 
    {
        ret = vtcm_PCRSelection_CheckRange(source);        
    }
    if (ret == 0) 
    {
        /* copy sizeOfSelect member */
        destination->sizeOfSelect = source->sizeOfSelect;
        /* copy pcrSelect map up to the size of the source */
        for (i = 0 ; i < source->sizeOfSelect ; i++) 
        {
            destination->pcrSelect[i] = source->pcrSelect[i];                             
        }
        /* if the input wasn't sufficient, zero the rest of the map */
        for ( ; i < (TCM_NUM_PCR/CHAR_BIT) ; i++ )
        {
             destination->pcrSelect[i] = 0;                                      
        }                       
    }
    return ret;
}


void vtcm_Digest_Copy(TCM_DIGEST destination, const TCM_DIGEST source)
{
    printf("  TCM_Digest_Copy:\n");
    memcpy(destination.digest, source.digest, TCM_DIGEST_SIZE);
    return;
}



/* vtcm_PCRInfoShort_Copy() copies the source pcrSelection, digestAtRelease, and digestAtCreation.
 *
 * */

int vtcm_PCRInfoShort_Copy(TCM_PCR_INFO_SHORT *dest_tcm_pcr_info_short,
                           TCM_PCR_INFO_SHORT *src_tcm_pcr_info_short)
{
    int ret = 0; 
    printf(" vtcm_PCRInfoShort_Copy:\n");
    /* copy TCM_PCR_SELECTION pcrSelection */
    if (ret == 0) 
    { 
        ret = vtcm_PCRSelection_Copy(&(dest_tcm_pcr_info_short->pcrSelection),
                                     &(src_tcm_pcr_info_short->pcrSelection));
    }    
    if (ret == 0) 
    { 
        /* copy TPM_LOCALITY_SELECTION localityAtRelease */
        dest_tcm_pcr_info_short->localityAtRelease = src_tcm_pcr_info_short->localityAtRelease;
        /* copy TPM_COMPOSITE_HASH digestAtRelease */
        vtcm_Digest_Copy(dest_tcm_pcr_info_short->digestAtRelease,
                         src_tcm_pcr_info_short->digestAtRelease);
    }    
    return ret;
}


/* vtcm_DelegatePublic_Copy() copies the 'src' to the 'dest' structure
*/

int vtcm_DelegatePublic_Copy(TCM_DELEGATE_PUBLIC *dest,
                             TCM_DELEGATE_PUBLIC *src)
{
    int ret = 0;     
    printf(" vtcm_DelegatePublic_Copy:\n");
    if (ret == 0) 
    { 
        /* copy rowLabel */
        dest->rowLabel = src->rowLabel;
        /* copy pcrInfo */
        ret = vtcm_PCRInfoShort_Copy(&(dest->pcrInfo), &(src->pcrInfo));
    }    
    if (ret == 0) 
    { 
        /* copy permissions */
        vtcm_Delegations_Copy(&(dest->permissions), &(src->permissions));
        /* copy familyID */
        dest->familyID = src->familyID;
        /* copy verificationCount */
        dest->verificationCount = src->verificationCount;
    }    
    return ret;
}




/* TPM_DSAPDelegate() implements the actions common to TPM_DSAP and TPM_OSAP with
 * ownerReference pointing to a delegate row.
 *
 * 'entityDigest' and 'authData' are returned, as they are used by common code.
 * authSession.
 *
 * protocolID is changed to DSAP.
 * the TPM_DELEGATE_PUBLIC blob is copied to the OSAP/DSAP session structure.
 */


static int vtcm_OSAPDelegate(TCM_DIGEST **entityDigest,
                             TCM_SECRET **authData,
                             TCM_SESSION_DATA *authSession,
                             tcm_state_t *tcm_state,
                             uint32_t delegateRowIndex)
{
    int ret = 0;
    TCM_DELEGATE_TABLE_ROW  *d1DelegateTableRow;
    TCM_FAMILY_TABLE_ENTRY  *familyRow;             /* family table row containing familyID */
    printf("vtcm_DSAPCommon: Index %u\n", delegateRowIndex);
    /* 2. Else if entityType == TCM_ET_DEL_ROW */
    /* a. Verify that entityValue points to a valid row in the delegation table. */
    /* b. Set d1 to the delegation information in the row. */
    if (ret == TCM_SUCCESS) 
    {/*
        ret = vtcm_DelegateTable_GetValidRow(&d1DelegateTableRow,
                                             &(tcm_state->tcm_permanent_data.delegateTable),
                                             delegateRowIndex);*/
    }
    if (ret == 0) 
    {
        /* d. Locate D1 -> familyID in the TPM_FAMILY_TABLE and set familyRow to indicate that
         * row, return TPM_BADINDEX if not found */
        /* e. Set FR to TPM_FAMILY_TABLE.FamTableRow[familyRow] */
        /* f. If FR -> flags TPM_FAMFLAG_ENABLED is FALSE, return TPM_DISABLED_CMD */
        /*ret = vtcm_FamilyTable_GetEnabledEntry(&familyRow,
                                               &(tcm_state->tcm_permanent_data.familyTable),
                                               d1DelegateTableRow->pub.familyID);*/
    }
    /* g. Verify that d1->verificationCount equals FR -> verificationCount. */
    if (ret == 0) 
    {
        if (d1DelegateTableRow->pub.verificationCount != familyRow->verificationCount) 
        {
            printf(" vtcm_DSAPCommon: Error, verificationCount mismatch %u %u\n",
                     d1DelegateTableRow->pub.verificationCount, familyRow->verificationCount);
            ret = TCM_FAMILYCOUNT;                        
        }
    }
    if (ret == 0) 
    {
        /* c. Set a1 to d1->authValue. */
        *authData = &d1DelegateTableRow->authValue;     /* use owner delegate authorization value */
        /* indicate later that the entity is the 'owner'.  Use the real owner auth because the
         * ordinal doesn't know about the delegation */
        *entityDigest = &(tcm_state->tcm_permanent_data.ownerAuth);
        authSession->protocolID = TCM_PID_DSAP;         /* change from OSAP to DSAP */
        /* Save the TPM_DELEGATE_PUBLIC to check the permissions and pcrInfo at DSAP session
         * use. */
        /*ret = vtcm_DelegatePublic_Copy(&(authSession->pub),
                                       &(d1DelegateTableRow->pub));*/
    }
    return ret;
}

int vtcm_Check_Permission(int ordinal,
                          UINT16 entityType,
                          BYTE *authData,
                          BYTE *nonce,
                          BYTE *authCode
                         )
{
    printf("vtcm_Check_Permission : Start\n");

    int ret = TCM_SUCCESS;
    //TCM_SECRET authData;
    printf("ordinal = %08x ,entityType = %04x\n", ordinal, entityType);
    if(ret == TCM_SUCCESS)
    {
        //Calculate authCode
        BYTE *Str_Hash = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE*2);
        BYTE *Str_Hash_out = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE*2);
        BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE*2);
        memcpy(Str_Hash, &ordinal, 4);
        UINT16 temp_type = htons(entityType);
        memcpy(Str_Hash + 4, &temp_type, 2);
        vtcm_SM3(Str_Hash_out, Str_Hash, 6);

        Memcpy(Str_Hash_out + TCM_NONCE_SIZE, nonce, TCM_NONCE_SIZE);
        vtcm_HMAC_SM3(authData, TCM_NONCE_SIZE, Str_Hash_out, TCM_NONCE_SIZE*2, checksum);

        //Compare authCode
        if(!strcmp(authCode ,checksum))
        {
            printf("Verification authCode Success\n");
        }
        else
        {
            printf("Verification authCode Fail\n");
            ret = -1;
        }
        free(Str_Hash);
        free(Str_Hash_out);
        free(checksum);
    }
    return ret;
}

/*
 * proc_vtcm_APCreate
 */

int proc_vtcm_APCreate(void* sub_proc, void* recv_msg)
{
    printf("proc_vtcm_APCreate : Start\n");

    int ret = 0;
    int i = 0;
    int keylen;
    int got_handle;
    uint32_t entityValue = 0;                           //The selection value based on entityType, e.g. akeyHandle # 
    TCM_ENTITY_TYPE     entityType;                     // The type of entity in use 
    uint32_t authHandle = 0;
    TCM_SESSION_DATA *authSession;
    TCM_NV_DATA_SENSITIVE *tcm_nv_data_sensitive;       // associated with entityValue 
    TCM_DIGEST  *entityDigest = NULL;                   // digest of the entity establishing the OSAP session, initialize to silence compiler 
    BYTE          *authData = NULL;                      // usageAuth for the entity 
    TCM_COUNTER_VALUE   *counterValue;                  // associated with entityValue 
    TCM_KEY             *authKey = NULL;                       // key to authorize 
    TCM_BOOL            parentPCRStatus;
    int returnCode=0;    

    //input process
    struct tcm_in_APCreate *vtcm_in;
    
    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0); // get structure 
    if(ret < 0) 
        return ret;
    else ret = 0;
    if(vtcm_in == NULL)
        return -EINVAL;
    
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    //output process
    void * template_out = memdb_get_template(DTYPE_VTCM_OUT_AUTH1, SUBTYPE_APCREATE_OUT);//Get the entire command template
    if(template_out == NULL)
    {    
        printf("can't solve this command!\n");
    }    
    struct tcm_out_APCreate * vtcm_out = malloc(struct_size(template_out));
    /*   
      Processing
    */
    //produce authSession
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_AuthSessions_GetNewHandle(&authSession,
                                             &authHandle,
                                             tcm_state->tcm_stany_data.sessions);
    }
    // 3. Internally the TCM will do the following: 
    if (ret == TCM_SUCCESS) 
    {
        printf("vtcm_Process_APCreate: Using authHandle %08x\n", authHandle);
        authSession->protocolID = TCM_PID_APCREATE;
        authSession->entityTypeByte = vtcm_in->entityType;      /* save entity type LSB */
        ret = vtcm_Random(authSession->nonceEven, TCM_NONCE_SIZE);
        //Anti-replay attack serial number
        vtcm_Generate_Random(&(vtcm_out->sernum), 4);
        authSession->SERIAL = vtcm_out->sernum;
        if(authSession->entityTypeByte != TCM_ET_NONE)
        {
            authSession->adipEncScheme = ((vtcm_in->entityType) >> 8) & 0x00ff;        // save entity type MSB 
            //ret = vtcm_AuthSessionData_CheckEncScheme(authSession->adipEncScheme,
            //                                          tcm_state->tcm_permanent_flags.FIPS);
        }
    }
    switch(authSession->entityTypeByte)
    {
        case TCM_ET_KEYHANDLE:
            // If entityType = TPM_ET_KEYHANDLE
            if (ret == TCM_SUCCESS) 
            {
                // get the TPM_KEY, entityValue is the handle
                printf("  proc_vtcm_APCreate: entityType TCM_ET_KEYHANDLE entityValue %08x\n", vtcm_in->entityValue);
                // TPM_KeyHandleEntries_GetKey() does the mapping from TPM_KH_SRK to the SRK 
                ret = vtcm_KeyHandleEntries_GetKey(&authKey,
                                                   &parentPCRStatus,
                                                   tcm_state,
                                                   vtcm_in->entityValue,
                                                   TRUE,          /* read only */
                                                   TRUE,          /* ignore PCRs */
                                                   FALSE);        /* cannot use EK */
            }
            if (ret == TCM_SUCCESS) 
            {
                // get the entityDigest for the key
                // entityDigest = vtcm_Key_GetpubDigest(&entityDigest, authKey);
                // get the usageAuth for the key
                ret = vtcm_Key_GetUsageAuth(&authData, authKey);                                            
            }
            break;
        case TCM_ET_OWNER:
            // 7. else if entityType = TPM_ET_OWNER
            if (ret == TCM_SUCCESS) 
            {
                //entityDigest = &(tcm_state->tcm_permanent_data.ownerAuth);
                authData = &(tcm_state->tcm_permanent_data.ownerAuth);
            }
            break;
	case TCM_ET_DATA:
	   {
            	authData = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
                memset(authData, 0 ,TCM_NONCE_SIZE);
	   }
	   break;
        case TCM_ET_SMK:
            /* 8. else if entityType = TCM_ET_SMK */
            /* a. The entity to authorize is the SM3. entityValue is ignored. */
            printf(" proc_vtcm_APCreate: entityType TCM_ET_SMK\n");
            //entityDigest = vtcm_Key_GetpubDigest(&entityDigest, &(tcm_state->tcm_permanent_data.smk));
            ret = vtcm_Key_GetUsageAuth(&authData, &(tcm_state->tcm_permanent_data.smk));
            break;
        case TCM_ET_COUNTER:
            /* 9. else if entityType = TCM_ET_COUNTER */
            /* a. The entity is a monotonic counter, entityValue contains the counter handle */
            if (ret == TCM_SUCCESS) 
            {
                printf(" proc_vtcm_APCreate: entityType TCM_ET_COUNTER entityValue %08x\n",
                         entityValue);
                ret = vtcm_Counters_GetCounterValue(&counterValue,
                                                    tcm_state->tcm_permanent_data.monotonicCounter,
                                                    entityValue);    
            }
            if (ret == TCM_SUCCESS) 
            {
                /* get the entityDigest for the counter */
                entityDigest = &(counterValue->digest);
                /* get the authData for the counter */
                authData = &(counterValue->authData);                                            
            }
            break;
        case TCM_ET_NV:
            /* 10. else if entityType = TPM_ET_NV 
             * a. The entity is a NV index, entityValue contains the NV index */
            if (ret == TCM_SUCCESS) 
            {
                printf("proc_vtcm_APCreate: entityType TCM_ET_NV\n");
                ret = vtcm_NVIndexEntries_GetEntry(&tcm_nv_data_sensitive,
                                                  &(tcm_state->tcm_nv_index_entries),
                                                  entityValue);   
            }    
            if (ret == TCM_SUCCESS) 
            {
                /* get the entityDigest for the NV data */
                //entityDigest = &(tcm_nv_data_sensitive->digest);
                /* get the authData for the NV data */
                authData = &(tcm_nv_data_sensitive->authValue);                                            
            }    
            break;
        case TCM_ET_NONE:
            authData = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
            memset(authData, 0 ,TCM_NONCE_SIZE);
            break;
        case TCM_ET_KEY:
            break;
        default:
            /* 11. else return TCM_INVALID_PARAMETER */
            printf("proc_vtcm_APCreate: Error, unknown entityType %04x\n", entityType);
            ret = TCM_BAD_PARAMETER;
            break;
    }
    //ret = 0; 
    //Verification authCode
    if(vtcm_in->entityType != TCM_ET_NONE)
    {
	// compute checkcode
	    BYTE CheckData[TCM_HASH_SIZE];	
	    Memcpy(CheckData,authData,TCM_HASH_SIZE);
    	ret=vtcm_Compute_AuthCode(vtcm_in,DTYPE_VTCM_IN_AUTH1,SUBTYPE_APCREATE_IN,NULL,CheckData);
        if(ret != TCM_SUCCESS)
        {
          printf("\n\n          APCreate in AuthCode Error\n");
        }
        else 
        {
          printf("\n\n          APCreate in AuthCode Success\n");
        }
	if(ret!=0)
	{
		returnCode=TCM_BAD_PARAMETER;
		goto apcreate_out;
	}
	if(Memcmp(CheckData,vtcm_in->authCode,TCM_HASH_SIZE)!=0)
	{
		returnCode=TCM_AUTHFAIL;
        printf("\nCompare AuthCode Error\n\n");
		goto apcreate_out;
	}

    }
    /* 2.c. shared secret */
    if(vtcm_in->entityType != TCM_ET_NONE)
    {
        //Calculate shareSecret
        BYTE *buffer_hmac_sm3 = (BYTE *)malloc(sizeof(BYTE)*TCM_NONCE_SIZE*2);
        Memcpy(buffer_hmac_sm3, vtcm_in->nonce, TCM_NONCE_SIZE);
        Memcpy(buffer_hmac_sm3+TCM_NONCE_SIZE, authSession->nonceEven, TCM_NONCE_SIZE);
        vtcm_HMAC_SM3(authData, TCM_NONCE_SIZE, buffer_hmac_sm3, TCM_NONCE_SIZE*2, authSession->sharedSecret);//!!!!


        //Entity authorization code
/*
        BYTE *buffer_sm3 = (BYTE *)malloc(sizeof(BYTE)*80);
        BYTE *buffer_sm3_out = (BYTE *)malloc(sizeof(BYTE)*80);
            
        int temp = htonl(ret);
        Memcpy(buffer_sm3, &temp, 4);
        temp = htonl(vtcm_in->ordinal);
        Memcpy(buffer_sm3 + 4, &temp, 4);
        Memcpy(buffer_sm3 + 8, vtcm_in->nonce, TCM_NONCE_SIZE);
        vtcm_SM3(buffer_sm3_out, buffer_sm3, 40);
        temp = htonl(vtcm_out->sernum);
        Memcpy(buffer_sm3_out + TCM_NONCE_SIZE, &temp, 4);
        vtcm_HMAC_SM3(authSession->sharedSecret , TCM_NONCE_SIZE,  buffer_sm3_out, TCM_NONCE_SIZE+4, vtcm_out->authCode);
*/
    }

apcreate_out:
    //Response
    printf("proc_vtcm_APCreate : Response \n");

    vtcm_out->tag = 0xC500;
    vtcm_out->returnCode = returnCode;
    vtcm_out->authHandle = authHandle;

    Memcpy(vtcm_out->nonceEven, authSession->nonceEven, TCM_NONCE_SIZE);
    
    ret = vtcm_Compute_AuthCode(vtcm_out,
                                DTYPE_VTCM_OUT_AUTH1,
                                SUBTYPE_APCREATE_OUT,
                                authSession,
                                vtcm_out->authCode);
    if(ret != TCM_SUCCESS)
    {
      printf("\nAPCreate Error\n\n\n");
    }

    int responseSize = 0;
    responseSize = struct_2_blob(vtcm_out, Buf, template_out);

    vtcm_out->paramSize = responseSize;
    void *send_msg = message_create(DTYPE_VTCM_OUT_AUTH1 ,SUBTYPE_APCREATE_OUT ,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n");
        return -EINVAL;      
    }
    message_add_record(send_msg, vtcm_out);

     // add vtcm's expand info	
    ret = vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret < 0)
    {
	    printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}


/* vtcm_Nonce_Init resets a nonce structure to zeros */

void vtcm_Nonce_Init(TCM_NONCE tcm_nonce)
{
    size_t i;

    printf("  vtcm_Nonce_Init:\n");
    for (i = 0 ; i < TCM_NONCE_SIZE ; i++) 
    {
        tcm_nonce[i] = 0;                    
    }   
    return;
}

void vtcm_Secret_Init(TCM_SECRET tcm_secret)
{
    printf("  vtcm_Secret_Init:\n");
    memset(tcm_secret, 0, TCM_SECRET_SIZE);
    return;
}


/* vtcm_Digest_Init resets a digest structure to zeros */

void vtcm_Digest_Init(TCM_DIGEST tcm_digest)
{
    printf("  vtcm_Digest_Init:\n");
    memset(tcm_digest.digest, 0, TCM_DIGEST_SIZE);
    return;
}



/* vtcm_AuthSessionData_Init()
 *
 * sets members to default values
 * sets all pointers to NULL and sizes to 0
 * always succeeds - no return code
 */

int vtcm_AuthSessionData_Init(TCM_SESSION_DATA *tcm_session_data)
{
    printf(" vtcm_AuthSessionData_Init:\n");
    int ret = TCM_SUCCESS;
    tcm_session_data->handle = 0; 
    tcm_session_data->protocolID = 0; 
    tcm_session_data->entityTypeByte = 0; 
    tcm_session_data->adipEncScheme = 0; 
    vtcm_Nonce_Init(tcm_session_data->nonceEven);
    vtcm_Secret_Init(tcm_session_data->sharedSecret);
    vtcm_Digest_Init(tcm_session_data->entityDigest);
    //vtcm_DelegatePublic_Init(&(tpm_auth_session_data->pub));
    tcm_session_data->valid = FALSE;
    return ret;
}




/* TPM_AuthSessionData_Delete()
 *
 * No-OP if the parameter is NULL, else:
 * frees memory allocated for the object
 * sets pointers to NULL
 * calls TPM_AuthSessionData_Init to set members back to default values
 * The object itself is not freed
 */   

int vtcm_AuthSessionData_Delete(TCM_SESSION_DATA *tcm_session_data)
{
    printf(" TPM_AuthSessionData_Delete:\n");
    int ret = TCM_SUCCESS;
    if (tcm_session_data != NULL) 
    {
        ret = vtcm_AuthSessionData_Init(tcm_session_data);               
    }
    else ret = -1;
    return ret;
}




/* vtcm_AuthSessions_TerminateHandle() terminates the session associated with 'authHandle'.
 *
 * */

int vtcm_AuthSessions_TerminateHandle(TCM_SESSION_DATA *sessions,
                                      TCM_AUTHHANDLE authHandle)
{
    int ret = TCM_SUCCESS;
    TCM_SESSION_DATA *tcm_session_data;

    printf(" vtcm_AuthSessions_TerminateHandle: Handle %08x\n", authHandle);
    /* get the TCM_SESSION_DATA associated with the TCM_AUTHHANDLE */
    if (ret == TCM_SUCCESS) 
    {
        ret = vtcm_AuthSessions_GetEntry(&tcm_session_data, sessions, authHandle);
    }
    /* invalidate the valid handle */
    if (ret == TCM_SUCCESS) 
    {
        vtcm_AuthSessionData_Delete(tcm_session_data);
    }
    return ret;
}

int vtcm_AuthCode_Check_APTerminate(int value_ordinal,
                                    TCM_SESSION_DATA *authSession,
                                    BYTE *authCode)
{
    printf("vtcm_AuthCode_Check_APTerminate : Start\n");
    int ret = TCM_SUCCESS;
    int i;
    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
    int temp = htonl(value_ordinal);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, sizeof(int));
    
    temp = htonl(authSession->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(authSession->sharedSecret, TCM_NONCE_SIZE, Str_Hash_Out,TCM_NONCE_SIZE + sizeof(int), checksum);
    //Compare authCode
    TCM_BOOL flag = false;
    for(i = 0;i < 32; ++i)
    {
        if(authCode[i] != checksum[i])
        {
            flag = true;
        }
    }
    if(!flag)
    {
        printf("Verification authCode Success\n");
    }
    else
    {
        printf("Verification authCode Fail\n");
        ret = -1;
    }
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(checksum);
    return ret;
}

/*
 * proc_vtcm_APTerminate
 */


int proc_vtcm_APTerminate(void *sub_proc, void* recv_msg)
{
    printf("proc_vtcm_APTerminate : Start\n");
    int ret = TCM_SUCCESS;
    TCM_SESSION_DATA *authSession = NULL;

    //input process
    struct tcm_in_APTerminate *vtcm_input;
    
    ret = message_get_record(recv_msg, (void **)&vtcm_input, 0); // get structure 
    if(ret < 0) 
        return ret;
    if(vtcm_input == NULL)
        return -EINVAL;
    
    tcm_state_t* curr_tcm = ex_module_getpointer(sub_proc);
    
    //output process
    void * template_out = memdb_get_template(DTYPE_VTCM_OUT, SUBTYPE_APTERMINATE_OUT);//Get the entire command template
    if(template_out == NULL)
    {    
        printf("can't solve this command!\n");
    }    
    struct tcm_out_APTerminate * vtcm_output = malloc(struct_size(template_out));

    //Processing
    //Get AuthSession
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_AuthSessions_GetEntry(&authSession,
                                         curr_tcm->tcm_stany_data.sessions,
                                         vtcm_input->authHandle);
    }
    //Check authCode
    if(ret == TCM_SUCCESS)
    {

        ret = vtcm_AuthCode_Check_APTerminate(vtcm_input->ordinal,
                                              authSession,
                                              vtcm_input->authCode);
    }
    if(ret == TCM_SUCCESS)
    {
        printf("  vtcm_proc_APTerminate: Using authHandle %08x\n", vtcm_input->authHandle);
        ret = vtcm_AuthSessionData_Delete(authSession);
    }

    //Response
    printf("proc_vtcm_APTerminate : Response \n");
    vtcm_output->tag = 0xC400;
    vtcm_output->returnCode = ret;

    BYTE* response = (BYTE*)malloc(sizeof(BYTE) * 15);
    int responseSize = struct_2_blob(vtcm_output, response, template_out);
    vtcm_output->paramSize = responseSize;
    void *send_msg = message_create(DTYPE_VTCM_OUT ,SUBTYPE_APTERMINATE_OUT ,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n");
        return -EINVAL;      
    }
    message_add_record(send_msg, vtcm_output);

      // add vtcm's expand info	
     ret=vtcm_addcmdexpand(send_msg,recv_msg);
     if(ret<0)
     {
 	  printf("fail to add vtcm copy info!\n");
     }	

    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}




int proc_vtcm_Sm3Start(void* sub_proc, void* recv_msg)
{
    printf("proc_vtcm_Sm3Start : start\n");
    int ret = 0;
    int i = 0;

    struct tcm_in_Sm3Start *tcm_Sm3Start_in;
    ret = message_get_record(recv_msg, (void **)&tcm_Sm3Start_in, 0);                                                            
    if(ret < 0)
        return ret;
    if(tcm_Sm3Start_in == NULL)
        return -EINVAL;
    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT, SUBTYPE_SM3START_OUT);
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_Sm3Start * tcm_Sm3Start_out = malloc(struct_size(command_template));
    
    tcm_state_t * tcm_state = proc_share_data_getpointer();

    /*
     * Processing
    */
    tcm_state->sm3_context = malloc(sizeof(sm3_context));
    SM3_init(tcm_state->sm3_context);

    tcm_Sm3Start_out->tag = 0xC400;
    tcm_Sm3Start_out->paramSize = 0x0E;
    tcm_Sm3Start_out->returnCode = 0;
    tcm_Sm3Start_out->sm3MaxBytes = 512;

    void *send_msg = message_create(DTYPE_VTCM_OUT, SUBTYPE_SM3START_OUT, recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg, tcm_Sm3Start_out);
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}

int proc_vtcm_Sm3Update(void* sub_proc, void* recv_msg)
{
    printf("proc_vtcm_Sm3Update : start\n");
    int ret = 0;
    int i = 0;

    struct tcm_in_Sm3Update *tcm_Sm3Update_in;
    ret = message_get_record(recv_msg, (void **)&tcm_Sm3Update_in, 0);                                                            
    if(ret < 0)
        return ret;
    if(tcm_Sm3Update_in == NULL)
        return -EINVAL;
    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT, SUBTYPE_SM3UPDATE_OUT);
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_Sm3Update * tcm_Sm3Update_out = malloc(struct_size(command_template));
    
    tcm_state_t * tcm_state = proc_share_data_getpointer();

    /*
     * Processing
    */
    SM3_update(tcm_state->sm3_context, tcm_Sm3Update_in->dataBlock, tcm_Sm3Update_in->dataBlockSize );

    tcm_Sm3Update_out->tag = 0xC400;
    tcm_Sm3Update_out->paramSize = 0x0A;
    tcm_Sm3Update_out->returnCode = 0;

    void *send_msg = message_create(DTYPE_VTCM_OUT, SUBTYPE_SM3UPDATE_OUT, recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg, tcm_Sm3Update_out);
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}

int proc_vtcm_Sm3Complete(void* sub_proc, void* recv_msg)
{
    printf("proc_vtcm_Sm3Complete : start\n");
    int ret = 0;
    int i = 0;

    struct tcm_in_Sm3Complete *tcm_Sm3Complete_in;
    ret = message_get_record(recv_msg, (void **)&tcm_Sm3Complete_in, 0);                                                            
    if(ret < 0)
        return ret;
    if(tcm_Sm3Complete_in == NULL)
        return -EINVAL;
    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT, SUBTYPE_SM3COMPLETE_OUT);
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_Sm3Complete * tcm_Sm3Complete_out = malloc(struct_size(command_template));
    
    tcm_state_t * tcm_state = proc_share_data_getpointer();

    /*
     * Processing
    */
    SM3_update(tcm_state->sm3_context, tcm_Sm3Complete_in->dataBlock, tcm_Sm3Complete_in->dataBlockSize);
    SM3_final(tcm_state->sm3_context, tcm_Sm3Complete_out->calResult);

    tcm_Sm3Complete_out->tag = 0xC400;
    tcm_Sm3Complete_out->returnCode = 0;

    tcm_Sm3Complete_out->paramSize = 0x2A;

    void *send_msg = message_create(DTYPE_VTCM_OUT, SUBTYPE_SM3COMPLETE_OUT, recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg, tcm_Sm3Complete_out);
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}
/*
int proc_vtcm_Sm3CompleteExtend(void* sub_proc, void* recv_msg)
{
    printf("proc_vtcm_Sm3CompleteExtend : start\n");
    int ret = 0;
    int i = 0;
    //BYTE buffer[32];
    int pcr_size;

    struct tcm_in_Sm3CompleteExtend *tcm_Sm3CompleteExtend_in;
    ret = message_get_record(recv_msg, (void **)&tcm_Sm3ompleteExtend_in, 0);                                                            
    if(ret < 0)
        return ret;
    if(tcm_Sm3CompleteExtend_in == NULL)
        return -EINVAL;
    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT, SUBTYPE_SM3COMPLETEEXTEND_OUT);
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_Sm3CompleteExtend * tcm_Sm3CompleteExtend_out = malloc(struct_size(command_template));

    struct tcm_pcr_scene * pcr_scene = ex_module_getpointer(sub_proc);

    tcm_state_t * tcm_state = proc_share_data_getpointer();


    sm3_update(tcm_state->sm3_context, tcm_Sm3CompleteExtend_in->dataBlock, tcm_Sm3CompleteExtend_in->dataBlockSize);
    
    pcr_size=pcr_scene[0].pcr_size;
    pcr=pcr_scene[0].pcr+(tcm_CompleteExtend_in->Num)*pcr_size;
    Memcpy(buffer, pcr, pcr_size);
    Memcpy(buffer+pcr_size,vtcm_extend->inDigest,pcr_size);

    vtcm_SM3(pcr, buffer, pcr_size*2);
    Memcpy(tcm_Sm3CompleteExtend_out->pcrResult, pcr, pcr_size);


    tcm_Sm3CompleteExtend_out->tag = 0xC400;
    tcm_Sm3CompleteExtend_out->returnCode = 0;

    tcm_Sm3CompleteExtend_out->paramSize = 0x4A;

    void *send_msg = message_create(DTYPE_VTCM_OUT, SUBTYPE_SM3COMPLETEEXTEND_OUT, recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg, tcm_Sm3CompleteExtend_out);
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}*/

void vtcm_Sbuffer_Init(TCM_STORE_BUFFER * sbuffer)
{
    sbuffer->buffer = NULL;
    sbuffer->buffer_current =  NULL;
    sbuffer->buffer_end = NULL;

    printf("Buffer Init Succeed.\n");
}

void vtcm_Sbuffer_Delete(TCM_STORE_BUFFER * sbuffer)
{
    free(sbuffer->buffer);
    vtcm_Sbuffer_Init(sbuffer);

    printf("Buffer Delete Succeed.\n");
}
/*
int vtcm_Random(BYTE * buffer, size_t bytes)
{
    int ret = 0;
    printf("vtcm_Random: Requesting %lu bytes\n", (unsigned long)bytes);
    ret = RAND_bytes(buffer, bytes);
    if(ret == 1) {
        ret = 0;
    }
    else {
        printf("Error(fatal) calling RAND_bytes()\n");
    }
    return ret;
}

int vtcm_Nonce_Generate(TCM_NONCE tcm_nonce)
{
    int ret = 0;
    printf("Nonce_Generate:\n");
    ret = vtcm_Random(tcm_nonce, TCM_NONCE_SIZE);
    return ret;
}
*/
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

int vtcm_key_CheckPubDataDigest(TCM_KEY * tcm_key)
{
    int ret = 0;
    TCM_STORE_BUFFER sbuffer;

    printf("Key_CheckPubDataDigest\n");
    vtcm_Sbuffer_Init(&sbuffer);
    vtcm_Sbuffer_Delete(&sbuffer);

    printf("Key_CheckPubDataDigest have already succeed.\n");
    return ret;
}

//Universal template ↓↓↓↓
/*
int proc_vtcm_XX(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_XX : Start\n") ;
    int ret = 0 ;
    int i = 0 ;
    
    struct tcm_in_XX *tcm_XX_in ;

    ret = message_get_record(recv_msg, (void **)&tcm_XX_in, 0) ; // get structure 
    if(ret < 0)
        return ret;
    if(tcm_XX_in == NULL)
        return -EINVAL;

    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_XXX_OUT);//Get the entire command template
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_XX * tcm_XX_out = malloc(struct_size(command_template));

    tcm_state_t * tcm_state = proc_share_data_getpointer();

    //Processing
    
    //Response 

    tcm_XX_out->tag = 0xC400;
    tcm_XX_out->paramSize = 10;
    tcm_XX_out->returnCode = 0;

    void *send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_XXX_OUT,recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg ,tcm_XX_out);
    ret = ex_module_sendmsg(sub_proc ,send_msg);

    return ret;
}
*/

/*
int vtcm_AuthSessionData_Decrypt(BYTE *retData,
                                 TCM_SESSION_DATA *authSession,
                                 BYTE *encData
                                )
{
    printf("vtcm_AuthSessionData_Decrypt : Start\n");

    int ret = TCM_SUCCESS;
    sm4_context ctx;
    
    BYTE *sessionKey = (BYTE *)malloc(sizeof(BYTE)*TCM_NONCE_SIZE/2);
    ret = KDFwithSm3(sessionKey, authSession->sharedSecret, TCM_NONCE_SIZE/2, TCM_NONCE_SIZE);
    if(ret != TCM_SUCCESS)
    {
        printf("Error, KDFwithSm3\n");
    }
    sm4_setkey_dec(&ctx, sessionKey);
    sm4_crypt_ecb(&ctx, 0, 32, encData, retData);
    return ret;
}
*/
int vtcm_AuthData_Check_CWrapKey(int ordinal,
                                 BYTE *dataUsageAuth,
                                 BYTE *dataMigrationAuth,
                                 TCM_KEY *tcm_key,
                                 TCM_SESSION_DATA *auth_session_data,
                                 BYTE *authCode
                                )
{
    printf("vtcm_AuthData_Check_CWrapKey : Start\n");

    int ret = TCM_SUCCESS;

    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Key = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
    int temp = htonl(ordinal);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int), dataUsageAuth, TCM_NONCE_SIZE);
    memcpy(Str_Hash_In + sizeof(int) + TCM_NONCE_SIZE, dataMigrationAuth, TCM_NONCE_SIZE);

    void * template_key = memdb_get_template(DTYPE_VTCM_IN_KEY, SUBTYPE_TCM_BIN_KEY);  //Get the TCM_KEY template
    if(template_key == NULL)
    {    
        printf("can't get Key template!\n");
    }    
    int Str_length_key = struct_2_blob(tcm_key, Str_Hash_Key, template_key);
    if(Str_length_key == 0)
    {
        printf("Error, struct_2_blob : TCM_KEY\n");
    }
    int Str_Hash_Len = sizeof(int) + TCM_NONCE_SIZE * 2;
    memcpy(Str_Hash_In + Str_Hash_Len, Str_Hash_Key, Str_length_key);
    Str_Hash_Len += Str_length_key;
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Str_Hash_Len);
    
    //auth_session_data->SERIAL = 0;
    temp = htonl(auth_session_data->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(auth_session_data->sharedSecret, TCM_NONCE_SIZE, Str_Hash_Out,TCM_NONCE_SIZE + sizeof(int), checksum);
    //Compare authCode
    if(!strcmp(authCode ,checksum))
    {
        printf("Verification authCode Success\n");
    }
    else
    {
        printf("Verification authCode Fail\n");
        ret = -1;
    }
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(Str_Hash_Key);
    free(checksum);
    return ret;
}


int vtcm_Compute_AuthCode_CWrapKey(int value_ret,
                                   int value_ordinal,
                                   TCM_KEY *tcm_key,
                                   TCM_SESSION_DATA *authSession,
                                   BYTE *resAuth)
{
    printf("vtcm_Compute_AuthCode_Sm2Decrypt : Start\n");
    int ret = TCM_SUCCESS;

    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE)*300);
    BYTE *Str_Hash_out = (BYTE *)malloc(sizeof(BYTE)*300);
    BYTE *Str_Hash_Key = (BYTE *)malloc(sizeof(BYTE)*300);
    int temp = htonl(value_ret);
    Memcpy(Str_Hash_In, &temp, sizeof(int));
    temp = htonl(value_ordinal);
    Memcpy(Str_Hash_In + sizeof(int), &temp, sizeof(int));
        
    void * template_key = memdb_get_template(DTYPE_VTCM_IN_KEY, SUBTYPE_TCM_BIN_KEY);//Get the entire command template
    if(template_key == NULL)
    {    
        printf("can't get Key template!\n");
    }    
    int Str_length_key = struct_2_blob(tcm_key, Str_Hash_Key, template_key);
    Memcpy(Str_Hash_In + sizeof(int)*2, Str_Hash_Key, Str_length_key);
    int Str_Hash_length = Str_length_key + sizeof(int) * 2 ;
    vtcm_SM3(Str_Hash_out, Str_Hash_In, Str_Hash_length);
    uint32_t sernum = htonl(authSession->SERIAL);
    Memcpy(Str_Hash_out, &sernum, sizeof(uint32_t));
    vtcm_HMAC_SM3(authSession->sharedSecret, TCM_NONCE_SIZE, Str_Hash_out,TCM_NONCE_SIZE + sizeof(uint32_t), resAuth);

    return ret;
}

static int proc_vtcm_CreateWrapKey(void *sub_proc, void* recv_msg)
{
    printf("proc_vtcm_CreateWrapKey : Start\n");

    int ret = 0;
    TCM_SESSION_DATA   *auth_session_data = NULL;  // session data for authHandle 
    BYTE *dataUsageAuth = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE) ;
    BYTE *dataMigrationAuth = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE) ;
    TCM_KEY *WrapKey = NULL;
    TCM_STORE_ASYMKEY *tcm_store_asymkey = NULL;
    TCM_STORE_SYMKEY *tcm_store_symkey = NULL;
    TCM_SYMMETRIC_KEY_PARMS * sm4_parms;
    TCM_KEY * smk = NULL;
    BYTE *Str_pub = (BYTE *)malloc(sizeof(BYTE) * 300);
    BYTE CheckData[TCM_HASH_SIZE];  
    int offset;
    int i;
    
    //input process
    struct tcm_in_CreateWrapKey *vtcm_in;
    
    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0); // get structure 
    if(ret < 0) 
        return ret;
    else ret = 0;
    if(vtcm_in == NULL)
        return -EINVAL;
    
    tcm_state_t* curr_tcm = ex_module_getpointer(sub_proc);

    //output process
    void * template_out = memdb_get_template(DTYPE_VTCM_OUT_AUTH1, SUBTYPE_CREATEWRAPKEY_OUT);//Get the entire command template
    if(template_out == NULL)
    {    
        printf("can't solve this command!\n");
    }    
    struct tcm_out_CreateWrapKey * vtcm_out = malloc(struct_size(template_out));

    //Processing
    //Get AuthSession
    if(ret == TCM_SUCCESS)
    {
        vtcm_AuthSessions_GetEntry(&auth_session_data,
                                   curr_tcm->tcm_stany_data.sessions,
                                   vtcm_in->authHandle);
    }
    //Verification authCode
    if(ret == TCM_SUCCESS)
    {
      ret = vtcm_Compute_AuthCode(vtcm_in, DTYPE_VTCM_IN_AUTH1,SUBTYPE_CREATEWRAPKEY_IN, auth_session_data, CheckData);
      if(ret == TCM_SUCCESS)
      {
        if(Memcmp(CheckData,vtcm_in->pubAuth,TCM_HASH_SIZE) != 0)
        {    
            ret = TCM_AUTHFAIL;
            printf("\n\n        Compare AuthCode Error\n\n");
        }
        else 
        {
          printf("\n\n          Compare AuthCode Sucess\n");
        }
      }
    }
    //Create dataUsageAuth by decrypting dataUsageAuth 
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_AuthSessionData_Decrypt(dataUsageAuth,
                                           auth_session_data,
                                           vtcm_in->dataUsageAuth);
    }
    //Create dataMigrationAuth by decrypting dataMigrationAuth
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_AuthSessionData_Decrypt(dataMigrationAuth,
                                           auth_session_data,
                                           vtcm_in->dataUsageAuth);
    }
    if(ret == TCM_SUCCESS)
    {
        if(vtcm_in->keyInfo.algorithmParms.algorithmID == TCM_ALG_SM4)
        {
            sm4_parms = Talloc0(sizeof(*sm4_parms));
            if(sm4_parms == NULL)
                return -ENOMEM;
            void *vtcm_template = memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_SYMMETRIC_KEY_PARMS);
            if(vtcm_template == NULL)
                return -EINVAL;
            ret = blob_2_struct(vtcm_in->keyInfo.algorithmParms.parms, sm4_parms, vtcm_template);
            if(ret < 0)
                return ret; 
            if(sm4_parms->keyLength != 0x80)
            {
                ret = TCM_BAD_KEY_PROPERTY;
            }
            else
            {   
                // Generate SMK 
                vtcm_template = memdb_get_template(DTYPE_VTCM_IN_KEY, SUBTYPE_TCM_BIN_KEY);
                if(vtcm_template == NULL)
                    return -EINVAL;
                ret = struct_clone(&vtcm_in->keyInfo, &(vtcm_out->wrappedKey), vtcm_template);
                if(ret < 0)
                    return ret;
                ret = vtcm_Keystruct_GenerateSM4(&(vtcm_out->wrappedKey), dataUsageAuth, NULL);
                if(ret < 0)
                    return ret;
            }
            //Add dataUsageAuth for WrappedKey 
            if(ret == TCM_SUCCESS)
            {
                printf(" Add dataUsageAuth for WrappedKey!\n");
                vtcm_Key_GetStoreSymkey(&tcm_store_symkey, &(vtcm_out->wrappedKey));
                memcpy(tcm_store_symkey->usageAuth, dataUsageAuth, TCM_NONCE_SIZE);
                memcpy(tcm_store_symkey->migrationAuth, dataMigrationAuth, TCM_NONCE_SIZE);
            }
        }
        else 
        {
            WrapKey = &(vtcm_out->wrappedKey); 
            vtcm_Key_Init(WrapKey);
            //Generate asymmetric key according to algorithm information in keyInfo
            ret = vtcm_Key_GenerateSM2(WrapKey,
                                       curr_tcm,
                                       NULL,
                                       curr_tcm->tcm_stclear_data.PCRS,
                                       TCM_KEY_STORAGE,
                                       0,
                                       TCM_AUTH_ALWAYS,
                                       &(vtcm_in->keyInfo.algorithmParms),
                                       NULL,
                                       NULL);
             tcm_store_asymkey = Talloc0(sizeof(*tcm_store_asymkey));
             if(tcm_store_asymkey == NULL)
                return -EINVAL;
             // fill the privpik's auth data
            tcm_store_asymkey->payload = TCM_PT_ASYM;
                     
            for(i = 0; i < TCM_HASH_SIZE; i++)
            {
                tcm_store_asymkey->usageAuth[i] = vtcm_in->dataUsageAuth[i]^auth_session_data->sharedSecret[i];
            }   
            for(i = 0; i < TCM_HASH_SIZE; i++)
            {
                tcm_store_asymkey->migrationAuth[i] = vtcm_in->dataMigrationAuth[i]^auth_session_data->sharedSecret[i];
            }   
            //Memcpy(privpik->migrationAuth, curr_tcm->tcm_permanent_data.tcmProof,TCM_SECRET_SIZE);
            // compute pubkey's digest
            void *template_pub = memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_STORE_PUBKEY);
            if(template_pub == NULL)
                return -EINVAL;     
            ret = struct_2_blob(&(WrapKey->pubKey), Str_pub, template_pub);
            if(ret < 0)
            {
                ret = -TCM_BAD_DATASIZE;
            }
            calculate_context_sm3(Str_pub, ret, &(tcm_store_asymkey->pubDataDigest));
            tcm_store_asymkey->privKey.keyLength=WrapKey->encDataSize;
            tcm_store_asymkey->privKey.key=WrapKey->encData;
            
            // output the pik's encdata blob
            void *template_Store = memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_STORE_ASYMKEY);
            if(template_Store==NULL)
                return -EINVAL;
             
             ret = struct_2_blob(tcm_store_asymkey, Str_pub + DIGEST_SIZE, template_Store);
             if(ret < 0)
             {
                ret = -TCM_BAD_DATASIZE;
             }
             Memset(Str_pub,0,DIGEST_SIZE);
             offset = ret % DIGEST_SIZE;
                                         
             if(offset == 0)
                offset = DIGEST_SIZE; 
             
             // ignore the smk crypt for debug, should add crypt later
             WrapKey->encDataSize = ret + DIGEST_SIZE - offset;
             WrapKey->encData = Talloc0(WrapKey->encDataSize);
             if(WrapKey->encData == NULL)
                return -EINVAL;
             else ret = TCM_SUCCESS;
             Memcpy(WrapKey->encData, Str_pub + offset, WrapKey->encDataSize);
        }
    }
    //Response

    printf("proc_vtcm_CreateWrapKey : Response \n");

    vtcm_out->tag = 0xC500;
    vtcm_out->returnCode = ret;

    int responseSize = 0;
    BYTE* response = (BYTE*)malloc(sizeof(BYTE) * 700);
    responseSize = struct_2_blob(vtcm_out, response, template_out);

    vtcm_out->paramSize = responseSize;

    //Compute authCode
    if(ret == TCM_SUCCESS)
    {    
        ret = vtcm_Compute_AuthCode(vtcm_out, 
                                    DTYPE_VTCM_OUT_AUTH1,
                                    SUBTYPE_CREATEWRAPKEY_OUT, 
                                    auth_session_data, 
                                    vtcm_out->resAuth);
    }
    if(ret != TCM_SUCCESS)
    {
        printf("\nret != TCM_SUCCESS  Error\n");
    }


    void *send_msg = message_create(DTYPE_VTCM_OUT_AUTH1,SUBTYPE_CREATEWRAPKEY_OUT ,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n");
        return -EINVAL;      
    }
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
/*
int vtcm_AuthData_Check_LoadKey(int ordinal,
                                 TCM_KEY *inKey,
                                 TCM_SESSION_DATA *auth_session_data,
                                 BYTE *authCode
                                )
{
    printf("vtcm_AuthData_Check_LoadKey : Start\n");

    int ret = TCM_SUCCESS;
    

    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Key = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
    int temp = htonl(ordinal);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    //memcpy(Str_Hash_In + sizeof(int), inKey, TCM_NONCE_SIZE);

    void * template_key = memdb_get_template(DTYPE_VTCM_IN_KEY, SUBTYPE_TCM_BIN_KEY);  //Get the TCM_KEY template
    if(template_key == NULL)
    {    
        printf("can't get Key template!\n");
    }
    int Str_length_key = struct_2_blob(inKey, Str_Hash_Key, template_key);
    if(Str_length_key == 0) {
        printf("Error, struct_2_blob: TCM_KEY\n");
    }
    int Str_Hash_Len = sizeof(int);
    memcpy(Str_Hash_In + Str_Hash_Len, Str_Hash_Key, Str_length_key);
    Str_Hash_Len += Str_length_key;
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Str_Hash_Len);
    
    //auth_session_data->SERIAL = 0;
    temp = htonl(auth_session_data->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(auth_session_data->sharedSecret, TCM_NONCE_SIZE, Str_Hash_Out,TCM_NONCE_SIZE + sizeof(int), checksum);
    //Compare authCode
    if(!strcmp(authCode ,checksum))
    {
        printf("Verification authCode Success\n");
    }
    else
    {
        printf("Verification authCode Fail\n");
        ret = -1;
    }
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(Str_Hash_Key);
    free(checksum);
    return ret;
}
*/
int proc_vtcm_LoadKey(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_LoadKey : Start\n") ;
    int ret = 0 ;
    TCM_SESSION_DATA *auth_session_data = NULL;
    TCM_STORE_SYMKEY tcm_store_symkey;
    TCM_STORE_ASYMKEY tcm_store_asymkey;

    BYTE CheckData[TCM_HASH_SIZE];
    
    struct tcm_in_LoadKey *vtcm_in ;

    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0) ; // get structure 
    if(ret < 0)
        return ret;
    if(vtcm_in == NULL)
        return -EINVAL;

    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT_AUTH1,SUBTYPE_LOADKEY_OUT);//Get the entire command template
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_LoadKey * vtcm_out = malloc(struct_size(command_template));

    tcm_state_t * curr_tcm = ex_module_getpointer(sub_proc);
    
    void * template_out = memdb_get_template(DTYPE_VTCM_OUT_AUTH1, SUBTYPE_LOADKEY_OUT);
    //Processing
    if(ret == TCM_SUCCESS) {
        vtcm_AuthSessions_GetEntry(&auth_session_data,
                                   curr_tcm->tcm_stany_data.sessions,
                                   vtcm_in->authHandle);
        printf("%08x\n",auth_session_data->SERIAL);
    }
    if(ret == TCM_SUCCESS) {
      ret = vtcm_Compute_AuthCode(vtcm_in,
                                  DTYPE_VTCM_IN_AUTH1,
                                  SUBTYPE_LOADKEY_IN,
                                  auth_session_data,
                                  CheckData);
    }
    if(ret == TCM_SUCCESS)
    {
      if(Memcmp(CheckData, vtcm_in->parentAuth, TCM_HASH_SIZE) != 0)
      {
        ret = TCM_AUTHFAIL;
        printf("\nCompare AuthCode failed\n");
      }
    }
    
    if(vtcm_in->inKey.algorithmParms.algorithmID == TCM_ALG_SM2) {
        tcm_store_asymkey.privKey.keyLength = vtcm_in->inKey.encDataSize;
        tcm_store_asymkey.privKey.key = (BYTE *)malloc(sizeof(BYTE) * vtcm_in->inKey.encDataSize);
        memcpy(tcm_store_asymkey.privKey.key, vtcm_in->inKey.encData, vtcm_in->inKey.encDataSize);
    }
    if(vtcm_in->inKey.algorithmParms.algorithmID == TCM_ALG_SM4) {
        tcm_store_symkey.size = vtcm_in->inKey.encDataSize;
        tcm_store_symkey.data = (BYTE *)malloc(sizeof(BYTE) * tcm_store_symkey.size);
        memcpy(tcm_store_symkey.data, vtcm_in->inKey.encData, vtcm_in->inKey.encDataSize);
    }

    if(ret == TCM_SUCCESS) {
        ret = vtcm_KeyHandleEntries_AddKeyEntry(&(vtcm_out->inKeyHandle),
                                                curr_tcm->tcm_key_handle_entries,
                                                &(vtcm_in->inKey));
    }
    if(ret == TCM_SUCCESS) {
        printf("proc_vtcm_LoadKey: Loaded key handle %08x\n", vtcm_out->inKeyHandle);
    }
    if(ret == TCM_SUCCESS) {
        BYTE *Str_Hash = (BYTE *)malloc(sizeof(BYTE)*700);
        BYTE *Str_Hash_out = (BYTE *)malloc(sizeof(BYTE)*700);
        int temp = htonl(ret);
        Memcpy(Str_Hash, (unsigned char *)(&temp), sizeof(int));
        temp = htonl(vtcm_in->ordinal);
        Memcpy(Str_Hash + sizeof(int), (unsigned char *)(&temp), sizeof(int));
        vtcm_SM3(Str_Hash_out, Str_Hash, 8);
        temp = htonl(auth_session_data->SERIAL);
        Memcpy(Str_Hash_out, (unsigned char *)(&temp), sizeof(int));
        vtcm_HMAC_SM3(auth_session_data, TCM_NONCE_SIZE, Str_Hash_out, TCM_NONCE_SIZE + sizeof(int), vtcm_out->resAuth);
    }
    //Response 

    vtcm_out->tag = 0xC500;
    //vtcm_out->paramSize = 46;
    vtcm_out->returnCode = ret;
    
    int responseSize = 0;
    BYTE * response = (BYTE*)malloc(sizeof(BYTE)*700);
    responseSize = struct_2_blob(vtcm_out, response, template_out);
    vtcm_out->paramSize = responseSize;

    if(ret == TCM_SUCCESS)
    {
      ret = vtcm_Compute_AuthCode(vtcm_out,
                                  DTYPE_VTCM_OUT_AUTH1,
                                  SUBTYPE_LOADKEY_OUT,
                                  auth_session_data,
                                  vtcm_out->resAuth);
    }

    void *send_msg = message_create(DTYPE_VTCM_OUT_AUTH1,SUBTYPE_LOADKEY_OUT,recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg ,vtcm_out);
      // add vtcm's expand info	
     ret=vtcm_addcmdexpand(send_msg,recv_msg);
     if(ret<0)
     {
 	  printf("fail to add vtcm copy info!\n");
     }	

    ret = ex_module_sendmsg(sub_proc ,send_msg);

    return ret;
}

int proc_vtcm_EvictKey(void *sub_proc, void* recv_msg)
{
    printf("proc_vtcm_EvictKey : Start\n");
    int ret = TCM_SUCCESS;
    int   returnCode=0;

    //input process
    struct tcm_in_EvictKey *vtcm_in;
    
    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0); // get structure 
    if(ret < 0) 
        return ret;
    if(vtcm_in == NULL)
        return -EINVAL;
    
    tcm_state_t* curr_tcm = ex_module_getpointer(sub_proc);
    
    TCM_KEY_HANDLE_ENTRY * remove_keyentry;

    returnCode=vtcm_KeyHandleEntries_GetEntry(&remove_keyentry,
					curr_tcm->tcm_key_handle_entries,	
				        vtcm_in->evictHandle);
    if(returnCode==TCM_SUCCESS)
    {
	vtcm_KeyHandleEntry_Delete(remove_keyentry);	
    }		
   	
	
    //output process
    void * template_out = memdb_get_template(DTYPE_VTCM_OUT, SUBTYPE_EVICTKEY_OUT);//Get the entire command template
    if(template_out == NULL)
    {    
        printf("can't solve this command!\n");
    }    
    
    struct tcm_out_EvictKey * vtcm_output = malloc(struct_size(template_out));

    //Processing

    //Response
    printf("proc_vtcm_EvictKey : Response \n");
    vtcm_output->tag = 0xC400;
    vtcm_output->returnCode = returnCode;

    BYTE* response = (BYTE*)malloc(sizeof(BYTE) * 15);
    int responseSize = struct_2_blob(vtcm_output, response, template_out);
    vtcm_output->paramSize = responseSize;
    void *send_msg = message_create(DTYPE_VTCM_OUT ,SUBTYPE_EVICTKEY_OUT ,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n");
        return -EINVAL;      
    }
    message_add_record(send_msg, vtcm_output);

      // add vtcm's expand info	
     ret=vtcm_addcmdexpand(send_msg,recv_msg);
     if(ret<0)
     {
 	  printf("fail to add vtcm copy info!\n");
     }	

    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}

int vtcm_Check_AuthCode_Sm2Decrypt(int value_ordinal,     
                                   int value_DecryptDataSize, 
                                   BYTE *DecryptData,
                                   TCM_SESSION_DATA *authSession,
                                   BYTE *authCode)
{
  printf("vtcm_Check_AuthCode_Sm2Decrypt : Start\n");

  int ret = TCM_SUCCESS;

  BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE)*100);
  BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE)*100);
  BYTE *checksum = (BYTE *)malloc(sizeof(BYTE)*100);
  int temp = htonl(value_ordinal);
  memcpy(Str_Hash_In, &temp, sizeof(int));
  temp = htonl(value_DecryptDataSize);
  memcpy(Str_Hash_In + sizeof(int), &temp, sizeof(int));
  memcpy(Str_Hash_In + sizeof(int)*2, DecryptData, TCM_NONCE_SIZE);
  int Hash_In_Len = sizeof(int)*2 + TCM_NONCE_SIZE;
  vtcm_SM3(Str_Hash_Out, Str_Hash_In, Hash_In_Len);

  UINT16 sernum = htons(authSession->SERIAL);
  memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &sernum, sizeof(UINT16));
  vtcm_HMAC_SM3(authSession->sharedSecret , TCM_NONCE_SIZE,  Str_Hash_Out, TCM_NONCE_SIZE + sizeof(UINT16), checksum);

  if(!strcmp(authCode, checksum))
  {
    printf("Verification SUCCESS!\n");
  }
  else 
  {
    printf("Verification Fail!\n");
    ret = -1;
  }
  free(Str_Hash_In);
  free(Str_Hash_Out);
  free(checksum);
  return ret;
}

int vtcm_Compute_AuthCode_Sm2Decrypt(int value_ret,
                                     int value_ordinal,
                                     int value_DecryptedDataSize,
                                     BYTE *DecryptedData,
                                     TCM_SESSION_DATA *authSession,
                                     BYTE *resAuth)
{
    printf("vtcm_Compute_AuthCode_Sm2Decrypt : Strart\n");

    int ret = TCM_SUCCESS;

    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);

    int temp = htonl(value_ret);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    temp = htonl(value_ordinal);
    memcpy(Str_Hash_In + sizeof(int), &temp, sizeof(int));
    temp = htonl(value_DecryptedDataSize);
    memcpy(Str_Hash_In + sizeof(int) * 2, &temp, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int) * 3, DecryptedData, TCM_NONCE_SIZE);
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, sizeof(int)*3 + TCM_NONCE_SIZE);
    
    UINT16 sernum = htons(authSession->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &sernum, sizeof(UINT16));
    
    vtcm_HMAC_SM3(authSession->sharedSecret , TCM_NONCE_SIZE,  Str_Hash_Out, TCM_NONCE_SIZE + sizeof(UINT16), resAuth);
    
    return ret;
}

/*
 * proc_vtcm_SM2Decrypt
 */

int proc_vtcm_SM2Decrypt(void *sub_proc, void* recv_msg)
{
    printf("proc_vtcm_SM2Decrypt : Start\n");

    // internal parameters define
    BYTE CheckData[TCM_HASH_SIZE];
    int ret = TCM_SUCCESS;
    TCM_KEY *tcm_key = NULL;
    TCM_BOOL parentPCRStatus;
    TCM_STORE_ASYMKEY *tcm_store_asymkey = NULL;
    TCM_SESSION_DATA *authSession = NULL;
    BYTE keyauth[DIGEST_SIZE];
    int offset=0;

    //input/output struct  process
    struct tcm_in_Sm2Decrypt *vtcm_in;  // input data
    struct tcm_out_Sm2Decrypt *vtcm_out;  // normal output data
    struct vtcm_external_output_command *vtcm_err_out;  // err output data
    void * vtcm_template;
    int   returnCode=0;
    
    // get input data struct
    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0);  
    if(ret < 0) 
        return ret;
    else ret = 0;
    if(vtcm_in == NULL)
        return -EINVAL;
    // get tcm context's pointer
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    //Processing
    //Get AuthSession
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_AuthSessions_GetEntry(&authSession,
                                         tcm_state->tcm_stany_data.sessions,
                                         vtcm_in->DecryptAuthHandle);
    }
    //Compute DecryptedAuthVerfication
    if(ret == TCM_SUCCESS)
    {
      ret = vtcm_Compute_AuthCode(vtcm_in, 
                                  DTYPE_VTCM_IN_AUTH1, 
                                  SUBTYPE_SM2DECRYPT_IN, 
                                  authSession, CheckData);
    }
    //Verification authCode
    if(ret == TCM_SUCCESS) 
    {
      if(memcmp(CheckData, vtcm_in->DecryptAuthVerfication, TCM_HASH_SIZE) != 0) 
      {
         ret = TCM_AUTHFAIL;
	 returnCode=TCM_AUTHFAIL;
         printf("\nerror,authcode compare fail\n");
         goto sm2decrypt_out;	
      }
    }

    //output process
    void * template_out = memdb_get_template(DTYPE_VTCM_OUT_AUTH1, SUBTYPE_SM2DECRYPT_OUT);//Get the entire command template
    if(template_out == NULL)
    {    
        printf("Fatal error: can't solve command (%x %x)'s output!\n",DTYPE_VTCM_OUT_AUTH1,SUBTYPE_SM2DECRYPT_OUT);
	return -EINVAL;
    }    
    vtcm_out = Talloc(struct_size(template_out));
    
    // Rely on the handle to get the key
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_KeyHandleEntries_GetKey(&tcm_key, 
                                           &parentPCRStatus, 
                                           tcm_state, 
                                           vtcm_in->keyHandle,
                                           FALSE,     // not r/o, using to encrypt
                                           FALSE,     // do not ignore PCRs
                                           FALSE);    // cannot use EK
    }
    //Decrypt DecryptData
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_Key_GetStoreAsymkey(&tcm_store_asymkey, tcm_key);
        if(ret == TCM_SUCCESS)
        {
            BYTE *buffer_1 = (BYTE *)malloc(sizeof(BYTE)*500);
            vtcm_out->DecryptedDataSize = 500;
            ret = GM_SM2Decrypt(buffer_1,
                                &(vtcm_out->DecryptedDataSize),
                                vtcm_in->DecryptData,
                                vtcm_in->DecryptDataSize,
                                tcm_store_asymkey->privKey.key,
                                tcm_store_asymkey->privKey.keyLength);
            vtcm_out->DecryptedData = (BYTE *)malloc(sizeof(BYTE)*(vtcm_out->DecryptedDataSize));
            Memcpy(vtcm_out->DecryptedData, buffer_1, vtcm_out->DecryptedDataSize);
        }
    }
    //Response
    printf("proc_vtcm_Sm2Decrypt : Response \n");

sm2decrypt_out:

    vtcm_out->tag = 0xC500;
    vtcm_out->returnCode = returnCode;

    void * send_msg;

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
	// normal output process	


    	vtcm_out->paramSize = struct_2_blob(vtcm_out, Buf, template_out);

        ret = vtcm_Compute_AuthCode(vtcm_out,
                 DTYPE_VTCM_OUT_AUTH1,
                 SUBTYPE_SM2DECRYPT_OUT,
                 authSession,
                 vtcm_out->DecryptedAuthVerfication);
	if(ret<0)
	{
		printf("Fatal error: compute output authcode failed!\n");
		return -EINVAL;
	}
	

    	send_msg = message_create(DTYPE_VTCM_OUT_AUTH1,SUBTYPE_SM2DECRYPT_OUT ,recv_msg);
    	if(send_msg == NULL)
    	{
        	printf("send_msg == NULL\n");
        	return -EINVAL;      
    	}
    	message_add_record(send_msg, vtcm_out);
    }	
    // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret < 0)
    {
	    printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}

int vtcm_Check_AuthCode_WrapKey(int value_ordinal,
                                BYTE * dataUsageAuth,
                                BYTE * dataMigrationAuth,
                                TCM_KEY *keyInfo,
                                TCM_SESSION_DATA *authSession,
                                BYTE *authCode)
{
    printf("vtcm_Check_AuthCode_WrapKey : Start\n");

    int ret = TCM_SUCCESS;
    
    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 300);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 300);
    BYTE *Str_Hash_Key = (BYTE *)malloc(sizeof(BYTE) * 300);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * 300);
    int temp = htonl(value_ordinal);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int), dataUsageAuth, TCM_NONCE_SIZE);
    memcpy(Str_Hash_In + sizeof(int) + TCM_NONCE_SIZE, dataMigrationAuth, TCM_NONCE_SIZE);
    int Hash_In_Len = sizeof(int) + TCM_NONCE_SIZE * 2;

    void * template_key = memdb_get_template(DTYPE_VTCM_IN_KEY, SUBTYPE_TCM_BIN_KEY);  //Get the TCM_KEY template
    if(template_key == NULL)
    {    
        printf("can't get Key template!\n");
    }    
    int Str_length_key = struct_2_blob(keyInfo, Str_Hash_Key, template_key);
    if(Str_length_key == 0)
    {
        printf("Error, struct_2_blob : TCM_KEY\n");
    }
    memcpy(Str_Hash_In + Hash_In_Len, Str_Hash_Key, Str_length_key);
    Hash_In_Len += Str_length_key;
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Hash_In_Len);

    UINT16 sernum = htons(authSession->SERIAL);
    memcpy(Str_Hash_Out, &sernum, sizeof(UINT16));
    vtcm_HMAC_SM3(authSession->sharedSecret, TCM_NONCE_SIZE, Str_Hash_Out, TCM_NONCE_SIZE + sizeof(UINT16), checksum);
    
    //Compare authCode
    if(!strcmp(authCode ,checksum))
    {
        printf("Verification authCode Success\n");
    }
    else
    {
        printf("Verification authCode Fail\n");
        ret = -1;
    }
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(Str_Hash_Key);
    free(checksum);
    return ret;
}


int vtcm_Compute_AuthCode_WrapKey(int value_ret,
                                  int value_ordinal,
                                  TCM_KEY *tcm_key,
                                  TCM_SESSION_DATA *authSession,
                                  BYTE *resAuth)
{
    printf("vtcm_Compute_AuthCode_WrapKey : Start\n");
    int ret = TCM_NONCE_SIZE;
    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 300);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 300);
    BYTE *Str_Hash_Key = (BYTE *)malloc(sizeof(BYTE) * 300);

    int temp = htonl(value_ret);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    temp = htonl(value_ordinal);
    memcpy(Str_Hash_In + sizeof(int), &temp, sizeof(int));
    int Hash_In_Len = sizeof(int) * 2;
    
    void * template_key = memdb_get_template(DTYPE_VTCM_IN_KEY, SUBTYPE_TCM_BIN_KEY);  //Get the TCM_KEY template
    if(template_key == NULL)
    {    
        printf("can't get Key template!\n");
    }    
    int Str_length_key = struct_2_blob(tcm_key, Str_Hash_Key, template_key);
    if(Str_length_key == 0)
    {
        printf("Error, struct_2_blob : TCM_KEY\n");
    }
    memcpy(Str_Hash_In + Hash_In_Len, Str_Hash_Key, Str_length_key);
    Hash_In_Len += Str_length_key;
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Hash_In_Len);

    UINT16 sernum = htons(authSession->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &sernum, sizeof(UINT16));
    vtcm_HMAC_SM3(authSession->sharedSecret, TCM_NONCE_SIZE, Str_Hash_Out, TCM_NONCE_SIZE + sizeof(UINT16), resAuth);

    return ret;
}
/*
int vtcm_AuthData_Checkin_Sm4(int ordinal, 
                            BYTE * CBCusedIV, 
                            int EncryptDataSize,
                            BYTE * EncryptData,
                            TCM_SESSION_DATA *auth_session_data,
                            BYTE *authCode)
{
    printf("vtcm_AuthData_Checkin_Sm4: Start\n");
    int ret = TCM_SUCCESS;

    TCM_BOOL flag = TRUE;
    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * 500);
    int temp = htonl(ordinal);
    int temp2 = htonl(EncryptDataSize);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int), CBCusedIV, 16);
    memcpy(Str_Hash_In + sizeof(int) + 16, &temp2, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int)*2 + 16, EncryptData, EncryptDataSize);
    int Str_Hash_Len = sizeof(int)*2 + 16 + EncryptDataSize;
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Str_Hash_Len);
    
    //auth_session_data->SERIAL = 0;
    temp = htonl(auth_session_data->SERIAL);
    memcpy(Str_Hash_Out+TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(auth_session_data->sharedSecret, TCM_NONCE_SIZE, 
                  Str_Hash_Out,TCM_NONCE_SIZE + sizeof(int), authCode);
    //Compare authCode
//    for(int i = 0; i < 32; i++) {
//        if(authCode[i] != checksum[i]) {
//            flag = FALSE;
//            printf("error!\n");
//        }
//    }
//    if(flag)
//    {
//        printf("Verification authCode Success\n");
//    }
//    else
//    {
//        printf("Verification authCode Fail\n");
//        ret = -1;
//    }
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(checksum);
    return ret;

}

int vtcm_AuthData_Checkout_Sm4(int returnCode, 
                            int ordinal, 
                            int DataSize,
                            BYTE * Data,
                            TCM_SESSION_DATA *auth_session_data,
                            BYTE *authCode)
{
    printf("vtcm_AuthData_Checkout_Sm4: Start\n");
    int ret = TCM_SUCCESS;

    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
    int temp = htonl(returnCode);
    int temp2 = htonl(ordinal);
    int temp3 = htonl(DataSize);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int), &temp2, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int)*2, &temp3, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int)*3, Data, DataSize);
    int Str_Hash_Len = sizeof(int)*3 + DataSize;
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Str_Hash_Len);
    //auth_session_data->SERIAL = 0;
    temp = htonl(auth_session_data->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(auth_session_data->sharedSecret, TCM_NONCE_SIZE, 
                  Str_Hash_Out,TCM_NONCE_SIZE + sizeof(int), authCode);
    //Compare authCode
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(checksum);
    return ret;

}
*/
int proc_vtcm_Sm4Encrypt(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_Sm4Encrypt: Start\n") ;
    BYTE CheckData[TCM_HASH_SIZE];
    int ret = TCM_SUCCESS;
    BYTE *Key = (BYTE *)Talloc0(sizeof(BYTE) * TCM_NONCE_SIZE);
    TCM_KEY *tcm_key = NULL;
    TCM_BOOL parentPCRStatus;
    TCM_SESSION_DATA *authSession = NULL;
    TCM_STORE_SYMKEY *tcm_store_symkey = NULL;
    BYTE keyauth[DIGEST_SIZE];
    int offset=0;

    struct tcm_in_Sm4Encrypt *vtcm_in;
    struct tcm_out_Sm4Encrypt *vtcm_out;
    struct vtcm_external_output_command *vtcm_err_out;  // err output data
    void * vtcm_template;
    int   returnCode=0;
    
    // get input data struct
    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0);  
    if(ret < 0) 
        return ret;
    else ret = 0;
    if(vtcm_in == NULL)
        return -EINVAL;
    // get tcm context's pointer
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    sm4_context ctx;
     int outLength;

    //Processing
    //Get AuthSession
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_AuthSessions_GetEntry(&authSession,
                                         tcm_state->tcm_stany_data.sessions,
                                         vtcm_in->EncryptAuthHandle);
    }
    if(ret == TCM_SUCCESS)
    {
      ret = vtcm_Compute_AuthCode(vtcm_in, 
                                  DTYPE_VTCM_IN_AUTH1,
                                  SUBTYPE_SM4ENCRYPT_IN, 
                                  authSession, 
                                  CheckData);
    }
    //Verification authCode
    if(ret == TCM_SUCCESS) 
    {
      if(Memcmp(CheckData, vtcm_in->EncryptAuthVerfication, TCM_HASH_SIZE) != 0) 
      {
         ret = TCM_AUTHFAIL;
	 returnCode=TCM_AUTHFAIL;
         printf("\nerror,authcode compare fail\n");
         goto sm4encrypt_out;	
      }
    }

    //output process
    void * template_out = memdb_get_template(DTYPE_VTCM_OUT_AUTH1, SUBTYPE_SM4ENCRYPT_OUT);//Get the entire command template
    if(template_out == NULL)
    {    
        printf("Fatal error: can't solve command (%x %x)'s output!\n",DTYPE_VTCM_OUT_AUTH1,SUBTYPE_SM4ENCRYPT_OUT);
	return -EINVAL;
    }    
    vtcm_out = Talloc(struct_size(template_out));

    // Rely on the handle to get the key
    if(ret == TCM_SUCCESS) {
        ret = vtcm_KeyHandleEntries_GetKey(&tcm_key,
                                           &parentPCRStatus,
                                           tcm_state,
                                           vtcm_in->keyHandle,
                                           FALSE,
                                           FALSE,
                                           FALSE);
    }
    if(ret == TCM_SUCCESS) {
        ret = vtcm_Key_GetStoreSymkey(&tcm_store_symkey, tcm_key);
    }
    if(ret == TCM_SUCCESS) {
        ret = KDFwithSm3(Key, tcm_store_symkey->data, 
                         TCM_NONCE_SIZE/2,
                         tcm_store_symkey->size);
    }
    if(ret == TCM_SUCCESS)
    {
        sm4_setkey_enc(&ctx, Key);
        //void sm4_crypt_cbc( sm4_context *ctx,int mode,int length,unsigned char iv[16],
        //                    unsigned char *input,unsigned char *output);
        //vtcm_out->EncryptedDataSize=vtcm_in->EncryptDataSize; 	

	sm4_cbc_data_prepare(vtcm_in->EncryptDataSize,vtcm_in->EncryptData,&vtcm_out->EncryptedDataSize,Buf);
        vtcm_out->EncryptedData = (BYTE *)Talloc0(sizeof(BYTE)*(vtcm_out->EncryptedDataSize));
        sm4_crypt_cbc(&ctx, 1, vtcm_out->EncryptedDataSize, vtcm_in->CBCusedIV, Buf,
                      vtcm_out->EncryptedData);
    }
    //Response 

sm4encrypt_out:

    vtcm_out->tag = 0xC500;
    vtcm_out->returnCode = returnCode;

    void * send_msg;
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
	// normal output process	


    	vtcm_out->paramSize = struct_2_blob(vtcm_out, Buf, template_out);

        ret = vtcm_Compute_AuthCode(vtcm_out,
                 DTYPE_VTCM_OUT_AUTH1,
                 SUBTYPE_SM4ENCRYPT_OUT,
                 authSession,
                 vtcm_out->EncryptedAuthVerfication);
	if(ret<0)
	{
		printf("Fatal error: compute output authcode failed!\n");
		return -EINVAL;
	}
	

    	send_msg = message_create(DTYPE_VTCM_OUT_AUTH1 ,SUBTYPE_SM4ENCRYPT_OUT ,recv_msg);
    	if(send_msg == NULL)
    	{
        	printf("send_msg == NULL\n");
        	return -EINVAL;      
    	}
    	message_add_record(send_msg, vtcm_out);
    }	
    // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret < 0)
    {
	    printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}

int proc_vtcm_Sm4Decrypt(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_Sm4Decrypt: Start\n") ;
    BYTE CheckData[TCM_HASH_SIZE];
    int ret = TCM_SUCCESS;
    BYTE *Key = (BYTE *)Talloc0(sizeof(BYTE) * TCM_NONCE_SIZE);
    TCM_KEY *tcm_key = NULL;
    TCM_BOOL parentPCRStatus;
    TCM_SESSION_DATA *authSession = NULL;
    TCM_STORE_SYMKEY *tcm_store_symkey = NULL;
    BYTE keyauth[DIGEST_SIZE];
    int offset=0;

    struct tcm_in_Sm4Decrypt *vtcm_in;
    struct tcm_out_Sm4Decrypt * vtcm_out;
    struct vtcm_external_output_command *vtcm_err_out;  // err output data
    void * vtcm_template;
    int   returnCode=0;


    // get input data struct
    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0); // get structure 
    if(ret < 0)
        return ret;
    if(vtcm_in == NULL)
        return -EINVAL;

    // get tcm context's pointer
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    sm4_context ctx;
    int outLength;

    //Processing
    if(ret == TCM_SUCCESS) {
        vtcm_AuthSessions_GetEntry(&authSession, 
                                   tcm_state->tcm_stany_data.sessions, 
                                   vtcm_in->DecryptAuthHandle);
        printf("Serial is %08x\n", authSession->SERIAL);
    }
    if(ret == TCM_SUCCESS) {
      ret = vtcm_Compute_AuthCode(vtcm_in,
                                  DTYPE_VTCM_IN_AUTH1,
                                  SUBTYPE_SM4DECRYPT_IN,
                                  authSession,
                                  CheckData);
    }
    if(ret == TCM_SUCCESS) {
      if(Memcmp(CheckData, vtcm_in->DecryptAuthVerfication, TCM_HASH_SIZE) != 0)
      {
        ret = TCM_AUTHFAIL;
	 returnCode=TCM_AUTHFAIL;
        printf("\nCompare AuthCode Error\n");
        goto sm4decrypt_out;
      }
    }
    //output process
    void * template_out = memdb_get_template(DTYPE_VTCM_OUT_AUTH1,SUBTYPE_SM4DECRYPT_OUT);//Get the entire command template
    if(template_out == NULL)
    {
        printf("Fatal error: can't solve command (%x %x)'s output!\n",DTYPE_VTCM_OUT_AUTH1,SUBTYPE_SM4DECRYPT_OUT);
	return -EINVAL;
    }
    vtcm_out = Talloc(struct_size(template_out));



    if(ret == TCM_SUCCESS) {
        ret = vtcm_KeyHandleEntries_GetKey(&tcm_key,
                                           &parentPCRStatus,
                                           tcm_state,
                                           vtcm_in->keyHandle,
                                           FALSE,
                                           FALSE,
                                           FALSE);
    }
    if(ret == TCM_SUCCESS) {
        ret = vtcm_Key_GetStoreSymkey(&tcm_store_symkey, tcm_key);
    }
    if(ret == TCM_SUCCESS) {
        ret = KDFwithSm3(Key,
                         tcm_store_symkey->data,
                         TCM_NONCE_SIZE/2,
                         tcm_store_symkey->size);
    }
    if(ret == TCM_SUCCESS) {
    	sm4_setkey_dec(&ctx, Key);
        sm4_crypt_cbc(&ctx, 0, vtcm_in->DecryptDataSize, vtcm_in->CBCusedIV, vtcm_in->DecryptData,Buf);
        vtcm_out->DecryptedData = (BYTE *)Talloc(sizeof(BYTE)*(vtcm_in->DecryptDataSize));
        
	sm4_cbc_data_recover(vtcm_in->DecryptDataSize,Buf,&vtcm_out->DecryptedDataSize,vtcm_out->DecryptedData);
    	//vtcm_out->DecryptedDataSize = vtcm_in->DecryptDataSize; 
    }
    returnCode=ret;
    
    //Response 
sm4decrypt_out:
    vtcm_out->tag = 0xC500;
    vtcm_out->returnCode=returnCode;

    void * send_msg;
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
	// normal output process	


    	vtcm_out->paramSize = struct_2_blob(vtcm_out, Buf, template_out);

        ret = vtcm_Compute_AuthCode(vtcm_out,
                 DTYPE_VTCM_OUT_AUTH1,
                 SUBTYPE_SM4DECRYPT_OUT,
                 authSession,
                 vtcm_out->DecryptedAuthVerfication);
	if(ret<0)
	{
		printf("Fatal error: compute output authcode failed!\n");
		return -EINVAL;
	}
	

    	send_msg = message_create(DTYPE_VTCM_OUT_AUTH1 ,SUBTYPE_SM4DECRYPT_OUT ,recv_msg);
    	if(send_msg == NULL)
    	{
        	printf("send_msg == NULL\n");
        	return -EINVAL;      
    	}
    	message_add_record(send_msg, vtcm_out);
    }	
    // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret < 0)
    {
	    printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}

int vtcm_AuthData_Check_Sign(int ordinal, 
                            int  dataSize, 
                            BYTE * data,
                            TCM_SESSION_DATA *auth_session_data,
                            BYTE *authCode)
{
    printf("vtcm_AuthData_Check_Sign: Start\n");
    int ret = TCM_SUCCESS;

    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Key = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
    int temp = htonl(ordinal);
    int temp2 = htonl(dataSize);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int),&temp2 , sizeof(int));
    memcpy(Str_Hash_In + sizeof(int)*2, data, dataSize);

    int Str_Hash_Len = sizeof(int)*2 + dataSize;
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Str_Hash_Len);
    
    //auth_session_data->SERIAL = 0;
    temp = htonl(auth_session_data->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(auth_session_data->sharedSecret, TCM_NONCE_SIZE, 
            Str_Hash_Out,TCM_NONCE_SIZE + sizeof(int), authCode);
    //Compare authCode
//    if(!strcmp(authCode ,checksum))
//    {
//        printf("Verification authCode Success\n");
//    }
//    else
//    {
//        printf("Verification authCode Fail\n");
//        ret = -1;
//    }
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(checksum);
    return ret;

}

int vtcm_AuthData_Check_Signout(int returnCode,
                                int ordinal,
                                int datasize,
                                BYTE * data,
                                TCM_SESSION_DATA *auth_session_data,
                                BYTE *authCode)
{
    printf("vtcm_AuthData_Check_Signout: Start\n");
    int ret = TCM_SUCCESS;

    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
    int temp = htonl(returnCode);
    int temp2 = htonl(ordinal);
    int temp3 = htonl(datasize);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int), &temp2, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int)*2, &temp3, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int)*3,data, datasize);
    int Str_Hash_Len = sizeof(int)*3 + datasize;
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Str_Hash_Len);
    //auth_session_data->SERIAL = 0;
    temp = htonl(auth_session_data->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(auth_session_data->sharedSecret, TCM_NONCE_SIZE, Str_Hash_Out,TCM_NONCE_SIZE + sizeof(int), authCode);
    //Compare authCode
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(checksum);
    return ret;
}

int proc_vtcm_Sign(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_Sign : Start\n") ;
    // internal parameters define
    BYTE CheckData[TCM_HASH_SIZE];
    int ret = TCM_SUCCESS;
    TCM_KEY *tcm_key = NULL;
    TCM_BOOL parentPCRStatus;
    TCM_STORE_ASYMKEY *tcm_store_asymkey = NULL;
    TCM_SESSION_DATA *authSession = NULL;

    BYTE UserID[DIGEST_SIZE];
    unsigned long lenUID = DIGEST_SIZE;
    memset(UserID, 'A', 32);
//    BYTE *keyUsageAuth;
    BYTE keyauth[DIGEST_SIZE];
    int offset=0;
//    struct tcm_in_Sign *tcm_input;
//    int outLength;
    //input/output struct  process
    struct tcm_in_Sign *vtcm_in;  // input data
    struct tcm_out_Sign *vtcm_out;  // normal output data
    struct vtcm_external_output_command *vtcm_err_out;  // err output data
    void * vtcm_template;
    int   returnCode=0;

    ret = message_get_record(recv_msg, (void **)&vtcm_in, 0) ; // get structure 
    if(ret < 0)
        return ret;
    if(vtcm_in == NULL)
        return -EINVAL;

    // get tcm context's pointer
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    //Processing
    //Get AuthSession
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_AuthSessions_GetEntry(&authSession,
                                         tcm_state->tcm_stany_data.sessions,
                                         vtcm_in->authHandle);
    }
    //Compute SignAuthVerfication
    if(ret == TCM_SUCCESS)
    {
      ret = vtcm_Compute_AuthCode(vtcm_in, 
                                  DTYPE_VTCM_IN_AUTH1, 
                                  SUBTYPE_SIGN_IN, 
                                  authSession, CheckData);
    }
    if(ret == TCM_SUCCESS) {
      if(Memcmp(CheckData, vtcm_in->privAuth, TCM_HASH_SIZE) != 0)
      {
        ret = TCM_AUTHFAIL;
	 returnCode=TCM_AUTHFAIL;
         printf("\nerror,authcode compare fail\n");
         goto sign_out;	
      }
    }
    if(vtcm_in->areaToSignSize == 0) {
        ret = TCM_BAD_PARAMETER;
	 returnCode=TCM_AUTHFAIL;
         printf("\nerror,sign size fail\n");
         goto sign_out;	
    }
    //output process
    void * template_out = memdb_get_template(DTYPE_VTCM_OUT_AUTH1,SUBTYPE_SIGN_OUT);//Get the entire command template
    if(template_out == NULL)
    {
        printf("Fatal error: can't solve command (%x %x)'s output!\n",DTYPE_VTCM_OUT_AUTH1,SUBTYPE_SIGN_OUT);
	return -EINVAL;
    }
    vtcm_out = Talloc(struct_size(template_out));

    if(ret == TCM_SUCCESS) {
        ret = vtcm_KeyHandleEntries_GetKey(&tcm_key,
                                           &parentPCRStatus,
                                           tcm_state,
                                           vtcm_in->keyHandle,
                                           FALSE,
                                           FALSE,
                                           FALSE);

    }
//    if(ret == TCM_SUCCESS) {
//        ret = vtcm_Key_GetUsageAuth(&keyUsageAuth, tcm_key);
//    }
    if(ret == TCM_SUCCESS) {
        ret = vtcm_Key_GetStoreAsymkey(&tcm_store_asymkey, 
                                       tcm_key);
    }

    vtcm_out->sigSize=vtcm_in->areaToSignSize;

    //Response 
    GM_SM2Sign(Buf, &vtcm_out->sigSize, 
               vtcm_in->areaToSign, vtcm_in->areaToSignSize,
               UserID, lenUID, 
               tcm_store_asymkey->privKey.key, tcm_store_asymkey->privKey.keyLength);
    vtcm_out->sig = (BYTE *)malloc(sizeof(BYTE) * vtcm_out->sigSize);
    Memcpy(vtcm_out->sig, Buf, vtcm_out->sigSize);
    //Response
    printf("proc_vtcm_Sm2Decrypt : Response \n");

sign_out:
    vtcm_out->tag = 0xC500;
    vtcm_out->returnCode = returnCode;

    void * send_msg;

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
	// normal output process	


    	vtcm_out->paramSize = struct_2_blob(vtcm_out, Buf, template_out);

        ret = vtcm_Compute_AuthCode(vtcm_out,
                 DTYPE_VTCM_OUT_AUTH1,
                 SUBTYPE_SIGN_OUT,
                 authSession,
                 vtcm_out->resAuth);
	if(ret<0)
	{
		printf("Fatal error: compute output authcode failed!\n");
		return -EINVAL;
	}
	

    	send_msg = message_create(DTYPE_VTCM_OUT_AUTH1 ,SUBTYPE_SIGN_OUT ,recv_msg);
    	if(send_msg == NULL)
    	{
        	printf("send_msg == NULL\n");
        	return -EINVAL;      
    	}
    	message_add_record(send_msg, vtcm_out);
    }	
    // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret < 0)
    {
	    printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}


int vtcm_Check_AuthCode_Seal(int value_ordinal,
                             BYTE *encAuth,
                             int pcrInfoSize,
                             BYTE *pcrInfo,
                             int InDataSize,
                             BYTE *InData,
                             TCM_SESSION_DATA *authSession,
                             BYTE *authCode)
{
    printf("vtcm_Check_AuthCode_Seal : Start\n");
    int ret = TCM_SUCCESS;
    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Key = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
    int temp = htonl(value_ordinal);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int), encAuth, TCM_NONCE_SIZE);
    temp = htonl(pcrInfoSize);
    memcpy(Str_Hash_In + sizeof(int) + TCM_NONCE_SIZE, &temp, sizeof(int));
    int Hash_In_Len = sizeof(int) * 2 + TCM_NONCE_SIZE ;
    memcpy(Str_Hash_In + Hash_In_Len, pcrInfo, pcrInfoSize);
    Hash_In_Len += pcrInfoSize;
    temp = htonl(InDataSize);
    memcpy(Str_Hash_In + Hash_In_Len, &temp, sizeof(int));
    Hash_In_Len += sizeof(int);
    memcpy(Str_Hash_In + Hash_In_Len, InData, InDataSize);
    Hash_In_Len += InDataSize;
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Hash_In_Len);
    
    temp = htonl(authSession->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(authSession->sharedSecret, TCM_NONCE_SIZE, Str_Hash_Out,TCM_NONCE_SIZE + sizeof(int), checksum);
    //Compare authCode
    if(!strcmp(authCode ,checksum))
    {
        printf("Verification authCode Success\n");
    }
    else
    {
        printf("Verification authCode Fail\n");
        ret = -1;
    }
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(checksum);
    return ret;
}


int vtcm_Compute_AuthCode_Seal(int value_ret,
                               int value_ordinal,
                               TCM_STORED_DATA *sealedData,
                               TCM_SESSION_DATA *authSession,
                               BYTE *authCode)
{
    printf("vtcm_Compute_AuthCode_Seal : Start\n");
    int ret = TCM_SUCCESS;
    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE)*300);
    BYTE *Str_Hash_out = (BYTE *)malloc(sizeof(BYTE)*300);
    BYTE *Str_Hash_Store = (BYTE *)malloc(sizeof(BYTE)*300);
    int temp = htonl(value_ret);
    Memcpy(Str_Hash_In, &temp, sizeof(int));
    temp = htonl(value_ordinal);
    Memcpy(Str_Hash_In + sizeof(int), &temp, sizeof(int));
    int Hash_In_Len = sizeof(int) * 2;
     
    void * template_store = memdb_get_template(DTYPE_VTCM_SEAL,SUBTYPE_TCM_STORED_DATA);//Get the entire command template
    if(template_store == NULL)
    {    
        printf("can't get Key template!\n");
    }    
    int Len = struct_2_blob(sealedData, Str_Hash_Store, template_store);
    Memcpy(Str_Hash_In + sizeof(int)*2, Str_Hash_Store, Len);
    int Str_Hash_length = Len + sizeof(int) * 2 ;
    
    vtcm_SM3(Str_Hash_out, Str_Hash_In, Hash_In_Len);
    uint32_t sernum = htonl(authSession->SERIAL);
    Memcpy(Str_Hash_out, &sernum, sizeof(uint32_t));
    vtcm_HMAC_SM3(authSession->sharedSecret, TCM_NONCE_SIZE, Str_Hash_out,TCM_NONCE_SIZE + sizeof(uint32_t), authCode);
    return ret;
}


void vtcm_SealedData_Init(TCM_SEALED_DATA *tcm_sealed_data)
{
    printf(" vtcm_SealedData_Init:\n");
    tcm_sealed_data->payload = TCM_PT_SEAL;
    memset(tcm_sealed_data->authData, 0, TCM_SECRET_SIZE);
    memset(tcm_sealed_data->tcmProof, 0, TCM_SECRET_SIZE);
    memset(tcm_sealed_data->storedDigest.digest, 0, TCM_DIGEST_SIZE);
    tcm_sealed_data->dataSize = 0;
    tcm_sealed_data->data = NULL;
    return;
}

void vtcm_StoredData_Init(TCM_STORED_DATA *tcm_stored_data)
{
    printf(" vtcm_StoredData_Init : Start\n");

    //tcm_stored_data->tag = htonl(TCM_TAG_STORED_DATA);
    tcm_stored_data->et = 0x0000;
    tcm_stored_data->sealInfoSize = 0;
    tcm_stored_data->sealInfo = NULL;
    tcm_stored_data->encDataSize = 0;
    tcm_stored_data->encData = NULL;
    return ;
}

/* vtcm_StoredData_GenerateDigest() generates a TCM_DIGEST over the TCM_STORED_DATA structure
 * excluding the encDataSize and encData members.
 */

int vtcm_StoredData_GenerateDigest(BYTE *digest, TCM_STORED_DATA *tcm_stored_data)
{
    printf(" vtcm_StoredData_GenerateDigest : Start\n");
    int ret = TCM_SUCCESS;
    BYTE *StoreData = (BYTE *)malloc(sizeof(BYTE) * 200);
    // serialize the TPM_STORED_DATA excluding the encData fields
    if (ret == TCM_SUCCESS) 
    {
        void * template = memdb_get_template(DTYPE_VTCM_SEAL, SUBTYPE_TCM_STORED_DATA);  //Get the TCM_STORED_DATA template
        if(template == NULL)
        {    
            printf("can't get template!\n");
        }    
        int Len = struct_2_blob(tcm_stored_data, StoreData, template);
        if(Len == 0)
        {
            printf("Error, struct_2_blob : TCM_STORED_DATA\n");
        }
        vtcm_SM3(digest, StoreData,  Len - sizeof(int) - (tcm_stored_data->encDataSize));
    }
    free(StoreData);
    return ret;
}


void vtcm_SizedBuffer_Init(TCM_SIZED_BUFFER *buffer)
{
    printf(" vtcm_SizedBuffer_Init : Start\n");
    buffer->size = 0;
    buffer->buffer = NULL;
}

void vtcm_SizedBuffer_Delete(TCM_SIZED_BUFFER *buffer)
{
    printf(" vtcm_SizedBuffer_Init : Start\n");
    free(buffer->buffer);
    vtcm_SizedBuffer_Init(buffer);
}

int vtcm_SealedData_Store(TCM_SIZED_BUFFER *Buffer, TCM_SEALED_DATA *tcm_sealed_data)
{
    printf(" vtcm_SealedData_Store : Start\n");

    int ret = TCM_SUCCESS;
    BYTE *Str_temp = (BYTE *)malloc(sizeof(BYTE) * 300);
    if(ret == TCM_SUCCESS)
    {
        void * template = memdb_get_template(DTYPE_VTCM_SEAL, SUBTYPE_TCM_SEALED_DATA);  //Get the TCM_KEY template
        if(template == NULL)
        {    
            printf("can't get template!\n");
        }    
        int Len = struct_2_blob(tcm_sealed_data, Str_temp, template);
        if(Len == 0)
        {
            printf("Error, struct_2_blob : TCM_SEALED_DATA\n");
        }
        Buffer->buffer = (BYTE *)malloc(sizeof(BYTE) * Len);
        Buffer->size = Len;
        Memcpy(Buffer->buffer, Str_temp, Len);
    }
    free(Str_temp);
    return ret;
}


int vtcm_SealedData_GenerateEncData(BYTE **encData,
                                    uint32_t *encDataSize,
                                    const TCM_SEALED_DATA *tcm_sealed_data,
                                    TCM_KEY *tcm_key)
{
    printf(" vtcm_SealedData_GenerateEncData : Start\n"); 
    int ret = TCM_SUCCESS;
    sm4_context ctx;
    TCM_SIZED_BUFFER sbuffer;             // TCM_SEALED_DATA serialization
    TCM_STORE_SYMKEY *tcm_store_symkey = NULL;
    BYTE *Key = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE/2);
    vtcm_SizedBuffer_Init(&sbuffer);
    // serialize the TPM_SEALED_DATA 
    if (ret == TCM_SUCCESS) 
    { 
        ret = vtcm_SealedData_Store(&sbuffer, tcm_sealed_data);
    }    
    // encrypt the TPM_SEALED_DATA serialization buffer with the public key, and place
    // the result in the encData members
    if (ret == TCM_SUCCESS) 
    { 
        ret = vtcm_Key_GetStoreSymkey(&tcm_store_symkey, tcm_key);
//        if(ret == TCM_SUCCESS)
//        {
//            ret = KDFwithSm3(Key, tcm_store_symkey->data, TCM_NONCE_SIZE/2, tcm_store_symkey->size);
//        }
        if(ret == TCM_SUCCESS)
        {
            sm4_setkey_enc(&ctx, tcm_store_symkey->data);

            int enc_len=0;
	    sm4_cbc_data_prepare(sbuffer.size,sbuffer.buffer,&enc_len,Buf);
    	    *encData = (BYTE *)malloc(sizeof(BYTE) * enc_len);
            sm4_crypt_ecb(&ctx, 1, enc_len,Buf, *encData);
    	    *encDataSize = enc_len;
        }
    }    
    vtcm_SizedBuffer_Delete(&sbuffer);
    return ret;
}

/*
 *   TPM_PCR_INFO
 */

void vtcm_PCRInfo_Init(TCM_PCR_INFO *tcm_pcr_info)                                                                                                                                              
{
    printf("vtcm_PCRInfo_Init : Start\n");
    return;
}


/*
 *  proc_vtcm_Seal
 */

int proc_vtcm_Seal(void *sub_proc, void *recv_msg)
{
    printf("proc_vtcm_Seal : Start\n");
    
    int ret = TCM_SUCCESS;
    TCM_SESSION_DATA *authSession = NULL;
    TCM_KEY *key = NULL;
    TCM_BOOL parentPCRStatus;
    BYTE *keyUsageAuth = NULL;
    TCM_SEALED_DATA  s2SealedData;
    TCM_SECRET Sealed_AuthData;
    TCM_STORED_DATA *s1StoredData;   // Encrypted, integrity-protected data object that is the
                                    // result of the TPM_Seal operation. Returned as SealedData
    TCM_PCR_INFO    tcm_pcr_info;       // deserialized pcrInfo v1
    BYTE CheckData[TCM_HASH_SIZE];
    BYTE CheckData_2[TCM_HASH_SIZE];

    //input process
    struct tcm_in_Seal *vtcm_input;
    
    ret = message_get_record(recv_msg, (void **)&vtcm_input, 0); // get structure 
    if(ret < 0) 
        return ret;
    else ret = 0;
    if(vtcm_input == NULL)
        return -EINVAL;
    
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);
    //output process
    void * template_out = memdb_get_template(DTYPE_VTCM_OUT_AUTH1, SUBTYPE_SEAL_OUT);//Get the entire command template
    if(template_out == NULL)
    {    
        printf("can't solve this command!\n");
    }    
    struct tcm_out_Seal * vtcm_output = malloc(struct_size(template_out));
    //Processing
    //Get AuthSession
    if(ret == TCM_SUCCESS)
    {
       ret = vtcm_AuthSessions_GetEntry(&authSession,
                                        tcm_state->tcm_stany_data.sessions,
                                        vtcm_input->authHandle);
    }
    //Verification authCode
    
    if(ret == TCM_SUCCESS)
    {
      ret = vtcm_Compute_AuthCode(vtcm_input, DTYPE_VTCM_IN_AUTH1,SUBTYPE_SEAL_IN, authSession, CheckData);
      if(ret == TCM_SUCCESS)
      {
        if(Memcmp(CheckData,vtcm_input->authCode,TCM_HASH_SIZE) != 0)
        {    
            ret = TCM_AUTHFAIL;
            printf("\nCompare AuthCode1 Error\n\n");
        }
      }
    }

    // Rely on the handle to get the key
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_KeyHandleEntries_GetKey(&key, 
                                           &parentPCRStatus, 
                                           tcm_state, 
                                           vtcm_input->keyHandle,
                                           FALSE,     // not r/o, using to encrypt
                                           FALSE,     // do not ignore PCRs
                                           FALSE);    // cannot use EK
    }
    //Create Sealed_AuthData by decrypting encAuth
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_AuthSessionData_Decrypt(Sealed_AuthData,
                                           authSession,
                                           vtcm_input->encAuth);
    }
    //Get authData
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_Key_GetUsageAuth(&keyUsageAuth, key);
    }
    /*
    //Filling TCM_STORED_DATA apart from encDataSize and encData
    if(ret == TCM_SUCCESS)
    {


    }*/

    //Filling TCM_SEALED_DATA
    if(ret == TCM_SUCCESS)
    {
    	vtcm_SealedData_Init(&s2SealedData);
        //  Set S2 -> tpmProof to TPM_PERMANENT_DATA -> tpmProof
        s2SealedData.payload = htonl(TCM_PT_SEAL);
        Memcpy(s2SealedData.authData, Sealed_AuthData, TCM_NONCE_SIZE);
        Memcpy(s2SealedData.tcmProof, tcm_state->tcm_permanent_data.tcmProof, TCM_NONCE_SIZE);
        s2SealedData.dataSize = vtcm_input->InDataSize;
        s2SealedData.data = (BYTE *)malloc(sizeof(BYTE) * s2SealedData.dataSize);
        Memcpy(s2SealedData.data, vtcm_input->InData, s2SealedData.dataSize);
    }
    //Filling TCM_STORED_DATA
    if(ret == TCM_SUCCESS)
    {
       s1StoredData = &(vtcm_output->sealedData);
       vtcm_StoredData_Init(s1StoredData);

       if(s1StoredData->sealInfoSize==0)
       {
//      	 vtcm_PCRInfo_Init(&tcm_pcr_info);
//         void * pcr_template=memdb_get_template(DTYPE_VTCM_PCR,SUBTYPE_TCM_PCR_INFO_LONG);
//         if(pcr_template==NULL)
//		return -EINVAL;
       }
       else
       {
	    s1StoredData->sealInfoSize=vtcm_input->pcrInfoSize;
	    s1StoredData->sealInfo=Talloc0(vtcm_input->pcrInfoSize);
	    if(s1StoredData->sealInfo==NULL)
		return -ENOMEM;
	    Memcpy(s1StoredData->sealInfo,vtcm_input->pcrInfo,vtcm_input->pcrInfoSize);
       }

       ret = vtcm_StoredData_GenerateDigest(s2SealedData.storedDigest.digest, s1StoredData);
       ret = vtcm_SealedData_GenerateEncData(&(s1StoredData->encData), &(s1StoredData->encDataSize), &s2SealedData, key);
    }
    //Compute authCode
    //Response
    printf("proc_vtcm_Seal : Response \n");

    vtcm_output->tag = 0xC500;
    vtcm_output->returnCode = ret;
    
    BYTE* response = (BYTE*)malloc(sizeof(BYTE) * 700);
    int responseSize = struct_2_blob(vtcm_output, response, template_out);
    vtcm_output->paramSize = responseSize;
    
    if(ret == TCM_SUCCESS)
    {    
        ret = vtcm_Compute_AuthCode(vtcm_output, 
                                    DTYPE_VTCM_OUT_AUTH1,
                                    SUBTYPE_SEAL_OUT, 
                                    authSession, 
                                    vtcm_output->authCode);
    }
    void *send_msg = message_create(DTYPE_VTCM_OUT_AUTH1 ,SUBTYPE_SEAL_OUT ,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n");
        return -EINVAL;      
    }
    message_add_record(send_msg, vtcm_output);

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret < 0)
    {
	    printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}

int vtcm_Check_AuthCode_UnSeal(int value_ordinal,
                               TCM_STORED_DATA *encAuth,
                               TCM_SESSION_DATA *authSession,
                               BYTE *authCode)
{
    printf(" vtcm_Check_AuthCode_UnSeal : Start\n");
    int ret = TCM_SUCCESS;
    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Store = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
    int temp = htonl(value_ordinal);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    void * template = memdb_get_template(DTYPE_VTCM_IN_KEY, SUBTYPE_TCM_BIN_KEY);  //Get the TCM_KEY template
    if(template == NULL)
    {    
        printf("can't get Key template!\n");
    }    
    int Len = struct_2_blob(encAuth, Str_Hash_Store, template);
    if(Len == 0)
    {
        printf("Error, struct_2_blob : TCM_STORED_DATA\n");
    }
    memcpy(Str_Hash_In + sizeof(int), Str_Hash_Store, Len);
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, sizeof(int) + Len);
    
    temp = htonl(authSession->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(authSession->sharedSecret, TCM_NONCE_SIZE, Str_Hash_Out,TCM_NONCE_SIZE + sizeof(int), checksum);
    //Compare authCode
    if(!strcmp(authCode ,checksum))
    {
        printf("Verification authCode Success\n");
    }
    else
    {
        printf("Verification authCode Fail\n");
        ret = -1;
    }
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(Str_Hash_Store);
    free(checksum);
    return ret;
}

int vtcm_Data_Decrypt(TCM_SEALED_DATA *a1decrypt,
                      BYTE *encData,
                      int encDataSize,
                      TCM_KEY *tcm_key)
{
    int dec_len=0;
    printf(" vtcm_Data_Decrypt : Start\n");
    int ret = TCM_SUCCESS;
    sm4_context ctx;
    TCM_STORE_SYMKEY *tcm_store_symkey = NULL;
    BYTE *SymKey = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE/2);
    BYTE *Str_sealed  = (BYTE *)malloc(sizeof(BYTE) * encDataSize);
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_Key_GetStoreSymkey(&tcm_store_symkey, tcm_key);
        if(ret == TCM_SUCCESS)
        {
//            ret = KDFwithSm3(SymKey, tcm_store_symkey->data, TCM_NONCE_SIZE/2, tcm_store_symkey->size);
//            if(ret != TCM_SUCCESS)
 //           {
 //               printf("Error, KDFwithSm3\n");
 //           }
            sm4_setkey_dec(&ctx, tcm_store_symkey->data);
            sm4_crypt_ecb(&ctx, 0, encDataSize, encData, Str_sealed);
	    ret=sm4_cbc_data_recover(encDataSize,Str_sealed,&dec_len,Buf);
		
        }
        void *template_sealed = memdb_get_template(DTYPE_VTCM_SEAL, SUBTYPE_TCM_SEALED_DATA);
        if(template_sealed == NULL)
                return -EINVAL;
        ret = blob_2_struct(Buf, a1decrypt, template_sealed);
        if(ret < 0)
             return ret; 
        else ret = 0;
    }
    return ret;
}


/*
 * proc_vtcm_UnSeal
 */

int proc_vtcm_UnSeal(void *sub_proc, void *recv_msg)
{
    printf("proc_vtcm_UnSeal : Start\n");
    int ret = TCM_SUCCESS;
    TCM_KEY *tcm_key = NULL;
    TCM_BOOL    parentPCRStatus; 
    TCM_SESSION_DATA *authSession = NULL;
    //TCM_SESSION_DATA *authSession_2 = NULL;
    TCM_SEALED_DATA a1decrypt;
    BYTE CheckData[TCM_HASH_SIZE];
    BYTE CheckData_2[TCM_HASH_SIZE];

    vtcm_SealedData_Init(&a1decrypt);
    //input process
    struct tcm_in_UnSeal *vtcm_input;
    
    ret = message_get_record(recv_msg, (void **)&vtcm_input, 0); // get structure 
    if(ret < 0) 
        return ret;
    else ret = 0;
    if(vtcm_input == NULL)
        return -EINVAL;
    
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);
    //output process
    void * template_out = memdb_get_template(DTYPE_VTCM_OUT_AUTH2, SUBTYPE_UNSEAL_OUT);//Get the entire command template
    if(template_out == NULL)
    {    
        printf("can't solve this command!\n");
    }    
    struct tcm_out_UnSeal * vtcm_output = malloc(struct_size(template_out));

    //Processing
    //Get AuthSession
    if(ret == TCM_SUCCESS)
    {
       ret = vtcm_AuthSessions_GetEntry(&authSession,
                                        tcm_state->tcm_stany_data.sessions,
                                        vtcm_input->UnAuthHandle);
    }
    //Verification authCode
    
    if(ret == TCM_SUCCESS)
    {
      ret = vtcm_Compute_AuthCode(vtcm_input, 
                                  DTYPE_VTCM_IN_AUTH2,
                                  SUBTYPE_UNSEAL_IN, 
                                  authSession, 
                                  CheckData);
    }
      if(ret == TCM_SUCCESS)
      {
        if(Memcmp(CheckData,vtcm_input->UnAuthCode,TCM_HASH_SIZE) != 0)
        {    
            ret = TCM_AUTHFAIL;
            printf("\nCompare AuthCode Error\n\n");
        }
      }
    if(ret == TCM_SUCCESS)
    {
      ret = vtcm_Compute_AuthCode(vtcm_input, 
                                  DTYPE_VTCM_IN_AUTH2,
                                  SUBTYPE_UNSEAL_IN, 
                                  authSession, 
                                  CheckData_2);
    }
      if(ret == TCM_SUCCESS)
      {
        if(Memcmp(CheckData_2,vtcm_input->authCode,TCM_HASH_SIZE) != 0)
        {    
            ret = TCM_AUTHFAIL;
            printf("\nCompare AuthCode Error\n\n");
        }
      }

    // Rely on the handle to get the key
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_KeyHandleEntries_GetKey(&tcm_key, 
                                           &parentPCRStatus, 
                                           tcm_state, 
                                           vtcm_input->keyHandle,
                                           FALSE,     // not r/o, using to encrypt
                                           FALSE,     // do not ignore PCRs
                                           FALSE);    // cannot use EK
    }
    //Decrypt data
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_Data_Decrypt(&a1decrypt,
                                vtcm_input->encAuth.encData,
                                vtcm_input->encAuth.encDataSize,
                                tcm_key);
    }
    //Add PrintData
    if(ret == TCM_SUCCESS)
    {
        vtcm_output->PrintDataSize = a1decrypt.dataSize;
        vtcm_output->PrintData = (BYTE *)malloc(sizeof(BYTE) * a1decrypt.dataSize);
        Memcpy(vtcm_output->PrintData, a1decrypt.data, vtcm_output->PrintDataSize);
    }
    
    //Response
    printf("proc_vtcm_UnSeal : Response \n");

    vtcm_output->tag = 0xC500;
    vtcm_output->returnCode = ret;
    BYTE* response = (BYTE*)malloc(sizeof(BYTE) * 700);
    int responseSize = struct_2_blob(vtcm_output, response, template_out);
    vtcm_output->paramSize = responseSize;
    
    if(ret == TCM_SUCCESS)
    {
      ret = vtcm_Compute_AuthCode(vtcm_output, 
                                  DTYPE_VTCM_OUT_AUTH2,
                                  SUBTYPE_UNSEAL_OUT, 
                                  authSession, 
                                  vtcm_output->UnauthCode);
    }
    if(ret == TCM_SUCCESS)
    {
      ret = vtcm_Compute_AuthCode(vtcm_output, 
                                  DTYPE_VTCM_OUT_AUTH2,
                                  SUBTYPE_UNSEAL_OUT, 
                                  authSession, 
                                  vtcm_output->authCode);
    }
    void *send_msg = message_create(DTYPE_VTCM_OUT_AUTH2 ,SUBTYPE_UNSEAL_OUT ,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n");
        return -EINVAL;      
    }
    message_add_record(send_msg, vtcm_output);
     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret < 0)
    {
	    printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}

int vtcm_AuthData_Check_OwnerReadInternalPub(int ordinal,
                                             int handle,
                                             TCM_SESSION_DATA *auth_session_data,
                                             BYTE *authCode)
{
    printf("vtcm_AuthData_Check_OwnerReadInternalPub: Start\n");
    int ret = TCM_SUCCESS;

    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
    int temp = htonl(ordinal);
    int temp2 = htonl(handle);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int),&temp2 , sizeof(int));

    int Str_Hash_Len = sizeof(int)*2;
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Str_Hash_Len);
    
    //auth_session_data->SERIAL = 0;
    temp = htonl(auth_session_data->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(auth_session_data->sharedSecret, TCM_NONCE_SIZE, 
                   Str_Hash_Out,TCM_NONCE_SIZE + sizeof(int), authCode);
    //Compare authCode
//    if(!strcmp(authCode ,checksum))
//    {
//        printf("Verification authCode Success\n");
//    }
//    else
//    {
//        printf("Verification authCode Fail\n");
 //       ret = -1;
//    }
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(checksum);
    return ret;

}

int vtcm_AuthData_Check_OwnerReadInternalPubout(int returnCode, 
                                                int ordinal, 
                                                TCM_PUBKEY *pubkey,
                                                TCM_SESSION_DATA *auth_session_data,
                                                BYTE *authCode)
{
    printf("vtcm_AuthData_Check_OwnerReadInternalPubout: Start\n");
    int ret = TCM_SUCCESS;

    BYTE *Str_Hash_In = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Key = (BYTE *)malloc(sizeof(BYTE) * 500);
    BYTE *Str_Hash_Out = (BYTE *)malloc(sizeof(BYTE) * 100);
    BYTE *checksum = (BYTE *)malloc(sizeof(BYTE) * TCM_NONCE_SIZE);
    int temp = htonl(returnCode);
    int temp2 = htonl(ordinal);
    memcpy(Str_Hash_In, &temp, sizeof(int));
    memcpy(Str_Hash_In + sizeof(int), &temp2, sizeof(int));

    void * template_key = memdb_get_template(DTYPE_VTCM_IN_KEY, SUBTYPE_TCM_BIN_PUBKEY);  //Get the TCM_KEY template
    if(template_key == NULL)
    {    
        printf("can't get Key template!\n");
    }    
    int Str_length_key = struct_2_blob(pubkey, Str_Hash_Key, template_key);
    if(Str_length_key == 0)
    {
        printf("Error, struct_2_blob : TCM_KEY\n");
    }
    int Str_Hash_Len = sizeof(int)*2;
    memcpy(Str_Hash_In + Str_Hash_Len, Str_Hash_Key, Str_length_key);
    Str_Hash_Len += Str_length_key;
    vtcm_SM3(Str_Hash_Out, Str_Hash_In, Str_Hash_Len);
    //auth_session_data->SERIAL = 0;
    temp = htonl(auth_session_data->SERIAL);
    memcpy(Str_Hash_Out + TCM_NONCE_SIZE, &temp, sizeof(int));
    vtcm_HMAC_SM3(auth_session_data->sharedSecret, TCM_NONCE_SIZE, 
                  Str_Hash_Out,TCM_NONCE_SIZE + sizeof(int), authCode);
    //Compare authCode
    free(Str_Hash_In);
    free(Str_Hash_Out);
    free(checksum);
    return ret;

}

int proc_vtcm_OwnerReadInternalPub(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_OwnerReadInternalPub : Start\n") ;
    int ret = 0 ;
   
    TCM_SESSION_DATA *auth_session_data = NULL;
    TCM_KEY *key = NULL;
    TCM_BOOL parentPCRStatus;
    struct tcm_in_OwnerReadInternalPub *tcm_input;

    ret = message_get_record(recv_msg, (void **)&tcm_input, 0) ; // get structure 
    if(ret < 0)
        return ret;
    if(tcm_input == NULL)
        return -EINVAL;

    key = Talloc0(sizeof(*key));
    if(key == NULL) {
        return -EINVAL;
    }
    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_OWNERREADINTERNALPUB_OUT);//Get the entire command template
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_OwnerReadInternalPub * tcm_output = malloc(struct_size(command_template));

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    //Processing

    if(ret == TCM_SUCCESS) {
        vtcm_AuthSessions_GetEntry(&auth_session_data,
                                   tcm_state->tcm_stany_data.sessions,
                                   tcm_input->authHandle);
        printf("%08x\n",auth_session_data->SERIAL);
    }
    if(ret == TCM_SUCCESS) {
        ret = vtcm_AuthData_Check_OwnerReadInternalPub(tcm_input->ordinal,
                                                       tcm_input->keyHandle,
                                                       auth_session_data,
                                                       tcm_input->ownerAuth);
    }

    if(ret == TCM_SUCCESS) {
        ret = vtcm_KeyHandleEntries_GetKey(&key,
                                           &parentPCRStatus,
                                           tcm_state,
                                           tcm_input->keyHandle,
                                           FALSE,
                                           FALSE,
                                           TRUE);
    }

    tcm_output->publicPortion.pubKey.keyLength = key->pubKey.keyLength;
    memcpy(tcm_output->publicPortion.pubKey.key, key->pubKey.key, key->pubKey.keyLength);

    if(ret == TCM_SUCCESS) {
        ret = vtcm_AuthData_Check_OwnerReadInternalPubout(tcm_output->returnCode,
                                                          tcm_input->ordinal,
                                                          &(tcm_output->publicPortion),
                                                          auth_session_data,
                                                          tcm_output->resAuth);
    }
    //Response 

    tcm_output->tag = 0xC500;
    tcm_output->paramSize = 42 + key->pubKey.keyLength;
    tcm_output->publicPortion.pubKey.key = (BYTE *)malloc(sizeof(BYTE) * 64);

    tcm_output->returnCode = 0;

    void *send_msg = message_create(DTYPE_VTCM_OUT,SUBTYPE_OWNERREADINTERNALPUB_OUT,recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg ,tcm_output);

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc ,send_msg);

    return ret;
}

int proc_vtcm_ChangeAuth(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_ChangeAuth: Start\n") ;
    int ret = TCM_SUCCESS;
   
    TCM_BOOL parentPCRStatus;
    TCM_KEY *parentKey = NULL;
    TCM_SESSION_DATA *auth_session;
    struct tcm_in_ChangeAuth *tcm_input;

    ret = message_get_record(recv_msg, (void **)&tcm_input, 0) ; // get structure 
    if(ret < 0)
        return ret;
    if(tcm_input == NULL)
        return -EINVAL;

    //output process
    void * command_template = memdb_get_template(DTYPE_VTCM_OUT_AUTH2,SUBTYPE_CHANGEAUTH_OUT);//Get the entire command template
    if(command_template == NULL)
    {
        printf("can't solve this command!\n");
    }
    struct tcm_out_ChangeAuth * tcm_output = malloc(struct_size(command_template));

    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    //Processing

    if(ret == TCM_SUCCESS) {
        if((tcm_input->entityType != TCM_ET_DATA) &&
           (tcm_input->entityType != TCM_ET_KEY)) {
            printf("vtcm_ChangeAuth: Error, bad entityType %04x\n", tcm_input->entityType);
            ret = TCM_WRONG_ENTITYTYPE;
        }
    }
    if(ret == TCM_SUCCESS) {
        ret = vtcm_KeyHandleEntries_GetKey(&parentKey,
                                           &parentPCRStatus,
                                           tcm_state,
                                           tcm_input->parentHandle,
                                           FALSE,
                                           FALSE,
                                           FALSE);
    }
    if(ret == TCM_SUCCESS) {
        ret = vtcm_AuthSessions_GetEntry(&auth_session,
                                         tcm_state->tcm_stany_data.sessions,
                                         tcm_input->entityAuthHandle);
    }
    //Response 

    tcm_output->tag = 0xC600;
    tcm_output->paramSize = 78 + tcm_output->outDataSize;
    tcm_output->returnCode = ret;

    void *send_msg = message_create(DTYPE_VTCM_OUT_AUTH2,SUBTYPE_CHANGEAUTH_OUT,recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg ,tcm_output);

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret<0)
    {
	printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc ,send_msg);

    return ret;
}

/*
int proc_vtcm_WrapKey(void *sub_proc, void* recv_msg)
{
    printf("proc_vtcm_WrapKey : Start\n");

    int ret = TCM_SUCCESS;
    TCM_SESSION_DATA *auth_session_data = NULL;

    //input process
    struct tcm_in_WrapKey *vtcm_input;
    
    ret = message_get_record(recv_msg, (void **)&vtcm_input, 0); // get structure 
    if(ret < 0) 
        return ret;
    else ret = 0;
    if(vtcm_input == NULL)
        return -EINVAL;
    
    tcm_state_t* tcm_state = ex_module_getpointer(sub_proc);

    //output process
    void * template_out = memdb_get_template(DTYPE_VTCM_OUT, SUBTYPE_WRAPKEY_OUT);//Get the entire command template
    if(template_out == NULL)
    {    
        printf("can't solve this command!\n");
    }    
    struct tcm_out_WrapKey * vtcm_output = malloc(struct_size(template_out));
    
    //Processing
    //Get AuthSession
    if(ret == TCM_SUCCESS)
    {
        vtcm_AuthSessions_GetEntry(&auth_session_data,
                                   tcm_state->tcm_stclear_data.authSessions,
                                   vtcm_input->authHandle);
        printf("%08x\n", auth_session_data->SERIAL);
    }
    //Verification authCode
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_Check_AuthCode_WrapKey(vtcm_input->ordinal,
                                          vtcm_input->dataUsageAuth,
                                          vtcm_input->dataMigrationAuth,
                                          &(vtcm_input->keyInfo),
                                          auth_session_data,
                                          vtcm_input->pubAuth);
    }


    //Compute DecryptedAuthVerfication
    if(ret == TCM_SUCCESS)
    {
        ret = vtcm_Compute_AuthCode_WrapKey(ret,
                                            vtcm_input->ordinal,
                                            &(vtcm_output->wrappedKey),
                                            auth_session_data,
                                            vtcm_output->resAuth
                                            );
    }

    //Response

    printf("proc_vtcm_WrapKey : Response \n");

    vtcm_output->tag = 0xC500;
    vtcm_output->returnCode = ret;

    
    int responseSize = 0;
    BYTE* response = (BYTE*)malloc(sizeof(BYTE) * 700);
    responseSize = struct_2_blob(vtcm_output, response, template_out);

    vtcm_output->paramSize = responseSize;
    void *send_msg = message_create(DTYPE_VTCM_OUT ,SUBTYPE_WRAPKEY_OUT ,recv_msg);
    if(send_msg == NULL)
    {
        printf("send_msg == NULL\n");
        return -EINVAL;      
    }
    message_add_record(send_msg, vtcm_output);

     // add vtcm's expand info	
    ret=vtcm_addcmdexpand(send_msg,recv_msg);
    if(ret < 0)
    {
	    printf("fail to add vtcm copy info!\n");
    }	
    ret = ex_module_sendmsg(sub_proc, send_msg);

    return ret;
}
*/
