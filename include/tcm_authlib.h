#ifndef TCM_AUTHLIB_H
#define TCM_AUTHLIB_H

void print_bin_data(BYTE * data,int len,int width);
int vtcm_setscene(void * sub_proc,void * recv_msg);
int vtcm_addcmdexpand(void * send_msg,void * recv_msg);
int RAND_bytes(unsigned char *buffer, size_t len);
/*
int vtcm_bn2binMalloc(unsigned char* bin, unsigned int* bytes,
    unsigned char* bn, uint32_t padBytes);
*/
void vtcm_KeyParms_Init(TCM_KEY_PARMS* tcm_key_parms);
void vtcm_StorePubKey_Init(TCM_STORE_PUBKEY* tcm_pubKey);
void vtcm_StoreAsymKey_Init(TCM_STORE_ASYMKEY* tcm_store_asymkey);
void vtcm_Key_Init(TCM_KEY* tcm_key);
int vtcm_KeyParms_Copy(TCM_KEY_PARMS* tcm_key_parms_dest,
    TCM_KEY_PARMS* tcm_key_parms);
int vtcm_Key_Set(TCM_KEY* tcm_key, TCM_KEY_USAGE keyUsage,
    TCM_KEY_FLAGS keyFlags, TCM_AUTH_DATA_USAGE authDataUsage,
    TCM_KEY_PARMS* tcm_key_parms, uint32_t keyLength,
    BYTE* pubKey);
void vtcm_Fill_PubKey(TCM_PUBKEY* pubEndorsementKey, TCM_KEY_PARMS* keyInfo,
    TCM_STORE_PUBKEY* pre_pubKey);

int vtcm_Key_GetSM2KeyParms(TCM_SM2_ASYMKEY_PARAMETERS** tcm_sm2_asymkey_parameters,
    TCM_KEY_PARMS* tcm_key_parms);

int vtcm_Key_GenerateSM2(TCM_KEY* tcm_key, tcm_state_t* tcm_state,
    TCM_KEY* parent_key,
    TCM_PCRVALUE* tcm_pcrs,
    TCM_KEY_USAGE keyUsage,
    TCM_KEY_FLAGS keyFlags,
    TCM_AUTH_DATA_USAGE authDataUsage,
    TCM_KEY_PARMS* tcm_key_parms,
    TCM_PCR_INFO* tcm_pcr_info,
    TCM_PCR_INFO_LONG* tcm_pcr_info_long);
int vtcm_Random(BYTE* buffer, size_t bytes);
int vtcm_SHA1(void* input, unsigned int len, unsigned char* output);
int vtcm_SM3(BYTE* checksum, unsigned char* buffer, int size);
int vtcm_HMAC_SM3(BYTE *key, int keylen, BYTE *buffer, int size, BYTE *output);
int vtcm_Create_Checksum(BYTE* checksum, TCM_PUBKEY* pubEndorsementKey,
    BYTE* antiReplay);
int vtcm_PubKey_Copy(TCM_SIZED_BUFFER* pubkey_des, TCM_STORE_PUBKEY* pubkey_src);
int vtcm_Nonce_Generate(TCM_NONCE tcm_nonce);
int vtcm_Nonce_Compare(TCM_NONCE expect, const TCM_NONCE actual);

/* TCM_AuthSessions_IsSpace() returns 'isSpace' TRUE if an entry is available,
   FALSE if not.

   If TRUE, 'index' holds the first free position.
*/
void vtcm_AuthSessions_IsSpace(TCM_BOOL* isSpace, uint32_t* index,
    TCM_SESSION_DATA* authSessions);
/* TCM_AuthSessions_GetEntry() searches all entries for the entry matching the
   handle, and
   returns the TCM_SESSION_DATA entry associated with the handle.

   Returns
        0 for success
        TCM_INVALID_AUTHHANDLE if the handle is not found
*/
int vtcm_AuthSessions_GetEntry(
    TCM_SESSION_DATA** tcm_session_data, /* session for authHandle */
    TCM_SESSION_DATA* authSessions, /* points to first session */
    TCM_AUTHHANDLE authHandle) ;/* input */

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
    TCM_BOOL keepHandle, TCM_BOOL isKeyHandle);

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
    TCM_SESSION_DATA* authSessions);
void vtcm_Generate_Random(int *dest, int num);
/* TPM_NVIndexEntries_GetEntry() gets the TPM_NV_DATA_SENSITIVE entry corresponding to nvIndex.
 *  Returns TPM_BADINDEX on non-existent nvIndex
 **/

int vtcm_NVIndexEntries_GetEntry(TCM_NV_DATA_SENSITIVE **tcm_nv_data_sensitive,
                                 TCM_NV_INDEX_ENTRIES *tcm_nv_index_entries,
                                 TCM_NV_INDEX nvIndex);
/* vtcm_Key_GetStoreAsymkey() gets the TPM_STORE_ASYMKEY from a TPM_KEY cache.
 *  */

int vtcm_Key_GetStoreAsymkey(TCM_STORE_ASYMKEY **tcm_store_asymkey,
                             TCM_KEY *tcm_key);

int vtcm_Key_GetStoreSymkey(TCM_STORE_SYMKEY **tcm_store_symkey,
                             TCM_KEY *tcm_key);

/* vtcm_Key_GetMigrateAsymkey() gets the TPM_MIGRATE_ASYMKEY from a TPM_KEY cache.
 *  */

int vtcm_Key_GetMigrateAsymkey(TCM_MIGRATE_ASYMKEY **tcm_migrate_asymkey,
                               TCM_KEY *tcm_key);
/* vtcm_Key_GetUsageAuth() gets the usageAuth from the TPM_STORE_ASYMKEY or TPM_MIGRATE_ASYMKEY
 * contained in a TPM_KEY
 */

int vtcm_Key_GetUsageAuth(BYTE **usageAuth,
                          TCM_KEY *tcm_key);
/* vtcm_Counters_IsValidId() verifies that countID is in range and a created counter
 *  */

int vtcm_Counters_IsValidId(TCM_COUNTER_VALUE *monotonicCounters,
                            TCM_COUNT_ID countID);
/* vtcm_Counters_GetCounterValue() gets the TPM_COUNTER_VALUE associated with the countID.
 *
 */

int vtcm_Counters_GetCounterValue(TCM_COUNTER_VALUE **tcm_counter_value,
                                  TCM_COUNTER_VALUE *monotonicCounters,
                                  TCM_COUNT_ID countID);
/* vtcm_AuthSessionData_CheckEncScheme() checks that the encryption scheme specified by
 * TCM_ENTITY_TYPE is supported by the TPM (by TPM_AuthSessionData_Decrypt)
 */

int vtcm_AuthSessionData_CheckEncScheme(TCM_ADIP_ENC_SCHEME adipEncScheme,
                                        TCM_BOOL FIPS);
int vtcm_AuthSessionData_Decrypt(BYTE *retData,
                                 TCM_SESSION_DATA *authSession,
                                 BYTE *encData);
int vtcm_AuthSessionData_Encrypt(BYTE *retData,
                                 TCM_SESSION_DATA *authSession,
                                 BYTE *plainData);
int vtcm_Key_GetpubDigest(TCM_DIGEST **entityDigest, TCM_KEY *tcm_key);
int vtcm_Init_PcrSelection(TCM_PCR_SELECTION * pcr_select);
int vtcm_Init_PcrComposite(TCM_PCR_COMPOSITE * pcr_comp);
int vtcm_Init_PcrInfo(TCM_PCR_INFO_LONG * pcr_info);
int vtcm_Set_PcrInfo(TCM_PCR_INFO_LONG * pcr_info, TCM_PCR_COMPOSITE * pcr_comp);
int vtcm_Set_PcrSelection(TCM_PCR_SELECTION * pcr_select,int index);
int vtcm_Clear_PcrSelection(TCM_PCR_SELECTION * pcr_select,int index);
int vtcm_Fill_PCRComposite(TCM_PCR_COMPOSITE * pcr_comp,tcm_state_t * curr_tcm);
int vtcm_Add_PCRComposite(TCM_PCR_COMPOSITE * pcr_comp,int index,BYTE * value);
int vtcm_Dup_PCRComposite(TCM_PCR_COMPOSITE * pcr_comp,int index,BYTE * value);
int vtcm_Comp_PcrsDigest(TCM_PCR_COMPOSITE * pcrs, BYTE * digest);


int vtcm_Compute_AuthCode(void * vtcm_data,
	int type,int subtype,
	TCM_SESSION_DATA * authsession,
	BYTE * AuthCode);
int vtcm_Compute_AuthCode2(void * vtcm_data,
	int type,int subtype,
	TCM_SESSION_DATA * authsession,
	BYTE * AuthCode);

void sm4_cbc_data_prepare(int input_len,BYTE * input_data,int * output_len,BYTE * output_data);
int sm4_cbc_data_recover(int input_len,BYTE * input_data,int * output_len,BYTE * output_data);

#endif
