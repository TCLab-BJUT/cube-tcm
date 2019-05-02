/********************************************************************************/
/*										*/
/*			     	TCM Functions					*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpmfunc.h 4645 2011-10-18 21:12:01Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#ifndef TCMFUNC_H
#define TCMFUNC_H

/* section 3: Admin startup and state */
UINT32 _TSMD_Init(void);
UINT32 TCM_LibInit(void);

UINT32 TCM_CreateEndorsementKeyPair(BYTE * pubkeybuf, 
		UINT32 * pubkeybuflen);

UINT32 TCM_Extend(UINT32 pcrIndex, BYTE * event,BYTE * pcrvalue);

UINT32 TCM_PcrRead(UINT32 pcrindex, BYTE * pcrvalue);

UINT32 TCM_PcrReset(UINT32 pcrindex, BYTE * pcrvalue);

UINT32 TCM_ReadPubek(TCM_PUBKEY *key);

UINT32 TCM_APCreate(UINT32 entityType, UINT32 entityValue, char * pwd, UINT32 * authHandle);

UINT32 TCM_APTerminate(UINT32 authHandle);

UINT32 TCM_EvictKey(UINT32 keyHandle);

UINT32 TCM_CreateWrapKey(TCM_KEY * keydata,UINT32 parentHandle,UINT32 authHandle,UINT32 keyusage,UINT32 keyflags,char *pwdk);

UINT32 TCM_LoadKey(UINT32 authHandle,char * keyfile,UINT32 *KeyHandle);

UINT32 TCM_SM2Decrypt(UINT32 keyHandle,UINT32 DecryptAuthHandle,BYTE * out, int * out_len,BYTE * in, int in_len);

int TCM_SM3Start();

int TCM_SM3Update(BYTE * data, int data_len);

UINT32 TCM_SM2LoadPubkey(char *keyfile,BYTE * key, int *keylen );

UINT32 TCM_SM2Encrypt(BYTE * pubkey, int pubkey_len, BYTE * out, int * out_len,BYTE * in ,int in_len);

int TCM_SM3Complete(BYTE * in, int in_len,BYTE * out);

UINT32 TCM_SM4Encrypt(UINT32 keyHandle,UINT32 EncryptAuthHandle,BYTE * out, int * out_len,BYTE * in, int in_len);

UINT32 TCM_SM4Decrypt(UINT32 keyHandle,UINT32 DecryptAuthHandle,BYTE * out, int * out_len,BYTE * in, int in_len);

UINT32 TCM_SM1Encrypt(UINT32 keyHandle,UINT32 EncryptAuthHandle,BYTE * out, int * out_len,BYTE * in, int in_len);

UINT32 TCM_SM1Decrypt(UINT32 keyHandle,UINT32 DecryptAuthHandle,BYTE * out, int * out_len,BYTE * in, int in_len);

UINT32 TCM_TakeOwnership(unsigned char *ownpass, unsigned char *smkpass,UINT32 authhandle);

UINT32 TCM_MakeIdentity(UINT32 ownerhandle, UINT32 smkhandle,
	int userinfolen,BYTE * userinfo,char * pwdk,
	TCM_KEY * pik, BYTE ** req, int * reqlen);

UINT32 TCM_ActivateIdentity(UINT32 pikhandle,UINT32 pikauthhandle,UINT32 ownerhandle,
	int encdatasize,BYTE * encdata,TCM_SYMMETRIC_KEY * symm_key,
	char * pwdo,char * pwdk);	

int TCM_ExCreateSm2Key(BYTE ** privkey,int * privkey_len,BYTE ** pubkey);
int TCM_ExCreateCAKey  ( );
int TCM_ExSaveCAPriKey (char * prikeyfile);
int TCM_ExLoadCAPriKey (char * prikeyfile);
int TCM_ExSaveCAPubKey (char * pubkeyfile);
int TCM_ExLoadCAPubKey (char * pubkeyfile);

int TCM_ExCAPikReqVerify(TCM_PUBKEY * pik, BYTE * userinfo,int userinfolen,
	 BYTE * reqdata, int reqdatalen);
int TCM_ExCAPikCertSign(TCM_PUBKEY * pubek, TCM_PUBKEY * pik, BYTE * certdata,int certdatalen,
	 BYTE ** cert,int * certlen,BYTE ** symmkeyblob, int * symmkeybloblen);

int TCM_ExGetPubkeyFromTcmkey(TCM_PUBKEY * pubkey,TCM_KEY * tcmkey);
int TCM_ExSaveTcmKey(TCM_KEY * tcmkey,char * keyfile);
int TCM_ExSaveTcmPubKey(TCM_PUBKEY * pubkey,char * keyfile);
int TCM_ExLoadTcmKey(TCM_KEY * tcmkey, char * keyfile);
int TCM_ExLoadTcmPubKey(TCM_PUBKEY * pubkey, char * keyfile);


/*
UINT32 TCM_Init(void); 
UINT32 TCM_Startup(UINT16 type);
UINT32 TCM_SaveState(void);
*/

/* section 4: Testing */
/*
UINT32 TCM_SelfTestFull(void);
UINT32 TCM_ContinueSelfTest(void);
UINT32 TCM_GetTestResult(char * buffer, UINT32 * bufferlen);
UINT32 TCM_CertifySelfTest(UINT32 keyhandle,
                             unsigned char *usageAuth,  // HMAC key
                             unsigned char *antiReplay,
                             struct tpm_buffer *signature);
*/
/* section 5: Admin Opt-in */
/*
UINT32 TCM_SetOwnerInstall(TCM_BOOL state);
UINT32 TCM_OwnerSetDisable(unsigned char *ownerauth,  // HMAC key
                             TCM_BOOL state);
UINT32 TCM_PhysicalEnable(void);
UINT32 TCM_PhysicalDisable(void);
UINT32 TCM_PhysicalSetDeactivated(TCM_BOOL state);
UINT32 TCM_SetTempDeactivated(unsigned char *operatorauth  // HMAC key
                            );
UINT32 TCM_SetOperatorAuth(unsigned char * operatorAuth);
*/
/* Basic TCM_ commands */
/*
UINT32 TCM_CreateRevocableEK(TCM_BOOL genreset,
                               unsigned char * inputekreset,
                               pubkeydata * k);
UINT32 TCM_RevokeTrust(unsigned char *ekreset);
*/
/*
UINT32 TCM_DisablePubekRead(unsigned char *ownauth);
UINT32 TCM_OwnerReadPubek(unsigned char *ownauth,pubkeydata *k);
UINT32 TCM_OwnerReadInternalPub(UINT32 keyhandle,
                                  unsigned char * ownerauth,
                                  pubkeydata *k);

*/
/*
UINT32 TCM_OwnerClear(unsigned char *ownpass);
*/
/*
UINT32 TCM_ForceClear(void);
UINT32 TCM_DisableOwnerClear(unsigned char *ownerauth);
UINT32 TCM_DisableForceClear(void);
UINT32 TSC_PhysicalPresence(UINT16 ppresence);
UINT32 TCM_ResetEstablishmentBit(void);
*/
/*
UINT32 TCM_CreateWrapKey(UINT32 keyhandle,
                  unsigned char *keyauth, unsigned char *newauth,
                  unsigned char *migauth,
                  keydata *keyparms,keydata *key,
                  unsigned char *keyblob, unsigned int *bloblen);
UINT32 TCM_EvictKey(UINT32 keyhandle);
*/
/* section 9: Administrative functions: Management */
/*
UINT32 TCM_SetRedirection(UINT32 keyhandle,
                            UINT32 redirCmd,
                            unsigned char * inputData, UINT32 inputDataSize,
                            unsigned char * ownerAuth,
                            unsigned char * usageAuth);
UINT32 TCM_ResetLockValue(unsigned char * ownerAuth);
*/

/* section 15: Identity creation and activation */
/*
UINT32 TCM_MakeIdentity(unsigned char * identityauth,
                          unsigned char * identitylabel,
                          keydata * keyparms,
                          keydata * key,
			  unsigned char *keyblob,
			  unsigned int  *keybloblen,
			  unsigned char * srkAuth,
                          unsigned char * ownerAuth,
                          unsigned char * idbinding, UINT32 * idbsize
                          );
UINT32 TCM_ActivateIdentity(UINT32 keyhandle,
                              unsigned char * blob, UINT32 blobsize,
                              unsigned char * usageAuth,
                              unsigned char * ownerAuth,
                              struct tpm_buffer *symkey
                          );


*/
/* Section 16: Integrity collection and reporting */
/*
UINT32 TCM_Extend(UINT32 pcrIndex,
                    BYTE * event,
                    BYTE * pcrvalue);
UINT32 TCM_PcrRead(UINT32 pcrindex, BYTE * pcrvalue);
*/
/*
UINT32 TCM_Quote(UINT32 keyhandle,
                   unsigned char *keyauth,
                   unsigned char *externalData,
                   TCM_PCR_SELECTION *tps,
                   TCM_PCR_COMPOSITE *tpc,
                   struct tpm_buffer *signature);
*/
//UINT32 TCM_PCRReset(TCM_PCR_SELECTION * selection);

/* Section 17: Authorization Changing */
/*
UINT32 TCM_ChangeKeyAuth(UINT32 keyhandle,
                           unsigned char *parauth,
                           unsigned char *keyauth,
                           unsigned char *newauth,
                           keydata *key);
UINT32 TCM_ChangeAuth(UINT32 keyhandle,
                        unsigned char *parauth,
                        unsigned char *keyauth,
                        unsigned char *newauth,
                        unsigned short etype,
                        unsigned char *encdata, UINT32 encdatalen);
UINT32 TCM_ChangeSRKAuth(unsigned char *ownauth,
                           unsigned char *newauth);
UINT32 TCM_ChangeOwnAuth(unsigned char *ownauth,
                           unsigned char *newauth);
*/

/* Section 10: Storage Functions */
/*
UINT32 TCM_Seal(UINT32 keyhandle,
                  unsigned char *pcrinfo, UINT32 pcrinfosize,
                  unsigned char *keyauth,
                  unsigned char *dataauth,
                  unsigned char *data, UINT32 datalen,
                  unsigned char *blob, UINT32 *bloblen);
UINT32 TCM_Unseal(UINT32 keyhandle,
                    unsigned char *keyauth,
                    unsigned char *dataauth,
                    unsigned char *blob, UINT32 bloblen,
                    unsigned char *rawdata, UINT32 *datalen);
UINT32 TCM_UnBind(UINT32 keyhandle,
                    unsigned char *keyauth,
                    unsigned char *data, UINT32 datalen,
                    unsigned char *blob, UINT32 *bloblen);
UINT32 TSS_Bind(RSA *key,
                  const struct tpm_buffer *data,
                  struct tpm_buffer *blob);
UINT32 TSS_BindPKCSv15(RSA *key,
                         const struct tpm_buffer *data,
                         struct tpm_buffer *blob);
*/
/*
UINT32 TCM_LoadKey(UINT32 keyhandle, unsigned char *keyauth,
                     keydata *keyparms,UINT32 *newhandle);
UINT32 TCM_GetPubKey(UINT32 keyhandle,
                       unsigned char *keyauth,
                       pubkeydata *pk);
*/
/* section 7: capability commands */
/*
UINT32 TCM_GetCapability(UINT32 caparea, 
                           struct tpm_buffer *scap,
                           struct tpm_buffer *response);
UINT32 TCM_GetCapability_NoTransport(UINT32 caparea,
                                       struct tpm_buffer *scap,
                                       struct tpm_buffer *response);
UINT32 TCM_SetCapability(UINT32 caparea, 
                           unsigned char *subcap, UINT32 subcaplen, 
                           struct tpm_buffer *setValue,
                           unsigned char * operatorauth);
UINT32 TCM_GetCapabilitySigned(UINT32 keyhandle,
                                 unsigned char * keypass,
                                 unsigned char * antiReplay,
                                 UINT32 caparea, 
                                 struct tpm_buffer *scap,
                                 struct tpm_buffer *resp,
                                 unsigned char *sig , UINT32 *siglen);


UINT32 TCM_GetCapabilityOwner(unsigned char *ownpass,
                                UINT32 *volflags, UINT32 *nvolflags);
*/

/* Section 11: Migration */
/*
UINT32 TCM_AuthorizeMigrationKey(unsigned char *ownpass,
                                   int migtype,
                                   struct tpm_buffer *keyblob,
                                   struct tpm_buffer *migblob);
UINT32 TCM_CreateMigrationBlob(unsigned int keyhandle,
                                 unsigned char *keyauth,
                                 unsigned char *migauth,
                                 int migtype,
                                 unsigned char *migblob,
                                 UINT32   migblen,
                                 unsigned char *keyblob,
                                 UINT32   keyblen,
                                 unsigned char *rndblob,
                                 UINT32  *rndblen,
                                 unsigned char *outblob,
                                 UINT32  *outblen);
UINT32 TCM_ConvertMigrationBlob(unsigned int keyhandle,
                          unsigned char *keyauth,
                          unsigned char *rndblob,
                          UINT32   rndblen,
                          unsigned char *keyblob,
                          UINT32   keyblen,
                          unsigned char *encblob,
                          UINT32  *encblen);

UINT32 TCM_MigrateKey(UINT32 keyhandle,
                        unsigned char * keyUsageAuth,
                        unsigned char * pubKeyBlob, UINT32 pubKeySize,
                        unsigned char * inData, UINT32 inDataSize,
                        unsigned char * outData, UINT32 * outDataSize);

UINT32 TCM_CMK_SetRestrictions(UINT32 restriction,
                                 unsigned char * ownerAuth);

UINT32 TCM_CMK_ApproveMA(unsigned char * migAuthDigest,
                           unsigned char * ownerAuth,
                           unsigned char * hmac);

UINT32 TCM_CMK_CreateKey(UINT32 parenthandle,
                           unsigned char * keyUsageAuth,
                           unsigned char * dataUsageAuth,
                           keydata * keyRequest,
                           unsigned char * migAuthApproval,
                           unsigned char * migAuthDigest,
                           keydata * key,
                           unsigned char * blob, UINT32 * bloblen);

UINT32 TCM_CMK_CreateTicket(keydata * key,
                              unsigned char * signedData,
                              unsigned char * signatureValue, UINT32 signatureValueSize,
                              unsigned char * ownerAuth,
                              unsigned char * ticketBuf);

UINT32 TCM_CMK_CreateBlob(UINT32 parenthandle,
                            unsigned char * parkeyUsageAuth,
                            UINT16 migScheme,
                            const struct tpm_buffer *migblob,
                            unsigned char * sourceKeyDigest,
                            TCM_MSA_COMPOSITE * msaList,
                            TCM_CMK_AUTH * resTicket,
                            unsigned char * sigTicket, UINT32 sigTicketSize,
                            unsigned char * encData, UINT32 encDataSize,
                            unsigned char * random, UINT32 * randomSize,
                            unsigned char * outData, UINT32 * outDataSize);

UINT32 TCM_CMK_ConvertMigration(UINT32 parenthandle,
                                  unsigned char * keyUsageAuth,
                                  TCM_CMK_AUTH * resTicket,
                                  unsigned char * sigTicket,
                                  keydata * key,
                                  TCM_MSA_COMPOSITE * msaList,
                                  unsigned char * random, UINT32 randomSize,
                                  unsigned char * outData, UINT32 * outDataSize);

UINT32 TCM_Reset(void);
*/

/* Section 20: NV storage related functions */
/*
UINT32 TCM_NV_DefineSpace(unsigned char *ownauth,  // HMAC key
                            unsigned char *pubInfo, UINT32 pubInfoSize,
                            unsigned char *keyauth   // used to create  encAuth
                            );
UINT32 TCM_NV_DefineSpace2(unsigned char *ownauth,  // HMAC key
                             UINT32 index,
                             UINT32 size,
                             UINT32 permissions,
                             unsigned char *areaauth,
			     TCM_PCR_INFO_SHORT *pcrInfoRead,
			     TCM_PCR_INFO_SHORT *pcrInfoWrite);
UINT32 TCM_NV_WriteValue(UINT32 nvIndex,
                           UINT32 offset,
                           unsigned char *data, UINT32 datalen,
                           unsigned char * ownauth) ;
UINT32 TCM_NV_WriteValueAuth(UINT32 nvIndex,
                               UINT32 offset,
                               unsigned char *data, UINT32 datalen,
                               unsigned char * areaauth) ;
UINT32 TCM_NV_ReadValue(UINT32 nvIndex,
                          UINT32 offset,
                          UINT32 datasize,
                          unsigned char * buffer, UINT32 * buffersize,
                          unsigned char * ownauth) ;
UINT32 TCM_NV_ReadValueAuth(UINT32 nvIndex,
                              UINT32 offset,
                              UINT32 datasize,
                              unsigned char * buffer, UINT32 * buffersize,
                              unsigned char * areaauth) ;

*/
/* Section 25: Counter related functions */
/*
UINT32 TCM_CreateCounter(UINT32 keyhandle,
                           unsigned char * ownauth,     // HMAC key
                           UINT32 label,              // label for counter
                           unsigned char * counterauth, //  authdata for counter
                           UINT32 * counterId,
                           unsigned char * counterValue
                           );
UINT32 TCM_IncrementCounter(UINT32 countid,              // id of the counter
                              unsigned char * counterauth,   // authdata for counter
                              unsigned char * counterbuffer  // buffer to return the counter in
                             );
UINT32 TCM_ReadCounter(UINT32 countid,              // id of the counter
                         unsigned char * counterauth,   // authdata for counter
                         unsigned char * counterbuffer // buffer to return the counter in
                         );
UINT32 TCM_ReleaseCounter(UINT32 countid,              // id of the counter
                            unsigned char * counterauth   // authdata for counter
                         );
UINT32 TCM_ReleaseCounterOwner(UINT32 countid,              // id of the counter
                                 unsigned char * ownerauth      // authdata for counter
                         );
*/
/* Section 13: crypto functions */
/*
UINT32 TCM_SHA1Start(UINT32 *maxNumBytes);
UINT32 TCM_SHA1Update(void * data, UINT32 datalen);
UINT32 TCM_SHA1Complete(void * data, UINT32 datalen,
                          unsigned char * hash);
UINT32 TCM_SHA1CompleteExtend(void * data, UINT32 datalen,
                                UINT32 pcrNum,
                                unsigned char * hash,
                                unsigned char * pcrValue) ;
UINT32 TCM_Sign(UINT32 keyhandle, unsigned char *keyauth,
                  unsigned char *data, UINT32 datalen,
                  unsigned char *sig, UINT32 *siglen);
UINT32 TCM_GetRandom(UINT32 bytesreq,
                       unsigned char * buffer, UINT32 * bytesret);
*/
/*
UINT32 TCM_CertifyKey(UINT32 certhandle,
                        UINT32 keyhandle,
                        unsigned char *certKeyAuth,
                        unsigned char *usageAuth,
                        struct tpm_buffer *certifyInfo,
                        struct tpm_buffer *signature);
*/

/* Section 28.2: Context management */
/*
UINT32 TCM_SaveKeyContext(UINT32 keyhandle,
                            struct tpm_buffer *context);
UINT32 TCM_LoadKeyContext(struct tpm_buffer *buffer,
                            UINT32 *keyhandle);
UINT32 TCM_SaveAuthContext(UINT32 authhandle,
                             unsigned char * authContextBlob, UINT32 * authContextSize);
UINT32 TCM_LoadAuthContext(unsigned char *authContextBlob, UINT32 authContextSize,
                             UINT32 *keyhandle);
*/

/* virtual TCM Management functions */

/* TCM helper functions */
/*
UINT32 TCM_SealCurrPCR(UINT32 keyhandle,
                  UINT32 pcrmap,
                  unsigned char *keyauth,
                  unsigned char *dataauth,
                  unsigned char *data, UINT32 datalen,
                  unsigned char *blob, UINT32 *bloblen);
UINT32 TSS_GenPCRInfo(UINT32 pcrmap, 
                        unsigned char *pcrinfo, 
                        UINT32 *len);
char *TCM_GetErrMsg(UINT32 code);

UINT32 TCM_GetCurrentTicks(const struct tpm_buffer *tb, UINT32 offset, TCM_CURRENT_TICKS * ticks) ;


*/

/* Additional functions for testing... */
/*
UINT32 TCM_RawDataRaw(UINT32 ordinal,
                        unsigned char * data, 
                        UINT32 datalen);

UINT32 TCM_RawDataOIAP(UINT32 ordinal,
                         unsigned char * ownerauth,
                         unsigned char * data, 
                         UINT32 datalen);

UINT32 TCM_RawDataOSAP(UINT32 keyhandle,
                         UINT32 ordinal,
                         unsigned char * ownerauth,
                         unsigned char * data, 
                         UINT32 datalen);

void TCM_CreateEncAuth(const struct session *sess, 
                       const unsigned char *in, unsigned char *out,
                       const unsigned char *nonceodd);

UINT32 TCM_ValidatePCRCompositeSignature(TCM_PCR_COMPOSITE *tpc,
                                           unsigned char *antiReplay,
                                           pubkeydata *pk,
                                           struct tpm_buffer *signature,
                                           UINT16 sigscheme);

*/
/* helper functions to serialize / deserialize data structures */
/*
UINT32 TCM_WriteEkBlobActivate(struct tpm_buffer *buffer, TCM_EK_BLOB_ACTIVATE * blob) ;
UINT32 TCM_WriteEkBlob(struct tpm_buffer *buffer, TCM_EK_BLOB * blob);

UINT32 TCM_WritePCRComposite(struct tpm_buffer *tb, TCM_PCR_COMPOSITE *comp);
UINT32 TCM_ReadPCRComposite(const struct tpm_buffer *buffer, UINT32 offset, TCM_PCR_COMPOSITE *tpc);


UINT32 TCM_ReadCounterValue(const unsigned char *buffer, TCM_COUNTER_VALUE * counter);
UINT32 TCM_WriteCounterValue(struct tpm_buffer *tb, TCM_COUNTER_VALUE * counter);
UINT32 TCM_WriteSignInfo(struct tpm_buffer *tb,
                           TCM_SIGN_INFO *tsi);
UINT32 TCM_WriteStoreAsymkey(struct tpm_buffer *buffer, TCM_STORE_ASYMKEY * sak);
UINT32 TCM_ReadStoredData(struct tpm_buffer *buffer, UINT32 offset, TCM_STORED_DATA *sd);
UINT32 TCM_WriteStoredData(struct tpm_buffer *buffer, TCM_STORED_DATA *sd);

UINT32 TCM_WritePCRInfoShort(struct tpm_buffer *buffer, TCM_PCR_INFO_SHORT * info);
UINT32 TCM_ReadPCRInfoLong(struct tpm_buffer *buffer, UINT32 offset, TCM_PCR_INFO_LONG * info);
UINT32 TCM_WritePCRInfoLong(struct tpm_buffer *buffer, TCM_PCR_INFO_LONG * info);
UINT32 TCM_ReadPCRInfo(struct tpm_buffer *buffer, UINT32 offset, TCM_PCR_INFO *info);
UINT32 TCM_WritePCRInfo(struct tpm_buffer *buffer, TCM_PCR_INFO * info);
UINT32 TCM_ReadPCRInfoShort(const struct tpm_buffer *buffer, UINT32 offset, 
                              TCM_PCR_INFO_SHORT * info);

UINT32 TCM_WriteCAContents(struct tpm_buffer *buffer, TCM_ASYM_CA_CONTENTS * data);

UINT32 TCM_HashPCRComposite(TCM_PCR_COMPOSITE * comp, unsigned char * digest);
UINT32 TCM_HashPubKey(keydata * k, unsigned char * digest);
UINT32 TCM_HashMSAComposite(TCM_MSA_COMPOSITE * comp, unsigned char * digest);

UINT32 TCM_WriteMSAComposite(struct tpm_buffer *buffer, TCM_MSA_COMPOSITE * comp);
UINT32 TCM_ReadMSAFile(const char * filename, TCM_MSA_COMPOSITE * msaList);

UINT32 TCM_ReadKeyfile(const char * filename, keydata *k);
UINT32 TCM_ReadPubKeyfile(const char * filename, pubkeydata *pubk);
UINT32 TCM_WritePCRSelection(struct tpm_buffer *buffer,
                               TCM_PCR_SELECTION *sel);
UINT32 TCM_ReadPCRSelection(struct tpm_buffer *buffer, UINT32 offset,
                              TCM_PCR_SELECTION * sel);

UINT32 TCM_ReadFile(const char * filename, unsigned char ** buffer, UINT32 * buffersize);
UINT32 TCM_WriteFile(const char * filename, unsigned char * buffer, UINT32 buffersize);

UINT32 TCM_WriteQuoteInfo(struct tpm_buffer *buffer, TCM_QUOTE_INFO * info);
UINT32 TCM_WriteQuoteInfo2(struct tpm_buffer *buffer, TCM_QUOTE_INFO2 * info2);

UINT32 TCM_WriteCMKAuth(struct tpm_buffer *buffer, TCM_CMK_AUTH * auth) ;
UINT32 TCM_HashCMKAuth(TCM_CMK_AUTH * auth, unsigned char * hash);

UINT32 TCM_WritePubInfo(TCM_NV_DATA_PUBLIC * pub, struct tpm_buffer *buffer);

UINT32 TCM_ReadPermanentFlags(const struct tpm_buffer *tb,
                                UINT32 offset, 
                                TCM_PERMANENT_FLAGS * pf,
				UINT32 used);
UINT32 TCM_ReadPermanentFlagsPre103(const struct tpm_buffer *tb,
                                      UINT32 offset, 
                                      TCM_PERMANENT_FLAGS * pf);
UINT32 TCM_ReadSTClearFlags(const struct tpm_buffer *tb, 
                              UINT32 offset,
                              TCM_STCLEAR_FLAGS * sf);

UINT32  TSS_KeyExtract(const struct tpm_buffer *tb, UINT32 offset, keydata *k);
UINT32  TSS_PubKeyExtract(const struct tpm_buffer *tb, UINT32 offset, pubkeydata *k);
UINT32  TCM_WriteKey(struct tpm_buffer *tb, keydata *k);
UINT32  TCM_ReadKey(const struct tpm_buffer *tb, UINT32 offset, keydata *k);
UINT32  TCM_WriteKeyPub(struct tpm_buffer *tp, keydata *k);
UINT32  TCM_WriteKeyInfo(struct tpm_buffer *tp, keydata *k);
UINT32  TCM_WriteSymmetricKey(struct tpm_buffer *tp, TCM_SYMMETRIC_KEY * key);
UINT32  TCM_ReadSymmetricKey(struct tpm_buffer *, UINT32 offset, TCM_SYMMETRIC_KEY * key);
int       TSS_KeySize(const struct tpm_buffer *tb, unsigned int offset);
int       TSS_PubKeySize(const struct tpm_buffer *, unsigned int offset, int pcrpresent);
int       TSS_AsymKeySize(const unsigned char * keybuff);
int       TSS_SymKeySize(const unsigned char * keybuff);
void      TSS_Key2Pub(unsigned char *keybuff, unsigned char *pkey, unsigned int *plen);
void      TSS_pkeyprint(pubkeydata *key, unsigned char *fprint);
void      TSS_keyprint(unsigned char *keybuff, unsigned char *fprint);
UINT32  TSS_lkeyprint(UINT32 keyhandle, unsigned char *keyauth, unsigned char *fprint);
UINT32  TCM_WriteStoreAsymkey(struct tpm_buffer *buffer, TCM_STORE_ASYMKEY * sak);

UINT32 TCM_GetCertifyInfoSize(const unsigned char * blob);
UINT32 TCM_GetCertifyInfo2Size(const unsigned char * blob);

UINT32 TCM_GetPubKeyDigest(UINT32 handle, unsigned char *keyPassHash, unsigned char *digest);

UINT32 TCM_WriteMigrationKeyAuth(struct tpm_buffer *buffer, TCM_MIGRATIONKEYAUTH * mka);
UINT32 TCM_WriteDelegatePublic(struct tpm_buffer *buffer, TCM_DELEGATE_PUBLIC * pub);
UINT32 TCM_ReadKeyParms(const struct tpm_buffer *, UINT32 offset, TCM_KEY_PARMS * keyparms);
UINT32 TCM_ReadCertifyInfo(const struct tpm_buffer *, UINT32 offset, TCM_CERTIFY_INFO * cinfo);
UINT32 TCM_ReadCertifyInfo2(const struct tpm_buffer *, UINT32 offset, TCM_CERTIFY_INFO2 * cinfo2);
UINT32 TCM_ReadNVDataPublic(const struct tpm_buffer *buffer, UINT32 offset, TCM_NV_DATA_PUBLIC * ndp);
UINT32 TCM_ReadCapVersionInfo(const struct tpm_buffer *fb, UINT32 offset, TCM_CAP_VERSION_INFO * cvi);
UINT32 TCM_ReadStartupEffects(const unsigned char * buffer, TCM_STARTUP_EFFECTS * se);

UINT32 TCM_GetNumPCRRegisters(UINT32 *res);
UINT32 TCM_GetTCMInputBufferSize(UINT32 *size);

struct tpm_buffer *TSS_AllocTCMBuffer(int len);
void TSS_FreeTCMBuffer(struct tpm_buffer * buf);
UINT32 TSS_SetTCMBuffer(struct tpm_buffer *tb, 
                          const unsigned char *buffer,
                          UINT32 len);

UINT32 TCM_WriteTCMFamilyLabel(struct tpm_buffer *buffer, 
                                 TCM_FAMILY_LABEL l);
UINT32 TCM_ReadTCMFamilyLabel(const unsigned char *buffer, 
                                TCM_FAMILY_LABEL *l);
UINT32 TCM_WriteTCMDelegations(struct tpm_buffer *buffer,
                                 TCM_DELEGATIONS *td);
UINT32 TCM_WriteTCMDelegatePublic(struct tpm_buffer *buffer,
                                    TCM_DELEGATE_PUBLIC * tdp);
UINT32 TCM_WriteTCMDelegateOwnerBlob(struct tpm_buffer *buffer,
                                       TCM_DELEGATE_OWNER_BLOB *tdob);
UINT32 TCM_WriteTCMDelegateKeyBlob(struct tpm_buffer *buffer,
                                     TCM_DELEGATE_KEY_BLOB *tdob);
UINT32 TCM_WriteDelegateOwnerBlob(struct tpm_buffer *buffer, TCM_DELEGATE_OWNER_BLOB * blob);

UINT32 TCM_ReadFamilyTableEntry(struct tpm_buffer *buffer,
                                  UINT32 offset,
                                  TCM_FAMILY_TABLE_ENTRY *fte);
UINT32 TCM_ReadDelegatePublic(struct tpm_buffer *buffer,
                                UINT32 offset,
                                TCM_DELEGATE_PUBLIC *dp);
UINT32 TCM_ReadTCMDelegations(const struct tpm_buffer *buffer, UINT32 offset,
                                TCM_DELEGATIONS *td);
UINT32 TCM_WriteTransportPublic(struct tpm_buffer *tb,
                                  TCM_TRANSPORT_PUBLIC *ttp);
UINT32 TCM_WriteTransportAuth(struct tpm_buffer *tb,
                                TCM_TRANSPORT_AUTH *tta);
UINT32 TCM_WriteContextBlob(struct tpm_buffer *buffer,
                              TCM_CONTEXT_BLOB * context);
UINT32 TCM_ReadContextBlob(const struct tpm_buffer *buffer,
                             UINT32 offset,
                             TCM_CONTEXT_BLOB *context);
UINT32 TCM_WriteAuditEventIn(struct tpm_buffer *buffer, 
                               TCM_AUDIT_EVENT_IN * aei);
UINT32 TCM_WriteAuditEventOut(struct tpm_buffer *buffer,
                                TCM_AUDIT_EVENT_OUT * aeo);
UINT32 TCM_ReadDAInfo(struct tpm_buffer *buffer,
                        UINT32 offset,
                        TCM_DA_INFO *tdi);
UINT32 TCM_ReadDAInfoLimited(struct tpm_buffer *buffer,
                               UINT32 offset,
                               TCM_DA_INFO_LIMITED *tdi);
UINT32 _TCM_GetCalculatedAuditDigest(TCM_DIGEST *digest);
UINT32 _TCM_SetAuditStatus(UINT32 ord, TCM_BOOL enable);
*/
/*
UINT32 TCM_ValidateSignature(UINT16 sigscheme,
                               struct tpm_buffer *data,
                               struct tpm_buffer *signature,
                               RSA *rsa);
*/
/*
UINT32 TCM_WriteTransportLogIn(struct tpm_buffer *buffer,
                                 TCM_TRANSPORT_LOG_IN *ttli);
UINT32 TCM_WriteTransportLogOut(struct tpm_buffer *buffer,
                                  TCM_TRANSPORT_LOG_OUT *ttlo);
UINT32 TCM_WriteCurrentTicks(struct tpm_buffer *buffer,
                               TCM_CURRENT_TICKS *tct);
UINT32 TCM_ReadCurrentTicks(struct tpm_buffer *buffer,
                              UINT32 offset,
                              TCM_CURRENT_TICKS *tct);

UINT32 read_transdigest(UINT32 handle, unsigned char *digest);



void print_array(const char *name, const unsigned char *data, unsigned int len);
*/
#endif
