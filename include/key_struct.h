#ifndef KEY_STRUCT_H
#define KEY_STRUCT_H

enum dtype_tesi_struct
{
	DTYPE_TESI_STRUCT=0x601,
	DTYPE_TESI_KEY_STRUCT=0x602,
};

enum subtype_tesi_struct
{
	SUBTYPE_SIGN_DATA=0x01,
	SUBTYPE_TCM_KEY_PARMS,
	SUBTYPE_TCM_IDENTITY_REQ
};

enum subtype_tesi_key_struct
{
	SUBTYPE_WRAPPED_KEY=0x01,
	SUBTYPE_PUBLIC_KEY,
	SUBTYPE_KEY_CERTIFY
};
struct vTCM_wrappedkey
{
	BYTE uuid[DIGEST_SIZE];
	BYTE vtcm_uuid[DIGEST_SIZE];
	int issmkwrapped; //flag which indices if the key is wrapped by srk
	int iskeyverified;// flag which indices if the key is verified
	int key_type; //the type of key,such as  STORAGE_KEY,SIGN_KEY
	int key_alg; //the key algorithm
	int key_size; // the size of key
	BYTE key_binding_policy_uuid[DIGEST_SIZE]; //if the key is wrappedKey,it is setted by uuid of binding policy 
	BYTE wrapkey_uuid[DIGEST_SIZE]; //the uuid of key;if the key is srk,uuid should be setted by the uuid of vtcm
	BYTE pubkey_uuid[DIGEST_SIZE];
	char * keypass; //the password of key
	char * key_filename; //the file which saves the key
}__attribute__((packed));

//the struct of pubKey
struct vTCM_publickey
{
	BYTE uuid[DIGEST_SIZE];
	BYTE vtcm_uuid[DIGEST_SIZE];
	int ispubek; //flag which decides if the pubkey is pubEK
	int iskeyverified;// flag which indices if the key is verified
	int key_type; //type of key,such as STORAGE_KEY,SIGN_KEY
	int key_alg; //key algorithm
	int key_size; // size of key
	BYTE key_binding_policy_uuid[DIGEST_SIZE]; //if the corresponding privateKey of the pubEK is bindkey,it should save the uuid of bind policy 
	BYTE privatekey_uuid[DIGEST_SIZE]; //the corresponding privatedKey's of pubKey,if the pubKey is pubEK,the uuid should be set by uuid of vtcm
	char * key_filename; //the file which saved the pubKey
}__attribute__((packed));

typedef struct tagtcm_key_certify_info   // KEY CERTIFO
{
	BYTE uuid[DIGEST_SIZE];
	BYTE keyuuid[DIGEST_SIZE];
	BYTE pikuuid[DIGEST_SIZE];
    	UINT16       keyusage;
    	UINT16	     keyflags;
    	BYTE authdatausage;
	int  keydigestsize;
	BYTE *pubkeydigest;
	int PCRinfosize;
	BYTE * PCRinfos;	
	char * filename;

}__attribute((packed)) KEY_CERT;

int get_radix_uuidstr(int len,BYTE * digest,char * uuidstr);
int convert_uuidname(char * name,int len,BYTE * digest,char * newfilename);


void * create_key_certify_struct(void * key_cert_file,char * keyuuid,char * pikuuid);
int create_blobkey_struct(struct vTCM_wrappedkey * blobkey,char * wrapkey_uuid,char * vtcm_uuid,char * keypass,char * keyfile);
int create_pubkey_struct(struct vTCM_publickey * pubkey,char * privatekey_uuid,char * vtcm_uuid,char * keyfile);
//void * verify_key_certify_struct(void * key_cert_file,char * keyuuid,char * pikuuid);

#endif
