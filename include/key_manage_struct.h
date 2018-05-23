#ifndef KEY_MANAGE_STRUCT_H
#define KEY_MANAGE_STRUCT_H

/*
秘钥管理主类别
*/
enum key_manage_type
{
	DTYPE_KEY_MANAGE=0x2100,
};

/*
秘钥管理子类别
*/
enum key_manage_subtype
{
	SUBTYPE_AIK_BIND=0x01,
};

/*
aik关联结构
*/
struct key_manage_aik_bind
{
	BYTE machine_uuid[DIGEST_SIZE];
	char * user_name;
	BYTE aik_pub_uuid[DIGEST_SIZE];
	BYTE aik_pri_uuid[DIGEST_SIZE];
	BYTE aik_cert_uuid[DIGEST_SIZE];
}__attribute__((packed));
/*
struct key_info_struct
{
	BYTE key_uuid[DIGEST_SIZE];
	int  key_type;
	char user_name[DIGEST_SIZE];
	BYTE machine_uuid[DIGEST_SIZE];
	BYTE pub_uuid[DIGEST_SIZE];
	BYTE key_cert_uuid[DIGEST_SIZE];
}__attribute__((packed));
*/
#endif
