#ifndef VTCM_SCRIPT_H
#define VTCM_SCRIPT_H

enum  dtype_vtcm_script
{
    DTYPE_VTCM_SCRIPT=0x2100,
    DTYPE_VTCM_SYS=0x2101,
    DTYPE_VTCM_FILETRANS=0x2102
};

enum subtype_vtcm_script
{
	VTCM_SCRIPT_CALL=0x01,
	VTCM_SCRIPT_RET
};

enum subtype_vtcm_sys
{
	VTCM_SYS_CP,
	VTCM_SYS_MV,
	VTCM_SYS_RM,
	VTCM_SYS_RENAME
};

enum  subtype_vtcm_filetrans
{
    VTCM_FILETRANS_SEND,
    VTCM_FILETRANS_RECEIVE
};

struct vtcm_script_call
{
    char name[DIGEST_SIZE];	
    int  param_num;
    BYTE * params;
}__attribute__((packed));

struct vtcm_script_ret
{
    int returnCode;	
    int  param_num;
    BYTE * params;
    int cmd_no;
}__attribute__((packed));
#endif
