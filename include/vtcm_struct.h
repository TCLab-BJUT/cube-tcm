#ifndef VTCM_STRUCT_H
#define VTCM_STRUCT_H
#include "./tcm_structures.h" 

#define TCM_TAG_RQU_VTCM_COMMAND        0xD100 /* An authenticated response with two authentication
                                                  handles */
#define TCM_TAG_RSP_VTCM_COMMAND       	0xD400 /* An authenticated response with two authentication
                                                  handles */
#define TCM_TAG_RQU_MANAGE_COMMAND      0xE100 /* An authenticated response with two authentication
                                                  handles */
#define TCM_TAG_RSP_MANAGE_COMMAND      0xE400 /* An authenticated response with two authentication
                                                  handles */
struct vtcm_manage_cmd_head
{
    UINT16 tag;
    int paramSize;
    UINT16 vtcm_no;	
    UINT16 cmd;
}__attribute__((packed));

struct vtcm_manage_return_head
{
    UINT16 tag;
    int paramSize;
    UINT16 vtcm_no;	
    UINT16 returnCode;
}__attribute__((packed));

enum  vtcm_manager_type
{
    DTYPE_VTCM_STRUCT=0x2080,
    DTYPE_VTCM_CTRL_IN=0x2081,
    DTYPE_VTCM_CTRL_OUT=0x2082,
};

enum vtcm_io_segment
{
	VTCM_IOSEG_PERMANENT_FLAGS=0x01,
	VTCM_IOSEG_STCLEAR_FLAGS,
	VTCM_IOSEG_STANY_FLAGS,
	VTCM_IOSEG_PERMANENT_DATAHEAD,
	VTCM_IOSEG_EK,
	VTCM_IOSEG_SMK,
	VTCM_IOSEG_CONTEXTKEY,
	VTCM_IOSEG_PERMANENT_DATATAIL,
	VTCM_IOSEG_STCLEAR_DATA,
	VTCM_IOSEG_PCRVALUE,
	VTCM_IOSEG_STANY_DATAHEAD,
	VTCM_IOSEG_STANY_CONTEXT,
	VTCM_IOSEG_STANY_SESSIONS,
	VTCM_IOSEG_KEY_ENTRIES,
	VTCM_IOSEG_NV_ENTRIES,
};

struct vtcm_io_datasegment
{
	UINT16  seg;
	UINT16  no;
	int data_size;
	BYTE * data;
}__attribute__((packed));

enum  vtcm_io_type
{
    VTCM_IO_STATIC=0x0100,
    VTCM_IO_CACHE=0x0300,
    VTCM_IO_MIG=0x0800
};

enum vtcm_struct_subtype
{
        SUBTYPE_VTCM_CMD_HEAD=0x01,
        SUBTYPE_VTCM_RETURN_HEAD,
        SUBTYPE_VTCM_STORAGE,
    	SUBTYPE_VTCM_INSTANCE,
    	SUBTYPE_VTCM_COPY,
    	SUBTYPE_VTCM_IO_CONTEXT,
    	SUBTYPE_VTCM_IO_DATASEGMENT,
};

enum vtcm_ctrl_cmd
// also is CTRL_IN and CTRL_OUT's SUBTYPE 
{
        VTCM_CTRL_INIT=0x0100,
        VTCM_CTRL_STOP=0x0200,
        VTCM_CTRL_CLEAN=0x0300,
        VTCM_CTRL_STARTUP=0x0400,
        VTCM_CTRL_KEYSET=0x0500,
        VTCM_CTRL_KEYUPDATE=0x0600,
        VTCM_CTRL_KEYEXPORT=0x0700,
        VTCM_CTRL_KEYIMPORT=0x0800,
        VTCM_CTRL_EXPORT=0x0900,
        VTCM_CTRL_IMPORT=0x0a00,
        VTCM_MIG_READY=0x1000,
        VTCM_MIG_EXPORTKEY=0x1100,
        VTCM_MIG_IMPORTKEY=0x1200,
        VTCM_MIG_CLEAN=0x1300,
        VTCM_MIG_ACTIVE=0x1400,
        VTCM_CMD_TRANS=0x4000,
        VTCM_RETURN_TRANS=0x4000,
};

enum vtcm_state
{
        VTCM_INIT=0x01,
    	VTCM_START,
	VTCM_ACTIVATE,
	VTCM_SLEEP,
	VTCM_MIGRATE
};

struct vtcm_storage
{
    BYTE vtcm_id[DIGEST_SIZE];	
    BYTE node_id[DIGEST_SIZE];
    BYTE pubek_id[DIGEST_SIZE];
}__attribute__((packed));

struct vtcm_instance
{
    BYTE vtcm_id[DIGEST_SIZE];
    enum vtcm_state state;
    int active_times;
    int sleep_times;
    int wait_times;
    int iswaitout;
}__attribute__((packed));

struct vtcm_copy
{
    BYTE vtcm_id[DIGEST_SIZE];
    int no;
    int active_times;
    int finish_cmds;	
} __attribute__((packed));

//by Search2016
struct vtcm_data_export_in
{
    BYTE crypt_id[DIGEST_SIZE];
    int type;
} __attribute__((packed));

struct vtcm_data_export_out
{
    BYTE crypt_id[DIGEST_SIZE];
    int data_size;
    int type;
    BYTE * data;
} __attribute__((packed));

struct vtcm_data_import_in
{
    BYTE crypt_id[DIGEST_SIZE];
    int data_size;
    int type;
    BYTE * data;
} __attribute__((packed));

struct vtcm_data_import_out
{
    BYTE crypt_id[DIGEST_SIZE];
    int data_size;
    BYTE * data;
} __attribute__((packed));


struct vtcm_io_context
{
	BYTE crypt_id[DIGEST_SIZE];
	BYTE wrapped_key[DIGEST_SIZE];
	BYTE key[DIGEST_SIZE];
	BYTE digest[DIGEST_SIZE];
} __attribute__((packed));


struct vtcm_io_keylist
{
    int key_no;
    struct vtcm_io_context * io_context;
} __attribute__((packed));

struct vtcm_init_cmd_in
{
	struct vtcm_manage_cmd_head cmd_head;
	BYTE uuid[DIGEST_SIZE];
	
}__attribute__((packed));

struct vtcm_init_cmd_out
{
	struct vtcm_manage_return_head return_head;
	BYTE uuid[DIGEST_SIZE];
	
}__attribute__((packed));


struct vtcm_export_cmd_in
{
	struct vtcm_manage_cmd_head cmd_head;
    	BYTE crypt_id[DIGEST_SIZE];
    	UINT16 type;
	int  max_size;
}__attribute__((packed));

struct vtcm_export_cmd_out
{
	struct vtcm_manage_return_head return_head;
    	UINT16 type;
    	int data_size;
    	BYTE * data;
}__attribute__((packed));


#endif
