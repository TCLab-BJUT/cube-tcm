#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "data_type.h"
#include "alloc.h"
#include "memfunc.h"
#include "json.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "basefunc.h"
#include "memdb.h"
#include "message.h"
#include "connector.h"
#include "ex_module.h"
#include "channel.h"
#include "sys_func.h"
#include "sha1.h"

#include "app_struct.h"
#include "vtcm_struct.h"
#include "tpm_init_channel.h"

#define MAX_LINE_LEN 1024

#define SHA1SIZE 20

#define TCM_TAG_RQU_VTCM_COMMAND        0xD100 /* An authenticated response with two authentication
                                                  handles */
#define TCM_TAG_RSP_VTCM_COMMAND        0xD400 /* An authenticated response with two authentication
                                                  handles */
#define TCM_TAG_RQU_MANAGE_COMMAND      0xE100 /* An authenticated response with two authentication
                                                  handles */
#define TCM_TAG_RSP_MANAGE_COMMAND      0xE400 /* An authenticated response with two authentication
                                                  handles */


static unsigned char Buf[DIGEST_SIZE*128];
static BYTE * ReadBuf=Buf;
static int readbuf_len=0;
static BYTE * WriteBuf=Buf+DIGEST_SIZE*64;
static int write_len=0;

static int index = 0;
static char errorbuf[1024];
static unsigned char sendbuf[4096];
static CHANNEL * ex_channel;
static CHANNEL * in_channel;
static void * extend_template;
static void * return_template;
static void * vtcm_head_template;
static void * vtcm_return_template;
static BYTE TPMPCR[16][SHA1SIZE];
static tpm_sha1_ctx_t sha1_ctx;

struct tpm_init_cmd
{
	UINT16 tag;
	unsigned int ordinal;
	int out_len;
	BYTE out_data[64];	
};

struct tpm_ordemu_struct
{
	UINT16 tag;
	unsigned int ordinal;
	int (*emu_func)(struct vtcm_external_input_command * input_head,BYTE * input,BYTE * output);
};

int tpm_ordemu_init(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_cont1(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_GetTicks(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_Startup(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_SelfTestFull(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_ContinueSelfTest(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_GetCapability(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_ResetEstablishmentBit(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_SHA1Start(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_SHA1Update(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_SHA1Complete(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_Extend(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_PcrRead(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_PhysicalPresence(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);

struct tpm_ordemu_struct tpm_emu_seq[] =
{
	{
		0x0180,
		0x81010000,
		&tpm_ordemu_init
	},

	{
		0xC100,
		0xF1000000,
		&tpm_ordemu_GetTicks
	},
	{
		0xC100,
		0x99000000,
		&tpm_ordemu_Startup
	},
	{
		0xC100,
		0x50000000,
		&tpm_ordemu_SelfTestFull
	},
	{
		0xC100,
		0x53000000,
		&tpm_ordemu_SelfTestFull
	},
	{
		0xC100,
		0x0B000040,
		&tpm_ordemu_ResetEstablishmentBit
	},
	{
		0xC100,
		0x65000000,
		&tpm_ordemu_GetCapability
	},
	{
		0xC100,
		0xA0000000,
		&tpm_ordemu_SHA1Start
	},
	{
		0xC100,
		0xA1000000,
		&tpm_ordemu_SHA1Update
	},
	{
		0xC100,
		0xA2000000,
		&tpm_ordemu_SHA1Complete
	},
	{
		0xC100,
		0x14000000,
		&tpm_ordemu_Extend
	},
	{
		0xC100,
		0x15000000,
		&tpm_ordemu_PcrRead
	},
	{
		0xC100,
		0x0A000040,
		&tpm_ordemu_PhysicalPresence
	},
	{
		0x0180,
		0x7a010000,
		&tpm_ordemu_cont1
	},
	{
		0,
		0,
		NULL
	}
};

int tpm_init_channel_init(void * sub_proc,void * para)
{
    int ret;
    struct tpm_init_para * init_para=para;
    if(para==NULL)
	return -EINVAL;
    ex_channel=channel_find(init_para->ex_channel);
    if(ex_channel==NULL)
	return -EINVAL;	

    in_channel=channel_register(init_para->in_channel,CHANNEL_RDWR,sub_proc);
    if(in_channel==NULL)
	return -EINVAL;

    extend_template=memdb_get_template(DTYPE_VTCM_EXTERNAL,SUBTYPE_INPUT_COMMAND_EXTERNAL) ;
    if(extend_template==NULL)
    {
    	printf("load extend template error!\n");
    	return -EINVAL;
    }
    return_template=memdb_get_template(DTYPE_VTCM_EXTERNAL,SUBTYPE_RETURN_DATA_EXTERNAL) ;
    if(return_template==NULL)
    {
    	printf("load return template error!\n");
    	return -EINVAL;
    }
    vtcm_head_template=memdb_get_template(DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_CMD_HEAD);
    if(vtcm_head_template==NULL)
    {
    	printf("load vtcm head template error!\n");
    	return -EINVAL;
    }
    vtcm_return_template=memdb_get_template(DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_RETURN_HEAD) ;
    if(return_template==NULL)
    {
    	printf("load vtcm return template error!\n");
    	return -EINVAL;
    }

    return 0;
}

int tpm_init_channel_start(void * sub_proc,void * para)
{
    int ret = 0, len = 0, i = 0, j = 0;
    int rc = 0;
    int extend_size;
    struct vtcm_external_input_command output_data;
    struct vtcm_manage_cmd_head cmd_head;
    struct vtcm_manage_return_head return_head;
    extend_size=struct_size(extend_template);	
    int offset=0;


    for (;;)
    {
        usleep(time_val.tv_usec);
	// read ex_channel 
	ret=channel_read(ex_channel,ReadBuf+readbuf_len,DIGEST_SIZE*32-readbuf_len);
	if(ret<0)
		return ret;
	if(ret>0)
	{
		readbuf_len+=ret;
		if(readbuf_len<extend_size)
			continue;	

		print_bin_data(ReadBuf,readbuf_len,8);
                offset=0;
		
        	ret = blob_2_struct(ReadBuf, &output_data,extend_template) ;
		if(ret<0)
			return -EINVAL;
		if(output_data.paramSize>readbuf_len)
			continue;

		if(output_data.tag==TCM_TAG_RQU_VTCM_COMMAND)
		{
			offset=ret;	
			ret=blob_2_struct(ReadBuf+offset,&output_data,extend_template);
		}

		i=0;
		while(tpm_emu_seq[i].ordinal!=0)
		{
			if((output_data.ordinal == tpm_emu_seq[i].ordinal)
				&&(output_data.tag == tpm_emu_seq[i].tag))
			{
			//Match a tpm init sequence
				if(tpm_emu_seq[i].emu_func==NULL)
					return -EINVAL;
				int out_len=0;
				out_len=tpm_emu_seq[i].emu_func(&output_data,ReadBuf+offset,sendbuf+offset);
				if(out_len<0)
					return -EINVAL;			
				if(offset>0)
				{
					ret=blob_2_struct(ReadBuf,&cmd_head,vtcm_head_template);
					if(ret<0)
						return -EINVAL;
					return_head.tag=TCM_TAG_RSP_VTCM_COMMAND;
					return_head.paramSize=sizeof(return_head)+out_len;
					return_head.vtcm_no=cmd_head.vtcm_no;
					return_head.returnCode=0;
					ret=struct_2_blob(&return_head,sendbuf,vtcm_return_template);
				}
				print_bin_data(sendbuf,out_len+offset,8);
				
				ret=channel_write(ex_channel,sendbuf,out_len+offset);
				if(ret<0)
					return -EINVAL;
				break;
			}
			i++;
			
		}		
		if(tpm_emu_seq[i].ordinal==0)
		// if no tpm init sequence match
		{
			ret=channel_inner_write(in_channel,ReadBuf,output_data.paramSize+offset);
			if(ret<output_data.paramSize)
				return -EINVAL;
		}
		readbuf_len-=output_data.paramSize+offset;
		Memcpy(ReadBuf,ReadBuf+output_data.paramSize+offset,readbuf_len);
	}
	ret=channel_inner_read(in_channel,WriteBuf,1024);
	if(ret<0)
		return -EINVAL;
	if(ret>0)
	{
		channel_write(ex_channel,WriteBuf,ret);
	}
    }
    return 0;
}
int tpm_ordemu_init(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	int out_len=10;
	BYTE out_data[10]={0x00,0xC4,0x00, 0x00,0x00,0x0A,0x00,0x00,0x00,0x0A};
	Memcpy(output,out_data,out_len);
	return out_len;
}

int tpm_ordemu_GetTicks(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	struct vtcm_external_output_command output_head;
	output_head.tag=0xC400;
	output_head.paramSize=0x0a;
	output_head.returnCode=0x26;

        ret = struct_2_blob(&output_head,output,return_template) ;
	return ret;
}

int tpm_ordemu_Startup(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	struct vtcm_external_output_command output_head;
	output_head.tag=0xC400;
	output_head.paramSize=0x0a;
	output_head.returnCode=0x00;

        ret = struct_2_blob(&output_head,output,return_template) ;
	return ret;
}

int tpm_ordemu_SelfTestFull(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	struct vtcm_external_output_command output_head;
	output_head.tag=0xC400;
	output_head.paramSize=0x0a;
	output_head.returnCode=0x00;

        ret = struct_2_blob(&output_head,output,return_template) ;
	return ret;
}

int tpm_ordemu_ContinueSelfTest(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	struct vtcm_external_output_command output_head;
	output_head.tag=0xC400;
	output_head.paramSize=0x0a;
	output_head.returnCode=0x00;

        ret = struct_2_blob(&output_head,output,return_template) ;
	return ret;
}


int tpm_ordemu_ResetEstablishmentBit(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	struct vtcm_external_output_command output_head;
	output_head.tag=0xC400;
	output_head.paramSize=0x0a;
	output_head.returnCode=0x3D;

        ret = struct_2_blob(&output_head,output,return_template) ;
	return ret;
}

int tpm_ordemu_GetCapability(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	struct vtcm_external_output_command output_head;
	struct tcm_in_GetCapability * tpm_in;
	struct tcm_out_GetCapability * tpm_out;
	void * tpm_in_template;
	void * tpm_out_template;


	tpm_in_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_GETCAPABILITY_IN);
	if(tpm_in_template==NULL)
	{
		printf("template error!\n");
		return -EINVAL;
	}
	tpm_out_template=memdb_get_template(DTYPE_VTCM_OUT,SUBTYPE_GETCAPABILITY_OUT);
	if(tpm_out_template==NULL)
	{
		printf("template error!\n");
		return -EINVAL;
	}

	tpm_in=Talloc0(sizeof(*tpm_in));
	tpm_out=Talloc0(sizeof(*tpm_out));
	ret=blob_2_struct(input,tpm_in,tpm_in_template);
	
	tpm_out->tag=0xC400;

	if(tpm_in->capArea==0x05)
	{
		if(tpm_in->subCapSize!=0x04)
			return -EINVAL;
		int subCapValue=tpm_in->subCap[2]*0x100+tpm_in->subCap[3];

		switch(subCapValue)
		{
			case 0x0115:
			{
				BYTE out_data[16]={0x00,0x0F,0x42,0x40,0x00,0x0F,0x42,0x40,0x00,0x0F,0x42,0x40,0x00,0x0F,0x42,0x40};
				tpm_out->paramSize=0x1E;
				tpm_out->returnCode=0;
				tpm_out->respSize=0x10;
				tpm_out->resp=Talloc0(tpm_out->respSize);
				Memcpy(tpm_out->resp,out_data,tpm_out->respSize);
			}	
			break;					
			case 0x0120:
			{
				BYTE out_data[16]={0x00,0x1E,0x84,0x80,0x00,0x4C,0x4B,0x40,0x03,0x93,0x87,0x00}; 
				tpm_out->paramSize=0x1A;
				tpm_out->returnCode=0;
				tpm_out->respSize=0x0C;
				tpm_out->resp=Talloc0(tpm_out->respSize);
				Memcpy(tpm_out->resp,out_data,tpm_out->respSize);
			}	
			break;					
			default:
				return -EINVAL;
		}
	}
	else if(tpm_in->capArea==0x1a)
	{
			BYTE out_data[16]={0x00,0x30,0x01,0x01,0x00,0x00,0x00,0x01,0x01,0x01,0x23,0x45,0x67,0x00,0x00}; 
			tpm_out->paramSize=0x1A;
			tpm_out->returnCode=0;
			tpm_out->respSize=0x0E;
			tpm_out->resp=Talloc0(tpm_out->respSize);
			Memcpy(tpm_out->resp,out_data,tpm_out->respSize);
			
	}
	
        ret = struct_2_blob(tpm_out,output,tpm_out_template) ;
	return ret;
}

int tpm_ordemu_SHA1Start(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	struct vtcm_external_output_command output_head;
	output_head.tag=0xC400;
	output_head.paramSize=0x0E;
	output_head.returnCode=0x0;
	BYTE out_data[16]={0x00,0x00,0x0F,0xCD};


        ret = struct_2_blob(&output_head,output,return_template) ;
	if(ret<0)
		return ret;
	tpm_sha1_init(&sha1_ctx);
	Memcpy(output+sizeof(output_head),out_data,output_head.paramSize-sizeof(output_head));
	return output_head.paramSize;
}

int tpm_ordemu_SHA1Update(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	struct vtcm_external_output_command output_head;
	struct tcm_in_Sm3Update * tpm_in;
	void * tpm_in_template;


	tpm_in_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_SM3COMPLETE_IN);
	if(tpm_in_template==NULL)
	{
		printf("template error!\n");
		return -EINVAL;
	}
	tpm_in=Talloc0(sizeof(*tpm_in));
	ret=blob_2_struct(input,tpm_in,tpm_in_template);

	tpm_sha1_update(&sha1_ctx,tpm_in->dataBlock,tpm_in->dataBlockSize);

	output_head.tag=0xC400;
	output_head.paramSize=0x0A;
	output_head.returnCode=0x0;

        ret = struct_2_blob(&output_head,output,return_template) ;
	if(ret<0)
		return ret;
	return output_head.paramSize;
}
int tpm_ordemu_SHA1Complete(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	struct vtcm_external_output_command output_head;
	struct tcm_in_Sm3Complete * tpm_in;
	void * tpm_in_template;


	tpm_in_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_SM3COMPLETE_IN);
	if(tpm_in_template==NULL)
	{
		printf("template error!\n");
		return -EINVAL;
	}
	tpm_in=Talloc0(sizeof(*tpm_in));
	ret=blob_2_struct(input,tpm_in,tpm_in_template);

	tpm_sha1_update(&sha1_ctx,tpm_in->dataBlock,tpm_in->dataBlockSize);

	output_head.tag=0xC400;
	output_head.paramSize=0x1E;
	output_head.returnCode=0x0;

        ret = struct_2_blob(&output_head,output,return_template) ;
	if(ret<0)
		return ret;
	tpm_sha1_final(&sha1_ctx,output+sizeof(output_head));
	return output_head.paramSize;
}
int tpm_ordemu_Extend(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	struct vtcm_external_output_command output_head;
	struct tcm_in_extend * tpm_in;
	void * tpm_in_template;

	BYTE SHA1Buf[SHA1SIZE*2];

	tpm_in_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_EXTEND_IN);
	if(tpm_in_template==NULL)
	{
		printf("template error!\n");
		return -EINVAL;
	}
	tpm_in=Talloc0(sizeof(*tpm_in));
	ret=blob_2_struct(input,tpm_in,tpm_in_template);

	output_head.tag=0xC400;
	output_head.paramSize=0x1E;
	output_head.returnCode=0x0;

	Memcpy(SHA1Buf,TPMPCR[tpm_in->pcrNum],SHA1SIZE);
	Memcpy(SHA1Buf+SHA1SIZE,tpm_in->inDigest,SHA1SIZE);
	calculate_context_sha1(SHA1Buf,SHA1SIZE*2,output+sizeof(output_head));
        ret = struct_2_blob(&output_head,output,return_template) ;
	if(ret<0)
		return ret;
	return output_head.paramSize;
}
int tpm_ordemu_PcrRead(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	struct vtcm_external_output_command output_head;
	struct tcm_in_pcrread * tpm_in;
	void * tpm_in_template;

	tpm_in_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_PCRREAD_IN);
	if(tpm_in_template==NULL)
	{
		printf("template error!\n");
		return -EINVAL;
	}
	tpm_in=Talloc0(sizeof(*tpm_in));
	ret=blob_2_struct(input,tpm_in,tpm_in_template);

	output_head.tag=0xC400;
	output_head.paramSize=0x1E;
	output_head.returnCode=0x0;

	Memcpy(output+sizeof(output_head),TPMPCR[tpm_in->pcrIndex],SHA1SIZE);
        ret = struct_2_blob(&output_head,output,return_template) ;
	if(ret<0)
		return ret;
	return output_head.paramSize;
}
int tpm_ordemu_PhysicalPresence(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	struct vtcm_external_output_command output_head;
	struct tcm_in_PhysicalPresence * tpm_in;
	void * tpm_in_template;

	BYTE SHA1Buf[SHA1SIZE*2];

	tpm_in_template=memdb_get_template(DTYPE_VTCM_IN,SUBTYPE_PHYSICALPRESENCE_IN);
	if(tpm_in_template==NULL)
	{
		printf("template error!\n");
		return -EINVAL;
	}
	tpm_in=Talloc0(sizeof(*tpm_in));
	ret=blob_2_struct(input,tpm_in,tpm_in_template);

	output_head.tag=0xC400;
	output_head.paramSize=0x0A;
	output_head.returnCode=0x0;

        ret = struct_2_blob(&output_head,output,return_template) ;
	if(ret<0)
		return ret;
	return output_head.paramSize;
}
int tpm_ordemu_cont1(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output)
{
	int ret;
	int out_len=10;
	BYTE out_data[10]={0x00,0xC4,0x00, 0x00,0x00,0x0A,0x00,0x00,0x00,0x0A};
	Memcpy(output,out_data,out_len);
	return out_len;
}
