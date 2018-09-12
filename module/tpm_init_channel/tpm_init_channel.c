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

#include "app_struct.h"
#include "vtcm_struct.h"
#include "tpm_init_channel.h"

#define MAX_LINE_LEN 1024

#define SHA1SIZE 20

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
static BYTE TPMPCR[16][SHA1SIZE];

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
int tpm_ordemu_GetTicks(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_GetCapability(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_ResetEstablishmentBit(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_SHA1Start(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_SHA1Complete(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);
int tpm_ordemu_Extend(struct vtcm_external_input_command * input_head,BYTE * input, BYTE * output);

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
		0,
		0,
		NULL
	}
};

struct tpm_init_cmd init_cmd_seq[] =
{
	{
		0x0180,
		0x81010000,
		10,
		{0x00,0xC4,0x00, 0x00,0x00,0x0A,0x00,0x00,0x00,0x0A}
	},
	{
		0,
		0xF1000000,
		10,
		{0x00,0xC4,0x00, 0x00,0x00,0x0A,0x00,0x00,0x00,0x26}
	},
	{
		0,
		0x99000000,
		10,
		{0x00,0xC4,0x00, 0x00,0x00,0x0A,0x00,0x00,0x00,0x00}
	},
	{
		0,
		0x50000000, 		
		10,
		{0x00,0xC4,0x00, 0x00,0x00,0x0A,0x00,0x00,0x00,0x00}
	},
	{
		0,
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

    return 0;
}

int tpm_init_channel_start(void * sub_proc,void * para)
{
    int ret = 0, len = 0, i = 0, j = 0;
    int rc = 0;
    int extend_size;
    struct vtcm_external_input_command output_data;
    extend_size=struct_size(extend_template);	


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
	
		i=0;
        	ret = blob_2_struct(ReadBuf, &output_data,extend_template) ;
		if(ret<0)
			return -EINVAL;
		if(output_data.paramSize>readbuf_len)
			continue;
		while(tpm_emu_seq[i].ordinal!=0)
		{
			if((output_data.ordinal == tpm_emu_seq[i].ordinal)
				&&(output_data.tag == tpm_emu_seq[i].tag))
			{
			//Match a tpm init sequence
				if(tpm_emu_seq[i].emu_func==NULL)
					return -EINVAL;
				int out_len=0;
				out_len=tpm_emu_seq[i].emu_func(&output_data,ReadBuf,sendbuf);
				if(out_len<0)
					return -EINVAL;			
				ret=channel_write(ex_channel,sendbuf,out_len);
				if(ret<0)
					return -EINVAL;
				break;
			}
			i++;
			
		}		
		if(init_cmd_seq[i].ordinal==0)
		// if no tpm init sequence match
		{
			ret=channel_inner_write(in_channel,ReadBuf,output_data.paramSize);
			if(ret<output_data.paramSize)
				return -EINVAL;
		}
		Memcpy(ReadBuf,ReadBuf+output_data.paramSize,readbuf_len-output_data.paramSize);
		readbuf_len-=output_data.paramSize;
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
