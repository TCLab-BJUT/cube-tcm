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
//#include "tesi.h"

#include "file_struct.h"
#include "tesi_key.h"
#include "tesi_aik_struct.h"
#include "vtcm_pcr.h"

#include "app_struct.h"
#include "tcm_global.h"
#include "tcm_error.h"

#include "sm3.h"
#include "vtcm_struct.h"

static struct timeval time_val={0,50*1000};
struct vtcm_pcr_scene * pcr_scenes;

static int proc_vtcm_pcrread(sub_proc, recv_msg);
static int proc_vtcm_extend(sub_proc, recv_msg);
static int proc_vtcm_pcrreset(sub_proc, recv_msg);

int vtcm_pcr_init(void * sub_proc,void * para)
{
    int i,j;
    pcr_scenes = malloc(sizeof(struct vtcm_pcr_scene )*3);//相当于申请了一个数组
    if(pcr_scenes==NULL)
        return -ENOMEM;
    tcm_state_t * tcm_instances = proc_share_data_getpointer();


    for(i=0;i<3;i++)//分配存储空间
    {
        pcr_scenes[i].index_num=TCM_NUM_PCR;
        pcr_scenes[i].pcr_size=sizeof(TCM_DIGEST);
        pcr_scenes[i].pcr=tcm_instances[i].tcm_stclear_data.PCRS;
    }

    ex_module_setpointer(sub_proc,&pcr_scenes[0]);
    // prepare the slot sock
    return 0;
}

int vtcm_pcr_setvtcmscene(void * sub_proc,void * recv_msg)
{
	int ret;
	int type=DTYPE_VTCM_STRUCT;	
	int subtype=SUBTYPE_VTCM_CMD_HEAD;
	MSG_EXPAND * msg_expand;
	struct vtcm_manage_cmd_head * cmd_head;
	struct vtcm_manage_return_head * return_head;

	ret=message_get_define_expand(recv_msg,&msg_expand,DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_CMD_HEAD);
	if(ret<0)
		return ret;
	if(msg_expand==NULL)
		return 0;
	cmd_head=msg_expand->expand;
	if(cmd_head==NULL)
	{
    		ex_module_setpointer(sub_proc,&pcr_scenes[0]);
		return 0;
	}
	else
	{
    		ex_module_setpointer(sub_proc,&pcr_scenes[cmd_head->vtcm_no]);
	}
	return cmd_head->vtcm_no;
}

int vtcm_pcr_start(void * sub_proc,void * para)
{
    int ret;
    int retval;
    void * recv_msg;
    void * context;
    int i;
    int type;
    int subtype;
    void * sock;	
    BYTE uuid[DIGEST_SIZE];

    printf("vtcm_pcr module start!\n");

    for(i=0;i<300*1000;i++)
    {
        usleep(time_val.tv_usec);
        ret=ex_module_recvmsg(sub_proc,&recv_msg);
        if(ret<0)
            continue;
        if(recv_msg==NULL)
            continue;

        type=message_get_type(recv_msg);
        subtype=message_get_subtype(recv_msg);

        if((type==DTYPE_VTCM_IN)&&(subtype==SUBTYPE_EXTEND_IN))
        {
            proc_vtcm_extend(sub_proc,recv_msg);
        }
        else if((type==DTYPE_VTCM_IN)&&(subtype==SUBTYPE_PCRREAD_IN))
        {
            proc_vtcm_pcrread(sub_proc,recv_msg);
        }
        else if((type==DTYPE_VTCM_IN)&&(subtype==SUBTYPE_PCRRESET_IN))
        {
            proc_vtcm_pcrreset(sub_proc,recv_msg);
        }
        else if((type==DTYPE_VTCM_IN)&&(subtype==SUBTYPE_SM3COMPLETEEXTEND_IN))
        {
            proc_vtcm_Sm3CompleteExtend(sub_proc,recv_msg);
        }
    }

    return 0;
};


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


int proc_vtcm_extend(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_extend : Start \n") ;

    int ret=0;
    int i=0;
    BYTE buffer[DIGEST_SIZE*2];
    struct vtcm_pcr_scene * pcr_scene = ex_module_getpointer(sub_proc);
    struct tcm_in_extend * vtcm_in;
    struct tcm_out_extend * vtcm_out;
    int pcr_size;
    BYTE * pcr;
    void * send_msg;
    int vtcm_no; 
    int returnCode;

    vtcm_no = vtcm_pcr_setvtcmscene(sub_proc,recv_msg);
    if(vtcm_no<0)
    {
	returnCode=-TCM_BAD_PARAMETER;
	goto extend_out_proc;
    }
		
    pcr_scene = ex_module_getpointer(sub_proc);
    ret = message_get_record(recv_msg,(void **)&vtcm_in,0);
    if(ret<0)
        return ret;
    if(vtcm_in==NULL)
        return -EINVAL;

    pcr_size=pcr_scene->pcr_size;
    pcr=pcr_scene->pcr+(vtcm_in->pcrNum)*pcr_size;
    Memcpy(buffer,pcr,pcr_size);
    Memcpy(buffer+pcr_size,vtcm_in->inDigest,pcr_size);

    vtcm_SM3(pcr, buffer, pcr_size*2);
    
extend_out_proc:
    vtcm_out=Talloc(sizeof(*vtcm_out));
    if(vtcm_out==NULL)
        return -ENOMEM;
    vtcm_out->tag=0xC400;
    vtcm_out->paramSize=sizeof(*vtcm_out);
    vtcm_out->returnCode=0;
    Memcpy(vtcm_out->outDigest,pcr,pcr_size);

    send_msg=message_create(DTYPE_VTCM_OUT,SUBTYPE_EXTEND_OUT,recv_msg);
    if(send_msg==NULL)
        return -EINVAL;

    message_add_record(send_msg,vtcm_out);
    if(vtcm_no>0)
    {
	ret=vtcm_addcmdexpand(send_msg,recv_msg);
    }			
    ret=ex_module_sendmsg(sub_proc,send_msg);

    return ret;
}

int proc_vtcm_pcrread(void * sub_proc,void * recv_msg)
{
    int ret=0;
    int i=0;
    BYTE buffer[DIGEST_SIZE*2];
    struct vtcm_pcr_scene * pcr_scene;// 当前的pcr场景
    struct tcm_in_pcrread * vtcm_in;
    struct tcm_out_pcrread * vtcm_out;
    int pcr_size;
    BYTE * pcr;
    void * send_msg;
    int vtcm_no; 
    int returnCode;

    vtcm_no = vtcm_pcr_setvtcmscene(sub_proc,recv_msg);
    if(vtcm_no<0)
    {
	returnCode=-TCM_BAD_PARAMETER;
	goto pcrread_out_proc;
    }

    pcr_scene = ex_module_getpointer(sub_proc);

    ret = message_get_record(recv_msg,(void **)&vtcm_in,0);//将 recv_msg 的值赋给vtcm_extend
    if(ret<0)
        return ret;
    if(vtcm_in==NULL)
        return -EINVAL;

    pcr_size=pcr_scene->pcr_size;
    pcr=pcr_scene->pcr+vtcm_in->pcrIndex*pcr_size;
    Memcpy(buffer,pcr,pcr_size);

pcrread_out_proc:
    vtcm_out=Talloc(sizeof(*vtcm_out));
    if(vtcm_out==NULL)
         return -ENOMEM;
    vtcm_out->tag=0xC400;
    vtcm_out->paramSize=sizeof(*vtcm_out);
    vtcm_out->returnCode=0;
    Memcpy(vtcm_out->outDigest,pcr,pcr_size);
    send_msg=message_create(DTYPE_VTCM_OUT,SUBTYPE_PCRREAD_OUT,recv_msg);
    if(send_msg==NULL)
        return -EINVAL;
    message_add_record(send_msg,vtcm_out);
    if(vtcm_no>0)
    {
	ret=vtcm_addcmdexpand(send_msg,recv_msg);
    }			
    ret=ex_module_sendmsg(sub_proc,send_msg);
    
    return ret;
}


int vtcm_PCR_CheckRange(TCM_PCRINDEX index)                                                                                                                                              
{
    printf("vtcm_PCR_CheckRange : Start\n");
    int ret = TCM_SUCCESS;
    if (index >= TCM_NUM_PCR) 
    {
        printf("vtcm_PCR_CheckRange: Error, PCR index was %u should be <= %u\n", index, TCM_NUM_PCR);
        ret = TCM_BADINDEX;      
    }    
    return ret;
}

/* vtcm_PCR_Reset() resets the PCR based on the platform specification.  This should be called by the
 * vtcm_PCR_Reset ordinal.
 *
 * The caller must check that the PCR index is in range and that pcrReset is TRUE!
 */

int vtcm_PCR_Reset(struct vtcm_pcr_scene *pcr_scene,
                   TCM_BOOL TOSPresent,
                   TCM_PCRINDEX pcrIndex)
{
    printf("vtcm_PCR_Reset : Start\n");
    int ret = TCM_SUCCESS;
    
    ret = vtcm_PCR_CheckRange(pcrIndex);
    if(ret == TCM_SUCCESS)
    {
        int pcr_size = pcr_scene->pcr_size;
        BYTE *pcr = pcr_scene->pcr + pcrIndex * pcr_size;
        if (TOSPresent) 
            memset(pcr, 0, pcr_size);
        else 
            memset(pcr, 0xff, pcr_size);
    }
    return ret;
}

/*
 * pcrreset
*/

int proc_vtcm_pcrreset(void * sub_proc,void * recv_msg)
{
    printf("proc_vtcm_pcrreset : Start\n");

    int ret = TCM_SUCCESS;
    int i = 0;
    int j = 0;
    TCM_BOOL pcrUsage;                  // TRUE if pcrSelection specifies one or more 
    TCM_PCRINDEX pcr_num;               // PCR iterator
    uint16_t sizeOfSelect = 0;          // from pcrSelection input parameter
    struct tcm_in_pcrreset * vtcm_input;
    int pcr_size;
    BYTE * pcr;
    void * send_msg;
    int vtcm_no;

    ret = message_get_record(recv_msg,(void **)&vtcm_input,0);
    if(ret < 0)
        return ret;
    if(vtcm_input == NULL)
        return -EINVAL;

     //output process
     void * template_out = memdb_get_template(DTYPE_VTCM_OUT, SUBTYPE_PCRRESET_OUT);//Get the entire command template
     if(template_out == NULL)
     {    
        printf("can't solve this command!\n");
     }    
     struct tcm_out_pcrreset * vtcm_output = malloc(struct_size(template_out));
     
     tcm_state_t * tcm_state = proc_share_data_getpointer(); 
     
     vtcm_no = vtcm_pcr_setvtcmscene(sub_proc,recv_msg);
     if(vtcm_no < 0)
     {
	    ret =-TCM_BAD_PARAMETER;
	 goto pcrreset_out_proc;
     }
    
     struct vtcm_pcr_scene * pcr_scene = ex_module_getpointer(sub_proc);

    //Processing
    /* 1. Validate that pcrSelection is valid 
          a. is a valid TPM_PCR_SELECTION structure 
          NOTE: Done during TPM_PCRSelection_Load() 
          b. pcrSelection -> pcrSelect is non-zero 
          NOTE: TPM_PCRSelection_GetPCRUsage() range checks pcrSelection 
    */
     
    sizeOfSelect = vtcm_input->pcrSelection.sizeOfSelect;
    /* 3. For each PCR selected perform the following */
    if (ret == TCM_SUCCESS) 
    {
        for (i = 0, pcr_num = 0 ; i < sizeOfSelect ; i++) 
        {
            /* iterate through all bits in each selection byte */
            for (j = 0x0001 ; j != (0x0001 << CHAR_BIT) ; j <<= 1, pcr_num++) 
            {
                if (vtcm_input->pcrSelection.pcrSelect[i] & j) 
                {
                    printf("TPM_Process_PcrReset: Resetting PCR %u\n", pcr_num);
                    ret = vtcm_PCR_Reset(pcr_scene,
                                         tcm_state->tcm_stany_flags.TOSPresent,
                                         pcr_num);
                }
            }
        }
    }

pcrreset_out_proc:
    //Response
    printf("  proc_vtcm_PcrReset : Response\n");
    vtcm_output->tag = 0xC400;
    vtcm_output->returnCode = ret; 
                                                                                                                                                                 
    BYTE* response = (BYTE*)malloc(sizeof(BYTE) * 700);
    int responseSize = struct_2_blob(vtcm_output, response, template_out);
    vtcm_output->paramSize = responseSize;

    send_msg=message_create(DTYPE_VTCM_OUT,SUBTYPE_PCRRESET_OUT,recv_msg);
    if(send_msg==NULL)
        return -EINVAL;
    message_add_record(send_msg,vtcm_output);
    ret=ex_module_sendmsg(sub_proc,send_msg);
    return ret;
}

int proc_vtcm_Sm3CompleteExtend(void* sub_proc, void* recv_msg)
{
    printf("proc_vtcm_Sm3CompleteExtend : start\n");
    int ret = 0;
    int i = 0;

    BYTE buffer[DIGEST_SIZE*2];
    int pcr_size;
    BYTE * pcr;

    struct tcm_in_Sm3CompleteExtend *tcm_Sm3CompleteExtend_in;
    ret = message_get_record(recv_msg, (void **)&tcm_Sm3CompleteExtend_in, 0);                                                            
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

    struct vtcm_pcr_scene * pcr_scene = ex_module_getpointer(sub_proc);

    tcm_state_t * tcm_state = proc_share_data_getpointer();

    /*
     * Processing
    */
    //sm3_update(tcm_state->sm3_context, tcm_Sm3CompleteExtend_in->dataBlock, tcm_Sm3CompleteExtend_in->dataBlockSize);

    pcr_size=pcr_scene->pcr_size;
    pcr=pcr_scene->pcr+(tcm_Sm3CompleteExtend_in->pcrIndex)*pcr_size;
    Memcpy(buffer,pcr,pcr_size);
    Memcpy(buffer+pcr_size, tcm_Sm3CompleteExtend_in->dataBlock, pcr_size);

    //Calculate_context_sha1(buffer,pcr_size*2,pcr) ;;
    vtcm_SM3(pcr, buffer, pcr_size*2);

    Memcpy(tcm_Sm3CompleteExtend_out->pcrResult, pcr, pcr_size);
    sm3_finish(tcm_state->sm3_context, tcm_Sm3CompleteExtend_out->calResult);
    tcm_Sm3CompleteExtend_out->tag = 0xC400;
    tcm_Sm3CompleteExtend_out->returnCode = 0;

    tcm_Sm3CompleteExtend_out->paramSize = 0x4A;

    void *send_msg = message_create(DTYPE_VTCM_OUT, SUBTYPE_SM3COMPLETEEXTEND_OUT, recv_msg);
    if(send_msg == NULL)
        return -EINVAL;
    message_add_record(send_msg, tcm_Sm3CompleteExtend_out);
    ret = ex_module_sendmsg(sub_proc, send_msg);
    return ret;
}

