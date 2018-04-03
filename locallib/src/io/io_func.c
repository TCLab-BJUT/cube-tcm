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
#include "memfunc.h"
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

#include "app_struct.h"
#include "tcm_global.h"
#include "tcm_error.h"
#include "vtcm_struct.h"
#include "tcm_iolib.h"

int vtcm_export_permanent_flags(void * instance,BYTE * buf);
int vtcm_export_stclear_flags(void * instance,BYTE * buf);
int vtcm_export_stany_flags(void * instance,BYTE *buf);

int vtcm_export_permanent_datahead(void * instance,BYTE * buf);
int vtcm_export_ekdata(void * instance,BYTE * buf);
int vtcm_export_smk(void * instance,BYTE * buf);
int vtcm_export_permanent_datatail(void * instance,BYTE * buf);
/*
int vtcm_export_stclear_data(instance,buf+offset);
int vtcm_export_stany_data(instance,buf+offset);
int vtcm_export_key_handle(instance,buf+offset);
int vtcm_export_transport_handle(instance,buf+offset);
int vtcm_import_permanent_flags(instance,buf+offset);
int vtcm_import_stclear_flags(instance,buf+offset);
int vtcm_import_stany_flags(instance,buf+offset);
int vtcm_import_permanentstany_flags(instance,buf+offset);
int vtcm_import_stclear_data(instance,buf+offset);
int vtcm_import_stany_data(instance,buf+offset);
int vtcm_import_key_handle(instance,buf+offset);
int vtcm_import_transport_handle(instance,buf+offset);
int vtcm_export_nv_data(void * instance, BYTE * buf, int storetype);
int vtcm_import_nv_data(void * instance, BYTE * buf, int storetype);
*/

static enum vtcm_io_segment static_seg[]=
{
	VTCM_IOSEG_PERMANENT_FLAGS,
	VTCM_IOSEG_PERMANENT_DATAHEAD,
	VTCM_IOSEG_EK,
	VTCM_IOSEG_SMK,
//	VTCM_IOSEG_CONTEXTKEY,
	VTCM_IOSEG_PERMANENT_DATATAIL,
//	VTCM_IOSEG_PCRVALUE,
//	VTCM_IOSEG_KEY_ENTRIES,
//	VTCM_IOSEG_NV_ENTRIES,
	0	
};

static enum vtcm_io_segment cache_seg[]=
{
	VTCM_IOSEG_PERMANENT_FLAGS,
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
	0
};

int vtcm_export_data_segment(void * instance,enum vtcm_io_segment seg,int no,BYTE * buf)
{
	int ret;
	switch(seg)
	{
		case	VTCM_IOSEG_PERMANENT_FLAGS:
			ret=vtcm_export_permanent_flags(instance,buf);
			break; 
		case    VTCM_IOSEG_STCLEAR_FLAGS: 
			ret=vtcm_export_stclear_flags(instance,buf);
			break; 
		case    VTCM_IOSEG_STANY_FLAGS: 
			ret=vtcm_export_stany_flags(instance,buf);
			break; 
		case    VTCM_IOSEG_PERMANENT_DATAHEAD: 
			ret=vtcm_export_permanent_datahead(instance,buf);
			break; 
		case    VTCM_IOSEG_EK: 
			ret=vtcm_export_ek(instance,buf);
			break; 
		case    VTCM_IOSEG_SMK: 
			ret=vtcm_export_smk(instance,buf);
			break; 
/*
		case    VTCM_IOSEG_CONTEXTKEY: 
			ret=vtcm_export_contextkey(instance,buf);
			break; 
*/
		case    VTCM_IOSEG_PERMANENT_DATATAIL: 
			ret=vtcm_export_permanent_datahead(instance,buf);
			break; 
/*
		case    VTCM_IOSEG_STCLEAR_DATA: 
			ret=vtcm_export_stclear_data(instance,buf);
			break; 
		case    VTCM_IOSEG_PCRVALUE: 
			ret=vtcm_export_pcrvalue(instance,buf);
			break; 
		case    VTCM_IOSEG_STANY_DATAHEAD: 
			ret=vtcm_export_stany_datahead(instance,buf);
			break; 
		case    VTCM_IOSEG_STANY_CONTEXT: 
			ret=vtcm_export_stany_context(instance,buf);
			break; 
		case    VTCM_IOSEG_STANY_SESSIONS: 
			ret=vtcm_export_stany_sessions(instance,buf);
			break; 
		case    VTCM_IOSEG_KEY_ENTRIES: 
			ret=vtcm_export_key_sessions(instance,buf);
			break; 
		case    VTCM_IOSEG_NV_ENTRIES: 
			ret=vtcm_export_nv_entries(instance,buf);
			break; 
*/
		default:
			return -EINVAL;
	}
	return ret;

}

int vtcm_import_data_segment(void * instance,enum vtcm_io_segment seg,int no,BYTE * buf)
{
	int ret;
	switch(seg)
	{
		case	VTCM_IOSEG_PERMANENT_FLAGS:
			ret=vtcm_import_permanent_flags(instance,buf);
			break; 
		case    VTCM_IOSEG_STCLEAR_FLAGS: 
			ret=vtcm_import_stclear_flags(instance,buf);
			break; 
		case    VTCM_IOSEG_STANY_FLAGS: 
			ret=vtcm_import_stany_flags(instance,buf);
			break; 
		case    VTCM_IOSEG_PERMANENT_DATAHEAD: 
			ret=vtcm_import_permanent_datahead(instance,buf);
			break; 
		case    VTCM_IOSEG_EK: 
			ret=vtcm_import_ek(instance,buf);
			break; 
		case    VTCM_IOSEG_SMK: 
			ret=vtcm_import_smk(instance,buf);
			break; 
/*
		case    VTCM_IOSEG_CONTEXTKEY: 
			ret=vtcm_import_contextkey(instance,buf);
			break; 
*/
		case    VTCM_IOSEG_PERMANENT_DATATAIL: 
			ret=vtcm_import_permanent_datahead(instance,buf);
			break; 
/*
		case    VTCM_IOSEG_STCLEAR_DATA: 
			ret=vtcm_import_stclear_data(instance,buf);
			break; 
		case    VTCM_IOSEG_PCRVALUE: 
			ret=vtcm_import_pcrvalue(instance,buf);
			break; 
		case    VTCM_IOSEG_STANY_DATAHEAD: 
			ret=vtcm_import_stany_datahead(instance,buf);
			break; 
		case    VTCM_IOSEG_STANY_CONTEXT: 
			ret=vtcm_import_stany_context(instance,buf);
			break; 
		case    VTCM_IOSEG_STANY_SESSIONS: 
			ret=vtcm_import_stany_sessions(instance,buf);
			break; 
		case    VTCM_IOSEG_KEY_ENTRIES: 
			ret=vtcm_import_key_sessions(instance,buf);
			break; 
		case    VTCM_IOSEG_NV_ENTRIES: 
			ret=vtcm_import_nv_entries(instance,buf);
			break; 
*/
		default:
			return -EINVAL;
	}
	return ret;

}

static BYTE buffer[DIGEST_SIZE*128];

int vtcm_instance_export(void * instance, BYTE * buf,int storetype)
// storetype: 0 means permanent data export, 1 means cache data export 
{
    int offset=0;	
    int ret;	
    int i;	
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
  	
    BYTE databuf[DIGEST_SIZE*32];
    void * data_segment_template;
    enum vtcm_io_segment * segment_list;  

    struct vtcm_io_datasegment * data_segment;  

    data_segment_template=memdb_get_template(DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_IO_DATASEGMENT);
    if(data_segment_template==NULL)
	return -EINVAL;

    if(storetype==VTCM_IO_STATIC)
    {
	segment_list=static_seg;
    }
    else if(storetype==VTCM_IO_CACHE)
    {
	segment_list=cache_seg;
    }
    else
	return -EINVAL;

    data_segment=Talloc0(sizeof(*data_segment));
    if(data_segment==NULL)
	return -ENOMEM;
    data_segment->data=databuf;
		
    for(i=0;segment_list[i]!=0;i++)
    {
	ret=vtcm_export_data_segment(instance,segment_list[i],0,databuf);
	if(ret<0)
		return ret;
	data_segment->seg=segment_list[i];
	data_segment->no=0;
	data_segment->data_size=ret;

	ret=struct_2_blob(data_segment,buf+offset,data_segment_template);
	if(ret<0)
		return ret;
	offset+=ret;
    }
   return offset;
}

int vtcm_instance_import(void * instance, BYTE * buf,int storetype)
// storetype: 0 means static data export, 1 means cache data export 
{
    int offset=0;	
    int ret;	
    int i;	
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
  	
    BYTE databuf[DIGEST_SIZE*32];
    void * data_segment_template;
    enum vtcm_io_segment * segment_list;  

    struct vtcm_io_datasegment * data_segment;  

    data_segment_template=memdb_get_template(DTYPE_VTCM_STRUCT,SUBTYPE_VTCM_IO_DATASEGMENT);
    if(data_segment_template==NULL)
	return -EINVAL;

    if(storetype==VTCM_IO_STATIC)
    {
	segment_list=static_seg;
    }
    else if(storetype==VTCM_IO_CACHE)
    {
	segment_list=cache_seg;
    }
    else
	return -EINVAL;

    data_segment=Talloc0(sizeof(*data_segment));
    if(data_segment==NULL)
	return -ENOMEM;
		
    for(i=0;segment_list[i]!=0;i++)
    {
	ret=blob_2_struct(buf+offset,data_segment,data_segment_template);
	if(ret<0)
		return ret;
	offset+=ret;
	if(data_segment->data_size>0)
	{
		ret=vtcm_import_data_segment(instance,data_segment->seg,data_segment->no,data_segment->data);
		if(data_segment->data_size!=ret)
			return -EINVAL;
	}
    }
    return offset;
}

int vtcm_export_permanent_flags(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
	
     ret=sizeof(TCM_PERMANENT_FLAGS);    
     Memcpy(buf,&tcm_instance->tcm_permanent_flags,ret);
     return ret;	
}

int vtcm_import_permanent_flags(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
	
     ret=sizeof(TCM_PERMANENT_FLAGS);    
     Memcpy(&tcm_instance->tcm_permanent_flags,buf,ret);
     return ret;	
}

int vtcm_export_stclear_flags(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
	
     ret=sizeof(TCM_STCLEAR_FLAGS);    
     Memcpy(buf,&tcm_instance->tcm_stclear_flags,ret);
     return ret;	
}
int vtcm_import_stclear_flags(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
	
     ret=sizeof(TCM_STCLEAR_FLAGS);    
     Memcpy(&tcm_instance->tcm_stclear_flags,buf,ret);
     return ret;	
}

int vtcm_export_stany_flags(void * instance,BYTE *buf)
{
    int offset=0;	
    int ret;	
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
	
     ret=sizeof(TCM_STANY_FLAGS);    
     Memcpy(buf,&tcm_instance->tcm_stany_flags,ret);
     return ret;	
}

int vtcm_import_stany_flags(void * instance,BYTE *buf)
{
    int offset=0;	
    int ret;	
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
	
     ret=sizeof(TCM_STANY_FLAGS);    
     Memcpy(&tcm_instance->tcm_stany_flags,buf,ret);
     return ret;	
}

int vtcm_export_permanent_datahead(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_PERMANENT_DATA * permanent_data=&tcm_instance->tcm_permanent_data;

//       ret=Struct_elemtail_offset(permanent_data,TCM_PERMANENT_DATA,operatorAuth);	
       ret=((unsigned long)(&((TCM_PERMANENT_DATA *)0)->operatorAuth)+sizeof(((TCM_PERMANENT_DATA *)permanent_data)->operatorAuth));
//     ret= &(((TCM_PERMANENT_DATA *)0)->operatorAuth)+sizeof(permanent_data->operatorAuth);
   
     Memcpy(buf+offset,permanent_data,ret);
     offset+=ret;
     return offset;	
}

int vtcm_import_permanent_datahead(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_PERMANENT_DATA * permanent_data=&tcm_instance->tcm_permanent_data;

//       ret=Struct_elemtail_offset(permanent_data,TCM_PERMANENT_DATA,operatorAuth);	
       ret=((unsigned long)(&((TCM_PERMANENT_DATA *)0)->operatorAuth)+sizeof(((TCM_PERMANENT_DATA *)permanent_data)->operatorAuth));
//     ret= &(((TCM_PERMANENT_DATA *)0)->operatorAuth)+sizeof(permanent_data->operatorAuth);
   
     Memcpy(permanent_data,buf+offset,ret);
     offset+=ret;
     return offset;	
}

int vtcm_export_ek(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_PERMANENT_DATA * permanent_data=&tcm_instance->tcm_permanent_data;

     // output endorsementKey
     struct_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
     if(struct_template==NULL)
	return -EINVAL;
     ret=struct_2_blob(&permanent_data->endorsementKey,buf+offset,struct_template);
     if(ret<0)
		return ret;
     offset+=ret;     	  
     return offset;	
}

int vtcm_import_ek(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_PERMANENT_DATA * permanent_data=&tcm_instance->tcm_permanent_data;

     // output endorsementKey
     struct_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
     if(struct_template==NULL)
	return -EINVAL;
     ret=blob_2_struct(buf+offset,&permanent_data->endorsementKey,struct_template);
     if(ret<0)
		return ret;
     offset+=ret;     	  
     return offset;	
}

int vtcm_export_smk(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_PERMANENT_DATA * permanent_data=&tcm_instance->tcm_permanent_data;

     // output smk
     struct_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
     if(struct_template==NULL)
	return -EINVAL;

     if(permanent_data->smk.keyUsage==0)
     {
	ret=0;
     }
     else
     {			
     	ret=struct_2_blob(&permanent_data->smk,buf+offset,struct_template);
     	if(ret<0)
		return ret;
     }	
     offset+=ret;     
     return offset;		  
}

int vtcm_import_smk(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_PERMANENT_DATA * permanent_data=&tcm_instance->tcm_permanent_data;

     // output smk
     struct_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
     if(struct_template==NULL)
	return -EINVAL;
     ret=blob_2_struct(buf+offset,&permanent_data->smk,struct_template);
     if(ret<0)
		return ret;
     offset+=ret;     	  
}

int vtcm_export_contextkey(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_PERMANENT_DATA * permanent_data=&tcm_instance->tcm_permanent_data;

/*
     // output contextKey
     struct_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
     if(struct_template==NULL)
	return -EINVAL;
     ret=blob_2_struct(buf+offset,&permanent_data->contextKey,struct_template);
     if(ret<0)
		return ret;
     offset+=ret;   
*/  	  

     return offset;	
}

int vtcm_import_contextkey(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_PERMANENT_DATA * permanent_data=&tcm_instance->tcm_permanent_data;

/*
     // output contextKey
     struct_template=memdb_get_template(DTYPE_VTCM_IN_KEY,SUBTYPE_TCM_BIN_KEY);
     if(struct_template==NULL)
	return -EINVAL;
     ret=blob_2_struct(buf+offset,&permanent_data->contextKey,struct_template);
     if(ret<0)
		return ret;
     offset+=ret;   
*/  	  

     return offset;	
}


int vtcm_export_permanent_datatail(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_PERMANENT_DATA * permanent_data=&tcm_instance->tcm_permanent_data;

     // output pcrAttrib

     struct_template=memdb_get_template(DTYPE_VTCM_PCR,SUBTYPE_TCM_PCR_ATTRIBUTES);
     if(struct_template==NULL)
	return -EINVAL;
     for(i=0;i<TCM_NUM_PCR;i++)
     {	
     	    ret=struct_2_blob(&permanent_data->pcrAttrib[i],buf+offset,struct_template);
     	    if(ret<0)
		return ret;
            offset+=ret;
     }     	  
     return offset;	
}

int vtcm_import_permanent_datatail(void * instance,BYTE * buf)
{
    int offset=0;	
    int ret;	
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_PERMANENT_DATA * permanent_data=&tcm_instance->tcm_permanent_data;

     // output pcrAttrib

     struct_template=memdb_get_template(DTYPE_VTCM_PCR,SUBTYPE_TCM_PCR_ATTRIBUTES);
     if(struct_template==NULL)
	return -EINVAL;
     for(i=0;i<TCM_NUM_PCR;i++)
     {	
     	    ret=blob_2_struct(buf+offset,&permanent_data->pcrAttrib[i],struct_template);
     	    if(ret<0)
		return ret;
            offset+=ret;
     }     	  
     return offset;	
}

int vtcm_export_stclear_data(void * instance,BYTE * buf,int storetype)
{
    int offset=0;	
    int ret;	
    int start_addr;
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_STCLEAR_DATA * stclear_data=&tcm_instance->tcm_stclear_data;

     ret= &(((TCM_STCLEAR_DATA *)0)->disableResetLock)+sizeof(stclear_data->disableResetLock);
   
     Memcpy(buf+offset,stclear_data,ret);
     offset+=ret;

     // output authSesions
     return offset;	
}

int vtcm_import_stclear_data(void * instance,BYTE * buf,int storetype)
{
    int offset=0;	
    int ret;	
    int start_addr;
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_STCLEAR_DATA * stclear_data=&tcm_instance->tcm_stclear_data;

     ret= &(((TCM_STCLEAR_DATA *)0)->disableResetLock)+sizeof(stclear_data->disableResetLock);
   
     Memcpy(stclear_data,buf+offset,ret);
     offset+=ret;

     // output authSesions
     return offset;	
}

int vtcm_export_nv_data(void * instance, BYTE * buf)
{

    int offset=0;	
    int ret;	
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_NV_INDEX_ENTRIES * nv_data=&tcm_instance->tcm_nv_index_entries;

     // export nvIndexCount;
     Memcpy(buf+offset,nv_data,sizeof(int));
     offset+=sizeof(int);

    for(i=0;i<nv_data->nvIndexCount;i++)
    {
        // Export TCM_NV_DATA_SENSITIVE
        TCM_NV_DATA_SENSITIVE * nv_sensitive = &(nv_data->tcm_nvindex_entry[i]);
     // output pubInfo
        struct_template=memdb_get_template(DTYPE_VTCM_NV,SUBTYPE_TCM_NV_DATA_PUBLIC);
        if(struct_template==NULL)
	        return -EINVAL;
        ret=struct_2_blob(&nv_sensitive->pubInfo,buf+offset,struct_template);
        if(ret<0)
		    return ret;
        offset+=ret;     	  

        //export authValue
        ret=sizeof(TCM_AUTHDATA);
        Memcpy(buf+offset,&nv_sensitive->authValue,ret);
        offset+=ret;     	  

        ret=nv_sensitive->pubInfo.dataSize;
        Memcpy(buf+offset,nv_sensitive->data,ret);
        offset+=ret;     	  

    }    

     return offset;	
}

int vtcm_import_nv_data(void * instance, BYTE * buf)
{

    int offset=0;	
    int ret;	
    int i;	  
    void * struct_template;
    tcm_state_t * tcm_instance  =instance;
    if(instance==NULL)
	return -EINVAL;
     TCM_NV_INDEX_ENTRIES * nv_data=&tcm_instance->tcm_nv_index_entries;

    // Free current nv_data
    //
    for(i=0;i<nv_data->nvIndexCount;i++)
    {
        free(nv_data->tcm_nvindex_entry[i].data);
    }    
    free(nv_data->tcm_nvindex_entry);


     // export nvIndexCount;
     Memcpy(&nv_data->nvIndexCount, buf+offset,sizeof(int));
     offset+=sizeof(int);

    nv_data->tcm_nvindex_entry=malloc(sizeof(TCM_NV_DATA_SENSITIVE)*nv_data->nvIndexCount);

    for(i=0;i<nv_data->nvIndexCount;i++)
    {
        // Export TCM_NV_DATA_SENSITIVE
        TCM_NV_DATA_SENSITIVE * nv_sensitive = &(nv_data->tcm_nvindex_entry[i]);
     // output pubInfo
        struct_template=memdb_get_template(DTYPE_VTCM_NV,SUBTYPE_TCM_NV_DATA_PUBLIC);
        if(struct_template==NULL)
	        return -EINVAL;
        ret=blob_2_struct(buf+offset,&nv_sensitive->pubInfo,struct_template);
        if(ret<0)
		    return ret;
        offset+=ret;     	  

        //export authValue
        ret=sizeof(TCM_AUTHDATA);
        Memcpy(&nv_sensitive->authValue,buf+offset,ret);
        offset+=ret;     	  

        ret=nv_sensitive->pubInfo.dataSize;
        nv_sensitive->data=malloc(ret);
        if(nv_sensitive->data==NULL)
                return -ENOMEM;
        Memcpy(nv_sensitive->data,buf+offset,ret);
        offset+=ret;     	  
    }    
     return offset;	
}
