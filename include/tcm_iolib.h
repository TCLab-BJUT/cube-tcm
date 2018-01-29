#ifndef TCM_IOLIB_H
#define TCM_IOLIB_H

int vtcm_instance_export(void * instance, BYTE * buf,int storetype);
int vtcm_instance_import(void * instance, BYTE * buf,int storetype);
#endif
