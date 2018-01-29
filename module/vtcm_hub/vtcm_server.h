#ifndef VTCM_SERVER_H
#define VTCM_SERVER_H
#include "data_type.h"
#include <netinet/in.h>

int vtcm_server_init(void * sub_proc,void * para);
int vtcm_server_start(void * sub_proc,void * para);

#define BEGIN {
#define END }
#define LIST_ADD(c, n) \
        BEGIN       \
        n->next = c->next;   \
        c->next = n;   \
        END
#define LIST_DEL(c) \
        BEGIN   \
        free c->next; \
        c->next = NULL: \
        END

#define IP_SIZE 16

typedef struct Node {
    struct Node* next;
    char ip[IP_SIZE];
    char uuid[DIGEST_SIZE];
    BYTE hash_id[DIGEST_SIZE];
} Node, *NodeList;

typedef struct Node Nodelist;

int initList(NodeList *l)
{
    *l = (NodeList) malloc(sizeof(Node));
    if (l != NULL)
    {
        (*l)->next = NULL;
        return 0;
    }
    else 
        return -1;
}

char* getUUIDByIp(NodeList list, const char *ip)
{
   Node *p = list->next; 
   while (p) {
      if (!memcmp(ip, p->ip, Strlen(p->ip)))
          return p->uuid;
      p = p->next;
   }
   return NULL; 
}

BYTE* getHashIDByIp(NodeList list, const char *ip)
{
   Node *p = list->next; 
   while (p) {
      if (!memcmp(ip, p->ip, Strlen(p->ip)))
          return p->hash_id;
      p = p->next;
   }
   return NULL; 
}

const char * getIpByUUID(NodeList list, char *uuid)
{
    // trim uuid '-'
    int i = 0, j = 0;  
    char trim_uuid[DIGEST_SIZE];
    int len = Strlen(uuid);

    Node *p = list->next; 
    while (p) {
        if (!memcmp(uuid, trim_uuid, DIGEST_SIZE))
            return p->ip;
        p = p->next;
    }
    return NULL;
}

const char * getIpByHashID(NodeList list, BYTE * hash_id)
{
    // trim uuid '-'

    Node *p = list->next; 
    while (p) {
        if (!memcmp(hash_id, p->hash_id, DIGEST_SIZE))
            return p->ip;
        p = p->next;
    }
    return NULL;
}

#endif
