#ifndef _HQUERY_H
#define _HQUERY_H

#include <fcommon.h>

char* makeAreaParam(s_link *creatingLink, char* c_area, char* msgbDir);

typedef struct query_areas
{
    char *name;
    char  type[5];
    struct FD
    {
      int day, month, year;
    } areaDate;
    struct FT
    {
      int hour, min;
    } areaTime;
    ps_addr downlinks;
    size_t linksCount;        
    struct query_areas *next;
//    struct query_areas *prev;
} s_query_areas;

enum  query_action{ FIND, ADDFREQ, ADDDEL };
typedef enum query_action e_query_action;

enum  changeConfigRet{ I_ERR=-2, // read config error
                       O_ERR=-1, // write config error
                       ADD_OK,   // link successfully added
                       DEL_OK    // link removed
};
typedef enum changeConfigRet e_changeConfigRet;

s_query_areas* af_CheckAreaInQuery(char *areatag, s_addr *uplink, s_addr *dwlink, e_query_action act);
int af_OpenQuery();
int af_CloseQuery();
char* makeAreaParam(s_link *creatingLink, char* c_area, char* msgbDir);



#endif
