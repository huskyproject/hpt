#ifndef _HQUERY_H
#define _HQUERY_H

#include <fcommon.h>


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
    int linksCount;        
    struct query_areas *next;
//    struct query_areas *prev;
} s_query_areas;

enum  query_action{ FIND, ADDFREQ, ADDDEL };
typedef enum query_action e_query_action;

enum  changeConfigRet{ I_ERR, // reed config error
                       O_ERR, // reed config error
                       ADD_OK,// link successfully added
                       DEL_OK
};
typedef enum changeConfigRet e_changeConfigRet;

s_query_areas* af_CheckAreaInQuery(char *areatag, s_addr *uplink, s_addr *dwlink, e_query_action act);
int af_OpenQuery();
int af_CloseQuery();


#endif
