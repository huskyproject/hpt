#ifndef _AREAFIX_H
#define _AREAFIX_H

#include <fcommon.h>

#define NOTHING 0
#define LIST    1
#define HELP    2
#define ADD     3
#define DEL     4
#define AVAIL   5
#define QUERY   6
#define UNLINK  7
#define PAUSE   8
#define RESUME  9
#define INFO    10
#define RESCAN  11
#define REMOVE  12
#define ADD_RSC 13 
#define DONE    100
#define STAT    101
#define ERROR   255

char *print_ch(int len, char ch);
int processAreaFix(s_message *msg, s_pktHeader *pktHeader, unsigned force_pwd);
void afix(s_addr addr, char *cmd);
void autoPassive(void);
s_message *makeMessage(s_addr *origAddr, s_addr *destAddr, char *fromName, char *toName, char *subject, int netmail);
int areaIsAvailable(char *areaName, char *fileName, char **desc, int retd);
int relink (char *straddr);
void addlink(s_link *link, s_area *area);
char *rescan(s_link *link, char *cmd);
char *errorRQ(char *line);
int isPatternLine(char *s);
void makeMsgToSysop(char *areaName, s_addr fromAddr, s_addr *uplinkAddr);
int forwardRequest(char *areatag, s_link *dwlink, s_link **lastRlink);
int forwardRequestToLink (char *areatag, s_link *uplink, s_link *dwlink, int act);
void sendAreafixMessages();
char *do_delete(s_link *link, s_area *area);

#endif
