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
#define DONE    100
#define ERROR   255

char *print_ch(int len, char ch);
int processAreaFix(s_message *msg, s_pktHeader *pktHeader);
void afix(void);
void autoPassive(void);
s_message *makeMessage(s_addr *origAddr, s_addr *destAddr, char *fromName, char *toName, char *subject, int netmail);
int areaIsAvailable(char *areaName, char *fileName, char **desc, int retd);
int relink (char *straddr);

#endif
