#ifndef _AREAFIX_H
#define _AREAFIX_H

#include <fcommon.h>

#define NOTHING 0
#define LIST    1
#define HELP    2
#define ADD     3
#define DEL     4
#define AVAIL   5
#define UNLINK  6
#define PAUSE   7
#define RESUME  8
#define INFO    9
#define RESCAN  10
#define ERROR   255

char *print_ch(int len, char ch);
int processAreaFix(s_message *msg, s_pktHeader *pktHeader);
void afix(void);
void autoPassive();
s_message *makeMessage(s_addr *origAddr, s_addr *destAddr, char *fromName, char *toName, char *subject, char netmail);

#endif
