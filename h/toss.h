#ifndef TOSS_H
#define TOSS_H
#include <pkt.h>

struct statToss {
   int pkts, msgs;
   int saved, passthrough, exported;
   int echoMail, netMail;
   int dupes, bad;
};
typedef struct statToss s_statToss;

int  to_us(s_pktHeader header);
void processEMMsg(s_message *msg, s_addr pktOrigAddr);
void processNMMsg(s_message *msg);
void processMsg(s_message *msg, s_addr pktOrigAddr);
int  processPkt(char *fileName, int onlyNetmail);
void toss(void);
void arcmail(void);

#endif
