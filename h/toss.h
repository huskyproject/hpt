#ifndef TOSS_H
#define TOSS_H
#include <pkt.h>

int  to_us(s_pktHeader header);
void processEMMsg(s_message *msg, s_addr pktOrigAddr);
void processNMMsg(s_message *msg);
void processMsg(s_message *msg, s_addr pktOrigAddr);
void processPkt(char *fileName, int onlyNetmail);
void toss(void);

#endif
