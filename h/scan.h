#ifndef SCAN_H
#define SCAN_H
#include <fidoconfig.h>

struct statScan {
   int areas, msgs;
   int exported;
};
typedef struct statScan s_statScan;

void scan(void);
void scanEMArea(s_area *echo);
void makePktHeader(s_message *msg, s_pktHeader *header);

#endif
