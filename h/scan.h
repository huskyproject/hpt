#ifndef SCAN_H
#define SCAN_H
#include <fidoconfig.h>

void scan(void);
void scanEMArea(s_area *echo);
void makePktHeader(s_message *msg, s_pktHeader *header);

#endif
