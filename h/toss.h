/*:ts=8*/
/*****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 * Copyright (C) 1997-1999
 *
 * Matthias Tichy
 *
 * Fido:     2:2433/1245 2:2433/1247 2:2432/605.14
 * Internet: mtt@tichy.de
 *
 * Grimmestr. 12         Buchholzer Weg 4
 * 33098 Paderborn       40472 Duesseldorf
 * Germany               Germany
 *
 * This file is part of HPT.
 *
 * HPT is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * HPT is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with HPT; see the file COPYING.  If not, write to the Free
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *****************************************************************************/
#ifndef TOSS_H
#define TOSS_H
#include <pkt.h>

struct statToss {
   int pkts, msgs;
   int saved, passthrough, exported;
   int echoMail, netMail;
   int dupes, bad;
   int inBytes;
   time_t startTossing;
};
typedef struct statToss s_statToss;

enum tossSecurity {secLocalInbound, secProtInbound, secInbound};
typedef enum tossSecurity e_tossSecurity;

int  to_us(const s_addr destAddr);
void processEMMsg(s_message *msg, s_addr pktOrigAddr);
void processNMMsg(s_message *msg, s_pktHeader *pktHeader);
void processMsg(s_message *msg, s_pktHeader *pktHeader);
int  processPkt(char *fileName, e_tossSecurity sec);
void putMsgInArea(s_area *echo, s_message *msg, int strip);
void toss(void);
void tossTempOutbound(char *directory); 
void arcmail(void);
int autoCreate(char *c_area, s_addr pktOrigAddr);
void tossFromBadArea(void);

int readCheck(s_area *echo, s_link *link);
// '\x0000' access o'k
// '\x0001' no access group
// '\x0002' no access level
// '\x0003' no access export
// '\x0004' not linked

int writeCheck(s_area *echo, s_link *link);
// '\x0000' access o'k
// '\x0001' no access group
// '\x0002' no access level
// '\x0003' no access import
// '\x0004' not linked

#endif
