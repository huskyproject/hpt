/* $Id$ */

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
#include <seenby.h>

struct statToss {
   int arch, pkts, msgs;
   int saved, passthrough, exported, CC;
   int echoMail, netMail;
   int dupes, bad, empty;
   int inBytes;
/*    time_t startTossing; */
   time_t realTime;
};
typedef struct statToss s_statToss;

enum tossSecurity {secLocalInbound, secProtInbound, secInbound};
typedef enum tossSecurity e_tossSecurity;


int  processEMMsg(s_message *msg, hs_addr pktOrigAddr, int dontdocc, dword forceattr);
int  processNMMsg(s_message *msg, s_pktHeader *pktHeader, s_area *area, int dontdocc, dword forceattr);
int  processMsg(s_message *msg, s_pktHeader *pktHeader, int secure);
int  processPkt(char *fileName, e_tossSecurity sec);
int  putMsgInArea(s_area *echo, s_message *msg, int strip, dword forceattr);
void toss(void);
void tossTempOutbound(char *directory); 
void arcmail(s_link *link);
int  autoCreate(char *c_area, hs_addr pktOrigAddr, ps_addr forwardAddr);
void tossFromBadArea(char force);
void writeMsgToSysop(void);
int  checkAreaLink(s_area *area, hs_addr aka, int type);
void forwardMsgToLink(s_message *msg, s_area *echo, s_link *link,
                    s_seenBy *seenBys, UINT16 seenByCount,
                    s_seenBy *pathArray, UINT16 pathArrayCount);
void forwardMsgToLinks(s_area *echo, s_message *msg, hs_addr pktOrigAddr);
int  carbonCopy(s_message *msg, XMSG *xmsg, s_area *echo);
s_arealink *getAreaLink(s_area *area, hs_addr aka);
void closeOpenedPkt(void);
int  isArcMail(char *fname);

s_message* MessForCC(s_message *msg);

#define REC_HDR 0x0001
#define REC_TXT 0x0002

#endif
