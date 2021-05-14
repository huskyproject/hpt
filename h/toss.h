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

typedef struct statToss
{
    int arch, pkts, msgs;
    int saved, passthrough, exported, CC;
    int echoMail, netMail;
    int dupes, bad, empty;
    int inBytes;
/*    time_t startTossing; */
    time_t realTime;
} s_statToss;

typedef enum tossSecurity
{
    secLocalInbound,
    secProtInbound,
    secInbound
} e_tossSecurity;

typedef enum processPktResult
{
    prPkt_OK,               /* 0 */
    prPkt_PasswdErr,        /* 1 */
    prPkt_CantOpenPkt,      /* 2 */
    prPkt_BadPktFmt,        /* 3 */
    prPkt_NotToUs,          /* 4 */
    prPkt_WriteErr,         /* 5 */
    prPkt_PerlFltReject,    /* 6 */
    prPkt_UnknownErr        /* 7 */
} e_processPktResult;

bool processEMMsg(s_message * msg, hs_addr pktOrigAddr, int dontdocc, dword forceattr);
bool processNMMsg(s_message * msg,
                 s_pktHeader * pktHeader,
                 s_area * area,
                 int dontdocc,
                 dword forceattr);
bool processMsg(s_message * msg, s_pktHeader * pktHeader, int secure);
e_processPktResult processPkt(char * fileName, e_tossSecurity sec);
bool putMsgInArea(s_area * echo, s_message * msg, int strip, dword forceattr);
void makeMsgToSysop(char * areaName, hs_addr fromAddr, ps_addr uplinkAddr);
void toss(void);
void tossTempOutbound(char * directory);
void arcmail(s_link * link);
void tossFromBadArea(char force);
void writeMsgToSysop(void);
void forwardToLinks(s_message * msg,
                    s_area * echo,
                    s_arealink ** newLinks,
                    s_seenBy ** seenBys,
                    UINT * seenByCount,
                    s_seenBy ** path,
                    UINT * pathCount);
void forwardMsgToLinks(s_area * echo, s_message * msg, hs_addr pktOrigAddr);
int carbonCopy(s_message * msg, XMSG * xmsg, s_area * echo);
void closeOpenedPkt(void);
bool isArcMail(char * fname);
s_message * MessForCC(s_message * msg);

#define REC_HDR 0x0001
#define REC_TXT 0x0002

#endif /* ifndef TOSS_H */
