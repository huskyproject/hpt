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
 *****************************************************************************
 * $Id$
 */
#include <pkt.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <huskylib/huskylib.h>
#include <huskylib/typesize.h>
#include "../cvsdate.h"
#include <version.h>

int main(void)
{
    s_pktHeader header;
    s_message msg;
    FILE * pkt;
    time_t t;
    struct tm * tm;

    header.origAddr.zone   = 2;
    header.origAddr.net    = 2432;
    header.origAddr.node   = 605;
    header.origAddr.point  = 0;
    header.destAddr.zone   = 2;
    header.destAddr.net    = 2432;
    header.destAddr.node   = 605;
    header.destAddr.point  = 14;
    header.hiProductCode   = HPT_PRODCODE_HIGHBYTE;
    header.loProductCode   = HPT_PRODCODE_LOWBYTE;
    header.majorProductRev = VER_MAJOR;
    header.minorProductRev = VER_MINOR;

    /* header.pktPassword[0] = 0; */
    strcpy(header.pktPassword, "xxx");
    header.pktCreated     = time(NULL);
    header.capabilityWord = 1;
    header.prodData       = 0;
    versionStr            = GenVersionStr("tpkt",
                                          VER_MAJOR,
                                          VER_MINOR,
                                          VER_PATCH,
                                          VER_BRANCH,
                                          cvs_date);
    printf("%s\n\n", versionStr);
    w_log(LL_START, "Start");
    pkt = createPkt("test.pkt", &header);
    w_log(LL_ECHOMAIL, "Create \'test.pkt\' packet file");

    if(pkt != NULL)
    {
        msg.origAddr.zone  = 2;
        msg.origAddr.net   = 2432;
        msg.origAddr.node  = 605;
        msg.origAddr.point = 0;
        msg.destAddr.zone  = 2;
        msg.destAddr.net   = 2432;
        msg.destAddr.node  = 603;
        msg.destAddr.point = 14;
        msg.attributes     = 1;
        t  = time(NULL);
        tm = localtime(&t);
        fts_time((char *)msg.datetime, tm);
        msg.netMail = 1;
        msg.text    = (char *)malloc(300);
        strcpy(msg.text, "AREA:test.ger\rasdasd\r---\r * Origin: klj\xf6klj (2:2432/605.0)\r");
        msg.toUserName = (char *)malloc(15);
        strcpy(msg.toUserName, "arix");
        msg.fromUserName = (char *)malloc(20);
        strcpy(msg.fromUserName, "edde");
        msg.subjectLine = (char *)malloc(5);
        strcpy(msg.subjectLine, "xxx");
        msg.textLength = strlen(msg.text);
        writeMsgToPkt(pkt, &msg);
        closeCreatedPkt(pkt);
    }
    else
    {
        w_log(LL_ERR, "Could not create packet");
    } /* endif */

    w_log(LL_STOP, "End");
    return 0;
} /* main */
