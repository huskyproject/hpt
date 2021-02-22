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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include <fidoconf/common.h>
#include <fidoconf/afixcmd.h>

#include <areafix/areafix.h>
#include <global.h>
#include <pkt.h>
#include <version.h>
#include "../cvsdate.h"


static char * attrStr[] =
{
    "pvt", "crash", "read", "sent", "att", "fwd", "orphan", "k/s", "loc", "hld", "xx2", "frq",
    "rrq", "cpt",   "arq",  "urq"
};
int displayPkt(char * name, int showHeader, int showText)
{
    s_pktHeader * header;
    s_message * msg;
    FILE * pkt;
    char * p;
    int i;

    pkt = fopen(name, "rb");

    if(pkt == NULL)
    {
        printf("couldn't open %s\n", name);
        return 2;
    }

    header = openPkt(pkt);

    if(header == NULL)
    {
        printf("wrong or no pkt\n");
        return 3;
    }

    printf("Pkt-Name:     %s\n", name);
    printf("OrigAddr:     %u:%u/%u.%u\n",
           header->origAddr.zone,
           header->origAddr.net,
           header->origAddr.node,
           header->origAddr.point);
    printf("DestAddr:     %u:%u/%u.%u\n",
           header->destAddr.zone,
           header->destAddr.net,
           header->destAddr.node,
           header->destAddr.point);
    printf("pkt created:  %s", ctime(&header->pktCreated));
    printf("pkt Password: %s\n", header->pktPassword);

    /*  printf("pktVersion:   %u\n", header->pktVersion);*/
    printf("prodCode:     %02x%02x\n", header->hiProductCode, header->loProductCode);
    printf("prodRevision  %u.%u\n", header->majorProductRev, header->minorProductRev);
    printf("----------------------------------------\n");

    while(1 == (readMsgFromPkt(pkt, header, &msg)))
    {
        printf("Msg: %u/%u -> %u/%u\n",
               msg->origAddr.net,
               msg->origAddr.node,
               msg->destAddr.net,
               msg->destAddr.node);

        /* Fix this \r's FIXME: and how does it do on non-*nix systems ? */
        for(p = msg->text; (p = strchr(p, '\r')) != NULL; )
        {
            *p = '\n';
        }

        if(showHeader)
        {
            printf("Written at %s\n", msg->datetime);
            printf("From:    %s\nTo:      %s\nSubject: %s\n",
                   msg->fromUserName,
                   msg->toUserName,
                   msg->subjectLine);
            printf("Attr:   ");

            for(i = 0; i < sizeof(attrStr) / sizeof(char *); i++)
            {
                if(((1 << i) & msg->attributes) != 0)
                {
                    printf(" %s", attrStr[i]);
                }
            }
            printf("\n");
        }

        if(showText)
        {
            printf("--Text----\n%s\n", msg->text);
        }

        freeMsgBuffers(msg);
        nfree(msg);
    } /* endwhile */
    nfree(globalBuffer); /*  free msg->text global buffer */
    nfree(header);
    fclose(pkt);
    printf("\n\n");
    return 0;
} /* displayPkt */

static struct fidoconfig noConfig;  /* "static" ensures struct is zeroed */

int main(int argc, char * argv[])
{
    int i, showHeader = 0, showText = 0;
    char * cfgFile = NULL;

/*  printf("PktInfo v%u.%u.%u\n",VER_MAJOR, VER_MINOR, VER_PATCH); */
    versionStr = GenVersionStr("PktInfo", VER_MAJOR, VER_MINOR, VER_PATCH, VER_BRANCH, cvs_date);
    printf("%s\n\n", versionStr);
    nfree(versionStr);

    if(argc == 1)
    {
        printf(
            "usage: pktinfo [options] <pktNames>\n" "Options: -h\t- means display msg header information (from/to/subject)\n"
                                                    "\t -t\t- means display msg text\n");
        return 1;
    }

    for(i = 1; i < argc; i++)
    {
        if(argv[i][0] == '-')
        {
            if(argv[i][1] == 'c')
            {
                cfgFile = argv[++i];
            }

            if(argv[i][1] == 'h')
            {
                showHeader = 1;
            }

            if(argv[i][1] == 't')
            {
                showText = 1;
            }
        }
        else
        {
            if (cfgFile || getenv("FIDOCONFIG"))
            {
                config = readConfig(cfgFile);
            }
            else
            {
                config = &noConfig;
            }

            displayPkt(argv[i], showHeader, showText);
        }
    }
    return 0;
} /* main */
