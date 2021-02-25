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

static s_fidoconfig noConfig;  /* "static" ensures struct is zeroed */
static hs_addr noAddr;

static int msgTotal;

static char * attrStr[] =
{
    "Private", "Crash", "Received", "Sent", "FileAttached", "InTransit",
    "Orphan", "Kill/Sent", "Local", "HoldForPickup", "unused", "FileRequest",
    "ReturnReceiptRequest", "IsReturnReceipt", "AuditRequest",  "FileUpdateReq"
};

int displayPkt(char * filename, int showHeader, int showText, int showCounters)
{
    s_pktHeader * header;
    s_message * msg;
    FILE * pkt;
    char * p;
    int i;
    char datestr[32];
    int msgCount;

    pkt = fopen(filename, "rb");

    if(pkt == NULL)
    {
        perror(filename);
        return 2;
    }

    header = openPkt(pkt);

    if(header == NULL)
    {
        printf("%s: Corrupt packet\n", filename);
        return 3;
    }

    msgCount = 0;

    printf("Packet header\n");
    printf("==============================================================================\n");

    printf("Filename       : %s\n", filename);

    printf("OrigAddr       : %u:%u/%u.%u\n",
      header->origAddr.zone, header->origAddr.net,
      header->origAddr.node, header->origAddr.point
    );

    printf("DestAddr       : %u:%u/%u.%u\n",
      header->destAddr.zone, header->destAddr.net,
      header->destAddr.node, header->destAddr.point);

    printf("AuxNet         : %u\n", header->auxNet);
    printf("CapWord        : 0x%04x\n", header->capabilityWord);

    strftime(datestr, sizeof datestr, "%a %Y-%m-%d %H:%M:%S", localtime(&header->pktCreated));
    printf("DateCreation   : %s\n", datestr);

    printf("Password       : \"%s\"\n", header->pktPassword);

    printf("ProdCode       : %02x%02x\n", header->hiProductCode, header->loProductCode);
    printf("ProdVersion    : %u.%u\n", header->majorProductRev, header->minorProductRev);

    printf("\n");

    if (showHeader)
    {
        printf("Message header\n");
        printf("------------------------------------------------------------------------------\n");
    }

    while(1 == (readMsgFromPkt(pkt, header, &msg)))
    {
        msgCount++;

        if (showHeader)
        {
            printf("From           : \"%s\"\n", msg->fromUserName);
            printf("To             : \"%s\"\n", msg->toUserName);
            printf("Subject        : \"%s\"\n", msg->subjectLine);
            printf("DateTime       : \"%s\"\n", msg->datetime);
            printf("Attr           : 0x%04x", msg->attributes);

            if (msg->attributes)
            {
                printf(" ->");
            }

            for(i = 0; i < sizeof(attrStr) / sizeof(char *); i++)
            {
                if(((1 << i) & msg->attributes) != 0)
                {
                    printf(" %s", attrStr[i]);
                }
            }

            printf("\n");
        }

        if (showHeader)
        {
	        printf("OrigAddr       : %u/%u\n", msg->origAddr.net, msg->origAddr.node);
	        printf("DestAddr       : %u/%u\n", msg->destAddr.net, msg->destAddr.node);
	    }
	    else
	    {
	        printf("%u/%u -> %u/%u\n",
	          msg->origAddr.net, msg->origAddr.node,
	          msg->destAddr.net, msg->destAddr.node);
	    }

        printf("\n");

        if (showText)
        {
	        /* convert FidoNet '\r' line endings to '\n' newlines suitable for stdout */

	        p = msg->text;

	        while (1)
	        {
	            p = strchr(p, '\r');

	            if (p == NULL)
	            {
	                break;
	            }

	            *p = '\n';
	        }

		    if (showHeader)
		    {
			    printf("Message text\n");
			    printf("------------------------------------------------------------------------------\n");
			}

            printf("%s\n", msg->text);
        }

        freeMsgBuffers(msg);
        nfree(msg);
    }

    nfree(globalBuffer); /*  free msg->text global buffer */
    nfree(header);
    fclose(pkt);

    if (showCounters)
    {
        printf("-- Messages in packet: %5d\n", msgCount);
        printf("\n");
    }

    msgTotal += msgCount;

    return 0;
}

int main(int argc, char * argv[])
{
    int i, showHeader = 0, showText = 0, showCounters = 0;
    char * cfgFile = NULL;

    versionStr = GenVersionStr("PktInfo", VER_MAJOR, VER_MINOR, VER_PATCH, VER_BRANCH, cvs_date);
    printf("%s\n\n", versionStr);
    nfree(versionStr);

    if(argc == 1)
    {
        printf(
            "Output the contents of FidoNet mail packet (*.pkt) files.\n"
            "\n"
            "Usage: pktinfo [options] <filename> [filename ...]\n"
            "\n"
            "Options:\n"
            "\n"
            "-c<cfgfile>   Specify FidoConfig config file\n"
            "-h            Display the message header information (From/To/Subject)\n"
            "-t            Display the message text\n"
            "-n            Count the number of messages\n");
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

            if(argv[i][1] == 'n')
            {
                showCounters = 1;
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
                /* make a dummy empty config if none was provided */
                config = &noConfig;

                /* avoid segfault on legacy Type 2 packets without zone info */
                noConfig.addr = &noAddr;
            }

            displayPkt(argv[i], showHeader, showText, showCounters);
        }
    }

    if (showCounters)
    {
        printf("------ Total messages: %5d\n", msgTotal);
    }

    return 0;
}
