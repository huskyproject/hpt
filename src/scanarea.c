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
 * Copyright (c) 1999-2001
 * Max Levenkov, sackett@mail.ru
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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <huskylib/compiler.h>
#include <huskylib/huskylib.h>
#include <huskylib/cvtdate.h>

#include <smapi/msgapi.h>

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <huskylib/xstr.h>
#include <fidoconf/afixcmd.h>
#include <huskylib/log.h>
#include <huskylib/recode.h>

#include <areafix/areafix.h>

#include <pkt.h>
#include <scan.h>
#include <seenby.h>
#include <global.h>
#include <version.h>
#include <toss.h>
#include <hpt.h>
#include <dupe.h>

#ifdef DO_PERL
#include <hptperl.h>
#endif

void makeMsg(HMSG hmsg, const XMSG * pxmsg, s_message * msg, s_area * echo, int action)
{
    /*  action == 0 - scan area */
    /*  action == 1 - rescan area */
    /*  action == 2 - rescan badarea */
    char * kludgeLines = NULL, * seenByPath = NULL;
    UCHAR * msgtid   = NULL;
    UCHAR * ctrlBuff = NULL;
    UINT32 ctrlLen;
    UCHAR tid[] = "TID";

    memset(msg, '\0', sizeof(s_message));
    msg->origAddr.zone  = pxmsg->orig.zone;
    msg->origAddr.net   = pxmsg->orig.net;
    msg->origAddr.node  = pxmsg->orig.node;
    msg->origAddr.point = pxmsg->orig.point;
    msg->destAddr.zone  = pxmsg->dest.zone;
    msg->destAddr.net   = pxmsg->dest.net;
    msg->destAddr.node  = pxmsg->dest.node;
    msg->destAddr.point = pxmsg->dest.point;
    msg->attributes     = pxmsg->attr & ~MSGLOCAL; /*  msg should not have MSGLOCAL bit set */

    /* if present, use the original DateTime string when exporting to a .PKT */

    if (*pxmsg->__ftsc_date)
    {
        memcpy(msg->datetime, pxmsg->__ftsc_date, sizeof pxmsg->__ftsc_date);
    }
    else
    {
        sc_time((union stamp_combo *)&(pxmsg->date_written), (char *)msg->datetime);
    }

    xstrcat(&msg->toUserName, (char *)pxmsg->to);
    xstrcat(&msg->fromUserName, (char *)pxmsg->from);
    xstrcat(&msg->subjectLine, (char *)pxmsg->subj);
    /*  make msgtext */
    /*  convert kludgeLines */
    ctrlLen  = MsgGetCtrlLen(hmsg);
    ctrlBuff = (UCHAR *)safe_malloc(ctrlLen + 1);
    MsgReadMsg(hmsg, NULL, 0, 0, NULL, ctrlLen, ctrlBuff);
    /* MsgReadMsg does not do zero termination! */
    ctrlBuff[ctrlLen] = '\0';

    if(action == 0 && config->disableTID == 0)
    {
        while((msgtid = GetCtrlToken(ctrlBuff, tid)) != NULL)
        {
            MsgRemoveToken(ctrlBuff, tid);
        }
        xstrscat((char **)&ctrlBuff, "\001TID: ", versionStr, NULLP);
    }

    /*  add '\r' after each kludge */
    kludgeLines = (char *)CvtCtrlToKludge(ctrlBuff);
    nfree(ctrlBuff);

    if(action == 0)
    {
        xstrcat(&seenByPath, "SEEN-BY: "); /*  9 bytes */
    }

    /*  create text */
    msg->textLength = MsgGetTextLen(hmsg); /*  with trailing \0 */
    msg->text       = NULL;

    if(action != 2)
    {
        xscatprintf(&(msg->text), "AREA:%s\r", echo->areaName);
        strUpper(msg->text + 5);
    }

    xstrcat(&(msg->text), kludgeLines);
    nfree(kludgeLines);
    ctrlLen = (UINT32)strlen(msg->text);
    xstralloc(&(msg->text), ctrlLen + msg->textLength);
    MsgReadMsg(hmsg,
               NULL,
               (dword)0,
               (dword)msg->textLength,
               (byte *)(msg->text + ctrlLen),
               (dword)0,
               (byte *)NULL);
    msg->text[msg->textLength + ctrlLen] = '\0';
    msg->textLength += ctrlLen - 1;

    /*  if origin has no ending \r add it */
    if(msg->text[msg->textLength - 1] != '\r')
    {
        xstrcat(&(msg->text), "\r");
        msg->textLength++;
    }

    if(action == 0)
    {
        xstrcat(&(msg->text), seenByPath);
        msg->textLength += 9; /*  strlen(seenByPath) */
    }

    /*  recoding from internal to transport charSet */
    if(config->outtab != NULL && action != 2)
    {
        recodeToTransportCharset((char *)msg->fromUserName);
        recodeToTransportCharset((char *)msg->toUserName);
        recodeToTransportCharset((char *)msg->subjectLine);
        recodeToTransportCharset((char *)msg->text);
    }
    else
    {
        msg->recode |= (REC_HDR | REC_TXT);
    }

    nfree(seenByPath);
} /* makeMsg */

void packEMMsg(HMSG hmsg, XMSG * xmsg, s_area * echo)
{
    s_message msg;
    s_message * messCC;

    makeMsg(hmsg, xmsg, &msg, echo, 0);

    /*  msg is dupe -- return */
    if(dupeDetection(echo, &msg) != 1)
    {
        return;
    }

#ifdef DO_PERL

    if(perlscanmsg(echo->areaName, &msg))
    {
        freeMsgBuffers(&msg);
        return;
    }

#endif

    messCC = MessForCC(&msg); /* make copy of original message*/
    /*  export msg to downlinks */
    forwardMsgToLinks(echo, &msg, *echo->useAka);

    /*  process carbon copy */
    if(config->carbonOut)
    {
        carbonCopy(messCC, xmsg, echo);
    }

    /*  mark msg as sent and scanned */
    xmsg->attr |= MSGSENT;
    xmsg->attr |= MSGSCANNED;

    if(0 != MsgWriteMsg(hmsg, 0, xmsg, NULL, 0, 0, 0, NULL))
    {
        w_log(LL_ERR,
              "Could not update msg in area %s! Check the wholeness of messagebase, please.",
              echo->areaName);
    }

    freeMsgBuffers(&msg);
    freeMsgBuffers(messCC);
    nfree(messCC);
    statScan.exported++;
    echo->scn++;
} /* packEMMsg */

void scanEMArea(s_area * echo)
{
    HAREA area;
    HMSG hmsg;
    XMSG xmsg;
    dword highestMsg, i;

    if(echo->scn)
    {
        return;
    }

    area =
        MsgOpenArea((UCHAR *)echo->fileName, MSGAREA_NORMAL,
                    (word)(echo->msgbType | MSGTYPE_ECHO));

    if(area != NULL)
    {
        statScan.areas++;
        echo->scn++;
        w_log(LL_SCANNING, "Scanning area: %s", echo->areaName);
        i          = (noHighWaters) ? 0 : MsgGetHighWater(area);
        highestMsg = MsgGetNumMsg(area);

        while(i < highestMsg)
        {
            hmsg = MsgOpenMsg(area, MOPEN_RW, ++i);

            if(hmsg == NULL)
            {
                continue;               /*  msg# does not exist */
            }

            statScan.msgs++;

            MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);

            if(((xmsg.attr & MSGSENT) != MSGSENT) && ((xmsg.attr & MSGLOCKED) != MSGLOCKED) &&
               ((xmsg.attr & MSGLOCAL) == MSGLOCAL))
            {
                packEMMsg(hmsg, &xmsg, echo);
            }

            MsgCloseMsg(hmsg);

            /*  kill msg */
            if((xmsg.attr & MSGKILL) == MSGKILL)
            {
                MsgKillMsg(area, i);
                i--;
            }
        }

        if(i < highestMsg)
        {
            MsgSetHighWater(area, i);
        }

        closeOpenedPkt();
        MsgCloseArea(area);
    }
    else
    {
        w_log(LL_SCANNING, "Could not open %s", echo->fileName);
    } /* endif */
} /* scanEMArea */

/* rescan functions taken from areafix.c */
int repackEMMsg(HMSG hmsg, const XMSG * pxmsg, s_area * echo, s_arealink * arealink)
{
    s_message msg;
    UINT32 j = 0;
    s_seenBy * seenBys = NULL, * path = NULL;
    UINT seenByCount = 0, pathCount = 0;
    s_arealink ** links;
    char * tempbefore, * addrstr, * tempafter;

    links = (s_arealink **)scalloc(2, sizeof(s_arealink *));

    if(links == NULL)
    {
        exit_hpt("out of memory", 1);
    }

    links[0] = arealink;
    makeMsg(hmsg, pxmsg, &msg, echo, 1);

    /* translating name of the area to uppercase */
    while(msg.text[j] != '\r')
    {
        msg.text[j] = (char)toupper(msg.text[j]);
        j++;
    }

    if(strncmp(msg.text + j + 1, "NOECHO", 6) == 0)
    {
        freeMsgBuffers(&msg);
        nfree(links);
        return 0;
    }

    if(!config->disableKludgeRescanned)
    {
        /* d_sergienko: Following FSC-0057 ... */
        tempbefore = (char *)scalloc(j + 1, 1);
        tempbefore = (char *)strncpy(tempbefore, msg.text, j);
        tempafter  = (char *)sstrdup(msg.text + j + 1);
        nfree(msg.text);
        xstrscat((char **)&msg.text, tempbefore, "\r\001RESCANNED ",
                 (addrstr = aka2str5d(*arealink->link->ourAka)), "\r", tempafter, NULLP);
        nfree(tempbefore);
        nfree(tempafter);
        nfree(addrstr);
    }

    createSeenByArrayFromMsg(echo, &msg, &seenBys, &seenByCount);
    createPathArrayFromMsg(&msg, &path, &pathCount);
    forwardToLinks(&msg, echo, links, &seenBys, &seenByCount, &path, &pathCount);
    freeMsgBuffers(&msg);
    nfree(links);
    nfree(seenBys);
    nfree(path);
    return 1;
} /* repackEMMsg */

int rescanEMArea(s_area * echo, s_arealink * arealink, long rescanCount, long rescanAfter)
{
    HAREA area;
    HMSG hmsg;
    XMSG xmsg;
/*   dword highestMsg; */
    dword i;
    dword * pool;            /* pool of messages to rescan */
    int n_pool = 0, s_pool;  /* actual and allocated pool size */
    unsigned int rc = 0;

    area =
        MsgOpenArea((UCHAR *)echo->fileName, MSGAREA_NORMAL,
                    (word)(echo->msgbType | MSGTYPE_ECHO));

    if(area != NULL)
    {
#if 0 /* val: change in algorithm */
        /*       i = highWaterMark = MsgGetHighWater(area); */
        i          = 0;
        highestMsg = MsgGetHighMsg(area);

        /*  if rescanCount == -1 all mails should be rescanned */
        if((rescanCount == -1) || (rescanCount > (long)highestMsg))
        {
            rescanCount = highestMsg;
        }

        while(i <= highestMsg)
        {
            if(i > highestMsg - rescanCount) /*  honour rescanCount paramater */
            {
                hmsg = MsgOpenMsg(area, MOPEN_RW, i);

                if(hmsg != NULL)   /*  msg# does not exist */
                {
                    MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
                    rc += repackEMMsg(hmsg, &xmsg, echo, arealink);
                    MsgCloseMsg(hmsg);
                }
            }

            i++;
        }
        MsgSetHighWater(area, i);
#else /* val: change in algorithm */
        i = MsgGetHighMsg(area);

        if(i > 0)
        {
            MsgSetHighWater(area, i);
        }

        if(rescanCount <= 0)
        {
            rescanCount = i;
        }

        s_pool = rescanCount > 1024 ? 1024 : rescanCount;
        pool   = safe_malloc(s_pool * sizeof(*pool));

        while(i > 0 && rescanCount > 0)
        {
            hmsg = MsgOpenMsg(area, MOPEN_RW, i--);

            if(hmsg != NULL)       /*  msg# does not exist */
            {
                MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);

                if(rescanAfter)
                {
                    struct tm stm;
                    DosDate_to_TmDate((SCOMBO *)(&xmsg.date_written), &stm);

                    if(mktime(&stm) + gettz() < rescanAfter)
                    {
                        MsgCloseMsg(hmsg);
                        continue;
                    }
                }

                /* add its number to pool of to-rescan messages */
                if(n_pool >= s_pool)
                {
                    s_pool *= 2;
                    pool    = safe_realloc(pool, s_pool * sizeof(*pool));
                }

                pool[n_pool++] = i + 1;
                rescanCount--;     /* keep track of left to rescan messages */
                MsgCloseMsg(hmsg);
            }
        }

        for(i = n_pool; i > 0; )
        {
            hmsg = MsgOpenMsg(area, MOPEN_RW, pool[--i]);

            if(hmsg != NULL)       /*  msg# does not exist */
            {
                MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
                rc += repackEMMsg(hmsg, &xmsg, echo, arealink);
                MsgCloseMsg(hmsg);
            }
        }
        nfree(pool);
#endif /* val: change in algorithm */
        MsgCloseArea(area);
        closeOpenedPkt();
    }
    else
    {
        w_log(LL_ERR, "Could not open %s: %s", echo->fileName, strerror(errno));
    }

    return rc;
} /* rescanEMArea */
