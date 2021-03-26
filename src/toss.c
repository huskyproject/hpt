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
 * Copyright (C) 1999-2002
 *
 * Max Levenkov
 *
 * Fido:     2:5000/117
 * Internet: sackett@mail.ru
 * Novosibirsk, West Siberia, Russia
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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
/* compiler.h */
#include <huskylib/compiler.h>


#if (defined (__EMX__) || defined (__MINGW32__)) && defined (__NT__)
/* we can't include windows.h for prevent compiler errors ... */
/*#  include <windows.h>*/
#  define CharToOem CharToOemA
#endif

#ifdef HAS_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAS_IO_H
#include <io.h>
#endif

#if defined (__OS2__)
#include <os2.h>
#endif

#ifdef HAS_DOS_H
#include <dos.h>
#endif

#if  defined (__NT__)
/* we can't include windows.h for several reasons ... */
#define GetFileAttributes GetFileAttributesA
#endif
/* huskylib */
#include <huskylib/huskylib.h>
#include <huskylib/cvtdate.h>
#include <huskylib/dirlayer.h>
/* smapi */
#include <smapi/msgapi.h>
/* fidoconf */
#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <huskylib/dirlayer.h>
#include <huskylib/xstr.h>
#include <fidoconf/afixcmd.h>
#include <huskylib/temp.h>
#include <huskylib/recode.h>
#include <fidoconf/stat.h>
#include <areafix/areafix.h>
#include <areafix/query.h>

#if defined (A_HIDDEN) && !defined (_A_HIDDEN)
#define _A_HIDDEN A_HIDDEN
#endif

#ifdef USE_HPTZIP
#   include <hptzip/hptzip.h>
#endif
/* hpt */
#include <pkt.h>
#include <scan.h>
#include <toss.h>
#include <global.h>
#include <seenby.h>
#include <dupe.h>
#include <version.h>
#include <scanarea.h>
#include <fcommon.h>
#include <hpt.h>
#ifdef DO_PERL
#include <hptperl.h>
#endif


#if defined (__MINGW32__) || (defined (__WATCOMC__) && (__WATCOMC__ < 1100))
#define NOSLASHES
#endif

#ifdef DO_PERL
extern int perl_setattr; /* perl.c */
#endif


extern s_message ** msgToSysop;
int save_err;
static ULONG nopenpkt, maxopenpkt;
s_statToss statToss;
int forwardPkt(const char * fileName, s_pktHeader * header, e_tossSecurity sec);
int processDir(char * directory, e_tossSecurity sec);
void makeMsgToSysop(char * areaName, hs_addr fromAddr, ps_addr uplinkAddr);
static void setmaxopen(void);

char * (BadmailReasonString[BM_MAXERROR + 1]) =
{
/* 0*/ "No reason",
/* 1*/ "System not allowed to create new area",
/* 2*/ "Sender not allowed to post in this area (access group)",
/* 3*/ "Sender not allowed to post in this area (access level)",
/* 4*/ "Sender not allowed to post in this area (access import)",
/* 5*/ "Sender not active for this area",
/* 6*/ "Rejected by perl filter",
/* 7*/ "MSGAPI error",
/* 8*/ "Can't create echoarea with forbidden symbols in areatag",
/* 9*/ "Sender not found in config file",
/*10*/ "Can't open config file",
/*11*/ "No downlinks for passthrough area",
/*12*/ "Length of CONFERENCE name is more than 60 symbols",
/*13*/ "Area killed (unsubscribed)",
/*14*/ "New area refused by NewAreaRefuseFile",
/*15*/ "Wrong link to autocreate from (area requested from other link)",
/*16*/ "Area is paused (unsubscribed at uplink)",
/*17*/ "No valid areatag is given in the message",
/*18*/ "Can't create subdirectories for echobase",
/*19*/ "Mail considered to be too old",
/*20*/ "Mail considered to be too new"
};
static char * get_filename(char * pathname)
{
    char * ptr = NULL;

    if(pathname == NULL || !(*pathname))
    {
        return pathname;
    }

    ptr = pathname + strlen(pathname) - 1;

    while(*ptr != '/' && *ptr != '\\' && *ptr != ':' && ptr != pathname)
    {
        ptr--;
    }

    if(*ptr == '/' || *ptr == '\\' || *ptr == ':')
    {
        ptr++;
    }

    return ptr;
}

/* return value: 1 if success, 0 if fail */
int putMsgInArea(s_area * echo, s_message * msg, int strip, dword forceattr)
{
    char * ctrlBuff = NULL, * textStart = NULL, * textWithoutArea = NULL;
    size_t textLength = (size_t)msg->textLength;
    /* HAREA harea = NULL; */
    HMSG hmsg;
    XMSG xmsg;
    char /**slash,*/ * p, * q, * tiny;
    int rc     = 0;
    int recode = 1;

    if(echo->msgbType == MSGTYPE_PASSTHROUGH)
    {
        w_log(LL_ERR, "Can't put message to passthrough area %s!", echo->areaName);
        return rc;
    }

    if(!msg->netMail)
    {
        msg->destAddr.zone  = echo->useAka->zone;
        msg->destAddr.net   = echo->useAka->net;
        msg->destAddr.node  = echo->useAka->node;
        msg->destAddr.point = echo->useAka->point;
    }

#ifdef DO_PERL

    switch(perl_putmsg(echo, msg))
    {
        case 0:
            return 1;

        case 2:
            recode = 0;

        default:
            textLength = (UINT)msg->textLength;
    }
#endif

    if(maxopenpkt == 0)
    {
        setmaxopen();
    }

    if(echo->harea == NULL)
    {
        w_log(LL_SRCLINE, "%s:%d opening %s", __FILE__, __LINE__, echo->fileName);
        echo->harea =
            MsgOpenArea((UCHAR *)echo->fileName, MSGAREA_CRIFNEC,
                        (word)(echo->msgbType | (msg->netMail ? 0 : MSGTYPE_ECHO)));

        if(echo->harea)
        {
            nopenpkt += 3;
        }
    }

    if(echo->harea != NULL)
    {
        w_log(LL_SRCLINE, "%s:%d creating msg", __FILE__, __LINE__);
        hmsg = MsgOpenMsg(getHAREA(echo->harea), MOPEN_CREATE, 0);

        if(hmsg != NULL)
        {
            /*  recode from TransportCharset to internal Charset */
            if((config->recodeMsgBase) && (recode && config->intab != NULL))
            {
                if((msg->recode & REC_HDR) == 0)
                {
                    recodeToInternalCharset((char *)msg->fromUserName);
                    recodeToInternalCharset((char *)msg->toUserName);
                    recodeToInternalCharset((char *)msg->subjectLine);
                    msg->recode |= REC_HDR;
                }

                if((msg->recode & REC_TXT) == 0)
                {
                    recodeToInternalCharset((char *)msg->text);
                    msg->recode |= REC_TXT;
                }
            }

            textWithoutArea = msg->text;

            if((strip == 1) && (strncmp(msg->text, "AREA:", 5) == 0))
            {
                /*  jump over AREA:xxxxx\r */
                while(*(textWithoutArea) != '\r')
                {
                    textWithoutArea++;
                }
                textWithoutArea++;
                textLength -= (size_t)(textWithoutArea - msg->text);
            }

            if(echo->killSB)
            {
                tiny = strrstr(textWithoutArea, " * Origin:");

                if(tiny == NULL)
                {
                    tiny = textWithoutArea;
                }

                if(NULL != (p = strstr(tiny, "\rSEEN-BY: ")))
                {
                    p[1]       = '\0';
                    textLength = (size_t)(p - textWithoutArea + 1);
                }
            }
            else if(echo->tinySB)
            {
                tiny = strrstr(textWithoutArea, " * Origin:");

                if(tiny == NULL)
                {
                    tiny = textWithoutArea;
                }

                if(NULL != (p = strstr(tiny, "\rSEEN-BY: ")))
                {
                    p++;

                    if(NULL != (q = strstr(p, "\001PATH: ")))
                    {
                        /*  memmove(p,q,strlen(q)+1); */
                        memmove(p, q, textLength - (size_t)(q - textWithoutArea) + 1);
                        textLength -= (size_t)(q - p);
                    }
                    else
                    {
                        p[0]       = '\0';
                        textLength = (size_t)(p - textWithoutArea);
                    }
                }
            }

            ctrlBuff = (char *)CopyToControlBuf((UCHAR *)textWithoutArea,
                                                (UCHAR **)&textStart,
                                                (unsigned int *)&textLength);
            /*  textStart is a pointer to the first non-kludge line */
            xmsg = createXMSG(config, msg, NULL, forceattr, tossDir);
            w_log(LL_SRCLINE, "%s:%d writing msg", __FILE__, __LINE__);

            if(MsgWriteMsg(hmsg, 0, &xmsg, (byte *)textStart, (dword)textLength, (dword)textLength,
                           (dword)strlen(ctrlBuff), (byte *)ctrlBuff) != 0)
            {
                w_log(LL_ERR,
                      "Could not write msg in %s! Check the wholeness of messagebase, please.",
                      echo->fileName);
            }
            else
            {
                rc = 1; /*  normal exit */
            }

            w_log(LL_SRCLINE, "%s:%d closing msg", __FILE__, __LINE__);

            if(MsgCloseMsg(hmsg) != 0)
            {
                w_log(LL_ERR, "Could not close msg in %s!", echo->fileName);
                rc = 0;
            }

            nfree(ctrlBuff);
        }
        else
        {
            w_log(LL_ERR, "Could not create new msg in %s!", echo->fileName);
        }

        /* endif */
        if(nopenpkt >= maxopenpkt - 12)
        {
            w_log(LL_SRCLINE, "%s:%d closing %s", __FILE__, __LINE__, echo->fileName);
            MsgCloseArea(getHAREA(echo->harea));
            echo->harea = NULL;
            nopenpkt   -= 3;
        }
    }
    else
    {
        w_log(LL_ERR, "Could not open/create EchoArea %s!", echo->fileName);
    }

    /* endif */
    w_log(LL_SRCLINE, "%s:%d end rc=%d", __FILE__, __LINE__, rc);
    return rc;
} /* putMsgInArea */

void closeOpenedPkt(void)
{
    unsigned int i;

    for(i = 0; i < config->linkCount; i++)
    {
        if(config->links[i]->pkt)
        {
            if(closeCreatedPkt(config->links[i]->pkt))
            {
                w_log(LL_ERR, "can't close pkt: %s", config->links[i]->pktFile);
            }

            config->links[i]->pkt = NULL;
            nopenpkt--;
        }
    }

    for(i = 0; i < config->echoAreaCount; i++)
    {
        if(getHAREA(config->echoAreas[i].harea))
        {
            w_log(LL_SRCLINE, "%s:%d closing %s", __FILE__, __LINE__,
                  config->echoAreas[i].fileName);
            MsgCloseArea(getHAREA(config->echoAreas[i].harea));
            config->echoAreas[i].harea = NULL;
            nopenpkt -= 3;
        }
    }

    for(i = 0; i < config->netMailAreaCount; i++)
    {
        if(getHAREA(config->netMailAreas[i].harea))
        {
            w_log(LL_SRCLINE,
                  "%s:%d closing %s",
                  __FILE__,
                  __LINE__,
                  config->netMailAreas[i].fileName);
            MsgCloseArea(getHAREA(config->netMailAreas[i].harea));
            config->netMailAreas[i].harea = NULL;
            nopenpkt -= 3;
        }
    }

    for(i = 0; i < config->localAreaCount; i++)
    {
        if(getHAREA(config->localAreas[i].harea))
        {
            w_log(LL_SRCLINE,
                  "%s:%d closing %s",
                  __FILE__,
                  __LINE__,
                  config->localAreas[i].fileName);
            MsgCloseArea(getHAREA(config->localAreas[i].harea));
            config->localAreas[i].harea = NULL;
            nopenpkt -= 3;
        }
    }

    if(getHAREA(config->badArea.harea))
    {
        w_log(LL_SRCLINE, "%s:%d closing %s", __FILE__, __LINE__, config->badArea.fileName);
        MsgCloseArea(getHAREA(config->badArea.harea));
        config->badArea.harea = NULL;
        nopenpkt -= 3;
    }

    if(getHAREA(config->dupeArea.harea))
    {
        w_log(LL_SRCLINE, "%s:%d closing %s", __FILE__, __LINE__, config->dupeArea.fileName);
        MsgCloseArea(getHAREA(config->dupeArea.harea));
        config->dupeArea.harea = NULL;
        nopenpkt -= 3;
    }
} /* closeOpenedPkt */

void forwardToLinks(s_message * msg,
                    s_area * echo,
                    s_arealink ** newLinks,
                    s_seenBy ** seenBys,
                    UINT * seenByCount,
                    s_seenBy ** path,
                    UINT * pathCount)
{
    unsigned int i, rc = 0;
    ULONG len;
    FILE * f = NULL;
    s_pktHeader header;
    char * start = NULL, * text = NULL, * seenByText = NULL, * pathText = NULL;
    char * debug = NULL;

    if(newLinks[0] == NULL)
    {
        return;
    }

    if(echo->debug)
    {
        xstrscat(&debug,
                 config->logFileDir,
                 (echo->DOSFile) ? "common" : echo->areaName,
                 ".dbg",
                 NULLP);

        if(config->areasFileNameCase == eLower)
        {
            debug = strLower(debug);
        }
        else
        {
            debug = strUpper(debug);
        }

        if((f = fopen(debug, "a")) == NULL)
        {
            w_log(LL_ERR, "can't open file: %s", debug);
        }
        else
        {
            w_log(LL_FILE, "toss.c:forwardToLinks(): opened %s (\"a\" mode)", debug);
        }

        nfree(debug);
    }

    if(echo->sbstripCount > 0)     /* strip SEEN-BYs */
    {
        stripSeenByArray(seenBys, seenByCount, echo->sbstrip, echo->sbstripCount);
    }

    for(i = 0; i < config->addToSeenCount; i++)
    {
        (*seenByCount)++;
        (*seenBys) = (s_seenBy *)safe_realloc(*seenBys, sizeof(s_seenBy) * (*seenByCount));
        (*seenBys)[*seenByCount - 1].net  = (UINT16)config->addToSeen[i].net;
        (*seenBys)[*seenByCount - 1].node = (UINT16)config->addToSeen[i].node;
    }

    for(i = 0; i < echo->sbaddCount; i++)
    {
        (*seenByCount)++;
        (*seenBys) = (s_seenBy *)safe_realloc(*seenBys, sizeof(s_seenBy) * (*seenByCount));
        (*seenBys)[*seenByCount - 1].net  = (UINT16)echo->sbadd[i].net;
        (*seenBys)[*seenByCount - 1].node = (UINT16)echo->sbadd[i].node;
    }

    /*  add our aka to seen-by (zonegating link must strip our aka) */
    if(echo->useAka->point == 0)
    {
        for(i = 0; i < *seenByCount; i++)
        {
            if((*seenBys)[i].net == echo->useAka->net && (*seenBys)[i].node == echo->useAka->node)
            {
                break;
            }
        }

        if(*seenByCount == i)
        {
            (*seenBys) =
                (s_seenBy *)safe_realloc((*seenBys), sizeof(s_seenBy) * (*seenByCount + 1));
            (*seenBys)[*seenByCount].net  = (UINT16)echo->useAka->net;
            (*seenBys)[*seenByCount].node = (UINT16)echo->useAka->node;
            (*seenByCount)++;
        }
    }

    /*  add seenBy for newLinks */
    for(i = 0; i < echo->downlinkCount; i++)
    {
        /*  no link at this index -> break */
        if(newLinks[i] == NULL)
        {
            break;
        }

        /*  don't include points in SEEN-BYs */
        if(newLinks[i]->link->hisAka.point != 0)
        {
            continue;
        }

        /*  fix for IgnoreSeen & -sbign */
        if(newLinks[i]->link->sb == 1)
        {
            continue;
        }

        (*seenBys) = (s_seenBy *)safe_realloc((*seenBys), sizeof(s_seenBy) * (*seenByCount + 1));
        (*seenBys)[*seenByCount].net  = (UINT16)newLinks[i]->link->hisAka.net;
        (*seenBys)[*seenByCount].node = (UINT16)newLinks[i]->link->hisAka.node;
        (*seenByCount)++;
    }
    sortSeenBys((*seenBys), *seenByCount);

#ifdef DEBUG_HPT

    for(i = 0; i < *seenByCount; i++)
    {
        printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
    }
#endif

    if(*pathCount > 0)
    {
        if(((*path)[*pathCount - 1].net != echo->useAka->net) ||
           ((*path)[*pathCount - 1].node != echo->useAka->node))
        {
            /*  add our aka to path */
            (*path) = (s_seenBy *)safe_realloc((*path), sizeof(s_seenBy) * (*pathCount + 1));
            (*path)[*pathCount].net  = (UINT16)echo->useAka->net;
            (*path)[*pathCount].node = (UINT16)echo->useAka->node;
            (*pathCount)++;
        }
    }
    else
    {
        (*pathCount)             = 0;
        (*path)                  = (s_seenBy *)safe_realloc((*path), sizeof(s_seenBy));
        (*path)[*pathCount].net  = (UINT16)echo->useAka->net;
        (*path)[*pathCount].node = (UINT16)echo->useAka->node;
        (*pathCount)             = 1;
    }

#ifdef DEBUG_HPT

    for(i = 0; i < *pathCount; i++)
    {
        printf("%u/%u ", (*path)[i].net, (*path)[i].node);
    }
#endif

    text = strrstr(msg->text, " * Origin:"); /*  jump over Origin */

    if(text)    /*  origin was found */
    {
        start = strrchr(text, ')');

        if(start)
        {
            start++;        /*  normal origin */
        }
        else
        {
            start = text; /*  broken origin */

            while(*start && *start != '\r')
            {
                start++;
            }
        }

        *start = '\0';
    }
    else     /*  no Origin found */
    {
        text  = msg->text;
        start = strstr(text, "\rSEEN-BY: ");

        if(start == NULL)
        {
            start = strstr(text, "SEEN-BY: ");
        }

        if(start)
        {
            *start = '\0';
        }

        /*  find start of PATH in Msg */
        start = strstr(text, "\001PATH: ");

        if(start)
        {
            *start = '\0';
        }
        else
        {
            start = text + strlen(text);
        }
    }

    msg->textLength = (hINT32)(start - msg->text);
    /*  create new seenByText */
    seenByText = createControlText(*seenBys, *seenByCount, "SEEN-BY: ");
    pathText   = createControlText(*path, *pathCount, "\001PATH: ");
    xstrscat(&msg->text, "\r", seenByText, pathText, NULLP);
    msg->textLength += (hINT32)(1 + strlen(seenByText) + strlen(pathText));
    nfree(seenByText);
    nfree(pathText);

    if(echo->debug)
    {
        debug = (char *)GetCtrlToken((byte *)msg->text, (byte *)"MSGID");

        if(f && debug)
        {
            fputs("\n[", f);
            fputs(debug, f);
            fputs("] ", f);
        }

        nfree(debug);
    }

    /*  add msg to the pkt's of the downlinks */
    if(maxopenpkt == 0)
    {
        setmaxopen();
    }

    for(i = 0; i < echo->downlinkCount; i++)
    {
        /*  no link at this index -> break; */
        if(newLinks[i] == NULL)
        {
            break;
        }

#ifdef DO_PERL

        if(!perl_export(echo, newLinks[i]->link, msg))
        {
            continue;
        }

#endif

        /*  check packet size */
        if(newLinks[i]->link->pktFile != NULL && newLinks[i]->link->pktSize != 0)
        {
            len = (ULONG)(newLinks[i]->link->pkt ? ftell(newLinks[i]->link->pkt) :
                          fsize(newLinks[i]->link->pktFile));

            if(len >= (newLinks[i]->link->pktSize * 1024L)) /* Stop writing to pkt */
            {
                if(newLinks[i]->link->pkt)
                {
                    fclose(newLinks[i]->link->pkt);
                    newLinks[i]->link->pkt = NULL;
                    nopenpkt--;
                }

                nfree(newLinks[i]->link->pktFile);
                nfree(newLinks[i]->link->packFile);
            }
        }

        /*  create pktfile if necessary */
        if(newLinks[i]->link->pktFile == NULL)
        {
            /*  pktFile does not exist */
            if(createTempPktFileName(newLinks[i]->link))
            {
                exit_hpt("Could not create new pkt!", 1);
            }
        }

        makePktHeader(NULL, &header);
        header.origAddr = *(newLinks[i]->link->ourAka);
        header.destAddr = newLinks[i]->link->hisAka;

        if(newLinks[i]->link->pktPwd != NULL)
        {
            strcpy(header.pktPassword, newLinks[i]->link->pktPwd);
        }

        if(newLinks[i]->link->pkt == NULL)
        {
            newLinks[i]->link->pkt = openPktForAppending(newLinks[i]->link->pktFile, &header);
            nopenpkt++;
        }

        /*  an echomail msg must be adressed to the link */
        msg->destAddr = header.destAddr;
        /*  .. and must come from us */
        msg->origAddr = header.origAddr;
        rc           += writeMsgToPkt(newLinks[i]->link->pkt, msg);

        if(rc)
        {
            w_log(LL_ERR, "can't write msg to pkt: %s", newLinks[i]->link->pktFile);
            exit_hpt("Can't write msg to pkt!", 1);
        }

        if(nopenpkt >= maxopenpkt - 12 || /*  std streams, in pkt, msgbase, log */
           (newLinks[i]->link->pktSize &&
            ftell(newLinks[i]->link->pkt) >= (long)newLinks[i]->link->pktSize * 1024L))
        {
            rc += closeCreatedPkt(newLinks[i]->link->pkt);

            if(rc)
            {
                w_log(LL_ERR, "can't close pkt: %s", newLinks[i]->link->pktFile);
            }

            newLinks[i]->link->pkt = NULL;
            nopenpkt--;
        }

        if(f)
        {
            if(rc)
            {
                fputs(" failed: ", f);
            }

            fputs(aka2str(&header.destAddr), f);
            fputc('>', f);
            fputs(get_filename(newLinks[i]->link->pktFile), f);
            fputc(' ', f);
        }

        if(rc == 0)
        {
            statToss.exported++;
        }
        else
        {
            rc = 0;
        }

#ifdef ADV_STAT

        if(config->advStatisticsFile != NULL)
        {
            put_stat(echo, &(header.destAddr), stOUT,
                     (INT32)(msg->textLength + strlen(msg->text + msg->textLength)));
        }

#endif
    }

    if(f)
    {
        fclose(f);
    }

    return;
} /* forwardToLinks */

void forwardMsgToLinks(s_area * echo, s_message * msg, hs_addr pktOrigAddr)
{
    s_seenBy * seenBys = NULL, * tempSeenBys = NULL, * path = NULL;
    UINT seenByCount = 0, tempSeenByCount = 0, pathCount = 0;
    /*  links who does not have their aka in seenBys and thus have not got the echomail */
    s_arealink ** newLinks = NULL, ** zoneLinks = NULL, ** otherLinks = NULL;

    createSeenByArrayFromMsg(echo, msg, &seenBys, &seenByCount);
    createPathArrayFromMsg(msg, &path, &pathCount);
    createNewLinkArray(seenBys, seenByCount, echo, &newLinks, &zoneLinks, &otherLinks,
                       pktOrigAddr);

    if(newLinks)
    {
        forwardToLinks(msg, echo, newLinks, &seenBys, &seenByCount, &path, &pathCount);
    }

    if(zoneLinks)
    {
        /* strip SEEN-BYs when zone-gating and sbkeepAll is disabled */
        if((echo->sbkeep_all == 0) && (echo->useAka->zone != pktOrigAddr.zone))
        {
            if(echo->sbkeepCount == 0)
            {
                seenByCount = 0;        /* strip all SEEN-BYs */
            }
            else
            {
                /* keep SEEN-BYs found in sbkeep */
                createFilteredSeenByArray(seenBys,
                                          seenByCount,
                                          &tempSeenBys,
                                          &tempSeenByCount,
                                          echo->sbkeep,
                                          echo->sbkeepCount);
                nfree(seenBys);
                seenBys     = tempSeenBys;
                seenByCount = tempSeenByCount;
            }
        }

        forwardToLinks(msg, echo, zoneLinks, &seenBys, &seenByCount, &path, &pathCount);
    }

    if(otherLinks)
    {
        nfree(seenBys);
        seenBys     = memdup(path, sizeof(s_seenBy) * pathCount);
        seenByCount = pathCount;
        forwardToLinks(msg, echo, otherLinks, &seenBys, &seenByCount, &path, &pathCount);
    }

    nfree(seenBys);
    nfree(path);
    nfree(newLinks);
    nfree(zoneLinks);
    nfree(otherLinks);
} /* forwardMsgToLinks */

/* return value: 1 if success, 0 if fail */
/* writeAccess MUST BE unsigned !!! */
int putMsgInBadArea(s_message * msg, hs_addr pktOrigAddr, unsigned writeAccess)
{
    char * tmp = NULL, * line = NULL, * textBuff = NULL, * areaName = NULL, * reason = NULL;
    char buff[128] = "";

    w_log(LL_FUNC, "putMsgInBadArea() begin");
    statToss.bad++;

    /*  get real name area */
    line = strchr(msg->text, '\r');

    if(line == NULL || strncmp(msg->text, "AREA:", 5) != 0)
    {
        areaName = xstrcat(&areaName, "no areatag");
    }
    else
    {
        *line = 0;
        xstrcat(&areaName, msg->text + 5);
        *line = '\r';
    }

    if(writeAccess > BM_MAXERROR)
    {
        reason = "Another error";
    }
    else if(writeAccess == BM_MSGAPI_ERROR)
    {
        reason =
            strncat(strcpy(buff, "MSGAPIERR: "),
                    strmerr(msgapierr),
                    sizeof(buff) - sizeof("MSGAPIERR: "));
    }
    else
    {
        reason = BadmailReasonString[writeAccess];
    }

    w_log(LL_ECHOMAIL, "Badmail reason: %s (AREA: %s)", reason, areaName);

#ifdef DO_PERL

    if(perltossbad(msg, areaName, pktOrigAddr, reason))
    {
        nfree(areaName);
        nfree(msg->text);
        w_log(LL_FUNC, "putMsgInBadArea():perltossbad OK (rc=1)");
        return 1;
    }

#endif

    tmp = msg->text;

    while((line = strchr(tmp, '\r')) != NULL)
    {
        if(*(line + 1) == '\x01')
        {
            tmp = line + 1;
        }
        else
        {
            tmp   = line + 1;
            *line = 0;
            break;
        }
    }
    xstrscat(&textBuff,
             msg->text,
             "\rFROM: ",
             aka2str(&pktOrigAddr),
             "\rREASON: ",
             reason,
             "\r",
             NULLP);

    if(areaName)
    {
        xscatprintf(&textBuff, "AREANAME: %s\r\r", areaName);
    }

    xstrcat(&textBuff, tmp);
    nfree(areaName);
    nfree(msg->text);
    msg->text       = textBuff;
    msg->textLength = (hINT32)strlen(msg->text);

    if(putMsgInArea(&(config->badArea), msg, 0, 0))
    {
        config->badArea.imported++;
        w_log(LL_FUNC, "putMsgInBadArea() OK");
        return 1;
    }

    w_log(LL_FUNC, "putMsgInBadArea() failed");
    return 0;
} /* putMsgInBadArea */

void makeMsgToSysop(char * areaName, hs_addr fromAddr, ps_addr uplinkAddr)
{
    s_area * echo = NULL;
    unsigned int i, netmail = 0;
    char * buff   = NULL;
    char * strbeg = NULL;

    if(config->ReportTo)
    {
        if(stricmp(config->ReportTo, "netmail") == 0)
        {
            netmail = 1;
        }
        else if(getNetMailArea(config, config->ReportTo) != NULL)
        {
            netmail = 1;
        }
    }
    else
    {
        netmail = 1;
    }

    echo = getArea(config, areaName);

    if(echo == &(config->badArea))
    {
        return;
    }

    for(i = 0; i < config->addrCount; i++)
    {
        if(echo->useAka == &(config->addr[i]))
        {
            if(msgToSysop[i] == NULL)
            {
                msgToSysop[i] = makeMessage(echo->useAka,
                                            echo->useAka,
                                            robot->fromName ? robot->fromName : versionStr,
                                            netmail ? (config->sysop ? config->sysop : "Sysop") : "All",
                                            "Created new areas",
                                            netmail,
                                            robot->reportsAttr);
                msgToSysop[i]->text = createKludges(config,
                                                    netmail ? NULL : config->ReportTo,
                                                    echo->useAka,
                                                    echo->useAka,
                                                    versionStr);

                if(robot->reportsFlags)
                {
                    xstrscat(&(msgToSysop[i]->text), "\001FLAGS ", robot->reportsFlags, "\r",
                             NULLP);
                }

                xstrscat(&(msgToSysop[i]->text), "Action   Name", repeat_char(49, ' '), "By\r",
                         NULLP);
                /*  Shitty static variables .... */
                xstrscat(&(msgToSysop[i]->text), repeat_char(79, '-'), "\r", NULLP);
                msgToSysop[i]->recode |= (REC_HDR | REC_TXT);
                w_log(LL_NETMAIL, "Created msg to sysop");
            }

            /*           New report generation */
            buff = safe_strdup("");

            if(config->reportRequester)
            {
                xstrcat(&buff, aka2str(&fromAddr));
            }

            if(uplinkAddr != NULL)    /*  autocreation with forward request */
            {
                xstrscat(&buff, " from ", aka2str(uplinkAddr), NULLP);
            }

            xstrscat(&strbeg, "Created  ", echo->areaName, NULLP);

            if(echo->description)
            {
                if(strlen(strbeg) + strlen(echo->description) >= 77)
                {
                    xstrscat(&(msgToSysop[i]->text), strbeg, "\r", NULLP);
                    nfree(strbeg);
                    xstrcat(&strbeg, repeat_char(9, ' '));
                }
                else
                {
                    xstrcat(&strbeg, " ");
                }

                xstrscat(&strbeg, "\"", echo->description, "\"", NULLP);
            }

            xstrcat(&(msgToSysop[i]->text), strbeg);

            if(strlen(strbeg) + strlen(buff) >= 79)
            {
                xstrscat(&(msgToSysop[i]->text),
                         "\r",
                         repeat_char(79 - strlen(buff), ' '),
                         buff,
                         "\r",
                         NULLP);
            }
            else if(strlen(strbeg) < 62 && strlen(buff) < 79 - 62)   /*  most beautiful */
            {
                xstrscat(&(msgToSysop[i]->text),
                         repeat_char(62 - strlen(strbeg), ' '),
                         buff,
                         "\r",
                         NULLP);
            }
            else
            {
                xstrscat(&(msgToSysop[i]->text),
                         repeat_char(79 - strlen(strbeg) - strlen(buff), ' '),
                         buff,
                         "\r",
                         NULLP);
            }

            nfree(buff);
            nfree(strbeg);
            break;
        }
    }
} /* makeMsgToSysop */

void writeMsgToSysop(void)
{
    char * ptr = NULL, * seenByPath = NULL;
    s_area * echo = NULL;
    unsigned int i, ccrc = 0;
    s_seenBy * seenBys = NULL;

    for(i = 0; i < config->addrCount; i++)
    {
        if(msgToSysop[i])
        {
            xscatprintf(&(msgToSysop[i]->text),
                        " \r--- %s\r * Origin: %s (%s)\r",
                        (config->tearline) ? config->tearline : "",
                        (config->origin) ? config->origin : config->name,
                        aka2str(&msgToSysop[i]->origAddr));
            msgToSysop[i]->textLength = (hINT32)strlen(msgToSysop[i]->text);

#ifdef DO_PERL
            perl_robotmsg(msgToSysop[i], "tosysop");
#endif

            if(msgToSysop[i]->netMail == 1)
            {
                /*  FIXME: should be putMsgInArea */
                processNMMsg(msgToSysop[i],
                             NULL,
                             config->ReportTo ? getNetMailArea(config, config->ReportTo) : NULL,
                             1,
                             0);
                writeEchoTossLogEntry(
                    config->ReportTo ? config->ReportTo : config->netMailAreas[0].areaName);
            }
            else
            {
                /*  get echoarea  for this msg */
                ptr  = strchr(msgToSysop[i]->text, '\r');
                *ptr = '\0';
                echo = getArea(config, msgToSysop[i]->text + 5);
                *ptr = '\r';

                if(echo != &(config->badArea))
                {
                    if(config->carbonCount != 0)
                    {
                        ccrc = carbonCopy(msgToSysop[i], NULL, echo);
                    }

                    if(echo->msgbType != MSGTYPE_PASSTHROUGH && ccrc <= 1)
                    {
                        putMsgInArea(echo, msgToSysop[i], 1, (MSGSCANNED | MSGSENT | MSGLOCAL));
                        echo->imported++;  /*  area has got new messages */
                    }

                    seenBys =
                        (s_seenBy *)safe_malloc(sizeof(s_seenBy) * (echo->downlinkCount + 1));
                    seenBys[0].net  = (UINT16)echo->useAka->net;
                    seenBys[0].node = (UINT16)echo->useAka->node;
                    sortSeenBys(seenBys, 1);
                    seenByPath = createControlText(seenBys, 1, "SEEN-BY: ");
                    nfree(seenBys);

                    /*  path line */
                    /*  only include node-akas in path */
                    if(echo->useAka->point == 0)
                    {
                        xscatprintf(&seenByPath,
                                    "\001PATH: %u/%u\r",
                                    echo->useAka->net,
                                    echo->useAka->node);
                    }

                    xstrcat(&(msgToSysop[i]->text), seenByPath);
                    nfree(seenByPath);

                    if(echo->downlinkCount > 0)
                    {
                        /*  recoding from internal to transport charSet */
                        if(config->outtab)
                        {
                            if(msgToSysop[i]->recode & REC_HDR)
                            {
                                recodeToTransportCharset((char *)msgToSysop[i]->fromUserName);
                                recodeToTransportCharset((char *)msgToSysop[i]->toUserName);
                                recodeToTransportCharset((char *)msgToSysop[i]->subjectLine);
                                msgToSysop[i]->recode &= ~REC_HDR;
                            }

                            if(msgToSysop[i]->recode & REC_TXT)
                            {
                                recodeToTransportCharset((char *)msgToSysop[i]->text);
                                msgToSysop[i]->recode &= ~REC_TXT;
                            }
                        }

                        forwardMsgToLinks(echo, msgToSysop[i], msgToSysop[i]->origAddr);
                        closeOpenedPkt();
                        writeEchoTossLogEntry(echo->areaName);
                        tossTempOutbound(config->tempOutbound);
                    }
                }
                else
                {
                    putMsgInBadArea(msgToSysop[i], msgToSysop[i]->origAddr, 0);
                }
            }
        }
    }
} /* writeMsgToSysop */

int processEMMsg(s_message * msg, hs_addr pktOrigAddr, int dontdocc, dword forceattr)
{
    char * area = NULL, * p = NULL, * q = NULL;
    s_message * messCC = NULL;
    s_area * echo      = &(config->badArea);
    s_link * link      = NULL;
    unsigned int days  = 0;
    struct tm msg_tm;
    time_t msgTime, diffTime;
    flag_t tFlag;
    int writeAccess = 0, rc = 0, ccrc = 0;

    w_log(LL_FUNC, "%s::processEMMsg() begin", __FILE__);
    p = strchr(msg->text, '\r');

    if(p)
    {
        *p = '\0';
        q  = msg->text + 5;

        while(*q == ' ')
        {
            q++;
        }
        xstrcat(&area, q);
        echo = getArea(config, area);
        *p   = '\r';
    }

    link = getLinkFromAddr(config, pktOrigAddr);

    /*  no area found -- trying to autocreate echoarea */
    if(echo == &(config->badArea))
    {
        /*  check if we should not refuse this area */
        /*  checking for autocreate option */
        if((link != NULL) && (link->areafix.autoCreate != 0))
        {
            if(BM_MAIL_OK == (writeAccess = autoCreate(area, NULL, pktOrigAddr, NULL)))
            {
                echo = getArea(config, area);
            }
            else
            {
                rc = putMsgInBadArea(msg, pktOrigAddr, writeAccess);
            }
        } /*  can't create echoarea - put msg in BadArea */
        else
        {
            rc = putMsgInBadArea(msg, pktOrigAddr, writeAccess);
        }
    }

    nfree(area);

    if(echo != &(config->badArea))
    {
        /*  area is autocreated! */
        /*  cheking access of this link */
        writeAccess = checkAreaLink(echo, pktOrigAddr, 0);

        if(writeAccess)
        {
            rc = putMsgInBadArea(msg, pktOrigAddr, writeAccess);
#ifdef ADV_STAT

            if(config->advStatisticsFile != NULL)
            {
                put_stat(echo, &pktOrigAddr, stBAD, 0);
            }

#endif

            /* notify link about bad post */
            if((link != NULL) && (link->sendNotifyMessages))
            {
                s_message * tmpmsg;
                char * reason = NULL;

                if(writeAccess > BM_MAXERROR)
                {
                    reason = "Unknown error";
                }
                else
                {
                    reason = BadmailReasonString[writeAccess];
                }

                tmpmsg = makeMessage(link->ourAka,
                                     &(link->hisAka),
                                     robot->fromName ? robot->fromName : versionStr,
                                     link->name,
                                     "Notification message",
                                     1,
                                     link->areafix.reportsAttr ? link->areafix.reportsAttr : robot->reportsAttr);
                tmpmsg->text = createKludges(config,
                                             NULL,
                                             link->ourAka,
                                             &(link->hisAka),
                                             versionStr);

                if(link->areafix.reportsFlags)
                {
                    xstrscat(&(tmpmsg->text), "\001FLAGS ", link->areafix.reportsFlags, "\r",
                             NULLP);
                }
                else if(robot->reportsFlags)
                {
                    xstrscat(&(tmpmsg->text), "\001FLAGS ", robot->reportsFlags, "\r", NULLP);
                }

                xstrcat(&tmpmsg->text,
                        "\r Your message was moved to badmail with the following reason:\r\r");
                xscatprintf(&tmpmsg->text, " %s\r\r", reason);
                xstrcat(&tmpmsg->text, " Header of original message:\r\r");
                xscatprintf(&tmpmsg->text, "      Area: %s\r", echo->areaName);
                xscatprintf(&tmpmsg->text, "      Date: %s\r", msg->datetime);
                xscatprintf(&tmpmsg->text, "      From: %s, %s\r", msg->fromUserName,
                            aka2str(&msg->origAddr));
                xscatprintf(&tmpmsg->text, "        To: %s\r", msg->toUserName);
                xscatprintf(&tmpmsg->text, "   Subject: %s\r", msg->subjectLine);
                xstrcat(&tmpmsg->text,
                        "\r Please contact sysop if you think this is a mistake!\r");
                xscatprintf(&tmpmsg->text, "\r\r--- %s areafix\r", versionStr);
                tmpmsg->textLength = (hINT32)strlen(tmpmsg->text);
                processNMMsg(tmpmsg, NULL, getRobotsArea(config), 0, MSGLOCAL);
                writeEchoTossLogEntry(getRobotsArea(config)->areaName);
                closeOpenedPkt();
                freeMsgBuffers(tmpmsg);
                nfree(tmpmsg);
                nfree(reason);
                w_log(LL_AREAFIX, "areafix: write notification msg for %s", aka2str(&link->hisAka));
            }
        }

        /* check age of message */
        if(writeAccess == 0)                      /* ok to proceed */
        {
            /* get message age if tooOld or tooNew feature is enabled */
            if((echo->tooOld > 0) || (echo->tooNew > 0))
            {
                /* get time from message */
                tFlag = parse_ftsc_date(&msg_tm, (char *)msg->datetime);

                if(!(tFlag & FTSC_BROKEN))
                {
                    msgTime = mktime(&msg_tm);

                    if(msgTime != (time_t)-1)
                    {
                        diffTime  = labs((long)(globalTime - msgTime));
                        diffTime /= (60 * 60 * 24);          /* convert to days */
                        days      = (unsigned int)diffTime;

                        /* tooOld */
                        if((echo->tooOld > 0) && globalTime > msgTime)
                        {
                            if(days > echo->tooOld)
                            {
                                writeAccess = BM_TOO_OLD;
                            }
                        }
                        /* tooNew */
                        else if((echo->tooNew > 0) && globalTime < msgTime)
                        {
                            if(days > echo->tooNew)
                            {
                                writeAccess = BM_TOO_NEW;
                            }
                        }
                    }
                }
            }

            if(writeAccess)             /* on any problem move message to BadArea */
            {
                rc = putMsgInBadArea(msg, pktOrigAddr, writeAccess);
            }
        }

        if(writeAccess == 0)                      /* ok to proceed */
        {
            /*  access ok - process msg */
            int not_dupe = 1;

#ifdef DO_PERL
            w_log(LL_SRCLINE, "toss.c:%u:processEMMsg() #ifdef DO_PERL", __LINE__);

            if((rc = perlfilter(msg, pktOrigAddr, -1)) == 1)
            {
                return not_dupe = 0;
            }
            else if(rc == 2)
            {
                return 1;
            }

#endif

            if(not_dupe)
            {
                not_dupe = dupeDetection(echo, msg);
            }

            if(not_dupe)
            {
                /*  no dupe */
                messCC = MessForCC(msg); /* make copy of original message */
                statToss.echoMail++;

                /*  if only one downlink, we've got the mail from him */
                if((echo->downlinkCount > 1) ||
                   ((echo->downlinkCount > 0) &&
                    /*  mail from us */
                    (addrComp(&pktOrigAddr, echo->useAka) == 0)))
                {
                    forwardMsgToLinks(echo, msg, pktOrigAddr);
                }

                /* todo: remove TID from local-generated msgs by hpt post -x
                 * (if (addrComp(&pktOrigAddr,echo->useAka)==0)) */
                if(messCC && !dontdocc)
                {
                    ccrc = carbonCopy(messCC, NULL, echo);
                }

                if(ccrc <= 1)
                {
                    echo->imported++;  /*  area has got new messages */
#ifdef ADV_STAT

                    if(config->advStatisticsFile != NULL)
                    {
                        put_stat(echo, &pktOrigAddr, stNORM, msg->textLength);
                    }

#endif

                    if(echo->msgbType != MSGTYPE_PASSTHROUGH)
                    {
                        if(messCC)
                        {
                            rc = putMsgInArea(echo, messCC, 1, forceattr);
                        }
                        else
                        {
                            rc = putMsgInArea(echo, msg, 1, forceattr);
                        }

                        statToss.saved += rc;
                    }
                    else   /*  passthrough */
                           /*
                              if (echo->downlinkCount==1 && dontdocc==0)
                              rc = putMsgInBadArea(msg, pktOrigAddr, 10);
                              else {
                              statToss.passthrough++;
                              rc = 1;
                              }
                            */
                    {
                        statToss.passthrough++;
                        rc = 1;
                    }
                }
                else
                {
                    rc = 1;    /*  normal exit for carbon move & delete */
                }

                freeMsgBuffers(messCC);
                nfree(messCC);
            }
            else
            {
                /*  msg is dupe */
                if(echo->dupeCheck == dcMove)
                {
                    /*  rc = putMsgInDupeArea(pktOrigAddr, msg, forceattr); */
                    rc = putMsgInArea(&(config->dupeArea), msg, 0, forceattr);
                }
                else
                {
                    rc = 1;
                }

                statToss.dupes++;
#ifdef ADV_STAT

                if(config->advStatisticsFile != NULL)
                {
                    put_stat(echo, &pktOrigAddr, stDUPE, 0);
                }

#endif

                if(rc)
                {
                    config->dupeArea.imported++;
                }
            }
        }
    }

    w_log(LL_FUNC, "%s::processEMMsg() rc=%d", __FILE__, rc);
    return rc;
} /* processEMMsg */

int processNMMsg(s_message * msg,
                 s_pktHeader * pktHeader,
                 s_area * area,
                 int dontdocc,
                 dword forceattr)
{
    HAREA netmail;
    HMSG msgHandle;
    UINT len         = 0;
    char * bodyStart = NULL;              /*  msg-body without kludgelines start */
    char * ctrlBuf   = NULL;              /*  Kludgelines */
    XMSG msgHeader;
/*     char   *slash = NULL; */
    unsigned int rc = 0, ccrc = 0, i;

    if(area == NULL)
    {
        area = &(config->netMailAreas[0]);

        for(i = 0; i < config->netMailAreaCount; i++)
        {
            if(addrComp(&(msg->destAddr), config->netMailAreas[i].useAka) == 0)
            {
                area = &(config->netMailAreas[i]);
                break;
            }
        }
    }

    if(dupeDetection(area, msg) == 0)
    {
        /*  msg is dupe */
        if(area->dupeCheck == dcMove)
        {
            rc = putMsgInArea(&(config->dupeArea), msg, 0, forceattr);
        }
        else
        {
            rc = 1;
        }

        statToss.dupes++;

        if(rc)
        {
            config->dupeArea.imported++;
        }

        return rc;
    }

    if((config->carbonCount != 0) && (!dontdocc))
    {
        ccrc = carbonCopy(msg, NULL, area);
    }

    if(ccrc > 1)
    {
        return 1;           /*  carbon del or move */
    }

    netmail = MsgOpenArea((unsigned char *)area->fileName, MSGAREA_CRIFNEC, (word)area->msgbType);

    if(netmail != NULL)
    {
        msgHandle = MsgOpenMsg(netmail, MOPEN_CREATE, 0);

        if(msgHandle != NULL)
        {
            area->imported++; /*  area has got new messages */

            /*  recode from TransportCharset to internal Charset */
            if((config->recodeMsgBase) && (config->intab != NULL))
            {
                if((msg->recode & REC_HDR) == 0)
                {
                    recodeToInternalCharset((char *)msg->fromUserName);
                    recodeToInternalCharset((char *)msg->toUserName);
                    recodeToInternalCharset((char *)msg->subjectLine);
                    msg->recode |= REC_HDR;
                }

                if((msg->recode & REC_TXT) == 0)
                {
                    recodeToInternalCharset((char *)msg->text);
                    msg->recode |= REC_TXT;
                }
            }

            msgHeader = createXMSG(config, msg, pktHeader, forceattr, tossDir);
#ifdef DO_PERL

            /* val: force attrs set by perlfilter() hook */
            if(perl_setattr)
            {
                msgHeader.attr = msg->attributes;
            }

#endif
            /* Create CtrlBuf for SMAPI */
            len     = msg->textLength;
            ctrlBuf = (char *)CopyToControlBuf((UCHAR *)msg->text, (UCHAR **)&bodyStart, &len);

            /* write message */
            if(MsgWriteMsg(msgHandle, 0, &msgHeader, (UCHAR *)bodyStart, len, len,
                           (dword)strlen(ctrlBuf) + 1, (UCHAR *)ctrlBuf) != 0)
            {
                w_log(LL_ERR,
                      "Could not write msg to NetmailArea %s! Check the wholeness of messagebase, please.",
                      area->areaName);
            }
            else
            {
                rc = 1; /*  normal exit */
            }

            nfree(ctrlBuf);

            if(MsgCloseMsg(msgHandle) != 0) /*  can't close */
            {
                w_log(LL_ERR, "Could not close msg in NetmailArea %s", area->areaName);
                rc = 0;
            }
            else /*  normal close */
            {
                w_log(LL_NETMAIL,
                      "Wrote Netmail: %u:%u/%u.%u -> %u:%u/%u.%u",
                      msg->origAddr.zone,
                      msg->origAddr.net,
                      msg->origAddr.node,
                      msg->origAddr.point,
                      msg->destAddr.zone,
                      msg->destAddr.net,
                      msg->destAddr.node,
                      msg->destAddr.point);
                statToss.netMail++;
            }
        }
        else
        {
            w_log(LL_ERR, "Could not create new msg in NetmailArea %s", area->areaName);
        } /* endif */

        MsgCloseArea(netmail);
    }
    else
    {
        fprintf(stderr, "msgapierr - %u\n", msgapierr);
        w_log(LL_ERR, "Could not open NetmailArea %s", area->areaName);
    } /* endif */

    return rc;
} /* processNMMsg */

int processMsg(s_message * msg, s_pktHeader * pktHeader, int secure)
{
    int rc;

    w_log(LL_FUNC, "toss.c::processMsg()");
    statToss.msgs++;

#ifdef DO_PERL
    w_log(LL_SRCLINE, "toss.c:%u:processMsg() #ifdef DO_PERL", __LINE__);

    if((rc = perlfilter(msg, pktHeader->origAddr, secure)) == 1)
    {
        return putMsgInBadArea(msg, pktHeader->origAddr, BM_DENY_BY_FILTER);
    }
    else if(rc == 2)
    {
        return 1;
    }

#else
    unused(secure);
#endif

    if(msg->netMail == 1)
    {
        w_log(LL_NETMAIL,
              "Netmail from %s to %u:%u/%u.%u",
              aka2str(&msg->origAddr),
              msg->destAddr.zone,
              msg->destAddr.net,
              msg->destAddr.node,
              msg->destAddr.point);

        if(config->areafixFromPkt &&
           isOurAka(config, msg->destAddr) &&
           msg->toUserName[0] != '\0' &&
           findInStrArray(robot->names, msg->toUserName) >= 0)
        {
            rc = processAreaFix(msg, pktHeader, 0);
        }
        else
        {
            rc = processNMMsg(msg, pktHeader, NULL, 0, 0);
        }
    }
    else
    {
        rc = processEMMsg(msg, pktHeader->origAddr, 0, 0);
    } /* endif */

    w_log(LL_FUNC, "toss.c::processMsg() rc=%d", rc);
    return rc;
} /* processMsg */

int processPkt(char * fileName, e_tossSecurity sec)
{
    FILE * pkt = NULL;
    s_pktHeader * header = NULL;
    s_message * msg = NULL;
    s_link * link = NULL;
    int rc = 0, msgrc = 0;
    long pktlen;
    /* +AS+ */
    char * extcmd = NULL;
    int cmdexit;
    /* -AS- */
    char processIt = 0;        /*  processIt = 1, process all mails */

    /*  processIt = 2, process only Netmail */
    /*  processIt = 0, do not process pkt */
    w_log(LL_FUNC, "toss.c::processPkt()");

    if((pktlen = fsize(fileName)) > 60)
    {
        statToss.inBytes += pktlen;

        /* +AS+ */
        if(config->processPkt)
        {
            extcmd = safe_malloc(strlen(config->processPkt) + strlen(fileName) + 2);
            sprintf(extcmd, "%s %s", config->processPkt, fileName);
            w_log(LL_EXEC, "ProcessPkt: execute string \"%s\"", extcmd);

            if((cmdexit = cmdcall(extcmd)) != 0)
            {
                w_log(LL_ERR, "exec failed, code %d", cmdexit);
            }

            nfree(extcmd);
        }

        /* -AS- */
#ifdef DO_PERL

        if(perlpkt(fileName, (sec == secLocalInbound || sec == secProtInbound) ? 1 : 0))
        {
            return 6;
        }

#endif

        pkt = fopen(fileName, "rb");

        if(pkt == NULL)
        {
            return 2;
        }

        w_log(LL_FILE, "toss.c:processPkt(): opened '%s' (\"rb\" mode)", fileName);
        header = openPkt(pkt);

        if(header != NULL)
        {
            /* if ((to_us(header->destAddr)==0) || (sec == secLocalInbound)) { */
            if(isOurAka(config, header->destAddr) || (sec == secLocalInbound))
            {
                w_log(LL_PKT, "pkt: %s [%s]", fileName, aka2str(&header->origAddr));
                statToss.pkts++;
                link = getLinkFromAddr(config, header->origAddr);

                if((link != NULL) && (link->pktPwd == NULL) && (header->pktPassword[0] != '\000'))
                {
                    w_log(LL_ERR, "Unexpected Password %s.", header->pktPassword);
                }

                switch(sec)
                {
                    case secLocalInbound:
                        processIt = 1;
                        break;

                    case secProtInbound:

                        if((link != NULL) && (link->pktPwd != NULL) && link->pktPwd[0])
                        {
                            if(stricmp(link->pktPwd, header->pktPassword) == 0)
                            {
                                processIt = 1;
                            }
                            else
                            {
                                if((header->pktPassword[0] == '\0') &&
                                   ((link->allowEmptyPktPwd == eSecure) ||
                                    (link->allowEmptyPktPwd == eOn)))
                                {
                                    w_log(LL_WARN,
                                          "pkt: %s Warning: missing packet password from %i:%i/%i.%i",
                                          fileName,
                                          header->origAddr.zone,
                                          header->origAddr.net,
                                          header->origAddr.node,
                                          header->origAddr.point);
                                    processIt = 1;
                                }
                                else
                                {
                                    w_log(LL_WARN,
                                          "pkt: %s Password Error for %i:%i/%i.%i",
                                          fileName,
                                          header->origAddr.zone,
                                          header->origAddr.net,
                                          header->origAddr.node,
                                          header->origAddr.point);
                                    rc = 1;
                                }
                            }
                        }
                        else if((link != NULL) &&
                                ((link->pktPwd == NULL) || (strcmp(link->pktPwd, "") == 0)))
                        {
                            processIt = 1;
                        }
                        else /* if (link == NULL) */
                        {
                            w_log(LL_ERR,
                                  "pkt: %s No Link for %i:%i/%i.%i, processing only Netmail",
                                  fileName,
                                  header->origAddr.zone,
                                  header->origAddr.net,
                                  header->origAddr.node,
                                  header->origAddr.point);
                            processIt = 2;
                        }

                        break;

                    case secInbound:

                        if((link != NULL) && (link->pktPwd != NULL) && link->pktPwd[0])
                        {
                            if(stricmp(link->pktPwd, header->pktPassword) == 0)
                            {
                                processIt = 1;
                            }
                            else
                            {
                                if((header->pktPassword[0] == '\0') &&
                                   (link->allowEmptyPktPwd == eOn))
                                {
                                    w_log(LL_ERR,
                                          "pkt: %s Warning: missing packet password from %i:%i/%i.%i",
                                          fileName,
                                          header->origAddr.zone,
                                          header->origAddr.net,
                                          header->origAddr.node,
                                          header->origAddr.point);
                                    processIt = 2; /* Unsecure inbound, do not process echomail
                                                      */
                                }
                                else
                                {
                                    w_log(LL_ERR,
                                          "pkt: %s Password Error for %i:%i/%i.%i",
                                          fileName,
                                          header->origAddr.zone,
                                          header->origAddr.net,
                                          header->origAddr.node,
                                          header->origAddr.point);
                                    rc = 1;
                                }
                            }
                        }
                        else if((link != NULL) &&
                                ((link->pktPwd == NULL) || (strcmp(link->pktPwd, "") == 0)))
                        {
                            processIt = 1;
                        }
                        else /* if (link == NULL) */
                        {
                            w_log(LL_ERR,
                                  "pkt: %s No Link for %i:%i/%i.%i, processing only Netmail",
                                  fileName,
                                  header->origAddr.zone,
                                  header->origAddr.net,
                                  header->origAddr.node,
                                  header->origAddr.point);
                            processIt = 2;
                        }

                        break;
                } /* switch */

                if(processIt != 0)
                {
                    while((msgrc = readMsgFromPkt(pkt, header, &msg)) == 1)
                    {
                        if(msg != NULL)
                        {
                            if((processIt == 1) || ((processIt == 2) && (msg->netMail == 1)))
                            {
                                if(processMsg(msg, header,
                                              (sec == secLocalInbound || sec == secProtInbound ||
                                               processIt == 1) ? 1 : 0) != 1)
                                {
                                    if(putMsgInBadArea(msg, header->origAddr,
                                                       BM_MSGAPI_ERROR) == 0)
                                    {
                                        rc = 5; /*  can't write to badArea - rename to .err */
                                    }
                                }
                            }
                            else
                            {
                                rc = 1;
                            }

                            freeMsgBuffers(msg);
                            nfree(msg);
                        }
                    }

                    if(msgrc == 2)
                    {
                        rc = 3;           /*  rename to .bad (wrong msg format) */
                    }

                    /*  real time of process pkt & msg without external programs */
                }
            }
            else
            {
                while((msgrc = readMsgFromPkt(pkt, header, &msg)) == 1)
                {
                    if(msg != NULL)
                    {
                        if(msg->netMail == 1)
                        {
                            if(processMsg(msg, header,
                                          (sec == secLocalInbound ||
                                           sec == secProtInbound) ? 1 : 0) != 1)
                            {
                                rc = 5;
                            }
                        }
                        else
                        {
                            break;
                        }

                        freeMsgBuffers(msg);
                        nfree(msg);
                    }
                }

                if(msg) /* echomail pkt not for us */
                {
                    freeMsgBuffers(msg);
                    nfree(msg);
                    /* PKT is not for us - try to forward it to our links */
                    w_log(LL_ERR,
                          "pkt: %s addressed to %d:%d/%d.%d but not to us",
                          fileName,
                          header->destAddr.zone,
                          header->destAddr.net,
                          header->destAddr.node,
                          header->destAddr.point);
                    fclose(pkt);
                    pkt = NULL;
                    rc  = forwardPkt(fileName, header, sec);
                }
            }

            nfree(header);
        }
        else     /*  header == NULL */
        {
            w_log(LL_ERR, "pkt: %s wrong pkt-file", fileName);
            rc = 3;
        }

        if(pkt)
        {
            fclose(pkt);
        }
    }
    else
    {
        statToss.empty++;
    }

#ifdef DO_PERL
    perlpktdone(fileName, rc);
#endif
    closeOpenedPkt();
    w_log(LL_FUNC, "toss.c::processPkt() OK");
    return rc;
} /* processPkt */

int processArc(char * fileName, e_tossSecurity sec)
{
    unsigned int i;
    int found, j;
    signed int cmdexit;
    FILE * bundle = NULL;
    char cmd[256];

    if(sec == secInbound)
    {
        w_log(LL_ERR, "bundle %s: tossing in unsecure inbound, security violation", fileName);
        return 1;
    }

    /*  find what unpacker to use */
    for(i = 0, found = 0; (i < config->unpackCount) && !found; i++)
    {
        bundle = fopen(fileName, "rb");

        if(bundle == NULL)
        {
            return 2;
        }

        w_log(LL_FILE, "toss.c:processArc(): opened '%s' (\"rb\" mode)", fileName);
        /*  is offset is negative we look at the end */
        fseek(bundle, config->unpack[i].offset,
              config->unpack[i].offset >= 0 ? SEEK_SET : SEEK_END);

        if(ferror(bundle))
        {
            fclose(bundle);
            continue;
        }

        for(found = 1, j = 0; j < config->unpack[i].codeSize; j++)
        {
            if((getc(bundle) & config->unpack[i].mask[j]) != config->unpack[i].matchCode[j])
            {
                found = 0;
            }
        }
        fclose(bundle);
    }

    /*  unpack bundle */
    if(found)
    {
        fillCmdStatement(cmd, config->unpack[i - 1].call, fileName, "", config->tempInbound);

        if(fc_stristr(config->unpack[i - 1].call, ZIPINTERNAL))
        {
            w_log(LL_BUNDLE, "bundle %s: unpacking with zlib", fileName);
#ifdef USE_HPTZIP
            cmdexit = UnPackWithZlib(fileName, NULL, config->tempInbound);
#else
            cmdexit = 1;
            w_log(LL_ERR, "zlib not compiled into hpt", fileName);
#endif
        }
        else
        {
            w_log(LL_EXEC, "bundle %s: unpacking with \"%s\"", fileName, cmd);
            cmdexit = cmdcall(cmd);
        }

        if(cmdexit != 0)
        {
            w_log(LL_ERR, "exec failed, code %d", cmdexit);
            return 3;
        }

        if(config->afterUnpack)
        {
            w_log(LL_EXEC, "afterUnpack: execute string \"%s\"", config->afterUnpack);

            if((cmdexit = cmdcall(config->afterUnpack)) != 0)
            {
                w_log(LL_ERR, "exec failed, code %d", cmdexit);
            }
        }

#ifdef DO_PERL
        perlafterunp();
#endif
    }
    else
    {
        w_log(LL_ERR, "bundle %s: cannot find unpacker", fileName);
        return 3;
    }

    statToss.arch++;
    remove(fileName);
    processDir(config->tempInbound, sec);
    return 7;
} /* processArc */

typedef struct fileInDir
{
    char * fileName;
    time_t fileTime;
} s_fileInDir;
int filesComparer(const void * elem1, const void * elem2)
{
    /*  File times comparer for qsort */
    if(((s_fileInDir *)elem1)->fileTime < ((s_fileInDir *)elem2)->fileTime)
    {
        return -1;
    }

    if(((s_fileInDir *)elem1)->fileTime > ((s_fileInDir *)elem2)->fileTime)
    {
        return 1;
    }

    return strcasecmp(((s_fileInDir *)elem1)->fileName, ((s_fileInDir *)elem2)->fileName);
}

static char * validExt[] =
{
    "su", "mo", "tu", "we", "th", "fr", "sa"
};
int isArcMail(char * fname)
{
    char * p;
    int i;

    p = strrchr(fname, PATH_DELIM);

    if(p)
    {
        p++;
    }
    else
    {
        p = fname;
    }

    /* Amiga? */
    for(i = 0; i < 8; i++)
    {
        if(!isalnum((unsigned char)p[i]))
        {
            break;
        }
    }

    if(i < 8)
    {
        /* Amiga? */
        for(i = 0; i < 4; i++)
        {
            if(!isdigit((unsigned char)*p++))
            {
                return 0;
            }

            while(isdigit((unsigned char)*p))
            {
                p++;
            }

            if(*p++ != '.')
            {
                return 0;
            }
        }
    }
    else
    {
        p += i;

        if(*p++ != '.')
        {
            return 0;
        }
    }

    for(i = 0; i < sizeof(validExt) / sizeof(validExt[0]); i++)
    {
        if(strncasecmp(p, validExt[i], 2) == 0)
        {
            break;
        }
    }

    if(i == sizeof(validExt) / sizeof(*validExt))
    {
        return 0;
    }

    return isalnum((unsigned char)p[2]) && (p[3] == '\0');
} /* isArcMail */

int processDir(char * directory, e_tossSecurity sec)
{
    husky_DIR * dir = NULL;
    char * filename = NULL;
    char * dummy    = NULL;
    int rc;
    int pktFile, arcFile;
    long pktCount       = 0;
    s_fileInDir * files = NULL;
    long nfiles         = 0;
    struct stat st;
    int dirNameLen;
    int filenum;
    char * newFileName = NULL;
    char * ext[]       =
    {
        NULL, "sec", "asc", "bad", "ntu", "err", "flt"
    };

#ifndef __UNIX__
    unsigned fattrs;
#endif

    if(directory == NULL)
    {
        return 0;
    }

    tossDir    = directory;
    dirNameLen = (int)strlen(directory);

#ifdef NOSLASHES
    directory[dirNameLen - 1] = '\0';
#endif

    if(NULL == (dir = husky_opendir(directory)))
    {
        printf("Can't open dir: %s!\n", directory);
        return 0;
    }

    w_log(LL_FUNC, "%s::processDir() begin", __FILE__);

#ifdef NOSLASHES
    directory[dirNameLen - 1] = '\\';
#endif

    while((filename = husky_readdir(dir)) != NULL)
    {
        dummy = (char *)safe_malloc(dirNameLen + strlen(filename) + 1);
        strcpy(dummy, directory);
        strcat(dummy, filename);

#if !defined (__UNIX__)
#ifndef HAS_DIRENT_H    /* FFindInfo() and FFindNext() store attributes */
        fattrs = dir->d_attr;
#elif defined (__TURBOC__) || defined (__DJGPP__)
        _dos_getfileattr(dummy, &fattrs); /*unused, but stay for information*/
#elif defined (__MINGW32__) /* May be move to dirlayer.c ? */
        fattrs = (GetFileAttributes(dummy) & 0x2) ? _A_HIDDEN : 0;
#else
        fattrs = dir->d_attr;
#endif

        if(fattrs & _A_HIDDEN)
        {
            nfree(dummy);
        }
        else
#endif
        {
            nfiles++;
            files = (s_fileInDir *)safe_realloc(files, nfiles * sizeof(s_fileInDir));
            (files[nfiles - 1]).fileName = dummy;

            if(stat((files[nfiles - 1]).fileName, &st) == 0)
            {
                (files[nfiles - 1]).fileTime = st.st_mtime;
            }
            else
            {
                /*  FixMe - don't know what to set :( */
                (files[nfiles - 1]).fileTime = 0L;
            }
        }
    }
    husky_closedir(dir);
    qsort(files, nfiles, sizeof(s_fileInDir), filesComparer);

    for(filenum = 0; filenum < nfiles; filenum++)
    {
        arcFile = pktFile = 0;
        dummy   = (files[filenum]).fileName;
        w_log(LL_FILE, "Process incoming file %s", dummy);

        if((pktFile = patimat(dummy + dirNameLen, "*.pkt")) == 0)
        {
            if(isArcMail(dummy + dirNameLen))
            {
                arcFile = 1;
            }
        }

        if(pktFile || (arcFile && !config->noProcessBundles))
        {
            pktCount++;
            rc = 3; /*  nonsence, but compiler warns */

            if(config->tossingExt != NULL &&
               (newFileName = changeFileSuffix(dummy, config->tossingExt, 1)) != NULL)
            {
                if(arcFile)
                {
                    w_log(LL_BUNDLE, "bundle %s: renaming to .%s", dummy, config->tossingExt);
                }

                nfree(dummy);
                dummy       = newFileName;
                newFileName = NULL;
            }

            if(pktFile)
            {
                rc = processPkt(dummy, sec);
            }
            else /*  if (arcFile) */
            {
                rc = processArc(dummy, sec);
            }

            if(rc >= 1 && rc <= 6)
            {
                w_log(LL_ERR, "Renaming pkt/arc to .%s", ext[rc]);
                newFileName = changeFileSuffix(dummy, ext[rc], 1);
            }
            else
            {
                if(rc != 7)
                {
                    remove(dummy);
                }
            }
        }

        nfree(dummy);
        nfree(newFileName);
    }
    nfree(files);
    w_log(LL_FUNC, "%s::processDir() returns %d", __FILE__, pktCount);
    return pktCount;
} /* processDir */

void writeStatLog(void)
{
    /* write personal mail statistic logfile if statlog is defined in config */
    /* if the log file exists, the existing value is increased */
    FILE * f = NULL;
    char buffer[256];
    int len, x, statNetmail, statCC;

    statNetmail = statToss.netMail; /* number of just received netmails */

    statCC = statToss.CC; /* number of just received personal echo mails */

    /* if there are new personal mails and statLog is defined in config */
    if(((statNetmail > 0) || (statCC > 0)) && (config->statlog != NULL))
    {
        f = fopen(config->statlog, "r");

        if(f != NULL) /* and statLog file is readable */
        {
            w_log(LL_FILE, "toss.c:writeStatLog(): opened '%s' (\"r\" mode)", config->statlog);

            /* then read last personal mail counter and add to actual counter */
            while(fgets(buffer, sizeof(buffer), f))
            {
                len = (int)strlen(buffer);

                for(x = 0; x != len; x++)
                {
                    if(!strncasecmp(buffer + x, "netmail: ", 9))
                    {
                        /* netmail found */
                        statNetmail += atoi(buffer + 9);
                    }

                    if(!strncasecmp(buffer + x, "CC: ", 4))
                    {
                        /* personal echomail (CC) found */
                        statCC += atoi(buffer + 4);
                    }
                }
            }
            fclose(f);
        }

        /* and write personal mail counter for netmails and echo mails */
        f = fopen(config->statlog, "wt");

        if(f != NULL)
        {
            w_log(LL_FILE, "toss.c:writeStatLog(): opened '%s' (\"wt\" mode)", config->statlog);

            if(statNetmail > 0)
            {
                fprintf(f, "netmail: %d\n", statNetmail);
            }

            if(statCC > 0)
            {
                fprintf(f, "CC: %d\n", statCC);
            }

            fclose(f);
        }
    }
} /* writeStatLog */

void writeTossStatsToLog(void)
{
    unsigned int i;
    float inMailsec, outMailsec, inKBsec;
    char logchar;

    if(statToss.pkts == 0 && statToss.msgs == 0)
    {
        logchar = '1';
    }
    else
    {
        logchar = '4';
    }

    if(statToss.realTime == 0)
    {
        statToss.realTime = 1;
    }

    inMailsec  = ((float)(statToss.msgs)) * 1000 / statToss.realTime;
    outMailsec = ((float)(statToss.exported)) * 1000 / statToss.realTime;
    inKBsec    = ((float)(statToss.inBytes)) * 1000 / statToss.realTime / 1024;
    w_log(logchar, "Statistics:");
    w_log(logchar,
          "     arc: % 5d   netMail: % 4d   echoMail: % 5d         CC: % 5d",
          statToss.arch,
          statToss.netMail,
          statToss.echoMail,
          statToss.CC);
    w_log(logchar,
          "   pkt's: % 5d      dupe: % 4d   passthru: % 5d   exported: % 5d",
          statToss.pkts,
          statToss.dupes,
          statToss.passthrough,
          statToss.exported);
    w_log(logchar,
          "    msgs: % 5d       bad: % 4d      saved: % 5d      empty: % 5d",
          statToss.msgs,
          statToss.bad,
          statToss.saved,
          statToss.empty);
    w_log(logchar,
          "   Input: % 8.2f mails/sec        Output: % 8.2f mails/sec",
          inMailsec,
          outMailsec);
    w_log(logchar, "          % 8.2f kb/sec", inKBsec);
    w_log(logchar, "          % 8.2f kb total, processed in %8.3f seconds",
          ((float)statToss.inBytes / 1024), (float)statToss.realTime / 1000);

    /* write personal mail statistic logfile */
    writeStatLog();
    /* Now write areas summary */
    w_log(logchar, "Areas summary:");

    for(i = 0; i < config->netMailAreaCount; i++)
    {
        if(config->netMailAreas[i].imported > 0)
        {
            w_log(logchar,
                  "netmail area %s - %d msgs",
                  config->netMailAreas[i].areaName,
                  config->netMailAreas[i].imported);
        }
    }

    if(config->dupeArea.imported)
    {
        w_log(logchar,
              "dupe area %s - %d msgs",
              config->dupeArea.areaName,
              config->dupeArea.imported);
    }

    if(config->badArea.imported)
    {
        w_log(logchar, "bad area %s - %d msgs", config->badArea.areaName,
              config->badArea.imported);
    }

    for(i = 0; i < config->echoAreaCount; i++)
    {
        if(config->echoAreas[i].imported > 0)
        {
            w_log(logchar,
                  "echo area %s - %d msgs",
                  config->echoAreas[i].areaName,
                  config->echoAreas[i].imported);
        }
    }

    for(i = 0; i < config->localAreaCount; i++)
    {
        if(config->localAreas[i].imported > 0)
        {
            w_log(logchar,
                  "local area %s - %d msgs",
                  config->localAreas[i].areaName,
                  config->localAreas[i].imported);
        }
    }
} /* writeTossStatsToLog */

int find_old_arcmail(s_link * link, FILE * flo)
{
    char * line = NULL, * bundle = NULL;
    ULONG len;
    unsigned as;

    while((line = readLine(flo)) != NULL)
    {
#ifndef __UNIX__
        line = trimLine(line);
#endif

        if((*line == '^' || *line == '#') && isArcMail(line + 1))
        {
            nfree(bundle);
            bundle = safe_strdup(line + 1);
        }

        nfree(line);
    }

    if(bundle == NULL)
    {
        return 0;
    }

    if(*bundle != '\000')
    {
        int ok = 0;
        len = fsize(bundle);

        if(len != -1L)
        {
            time_t t = fmtime(bundle);

            if(link->arcmailSize != 0)
            {
                as = link->arcmailSize;
            }
            else if(config->defarcmailSize != 0)
            {
                as = config->defarcmailSize;
            }
            else
            {
                as = 500; /*  default 500 kb max */
            }

            /* check size */
            ok = (len < as * 1024L);

            /* check mtime */
            if(ok && t != -1L && link->dailyBundles)
            {
                time_t t0, cur = time(NULL);
                struct tm * tcur = localtime(&cur);
                tcur->tm_sec = tcur->tm_min = tcur->tm_hour = 0;
                t0           = mktime(tcur);

                if(t < t0)
                {
                    ok = 0;
                }
            }

            /* use the bundle */
            if(ok)
            {
                link->packFile = (char *)safe_realloc(link->packFile, strlen(bundle) + 1);
                strcpy(link->packFile, bundle);
                nfree(bundle);
                return 1;
            }
        }
    }

    nfree(bundle);
    return 0;
} /* find_old_arcmail */

void arcmail(s_link * tolink)
{
    char cmd[256], * pkt = NULL, * lastPathDelim = NULL, saveChar;
    UINT i;
    int cmdexit, foa = 0;
    FILE * flo    = NULL;
    s_link * link = NULL;
    hs_addr * aka;
    e_bundleFileNameStyle bundleNameStyle;

    closeOpenedPkt();

    if(config->beforePack)
    {
        w_log(LL_EXEC, "beforePack: execute string \"%s\"", config->beforePack);

        if((cmdexit = cmdcall(config->beforePack)) != 0)
        {
            w_log(LL_ERR, "exec failed, code %d", cmdexit);
        }
    }

#ifdef DO_PERL
    perlbeforepack();
#endif

    for(i = 0; i < config->linkCount; i++)
    {
        if(tolink)
        {
            link = tolink;
            i    = config->linkCount;
        }
        else
        {
            link = config->links[i];
        }

        /*  only create floFile if we have mail for this link */
        if(link->pktFile != NULL)
        {
            aka = SelectPackAka(link);

            if(needUseFileBoxForLinkAka(config, link, aka))
            {
                if(!link->fileBox)
                {
                    link->fileBox = makeFileBoxNameAka(config, link, aka);
                }

                _createDirectoryTree(link->fileBox);

                if(link->packFile == NULL)
                {
                    if(createPackFileName(link))
                    {
                        exit_hpt("Could not create new bundle!", 1);
                    }
                }

                if(link->packerDef != NULL)
                {
/* FIXME  It's need to fix logic: MUST don't allow pack into filebox directly!!!
   Normal logic: make bundle in temporary dir, next move(rename!) it into filebox,
   and at scanning tempoutbound should to check bundles (not only PKT)
 */
                    fillCmdStatement(cmd, link->packerDef->call, link->packFile, link->pktFile,
                                     "");
                    w_log(LL_BUNDLE,
                          "Packing for %s %s, %s > %s",
                          aka2str(&link->hisAka),
                          link->name,
                          get_filename(link->pktFile),
                          get_filename(link->packFile));
                    w_log(LL_EXEC, "cmd: %s", cmd);

                    if(stricmp(link->packerDef->call, ZIPINTERNAL) == 0)
                    {
#ifdef USE_HPTZIP
                        cmdexit = PackWithZlib(link->packFile, link->pktFile);
#else
                        cmdexit = -1;
                        w_log(LL_ERR, "zlib not compiled into hpt");
#endif
                    }
                    else
                    {
                        cmdexit = cmdcall(cmd);
                    }

                    if(cmdexit == 0)
                    {
                        remove(link->pktFile);
                    }
                    else
                    {
                        w_log(LL_ERR, "Error executing packer (errorlevel==%i)", cmdexit);
                    }
                } /*  end packerDef */
                else
                {
                    /*  there is no packer defined -> put pktFile into fileBox */
                    xstrcat(&pkt, link->fileBox);
                    xstrcat(&pkt, link->pktFile + strlen(config->tempOutbound));
                    cmdexit = move_file(link->pktFile, pkt, 0);

                    if(cmdexit == 0)
                    {
                        w_log(LL_BUNDLE, "Leave non-packed mail for %s %s, %s",
                              aka2str(&link->hisAka), link->name, get_filename(link->pktFile));
                    }
                    else
                    {
                        w_log(LL_ERR,
                              "error moving file for %s %s, %s->%s (errorlevel==%i)",
                              aka2str(&link->hisAka),
                              link->name,
                              link->pktFile,
                              pkt,
                              errno);
                    }

                    nfree(pkt);
                }
            }
            else if(createOutboundFileNameAka(link, link->echoMailFlavour, FLOFILE, aka) == 0)
            {
                /*  process if the link not busy, else do not create 12345678.?lo */
                flo = fopen(link->floFile, "a+");

                if(flo == NULL)
                {
                    w_log(LL_ERR, "Cannot open flo file %s", config->links[i]->floFile);
                }
                else
                {
                    w_log(LL_FILE, "toss.c:arcmail(): opened '%s' (\"a+\" mode)", link->floFile);

                    if(link->linkBundleNameStyle != eUndef)
                    {
                        bundleNameStyle = link->linkBundleNameStyle;
                    }
                    else if(config->bundleNameStyle != eUndef)
                    {
                        bundleNameStyle = config->bundleNameStyle;
                    }
                    else
                    {
                        bundleNameStyle = eTimeStamp;
                    }

                    if(link->packerDef != NULL)
                    {
                    pack_retry:
                        /*there is a packer defined -> put packFile into flo */
                        /*if we are creating new arcmail bundle -> put packFile into flo*/
                        fseek(flo, 0L, SEEK_SET);

                        if(!foa)  /* retry pack bundle? */
                        {
                            foa = find_old_arcmail(link, flo);
                        }
                        else   /* try to generate new bundle name */
                        {
                            foa            = 0;
                            link->packFile = NULL;
                        }

                        if(link->packFile == NULL)
                        {
                            if(createPackFileName(link))
                            {
                                exit_hpt("Could not create new bundle!", 1);
                            }
                        }

                        fillCmdStatement(cmd,
                                         link->packerDef->call,
                                         link->packFile,
                                         link->pktFile,
                                         "");
                        w_log(LL_BUNDLE,
                              "Packing for %s %s, %s > %s",
                              aka2str(&link->hisAka),
                              link->name,
                              get_filename(link->pktFile),
                              get_filename(link->packFile));
                        w_log(LL_EXEC, "cmd: %s", cmd);

                        if(stricmp(link->packerDef->call, ZIPINTERNAL) == 0)
                        {
#ifdef USE_HPTZIP
                            cmdexit = PackWithZlib(link->packFile, link->pktFile);
#else
                            cmdexit = -1;
                            w_log(LL_ERR, "zlib not compiled into hpt");
#endif
                        }
                        else
                        {
                            cmdexit = cmdcall(cmd);
                        }

                        if(cmdexit == 0)
                        {
                            if(foa == 0)
                            {
                                if(bundleNameStyle == eAddrDiff ||
                                   bundleNameStyle == eAddrsCRC32 ||
                                   bundleNameStyle == eAddrDiffAlways ||
                                   bundleNameStyle == eAddrsCRC32Always ||
                                   bundleNameStyle == eAmiga)
                                {
                                    fprintf(flo, "#%s\n", link->packFile);
                                }
                                else
                                {
                                    fprintf(flo, "^%s\n", link->packFile);
                                }
                            }

                            remove(link->pktFile);
                        }
                        else
                        {
                            w_log(LL_ERR,
                                  "Error executing packer (errorlevel==%i, %s)",
                                  cmdexit,
                                  foa ? "retrying" : "permanent error");

                            if(foa)
                            {
                                goto pack_retry;
                            }
                        }
                    } /*  end packerDef */
                    else
                    {
                        /*  there is no packer defined -> put pktFile into flo */
                        lastPathDelim = strrchr(link->floFile, PATH_DELIM);
                        /*  change path of file to path of flofile */
                        saveChar       = *(++lastPathDelim);
                        *lastPathDelim = '\0';
                        xstrcat(&pkt, link->floFile);
                        *lastPathDelim = saveChar;

                        if(config->separateBundles)
                        {
                            if(bundleNameStyle == eAmiga)
                            {
                                xscatprintf(&pkt,
                                            "%u.%u.%u.%u.sep%c",
                                            aka->zone,
                                            aka->net,
                                            aka->node,
                                            aka->point,
                                            PATH_DELIM);
                            }
                            else
                            {
                                if(aka->point != 0)
                                {
                                    xscatprintf(&pkt, "%08x.sep%c", aka->point, PATH_DELIM);
                                }
                                else
                                {
                                    xscatprintf(&pkt,
                                                "%04x%04x.sep%c",
                                                aka->net,
                                                aka->node,
                                                PATH_DELIM);
                                }
                            }
                        }

                        xstrcat(&pkt, link->pktFile + strlen(config->tempOutbound));
                        cmdexit = move_file(link->pktFile, pkt, 0);

                        if(cmdexit == 0)
                        {
                            fprintf(flo, "^%s\n", pkt);
                            w_log(LL_BUNDLE, "Leave non-packed mail for %s %s, %s",
                                  aka2str(&link->hisAka), link->name, get_filename(link->pktFile));
                        }
                        else
                        {
                            w_log(LL_ERR,
                                  "error moving file for %s %s, %s->%s (errorlevel==%i)",
                                  aka2str(&link->hisAka),
                                  link->name,
                                  link->pktFile,
                                  pkt,
                                  errno);
                        }

                        nfree(pkt);
                    }

                    fclose(flo);
                } /*  end flo */

                nfree(link->floFile);
                remove(link->bsyFile);
                nfree(link->bsyFile);
            } /*  end outboundFileNameCreated */

            nfree(link->pktFile);
            nfree(link->packFile);
        } /*  end pkt file */
    } /*  endfor */
    return;
} /* arcmail */

static int forwardedPkts = 0;
int forwardPkt(const char * fileName, s_pktHeader * header, e_tossSecurity sec)
{
    unsigned int i;
    s_link * link = NULL;
    char * newfn  = NULL;

    for(i = 0; i < config->linkCount; i++)
    {
        if(addrComp(&(header->destAddr), &(config->links[i]->hisAka)) == 0)
        {
            /* we found a link to forward the pkt file to */
            link = config->links[i];

            /* security checks */
            if(link->forwardPkts == fOff)
            {
                return 4;
            }

            if((link->forwardPkts == fSecure) && (sec != secProtInbound) &&
               (sec != secLocalInbound))
            {
                return 4;
            }

            /* as we have feature freeze currently, */
            /* I enclose the following code with an ifdef ... */
            newfn = makeUniqueDosFileName(config->tempOutbound, "pkt", config);

            if(move_file(fileName, newfn, 0) == 0) /* save if exist */
            {
                w_log(LL_PKT,
                      "Forwarding %s to %s as %s",
                      fileName,
                      config->links[i]->name,
                      newfn + strlen(config->tempOutbound));
                nfree(newfn);
                forwardedPkts = 1;
                return 0;
            }
            else
            {
                w_log(LL_ERR, "Failed moving %s to %s (%s)", fileName, newfn, strerror(errno));
                nfree(newfn);
                return 4;
            }
        }
    }
    w_log(LL_ERR, "Packet %s is not for us or our links", fileName);
    return 4;       /* PKT is not for us and we did not find a link to
                       forward the pkt file to */
} /* forwardPkt */

/* According to the specs, a .QQQ file does not have two leading
   zeros. This routine checks if the file is a .QQQ file, and if so,
   it appends the zeros and renames the file to .PKT. */
void fix_qqq(char * filename)
{
    FILE * f       = NULL;
    char buffer[2] =
    {
        '\0', '\0'
    };
    size_t l       = strlen(filename);
    char * newname = NULL;

    if(l > 3 && newname != NULL && toupper(filename[l - 1]) == 'Q' &&
       toupper(filename[l - 2]) == 'Q' && toupper(filename[l - 3]) == 'Q')
    {
        newname = safe_strdup(filename);
        strcpy(newname + l - 3, "pkt");

        if(move_file(newname, filename, 0) == 0)
        {
            strcpy(filename, newname);

            if((f = fopen(filename, "ab")) != NULL)
            {
                fwrite(buffer, 2, 1, f);
                fclose(f);
            }
        }
        else
        {
            w_log(LL_ERR, "Failed moving %s to %s (%s)", newname, filename, strerror(errno));
        }

        nfree(newname);
    }
} /* fix_qqq */

void tossTempOutbound(char * directory)
{
    husky_DIR * dir      = NULL;
    FILE * pkt           = NULL;
    char * filename      = NULL;
    char * dummy         = NULL;
    s_pktHeader * header = NULL;
    s_link * link        = NULL;
    size_t l;
    size_t dirNameLen;

    if(directory == NULL)
    {
        return;
    }

    dirNameLen = strlen(directory);

#ifdef NOSLASHES
    directory[dirNameLen - 1] = '\0';
#endif

    if(NULL == (dir = husky_opendir(directory)))
    {
        printf("Can't open dir: %s!\n", directory);
        return;
    }

#ifdef NOSLASHES
    directory[dirNameLen - 1] = '\\';
#endif

    while((filename = husky_readdir(dir)) != NULL)
    {
        l = strlen(filename);

        if(l > 4 &&
           (stricmp(filename + l - 4, ".pkt") == 0 || stricmp(filename + l - 4, ".qqq") == 0))
        {
            dummy = (char *)safe_malloc(dirNameLen + l + 1);
            strcpy(dummy, directory);
            strcat(dummy, filename);
            fix_qqq(dummy);
            pkt = fopen(dummy, "rb");

            if(pkt == NULL)
            {
                continue;
            }

            header = openPkt(pkt);

            if(header != NULL)
            {
                link = getLinkFromAddr(config, header->destAddr);
                nfree(header);
            }
            else
            {
                link = NULL;
            }

            if(link != NULL)
            {
                if(link->packFile == NULL)
                {
                    if(createPackFileName(link))
                    {
                        exit_hpt("Could not create new bundle!", 1);
                    }
                }

                nfree(link->pktFile);
                link->pktFile = dummy;
                fclose(pkt);
                arcmail(link);
            }
            else
            {
                nfree(dummy);
                w_log(LL_ERR, "found non packed mail without matching link in tempOutbound");
                fclose(pkt);
            }
        }
    }
    husky_closedir(dir);
    return;
} /* tossTempOutbound */


#ifdef __UNIX__
static void chownChmodImportLog(void)
{
    int rc;

    rc = chown(config->importlog, config->loguid, config->loggid);

    if(rc != 0)
    {
        w_log(LL_ERR, "Could not chown() importlogfile: %s", strerror(errno));
    }

    if(config->logperm != -1)
    {
        rc = chmod(config->importlog, config->logperm);

        if(rc != 0)
        {
            w_log(LL_ERR, "Could not chmod() importlogfile: %s", strerror(errno));
        }
    }
}
#endif


static void deleteEmptyImportLog(void)
{
    struct stat buf;
    /*  remove empty importlog */
    if(stat(config->importlog, &buf) == 0 && buf.st_size == 0)
    {
        remove(config->importlog);
    }
}


static void writeImportLog(void)
{
    unsigned int i;
    FILE * f;

    if(!config->importlog)
    {
        return;
    }

    /*  write importlog */
    f = fopen(config->importlog, "a");

    if(f == NULL)
    {
        w_log(LL_ERR, "Could not open importlogfile");
        deleteEmptyImportLog();
        return;
    }

    for(i = 0; i < config->netMailAreaCount; i++)
    {
        if(config->netMailAreas[i].imported > 0)
        {
            fprintf(f, "%s\n", config->netMailAreas[i].areaName);
        }
    }

    for(i = 0; i < config->echoAreaCount; i++)
    {
        if(config->echoAreas[i].imported > 0 &&
           config->echoAreas[i].msgbType != MSGTYPE_PASSTHROUGH)
        {
            fprintf(f, "%s\n", config->echoAreas[i].areaName);
        }
    }

    for(i = 0; i < config->localAreaCount; i++)
    {
        if(config->localAreas[i].imported > 0)
        {
            fprintf(f, "%s\n", config->localAreas[i].areaName);
        }
    }

    fclose(f);

#ifdef __UNIX__
    chownChmodImportLog();
#endif

    deleteEmptyImportLog();
} /* writeImportLog */


#define MAXOPEN_DEFAULT 512

#if defined (__OS2__)

#define INCL_DOS
/* From os2emx.h:
   ULONG DosSetMaxFH (ULONG ulCount);
   ULONG DosSetRelMaxFH (PLONG pulReqCount, PULONG pulCurMaxFH);
 */
static void setmaxopen(void)
{
    ULONG cur = 0;
    LONG add = 0;

    if(DosSetRelMaxFH(&add, &cur) == 0)
    {
        if(cur >= maxopenpkt)
        {
            return;
        }
    }

    if(DosSetMaxFH(maxopenpkt))
    {
        while(cur < maxopenpkt)
        {
            add = 1;

            if(DosSetRelMaxFH(&add, &cur))
            {
                break;
            }
        }
    }

#ifdef __WATCOMC__
    _grow_handles(maxopenpkt);
#endif
    cur = add = 0;

    if(DosSetRelMaxFH(&add, &cur) == 0)
    {
        maxopenpkt = cur;
        /*  return; */
    }

#elif defined (__UNIX__)

#include <sys/resource.h>

static void setmaxopen(void)
{
#ifdef RLIMIT_NOFILE
    struct rlimit rl;
    unsigned maxopenpkt = MAXOPEN_DEFAULT;

    if(getrlimit(RLIMIT_NOFILE, &rl) == 0)
    {
        if(rl.rlim_cur >= MAXOPEN_DEFAULT)
        {
            return;
        }
    }

    /*  try to set max open */
    rl.rlim_cur = rl.rlim_max;

    if(setrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur >= MAXOPEN_DEFAULT)
    {
        return;
    }

    rl.rlim_cur = rl.rlim_max = maxopenpkt;
    setrlimit(RLIMIT_NOFILE, &rl);

    if(getrlimit(RLIMIT_NOFILE, &rl) == 0)
    {
        maxopenpkt = rl.rlim_cur;
        return;
    }

#endif /* ifdef RLIMIT_NOFILE */

#else /*  windows or unknown OS, just test */
static void setmaxopen(void)
{
#endif /* if defined (__OS2__) */

    {
        int handles[MAXOPEN_DEFAULT];
        ULONG i;

        for(i = 0; i < MAXOPEN_DEFAULT; i++)
        {
            if((handles[i] = dup(1)) == -1)
            {
                break;
            }
        }
        maxopenpkt = i;

        for(i = 0; i < maxopenpkt; i++)
        {
            close(handles[i]);
        }
    }

    if(maxopenpkt == 0)
    {
        maxopenpkt = 1;
    }
} /* setmaxopen */

void toss(void)
{
    FILE * f = NULL;
    hs_time timer;

    /*  set stats to 0 */
    memset(&statToss, '\0', sizeof(s_statToss));
    w_log(LL_START, "Start tossing...");
    husky_SetTimer(&timer);

    while(processDir(config->localInbound, secLocalInbound))
    {}

    while(processDir(config->protInbound, secProtInbound))
    {}

    while(processDir(config->inbound, secInbound))
    {}
    nfree(globalBuffer); /*  free msg->text global buffer */
    writeDupeFiles();
    writeImportLog();

    if(forwardedPkts)
    {
        tossTempOutbound(config->tempOutbound);
        forwardedPkts = 0;
    }

    statToss.realTime = husky_GetTimer(&timer);
    /*  write statToss to Log */
    writeTossStatsToLog();
    tossTempOutbound(config->tempOutbound);

    /*  create flag for netmail trackers */
    if(config->netmailFlag && statToss.netMail)
    {
        if(NULL == (f = fopen(config->netmailFlag, "a")))
        {
            w_log(LL_ERR, "Could not create netmail flag: %s", config->netmailFlag);
        }
        else
        {
            w_log(LL_FLAG, "Created netmail flag: %s", config->netmailFlag);
            fclose(f);
        }
    }

    w_log(LL_STOP, "End tossing");
} /* toss */

int packBadArea(HMSG hmsg, XMSG xmsg, char force)
{
    int rc = 0;
    s_message msg;
    s_area * echo = &(config->badArea);
    hs_addr pktOrigAddr;
    char * ptmp = NULL, * line = NULL, * areaName = NULL, * area = NULL, noexp = 0;
    s_link * link = NULL;

    makeMsg(hmsg, &xmsg, &msg, &(config->badArea), 2);
    memset(&pktOrigAddr, '\0', sizeof(hs_addr));
    statToss.msgs++; /*  really processed one more msg */

    /*  deleting valet string - "FROM:" and "REASON:" */
    ptmp = msg.text;

    while((line = strchr(ptmp, '\r')) != NULL)
    {
        /* Temporary make it \0 terminated string */
        *line = '\000';

        if(strncmp(ptmp, "FROM: ",
                   6) == 0 ||
           strncmp(ptmp, "REASON: ", 8) == 0 || strncmp(ptmp, "AREANAME: ", 10) == 0)
        {
            /*  It's from address */
            if(*ptmp == 'F')
            {
                parseFtnAddrZS(ptmp + 6, &pktOrigAddr);
            }

            /*  Don't export to links */
            if(*ptmp == 'R')
            {
                if(strstr(ptmp, "MSGAPIERR: ") != NULL)
                {
                    noexp = 1;
                }
            }

            /*  Cut this kludges */
            if(*ptmp == 'A')
            {
                if(area == NULL)
                {
                    echo = getArea(config, ptmp + 10);
                    xstrcat(&area, ptmp + 10);
                }

                memmove(ptmp, line + 1, strlen(line + 1) + 1);
                break;
            }
            else
            {
                memmove(ptmp, line + 1, strlen(line + 1) + 1);
                continue;
            }
        }
        else
        {
            if((strncmp(ptmp, "AREA:",
                        5) == 0 || strncmp(ptmp, "\001AREA:", 6) == 0) && area == NULL)
            {
                /* translating name of the area to uppercase */
                strUpper(ptmp);
                areaName = (*ptmp != '\001') ? ptmp + 5 : ptmp + 6;

                /*  if the areaname begins with a space */
                while(*areaName == ' ')
                {
                    areaName++;
                }
                echo = getArea(config, areaName);
                xstrcat(&area, areaName);
            }

            ptmp = line + 1;
        }

        *line = '\r';
    }

    if(echo == &(config->badArea))
    {
        link = getLinkFromAddr(config, pktOrigAddr);

        if(link && link->areafix.autoCreate && area)
        {
            if(0 == autoCreate(area, NULL, pktOrigAddr, NULL))
            {
                echo = getArea(config, area);
            }
        }
    }

    nfree(area);

    if(echo == &(config->badArea))
    {
        freeMsgBuffers(&msg);
        return rc;
    }

    if(checkAreaLink(echo, pktOrigAddr, 0) == 0 || force)
    {
        if(dupeDetection(echo, &msg) == 1 || noexp)
        {
            /*  no dupe or toss whithout export to links */
            if(config->carbonCount != 0)
            {
                carbonCopy(&msg, NULL, echo);
            }

            echo->imported++; /*  area has got new messages */
#ifdef ADV_STAT

            if(config->advStatisticsFile != NULL)
            {
                put_stat(echo, &pktOrigAddr, stNORM, msg.textLength);
            }

#endif

            if(echo->msgbType != MSGTYPE_PASSTHROUGH)
            {
                rc              = putMsgInArea(echo, &msg, 1, 0);
                statToss.saved += rc;
            }
            else
            {
                statToss.passthrough++;
                rc = 1; /*  passthrough always work */
            }

            if(noexp == 0) /*  recode & export to links */
            /*  recoding from internal to transport charSet */
            {
                if(config->outtab)
                {
                    if(msg.recode & REC_HDR)
                    {
                        recodeToTransportCharset((char *)msg.fromUserName);
                        recodeToTransportCharset((char *)msg.toUserName);
                        recodeToTransportCharset((char *)msg.subjectLine);
                        msg.recode &= ~REC_HDR;
                    }

                    if(msg.recode & REC_TXT)
                    {
                        recodeToTransportCharset((char *)msg.text);
                        msg.recode &= ~REC_TXT;
                    }
                }

                if(echo->downlinkCount > 0)
                {
                    forwardMsgToLinks(echo, &msg, pktOrigAddr);
                }
            }
        }
        else
        {
            /*  msg is dupe */
            if(echo->dupeCheck == dcMove)
            {
                rc = putMsgInArea(&(config->dupeArea), &msg, 0, 0);
            }
            else
            {
                rc = 1; /*  dupeCheck del */
            }

            if(rc)
            {
                config->dupeArea.imported++;
            }

#ifdef ADV_STAT

            if(config->advStatisticsFile != NULL)
            {
                put_stat(echo, &pktOrigAddr, stDUPE, 0);
            }

#endif
        }
    }
    else
    {
        rc = 0;
    }

    freeMsgBuffers(&msg);
    return rc;
} /* packBadArea */

void tossFromBadArea(char force)
{
    HAREA area;
    HMSG hmsg;
    XMSG xmsg;
    dword highestMsg, i;
    int delmsg;

    area =
        MsgOpenArea((UCHAR *)config->badArea.fileName, MSGAREA_NORMAL,
                    (word)(config->badArea.msgbType | MSGTYPE_ECHO));

    if(area != NULL)
    {
        w_log(LL_SCANNING, "Scanning area: %s", config->badArea.areaName);
        highestMsg = MsgGetNumMsg(area);

        for(i = 1; i <= highestMsg; highestMsg--)
        {
            hmsg = MsgOpenMsg(area, MOPEN_RW, i);

            if(hmsg == NULL)
            {
                continue;                /*  msg# does not exist */
            }

            MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
            delmsg = packBadArea(hmsg, xmsg, force);
            MsgCloseMsg(hmsg);

            if(delmsg)
            {
                MsgKillMsg(area, i);
            }
            else
            {
                i++;
                highestMsg++;
            }
        }
        MsgCloseArea(area);
        closeOpenedPkt();
        writeDupeFiles();
        writeImportLog();
        w_log(LL_STAT, "Statistics");
        w_log(LL_STAT,
              "    scanned: % 5d   saved: % 7d   CC: % 2d",
              statToss.msgs,
              statToss.saved,
              statToss.CC);
        w_log(LL_STAT,
              "    exported: % 4d   passthru: % 4d",
              statToss.exported,
              statToss.passthrough);
        tossTempOutbound(config->tempOutbound);
    }
    else
    {
        w_log(LL_ERR, "Could not open %s", config->badArea.fileName);
    }
} /* tossFromBadArea */
