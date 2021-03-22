/*****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 * Copyright (C) 1997-2000
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
 * Hash Dupe and other typeDupeBase (C) 2000
 *
 * Alexander Vernigora
 *
 * Fido:     2:4625/69
 * Internet: alexv@vsmu.vinnica.ua
 *
 * Yunosty 79, app.13
 * 287100 Vinnitsa
 * Ukraine
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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include <pkt.h>
#include <areafix/areafix.h>
#include <global.h>

#include <huskylib/compiler.h>
#include <huskylib/huskylib.h>
#include <huskylib/cvtdate.h>
#include <huskylib/unused.h>

#include <smapi/msgapi.h>
#include <dupe.h>

#include <fidoconf/common.h>
#include <huskylib/xstr.h>
#include <huskylib/crc.h>


FILE * fDupe;
UINT32 DupeCountInHeader, maxTimeLifeDupesInArea;
s_dupeMemory * CommonDupes = NULL;

#define MSGIDPOS 7
#define HASHBUFSIZE 3 * XMSG_TO_SIZE /* msgid len */ + AREANAMELEN
static char hashBuf[HASHBUFSIZE];
static time_t TimeStamp;
char * createDupeFileName(s_area * area)
{
    char * name = NULL, * ptr, * retname = NULL;

    if(!area->DOSFile)
    {
        name = makeMsgbFileName(config, area->areaName);
    }
    else
    {
        if(area->fileName)
        {
            xstrcat(&name,
                    ((ptr = strrchr(area->fileName,
                                    PATH_DELIM)) != NULL) ? ptr + 1 : area->fileName);
        }
        else
        {
            xscatprintf(&name, "%X", strcrc32(area->areaName, 0xFFFFFFFFUL));
        }
    }

    switch(config->typeDupeBase)
    {
        case hashDupes:
            xstrcat(&name, ".dph");
            break;

        case hashDupesWmsgid:
            xstrcat(&name, ".dpd");
            break;

        case textDupes:
            xstrcat(&name, ".dpt");
            break;

        case commonDupeBase:
            break;
    }

    if(config->areasFileNameCase == eUpper)
    {
        name = strUpper(name);
    }
    else
    {
        name = strLower(name);
    }

    xstrscat(&retname, config->dupeHistoryDir, name, NULLP);
    nfree(name);
    return retname;
} /* createDupeFileName */

int compareEntries(char * p_e1, char * p_e2)
{
    const s_textDupeEntry * atxt, * btxt;
    const s_hashDupeEntry * ahash, * bhash;
    const s_hashMDupeEntry * ahashM, * bhashM;
    int rc = 0;
    const void * e1 = (const void *)p_e1, * e2 = (const void *)p_e2;

    switch(config->typeDupeBase)
    {
        case hashDupes:
            ahash = e1;
            bhash = e2;

            if(ahash->CrcOfDupe > bhash->CrcOfDupe)
            {
                rc = 1;
            }
            else if(ahash->CrcOfDupe < bhash->CrcOfDupe)
            {
                rc = -1;
            }
            else
            {
                rc = 0;
            }

            break;

        case hashDupesWmsgid:
            ahashM = e1;
            bhashM = e2;

            if(ahashM->CrcOfDupe == bhashM->CrcOfDupe)
            {
                rc = sstrcmp(ahashM->msgid, bhashM->msgid);
            }
            else if(ahashM->CrcOfDupe > bhashM->CrcOfDupe)
            {
                rc = 1;
            }
            else
            {
                rc = -1;
            }

            break;

        case textDupes:
            atxt = e1;
            btxt = e2;
            rc   = sstrcmp(atxt->msgid, btxt->msgid);
            break;

        case commonDupeBase:
            ahash = e1;
            bhash = e2;

            if(ahash->CrcOfDupe > bhash->CrcOfDupe)
            {
                rc = 1;
            }
            else if(ahash->CrcOfDupe < bhash->CrcOfDupe)
            {
                rc = -1;
            }
            else
            {
                rc = 0;
            }

            break;
    } /* switch */
    return rc;
} /* compareEntries */

int writeEntry(char * p_entry)
{
    const s_textDupeEntry * entxt;
    const s_hashDupeEntry * enhash;
    const s_hashMDupeEntry * enhashM;
    UINT32 diff = 0;
    time_t currtime;
    const void * entry = (const void *)p_entry;

    currtime = TimeStamp;

    switch(config->typeDupeBase)
    {
        case hashDupes:
            enhash = entry;

            if((diff = currtime - enhash->TimeStampOfDupe) < maxTimeLifeDupesInArea)
            {
                fwrite(enhash, sizeof(s_hashDupeEntry), 1, fDupe);
                DupeCountInHeader++;
            }

            break;

        case hashDupesWmsgid:
            enhashM = entry;

            if((diff = currtime - enhashM->TimeStampOfDupe) < maxTimeLifeDupesInArea)
            {
                fwrite(enhashM, sizeof(time_t) + sizeof(UINT32), 1, fDupe);

                if((enhashM->msgid != NULL) && (0 < strlen(enhashM->msgid)))
                {
                    fputc(strlen(enhashM->msgid), fDupe);
                    fputs(enhashM->msgid, fDupe);
                }
                else
                {
                    fputc(0, fDupe);
                }

                DupeCountInHeader++;
            }

            break;

        case textDupes:
            entxt = entry;

            if((diff = currtime - entxt->TimeStampOfDupe) < maxTimeLifeDupesInArea)
            {
                fwrite(entxt, sizeof(time_t), 1, fDupe);
                /* write zero length of this field. left for backward compatibility
                   if ((entxt->msgid != NULL)&&(0 < strlen(entxt->from))) {
                   fputc(strlen(entxt->from), fDupe);
                   fputs(entxt->from, fDupe);
                   }
                   else
                 */
                fputc(0, fDupe);
                /* write zero length of this field. left for backward compatibility
                   if ((entxt->msgid != NULL)&&(0 < strlen(entxt->to))) {
                   fputc(strlen(entxt->to), fDupe);
                   fputs(entxt->to, fDupe);
                   }
                   else
                 */
                fputc(0, fDupe);
                /* write zero length of this field. left for backward compatibility
                   if ((entxt->msgid != NULL)&&(0 < strlen(entxt->subject))) {
                   fputc(strlen(entxt->subject), fDupe);
                   fputs(entxt->subject, fDupe);
                   }
                   else
                 */
                fputc(0, fDupe);

                if((entxt->msgid != NULL) && (0 < strlen(entxt->msgid)))
                {
                    fputc(strlen(entxt->msgid), fDupe);
                    fputs(entxt->msgid, fDupe);
                }
                else
                {
                    fputc(0, fDupe);
                }

                DupeCountInHeader++;
            }

            break;

        case commonDupeBase:
            enhash = entry;

            if((diff = currtime - enhash->TimeStampOfDupe) < maxTimeLifeDupesInArea)
            {
                fwrite(enhash, sizeof(s_hashDupeEntry), 1, fDupe);
                DupeCountInHeader++;
            }

            break;
    } /* switch */
    return 1;
} /* writeEntry */

int deleteEntry(char * entry)
{
    if(entry)
    {
        s_textDupeEntry * entxt;
        s_hashDupeEntry * enhash;
        s_hashMDupeEntry * enhashM;

        switch(config->typeDupeBase)
        {
            case hashDupes:
                enhash = (s_hashDupeEntry *)entry;
                nfree(enhash);
                break;

            case hashDupesWmsgid:
                enhashM = (s_hashMDupeEntry *)entry;
                nfree(enhashM->msgid);
                nfree(enhashM);
                break;

            case textDupes:
                entxt = (s_textDupeEntry *)entry;
                nfree(entxt->msgid);
                nfree(entxt);
                break;

            case commonDupeBase:
                enhash = (s_hashDupeEntry *)entry;
                nfree(enhash);
                break;
        }
    }

    return 1;
} /* deleteEntry */

static void xfread(void * ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t rc;

    if(!ptr)
    {
        w_log(LL_ERR, "xfread(): Cannot read to NULL pointer");
        return;
    }

    if(size == 0)
    {
        w_log(LL_ERR, "xfread(): Attempted to fread() zero bytes");
        return;
    }

    if(nmemb == 0)
    {
        w_log(LL_ERR, "xfread(): Attempted to fread() zero objects");
        return;
    }

    if(!stream)
    {
        w_log(LL_ERR, "xfread(): Cannot fread() from NULL stream");
        return;
    }

    rc = fread(ptr, size, nmemb, stream);

    if(rc == nmemb)
    {
        return;
    }

    if(feof(stream))
    {
        w_log(LL_ERR, "xfread(): fread() reached EOF");
        return;
    }

    if(ferror(stream))
    {
        w_log(LL_ERR, "xfread(): fread() encountered I/O error (%s)", strerror(errno));
        return;
    }

    w_log(LL_ERR, "xfread(): Unhandled error");
}

static void doReading(FILE * f, s_dupeMemory * mem)
{
    s_textDupeEntry * entxt;
    s_hashDupeEntry * enhash;
    s_hashMDupeEntry * enhashM;
    UCHAR length;
    UINT32 i;
    time_t timedupe;

    /*  read Number Of Dupes from dupefile */
    xfread(&DupeCountInHeader, sizeof(UINT32), 1, f);

    /*  process all dupes */
    for(i = 0; i < DupeCountInHeader; i++)
    {
        if(feof(f))
        {
            break;
        }

        switch(config->typeDupeBase)
        {
            case hashDupes:
                enhash = (s_hashDupeEntry *)safe_malloc(sizeof(s_hashDupeEntry));
                xfread(enhash, sizeof(s_hashDupeEntry), 1, f);
                tree_add(&(mem->avlTree), compareEntries, (char *)enhash, deleteEntry);
                break;

            case hashDupesWmsgid:
                enhashM = (s_hashMDupeEntry *)safe_malloc(sizeof(s_hashMDupeEntry));
                xfread(enhashM, sizeof(time_t) + sizeof(UINT32), 1, f);

                if((length = (UCHAR)getc(f)) > 0) /* no EOF check :-( */
                {
                    enhashM->msgid = safe_malloc(length + 1);
                    xfread((UCHAR *)enhashM->msgid, length, 1, f);
                    enhashM->msgid[length] = '\0';
                }
                else
                {
                    enhashM->msgid = NULL;
                }

                tree_add(&(mem->avlTree), compareEntries, (char *)enhashM, deleteEntry);
                break;

            case textDupes:
                entxt = (s_textDupeEntry *)safe_malloc(sizeof(s_textDupeEntry));
                xfread(&timedupe, sizeof(time_t), 1, f);
                entxt->TimeStampOfDupe = timedupe;

                if((length = (UCHAR)getc(f)) > 0)    /* no EOF check :-( */
                {
                    xfread(hashBuf, length, 1, f);
                }

                if((length = (UCHAR)getc(f)) > 0)     /* no EOF check :-( */
                {
                    xfread(hashBuf, length, 1, f);
                }

                if((length = (UCHAR)getc(f)) > 0)    /* no EOF check :-( */
                {
                    xfread(hashBuf, length, 1, f);
                }

                if((length = (UCHAR)getc(f)) > 0)    /* no EOF check :-( */
                {
                    entxt->msgid = safe_malloc(length + 1);
                    xfread((UCHAR *)entxt->msgid, length, 1, f);
                    entxt->msgid[length] = '\0';
                }
                else
                {
                    entxt->msgid = NULL;
                }

                if(entxt->msgid)
                {
                    tree_add(&(mem->avlTree), compareEntries, (char *)entxt, deleteEntry);
                }

                break;

            case commonDupeBase:
                enhash = (s_hashDupeEntry *)safe_malloc(sizeof(s_hashDupeEntry));
                xfread(enhash, sizeof(s_hashDupeEntry), 1, f);
                tree_add(&(mem->avlTree), compareEntries, (char *)enhash, deleteEntry);
                break;
        } /* switch */
    }
} /* doReading */

s_dupeMemory * readDupeFile(s_area * area)
{
    FILE * f;
    char * fileName = NULL;
    s_dupeMemory * dupeMemory;

    TimeStamp  = time(NULL);
    dupeMemory = safe_malloc(sizeof(s_dupeMemory));
    tree_init(&(dupeMemory->avlTree), 1);

    if(config->typeDupeBase != commonDupeBase)
    {
        fileName = createDupeFileName(area);
        w_log(LL_DUPE, "Reading dupes of %s", area->areaName);
    }
    else
    {
        xstrscat(&fileName, config->dupeHistoryDir, "hpt_base.dpa", NULLP);
        w_log(LL_DUPE, "Reading dupes from %s", fileName);
    }

    f = fopen(fileName, "rb");

    if(f != NULL)
    {
        w_log(LL_FILE, "dupe.c:readDupeFile(): opened %s (\"rb\" mode)", fileName);
        /*  readFile */
        doReading(f, dupeMemory);
        fclose(f);
    }
    else
    {
        if(fexist(fileName))
        {
            w_log(LL_ERR, "Error reading dupe base: %s", fileName);
        }
        else if(errno != ENOENT)
        {
            w_log(LL_ERR, "Dupe base '%s' read error: %s", fileName, strerror(errno));
        }
    }

    nfree(fileName);
    return dupeMemory;
} /* readDupeFile */

int createDupeFile(s_area * area, char * name, s_dupeMemory DupeEntries)
{
    FILE * f;

/*    w_log(LL_SRCLINE,"dupe.c:%u:createDupeFile() name='%s'", __LINE__, name); */
    f = fopen(name, "wb");

    if(f != NULL)
    {
        w_log(LL_FILE, "dupe.c:createDupeFile(): opened %s (\"wb\" mode)", name);

        if(config->typeDupeBase != commonDupeBase)
        {
            maxTimeLifeDupesInArea = area->dupeHistory * 86400;
        }
        else
        {
            maxTimeLifeDupesInArea = config->areasMaxDupeAge * 86400;
        }

        DupeCountInHeader = 0;
        fwrite(&DupeCountInHeader, sizeof(UINT32), 1, f);
        fDupe = f;
        tree_trav(&(DupeEntries.avlTree), writeEntry);
        fDupe = NULL;

        /*  writeDupeFileHeader */
        if(DupeCountInHeader > 0)
        {
            fseek(f, 0, SEEK_SET);
            fwrite(&DupeCountInHeader, sizeof(UINT32), 1, f);
            fclose(f);

            /*  for 1 save commonDupeBase */
            if(config->typeDupeBase == commonDupeBase)
            {
                freeDupeMemory(area);
            }
        }
        else
        {
            fclose(f);
            remove(name);
        }

        return 0;
    }
    else
    {
        return 1;
    }
} /* createDupeFile */

int writeToDupeFile(s_area * area)
{
    char * fileName = NULL;
    s_dupeMemory * dupes;
    int rc = 0;

    if(area->dupeCheck == dcOff)
    {
        return rc;
    }

    if(config->typeDupeBase != commonDupeBase)
    {
        dupes    = area->dupes;
        fileName = createDupeFileName(area);
    }
    else
    {
        dupes = CommonDupes;
        xstrscat(&fileName, config->dupeHistoryDir, "hpt_base.dpa", NULLP);
    }

    if(dupes != NULL)
    {
        if(tree_count(&(dupes->avlTree)) > 0)
        {
            rc = createDupeFile(area, fileName, *dupes);
        }
    }

    nfree(fileName);
    return rc;
} /* writeToDupeFile */

void freeDupeMemory(s_area * area)
{
    s_dupeMemory * dupes;

    if(area->dupeCheck == dcOff)
    {
        return;
    }

    if(config->typeDupeBase != commonDupeBase)
    {
        dupes = area->dupes;
    }
    else
    {
        dupes = CommonDupes;
    }

    if(dupes != NULL)
    {
        tree_mung(&(dupes->avlTree), deleteEntry);

        if(config->typeDupeBase != commonDupeBase)
        {
            nfree(area->dupes);
        }
        else
        {
            nfree(CommonDupes);
        }
    }
} /* freeDupeMemory */

/*
 *  find start of content in echomail's message text
 *
 *  requires:
 *  - msg_text: pointer to message text
 *
 *  returns:
 *  - pointer to start of content or NULL in case of any error
 */
char * findStartOfContent(char * msg_text)
{
    char * start = NULL;                /* start of content */
    char * temp;                        /* temporary pointer */
    unsigned int run = TRUE;            /* loop control flag */

    /* sanity check */
    if(msg_text == NULL)
    {
        return start;
    }

    /* message has to start with AREA: line */
    if(strncmp(msg_text, "AREA:", 5) == 0)
    {
        /* find next line not starting with <soh> */
        while(run == TRUE)
        {
            /* find end of current line */
            temp = strchr(msg_text, '\r'); /* find next CR */

            if(temp)                    /* found CR */
            {
                /* check for <soh> */
                temp++;                 /* first char of new line */

                if(*temp == 0x01)       /* is <soh> */
                {
                    msg_text = temp;    /* skip this kludge line */
                }
                else                    /* not <soh> */
                {
                    start = temp;       /* found start of content */
                    run   = FALSE;      /* end loop */
                }
            }
            else                        /* no CR found */
            {
                run = FALSE;            /* end loop */
            }
        }
    }

    return start;
} /* findStartOfContent */

/*
 *  find end of content in echomail's message text
 *
 *  requires:
 *  - msg_text: pointer to message text
 *
 *  returns:
 *  - pointer to end of content or NULL in case of any error
 */
char * findEndOfContent(char * msg_text)
{
    char * end = NULL;                  /* end of content */
    char * eol;                         /* end of line */
    char * temp;                        /* temporary pointer */
    unsigned int run = TRUE;            /* loop control flag */
    unsigned long length;               /* string length */

    /* sanity check */
    if(msg_text == NULL)
    {
        return end;
    }

    /* get end of last line */
    length = strlen(msg_text);          /* get length of message */
    eol    = msg_text + length - 1;     /* pointer to last char */
    length = 0;                         /* use as SEEN-BY counter */

    /* find line */
    while(run == TRUE)
    {
        /* find start of line (starting at the end) */
        temp = eol;

        if((*temp == '\r') && (temp > msg_text))
        {
            temp--;                                    /* skip CR at end */
        }

        /* next CR is end of previous line */
        while((*temp != '\r') && (temp > msg_text))    /* find next CR */
        {
            temp--;
        }

        if(temp == msg_text)  /* no CR found or reached start of message */
        {
            run = FALSE;      /* end loop */
        }
        else                  /* found CR */
        {
            temp++;           /* first char of current line */

            /* check for non-control line */
            if(*temp != 0x01) /* not <soh> */
            {
                /* check for SEEN-BY: (special case without <soh>) */
                if(strncmp(temp, "SEEN-BY:", 8) == 0) /* is SEEN-BY */
                {
                    length++;    /* increase counter */
                }
                else             /* not SEEN-BY */
                {
                    end = eol;   /* found end of content */
                    run = FALSE; /* end loop */
                }
            }

            temp--;              /* end of previous line */
            eol = temp;          /* update pointer for next run */
        }
    }

    /* check for required SEEN-BY lines */
    if(length == 0)                /* no SEEN-BY lines */
    {
        end = NULL;                /* signal error */
    }

    return end;
} /* findEndOfContent */

int dupeDetection(s_area * area, const s_message msg)
{
    s_dupeMemory * Dupes = area->dupes;
    s_textDupeEntry * entxt;
    s_hashDupeEntry * enhash;
    s_hashMDupeEntry * enhashM;
    char * str;
    int nRet = 0;

    w_log(LL_FUNC, "dupe.c::dupeDetection() begin");

    if(area->dupeCheck == dcOff)
    {
        return 1;                           /*  no dupeCheck return 1 "no dupe" */
    }

    str = (char *)MsgGetCtrlToken((byte *)msg.text, (byte *)"MSGID:");

    if(str == NULL) /* Kluge MSGID is not found so make it from crc of message body */
    {
        if(msg.text)
        {
            char * hbuf = NULL;    /* buffer */
            char * start;          /* start of content */
            char * end;            /* end of content */
            char orig;             /* original character */
            /* isolate content from message text (no control lines) */
            end   = NULL;
            start = findStartOfContent(msg.text);    /* find start of content */

            if(start)                          /* found start */
            {
                end = findEndOfContent(start); /* find end of content */

                if(end)                        /* found end */
                {
                    orig = *end;               /* save original char */
                    *end = 0;                  /* end string */
                }
            }

            if(end == NULL)                    /* just in case something went wrong */
            {
                start = msg.text;              /* use complete message text */
            }

            /* create pseudo MSGID */
            xstrscat(&hbuf,
                     start,
                     msg.fromUserName,
                     msg.datetime,
                     msg.toUserName,
                     msg.subjectLine,
                     NULLP);
            xscatprintf(&str, "MSGID: %08lx", strcrc32(hbuf, 0xFFFFFFFFL));
            nfree(hbuf);

            if(end)                     /* un-modify message text */
            {
                *end = orig;            /* restore original char */
            }
        }
        else
        {
            return 1; /*  without msg.text - message is empty, no dupeCheck */
        }
    }

    /*   testif dupeDatabase is already read */
    if(config->typeDupeBase != commonDupeBase)
    {
        if(area->dupes == NULL)
        {
            Dupes = area->dupes = readDupeFile(area); /* read Dupes */
        }
    }
    else
    {
        if(CommonDupes == NULL)
        {
            CommonDupes = readDupeFile(area); /* read Dupes */
        }
    }

    memset(&hashBuf, 0, HASHBUFSIZE);

    switch(config->typeDupeBase)
    {
        case hashDupes:
            enhash = safe_malloc(sizeof(s_hashDupeEntry));
            strnzcpy(hashBuf, area->areaName, AREANAMELEN);
            /*
               strnzcpy(hashBuf, msg.fromUserName, XMSG_FROM_SIZE);
               strnzcat(hashBuf, msg.toUserName,   XMSG_TO_SIZE);
               strnzcat(hashBuf, msg.subjectLine,  XMSG_SUBJ_SIZE);
             */
            strnzcat(hashBuf, str + MSGIDPOS, 3 * XMSG_TO_SIZE);
            enhash->CrcOfDupe       = strcrc32(hashBuf, 0xFFFFFFFFL);
            enhash->TimeStampOfDupe = TimeStamp;
            nRet = tree_add(&(Dupes->avlTree), compareEntries, (char *)enhash, deleteEntry);
            break;

        case hashDupesWmsgid:
            enhashM = safe_malloc(sizeof(s_hashMDupeEntry));
            strnzcpy(hashBuf, area->areaName, AREANAMELEN);
            /*
               strnzcpy(hashBuf, msg.fromUserName, XMSG_FROM_SIZE);
               strnzcat(hashBuf, msg.toUserName,   XMSG_TO_SIZE);
               strnzcat(hashBuf, msg.subjectLine,  XMSG_SUBJ_SIZE);
             */
            strnzcat(hashBuf, str + MSGIDPOS, 3 * XMSG_TO_SIZE);
            enhashM->msgid = safe_malloc(strlen(str) + 1 - MSGIDPOS);
            strcpy(enhashM->msgid, str + MSGIDPOS);
            enhashM->CrcOfDupe       = strcrc32(hashBuf, 0xFFFFFFFFL);
            enhashM->TimeStampOfDupe = TimeStamp;
            nRet = tree_add(&(Dupes->avlTree), compareEntries, (char *)enhashM, deleteEntry);
            break;

        case textDupes:
            entxt = safe_malloc(sizeof(s_textDupeEntry));
            entxt->TimeStampOfDupe = TimeStamp;
            entxt->msgid           = safe_malloc(strlen(str) + 2 - MSGIDPOS);
            strcpy(entxt->msgid, str + MSGIDPOS);
            nRet = tree_add(&(Dupes->avlTree), compareEntries, (char *)entxt, deleteEntry);
            break;

        case commonDupeBase:
            enhash = safe_malloc(sizeof(s_hashDupeEntry));
            strnzcpy(hashBuf, area->areaName, AREANAMELEN);
            /*
               strnzcat(hashBuf, msg.fromUserName, XMSG_FROM_SIZE);
               strnzcat(hashBuf, msg.toUserName,   XMSG_TO_SIZE);
               strnzcat(hashBuf, msg.subjectLine,  XMSG_SUBJ_SIZE);
             */
            strnzcat(hashBuf, str + MSGIDPOS, 3 * XMSG_TO_SIZE);
            enhash->CrcOfDupe       = strcrc32(hashBuf, 0xFFFFFFFFL);
            enhash->TimeStampOfDupe = TimeStamp;
            nRet = tree_add(&(CommonDupes->avlTree), compareEntries, (char *)enhash, deleteEntry);
            break;
    } /* switch */
    nfree(str);
    w_log(LL_FUNC, "dupe.c::dupeDetection() end nRet = %d", nRet);
    return nRet;
} /* dupeDetection */
