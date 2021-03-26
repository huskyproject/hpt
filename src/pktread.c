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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <huskylib/compiler.h>
#include <huskylib/huskylib.h>

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <huskylib/xstr.h>
#include <fidoconf/afixcmd.h>
#include <huskylib/log.h>
#include <huskylib/recode.h>

#include <areafix/areafix.h>
#include <global.h>
#include <fcommon.h>
#include <pkt.h>

time_t readPktTime(FILE * pkt)
{
    struct tm time;

    time.tm_year = getUINT16(pkt) - 1900; /* years since 1900 */

    time.tm_mon   = getUINT16(pkt);
    time.tm_mday  = getUINT16(pkt);
    time.tm_hour  = getUINT16(pkt);
    time.tm_min   = getUINT16(pkt);
    time.tm_sec   = getUINT16(pkt);
    time.tm_isdst = 0;                  /* disable daylight saving */
    return mktime(&time);
}

void readPktPassword(FILE * pkt, UCHAR * password)
{
    int i;

    for(i = 0; i < 8; i++)
    {
        password[i] = (UCHAR)getc(pkt); /* no EOF check :-( */
    } /* endfor */
    password[8] = 0;
}

s_pktHeader * openPkt(FILE * pkt)
{
    s_pktHeader * header;
    UINT16 pktVersion, capWord;

    header = (s_pktHeader *)safe_malloc(sizeof(s_pktHeader));
    memset(header, '\0', sizeof(s_pktHeader));
    header->origAddr.node = getUINT16(pkt);
    header->destAddr.node = getUINT16(pkt);
    header->pktCreated    = readPktTime(pkt); /*  12 bytes */

    getUINT16(pkt); /* read 2 bytes for the unused baud field */
    pktVersion = getUINT16(pkt);

    if(pktVersion != 2)
    {
        nfree(header);
        w_log(LL_ERR, "Invalid pkt version %u!", pktVersion);
        return NULL;
    } /* endif */

    header->origAddr.net    = getUINT16(pkt);
    header->destAddr.net    = getUINT16(pkt);
    header->loProductCode   = (UCHAR)getc(pkt);
    header->majorProductRev = (UCHAR)getc(pkt);
    readPktPassword(pkt, (UCHAR *)header->pktPassword); /*  8 bytes */
    header->origAddr.zone   = getUINT16(pkt);
    header->destAddr.zone   = getUINT16(pkt);
    header->auxNet          = getUINT16(pkt);
    header->capabilityWord  = (UINT16)((fgetc(pkt) << 8) + fgetc(pkt));
    header->hiProductCode   = (UCHAR)getc(pkt);
    header->minorProductRev = (UCHAR)getc(pkt);
    capWord = getUINT16(pkt);

    if(!config->ignoreCapWord)
    {
        /* if both capabilitywords aren't the same, abort */
        /* but read stone-age pkt */
        if(capWord != header->capabilityWord && header->capabilityWord != 0)
        {
            nfree(header);
            w_log(LL_ERR, "CapabilityWord error in following pkt! rtfm: IgnoreCapWord.");
            return NULL;
        } /* endif */
    }

    getUINT16(pkt);
    getUINT16(pkt);               /* read the additional zone info */
    header->origAddr.point = getUINT16(pkt);
    header->destAddr.point = getUINT16(pkt);
    getUINT16(pkt);
    getUINT16(pkt);               /* read ProdData */

    if(((UINT16)header->origAddr.net) == 65535U)
    {
        if(header->origAddr.point)
        {
            header->origAddr.net = header->auxNet;
        }
        else
        {
            header->origAddr.net = header->destAddr.net; /*  not in FSC ! */
        }
    }

    if(header->origAddr.zone == 0)
    {
        for(capWord = 0; capWord < config->addrCount; capWord++)
        {
            if(header->origAddr.net == config->addr[capWord].net)
            {
                header->origAddr.zone = config->addr[capWord].zone;
                break;
            }
        }

        if(header->origAddr.zone == 0)
        {
            header->origAddr.zone = config->addr[0].zone;
        }
    }

    if(header->destAddr.zone == 0)
    {
        for(capWord = 0; capWord < config->addrCount; capWord++)
        {
            if(header->destAddr.net == config->addr[capWord].net)
            {
                header->destAddr.zone = config->addr[capWord].zone;
                break;
            }
        }

        if(header->destAddr.zone == 0)
        {
            header->destAddr.zone = config->addr[0].zone;
        }
    }

    return header;
} /* openPkt */

/* WARNING: *from and *to addresses should be properly initialized */
int parseINTL(char * msgtxt, hs_addr * from, hs_addr * to)
{
    char * start;
    hs_addr intl_from = *from, intl_to = *to; /* set defaults */
    int result = 0, temp_point;

    /* Parse the INTL Kludge */
    start = strstr(msgtxt, "\001INTL ");

    if(start)
    {
        start += 6;               /*  skip "INTL " */

        if(!(parseFtnAddrZ(start, &intl_to, FTNADDR_GOOD,
                           (const char **)(&start)) & FTNADDR_ERROR) &&
           !(parseFtnAddrZ(start, &intl_from, FTNADDR_GOOD,
                           (const char **)(&start)) & FTNADDR_ERROR))
        /*  '(const char**)(&start)' is needs for prevent warning "passing arg 4 of
           `parseFtnAddrZ' from incompatible pointer type" */
        {
            /* INTL is valid, copy parsed data to output */
            /* copying the whole structures is ok since they are initialized by from and to */
            *from   = intl_from;
            *to     = intl_to;
            result |= INTL_FOUND;
        }
    }
    else
    {
        w_log(LL_DEBUGB, "Warning: no INTL kludge found in message");
    }

    start = strstr(msgtxt, "\001FMPT");

    if(start)
    {
        start      += 6;           /* skip "FMPT " */
        temp_point  = atoi(start);
        from->point = (temp_point >= 0 && temp_point <= 32767) ? (sword)temp_point : 0;
        /* Actually there should not be */
        result |= FMPT_FOUND;
    }
    else
    {
        /* while standard says that no FMPT kludge means zero point, we wont change
         * point nuber here but will rely on interpretation of caller function */
    }

    /* and the same for TOPT */
    start = strstr(msgtxt, "\001TOPT");

    if(start)
    {
        start     += 6;            /* skip "TOPT " */
        temp_point = atoi(start);
        to->point  = (temp_point >= 0 && temp_point <= 32767) ? (sword)temp_point : 0;
        result    |= TOPT_FOUND;
    }
    else
    {
        /* while standard says that no TOPT kludge means zero point, we wont change
         * point nuber here but will rely on interpretation of caller function */
    }

    return result;
} /* parseINTL */

void correctEMAddr(s_message * msg)
{
    char * start = NULL, * temp;

    /* Find originating address in Origin line */
    start = strrstr(msg->text, " * Origin:");

    if(start)
    {
        temp = start += 10; /* skip " * Origin:" */

        while(*start && (*start != '\r') && (*start != '\n'))
        {
            start++;                                                   /*  get to end of line */
        }
        --start;

        while(*(start) == ' ')
        {
            --start;                   /* skip trailing spaces, just in case */
        }

        if(*(start) == ')')                          /*  if there is no ')', there is no origin
                                                        */
        {
            while(--start > temp && *start != '(' && /*  find beginning '(' */
                  !isspace(*start))
            {}

            if(*start == '(' || *start == ' ') /* "(1:2/3.4@dom)" or " 1:2/3.4@dom)" is found */
            {
                start++;               /*  skip '(' or ' ' */

                if(!(parseFtnAddrZS(start, &msg->origAddr) & FTNADDR_ERROR))
                {
                    return; /* FTN address is taken from Origin */
                }
            }
        }
    }

    /* Find originating address in MSGID line */
    start = strrstr(msg->text, "\001MSGID:");

    /* Standard requires "\001MSGID: " but not all software is compatible with FTS-9 :( */
    if(start)
    {
        start += 7;

        if(!(parseFtnAddrZS(start, &msg->origAddr) & FTNADDR_ERROR))
        {
            return; /* FTN address is taken from MSGID */
        }
    }

    /*  Another try...
     *  But if MSGID isn't present or broken and origin is broken
     *  then PATH may be broken too...
     */
    start = strstr(msg->text, "\001PATH: ");

    if(start)
    {
        start += 7;

        if(!(parseFtnAddrZ(start, &msg->origAddr, FTNADDR_2D, NULL) & FTNADDR_ERROR))
        {
            return; /* FTN address is taken from PATH */
        }
    }

    /* if nothing works then send report to RC ;) */
} /* correctEMAddr */

void correctNMAddr(s_message * msg, s_pktHeader * header)
{
    char * text = NULL;
    int valid_intl_kludge;
    int zonegated = 0;
    hs_addr intl_from = msg->origAddr, intl_to = msg->destAddr;
    UINT i;

    valid_intl_kludge = parseINTL(msg->text, &intl_from, &intl_to);

    /* Assign point numbers if FMPT/TOPT kludges are found */
    if(valid_intl_kludge & FMPT_FOUND)
    {
        msg->origAddr.point = intl_from.point;
    }

    if(valid_intl_kludge & TOPT_FOUND)
    {
        msg->destAddr.point = intl_to.point;
    }

    /* if no kludges are found then leave current values
     *  which most possible are zeroes */
    /* now interpret the INTL kludge */
    if(valid_intl_kludge & INTL_FOUND)
    {
        /* the from part is easy - we can always use it */
        msg->origAddr.zone = intl_from.zone;
        msg->origAddr.net  = intl_from.net;
        msg->origAddr.node = intl_from.node;
        /* the to part is more complicated */
        zonegated = 0;

        if(msg->destAddr.net == intl_from.zone && msg->destAddr.node == intl_to.zone)
        {
            zonegated = 1;

            /* we want to ignore the zone gating if we are the zone gate */
            for(i = 0; i < config->addrCount; i++)
            {
                if(config->addr[i].zone == msg->destAddr.net &&
                   config->addr[i].net == msg->destAddr.net &&
                   config->addr[i].node == msg->destAddr.node && config->addr[i].point == 0)
                {
                    zonegated = 0;
                }
            }
        }

        if(zonegated)
        {
            msg->destAddr.zone = intl_from.zone;
            msg->destAddr.net  = intl_from.zone;
            msg->destAddr.node = intl_to.zone;
        }
        else
        {
            msg->destAddr.zone = intl_to.zone;
            msg->destAddr.net  = intl_to.net;
            msg->destAddr.node = intl_to.node;
        }
    }
    else
    {
        /* no INTL kludge */
        msg->destAddr.zone = header->destAddr.zone;
        msg->origAddr.zone = header->origAddr.zone;
        msg->textLength   += xscatprintf(&text,
                                         "\001INTL %u:%u/%u %u:%u/%u\r",
                                         msg->destAddr.zone,
                                         msg->destAddr.net,
                                         msg->destAddr.node,
                                         msg->origAddr.zone,
                                         msg->origAddr.net,
                                         msg->origAddr.node);
        xstrcat(&text, msg->text);
        nfree(msg->text);
        msg->text = text;
        w_log(LL_PKT,
              "Mail without INTL-Kludge. Assuming %i:%i/%i.%i -> %i:%i/%i.%i",
              msg->origAddr.zone,
              msg->origAddr.net,
              msg->origAddr.node,
              msg->origAddr.point,
              msg->destAddr.zone,
              msg->destAddr.net,
              msg->destAddr.node,
              msg->destAddr.point);
    } /* endif */
} /* correctNMAddr */

void correctAddr(s_message * msg, s_pktHeader * header)
{
    if(strncmp(msg->text, "AREA:", 5) == 0)
    {
        if(strncmp(msg->text + 5, "NETMAIL\r", 8) == 0)
        {
            switch(config->kludgeAreaNetmail)
            {
                case kanKill: /*  kill "AREA:NETMAIL\r" */
                    memmove(msg->text, msg->text + 13, msg->textLength - 12);

                case kanIgnore: /*  process as netmail. don't touch kludge. */
                    msg->netMail = 1;

                default: /*  process as echomail */
                    break;
            }
        }
    }
    else
    {
        msg->netMail = 1;
    }

    if(msg->netMail)
    {
        correctNMAddr(msg, header);
    }
    else
    {
        correctEMAddr(msg);
    }
} /* correctAddr */

/* Some toupper routines crash when they get invalid input. As this program
   is intended to be portable and deal with any sort of malformed input,
   we have to provide our own toupper routine. */
char safe_toupper(char c)
{
    const char * from_table = "abcdefghijklmnopqrstuvwxyz";
    const char * to_table   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char * p;

    if((p = strchr(from_table, c)) != NULL)
    {
        return to_table[p - from_table];
    }

    return c;
}

int get_month(const char * pmon, flag_t * flag)
{
    int i;

    if(strlen(pmon) != 3 && flag != NULL)
    {
        (*flag) |= FTSC_FLAWY;
    }

    for(i = 0; i < 12; i++)
    {
        if(pmon[0] == months_ab[i][0] && pmon[1] == months_ab[i][1] && pmon[2] == months_ab[i][2])
        {
            return i;
        }
    }

    for(i = 0; i < 12; i++)
    {
        if(safe_toupper(pmon[0]) == safe_toupper(months_ab[i][0]) &&
           safe_toupper(pmon[1]) == safe_toupper(months_ab[i][1]) &&
           safe_toupper(pmon[2]) == safe_toupper(months_ab[i][2]))
        {
            (*flag) |= FTSC_FLAWY;
            return i;
        }
    }
    (*flag) |= FTSC_BROKEN;
    return 0;
} /* get_month */

flag_t parse_ftsc_date(struct tm * ptm, char * pdatestr)
{
    const char * pday, * pmon, * pyear, * phour, * pminute, * psecond;
    flag_t rval;
    char buf[22];
    int fixseadog = 0;
    struct tm * pnow;
    time_t t_now;

    time(&t_now);
    pnow = localtime(&t_now);   /* get the current time */

    pday = pmon = pyear = phour = pminute = psecond = NULL;
    rval = FTSC_BROKEN;
    memcpy(buf, pdatestr, 21);
    buf[21] = 0;

    if((pday = strtok(buf, " ")) != NULL)
    {
        if((pmon = strtok(NULL, " ")) != NULL)
        {
            if((pyear = strtok(NULL, " ")) != NULL)
            {
                if((phour = strtok(NULL, ":")) != NULL)
                {
                    if((pminute = strtok(NULL, ":")) != NULL)
                    {
                        if((psecond = strtok(NULL, " ")) != NULL)
                        {
                            rval = 0;
                        }
                    }
                }
            }
        }
    }

    if(rval == FTSC_BROKEN)
    {
        /* let's try and see if it might be the old SeaDog format */
        memcpy(buf, pdatestr, 21);
        buf[21] = 0;

        if((strtok(buf, " ")) != NULL)
        {
            if((pday = strtok(NULL, " ")) != NULL)
            {
                if((pmon = strtok(NULL, " ")) != NULL)
                {
                    if((pyear = strtok(NULL, " ")) != NULL)
                    {
                        if((phour = strtok(NULL, ": ")) != NULL)
                        {
                            if((pminute = strtok(NULL, ": ")) != NULL)
                            {
                                psecond = NULL;

                                if(fixseadog)
                                {
                                    rval = FTSC_SEADOG;
                                }
                                else
                                {
                                    rval = 0;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    ptm->tm_sec = ptm->tm_min = ptm->tm_hour = ptm->tm_mday = ptm->tm_mon = ptm->tm_year = 0;

    while(rval != FTSC_BROKEN)     /* at least we could tokenize it! */
    {
        if(psecond != NULL)
        {
            ptm->tm_sec = atoi(psecond);   /* Is the number of seconds valid? */

            if(strlen(psecond) == 1)
            {
                rval |= FTSC_FLAWY;

                if(ptm->tm_sec < 6)
                {
                    (ptm->tm_sec *= 10);
                }
            }

            if(ptm->tm_sec < 0 || ptm->tm_sec > 59)
            {
                rval       |= FTSC_TS_BROKEN;
                ptm->tm_sec = 0;
            }
        }
        else
        {
            ptm->tm_sec = 0;
        }

        ptm->tm_min = atoi(pminute);   /* Is the number of minutes valid? */

        if(ptm->tm_min < 0 || ptm->tm_min > 59)
        {
            rval       |= FTSC_TS_BROKEN;
            ptm->tm_min = 0;
        }

        ptm->tm_hour = atoi(phour);    /* Is the number of hours valid? */

        if(ptm->tm_hour < 0 || ptm->tm_hour > 23)
        {
            rval        |= FTSC_TS_BROKEN;
            ptm->tm_hour = 0;
        }

        ptm->tm_mday = atoi(pday);     /* Is the day in the month valid? */

        if(ptm->tm_mday < 1 || ptm->tm_mday > 31)
        {
            rval |= FTSC_BROKEN;
            break;
        }

        ptm->tm_mon = get_month(pmon, &rval); /* Is the month valid? */

        if(strlen(pyear) != 2)         /* year field format check */
        {
            rval |= FTSC_FLAWY;
        }

        if(*pyear)
        {
            ptm->tm_year = (*pyear - '0'); /* allows for the ":0" bug */

            for(pyear++; isdigit((int)(*pyear)); pyear++)
            {
                ptm->tm_year *= 10;
                ptm->tm_year += (*pyear - '0');
            }

            if(*pyear)
            {
                rval |= FTSC_BROKEN;
                break;
            }
        }
        else
        {
            rval |= FTSC_BROKEN;
            break;
        }

        if(ptm->tm_year < 100)   /* correct date field! */
        {
            while(pnow->tm_year - ptm->tm_year > 50) /* sliding window adaption */
            {
                ptm->tm_year += 100;
            }
        }
        else if(ptm->tm_year < 1900)  /* probably the field directly */
                                      /* contains tm_year, like produced */
                                      /* by the Timed/Netmgr bug and others */
        {
            rval |= FTSC_FLAWY;
        }
        else                          /* 4 digit year field, not correct! */
        {
            ptm->tm_year -= 1900;
            rval         |= FTSC_FLAWY;
        }

        break;
    }
    return rval;
} /* parse_ftsc_date */

void make_ftsc_date(char * pdate, const struct tm * ptm)
{
    sprintf(pdate,
            "%02d %-3.3s %02d  %02d:%02d:%02d",
            ptm->tm_mday % 100,
            months_ab[ptm->tm_mon],
            ptm->tm_year % 100,
            ptm->tm_hour % 100,
            ptm->tm_min % 100,
            ptm->tm_sec % 100);
}

int readMsgFromPkt(FILE * pkt, s_pktHeader * header, s_message ** message)
{
    s_message * msg;
    size_t len;
    int badmsg = 0;
    struct tm tm;
    long unread;

    if(2 != getUINT16(pkt))
    {
        *message = NULL;
        unread   = (long)ftell(pkt);
        fseek(pkt, 0L, SEEK_END);
        unread = (long)ftell(pkt) - unread; /*  unread bytes */

        if(unread)
        {
            w_log(LL_ERR, "There are %d bytes of unknown data at the end of pkt file!", unread);
            return 2; /*  rename to bad */
        }
        else
        {
            return 0;  /*  end of pkt file */
        }
    }

    msg = (s_message *)safe_malloc(sizeof(s_message));
    memset(msg, '\0', sizeof(s_message));
    msg->origAddr.node = getUINT16(pkt);
    msg->destAddr.node = getUINT16(pkt);
    msg->origAddr.net  = getUINT16(pkt);
    msg->destAddr.net  = getUINT16(pkt);
    msg->attributes    = getUINT16(pkt);
    getc(pkt);
    getc(pkt);                           /*  read unused cost fields (2bytes) */

    /* val: fgetsUntil0 (msg->datetime, 22, pkt, NULL);*/
    if(fread(msg->datetime, 20, 1, pkt) != 1)       /* read datetime field - 20 bytes */
    {
        badmsg++;
    }

    msg->datetime[20] = 0;               /* ensure it's null-terminated */
    parse_ftsc_date(&tm, (char *)msg->datetime);

    /* val: make_ftsc_date((char*)msg->datetime, &tm); */
    if(globalBuffer == NULL)
    {
        globalBuffer = (UCHAR *)safe_malloc(BUFFERSIZE + 1); /*  128K (32K in MS-DOS) */
    }

    len = fgetsUntil0((UCHAR *)globalBuffer, BUFFERSIZE + 1, pkt, NULL);

    if(len > XMSG_TO_SIZE)
    {
        if(config->intab)
        {
            recodeToInternalCharset((char *)globalBuffer);
        }

        w_log(LL_ERR,
              "wrong msg header: toUserName (%s) is longer than %d bytes.",
              globalBuffer,
              XMSG_TO_SIZE - 1);

        if(config->outtab)
        {
            recodeToTransportCharset((char *)globalBuffer);
        }

        globalBuffer[XMSG_TO_SIZE - 1] = '\0';
        badmsg++;
    }

    xstrcat(&msg->toUserName, (char *)globalBuffer);
    len = fgetsUntil0((UCHAR *)globalBuffer, BUFFERSIZE + 1, pkt, NULL);

    if(len > XMSG_FROM_SIZE)
    {
        if(config->intab)
        {
            recodeToInternalCharset((char *)globalBuffer);
        }

        w_log(LL_ERR,
              "wrong msg header: fromUserName (%s) is longer than %d bytes.",
              globalBuffer,
              XMSG_FROM_SIZE - 1);

        if(config->outtab)
        {
            recodeToTransportCharset((char *)globalBuffer);
        }

        globalBuffer[XMSG_FROM_SIZE - 1] = '\0';
        badmsg++;
    }

    xstrcat(&msg->fromUserName, (char *)globalBuffer);
    len = fgetsUntil0((UCHAR *)globalBuffer, BUFFERSIZE + 1, pkt, NULL);

    if(len > XMSG_SUBJ_SIZE)
    {
        if(config->intab)
        {
            recodeToInternalCharset((char *)globalBuffer);
        }

        w_log(LL_ERR,
              "wrong msg header: subjectLine (%s) is longer than %d bytes.",
              globalBuffer,
              XMSG_SUBJ_SIZE - 1);

        if(config->outtab)
        {
            recodeToTransportCharset((char *)globalBuffer);
        }

        globalBuffer[XMSG_SUBJ_SIZE - 1] = '\0';
        badmsg++;
    }

    xstrcat(&msg->subjectLine, (char *)globalBuffer);

    if(badmsg)
    {
        freeMsgBuffers(msg);
        *message = NULL;
        w_log(LL_ERR, "wrong msg header: renaming pkt to bad.");
        return 2; /*  exit with error */
    }

#if !defined (__DOS__) || defined (__FLAT__)
    do
    {
        len = fgetsUntil0((UCHAR *)globalBuffer, BUFFERSIZE + 1, pkt, "\n");
        xstrcat(&msg->text, (char *)globalBuffer);
        msg->textLength += (hINT32)len - 1; /*  trailing \0 is not the text */
    }
    while(len == BUFFERSIZE + 1);
#else
    /* DOS: read only one segment of message */
    len = fgetsUntil0((UCHAR *)globalBuffer, BUFFERSIZE + 1, pkt, "\n");
    xstrcat(&msg->text, globalBuffer);
    msg->textLength += len - 1; /*  trailing \0 is not the text */

    if((len == BUFFERSIZE + 1))
    {
        badmsg++;
        xstrscat(&msg->text, "\r* Message too big, truncated by ", versionStr, "\r", NULLP);

        do
        {
            char * origin;
            len = fgetsUntil0((UCHAR *)globalBuffer, BUFFERSIZE + 1, pkt, "\n");

            /* add kludges to end of striped text */
            if((origin = strstr(globalBuffer, " * Origin")))
            {
                xstrcat(&msg->text, origin);
            }
        }
        while(len == BUFFERSIZE + 1);
        strncpy(globalBuffer, aka2str(&msg->destAddr), BUFFERSIZE);
        w_log(LL_ERR, "Message from %s to %s is too big!", aka2str(&msg->origAddr), globalBuffer);
    }

#endif /* if !defined (__DOS__) || defined (__FLAT__) */

    correctAddr(msg, header);
#ifndef DO_PERL
    {
        char * p, * q;

        /*  del "\001FLAGS" from message text */
        if(NULL != (p = strstr(msg->text, "\001FLAGS")))
        {
            for(q = p; *q && *q != '\r'; q++)
            {}
            memmove(p, q + 1, msg->textLength - (q - msg->text));
            msg->textLength -= (hINT32)(q - p + 1);
        }
    }
#endif
    *message = msg;
    return 1;
} /* readMsgFromPkt */
