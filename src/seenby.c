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
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <fcommon.h>
#include <global.h>
#include <seenby.h>
#include <fidoconf/xstr.h>
#include <fidoconf/common.h>

s_seenByZone seenBysZone[MAX_ZONE];

int compare(const void *first, const void *second)
{
   if ( ((s_seenBy*) first)->net < ((s_seenBy*) second)->net) return -1;
   else
      if ( ((s_seenBy*) first)->net > ((s_seenBy*) second)->net) return 1;
      else if ( ((s_seenBy*) first)->node < ((s_seenBy*) second)->node) return -1;
           else if ( ((s_seenBy*) first)->node > ((s_seenBy*) second)->node) return 1;
   return 0;
}

void sortSeenBys(s_seenBy *seenBys, UINT16 count)
{
   qsort(seenBys, count, sizeof(s_seenBy), compare);
}

void cleanDupesFromSeenBys(s_seenBy **seenBys, UINT16 *count)
{
    UINT16 i;
    s_seenBy seenBy;

    if (seenBys == NULL || *seenBys == NULL || count == NULL || *count < 2)
        return;

    sortSeenBys(*seenBys, *count);
    seenBy.net = (*seenBys)[0].net;
    seenBy.node = (*seenBys)[0].node;

    for (i=1;i<*count;i++) {
        if ((*seenBys)[i].net == seenBy.net &&
            (*seenBys)[i].node == seenBy.node)
        { /* seenby[i-1] == seenby[i] - overwrite it */
            (*seenBys)[i].net = (*seenBys)[--*count].net;
            (*seenBys)[i].node = (*seenBys)[--*count].node;
            sortSeenBys((*seenBys), *count);
        }
        seenBy.net = (*seenBys)[i].net;
        seenBy.node = (*seenBys)[i].node;
    }
}

void cleanDupes_seenByZone()
{
    UINT16 i;

    for (i=0;i<MAX_ZONE;i++)
        cleanDupesFromSeenBys(&(seenBysZone[i].seenByArray), (UINT16 *) &(seenBysZone[i].seenByCount));
}

void zero_seenBysZone()
{
    UINT16 i;

    for (i=0;i<MAX_ZONE;i++)
    {
        seenBysZone[i].seenByArray = NULL;
        seenBysZone[i].seenByCount = 0;
    }
}

void print_seenBysZone()
{
    UINT16 i;
    char *text;

    w_log(LL_DEBUGS, "printing seen-bys...");

    for (i=0;i<MAX_ZONE;i++)
    {
        if (seenBysZone[i].seenByCount) {
            w_log(LL_DEBUGS, "printing %u seenbys of zone %u", seenBysZone[i].seenByCount, i);
            text = createControlText(seenBysZone[i].seenByArray, seenBysZone[i].seenByCount, "");
            w_log(LL_DEBUGS, "SEEN-BY: %s", text);
            nfree(text);
        }
    }
}

void free_seenBysZone()
{
    UINT16 i;
    for (i=0;i<MAX_ZONE;i++)
        nfree(seenBysZone[i].seenByArray);
    zero_seenBysZone();
}

void attachTo_seenBysZone(UINT16 zone, s_seenBy **seenBys, UINT16 count)
{
    seenBysZone[zone].seenByArray = *seenBys;
    seenBysZone[zone].seenByCount = count;
}

void addTo_seenByZone(UINT16 zone, UINT16 net, UINT16 node)
{
    UINT16 i;
    s_seenBy *tmp=NULL, *tmp2=NULL;

#ifdef DEBUG_HPT
    w_log(LL_DEBUGS, "adding %u:%u/%u to seen-by chain", zone, net, node);
    print_seenBysZone();
#endif
    if (seenBysZone[zone].seenByArray == NULL) {
        i=0;
        seenBysZone[zone].seenByArray = (s_seenBy *) safe_calloc(sizeof(s_seenBy), 1);
        seenBysZone[zone].seenByCount++;
#ifdef DEBUG_HPT
        w_log(LL_DEBUGS, "created seen-by array for zone %u", zone);
#endif
    } else {
        for (i=0;i<seenBysZone[zone].seenByCount;i++)
        {
            if (seenBysZone[zone].seenByArray[i].net == net &&
                seenBysZone[zone].seenByArray[i].node == node) {
#ifdef DEBUG_HPT
                w_log(LL_DEBUGS, "already found this address in sb array");
#endif
                return; /* already found this address in sb array */
            }
        }
        seenBysZone[zone].seenByCount++;
        tmp = (s_seenBy *) safe_malloc(seenBysZone[zone].seenByCount * sizeof(s_seenBy));
        memset(tmp, 0, sizeof(s_seenBy) * seenBysZone[zone].seenByCount);
        memcpy(tmp, seenBysZone[zone].seenByArray, sizeof(s_seenBy) * (seenBysZone[zone].seenByCount-1));
        tmp2 = seenBysZone[zone].seenByArray;
        seenBysZone[zone].seenByArray = tmp;
        nfree(tmp2);
#ifdef DEBUG_HPT
        w_log(LL_DEBUGS, "enlarge sb array to 1 element, %u bytes of memory", sizeof(s_seenBy));
        print_seenBysZone();
#endif
    }
    seenBysZone[zone].seenByArray[seenBysZone[zone].seenByCount-1].net = net;
    seenBysZone[zone].seenByArray[seenBysZone[zone].seenByCount-1].node = node;
#ifdef DEBUG_HPT
    w_log(LL_DEBUGS, "seenBysZone[%u].seenByCount = %u", zone, seenBysZone[zone].seenByCount);
    print_seenBysZone();
#endif
}

void deleteFrom_seenByZone(UINT16 zone, UINT16 net, UINT16 node)
{
    UINT16 i;

    if (seenBysZone[zone].seenByArray == NULL) return;

    for (i=0;i<seenBysZone[zone].seenByCount;i++)
    {
        if (seenBysZone[zone].seenByArray[i].net == net &&
            seenBysZone[zone].seenByArray[i].node == node)
            break; /* already found this address in sb array */
    }
    seenBysZone[zone].seenByArray[i].net = 0;
    seenBysZone[zone].seenByArray[i].net = 0;
}

char *createControlText(s_seenBy seenBys[], UINT16 seenByCount, char *lineHeading)
{
#define size 81
#define addr2dSize 13
   UINT16  i;
   char *text=NULL, *line = NULL, addr2d[addr2dSize];

   if (seenByCount==0) {              /* return empty control line */
       xstrcat(&text, lineHeading);
       /* reserve one byte for \r */
       text = (char *) safe_realloc(text, strlen(text)+2);
   } else {
      line = safe_malloc ((size_t) size);
      sprintf(addr2d, "%u/%u", seenBys[0].net, seenBys[0].node);
      text = (char *) safe_malloc((size_t) size);
      text[0]='\0';
      strncpy(line, lineHeading, size);
      strncat(line, addr2d, size);
      for (i=1; i < seenByCount; i++) {

/*  fix for double seen-by's (may be after ignoreSeen) */
/*  NOTE! fixed seen-by's hides shitty tossers! */
/*  it is not recommended to uncomment this. */
/* 		 if (config->ignoreSeenCount && */
/* 			 seenBys[i-1].net == seenBys[i].net && */
/* 			 seenBys[i-1].node == seenBys[i].node) continue; */

         if (seenBys[i-1].net == seenBys[i].net)
            sprintf(addr2d, " %u", seenBys[i].node);
         else
            sprintf(addr2d, " %u/%u", seenBys[i].net, seenBys[i].node);

         if (strlen(line)+strlen(addr2d) > size-3) {
            /* if line would be greater than 79 characters, make new line */
            strcat(text, line);
            strncat(text, "\r", size);
            text = (char *) safe_realloc(text,strlen(text)+size);
            strncpy(line, lineHeading, size);
            /*  start new line with full 2d information */
            sprintf(addr2d, "%u/%u", seenBys[i].net, seenBys[i].node);
         }
         strcat(line, addr2d);
      }
	  /*  reserve only needed space + ending \r */
	  text = (char *) safe_realloc(text, strlen(text)+strlen(line)+2);
	  strcat(text,line);
	  nfree(line);
   }
                           
   strncat(text, "\r", size);

   return text;
}

void createSeenByArrayFromMsg(s_message *msg, s_seenBy **seenBys, UINT16 *seenByCount)
{
    char *seenByText=NULL, *start = NULL, *token = NULL;
    unsigned long temp;
    char *endptr = NULL;
    UINT16 seenByAlloced;
#ifdef DEBUG_HPT
    int i;
#endif
    *seenByCount = seenByAlloced = 0;

    start = strrstr(msg->text, " * Origin:"); /*  jump over Origin */
    if (start == NULL) start = msg->text;

    /*  find beginning of seen-by lines */
    do {
        start = strstr(start, "SEEN-BY:");
        if (start == NULL) return;
        start += 8; /*  jump over SEEN-BY: */

        while (*start == ' ') start++; /*  find first word after SEEN-BY: */
    } while (!isdigit(*start));

    /*  now that we have the start of the SEEN-BY's we can tokenize the lines and read them in */
    xstrcat(&seenByText, start);

    token = strtok(seenByText, " \r\t\376");
    for (; token != NULL; token = strtok(NULL, " \r\t\376")) {
        if (isdigit(*token)) {
            /*  parse token */
            temp = strtoul(token, &endptr, 10);
            if (*endptr==':') {
                token = endptr+1;
                temp = strtoul(token, &endptr, 10);
            }
            if (*endptr && *endptr != '/')
                continue;

            /*  get new memory */
            if ((*seenByCount)++ >= seenByAlloced)
                (*seenBys) = (s_seenBy*) safe_realloc(*seenBys, sizeof(s_seenBy) * (seenByAlloced+=32));

            if ((*endptr) == '\0') {
                /*  only node aka */
                (*seenBys)[*seenByCount-1].node = (UINT16) temp;
                /*  use net aka of last seenBy */
                (*seenBys)[*seenByCount-1].net = (*seenBys)[*seenByCount-2].net;
            } else {
                /*  net and node aka */
                (*seenBys)[*seenByCount-1].net = (UINT16) temp;
                /*  eat up '/' */
                endptr++;
                (*seenBys)[*seenByCount-1].node = (UINT16) atol(endptr);
            }
        } else if (strcmp(token,"SEEN-BY:")!=0) break; /*  not digit and not SEEN-BY */

    } /*  end while */

    if (*seenByCount != seenByAlloced)
        (*seenBys) = (s_seenBy*) safe_realloc(*seenBys, sizeof(s_seenBy) * (*seenByCount));
    /* test output for reading of seenBys... */
#ifdef DEBUG_HPT
    for (i=0; i < *seenByCount; i++) printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
#endif
    /*    exit(2); */

    nfree(seenByText);
}

void createPathArrayFromMsg(s_message *msg, s_seenBy **seenBys, UINT16 *seenByCount)
{

    /*  DON'T GET MESSED UP WITH THE VARIABLES NAMED SEENBY... */
    /*  THIS FUNCTION READS PATH!!! */

    char *seenByText=NULL, *start = NULL, *token = NULL;
    char *endptr = NULL;
    unsigned long temp;
    UINT16 seenByAlloced;
#ifdef DEBUG_HPT
    UINT16 i;
#endif

    *seenByCount = seenByAlloced = 0;

    start = strrstr(msg->text, " * Origin:"); /*  jump over Origin */
    if (start == NULL) start = msg->text;

    /*  find beginning of path lines */
    do {
        start = strstr(start, "\001PATH:");
        if (start == NULL) return;
        for (endptr = strchr(start, '\r'); endptr; endptr = strchr(endptr, '\r')) {
            while (*endptr == '\r' || *endptr == '\n') endptr++;
            if (strncmp(endptr, "\001PATH:", 6)) break; /* not path line */
        }
        if (endptr && strstr(endptr, "\001PATH:")) {
            start = endptr;
            continue; /* only last path lines are valid */
        }
        start += 7; /*  jump over PATH: */

        while (*start == ' ') start++; /*  find first word after PATH: */
    } while (!isdigit(*start));

    /*  now that we have the start of the PATH' so we can tokenize the lines and read them in */
    xstrcat(&seenByText, start);

    token = strtok(seenByText, " \r\t\376");
    for (; token != NULL; token = strtok(NULL, " \r\t\376")) {
        if (isdigit(*token)) {
            /*  parse token */
            temp = strtoul(token, &endptr, 10);
            if (*endptr==':') {
                token = endptr+1;
                temp = strtoul(token, &endptr, 10);
            }
            if (*endptr && *endptr != '/')
                continue;

            /*  get new memory */
            if ((*seenByCount)++ >= seenByAlloced)
                (*seenBys) = (s_seenBy*) safe_realloc(*seenBys, sizeof(s_seenBy) * (seenByAlloced+=32));

            if ((*endptr) == '\0') {
                /*  only node aka */
                (*seenBys)[*seenByCount-1].node = (UINT16) temp;
                /*  use net aka of last seenBy */
                (*seenBys)[*seenByCount-1].net = (*seenBys)[*seenByCount-2].net;
            } else {
                /*  net and node aka */
                (*seenBys)[*seenByCount-1].net = (UINT16) temp;
                /*  eat up '/' */
                endptr++;
                (*seenBys)[*seenByCount-1].node = (UINT16) atol(endptr);
            }
        } else if (strcmp(token, "\001PATH:")!=0) break; /*  not digit and not PATH */
    }

    if (*seenByCount != seenByAlloced)
        (*seenBys) = (s_seenBy*) safe_realloc(*seenBys, sizeof(s_seenBy) * (*seenByCount));

    /*  test output for reading of paths... */
#ifdef DEBUG_HPT
    for (i=0; i < *seenByCount; i++) printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
#endif
    /* exit(2); */

    nfree(seenByText);
}

/**
  * This function returns 0 if the link is not in seenBy else it returns 1.
  */

UINT16 checkLink(s_seenBy *seenBys, UINT16 seenByCount, s_link *link,
              s_area *echo, hs_addr pktOrigAddr)
{
    UINT16 i,j;

    /*  the link where we got the mail from */
    if (addrComp(pktOrigAddr, link->hisAka) == 0) return 1;

    if (seenBys==NULL) return 0;

    /* skip our address in seen-by and allow to
       send the mail to links within our node-system */
    for (i=0; i < config->addrCount; i++)
        if ((link->hisAka.zone == config->addr[i].zone) &&
            (link->hisAka.net  == config->addr[i].net) &&
            (link->hisAka.node == config->addr[i].node))
            return 0;

    for (i=0; i < seenByCount; i++) {
        if ((link->hisAka.net==seenBys[i].net) &&
            (link->hisAka.node==seenBys[i].node)) {
            return 1;
        }
        for (j=0; j < config->ignoreSeenCount; j++) {
            if (config->ignoreSeen[j].net == seenBys[i].net &&
                config->ignoreSeen[j].node == seenBys[i].node) {
                link->sb = 1; /*  fix for double seen-bys */
                return 0;
            }
        }
        for (j=0; j < echo->sbignCount; j++) {
            if (echo->sbign[j].net == seenBys[i].net &&
                echo->sbign[j].node == seenBys[i].node) {
                link->sb = 1; /*  fix for double seen-bys */
                return 0;
            }
        }
    }
    return 0;
}

/* helper function, just for debugging */
void printNewLinks(s_arealink **newLinks, int count)
{
    char *str;
    int i;

    str=strdup("");
    for (i=0;i<count;i++)
        if (newLinks[i] != NULL)
            xscatprintf(&str, " %s", aka2str(newLinks[i]->link->hisAka));
    w_log(LL_DEBUGS, "newLinks: %s", str);
    nfree(str);
}

/*
 * This function builds an array of links who is subscribed to this echo
 * except ones listed in seenbys.
 */

void createNewLinksArray(s_area *echo, s_arealink ***newLinks,
                         hs_addr pktOrigAddr, UINT16 rsb)
{
    UINT16 i, lFound = 0;

    *newLinks =  (s_arealink **)safe_calloc(echo->downlinkCount,sizeof(s_arealink*));

#ifdef DEBUG_HPT
    w_log(LL_DEBUGS, "echo->downlinkCount = %u", echo->downlinkCount);
    printNewLinks(*newLinks, echo->downlinkCount);
#endif

    for (i=0; i < echo->downlinkCount; i++) {
        /*  link with "export off" */
        if (echo->downlinks[i]->export == 0) continue;
        if (echo->downlinks[i]->link->reducedSeenBy != rsb) continue;
        /* don't send to link if it is in seen-bys */
        if (checkLink(seenBysZone[echo->downlinks[i]->link->hisAka.zone].seenByArray,
                      seenBysZone[echo->downlinks[i]->link->hisAka.zone].seenByCount,
                      echo->downlinks[i]->link, echo, pktOrigAddr))
            continue;
#ifdef DEBUG_HPT
        w_log(LL_DEBUGS, "i=%u, lFound=%u", i, lFound);
#endif
        (*newLinks)[lFound++] = echo->downlinks[i];
#ifdef DEBUG_HPT
        w_log(LL_DEBUGS, "adding link %s to newLinks chain", aka2str(echo->downlinks[i]->link->hisAka));
        printNewLinks(*newLinks, echo->downlinkCount);
        w_log(LL_DEBUGS, "i=%u, lFound=%u --", i, lFound);
#endif
    }

#ifdef DEBUG_HPT
    w_log(LL_DEBUGS, "created %u links in newLinks chain", lFound);
    printNewLinks(*newLinks, echo->downlinkCount);
#endif

    if(lFound == 0)
        nfree(*newLinks);
}

void addLinksTo_seenByZone(s_arealink **newLinks, UINT16 count)
{
    UINT16 i;
    hs_addr *addr;

    if (newLinks == NULL) return;

    for (i=0; i < count; i++) {
        if (newLinks[i] == NULL) continue;
        addr = &newLinks[i]->link->hisAka;
        if (addr->point != 0) continue; /* don't include points */
        addTo_seenByZone(addr->zone, addr->net, addr->node);
    }
}

void addAkasTo_seenByZone()
{
    UINT16 i;
    for (i=0; i < config->addrCount; i++) {
        if (config->addr[i].point != 0) continue; /* don't include point addresses */
        addTo_seenByZone(config->addr[i].zone, config->addr[i].net, config->addr[i].node);
    }
}

void processAutoAdd_seenByZone(s_area *echo)
{
    UINT16 i, zone;

    for (zone=0;zone<MAX_ZONE;zone++) {
        for (i=0; i<config->addToSeenCount; i++)
            addTo_seenByZone(zone, config->addToSeen[i].net, config->addToSeen[i].node);
        for (i=0; i<echo->sbaddCount; i++)
            addTo_seenByZone(zone, echo->sbadd[i].net, echo->sbadd[i].node);
/*        for (i=0; i<config->ignoreSeenCount; i++)
            deleteFrom_seenByZone(zone, config->ignoreSeen[i].net, config->ignoreSeen[i].node);
        for (i=0; i<echo->sbignCount; i++)
            deleteFrom_seenByZone(zone, echo->sbign[i].net, echo->sbign[i].node); */
    }
}
