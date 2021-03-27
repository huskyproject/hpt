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
#include <assert.h>
#include <fcommon.h>
#include <areafix/areafix.h>
#include <global.h>
#include <seenby.h>
#include <huskylib/xstr.h>
#include <fidoconf/common.h>

int compare(const void * first, const void * second)
{
    if(((s_seenBy *)first)->net < ((s_seenBy *)second)->net)
    {
        return -1;
    }
    else
    {
        if(((s_seenBy *)first)->net > ((s_seenBy *)second)->net)
        {
            return 1;
        }
        else if(((s_seenBy *)first)->node < ((s_seenBy *)second)->node)
        {
            return -1;
        }
        else if(((s_seenBy *)first)->node > ((s_seenBy *)second)->node)
        {
            return 1;
        }
    }

    return 0;
}

void sortSeenBys(s_seenBy * seenBys, UINT count)
{
    assert(seenBys != NULL || count == 0);

    if(count)
    {
        qsort(seenBys, count, sizeof(s_seenBy), compare);
    }
}

char * createControlText(s_seenBy seenBys[], UINT seenByCount, char * lineHeading)
{
    #define size 81
    #define addr2dSize 13
    UINT i;
    char * text = NULL, * line = NULL, addr2d[addr2dSize];

    if(seenByCount == 0)              /* return empty control line */
    {
        xstrcat(&text, lineHeading);
        /* reserve one byte for \r */
        text = (char *)safe_realloc(text, strlen(text) + 2);
    }
    else
    {
        line = safe_malloc((size_t)size);
        sprintf(addr2d, "%u/%u", seenBys[0].net, seenBys[0].node);
        text    = (char *)safe_malloc((size_t)size);
        text[0] = '\0';
        strncpy(line, lineHeading, strnlen(lineHeading, size - 1));
        strncat(line, addr2d, strnlen(addr2d, size - 1 - strlen(line)));

        for(i = 1; i < seenByCount; i++)
        {
/*  fix for double seen-by's (may be after ignoreSeen) */
/*  NOTE! fixed seen-by's hides shitty tossers! */
/*  it is not recommended to uncomment this. */
/*       if (config->ignoreSeenCount && */
/*           seenBys[i-1].net == seenBys[i].net && */
/*           seenBys[i-1].node == seenBys[i].node) continue; */
            if(seenBys[i - 1].net == seenBys[i].net)
            {
                sprintf(addr2d, " %u", seenBys[i].node);
            }
            else
            {
                sprintf(addr2d, " %u/%u", seenBys[i].net, seenBys[i].node);
            }

            if(strlen(line) + strlen(addr2d) > size - 3)
            {
                /* if line would be greater than 79 characters, make new line */
                strcat(text, line);
                strncat(text, "\r", size);
                text = (char *)safe_realloc(text, strlen(text) + size);
                strncpy(line, lineHeading, size);
                /*  start new line with full 2d information */
                sprintf(addr2d, "%u/%u", seenBys[i].net, seenBys[i].node);
            }

            strcat(line, addr2d);
        }
        /*  reserve only needed space + ending \r */
        text = (char *)safe_realloc(text, strlen(text) + strlen(line) + 2);
        strcat(text, line);
        nfree(line);
    }

    strncat(text, "\r", size);
    return text;
} /* createControlText */

void createSeenByArrayFromMsg(s_area * area,
                              s_message * msg,
                              s_seenBy ** seenBys,
                              UINT * seenByCount)
{
    char * seenByText = NULL, * start = NULL, * token = NULL;
    unsigned long temp;
    char * endptr = NULL;
    UINT seenByAlloced;

    unused(area);
    *seenByCount = seenByAlloced = 0;
    start        = strrstr(msg->text, " * Origin:"); /*  jump over Origin */

    if(start == NULL)
    {
        start = msg->text;
    }

    /*  find beginning of seen-by lines */
    do
    {
        start = strstr(start, "SEEN-BY:");

        if(start == NULL)
        {
            return;
        }

        start += 8; /*  jump over SEEN-BY: */

        while(*start == ' ')
        {
            start++;               /*  find first word after SEEN-BY: */
        }
    }
    while(!isdigit(*start));
    /*  now that we have the start of the SEEN-BY's we can tokenize the lines and read them in
       */
    xstrcat(&seenByText, start);
    token = strtok(seenByText, " \r\t\376");

    for( ; token != NULL; token = strtok(NULL, " \r\t\376"))
    {
        if(isdigit(*token))
        {
            /*  parse token */
            temp = strtoul(token, &endptr, 10);

            if(*endptr == ':')
            {
                token = endptr + 1;
                temp  = strtoul(token, &endptr, 10);
            }

            if(*endptr && *endptr != '/')
            {
                continue;
            }

            /*  get new memory */
            if((*seenByCount)++ >= seenByAlloced)
            {
                (*seenBys) =
                    (s_seenBy *)safe_realloc(*seenBys, sizeof(s_seenBy) * (seenByAlloced += 32));
            }

            if((*endptr) == '\0')
            {
                /*  only node aka */
                (*seenBys)[*seenByCount - 1].node = (UINT16)temp;

                /*  use net aka of last seenBy */
                if(*seenByCount >= 2)
                {
                    (*seenBys)[*seenByCount - 1].net = (*seenBys)[*seenByCount - 2].net;
                }
                else /* Shouldn't really happen. The best way out is unclear. */
                     /* I propose to drop incorrect seen-by's, as possible dupes seem to be
                        lesser evil
                        compared to possible loss of mail if choose to propagate mail with buggy
                           control
                        lines --Elfy 2010-03-18 */
                {
                    w_log(LL_ALERT,
                          "Buggy SEEN-BY line encountered. Invalid node was removed from the line!");   /*
                                                                                                           FIXME:
                                                                                                           print
                                                                                                           msgid
                                                                                                           to
                                                                                                           pinpoint
                                                                                                           problem?
                                                                                                           */
                    --*seenByCount;
                }
            }
            else
            {
                /*  net and node aka */
                (*seenBys)[*seenByCount - 1].net = (UINT16)temp;
                /*  eat up '/' */
                endptr++;
                (*seenBys)[*seenByCount - 1].node = (UINT16)atol(endptr);
            }
        }
        else if(strcmp(token, "SEEN-BY:") != 0)
        {
            break;                                 /*  not digit and not SEEN-BY */
        }
    } /*  end while */

    if(*seenByCount != seenByAlloced)
    {
        if(*seenByCount > 0)
        {
            (*seenBys) = (s_seenBy *)safe_realloc(*seenBys, sizeof(s_seenBy) * (*seenByCount));
        }
        else
        {
            nfree(*seenBys);
            seenByAlloced = 0;
        }
    }

    /* test output for reading of seenBys... */
#ifdef DEBUG_HPT

    for(i = 0; i < *seenByCount; i++)
    {
        printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
    }
#endif
/*    exit(2); */
    nfree(seenByText);
} /* createSeenByArrayFromMsg */

void createPathArrayFromMsg(s_message * msg, s_seenBy ** seenBys, UINT * seenByCount)
{
    /*  DON'T GET MESSED UP WITH THE VARIABLES NAMED SEENBY... */
    /*  THIS FUNCTION READS PATH!!! */
    char * seenByText = NULL, * start = NULL, * token = NULL;
    char * endptr = NULL;
    unsigned long temp;
    UINT seenByAlloced;

#ifdef DEBUG_HPT
    int i;
#endif

    *seenByCount = seenByAlloced = 0;
    start        = strrstr(msg->text, " * Origin:"); /*  jump over Origin */

    if(start == NULL)
    {
        start = msg->text;
    }

    /*  find beginning of path lines */
    do
    {
        start = strstr(start, "\001PATH:");

        if(start == NULL)
        {
            return;
        }

        for(endptr = strchr(start, '\r'); endptr; endptr = strchr(endptr, '\r'))
        {
            while(*endptr == '\r' || *endptr == '\n')
            {
                endptr++;
            }

            if(strncmp(endptr, "\001PATH:", 6))
            {
                break; /* not path line */
            }
        }

        if(endptr && strstr(endptr, "\001PATH:"))
        {
            start = endptr;
            continue; /* only last path lines are valid */
        }

        start += 7; /*  jump over PATH: */

        while(*start == ' ')
        {
            start++; /*  find first word after PATH: */
        }
    }
    while(!isdigit(*start));
    /*  now that we have the start of the PATH' so we can tokenize the lines and read them in */
    xstrcat(&seenByText, start);
    token = strtok(seenByText, " \r\t\376");

    for( ; token != NULL; token = strtok(NULL, " \r\t\376"))
    {
        if(isdigit(*token))
        {
            /*  parse token */
            temp = strtoul(token, &endptr, 10);

            if(*endptr == ':')
            {
                token = endptr + 1;
                temp  = strtoul(token, &endptr, 10);
            }

            if(*endptr && *endptr != '/')
            {
                continue;
            }

            /*  get new memory */
            if((*seenByCount)++ >= seenByAlloced)
            {
                (*seenBys) =
                    (s_seenBy *)safe_realloc(*seenBys, sizeof(s_seenBy) * (seenByAlloced += 32));
            }

            if((*endptr) == '\0')
            {
                /*  only node aka */
                (*seenBys)[*seenByCount - 1].node = (UINT16)temp;

                /*  use net aka of last seenBy */
                if(*seenByCount >= 2)
                {
                    (*seenBys)[*seenByCount - 1].net = (*seenBys)[*seenByCount - 2].net;
                }
                else
                {
                    w_log(LL_ALERT,
                          "Buggy PATH line encountered. Invalid node was removed from the line!");
                    --*seenByCount;
                }
            }
            else
            {
                /*  net and node aka */
                (*seenBys)[*seenByCount - 1].net = (UINT16)temp;
                /*  eat up '/' */
                endptr++;
                (*seenBys)[*seenByCount - 1].node = (UINT16)atol(endptr);
            }
        }
        else if(strcmp(token, "\001PATH:") != 0)
        {
            break; /*  not digit and not PATH */
        }
    }

    if(*seenByCount != seenByAlloced)
    {
        (*seenBys) = (s_seenBy *)safe_realloc(*seenBys, sizeof(s_seenBy) * (*seenByCount));
    }

    /*  test output for reading of paths... */
#ifdef DEBUG_HPT

    for(i = 0; i < *seenByCount; i++)
    {
        printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
    }
#endif
    /* exit(2); */
    nfree(seenByText);
} /* createPathArrayFromMsg */

/**
 * This function returns 0 if the link is not in seenBy else it returns 1.
 */
int checkLink(s_seenBy * seenBys,
              UINT seenByCount,
              s_link * link,
              hs_addr pktOrigAddr,
              s_area * area)
{
    UINT i, j;

    /*  the link where we got the mail from */
    if(addrComp(&pktOrigAddr, &(link->hisAka)) == 0)
    {
        return 1;
    }

    if(seenBys == NULL)
    {
        return 0;
    }

    /*  a point always gets the mail */
    /*  if (link->hisAka.point != 0) return 0; */
    /*  send the mail to links within our node-system */
    if((link->hisAka.zone == area->useAka->zone) && (link->hisAka.net == area->useAka->net) &&
       (link->hisAka.node == area->useAka->node))
    {
        return 0;
    }

    for(i = 0; i < seenByCount; i++)
    {
        if((link->hisAka.net == seenBys[i].net) && (link->hisAka.node == seenBys[i].node))
        {
            for(j = 0; j < config->ignoreSeenCount; j++)
            {
                if(config->ignoreSeen[j].net == seenBys[i].net &&
                   config->ignoreSeen[j].node == seenBys[i].node)
                {
                    link->sb = 1; /*  fix for double seen-bys */
                    return 0;
                }
            }

            for(j = 0; j < area->sbignCount; j++)
            {
                if(area->sbign[j].net == seenBys[i].net && area->sbign[j].node == seenBys[i].node)
                {
                    link->sb = 1; /*  fix for double seen-bys */
                    return 0;
                }
            }
            return 1;
        }
    }
    return 0;
} /* checkLink */

/*
   This function puts all the links of the echoarea in the newLink
   array who does not have got the mail, zoneLinks - the links who
   receive msg with stripped seen-by's.
 */
void createNewLinkArray(s_seenBy * seenBys,
                        UINT seenByCount,
                        s_area * echo,
                        s_arealink *** newLinks,
                        s_arealink *** zoneLinks,
                        s_arealink *** otherLinks,
                        hs_addr pktOrigAddr)
{
    UINT i, lFound = 0, zFound = 0, oFound = 0;

    *newLinks   = (s_arealink **)safe_calloc(echo->downlinkCount, sizeof(s_arealink *));
    *zoneLinks  = (s_arealink **)safe_calloc(echo->downlinkCount, sizeof(s_arealink *));
    *otherLinks = (s_arealink **)safe_calloc(echo->downlinkCount, sizeof(s_arealink *));

    for(i = 0; i < echo->downlinkCount; i++)
    {
        /*  is the link in SEEN-BYs? */
        if(checkLink(seenBys, seenByCount, echo->downlinks[i]->link, pktOrigAddr, echo) != 0)
        {
            continue;
        }

        /*  link with "export off" */
        if(echo->downlinks[i]->aexport == 0)
        {
            continue;
        }

        if(pktOrigAddr.zone == echo->downlinks[i]->link->hisAka.zone)
        {
            /*  links with same zone */
            if(echo->downlinks[i]->link->reducedSeenBy)
            {
                (*otherLinks)[oFound++] = echo->downlinks[i];
            }
            else
            {
                (*newLinks)[lFound++] = echo->downlinks[i];
            }
        }
        else
        {
            /*  links in different zones */
            (*zoneLinks)[zFound++] = echo->downlinks[i];
        }
    }

    if(lFound == 0)
    {
        nfree(*newLinks);
    }

    if(zFound == 0)
    {
        nfree(*zoneLinks);
    }

    if(oFound == 0)
    {
        nfree(*otherLinks);
    }
} /* createNewLinkArray */

/*
   Create a new SEEN-BY array from another one for AKAs found in an address list.
 */
void createFilteredSeenByArray(s_seenBy * seenBys,
                               UINT seenByCount,
                               s_seenBy ** newSeenBys,
                               UINT * newSeenByCount,
                               ps_addr addr,
                               unsigned int addrCount)
{
    unsigned int i, j;

    /* sanity checks */
    if((newSeenBys == NULL) || (newSeenByCount == NULL))
    {
        return;
    }

    if((seenByCount > 0) && (seenBys == NULL))
    {
        return;
    }

    if((addrCount > 0) && (addr == NULL))
    {
        return;
    }

    *newSeenByCount = 0;
    /* get memory for array (required at maximum) */
    (*newSeenBys) = (s_seenBy *)safe_calloc(addrCount, sizeof(s_seenBy));

    /* search for matches */
    for(i = 0; i < addrCount; i++)           /* address array */
    {
        for(j = 0; j < seenByCount; j++)     /* SEEN-BY array */
        {
            if(((UINT16)addr[i].net == seenBys[j].net) &&
               ((UINT16)addr[i].node == seenBys[j].node))
            {
                /* copy this one to new array */
                (*newSeenBys)[*newSeenByCount].net  = (UINT16)addr[i].net;
                (*newSeenBys)[*newSeenByCount].node = (UINT16)addr[i].node;
                (*newSeenByCount)++;
            }
        }
    }
} /* createFilteredSeenByArray */

/*
   strip specific AKAs (address array) from SEEN-BY array
 */
void stripSeenByArray(s_seenBy ** seenBys, UINT * seenByCount, ps_addr addr,
                      unsigned int addrCount)
{
    unsigned int i, j, k;
    unsigned int counter;

    /* sanity check */
    if((seenBys == NULL) || (seenByCount == NULL))
    {
        return;
    }

    counter = *seenByCount;   /* local variable to speed up access */

    /* search for matches */
    for(i = 0; i < addrCount; i++)           /* address array */
    {
        for(j = 0; j < counter; j++)         /* SEEN-BY array */
        {
            if(((UINT16)addr[i].net == (*seenBys)[j].net) &&
               ((UINT16)addr[i].node == (*seenBys)[j].node))
            {
                /* remove this AKA by moving remaining SEEN-BYs one up */
                counter--;

                for(k = j; k < counter; k++)
                {
                    (*seenBys)[k].net  = (*seenBys)[k + 1].net;
                    (*seenBys)[k].node = (*seenBys)[k + 1].node;
                }
            }
        }
    }
    *seenByCount = counter;   /* update counter */
} /* stripSeenByArray */
