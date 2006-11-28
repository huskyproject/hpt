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
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

/* compiler.h */
#include <smapi/compiler.h>

#ifdef HAS_PROCESS_H
#  include <process.h>
#endif

#ifdef HAS_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAS_IO_H
#include <io.h>
#endif

/* smapi */
#include <smapi/progprot.h>
#include <smapi/msgapi.h>
#include <smapi/patmat.h>

/* fidoconf */
#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/xstr.h>
#include <fidoconf/afixcmd.h>
#include <fidoconf/temp.h>
#include <fidoconf/recode.h>
#include <fidoconf/log.h>

/* hpt */
#include <fcommon.h>
#include <pkt.h>
#include <scan.h>
#include <global.h>
#include "version.h"
#include <toss.h>

#ifdef DO_PERL
#include <hptperl.h>
#endif

s_statScan statScan;

int parseINTL(char *msgtxt, hs_addr *from, hs_addr *to)
{
   char *start, *copy, buffer[35]; /* FIXME: static buffer */
   hs_addr intl_from, intl_to;

   copy = buffer;
   start = strstr(msgtxt, "FMPT");
   if (start) {
      start += 6;                  /* skip "FMPT " */
      while (isdigit(*start)) {     /* copy all digit data */
         *copy = *start;
         copy++;
         start++;
      } /* endwhile */
      *copy = '\0';                /* don't forget to close the string with 0 */

      from->point = atoi(buffer);
   } else {
      from->point = 0;
   } /* endif */

   /* and the same for TOPT */
   copy = buffer;
   start = strstr(msgtxt, "TOPT");
   if (start) {
      start += 6;                  /* skip "TOPT " */
      while (isdigit(*start)) {     /* copy all digit data */
         *copy = *start;
         copy++;
         start++;
      } /* endwhile */
      *copy = '\0';                /* don't forget to close the string with 0 */

      to->point = atoi(buffer);
   } else {
      to->point = 0;
   } /* endif */

   /* Parse the INTL Kludge */

   start = strstr(msgtxt, "INTL ");
   if (start)
   {
      start += 6;                 /*  skip "INTL " */
      while(1)
      {
          while (*start && isspace(*start)) start++;
          if (!*start) break;

          copy = buffer;
          while (*start && !isspace(*start)) *copy++ = *start++;
          *copy='\0';
          if (strchr(buffer,':')==NULL || strchr(buffer,'/')==NULL) break;
          string2addr(buffer, &intl_to);

          while (*start && isspace(*start)) start++;
          if (!*start) break;

          copy = buffer;
          while (*start && !isspace(*start)) *copy++ = *start++;
          *copy='\0';
          if (strchr(buffer,':')==NULL || strchr(buffer,'/')==NULL) break;
          string2addr(buffer, &intl_from);

          /* INTL is valid, copy parsed data to output */
          from->zone = intl_from.zone;
          from->net = intl_from.net;
          from->node = intl_from.node;

          to->zone = intl_to.zone;
          to->net = intl_to.net;
          to->node = intl_to.node;
          return 1;
          break;
      }
   } else
       w_log(LL_DEBUGB, "Warning: no INTL kludge found in message");

   return 0;
}

void cvtAddr(const NETADDR aka1, hs_addr *aka2)
{
  aka2->zone = aka1.zone;
  aka2->net  = aka1.net;
  aka2->node = aka1.node;
  aka2->point = aka1.point;
}

void convertMsgHeader(XMSG xmsg, s_message *msg)
{
   /*  convert header */
   msg->attributes  = xmsg.attr;

   msg->origAddr.zone  = xmsg.orig.zone;
   msg->origAddr.net   = xmsg.orig.net;
   msg->origAddr.node  = xmsg.orig.node;
   msg->origAddr.point = xmsg.orig.point;

   msg->destAddr.zone  = xmsg.dest.zone;
   msg->destAddr.net   = xmsg.dest.net;
   msg->destAddr.node  = xmsg.dest.node;
   msg->destAddr.point = xmsg.dest.point;

   strcpy((char *)msg->datetime, (char *) xmsg.__ftsc_date);
   xstrcat(&(msg->subjectLine), (char *) xmsg.subj);
   xstrcat(&(msg->toUserName), (char *) xmsg.to);
   xstrcat(&(msg->fromUserName), (char *) xmsg.from);

   /*  recoding subjectLine to TransportCharset */
   if (config->outtab != NULL) {
       recodeToTransportCharset((CHAR*)msg->subjectLine);
       recodeToTransportCharset((CHAR*)msg->fromUserName);
       recodeToTransportCharset((CHAR*)msg->toUserName);
   }

   /*  set netmail flag */
   msg->netMail = 1;
}

void convertMsgText(HMSG SQmsg, s_message *msg)
{
   UCHAR   *ctrlBuff;
   UINT32  ctrlLen;

   /*  get kludge lines */
   ctrlLen = MsgGetCtrlLen(SQmsg);
   ctrlBuff = (unsigned char *) safe_malloc(ctrlLen+1);
   MsgReadMsg(SQmsg, NULL, 0, 0, NULL, ctrlLen, ctrlBuff);
   /* MsgReadMsg does not do zero termination! */
   ctrlBuff[ctrlLen] = '\0';
   msg->text = (char *) CvtCtrlToKludge(ctrlBuff);
   nfree(ctrlBuff);

   /*  make text */
   msg->textLength = MsgGetTextLen(SQmsg); /*  including zero termination??? */

   ctrlLen = strlen(msg->text);
   xstralloc(&(msg->text), msg->textLength + ctrlLen);

   MsgReadMsg(SQmsg, NULL, 0, msg->textLength, (UCHAR *) msg->text+ctrlLen, 0, NULL);
   /* MsgReadMsg doesn't do zero termination! */
   msg->text[msg->textLength+ctrlLen] = '\0';
   msg->textLength += ctrlLen-1;

   /*  recoding text to TransportCharSet */
   if (config->outtab != NULL) recodeToTransportCharset((CHAR*)msg->text);
}

void addViaToMsg(s_message *msg, hs_addr ourAka) {
	time_t  tm;
	struct tm *dt;
        char buf[2];

	time(&tm);
	dt = gmtime(&tm);

        /*
         * OG: If the last char of the message isn't a \r, so it is a good
	 * idea to add the \r.
        */
        buf[0] = buf[1] = 0;
        if (msg->text && msg->text[0])
        {
          if (msg->text[strlen(msg->text)-1] != '\r')
             buf[0] = '\r';
        }

	if (ourAka.point==0)
	xscatprintf(&(msg->text),"%s\001Via %u:%u/%u @%04u%02u%02u.%02u%02u%02u.UTC %s\r",
				buf, ourAka.zone, ourAka.net, ourAka.node,
				dt->tm_year + 1900, dt->tm_mon + 1, dt->tm_mday,
				dt->tm_hour, dt->tm_min, dt->tm_sec, versionStr);
	else
	xscatprintf(&(msg->text),"%s\001Via %u:%u/%u.%u @%04u%02u%02u.%02u%02u%02u.UTC %s\r",
				buf, ourAka.zone, ourAka.net, ourAka.node, ourAka.point,
				dt->tm_year + 1900, dt->tm_mon + 1, dt->tm_mday,
				dt->tm_hour, dt->tm_min, dt->tm_sec, versionStr);
}

void makePktHeader(s_link *link, s_pktHeader *header)
{
   if (link != NULL) {
      header->origAddr = *(link->ourAka);
      header->destAddr = link->hisAka;
   }
   header->minorProductRev = (UCHAR)VER_MINOR;
   header->majorProductRev = (UCHAR)VER_MAJOR;
   header->hiProductCode   = 0;
   header->loProductCode   = 0xfe;
   memset(header->pktPassword, '\0', sizeof(header->pktPassword)); /*  no password */
   if (link != NULL && link->pktPwd != NULL) {
      if (strlen(link->pktPwd) > 8)
         strncpy(header->pktPassword, link->pktPwd, 8);
      else
         strcpy(header->pktPassword, link->pktPwd);
   }
   time(&(header->pktCreated));
   header->capabilityWord  = 1;
   header->prodData        = 0;
}

static s_route *findSelfRouteForNetmail(s_message msg)
{
    char *addrStr=NULL;
    UINT i;

    xscatprintf(&addrStr, "%u:%u/%u.%u",
		msg.destAddr.zone, msg.destAddr.net,
		msg.destAddr.node, msg.destAddr.point);

    for (i=0; i < config->routeCount; i++) {
	if ((msg.attributes & MSGFILE) == MSGFILE) { /*  routeFile */
	    if (config->route[i].id == id_routeFile)
		if (patmat(addrStr, config->route[i].pattern))
		    break;
	} else {
	    if (config->route[i].id != id_routeFile) /*  route & routeMail */
		if (patmat(addrStr, config->route[i].pattern))
		    break;
	}
    }

    nfree(addrStr);

    return (i==config->routeCount) ? NULL : &(config->route[i]);
}

s_route *findRouteForNetmail(s_message msg)
{
	s_route *route;

	route = findSelfRouteForNetmail(msg);

#ifdef DO_PERL
	{ s_route *sroute;
	  if ((sroute = perlroute(&msg, route)) != NULL)
		return sroute;
	}
#endif

	return route;
}

s_link *getLinkForRoute(s_route *route, s_message *msg) {
   static s_link tempLink;
   s_link *getLink = NULL;

   if (route==NULL) return NULL;

   if (route->target == NULL) {
      memset(&tempLink, '\0', sizeof(s_link));

      tempLink.hisAka = msg->destAddr;
      tempLink.ourAka = &(config->addr[0]);

      switch (route->routeVia) {

	  case route_zero:
		  break;

	  case host:
		  tempLink.hisAka.node  = 0;
		  tempLink.hisAka.point = 0;
		  break;

	  case boss:
		  tempLink.hisAka.point = 0;
		  break;

	  case noroute:
		  break;

	  case nopack:
		  break;

	  case hub:
		  tempLink.hisAka.node -= (tempLink.hisAka.node % 100);
		  tempLink.hisAka.point = 0;
		  break;

	  case route_extern:
		  string2addr(route->viaStr, &tempLink.hisAka);
		  break;
      }

      getLink = getLinkFromAddr(config, tempLink.hisAka);

      if (getLink != NULL) return getLink;
      else return &tempLink;

   } else return route->target;
}

void processAttachs(s_link *link, s_message *msg, unsigned int attr)
{
   FILE *flo = NULL;
   char *p = NULL, *running = NULL, *token = NULL, *flags = NULL;
   char *newSubjectLine = NULL;

   flo = fopen(link->floFile, "a");

   running = msg->subjectLine;
   token = strseparate(&running, " \t");

   while (token != NULL) {
#if defined(UNIX) || defined(__linux__)
	   if (!fexist(token)) strLower(token);
#endif
      if (flo != NULL) {
		  if (msg->text) flags =
             (char *) GetCtrlToken((byte *)msg->text,(byte *)"FLAGS");
          if ((flags && strstr(flags, "KFS")) ||
			  (config->keepTrsFiles==0 && (attr & MSGFWD)==MSGFWD))
			  fprintf(flo, "^%s\n", token);
          else if (flags && strstr(flags, "TFS"))
			  fprintf(flo, "#%s\n", token);
          else
			  fprintf(flo, "%s\n", token);
		  nfree(flags);
      }
	  if (newSubjectLine!=NULL) xstrcat(&newSubjectLine, " ");
      if (NULL != (p=strrchr(token, PATH_DELIM))) xstrcat(&newSubjectLine, p+1);
	  else xstrcat(&newSubjectLine, token);
      token = strseparate(&running, " \t");
   }

   if (flo!= NULL) {
      fclose(flo);
   } else w_log(LL_ERR, "Could not open FloFile");

   /*  replace subjectLine */
   nfree(msg->subjectLine);
   msg->subjectLine = newSubjectLine;
}

void processRequests(s_link *link, s_message *msg)
{
   FILE *flo = NULL;
   char *running = NULL;
   char *token = NULL;

   flo = fopen(link->floFile, "ab");

   running = msg->subjectLine;
   token = strseparate(&running, " \t");

   while (token != NULL) {
     if (flo != NULL) fprintf(flo, "%s\015\012", token); /*  #13#10 to create dos LFCR which ends a line */

      token = strseparate(&running, " \t");
   }
   if (flo!= NULL) {
      fclose(flo);
   } else w_log(LL_ERR, "Could not open FloFile");

}

int packMsg(HMSG SQmsg, XMSG *xmsg, s_area *area)
{
   FILE        *pkt = NULL;
   e_flavour   prio = normal;
   s_message   msg;
   s_pktHeader header;
   s_route     *route = NULL;
   s_link      *link = NULL, *virtualLink = NULL;
   char        freeVirtualLink = 0;
   char        *flags=NULL;
   int         r, arcNetmail;

   w_log( LL_FUNC, "packMsg() begin");

   memset(&msg,'\0',sizeof(s_message));
   convertMsgHeader(*xmsg, &msg);
   convertMsgText(SQmsg, &msg);

   w_log(LL_DEBUGB, "%s::%u Msg from %u:%u/%u.%u to %u:%u/%u.%u",__FILE__,__LINE__, msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point );

#ifdef DO_PERL
   if (perlscanmsg(area->areaName, &msg)) {
	xmsg->attr |= MSGSENT;
	freeMsgBuffers(&msg);
        w_log( LL_FUNC, "packMsg() end: perl hook proceed");
	return 0;
   }
#endif
   /*  clear trs, local & k/s flags */
   msg.attributes &= ~(MSGFWD|MSGLOCAL|MSGKILL);

   /*  prepare virtual link... */
   virtualLink = getLinkFromAddr(config, msg.destAddr);  /* maybe the link is in config? */
   if (virtualLink == NULL) {
      virtualLink = safe_malloc(sizeof(s_link));  /*  if not create new virtualLink link */
      memset(virtualLink, '\0', sizeof(s_link));
      virtualLink->hisAka = msg.destAddr;
      virtualLink->ourAka = &(msg.origAddr);
      virtualLink->name = (char *) safe_malloc(strlen(msg.toUserName)+1);
      strcpy(virtualLink->name, msg.toUserName);
      freeVirtualLink = 1;  /* virtualLink is a temporary link, please free it.. */
   }

   /*  calculate prio */
   if ((xmsg->attr & MSGCRASH)==MSGCRASH) prio = crash;
   if ((xmsg->attr & MSGHOLD)==MSGHOLD) prio = hold;
   if ((xmsg->attr & MSGXX2)==MSGXX2 ||
	   ((xmsg->attr & MSGHOLD)==MSGHOLD &&
		(xmsg->attr & MSGCRASH)==MSGCRASH)) prio = direct; /*  XX2 or Crash+Hold */
   if (msg.text) {
	   flags = (char *) GetCtrlToken((byte *)msg.text,(byte *)"FLAGS");
	   if (flags) {
		   if (strstr(flags,"DIR")!=NULL) prio = direct;
		   if (strstr(flags,"IMM")!=NULL) prio = immediate; /*  most priority */
		   nfree(flags);
	   }
   }

   if ((xmsg->attr & MSGFILE) == MSGFILE) {
       /*  file attach */
	
       /*  we need route mail */
       if (prio==normal) {
	   route = findRouteForNetmail(msg);
	   link = getLinkForRoute(route, &msg);
	   if ((route != NULL) && (link != NULL)) {
	       if (createOutboundFileName(link,route->flavour,
					  FLOFILE) == 0) {
		   processAttachs(link, &msg, xmsg->attr);
		   remove(link->bsyFile);
		   nfree(link->bsyFile);
		   /*  mark Mail as sent */
		   xmsg->attr |= MSGSENT;
		   if (0!=MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL))
                        w_log(LL_ERR, "Could not update msg in area %s! Check the wholeness of messagebase, please.", area->areaName);
		   nfree(link->floFile);
		   w_log(LL_FROUTE, "File %s from %u:%u/%u.%u -> %u:%u/%u.%u via %u:%u/%u.%u", msg.subjectLine, msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point, link->hisAka.zone, link->hisAka.net, link->hisAka.node, link->hisAka.point);
	       }
	   }
       }
	   else if (createOutboundFileName(virtualLink, prio, FLOFILE) == 0) {
		   processAttachs(virtualLink, &msg, xmsg->attr);
		   remove(virtualLink->bsyFile);
		   nfree(virtualLink->bsyFile);
		   /*  mark Mail as sent */
		   xmsg->attr |= MSGSENT;
		   if (0!=MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL))
                        w_log(LL_ERR, "Could not update msg in area %s! Check the wholeness of messagebase, please.", area->areaName);
		   nfree(virtualLink->floFile);
		   w_log(LL_FROUTE, "File %s from %u:%u/%u.%u -> %u:%u/%u.%u", msg.subjectLine, msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
	   }
   } /* endif file attach */

   /*  file requests always direct */
   if ((xmsg->attr & MSGFRQ) == MSGFRQ) {
	   /*  if msg has request flag then put the subjectline into request file. */
	   if (createOutboundFileName(virtualLink, normal, REQUEST) == 0) {
		   processRequests(virtualLink, &msg);
		   remove(virtualLink->bsyFile);
		   nfree(virtualLink->bsyFile);
		   /*  mark Mail as sent */
		   xmsg->attr |= MSGSENT;
		   if (0!=MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL))
                        w_log(LL_ERR, "Could not update msg in area %s! Check the wholeness of messagebase, please.", area->areaName);
		   nfree(virtualLink->floFile);
		   w_log(LL_FREQ, "Request %s from %u:%u/%u.%u", msg.subjectLine, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
	   }
   }

   w_log(LL_DEBUGB, "%s::%u Msg from %u:%u/%u.%u to %u:%u/%u.%u",__FILE__,__LINE__, msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point );

   /*  no route */
   if (prio!=normal || (xmsg->attr & MSGFRQ)==MSGFRQ) {
	   /*  direct, crash, immediate, hold messages */
           if (virtualLink->arcNetmail &&
               prio == virtualLink->echoMailFlavour) {
                   arcNetmail = 1;
                   if (virtualLink->pktFile && virtualLink->pktSize)
                        if (fsize(virtualLink->pktFile) >= (long)(virtualLink->pktSize*1024)) {
                             nfree(virtualLink->pktFile);
                             nfree(virtualLink->packFile);
                        }
                   if (virtualLink->pktFile == NULL)
                        r = createTempPktFileName(virtualLink);
                   else
                        r = 0;
           } else {
                   arcNetmail = 0;
                   r = createOutboundFileName(virtualLink, prio, PKT);
           }
	   if (r == 0) {
		   addViaToMsg(&msg, msg.origAddr);
		   makePktHeader(virtualLink, &header);
		   pkt = openPktForAppending(arcNetmail ? virtualLink->pktFile : virtualLink->floFile, &header);
		   writeMsgToPkt(pkt, msg);
		   closeCreatedPkt(pkt);
		   if (prio==crash) w_log(LL_ROUTE, "Crash-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
		   else if (prio==hold) w_log(LL_ROUTE, "Hold-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
		   else if (prio==direct) w_log(LL_ROUTE, "Direct-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
		   else if (prio==immediate) w_log(LL_ROUTE, "Immediate-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
		   else if (prio==normal) w_log(LL_ROUTE, "Normal-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
                   if (!arcNetmail) {
		         remove(virtualLink->bsyFile);
		         nfree(virtualLink->bsyFile);
		         nfree(virtualLink->floFile);
                   }
		   /*  mark Mail as sent */
		   xmsg->attr |= MSGSENT;
		   if (0!=MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL))
                        w_log(LL_ERR, "Could not update msg in area %s! Check the wholeness of messagebase, please.", area->areaName);
	   }
   } else {
           /*  no crash, no hold flag -> route netmail */
	   route = findRouteForNetmail(msg);
	   link = getLinkForRoute(route, &msg);

	   if ((route != NULL) && (link != NULL) && (route->routeVia != nopack)) {
		   prio = route->flavour;
                   if (link->arcNetmail &&
                       route->flavour == link->echoMailFlavour) {
                           arcNetmail = 1;
                           if (link->pktFile && link->pktSize)
                                if (fsize(link->pktFile) >= (long)(link->pktSize*1024)) {
                                     nfree(link->pktFile);
                                     nfree(link->packFile);
                                }

                           if (link->pktFile == NULL)
                                r = createTempPktFileName(link);
                           else
                                r = 0;
                   } else {
                           arcNetmail = 0;
                           r = createOutboundFileName(link, prio, PKT);
                   }
		   if (r == 0) {
			   addViaToMsg(&msg, *(link->ourAka));
			   makePktHeader(NULL, &header);
			   header.destAddr = link->hisAka;
			   header.origAddr = *(link->ourAka);
			   if (link->pktPwd != NULL)
				   strcpy(&(header.pktPassword[0]), link->pktPwd);
			   pkt = openPktForAppending(arcNetmail ? link->pktFile : link->floFile, &header);
			   writeMsgToPkt(pkt, msg);
			   closeCreatedPkt(pkt);
			   w_log(LL_ROUTE, "Msg from %u:%u/%u.%u to %u:%u/%u.%u packed to %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point, link->hisAka.zone, link->hisAka.net, link->hisAka.node, link->hisAka.point);
                           if (!arcNetmail) {
			        remove(link->bsyFile);
			        nfree(link->bsyFile);
			        nfree(link->floFile);
                           }
			   /*  mark Mail as sent */
			   xmsg->attr |= MSGSENT;
			   if (0!=MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL))
                             w_log(LL_ERR, "Could not update msg in area %s! Check the wholeness of messagebase, please.", area->areaName);
		   }
	   } else {
                if ((xmsg->attr & MSGFILE) == MSGFILE) w_log(LL_FROUTE, "no routeFile found or no-pack for %s - leave mail untouched", aka2str(msg.destAddr));
		else w_log(LL_ROUTE, "no route found or no-pack for %s - leave mail untouched", aka2str(msg.destAddr));
	   }
   }

   /*  process carbon copy */
   if (config->carbonOut) carbonCopy(&msg, xmsg, area);

   freeMsgBuffers(&msg);
   if (freeVirtualLink==1) {
      nfree(virtualLink->name);
      nfree(virtualLink);
   }

   if ((xmsg->attr & MSGSENT) == MSGSENT) {
      w_log( LL_FUNC, "packMsg() rc=0");
      return 0;
   }
   w_log( LL_FUNC, "packMsg() rc=1");
   return 1;
}

void scanNMArea(s_area *area)
{
    HAREA           netmail;
    HMSG            msg;
    dword           highestMsg, i, j;
    XMSG            xmsg;
    hs_addr         dest, orig;
    hs_addr         intl_dest, intl_orig;
    char            *ctl;
    int             ctllen;
    int             for_us, from_us;
    FILE            *f = NULL;

    /*  do not scan one area twice */
    if (area->scn) return;

    if (config->routeCount == 0) {
        w_log(LL_ROUTE, "No routing -> Scanning stop");
        /*  create flag for netmail trackers */
        if (config->netmailFlag) {
            if (NULL == (f = fopen(config->netmailFlag,"a")))
                w_log(LL_ERR, "Could not create netmail flag: %s", config->netmailFlag);
            else {
                w_log(LL_FLAG, "Created netmail flag: %s", config->netmailFlag);
                fclose(f);
            }
        }
        return;
    }

    netmail = MsgOpenArea((unsigned char *) area -> fileName, MSGAREA_NORMAL,
                          /* config->netMailArea.fperm,
                           config->netMailArea.uid,
                           config->netMailArea.gid, */
                          (word)area -> msgbType);
    if (netmail != NULL) {

        statScan.areas++;
        area->scn++;
        w_log(LL_START, "Scanning NetmailArea %s", area -> areaName);

        if (area->msgbType == MSGTYPE_SDM) noHighWaters = 1;
        i = (noHighWaters) ? 0 : MsgGetHighWater(netmail);
        highestMsg = MsgGetNumMsg(netmail);

        /*  scan all Messages and test if they are already sent. */
        while (i < highestMsg) {
            msg = MsgOpenMsg(netmail, MOPEN_RW, ++i);

            /*  msg does not exist */
            if (msg == NULL) continue;
            statScan.msgs++;

            ctllen = MsgGetCtrlLen(msg);
            ctl = (char *) safe_malloc(ctllen+1);
            ctl[ctllen] = '\0';

            MsgReadMsg(msg, &xmsg, 0, 0, NULL, ctllen, (byte *)ctl);
            cvtAddr(xmsg.dest, &dest);
            cvtAddr(xmsg.orig, &orig);
            memset(&intl_orig, 0, sizeof(hs_addr));
            memset(&intl_dest, 0, sizeof(hs_addr));
            /*
             * if @INTL and optionally @TOPT/@FMPT found, take address
             * from there
             */
            if (parseINTL(ctl, &intl_orig, &intl_dest))
            {
                if (addrComp(orig, intl_orig)) /* addresses are differ */
                {
                    orig.zone = xmsg.orig.zone = intl_orig.zone;
                    orig.net = xmsg.orig.net = intl_orig.net;
                    orig.node = xmsg.orig.node = intl_orig.node;
                    orig.point = xmsg.orig.point = intl_orig.point;
                }
                if (addrComp(dest, intl_dest)) /* addresses are differ */
                {
                    dest.zone = xmsg.dest.zone = intl_dest.zone;
                    dest.net = xmsg.dest.net = intl_dest.net;
                    dest.node = xmsg.dest.node = intl_dest.node;
                    dest.point = xmsg.dest.point = intl_dest.point;
                }
            }

            nfree(ctl);

            ctl = safe_strdup(aka2str(dest)); /* use this just as temp buffer */
            w_log( LL_DEBUGB, "%s::%u Msg from %s to %s",__FILE__,__LINE__,
                  aka2str(orig), ctl);
            nfree(ctl);

            for_us = 0;
            for (j=0; j < config->addrCount; j++)
            {
                if (addrComp(dest, config->addr[j])==0) {for_us = 1; break;}
            }
            /*  if not sent and not for us -> pack it */
            if (((xmsg.attr & MSGSENT) != MSGSENT) &&
                ((xmsg.attr & MSGLOCKED) != MSGLOCKED) &&
                (for_us==0))
            {
                if (packMsg(msg, &xmsg, area) == 0) {
                    statScan.exported++;
                    area->scn++;
                }
            }

            MsgCloseMsg(msg);

            from_us = 0;
            for (j=0; j < config->addrCount; j++)
                if (addrComp(orig, config->addr[j])==0) {from_us = 1; break;}

            /*   non transit messages without k/s flag not killed */
            if (!(xmsg.attr & MSGKILL) && !(xmsg.attr & MSGFWD)) from_us = 1;

            /*  transit messages from us will be killed */
            if (from_us && (xmsg.attr & MSGFWD)) from_us = 0;

            if ((!config->keepTrsMail) && ((!for_us && !from_us) ||
                                           (xmsg.attr&MSGKILL)) && (xmsg.attr&MSGSENT)) {
                MsgKillMsg(netmail, i);
                i--;
            }

        } /* endfor */

        if (noHighWaters==0) MsgSetHighWater(netmail, i);
        MsgCloseArea(netmail);
        closeOpenedPkt();
    } else {
        w_log(LL_ERR, "Could not open NetmailArea %s", area -> areaName);
    } /* endif */
}

void writeScanStatToLog(void) {
   unsigned i;

   w_log(LL_STAT, "Statistics");
   w_log(LL_STAT, "    areas: % 4d   msgs: % 6d", statScan.areas, statScan.msgs);
   w_log(LL_STAT, "    exported: % 4d", statScan.exported);

   /* Now write areas summary */
   w_log(LL_SUMMARY, "Areas summary:");
   for (i = 0; i < config->netMailAreaCount; i++)
       if (config->netMailAreas[i].scn > 1)
	   w_log(LL_SUMMARY, "netmail area %s - %d msgs",
		 config->netMailAreas[i].areaName, config->netMailAreas[i].scn-1);
   for (i = 0; i < config->echoAreaCount; i++)
       if (config->echoAreas[i].scn > 1)
	   w_log(LL_SUMMARY, "echo area %s - %d msgs",
		 config->echoAreas[i].areaName, config->echoAreas[i].scn-1);
}

s_area *getLocalArea(s_fidoconfig *config, char *areaName)
{
   UINT i;

   for (i=0; i < config->localAreaCount; i++) {
      if (stricmp(config->localAreas[i].areaName, areaName)==0)
         return &(config->localAreas[i]);
   }

   return NULL;
}


int scanByName(char *name) {
    s_area *area = NULL;

    if ((area = getNetMailArea(config, name)) != NULL) {
	scanNMArea(area);
	return 1;
    } else {
	/*  maybe it's echo area */
	area = getEchoArea(config, name);
	if (area != &(config->badArea)) {
	    if (area && area->msgbType != MSGTYPE_PASSTHROUGH &&
		area -> downlinkCount > 0) {
		scanEMArea(area);
		return 1;
	    }
	} else {
	    if (NULL != getLocalArea(config,name))
		w_log(LL_SCANNING, "Area \'%s\' is local -> Skipped", name);
	    else
		w_log(LL_SCANNING, "Area \'%s\' is not found -> Scanning stop", name);
	}
    }
    return 0;
}

void scanAllAreas(int type)
{
    unsigned int i;
    if (type & SCN_ECHOMAIL) {
        for (i = 0; i< config->echoAreaCount; i++) {
            if ((config->echoAreas[i].msgbType != MSGTYPE_PASSTHROUGH) && (config->echoAreas[i].downlinkCount > 0)) {
                scanEMArea(&(config->echoAreas[i]));
            }
        }
    };
    if (type & SCN_NETMAIL) {
        for (i = 0; i < config->netMailAreaCount; i++) {
            scanNMArea(&(config->netMailAreas[i]));
        }
    };
}

void scanExport(int type, char *str) {

    unsigned int i = 0;
    FILE *f = NULL;
    FILE *ftmp = NULL;
    char *tmplogname = NULL;
    char *line = NULL;
    struct stat st;
    int processed=0;

    if ( !config->tempDir )
    {
        exit_hpt( "tempDir not defined in config. scanExport is not possible" , 1 );
    }

    w_log( LL_FUNC, "scanExport() begin" );

    /*  zero statScan */
    memset(&statScan, '\0', sizeof(s_statScan));
    w_log(LL_START, "Start %s%s...",
        type & SCN_ECHOMAIL ? "scanning" : "packing",
        type & SCN_FILE ? " with -f " :
    type & SCN_NAME ? " with -a " : "");


    w_log( LL_SRCLINE, "%s:%d", __FILE__, __LINE__ );

    if (type & SCN_ALL) {
        if (config->echotosslog)
        {
            f = fopen(config->echotosslog, "r");
            if (f != NULL && config->packNetMailOnScan == 0) {
                ftmp = createTempTextFile(config , &tmplogname); /* error diagnostic prints by createTempTextFile() */
                if (ftmp == NULL) {
                    /* close file so all areas will be scanned instead of panic. */
                    fclose(f);
                    f = NULL;
                }
            }
        }
    }

    w_log( LL_SRCLINE, "%s:%d", __FILE__, __LINE__ );

    if (type & SCN_FILE) {
        if (str == NULL) str = config->echotosslog;
        f = fopen(str, "r");
        if (f != NULL && config->packNetMailOnScan == 0) {
            ftmp = createTempTextFile(config , &tmplogname); /* error diagnostic prints by createTempTextFile() */
            if (ftmp == NULL) {
                /* close file so all areas will be scanned instead of panic. */
                fclose(f);
                f = NULL;
            }
        }
    }

    w_log( LL_SRCLINE, "%s:%d", __FILE__, __LINE__ );

    if (type & SCN_NAME) {
        for (i = 0; i< config->echoAreaCount; i++) {
            if (patimat(config->echoAreas[i].areaName, str))
                scanByName(config->echoAreas[i].areaName);
        }
        for (i = 0; i< config->netMailAreaCount; i++) {
            if (patimat(config->netMailAreas[i].areaName, str))
                scanByName(config->netMailAreas[i].areaName);
        }
    } else if (f == NULL) {
        if (type & SCN_FILE) {
            w_log(LL_START, "EchoTossLogFile not found -> Scanning stop");
            nfree(tmplogname);
            return;
        }
        /*  if echotoss file does not exist scan all areas */
        w_log(LL_START, "EchoTossLogFile not found -> Scanning all areas.");
        scanAllAreas(type);
    } else {
        /*  else scan only those areas which are listed in the file */
        w_log(LL_START, "EchoTossLogFile found -> Scanning only listed areas");

        while (!feof(f)) {
            line = readLine(f);

            if (line != NULL) {
                if (*line && line[strlen(line)-1] == '\r')
                    line[strlen(line)-1] = '\0';  /* fix for DOSish echotoss.log */
                striptwhite(line);
                if (!ftmp) { /*  the same as if(config->packNetMailOnScan) { */
                    scanByName(line);
                } else {
                    processed |= 1;
                    /* exclude NetmailAreas in echoTossLogFile */
                   if (type & SCN_ECHOMAIL) {
                       if (getNetMailArea(config, line) == NULL) {
                           if(scanByName(line))
                               processed |= 2;
                       }
                       else
                       {
                           fprintf(ftmp, "%s\n", line);
                           processed |= 2;
                       }
                    } else {
                       if (getNetMailArea(config, line) != NULL) {
                           if(scanByName(line))
                               processed |= 2;
                       }
                        else
                            fprintf(ftmp, "%s\n", line);
                    }
                }
                nfree(line);
            }
        }
    }

    w_log( LL_SRCLINE, "%s:%d", __FILE__, __LINE__ );

    if (processed == 1) {
        w_log(LL_START, "EchoTossLogFile found, but contains no areas -> processing all areas.");
        scanAllAreas(type);
    }

    w_log( LL_SRCLINE, "%s:%d", __FILE__, __LINE__ );

    if (f != NULL) {
        fclose(f);
        if (ftmp != NULL)
        {
            fclose(ftmp);
            memset(&st, 0, sizeof(st));
            stat(tmplogname, &st);
            if (type & SCN_ALL) {
                if (st.st_size == 0) { /*  all entries was processed */
                    remove(config->echotosslog);
                    if (remove(tmplogname) != 0)
                        w_log(LL_ERR, "Couldn't remove temporary file\"%s\"", tmplogname);
                } else { /*  we still have areas */
                    remove(config->echotosslog);
                    if (rename(tmplogname, config->echotosslog) != 0)
                        w_log(LL_ERR, "Couldn't rename \"%s\" -> \"%s\"", tmplogname, config->echotosslog);
                }
            } else {
                if (st.st_size == 0) {
                    remove(str);
                    if (remove(tmplogname) != 0)
                        w_log(LL_ERR, "Couldn't remove temporary file\"%s\"", tmplogname);
                } else {
                    remove(str);
                    if (rename(tmplogname, str) != 0)
                        w_log(LL_ERR, "Couldn't rename \"%s\" -> \"%s\"", tmplogname, str);
                }
            }
        }
        else
        {
            if (type & SCN_ALL) {
                remove(config->echotosslog);
            }
            else if (type & SCN_FILE) {
                remove(str);
            }
        }
    }
    nfree (tmplogname);

    tossTempOutbound(config->tempOutbound);

    writeDupeFiles();
    writeScanStatToLog();

    w_log( LL_FUNC, "scanExport() end" );
}
