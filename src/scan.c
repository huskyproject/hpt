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
#include <sys/stat.h>
#include <errno.h>

#if defined (UNIX) 
#include <unistd.h>
#endif

#if defined (__WATCOMC__) || defined(__TURBOC__) || defined(__DJGPP__) || defined (__EMX__) || (defined (_MSC_VER) && (_MSC_VER >= 1200))
  #include <process.h>
  #include <io.h>
#endif

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/xstr.h>

#include <fcommon.h>
#include <pkt.h>
#include <scan.h>
#include <fidoconf/log.h>
#include <global.h>
#include <version.h>
#include <fidoconf/recode.h>
#include <toss.h>

#include <smapi/msgapi.h>
#include <smapi/progprot.h>
#include <smapi/patmat.h>

#ifdef DO_PERL
#include <hptperl.h>
#endif

s_statScan statScan;

void cvtAddr(const NETADDR aka1, s_addr *aka2)
{
  aka2->zone = aka1.zone;
  aka2->net  = aka1.net;
  aka2->node = aka1.node;
  aka2->point = aka1.point;
}

void convertMsgHeader(XMSG xmsg, s_message *msg)
{
   // convert header
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

   // recoding subjectLine to TransportCharset
   if (config->outtab != NULL) {
       recodeToTransportCharset((CHAR*)msg->subjectLine);
       recodeToTransportCharset((CHAR*)msg->fromUserName);
       recodeToTransportCharset((CHAR*)msg->toUserName);
   }
   
   // set netmail flag
   msg->netMail = 1;
}

void convertMsgText(HMSG SQmsg, s_message *msg)
{
   UCHAR   *ctrlBuff;
   UINT32  ctrlLen;

   // get kludge lines
   ctrlLen = MsgGetCtrlLen(SQmsg);
   ctrlBuff = (unsigned char *) safe_malloc(ctrlLen+1);
   MsgReadMsg(SQmsg, NULL, 0, 0, NULL, ctrlLen, ctrlBuff);
   /* MsgReadMsg does not do zero termination! */
   ctrlBuff[ctrlLen] = '\0';
   msg->text = (char *) CvtCtrlToKludge(ctrlBuff);
   nfree(ctrlBuff);

   // make text
   msg->textLength = MsgGetTextLen(SQmsg); // including zero termination???

   ctrlLen = strlen(msg->text);
   xstralloc(&(msg->text), msg->textLength + ctrlLen);

   MsgReadMsg(SQmsg, NULL, 0, msg->textLength, (UCHAR *) msg->text+ctrlLen, 0, NULL);
   /* MsgReadMsg doesn't do zero termination! */
   msg->text[msg->textLength+ctrlLen] = '\0';
   msg->textLength += ctrlLen-1;

   // recoding text to TransportCharSet
   if (config->outtab != NULL) recodeToTransportCharset((CHAR*)msg->text);
}

void addViaToMsg(s_message *msg, s_addr ourAka) {
	time_t  tm;
	struct tm *dt;

	time(&tm);
	dt = gmtime(&tm);

	if (ourAka.point==0)
	xscatprintf(&(msg->text),"\001Via %u:%u/%u @%04u%02u%02u.%02u%02u%02u.UTC %s\r",
				ourAka.zone, ourAka.net, ourAka.node,
				dt->tm_year + 1900, dt->tm_mon + 1, dt->tm_mday,
				dt->tm_hour, dt->tm_min, dt->tm_sec, versionStr);
	else
	xscatprintf(&(msg->text),"\001Via %u:%u/%u.%u @%04u%02u%02u.%02u%02u%02u.UTC %s\r",
				ourAka.zone, ourAka.net, ourAka.node, ourAka.point,
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
   memset(header->pktPassword, '\0', sizeof(header->pktPassword)); // no password
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
	if ((msg.attributes & MSGFILE) == MSGFILE) { // routeFile
	    if (config->route[i].id == id_routeFile)
		if (patmat(addrStr, config->route[i].pattern))
		    break;
	} else {
	    if (config->route[i].id != id_routeFile) // route & routeMail
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
   s_link *getLink;

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
   FILE *flo;
   char *p, *running, *token, *flags=NULL;
   char *newSubjectLine = NULL;

   flo = fopen(link->floFile, "a");

   running = msg->subjectLine;
   token = strseparate(&running, " \t");

   while (token != NULL) {
#if defined(UNIX) || defined(__linux__)
	   if (!fexist(token)) strLower(token);
#endif
      if (flo != NULL) {
		  if (msg->text) flags = (char *) GetCtrlToken(msg->text,(byte *)"FLAGS");
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
   } else w_log('9', "Could not open FloFile");

   // replace subjectLine
   nfree(msg->subjectLine);
   msg->subjectLine = newSubjectLine;
}

void processRequests(s_link *link, s_message *msg)
{
   FILE *flo;
   char *running;
   char *token;
   
   flo = fopen(link->floFile, "ab");

   running = msg->subjectLine;
   token = strseparate(&running, " \t");

   while (token != NULL) {
     if (flo != NULL) fprintf(flo, "%s\015\012", token); // #13#10 to create dos LFCR which ends a line

      token = strseparate(&running, " \t");
   }
   if (flo!= NULL) {
      fclose(flo);
   } else w_log('9', "Could not open FloFile");

}

int packMsg(HMSG SQmsg, XMSG *xmsg, s_area *area)
{
   FILE        *pkt;
   e_flavour   prio = normal;
   s_message   msg;
   s_pktHeader header;
   s_route     *route;
   s_link      *link, *virtualLink;
   char        freeVirtualLink = 0;
   char        *flags=NULL;
   int         r, arcNetmail;

   memset(&msg,'\0',sizeof(s_message));
   convertMsgHeader(*xmsg, &msg);
   convertMsgText(SQmsg, &msg);
#ifdef DO_PERL
   if (perlscanmsg(area->areaName, &msg)) {
	xmsg->attr |= MSGSENT;
	freeMsgBuffers(&msg);
	return 0;
   }
#endif
   // clear trs, local & k/s flags
   msg.attributes &= ~(MSGFWD|MSGLOCAL|MSGKILL);

   // prepare virtual link...
   virtualLink = getLinkFromAddr(config, msg.destAddr);  //maybe the link is in config?
   if (virtualLink == NULL) {
      virtualLink = safe_malloc(sizeof(s_link));  // if not create new virtualLink link
      memset(virtualLink, '\0', sizeof(s_link));
      virtualLink->hisAka = msg.destAddr;
      virtualLink->ourAka = &(msg.origAddr);
      virtualLink->name = (char *) safe_malloc(strlen(msg.toUserName)+1);
      strcpy(virtualLink->name, msg.toUserName);
      freeVirtualLink = 1;  //virtualLink is a temporary link, please free it..
   }

   // calculate prio
   if ((xmsg->attr & MSGCRASH)==MSGCRASH) prio = crash; 
   if ((xmsg->attr & MSGHOLD)==MSGHOLD) prio = hold;
   if ((xmsg->attr & MSGXX2)==MSGXX2 ||
	   ((xmsg->attr & MSGHOLD)==MSGHOLD &&
		(xmsg->attr & MSGCRASH)==MSGCRASH)) prio = direct; // XX2 or Crash+Hold
   if (msg.text) {
	   flags = (char *) GetCtrlToken(msg.text,(byte *)"FLAGS");
	   if (flags) {
		   if (strstr(flags,"DIR")!=NULL) prio = direct;
		   if (strstr(flags,"IMM")!=NULL) prio = immediate; // most priority
		   nfree(flags);
	   }
   }

   if ((xmsg->attr & MSGFILE) == MSGFILE) {
       // file attach
	   
       // we need route mail
       if (prio==normal) {
	   route = findRouteForNetmail(msg);
	   link = getLinkForRoute(route, &msg);
	   if ((route != NULL) && (link != NULL)) {
	       if (createOutboundFileName(link,route->flavour,
					  FLOFILE) == 0) {
		   processAttachs(link, &msg, xmsg->attr);
		   remove(link->bsyFile);
		   nfree(link->bsyFile);
		   // mark Mail as sent
		   xmsg->attr |= MSGSENT;
		   MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL);
		   nfree(link->floFile);
		   w_log('7', "File %s from %u:%u/%u.%u -> %u:%u/%u.%u via %u:%u/%u.%u", msg.subjectLine, msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point, link->hisAka.zone, link->hisAka.net, link->hisAka.node, link->hisAka.point);
	       }
	   }
       }
	   else if (createOutboundFileName(virtualLink, prio, FLOFILE) == 0) {
		   processAttachs(virtualLink, &msg, xmsg->attr);
		   remove(virtualLink->bsyFile);
		   nfree(virtualLink->bsyFile);
		   // mark Mail as sent
		   xmsg->attr |= MSGSENT;
		   MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL);
		   nfree(virtualLink->floFile);
		   w_log('7', "File %s from %u:%u/%u.%u -> %u:%u/%u.%u", msg.subjectLine, msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
	   }
   } /* endif file attach */

   // file requests always direct
   if ((xmsg->attr & MSGFRQ) == MSGFRQ) {
	   // if msg has request flag then put the subjectline into request file.
	   if (createOutboundFileName(virtualLink, normal, REQUEST) == 0) {
		   processRequests(virtualLink, &msg);
		   remove(virtualLink->bsyFile);
		   nfree(virtualLink->bsyFile);
		   // mark Mail as sent
		   xmsg->attr |= MSGSENT;
		   MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL);
		   nfree(virtualLink->floFile);
		   w_log('7', "Request %s from %u:%u/%u.%u", msg.subjectLine, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
	   }
   }

   // no route
   if (prio!=normal || (xmsg->attr & MSGFRQ)==MSGFRQ) {
	   // direct, crash, immediate, hold messages
           if (virtualLink->arcNetmail &&
               prio == virtualLink->echoMailFlavour) {
                   arcNetmail = 1;
                   if (virtualLink->pktFile && virtualLink->pktSize)
                        if (fsize(virtualLink->pktFile) >= virtualLink->pktSize * 1024L) {
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
		   if (prio==crash) w_log('7', "Crash-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
		   else if (prio==hold) w_log('7', "Hold-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
		   else if (prio==direct) w_log('7', "Direct-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
		   else if (prio==immediate) w_log('7', "Immediate-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
		   else if (prio==normal) w_log('7', "Normal-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
                   if (!arcNetmail) {
		         remove(virtualLink->bsyFile);
		         nfree(virtualLink->bsyFile);
		         nfree(virtualLink->floFile);
                   }
		   // mark Mail as sent
		   xmsg->attr |= MSGSENT;
		   MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL);
	   }
   } else {
           // no crash, no hold flag -> route netmail
	   route = findRouteForNetmail(msg);
	   link = getLinkForRoute(route, &msg);

	   if ((route != NULL) && (link != NULL) && (route->routeVia != nopack)) {
		   prio = route->flavour;
                   if (link->arcNetmail &&
                       route->flavour == link->echoMailFlavour) {
                           arcNetmail = 1;
                           if (link->pktFile && link->pktSize)
                                if (fsize(link->pktFile) >= link->pktSize * 1024L) {
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
			   w_log('7', "Msg from %u:%u/%u.%u -> %u:%u/%u.%u via %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point, link->hisAka.zone, link->hisAka.net, link->hisAka.node, link->hisAka.point);
                           if (!arcNetmail) {
			        remove(link->bsyFile);
			        nfree(link->bsyFile);
			        nfree(link->floFile);
                           }
			   // mark Mail as sent
			   xmsg->attr |= MSGSENT;
			   MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL);
		   }
	   } else {
                if ((xmsg->attr & MSGFILE) == MSGFILE) w_log('7', "no routeFile found or no-pack for %s - leave mail untouched", aka2str(msg.destAddr));
		else w_log('7', "no route found or no-pack for %s - leave mail untouched", aka2str(msg.destAddr));
	   }
   }

   // process carbon copy
   if (config->carbonOut) carbonCopy(&msg, xmsg, area);
   
   freeMsgBuffers(&msg);
   if (freeVirtualLink==1) {
      nfree(virtualLink->name);
      nfree(virtualLink);
   }

   if ((xmsg->attr & MSGSENT) == MSGSENT) {
	   return 0;
   } else {
	   return 1;
   }
}

void scanNMArea(s_area *area)
{
   HAREA           netmail;
   HMSG            msg;
   dword           highestMsg, i, j;
   XMSG            xmsg;
   s_addr          dest, orig;
   int             for_us, from_us;
   FILE            *f;

   // do not scan one area twice
   if (area->scn) return;

   if (config->routeCount == 0) {
       w_log('7', "No routing -> Scanning stop");
       // create flag for netmail trackers
       if (config->netmailFlag) {
	   if (NULL == (f = fopen(config->netmailFlag,"a")))
	       w_log('9', "Could not create netmail flag: %s", config->netmailFlag);
	   else {
	       w_log('0', "Created netmail flag: %s", config->netmailFlag);
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
       w_log('1', "Scanning NetmailArea %s", area -> areaName);

       if (area->msgbType == MSGTYPE_SDM) noHighWaters = 1;
       i = (noHighWaters) ? 0 : MsgGetHighWater(netmail);
       highestMsg = MsgGetNumMsg(netmail);

       // scan all Messages and test if they are already sent.
       while (i < highestMsg) {
	   msg = MsgOpenMsg(netmail, MOPEN_RW, ++i);

	   // msg does not exist
	   if (msg == NULL) continue;
	   statScan.msgs++;

	   MsgReadMsg(msg, &xmsg, 0, 0, NULL, 0, NULL);
	   cvtAddr(xmsg.dest, &dest);
	   for_us = 0;
	   for (j=0; j < config->addrCount; j++)
	       if (addrComp(dest, config->addr[j])==0) {for_us = 1; break;}
                
	   // if not sent and not for us -> pack it
	   if (((xmsg.attr & MSGSENT) != MSGSENT) && (for_us==0)) {
	       if (packMsg(msg, &xmsg, area) == 0) {
		   statScan.exported++;
		   area->scn++;
	       }
	   }

	   MsgCloseMsg(msg);

	   cvtAddr(xmsg.orig, &orig);
	   from_us = 0;
	   for (j=0; j < config->addrCount; j++)
	       if (addrComp(orig, config->addr[j])==0) {from_us = 1; break;}

	   //  non transit messages without k/s flag not killed
	   if (!(xmsg.attr & MSGKILL) && !(xmsg.attr & MSGFWD)) from_us = 1;

	   // transit messages from us will be killed
	   if (from_us && (xmsg.attr & MSGFWD)) from_us = 0;

	   if (((!for_us && !from_us) || (xmsg.attr&MSGKILL)) && (xmsg.attr&MSGSENT)) {
	       MsgKillMsg(netmail, i);
	       i--;
	   }

       } /* endfor */

       if (noHighWaters==0) MsgSetHighWater(netmail, i);
       MsgCloseArea(netmail);
   } else {
       w_log('9', "Could not open NetmailArea %s", area -> areaName);
   } /* endif */
}

void writeScanStatToLog(void) {
   char logchar;
   unsigned i;

   if (statScan.exported==0)
      logchar='1';
     else
      logchar='4';

   w_log(logchar, "Statistics");
   w_log(logchar, "    areas: % 4d   msgs: % 6d", statScan.areas, statScan.msgs);
   w_log(logchar, "    exported: % 4d", statScan.exported);

   /* Now write areas summary */
   w_log(logchar, "Areas summary:");
   for (i = 0; i < config->netMailAreaCount; i++)
       if (config->netMailAreas[i].scn > 1)
	   w_log(logchar, "netmail area %s - %d msgs", 
		 config->netMailAreas[i].areaName, config->netMailAreas[i].scn-1);
   for (i = 0; i < config->echoAreaCount; i++)
       if (config->echoAreas[i].scn > 1)
	   w_log(logchar, "echo area %s - %d msgs", 
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
	
    s_area *area;
    
    if ((area = getNetMailArea(config, name)) != NULL) {
	scanNMArea(area); 
	return 1;
    } else {
	// maybe it's echo area    
	area = getEchoArea(config, name);
	if (area != &(config->badArea)) {
	    if (area && area->msgbType != MSGTYPE_PASSTHROUGH && 
		area -> downlinkCount > 0) { 
		scanEMArea(area);
		return 1;
	    }
	} else {
	    if (NULL != getLocalArea(config,name))
		w_log('4', "Area \'%s\' is local -> Skipped", name);
	    else
		w_log('4', "Area \'%s\' is not found -> Scanning stop", name);
	}
    }
    return 0;
}

void scanExport(int type, char *str) {
	
   int i;
   FILE *f = NULL;
   FILE *ftmp = NULL;
   char *tmplogname = NULL;
   char *line;
   struct stat st;
   
   // zero statScan   
   memset(&statScan, '\0', sizeof(s_statScan));
   w_log('1', "Start %s%s...",
		   type & SCN_ECHOMAIL ? "scanning" : "packing",
		   type & SCN_FILE ? " with -f " : 
		   type & SCN_NAME ? " with -a " : "");

   if (type & SCN_ALL) {
       if (config->echotosslog)
       {
           f = fopen(config->echotosslog, "r");
	   if (f != NULL && config->packNetMailOnScan == 0) {
               tmplogname = (char *) smalloc(strlen(config->echotosslog)+7);
               // assuming we have max. 5 digits pid + '.' and '\0'
               sprintf(tmplogname, "%s.%u", config->echotosslog, getpid());
               ftmp = fopen(tmplogname, "w");
               if (ftmp == NULL) {
                   w_log('9', "Can't open file %s for writing : %s", tmplogname, strerror(errno));
                   // close file so all areas will be scanned instead of panic.
                   fclose(f);
               }
	   }
       }
   }
   if (type & SCN_FILE) {
       tmplogname = (char *) smalloc(strlen(str)+7);
       // assuming we have max. 5 digits pid + '.' and '\0'
       sprintf(tmplogname, "%s.%d", str, getpid());
       f = fopen(str, "r");
       if (f != NULL) {
           ftmp = fopen(tmplogname, "w");
           if (ftmp == NULL) {
               w_log('9', "Can't open file %s for writing : %s", tmplogname, strerror(errno));
               // close file so all areas will be scanned instead of panic.
               fclose(f);
           }
       }
   }

   if (type & SCN_NAME) {
      scanByName(str);   
   } else if (f == NULL) {
       if (type & SCN_FILE) {
           w_log('4', "EchoTossLogFile not found -> Scanning stop");
           return;
       }
       if (type & SCN_ECHOMAIL) {
           // if echotoss file does not exist scan all areas
           w_log('4', "EchoTossLogFile not found -> Scanning all areas.");
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
   } else {
   // else scan only those areas which are listed in the file
      w_log('4', "EchoTossLogFile found -> Scanning only listed areas");

      while (!feof(f)) {
         line = readLine(f);

         if (line != NULL) {
	    if (*line && line[strlen(line)-1] == '\r')
	       line[strlen(line)-1] = '\0';  /* fix for DOSish echotoss.log */
            striptwhite(line);
            if (!ftmp) { // the same as if(config->packNetMailOnScan) {
                scanByName(line);
            } else {
                /* exclude NetmailAreas in echoTossLogFile */
                if (type & SCN_ECHOMAIL) {
                    if (getNetMailArea(config, line) == NULL)
                        scanByName(line);
                    else
                        fprintf(ftmp, "%s\n", line);
                } else {
                    if (getNetMailArea(config, line) != NULL)
                        scanByName(line);
                    else
                        fprintf(ftmp, "%s\n", line);
                }
            }
            nfree(line);
         }
      }
   };
   
   if (f != NULL) { 
       fclose(f);
       if (ftmp != NULL) fclose(ftmp);
       st.st_size = 0;
       if (tmplogname) stat(tmplogname, &st);
       if (type & SCN_ALL) {
           if (st.st_size == 0) { // all entries was processed
               remove(config->echotosslog);
               if (tmplogname) remove(tmplogname);
           } else { // we still have areas
               remove(config->echotosslog);
               rename(tmplogname, config->echotosslog);
           }
       } 
       else if (type & SCN_FILE) {
           if (st.st_size == 0) {
               remove(str);
               if (tmplogname) remove(tmplogname);
    	   } else {
               remove(str);
               rename(tmplogname, str);
           }
       }
   };
   if (tmplogname) nfree (tmplogname);

//   if (type & SCN_ECHOMAIL) arcmail(NULL);
//   if (type & SCN_ECHOMAIL)
   // pack tempOutbound after scan Echomail, Netmail or EchoTossLogFile
   tossTempOutbound(config->tempOutbound);

   writeDupeFiles();
   writeScanStatToLog();
}
