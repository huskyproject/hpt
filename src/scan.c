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
 *****************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/xstr.h>

#include <fcommon.h>
#include <pkt.h>
#include <scan.h>
#include <log.h>
#include <global.h>
#include <version.h>
#include <recode.h>
#include <toss.h>
#include <strsep.h>

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
   // clear trs, local & k/s flags
   msg->attributes &= ~(MSGFWD|MSGLOCAL|MSGKILL);

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

void convertMsgText(HMSG SQmsg, s_message *msg, s_addr ourAka)
{
   char    *kludgeLines;
   UCHAR   *ctrlBuff;
   UINT32  ctrlLen;
   time_t  tm;
   struct tm *dt;

   // get kludge lines
   ctrlLen = MsgGetCtrlLen(SQmsg);
   ctrlBuff = (unsigned char *) safe_malloc(ctrlLen+1);
   MsgReadMsg(SQmsg, NULL, 0, 0, NULL, ctrlLen, ctrlBuff);
   ctrlBuff[ctrlLen] = '\0'; /* MsgReadMsg does not do zero termination! */
   kludgeLines = (char *) CvtCtrlToKludge(ctrlBuff);
   nfree(ctrlBuff);

   // make text
   msg->textLength = MsgGetTextLen(SQmsg);

   time(&tm);
   dt = gmtime(&tm);

   msg->text = NULL;
   xstrcat(&(msg->text), kludgeLines);
   // FIXME: make a switch in config file
   //xscatprintf(&(msg->text), "\001TID: %s\r", versionStr);
   
   ctrlLen = strlen(msg->text);
   xstralloc(&(msg->text), msg->textLength + ctrlLen);

   MsgReadMsg(SQmsg, NULL, 0, msg->textLength, (unsigned char *) msg->text+ctrlLen, 0, NULL);
   msg->text[msg->textLength+ctrlLen] = '\0'; /* MsgReadMsg doesn't do zero termination */

   xscatprintf(&(msg->text), "\001Via %u:%u/%u.%u @%04u%02u%02u.%02u%02u%02u.UTC %s\r",
			   ourAka.zone, ourAka.net, ourAka.node, ourAka.point,
			   dt->tm_year + 1900, dt->tm_mon + 1, dt->tm_mday,
			   dt->tm_hour, dt->tm_min, dt->tm_sec, versionStr);

   // recoding text to TransportCharSet
   if (config->outtab != NULL) recodeToTransportCharset((CHAR*)msg->text);

   nfree(kludgeLines);
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

s_route *findRouteForNetmail(s_message msg)
{
   char addrStr[24];
   UINT i;

   // FIX ME - we need a better solution here...
   sprintf(addrStr, "%u:%u/%u.%u", msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);

#ifdef DO_PERL
   { s_route *route;
     if ((route = perlroute(&msg)) != NULL)
       return route;
   }
#endif
   if ((msg.attributes & MSGFILE) == MSGFILE) {
      // if msg has file attached
      for (i=0; i < config->routeFileCount; i++) {
         if (patmat(addrStr, config->routeFile[i].pattern))
            return &(config->routeFile[i]);
      }
   } else {
      // if msg has no file attached
      for (i=0; i < config->routeMailCount; i++) {
         if (patmat(addrStr, config->routeMail[i].pattern))
            return &(config->routeMail[i]);
      }
   }

   for (i=0; i < config->routeCount; i++) {
      if(patmat(addrStr, config->route[i].pattern))
         return &(config->route[i]);
   }

   // if no aka is found return no link
   return NULL;
}

s_link *getLinkForRoute(s_route *route, s_message *msg) {
   static s_link tempLink;
   s_link *getLink;

   if (route==NULL) return NULL;
   
   if (route->target == NULL) {
      memset(&tempLink, '\0', sizeof(s_link));

      tempLink.hisAka = msg->destAddr;
      tempLink.ourAka = &(config->addr[0]);
      tempLink.name   = (char *) safe_malloc(1);
      tempLink.name[0] = '\0';
       
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

      getLink = getLinkFromAddr(*config, tempLink.hisAka);

      if (getLink != NULL) return getLink;
      else return &tempLink;
      
   } else return route->target;
}

void processAttachs(s_link *link, s_message *msg)
{
   FILE *flo;
   char *p, *running, *token;
   char *newSubjectLine = NULL;
   
   flo = fopen(link->floFile, "a");

   running = msg->subjectLine;
   token = strseparate(&running, " \t");

   while (token != NULL) {
#if defined(UNIX) || defined(__linux__)
	   if (!fexist(token)) strLower(token);
#endif
      if (flo != NULL) {
          if (msg->text && strstr(msg->text, "\001FLAGS KFS"))
			  fprintf(flo, "^%s\n", token);
          else if (msg->text && strstr(msg->text, "\001FLAGS TFS"))
			  fprintf(flo, "#%s\n", token);
          else
			  fprintf(flo, "%s\n", token);
      }
	  if (newSubjectLine!=NULL) xstrcat(&newSubjectLine, " ");
      if (NULL != (p=strrchr(token, PATH_DELIM)))
		  xstrcat(&newSubjectLine, p+1);
	  else xstrcat(&newSubjectLine, token);
      token = strseparate(&running, " \t");
   }
   
   if (flo!= NULL) {
      fclose(flo);
   } else writeLogEntry(hpt_log, '9', "Could not open FloFile");

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
   } else writeLogEntry(hpt_log, '9', "Could not open FloFile");

}

int packMsg(HMSG SQmsg, XMSG *xmsg, s_area *area)
{
   FILE        *pkt;
   e_prio      prio;
   s_message   msg;
   s_pktHeader header;
   s_route     *route;
   s_link      *link, *virtualLink;
   char        freeVirtualLink = 0;

   memset(&msg,'\0',sizeof(s_message));
   convertMsgHeader(*xmsg, &msg);
   convertMsgText(SQmsg, &msg, msg.origAddr);

   // prepare virtual link...
   virtualLink = getLinkFromAddr(*config, msg.destAddr);  //maybe the link is in config?
   if (virtualLink == NULL) {
      virtualLink = safe_malloc(sizeof(s_link));  // if not create new virtualLink link
      memset(virtualLink, '\0', sizeof(s_link));
      virtualLink->hisAka = msg.destAddr;
      virtualLink->ourAka = &(msg.origAddr);
      virtualLink->name = (char *) safe_malloc(strlen(msg.toUserName)+1);
      strcpy(virtualLink->name, msg.toUserName);
      freeVirtualLink = 1;  //virtualLink is a temporary link, please free it..
   }
   if ((xmsg->attr & MSGFILE) == MSGFILE) {
	   // file attach
	   prio = NORMAL;
	   if ((xmsg->attr & MSGCRASH)==MSGCRASH) prio = CRASH; 
	   if ((xmsg->attr & MSGHOLD)==MSGHOLD) prio = HOLD;
	   
	   // we need route mail
	   if (prio==NORMAL) {
		   route = findRouteForNetmail(msg);
		   link = getLinkForRoute(route, &msg);
		   if ((route != NULL) && (link != NULL)) {
			   prio = cvtFlavour2Prio(route->flavour);
			   if (createOutboundFileName(link, prio, FLOFILE) == 0) {
				   processAttachs(link, &msg);
				   remove(link->bsyFile);
				   nfree(link->bsyFile);
				   // mark Mail as sent
				   xmsg->attr |= MSGSENT;
				   MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL);
				   nfree(link->floFile);
				   writeLogEntry(hpt_log, '7', "File %s from %u:%u/%u.%u -> %u:%u/%u.%u via %u:%u/%u.%u", msg.subjectLine, msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point, link->hisAka.zone, link->hisAka.net, link->hisAka.node, link->hisAka.point);
			   }
		   }
	   }
	   else if (createOutboundFileName(virtualLink, prio, FLOFILE) == 0) {
		   processAttachs(virtualLink, &msg);
		   remove(virtualLink->bsyFile);
		   nfree(virtualLink->bsyFile);
		   // mark Mail as sent
		   xmsg->attr |= MSGSENT;
		   MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL);
		   nfree(virtualLink->floFile);
		   writeLogEntry(hpt_log, '7', "File %s from %u:%u/%u.%u -> %u:%u/%u.%u", msg.subjectLine, msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
	   }
   } /* endif file attach */

   if ((xmsg->attr & MSGFRQ) == MSGFRQ) {
	   prio = NORMAL;
	   if ((xmsg->attr & MSGCRASH)==MSGCRASH) prio = CRASH; 
#ifdef DO_PERL
		   if (perlscanmsg(area->areaName, &msg)) {
perlscanexit:
			remove(virtualLink->bsyFile);
			nfree(virtualLink->bsyFile);
			xmsg->attr |= MSGSENT;
			freeMsgBuffers(&msg);
			if (freeVirtualLink==1) {
				nfree(virtualLink->name);
				nfree(virtualLink);
			}
			return 0;
		   }
#endif
	   if ((xmsg->attr & MSGHOLD)==MSGHOLD) prio = HOLD;
	   
	   if (prio!=NORMAL) {
		   // if msg has request flag then put the subjectline into request file.
		   if (createOutboundFileName(virtualLink, NORMAL, REQUEST) == 0) {
			   
			   processRequests(virtualLink, &msg);
			   
			   remove(virtualLink->bsyFile);
			   nfree(virtualLink->bsyFile);
			   // mark Mail as sent
			   xmsg->attr |= MSGSENT;
			   MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL);
			   nfree(virtualLink->floFile);
			   writeLogEntry(hpt_log, '7', "Request %s from %u:%u/%u.%u", msg.subjectLine, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
		   }
	   }
   } /* endif */
   
#ifdef DO_PERL
		   if (perlscanmsg(area->areaName, &msg))
			goto perlscanexit;
#endif
   if ((xmsg->attr & MSGCRASH) == MSGCRASH) {
	   // crash-msg -> make CUT
	   if (createOutboundFileName(virtualLink, CRASH, PKT) == 0) {
		   makePktHeader(virtualLink, &header);
		   pkt = openPktForAppending(virtualLink->floFile, &header);
		   writeMsgToPkt(pkt, msg);
		   closeCreatedPkt(pkt);
		   writeLogEntry(hpt_log, '7', "Crash-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);

		   remove(virtualLink->bsyFile);
		   nfree(virtualLink->bsyFile);
		   // mark Mail as sent
		   xmsg->attr |= MSGSENT;
		   MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL);
		   nfree(virtualLink->floFile);
	   }
   } else
   
   if ((xmsg->attr & MSGHOLD) == MSGHOLD) {
	   // hold-msg -> make HUT
	   if (createOutboundFileName(virtualLink, HOLD, PKT) == 0) {
		   makePktHeader(virtualLink, &header);
		   pkt = openPktForAppending(virtualLink->floFile, &header);
#ifdef DO_PERL
			   if (perlscanmsg(area->areaName, &msg))
				goto perlscanexit;
#endif
		   writeMsgToPkt(pkt, msg);
		   closeCreatedPkt(pkt);
		   writeLogEntry(hpt_log, '7', "Hold-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
		   
		   remove(virtualLink->bsyFile);
		   nfree(virtualLink->bsyFile);
		   // mark Mail as sent
		   xmsg->attr |= MSGSENT;
		   MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL);
		   nfree(virtualLink->floFile);
	   }
   } else {
      
	   // no crash, no hold flag -> route netmail
	   route = findRouteForNetmail(msg);
	   link = getLinkForRoute(route, &msg);
	   
	   if ((route != NULL) && (link != NULL) && (route->routeVia != nopack)) {
		   prio = cvtFlavour2Prio(route->flavour);
		   if (createOutboundFileName(link, prio, PKT) == 0) {
			   makePktHeader(NULL, &header);
			   header.destAddr = link->hisAka;
			   header.origAddr = *(link->ourAka);
			   if (link->pktPwd != NULL)
				   strcpy(&(header.pktPassword[0]), link->pktPwd);
			   pkt = openPktForAppending(link->floFile, &header);
			   writeMsgToPkt(pkt, msg);
			   closeCreatedPkt(pkt);
			   writeLogEntry(hpt_log, '7', "Msg from %u:%u/%u.%u -> %u:%u/%u.%u via %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point, msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point, link->hisAka.zone, link->hisAka.net, link->hisAka.node, link->hisAka.point);
			   remove(link->bsyFile);
			   nfree(link->bsyFile);
			   // mark Mail as sent
			   xmsg->attr |= MSGSENT;
			   MsgWriteMsg(SQmsg, 0, xmsg, NULL, 0, 0, 0, NULL);
			   nfree(link->floFile);
		   }
	   } else writeLogEntry(hpt_log, '7', "no route found or no-pack for %s - leave mail untouched", aka2str(msg.destAddr));
   }

   // process carbon copy
   if (config->carbonOut) carbonCopy(&msg, area);
   
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
   unsigned long   highMsg, i, j;
   XMSG            xmsg;
   s_addr          dest, orig;
   int             for_us, from_us;

   // do not scan one area twice
   if (area->scn) return;

   // FixMe: workaround for not netmail packing when there's no any routing
   if (config->routeFileCount == 0 && config->routeMailCount == 0 && config->routeCount == 0) {
      writeLogEntry(hpt_log, '7', "no route at all - leave mail untouched");
      return;
   }

   netmail = MsgOpenArea((unsigned char *) area -> fileName, MSGAREA_NORMAL, 
/*								 config->netMailArea.fperm, 
								 config->netMailArea.uid, 
								 config->netMailArea.gid, */
								 (word)area -> msgbType);
   if (netmail != NULL) {

      statScan.areas++;
      area->scn = 1;
      highMsg = MsgGetHighMsg(netmail);
      writeLogEntry(hpt_log, '1', "Scanning NetmailArea %s", area -> areaName);

      // scan all Messages and test if they are already sent.
      for (i=1; i<= highMsg; i++) {
         msg = MsgOpenMsg(netmail, MOPEN_RW, i);

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
			 if (packMsg(msg, &xmsg, area) == 0) statScan.exported++;
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
	 
         if ( (((!for_us) && (!from_us)) || (xmsg.attr & MSGKILL)) &&(xmsg.attr & MSGSENT) ){
              MsgKillMsg(netmail, i);
              i--;
         }
         
      } /* endfor */

      MsgCloseArea(netmail);
   } else {
      writeLogEntry(hpt_log, '9', "Could not open NetmailArea %s", area -> areaName);
   } /* endif */
}

void writeScanStatToLog(void) {
   char logchar;

   if (statScan.exported==0)
      logchar='1';
     else
      logchar='4';

   writeLogEntry(hpt_log, logchar, "Statistics");
   writeLogEntry(hpt_log, logchar, "    areas: % 4d   msgs: % 6d", statScan.areas, statScan.msgs);
   writeLogEntry(hpt_log, logchar, "    exported: % 4d", statScan.exported);
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
	  }; 
       } else {
          writeLogEntry(hpt_log, '4', "Area \'%s\' is not found -> Scanning stop.", name);
       };
    } /* endif */
    return 0;
};

void scanExport(int type, char *str) {
	
   int i;
   FILE *f = NULL;
   char *line;
   
   // zero statScan   
   memset(&statScan, '\0', sizeof(s_statScan));
   writeLogEntry(hpt_log, '1', "Start %s%s...",
		   type & SCN_ECHOMAIL ? "scanning" : "packing",
		   type & SCN_FILE ? " with -f " : 
		   type & SCN_NAME ? " with -a " : "");
   
   if (type & SCN_ALL) {
   	if (config->echotosslog)
   		f = fopen(config->echotosslog, "r");
   };
   
   if (type & SCN_FILE) f = fopen(str, "r");

   if (type & SCN_NAME) {
      scanByName(str);   
   } else if (f == NULL) {
	   
      if (type & SCN_FILE) {
	  writeLogEntry(hpt_log, '4', "EchoTossLogFile not found -> Scanning stop.");
	  return; 
      };
   // if echotoss file does not exist scan all areas
      writeLogEntry(hpt_log, '4', "EchoTossLogFile not found -> Scanning all areas.");
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
   } else {
   // else scan only those areas which are listed in the file
      writeLogEntry(hpt_log, '4', "EchoTossLogFile found -> Scanning only listed areas");

      while (!feof(f)) {
         line = readLine(f);

         if (line != NULL) {
	    if (*line && line[strlen(line)-1] == '\r')
	       line[strlen(line)-1] = '\0';  /* fix for DOSish echotoss.log */
    	    scanByName(line);
            nfree(line);
         }
      }
   };
   
   if (f != NULL) { 
      fclose(f);
      if (type & SCN_ALL) remove(config->echotosslog);
   };

//   if (type & SCN_ECHOMAIL) arcmail(NULL);
   if (type & SCN_ECHOMAIL) tossTempOutbound(config->tempOutbound);
   
   writeDupeFiles();
   writeScanStatToLog();
}
   
