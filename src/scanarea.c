/*:ts=8*/
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
#include <ctype.h>

#include <fidoconfig.h>
#include <common.h>

#include <pkt.h>
#include <scan.h>
#include <seenby.h>
#include <log.h>
#include <global.h>
#include <version.h>
#include <recode.h>

#include <msgapi.h>

#include <stamp.h>
#include <typedefs.h>
#include <compiler.h>
#include <progprot.h>

void makeMsg(HMSG hmsg, XMSG xmsg, s_message *msg, s_area *echo)
{
   char   *kludgeLines, *seenByPath, addr2d[12];
   UCHAR  *ctrlBuff;
   UINT32 ctrlLen;
   int    i, seenByCount;
   s_seenBy *seenBys;

   // convert Header
   msg->origAddr.zone  = xmsg.orig.zone;
   msg->origAddr.net   = xmsg.orig.net;
   msg->origAddr.node  = xmsg.orig.node;
   msg->origAddr.point = xmsg.orig.point;
   msg->origAddr.domain = NULL;

   msg->destAddr.zone  = xmsg.dest.zone;
   msg->destAddr.net   = xmsg.dest.net;
   msg->destAddr.node  = xmsg.dest.node;
   msg->destAddr.point = xmsg.dest.point;
   msg->destAddr.domain = NULL;

   msg->attributes = xmsg.attr & !MSGLOCAL; // msg should not have MSGLOCAL bit set
   //strcpy(msg->datetime, xmsg.__ftsc_date);
   sc_time(&(xmsg.date_written), msg->datetime);

   msg->toUserName   = (char *) malloc(strlen(xmsg.to)+1);
   strcpy(msg->toUserName, xmsg.to);
   msg->fromUserName = (char *) malloc(strlen(xmsg.from)+1);
   strcpy(msg->fromUserName, xmsg.from);
   msg->subjectLine  = (char *) malloc(strlen(xmsg.subj)+1);
   strcpy(msg->subjectLine, xmsg.subj);

   // make msgtext

   // convert kludgeLines
   ctrlLen = MsgGetCtrlLen(hmsg);
   ctrlBuff = (UCHAR *) malloc(ctrlLen+1+6+strlen(versionStr)+1); // 6 == "\001TID: " // 1 == "\r"
   MsgReadMsg(hmsg, NULL, 0, 0, NULL, ctrlLen, ctrlBuff);
   kludgeLines = CvtCtrlToKludge(ctrlBuff);
   strcat(kludgeLines, "\001TID: ");
   strcat(kludgeLines, versionStr);
   strcat(kludgeLines, "\r");
   free(ctrlBuff);

   // create seen-by's & path
   seenByCount = 0;
   seenBys = (s_seenBy*) calloc(echo->downlinkCount+1,sizeof(s_seenBy));
   for (i = 0;i < echo->downlinkCount; i++) {
      if (echo->downlinks[i]->hisAka.point != 0) continue; // only include nodes in SEEN-BYS
      
      seenBys[i].net  = echo->downlinks[i]->hisAka.net;
      seenBys[i].node = echo->downlinks[i]->hisAka.node;
      seenByCount++;
   }
   if (echo->useAka->point == 0) {      // only include if system is node
      seenBys[seenByCount].net = echo->useAka->net;
      seenBys[seenByCount].node = echo->useAka->node;
      seenByCount++;
   }
   sortSeenBys(seenBys, seenByCount);
   
   seenByPath = createControlText(seenBys, seenByCount, "SEEN-BY: ");
   free(seenBys);
   
   // path line
   // only include node-akas in path
   if (echo->useAka->point == 0) {
      sprintf(addr2d, "%u/%u", echo->useAka->net, echo->useAka->node);
      seenByPath = (char *) realloc(seenByPath, strlen(seenByPath)+strlen(addr2d)+1+8); // 8 == strlen("\001PATH: \r")
      strcat(seenByPath, "\001PATH: ");
      strcat(seenByPath, addr2d);
      strcat(seenByPath, "\r");
   }

   // create text
   msg->textLength = MsgGetTextLen(hmsg);
   msg->text = (char *) malloc(msg->textLength+strlen(seenByPath)+strlen(kludgeLines)+strlen(echo->areaName)+strlen("AREA:\r")+1+1); // second 1 for \r at the end of the origin line
   strcpy(msg->text, "AREA:");
   strcat(msg->text, strUpper(echo->areaName));
   strcat(msg->text, "\r");
   strcat(msg->text, kludgeLines);
   MsgReadMsg(hmsg, NULL, 0, msg->textLength, msg->text+strlen(msg->text), 0, NULL);
   if (msg->text[strlen(msg->text)-1] != '\r')  // if origin has no ending \r add it
      strcat(msg->text, "\r");
   free(kludgeLines);
   strcat(msg->text, seenByPath);

   // recoding from internal to transport charSet
   if (config->outtab != NULL) {
      recodeToTransportCharset(msg->text);
      recodeToTransportCharset(msg->subjectLine);
   }

   free(seenByPath);
}

void packEMMsg(HMSG hmsg, XMSG xmsg, s_area *echo)
{
   s_message    msg;
   UINT32       i,j=0;
   s_pktHeader  header;
   FILE         *pkt;
   
   makeMsg(hmsg, xmsg, &msg, echo);

   //translating name of the area to uppercase
   while (msg.text[j] != '\r') {msg.text[j]=toupper(msg.text[j]);j++;}

   // scan msg to donwlinks

   for (i = 0; i<echo->downlinkCount; i++) {
	  if (echo->downlinks[i]->pktFile == NULL) {
		   
		  // pktFile does not exist
		  if ( createTempPktFileName(echo->downlinks[i]) ) {
			  writeLogEntry(log, '9', "Could not create new pkt.");
			  printf("Could not create new pkt.\n");
			  disposeConfig(config);
			  closeLog(log);
			  exit(1);
		  }
		   
	  } /* endif */
		   
      makePktHeader(NULL, &header);
      header.origAddr = *(echo->downlinks[i]->ourAka);
      header.destAddr = echo->downlinks[i]->hisAka;
      if (echo->downlinks[i]->pktPwd != NULL)
      strcpy(header.pktPassword, echo->downlinks[i]->pktPwd);
      pkt = openPktForAppending(echo->downlinks[i]->pktFile, &header);

      // an echomail messages must be adressed to the link
      msg.destAddr = header.destAddr;
      writeMsgToPkt(pkt, msg);

      closeCreatedPkt(pkt);
   }

   // mark msg as sent and scanned
   xmsg.attr |= MSGSENT;
   xmsg.attr |= MSGSCANNED;
   MsgWriteMsg(hmsg, 0, &xmsg, NULL, 0, 0, 0, NULL);

   freeMsgBuffers(&msg);
}

void scanEMArea(s_area *echo)
{
   HAREA area;
   HMSG  hmsg;
   XMSG  xmsg;
   char  buff[50];
   dword highWaterMark, highestMsg, i;
   
   area = MsgOpenArea((UCHAR *) echo->fileName, MSGAREA_NORMAL, echo->msgbType | MSGTYPE_ECHO);
   if (area != NULL) {
      statScan.areas++;
      sprintf(buff, "Scanning area: %s", echo->areaName);
      writeLogEntry(log, '1', buff);
      i = highWaterMark = MsgGetHighWater(area);
      highestMsg    = MsgGetHighMsg(area);

      while (i <= highestMsg) {
         hmsg = MsgOpenMsg(area, MOPEN_RW, i++);
         if (hmsg == NULL) continue;      // msg# does not exist
         statScan.msgs++;
         MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
         if (((xmsg.attr & MSGSENT) != MSGSENT) && ((xmsg.attr & MSGLOCAL) == MSGLOCAL)) {
            packEMMsg(hmsg, xmsg, echo);
            statScan.exported++;
         }

         MsgCloseMsg(hmsg);
      }

      MsgSetHighWater(area, i);

      MsgCloseArea(area);
   } else {
      sprintf(buff, "Could not open %s", echo->fileName);
      writeLogEntry(log, '9', buff);
   } /* endif */
}
