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
#include <toss.h>

void makeMsg(HMSG hmsg, XMSG xmsg, s_message *msg, s_area *echo, int action)
{
   // action == 0 - scan area
   // action == 1 - rescan area
   // action == 2 - rescan badarea
   char   *kludgeLines, *seenByPath = NULL, addr2d[12];
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

   msg->attributes = xmsg.attr & ~MSGLOCAL; // msg should not have MSGLOCAL bit set
   //strcpy(msg->datetime, xmsg.__ftsc_date);
   sc_time((union stamp_combo *) &(xmsg.date_written), (char *)msg->datetime);

   msg->toUserName   = (char *) malloc(strlen((char*)xmsg.to)+1);
   strcpy(msg->toUserName, (char*)xmsg.to);
   msg->fromUserName = (char *) malloc(strlen((char*)xmsg.from)+1);
   strcpy(msg->fromUserName, (char*)xmsg.from);
   msg->subjectLine  = (char *) malloc(strlen((char*)xmsg.subj)+1);
   strcpy(msg->subjectLine, (char*)xmsg.subj);

   // make msgtext

   // convert kludgeLines
   ctrlLen = MsgGetCtrlLen(hmsg);
   ctrlBuff = (UCHAR *) malloc(ctrlLen+1+6+strlen(versionStr)+1); // 6 == "\001TID: " // 1 == "\r"
   MsgReadMsg(hmsg, NULL, 0, 0, NULL, ctrlLen, ctrlBuff);
   ctrlBuff[ctrlLen] = '\0'; /* MsgReadMsg does not do zero termination! */
   if (action == 0) {
       strcat(ctrlBuff, "\001TID: ");
       strcat(ctrlBuff, versionStr);
   }
   kludgeLines = (char *) CvtCtrlToKludge(ctrlBuff);
   
   free(ctrlBuff);

   if (action == 0) {
       // added SEEN-BY and PATH from scan area only
       // create seen-by's & path
       seenByCount = 0;
       seenBys = (s_seenBy*) calloc(echo->downlinkCount+1,sizeof(s_seenBy));
       for (i = 0;i < echo->downlinkCount; i++) {
          if (echo->downlinks[i]->link->hisAka.point != 0) continue; // only include nodes in SEEN-BYS
      
          seenBys[seenByCount].net  = echo->downlinks[i]->link->hisAka.net;
          seenBys[seenByCount].node = echo->downlinks[i]->link->hisAka.node;
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
   }
   
   // create text
   msg->textLength = MsgGetTextLen(hmsg);
   switch (action) {
   case 0:
      msg->text = (char *)calloc(msg->textLength+strlen(seenByPath)+strlen(kludgeLines)+strlen(echo->areaName)+strlen("AREA:\r")+1+1, sizeof(char));
      break;
   case 1:
      msg->text = (char *)calloc(msg->textLength+strlen(kludgeLines)+strlen(echo->areaName)+strlen("AREA:\r")+1+1, sizeof(char));
      break;
   default: 
      msg->text = (char *)calloc(msg->textLength+strlen(kludgeLines)+1, sizeof(char)); 
     break;
   } /* endswitch */
   if (action != 2) {
       strcpy(msg->text, "AREA:");
       strcat(msg->text, strUpper(echo->areaName));
       strcat(msg->text, "\r");
   } 
   strcat(msg->text, kludgeLines);
   MsgReadMsg(hmsg, NULL, (dword) 0, (dword) msg->textLength,
              (byte *)(msg->text+strlen(msg->text)), (dword) 0, (byte *)NULL);
   if (msg->text[strlen(msg->text)-1] != '\r')  // if origin has no ending \r add it
      strcat(msg->text, "\r");
   free(kludgeLines);
   if (action == 0) strcat(msg->text, seenByPath);
   
   // recoding from internal to transport charSet
   if (config->outtab != NULL && action != 2) {
      recodeToTransportCharset((CHAR*)msg->fromUserName);
      recodeToTransportCharset((CHAR*)msg->toUserName);
      recodeToTransportCharset((CHAR*)msg->subjectLine);
      recodeToTransportCharset((CHAR*)msg->text);
   }

   free(seenByPath);
}

void packEMMsg(HMSG hmsg, XMSG xmsg, s_area *echo)
{
   s_message    msg;
   UINT32       i,j=0;
   s_pktHeader  header;
   FILE         *pkt;
   makeMsg(hmsg, xmsg, &msg, echo, 0);

   //translating name of the area to uppercase
   while (msg.text[j] != '\r') {msg.text[j]=toupper(msg.text[j]);j++;}

   // scan msg to downlinks
   
   for (i = 0; i<echo->downlinkCount; i++) {
       // link is passive?
       if (echo->downlinks[i]->link->Pause && !echo->noPause) continue;
       // check access read for link
       if (readCheck(echo, echo->downlinks[i]->link)) continue;
	  if (echo->downlinks[i]->link->pktFile == NULL) {
		   
		  // pktFile does not exist
		  if ( createTempPktFileName(echo->downlinks[i]->link) ) {
			  writeLogEntry(hpt_log, '9', "Could not create new pkt.");
			  fprintf(stderr, "Could not create new pkt.\n");
			  disposeConfig(config);
			  closeLog(hpt_log);
			  exit(1);
		  }
		   
	  } /* endif */
		   
      makePktHeader(NULL, &header);
      header.origAddr = *(echo->downlinks[i]->link->ourAka);
      header.destAddr = echo->downlinks[i]->link->hisAka;
      if (echo->downlinks[i]->link->pktPwd != NULL)
      strcpy(header.pktPassword, echo->downlinks[i]->link->pktPwd);
      pkt = openPktForAppending(echo->downlinks[i]->link->pktFile, &header);

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
   dword highWaterMark, highestMsg, i;
   
   area = MsgOpenArea((UCHAR *) echo->fileName, MSGAREA_NORMAL, echo->msgbType | MSGTYPE_ECHO);
   if (area != NULL) {
      statScan.areas++;
      writeLogEntry(hpt_log, '1', "Scanning area: %s", echo->areaName);
      if (noHighWaters) i = highWaterMark = 0;
      else i = highWaterMark = MsgGetHighWater(area);
      highestMsg    = MsgGetHighMsg(area);

      while (i < highestMsg) {
         hmsg = MsgOpenMsg(area, MOPEN_RW, ++i);
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
      writeLogEntry(hpt_log, '9', "Could not open %s", echo->fileName);
   } /* endif */
}
