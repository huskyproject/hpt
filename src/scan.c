#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <msgapi.h>

#include <common.h>
#include <pkt.h>
#include <patmat.h>
#include <scan.h>
#include <log.h>
#include <global.h>
#include <version.h>

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
   msg->origAddr.domain =  NULL;

   msg->destAddr.zone  = xmsg.dest.zone;
   msg->destAddr.net   = xmsg.dest.net;
   msg->destAddr.node  = xmsg.dest.node;
   msg->destAddr.point = xmsg.dest.point;
   msg->destAddr.domain = NULL;

   strcpy(msg->datetime, (char *) xmsg.__ftsc_date);
   msg->subjectLine = (char *) malloc(strlen((char *)xmsg.subj)+1);
   msg->toUserName  = (char *) malloc(strlen((char *)xmsg.to)+1);
   msg->fromUserName = (char *) malloc(strlen((char *)xmsg.from)+1);
   strcpy(msg->subjectLine, (char *) xmsg.subj);
   strcpy(msg->toUserName, (char *) xmsg.to);
   strcpy(msg->fromUserName, (char *) xmsg.from);
}

void convertMsgText(HMSG SQmsg, s_message *msg, s_addr ourAka)
{
   char    *kludgeLines, viaLine[100];
   UCHAR   *ctrlBuff;
   UINT32  ctrlLen;
   time_t  tm;

   // get kludge lines
   ctrlLen = MsgGetCtrlLen(SQmsg);
   ctrlBuff = (unsigned char *) malloc(ctrlLen+1);
   MsgReadMsg(SQmsg, NULL, 0, 0, NULL, ctrlLen, ctrlBuff);
   kludgeLines = (char *) CvtCtrlToKludge(ctrlBuff);
   free(ctrlBuff);

   // make text
   msg->textLength = MsgGetTextLen(SQmsg);

   time(&tm);
   sprintf(viaLine, "\001Via %u:%u/%u.%u ,%s ,%s", ourAka.zone, ourAka.net, ourAka.node, ourAka.point, ctime(&tm), versionStr);

   msg->text = (char *) malloc(msg->textLength+strlen(kludgeLines)+strlen(viaLine)+1);

   strcpy(msg->text, kludgeLines);
//   strcat(msg->text, "\001TID: ");
//   strcat(msg->text, versionStr);
//   strcat(msg->text, "\r");

   MsgReadMsg(SQmsg, NULL, 0, msg->textLength, (unsigned char *) msg->text+strlen(msg->text), 0, NULL);

   strcat(msg->text, viaLine);

   free(kludgeLines);
}

void makePktHeader(s_message *msg, s_pktHeader *header)
{
   if (msg != NULL) {
      header->origAddr = msg->origAddr;
      header->destAddr = msg->destAddr;
   }
   header->minorProductRev = VER_MINOR;
   header->majorProductRev = VER_MAJOR;
   header->hiProductCode   = 0;
   header->loProductCode   = 0xfe;
   memset(&(header->pktPassword), 0, 9);
//   header->pktPassword[0]  = 0;       // no pwd
   time(&(header->pktCreated));
   header->capabilityWord  = 1;
   header->prodData        = 0;
}

s_link *findLinkForRoutedNetmail(s_addr destAddr)
{
   char buff[72], addrStr[24];
   UINT i;

   sprintf(addrStr, "%u:%u/%u.%u", destAddr.zone, destAddr.net, destAddr.node, destAddr.point);
   for (i=0; i < routeCount; i++) {
      if (patmat(addrStr, routes[i].pattern))
         return routes[i].link;
   }
   
   // if no aka is found return first link
   sprintf(buff, "No route for %s found. Using first link statement", addrStr);
   writeLogEntry(log, '8', buff);
   return &(links[0]);
}

void packMsg(HMSG SQmsg, XMSG xmsg)
{
   FILE        *flo, *pkt, *req;
   char        *fileName, buff[90];
   e_prio      prio;
   s_message   msg;
   s_pktHeader header;
   s_link      *link;

   convertMsgHeader(xmsg,  &msg);

   if ((xmsg.attr & MSGFRQ) == MSGFRQ) {
      // if msg has request flag then put the subjectline into request file.
      fileName = createOutboundFileName(msg.destAddr, NORMAL, REQUEST);
      req = fopen(fileName, "a");
      if (req!=NULL) {
         fprintf(req, msg.subjectLine);
         fprintf(req, "\n");
         fclose(req);
      } else writeLogEntry(log, '9', "Could not open Request File");
      free(fileName);
   } /* endif */

   if ((xmsg.attr & MSGFILE) == MSGFILE) {
      // file attach
      prio = NORMAL;
      if ((xmsg.attr & MSGCRASH) == MSGCRASH) prio = CRASH;
      if ((xmsg.attr & MSGHOLD)  == MSGHOLD)  prio = HOLD;
      if (prio != NORMAL) {
         fileName = createOutboundFileName(msg.destAddr, prio, FLOFILE);
      } else {
         link = findLinkForRoutedNetmail(msg.destAddr);
         fileName = createOutboundFileName(link->hisAka, NORMAL, FLOFILE);
      } /* endif */
      flo = fopen(fileName, "a");
      if (flo!= NULL) {
         fprintf(flo, msg.subjectLine);
         fprintf(flo, "\n");
         fclose(flo);
      } else writeLogEntry(log, '9', "Could not open FloFile");
      free(fileName);
   } /* endif */

   if ((xmsg.attr & MSGCRASH) == MSGCRASH) {
      // crash-msg -> make CUT
      fileName = createOutboundFileName(msg.destAddr, CRASH, PKT);
      convertMsgText(SQmsg, &msg, msg.origAddr);
      makePktHeader(&msg, &header);
      pkt = openPktForAppending(fileName, &header);
      writeMsgToPkt(pkt, msg);
      closeCreatedPkt(pkt);
      sprintf(buff, "Crash-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point,
              msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
      writeLogEntry(log, '7', buff);
      free(fileName);
   } else
   
   if ((xmsg.attr & MSGHOLD) == MSGHOLD) {
      // hold-msg -> make HUT
      fileName = createOutboundFileName(msg.destAddr, HOLD, PKT);
      convertMsgText(SQmsg, &msg, msg.origAddr);
      makePktHeader(&msg, &header);
      pkt = openPktForAppending(fileName, &header);
      writeMsgToPkt(pkt, msg);
      closeCreatedPkt(pkt);
      sprintf(buff, "Hold-Msg packed: %u:%u/%u.%u -> %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point,
              msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point);
      writeLogEntry(log, '7', buff);
      free(fileName);
   } else {
      
      // no crash, no hold flag -> route netmail
      link = findLinkForRoutedNetmail(msg.destAddr);
      fileName = createOutboundFileName(link->hisAka, NORMAL, PKT);
      convertMsgText(SQmsg, &msg, link->ourAka);
      makePktHeader(NULL, &header);
      header.destAddr = link->hisAka;
      header.origAddr = link->ourAka;
      strcpy(&(header.pktPassword[0]), link->pwd);
      pkt = openPktForAppending(fileName, &header);
      writeMsgToPkt(pkt, msg);
      closeCreatedPkt(pkt);
      sprintf(buff, "Msg from %u:%u/%u.%u -> %u:%u/%u.%u via %u:%u/%u.%u", msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node, msg.origAddr.point,
              msg.destAddr.zone, msg.destAddr.net, msg.destAddr.node, msg.destAddr.point, link->hisAka.zone, link->hisAka.net, link->hisAka.node, link->hisAka.point);
      writeLogEntry(log, '7', buff);
      free(fileName);
   }
   
   // mark Mail as sent
   xmsg.attr |= MSGSENT;
   MsgWriteMsg(SQmsg, 0, &xmsg, NULL, 0, 0, 0, NULL);
   
   freeMsgBuffers(&msg);
}

void scanNMArea(void)
{
   HAREA           netmail;
   HMSG            msg;
   unsigned long   highMsg, i, j;
   XMSG            xmsg;
   s_addr          dest;
   int             for_us;

   netmail = MsgOpenArea((unsigned char *) netArea.filename, MSGAREA_NORMAL, MSGTYPE_SDM);
   if (netmail != NULL) {

      highMsg = MsgGetHighMsg(netmail);

      // scan all Messages and test if they are already sent.
      for (i=1; i<= highMsg; i++) {
         msg = MsgOpenMsg(netmail, MOPEN_RW, i);

         // msg does not exist
         if (msg == NULL) continue;

         MsgReadMsg(msg, &xmsg, 0, 0, NULL, 0, NULL);
         cvtAddr(xmsg.dest, &dest);
         for_us = 0;
         for (j=0; j < addrCount; j++)
            if (addrComp(dest, addr[j])==0) {for_us = 1; break;}
                
         // if not sent and not for us -> pack it
         if (((xmsg.attr & MSGSENT) != MSGSENT) && (for_us==0))
            packMsg(msg, xmsg);

         MsgCloseMsg(msg);

         // kill/sent flag
         if ((xmsg.attr & MSGKILL) == MSGKILL) MsgKillMsg(netmail, i);
      } /* endfor */

      MsgCloseArea(netmail);
   } else {
      writeLogEntry(log, '9', "Could not open NetmailArea");
   } /* endif */
}

void scan(void)
{
   UINT i;
   
   scanNMArea();
   for (i = 0; i< echoAreaCount; i++) {
      scanEMArea(&echoAreas[i]);
   }
}
