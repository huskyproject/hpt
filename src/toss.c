/*:ts=8*/
/*****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 * Copyright (C) 1997-1998
 *
 * Matthias Tichy
 *
 * Fido:     2:2433/1245 2:2433/1247 2:2432/601.29
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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include <fidoconfig.h>
#include <common.h>

#include <dir.h>
#include <pkt.h>
#include <scan.h>
#include <toss.h>
#include <global.h>
#include <patmat.h>
#include <seenby.h>
#include <dupe.h>

#include <recode.h>
#include <areafix.h>

#include <msgapi.h>
#include <stamp.h>
#include <typedefs.h>
#include <compiler.h>
#include <progprot.h>

s_statToss statToss; 

void changeFileSuffix(char *fileName, char *newSuffix) {
   char *beginOfSuffix = strrchr(fileName, '.')+1;
   char *newFileName;
   int  length = strlen(fileName)-strlen(beginOfSuffix)+strlen(newSuffix);

   newFileName = (char *) calloc(length+1, 1);
   strncpy(newFileName, fileName, length-strlen(newSuffix));
   strcat(newFileName, newSuffix);

//   printf("old: %s      new: %s\n", fileName, newFileName);
   
   rename(fileName, newFileName);
}

int to_us(s_pktHeader header)
{
   int i = 0;

   while (i < config->addrCount)
     if (addrComp(header.destAddr, config->addr[i++]) == 0)
       return 0;
   return !0;
}

XMSG createXMSG(s_message *msg)
{
   XMSG  msgHeader;
   struct tm *date;
   time_t    currentTime;
   union stamp_combo dosdate;

   msgHeader.attr = MSGPRIVATE;
   strcpy((char *) msgHeader.from,msg->fromUserName);
   strcpy((char *) msgHeader.to, msg->toUserName);
   strcpy((char *) msgHeader.subj,msg->subjectLine);
   msgHeader.orig.zone  = msg->origAddr.zone;
   msgHeader.orig.node  = msg->origAddr.node;
   msgHeader.orig.net   = msg->origAddr.net;
   msgHeader.orig.point = msg->origAddr.point;
   msgHeader.dest.zone  = msg->destAddr.zone;
   msgHeader.dest.node  = msg->destAddr.node;
   msgHeader.dest.net   = msg->destAddr.net;
   msgHeader.dest.point = msg->destAddr.point;

   memset(&(msgHeader.date_written), 0, 8);    // date to 0

   msgHeader.utc_ofs = 0;
   msgHeader.replyto = 0;
   memset(&(msgHeader.replies), 0, 40);   // no replies
   strcpy((char *) msgHeader.__ftsc_date, msg->datetime);
   ASCII_Date_To_Binary(msg->datetime, &(msgHeader.date_written));

   currentTime = time(NULL);
   date = localtime(&currentTime);
   TmDate_to_DosDate(date, &dosdate);
   msgHeader.date_arrived = dosdate.msg_st;

   return msgHeader;
}

void putMsgInArea(s_area *echo, s_message *msg, int strip)
{
   char buff[70], *ctrlBuff, *textStart, *textWithoutArea;
   UINT textLength = msg->textLength;
   HAREA harea;
   HMSG  hmsg;
   XMSG  xmsg;
   char *slash;
#ifdef UNIX
   char limiter = '/';
#else
   char limiter = '\\';
#endif

   // create Directory Tree if necessary
   if (echo->msgbType == MSGTYPE_SDM)
      createDirectoryTree(echo->fileName);
   else {
      // squish area
      slash = strrchr(echo->fileName, limiter);
      *slash = '\0';
      createDirectoryTree(echo->fileName);
      *slash = limiter;
   }

   harea = MsgOpenArea((UCHAR *) echo->fileName, MSGAREA_CRIFNEC, echo->msgbType | MSGTYPE_ECHO);
   if (harea != NULL) {
      hmsg = MsgOpenMsg(harea, MOPEN_CREATE, 0);
      if (hmsg != NULL) {

         // recode from TransportCharset to internal Charset
         if (msg->recode == 0 && config->intab != NULL) {
            recodeToInternalCharset(msg->subjectLine);
            recodeToInternalCharset(msg->text);
			msg->recode = 1;
         }

         textWithoutArea = msg->text;
         
         if ((strncmp(msg->text, "AREA:", 5) == 0) && (strip==1)) {
            // jump over AREA:xxxxx\r
            while (*(textWithoutArea) != '\r') textWithoutArea++;
            textWithoutArea++;
         }
         
         ctrlBuff = CopyToControlBuf((UCHAR *) textWithoutArea, (UCHAR **) &textStart, &textLength);
         // textStart is a pointer to the first non-kludge line
         xmsg = createXMSG(msg);
		 
         MsgWriteMsg(hmsg, 0, &xmsg, textStart, strlen(textStart), strlen(textStart), strlen(ctrlBuff), ctrlBuff);
		 
         MsgCloseMsg(hmsg);
		 
      } else {
         sprintf(buff, "Could not create new msg in %s!", echo->fileName);
         writeLogEntry(log, '9', buff);
      } /* endif */
      MsgCloseArea(harea);
   } else {
      sprintf(buff, "Could not open/create EchoArea %s!", echo->fileName);
      writeLogEntry(log, '9', buff);
   } /* endif */
}

void createSeenByArrayFromMsg(s_message *msg, s_seenBy *seenBys[], UINT *seenByCount)
{
   char *seenByText, *start, *token;
   unsigned long temp;
   char *endptr;
   
   *seenByCount = 0;
   start = msg->text;

   // find beginning of seen-by lines
   do {
      start = strstr(start, "SEEN-BY:");
      if (start == NULL) return;
      start += 8; // jump over SEEN-BY:

      while (*start == ' ') start++; // find first word after SEEN-BY:
   } while (!isdigit(*start));

   // now that we have the start of the SEEN-BY's we can tokenize the lines and read them in
   seenByText = malloc(strlen(start)+1);
   strcpy(seenByText, start);

   token = strtok(seenByText, " \r\t\xfe");
   while (token != NULL) {
      if (strcmp(token, "\001PATH:")==0) break;
      if (isdigit(*token)) {

         // get new memory
         (*seenByCount)++;
         *seenBys = (s_seenBy*) realloc(*seenBys, sizeof(s_seenBy) * (*seenByCount));
         
         // parse token
         temp = strtoul(token, &endptr, 10);
         if ((*endptr) == '\0') {
            // only node aka
            (*seenBys)[*seenByCount-1].node = temp;
            // use net aka of last seenBy
            (*seenBys)[*seenByCount-1].net = (*seenBys)[*seenByCount-2].net;
         } else {
            // net and node aka
            (*seenBys)[*seenByCount-1].net = temp;
            // eat up '/'
            endptr++;
            (*seenBys)[*seenByCount-1].node = atoi(endptr);
         }
      }
      token = strtok(NULL, " \r\t\xfe");
   }

   //test output for reading of seenBys...
//   for (i=0; i < *seenByCount; i++) printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
//   exit(2);

   free(seenByText);
}

void createPathArrayFromMsg(s_message *msg, s_seenBy *seenBys[], UINT *seenByCount)
{

   // DON'T GET MESSED UP WITH THE VARIABLES NAMED SEENBY...
   // THIS FUNCTION READS PATH!!!
   
   char *seenByText, *start, *token;
   char *endptr;
   unsigned long temp;
   
   *seenByCount = 0;
   start = msg->text;
   // find beginning of path lines
   do {
      start = strstr(start, "\001PATH:");
      if (start == NULL) return;
      start += 7; // jump over PATH:

      while (*start == ' ') start++; // find first word after PATH:
   } while (!isdigit(*start));

   // now that we have the start of the PATH' so we can tokenize the lines and read them in
   seenByText = malloc(strlen(start)+1);
   strcpy(seenByText, start);

   token = strtok(seenByText, " \r\t\xfe");
   while (token != NULL) {
      if (isdigit(*token)) {
         (*seenByCount)++;
         *seenBys = (s_seenBy*) realloc(*seenBys, sizeof(s_seenBy) * (*seenByCount));
         
         // parse token
         temp = strtoul(token, &endptr, 10);
         if ((*endptr) == '\0') {
            // only node aka
            (*seenBys)[*seenByCount-1].node = temp;
            // use net aka of last seenBy
            (*seenBys)[*seenByCount-1].net = (*seenBys)[*seenByCount-2].net;
         } else {
            // net and node aka
            (*seenBys)[*seenByCount-1].net = temp;
            // eat up '/'
            endptr++;
            (*seenBys)[*seenByCount-1].node = atoi(endptr);
         }

      }
      token = strtok(NULL, " \r\t\xfe");
   }

   // test output for reading of paths...
   //for (i=0; i < *seenByCount; i++) printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
   //exit(2);

   free(seenByText);
}

int readCheck(s_area *echo, s_link *link) {
	int i, rc=0;
	char *denygrp;

	// read for all
	if (echo->rgrp==NULL) return 0;

	denygrp = link->DenyGrp;

	if (echo->rgrp!=NULL && denygrp!=NULL) {
		// is this link allowed to read messages from this area?
		for (i=0; i< strlen(echo->rgrp); i++) {
			if ( strchr( denygrp, echo->rgrp[i]) != NULL) {
//				printf("read!\n");
				return 0;
			} else if ( i == strlen (echo->rgrp) - 1 ) rc++;
		}
	} else rc++;

	if (echo->rwgrp!=NULL && denygrp!=NULL) {
		// maybe he have r/w acess?
		for (i=0; i< strlen(echo->rwgrp); i++) {
			if ( strchr( denygrp, echo->rwgrp[i]) != NULL) {
//				printf("read/write!\n");
				return 0;
			} else if ( i == strlen (echo->rwgrp) - 1 ) rc++;
		}
	} else rc++;
	
	return rc;
}

int writeCheck(s_area *echo, s_link *link) {
	int i, rc=0;
	char *denygrp;

	// read/write for all
	if ((echo->wgrp==NULL) && (echo->rwgrp==NULL)) return 0;

	denygrp = link->DenyGrp;

	if (echo->wgrp!=NULL && denygrp!=NULL) {
		// is this link allowed to post messages to this area?
		for (i=0; i< strlen(echo->wgrp); i++) {
			if ( strchr( denygrp, echo->wgrp[i]) != NULL) {
//				printf("write!\n");
				return 0;
			} else if ( i == strlen (echo->wgrp) - 1 ) rc++;
		}
	} else rc++;

	if (echo->rwgrp!=NULL && denygrp!=NULL) {
		// maybe he have r/w acess?
		for (i=0; i< strlen(echo->rwgrp); i++) {
			if ( strchr( denygrp, echo->rwgrp[i]) != NULL) {
//				printf("read/write!\n");
				return 0;
			} else if ( i == strlen (echo->rwgrp) - 1 ) rc++;
		}
	} else rc++;
	
	return rc;
}

void forwardMsgToLinks(s_area *echo, s_message *msg, s_addr pktOrigAddr)
{
   s_seenBy *seenBys = NULL, *path = NULL;
   UINT     seenByCount, pathCount, i;
   char     *start, *c, *newMsgText, *seenByText = NULL, *pathText = NULL;
   
   FILE     *pkt;
   s_pktHeader header;

   createSeenByArrayFromMsg(msg, &seenBys, &seenByCount);
   // add seenBy for links
   for (i=0; i<echo->downlinkCount; i++) {
      if (echo->downlinks[i]->hisAka.point != 0) continue; // don't include points in SEEN-BYS
      if (addrComp(echo->downlinks[i]->hisAka, pktOrigAddr)==0) continue; // don´t include the link we have got the mail from in SEEN-BYS
      
      seenBys = (s_seenBy*) realloc(seenBys, sizeof(s_seenBy) * (seenByCount)+1);
      seenBys[seenByCount].net = echo->downlinks[i]->hisAka.net;
      seenBys[seenByCount].node = echo->downlinks[i]->hisAka.node;
      seenByCount++;
   }

   sortSeenBys(seenBys, seenByCount);

//   for (i=0; i< seenByCount;i++) printf("%u/%u ", seenBys[i].net, seenBys[i].node);
   //exit(2);

   createPathArrayFromMsg(msg, &path, &pathCount);
   if (pathCount > 0) {
      if (path[pathCount-1].net != echo->useAka->net && path[pathCount-1].node != echo->useAka->node ) {
         // add our aka to path
         path = (s_seenBy*) realloc(path, sizeof(s_seenBy) * (pathCount)+1);
         path[pathCount].net = echo->useAka->net;
         path[pathCount].node = echo->useAka->node;
         pathCount++;
      }
   } else {
      path = (s_seenBy*) malloc(sizeof(s_seenBy) * (pathCount)+1);
      path[pathCount].net = echo->useAka->net;
      path[pathCount].node = echo->useAka->node;
      pathCount++;
   }

//   for (i=0; i< pathCount;i++) printf("%u/%u ", path[i].net, path[i].node);
   //exit(2);


   // find start of seenBys in Msg
   start = strstr(msg->text, ")\rSEEN-BY: ");
   if (start == NULL) start = strstr(msg->text, "\rSEEN-BY: ");
   if (start != NULL) {
      while(*start != 'S') start++; // to jump over )\r

      // create new seenByText
      seenByText = createControlText(seenBys, seenByCount, "SEEN-BY: ");
      pathText   = createControlText(path, pathCount, "\001PATH: ");
   
      // reserve space for msg-body - old seenbys&path + new seenbys + new path
      newMsgText = (char *) malloc(strlen(msg->text) - strlen(start) + strlen(seenByText) + strlen(pathText) + 1);
   
      // replace msg's seen-bys and path with our new generated
      c = msg->text;
      i = 0;
      while (c != start) {
         newMsgText[i] = *c;
         c++;
         i++;
      }
      newMsgText[i] = 0;
      strcat(newMsgText, seenByText);
      strcat(newMsgText, pathText);

      free(msg->text);
      msg->text = newMsgText;
   }

   // add msg to the pkt's of the downlinks
   for (i = 0; i<echo->downlinkCount; i++)
   {
      // don't export to link who has sent the echomail to us
      if (addrComp(pktOrigAddr, echo->downlinks[i]->hisAka)==0) continue;

      // does the link has read access for this echo?
      if (readCheck(echo, echo->downlinks[i])!=0) continue;
      
      // create pktfile if necessary
      if (echo->downlinks[i]->pktFile == NULL) {
         // pktFile does not exist
         if ( createTempPktFileName(echo->downlinks[i]) ) {
	    writeLogEntry(log, '9', "Could not create new pkt!\n");
	    printf("Could not create new pkt!\n");
	    exit(1);
	 }
      } /* endif */

      makePktHeader(NULL, &header);
      header.origAddr = *(echo->downlinks[i]->ourAka);
      header.destAddr = echo->downlinks[i]->hisAka;
      if (echo->downlinks[i]->pktPwd != NULL)
         strcpy(header.pktPassword, echo->downlinks[i]->pktPwd);
      pkt = openPktForAppending(echo->downlinks[i]->pktFile, &header);

      // an echomail msg must be adressed to the link
      msg->destAddr = header.destAddr;
      writeMsgToPkt(pkt, *msg);
      closeCreatedPkt(pkt);
   }

   if (start != NULL) {  // no seenBys found seenBys not changed...
      free(seenByText);
      free(pathText);
   }
   free(seenBys);
   free(path);
}

int autoCreate(char *c_area, s_addr pktOrigAddr)
{
   FILE *f;
   char buff[255], myaddr[20], hisaddr[20];
   int i=0,j=0;
   
   //translating name of the area to lowercase, much better imho.
   while (*c_area != '\0') {
      *c_area=tolower(*c_area);
      if ((*c_area=='/') || *c_area=='\\')) *c_area = '_'; // convert any path delimiters to _
      c_area++;
      i++;
   }

   while (i>0) {c_area--;i--;};
   
   if ((f=fopen(getConfigFileName(),"a")) == NULL)
	   {
		   fprintf(stderr,"autocreate: cannot open config file\n");
		   return 1;
	   }
   
   // making local address and address of uplink
   sprintf(myaddr, "%u:%u/%u",config->addr[j].zone,config->addr[j].net,
           config->addr[j].node);
   sprintf(hisaddr,"%u:%u/%u",pktOrigAddr.zone,pktOrigAddr.net,
            pktOrigAddr.node);
   
   //if you are point...
   if (config->addr[j].point != 0)  {
	   sprintf(buff,".%u",config->addr[j].point);
	   strcat(myaddr,buff);
   }
   
   //autocreating from point...
   if (pktOrigAddr.point != 0)  {
	   sprintf(buff,".%u",pktOrigAddr.point);
	   strcat(hisaddr,buff);
   }
   
   //write new line in config file
   if (stricmp(config->msgBaseDir, "passthrough")!=0)
      sprintf(buff, "EchoArea %s %s%s -a %s Squish %s ", c_area, config->msgBaseDir, c_area, myaddr, hisaddr);
   else
      sprintf(buff, "EchoArea %s Passthrough -a %s %s ", c_area, myaddr, hisaddr);
   if ((config->autoCreateDefaults != NULL) &&
       (strlen(buff)+strlen(config->autoCreateDefaults))<255) {
      strcat(buff, config->autoCreateDefaults);
   }
   fprintf(f, buff);
   fprintf(f, "\n");
   
   fclose(f);

   // add new created echo to config in memory
   parseLine(buff,config);
   
   sprintf(buff, "Area '%s' autocreated by %s", c_area, hisaddr);
   writeLogEntry(log, '8', buff);
   return 0;
}

int carbonCopy(s_message *msg, s_area *echo)
{
	int i;
	char *kludge;
	s_area *area;

	if (echo->ccoff==1) return 1;

	for (i=0; i<config->carbonCount; i++) {

		area = config->carbons[i].area;

		switch (config->carbons[i].type) {

		case 0:
			if (strcasecmp(msg->toUserName, config->carbons[i].str)==0) {
				putMsgInArea(area,msg,0);
				return 0;
			}
			break;
		case 1:
			if (strcasecmp(msg->fromUserName, config->carbons[i].str)==0) {
				putMsgInArea(area,msg,0);
				return 0;
			}
			break;
		case 2:
			kludge=getKludge(*msg, config->carbons[i].str);
			if (kludge!=NULL) {
				putMsgInArea(area,msg,0);
				free(kludge);
				return 0;
			}
			break;
		default: break;
		}
	}

	return 1;
}

void processEMMsg(s_message *msg, s_addr pktOrigAddr)
{
   char   *area, *textBuff;
   s_area *echo;
   s_link *link;
   int    writeAccess;

   link = getLinkFromAddr(*config, pktOrigAddr);

   textBuff = (char *) malloc(strlen(msg->text)+1);
   strcpy(textBuff, msg->text);
   
   area = strtok(textBuff, "\r");
   area += 5;

   echo = getArea(config, area);
   statToss.echoMail++;

   writeAccess = writeCheck(echo, link);
   if (writeAccess!=0) echo = &(config->badArea);

   if (echo != &(config->badArea)) {
      if (dupeDetection(echo, *msg)==1) {
         // no dupe

         if (echo->downlinkCount > 1) {   // if only one downlink, we've got the mail from him
            forwardMsgToLinks(echo, msg, pktOrigAddr);
            statToss.exported++;
         }

         if (echo->msgbType != MSGTYPE_PASSTHROUGH) {
            putMsgInArea(echo, msg,1);
            echo->imported = 1;  // area has got new messages
	    statToss.saved++;
         } else statToss.passthrough++;

         if (config->carbonCount != 0) carbonCopy(msg, echo);
   
      } else {
         // msg is dupe
         if (echo->dupeCheck == move) {
            putMsgInArea(&(config->dupeArea), msg, 0);
         }
	 statToss.dupes++;
      }
   }

   if (echo == &(config->badArea)) {
      if (config->carbonCount != 0) carbonCopy(msg, echo);
      // checking for autocreate option
      link = getLinkFromAddr(*config, pktOrigAddr);
      if ((link != NULL) && (link->autoAreaCreate != 0) &&(writeAccess == 0)) {
         autoCreate(area, pktOrigAddr);
         echo = getArea(config, area);
         putMsgInArea(echo, msg, 1);
      } else {
         // no autoareaCreate -> msg to bad
         statToss.bad++;
      
         putMsgInArea(&(config->badArea), msg, 0);
      }
   }


   free(textBuff);
}

void processNMMsg(s_message *msg,s_addr pktOrigAddr)
{
   HAREA  netmail;
   HMSG   msgHandle;
   UINT   len = msg->textLength;
   char   *bodyStart;             // msg-body without kludgelines start
   char   *ctrlBuf;               // Kludgelines
   XMSG   msgHeader;
   char   buff[36];               // buff for sprintf
   char *slash;
#ifdef UNIX
   char limiter = '/';
#else
   char limiter = '\\';
#endif

   // create Directory Tree if necessary
   if (config->netMailArea.msgbType == MSGTYPE_SDM)
      createDirectoryTree(config->netMailArea.fileName);
   else {
      // squish area
      slash = strrchr(config->netMailArea.fileName, limiter);
      *slash = '\0';
      createDirectoryTree(config->netMailArea.fileName);
      *slash = limiter;
   }

   netmail = MsgOpenArea((unsigned char *) config->netMailArea.fileName, MSGAREA_CRIFNEC, config->netMailArea.msgbType);

   if (netmail != NULL) {
      msgHandle = MsgOpenMsg(netmail, MOPEN_CREATE, 0);

      if (msgHandle != NULL) {
         config->netMailArea.imported = 1; // area has got new messages

         if (config->intab != NULL) {
            recodeToInternalCharset(msg->text);
            recodeToInternalCharset(msg->subjectLine);
         }
         
         msgHeader = createXMSG(msg);
         /* Create CtrlBuf for SMAPI */
         ctrlBuf = (char *) CopyToControlBuf((UCHAR *) msg->text, (UCHAR **) &bodyStart, &len);
         /* write message */
         MsgWriteMsg(msgHandle, 0, &msgHeader, (UCHAR *) bodyStart, len, len, strlen(ctrlBuf)+1, (UCHAR *) ctrlBuf);
         free(ctrlBuf);
         MsgCloseMsg(msgHandle);

         sprintf(buff, "Tossed Netmail: %u:%u/%u.%u -> %u:%u/%u.%u", msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node, msg->origAddr.point,
                         msg->destAddr.zone, msg->destAddr.net, msg->destAddr.node, msg->destAddr.point);
         writeLogEntry(log, '7', buff);
	 statToss.netMail++;
      } else {
         writeLogEntry(log, '9', "Could not write message to NetmailArea");
      } /* endif */

      MsgCloseArea(netmail);
   } else {
      printf("%u\n", msgapierr);
      writeLogEntry(log, '9', "Could not open NetmailArea");
   } /* endif */
}

void processMsg(s_message *msg, s_addr pktOrigAddr)
{

   statToss.msgs++;
   if (msg->netMail == 1) {
	   if (stricmp(msg->toUserName,"areafix")==0) {
		   processAreaFix(msg, &pktOrigAddr);
	   } else
		   processNMMsg(msg,pktOrigAddr);
   } else {
	   processEMMsg(msg, pktOrigAddr);
   } /* endif */
}

int processPkt(char *fileName, e_tossSecurity sec)
{
   FILE        *pkt;
   s_pktHeader *header;
   s_message   *msg;
   s_link      *link;
   char        rc = 0;
   char        buff[256];
   char        processIt = 0; // processIt = 1, process all mails
                              // processIt = 2, process only Netmail
                              // processIt = 0, do not process pkt

   pkt = fopen(fileName, "rb");
   if (pkt == NULL) return 2;

   header = openPkt(pkt);
   if (header != NULL) {
      if (to_us(*header)==0) {
         sprintf(buff, "pkt: %s", fileName);
         writeLogEntry(log, '6', buff);
         statToss.pkts++;
         link = getLinkFromAddr(*config, header->origAddr);

         switch (sec) {
            case secLocalInbound:
               processIt = 1;
               break;
               
            case secProtInbound:
               if ((link != NULL) && ((link->pktPwd == NULL) || (stricmp(link->pktPwd, header->pktPassword) == 0))) {
                  processIt = 1;
               } else {
                  sprintf(buff, "pkt: %s Password Error or no link for %i:%i/%i.%i",
                          fileName, header->origAddr.zone, header->origAddr.net,
                          header->origAddr.node, header->origAddr.point);
                  writeLogEntry(log, '9', buff);
                  rc = 1;
               }
               break;
               
            case secInbound:
               if ((link != NULL) && ((link->pktPwd == NULL) || (stricmp(link->pktPwd, header->pktPassword) == 0))) {
                  processIt = 1;
               } else {
                  sprintf(buff, "pkt: %s No Link for %i:%i/%i.%i, processing only Netmail",
                          fileName, header->origAddr.zone, header->origAddr.net,
                          header->origAddr.node, header->origAddr.point);
                  writeLogEntry(log, '9', buff);
                  processIt = 2;
               }
               break;
         }

         if (processIt != 0) {
            while ((msg = readMsgFromPkt(pkt, header->origAddr.zone)) != NULL) {
               if (msg != NULL) {
                  if ((processIt = 1) || ((processIt==2) && (msg->netMail==1)))
                     processMsg(msg, header->origAddr);
                  freeMsgBuffers(msg);
               }
            }
         }
         
      }

      free(header);
      
   } else {
      sprintf(buff, "pkt: %s wrong pkt-file", fileName);
      writeLogEntry(log, '9', buff);
      rc = 3;
   }

   fclose(pkt);
   return rc;
}

/* int processPkt(char *fileName, e_tossSecurity sec)
{
   FILE        *pkt;
   s_pktHeader *header;
   s_message   *msg;
   char        buff[265];
   s_link      *link;
   char        pwdOK = !0;
   int         rc = 0;

   pkt = fopen(fileName, "rb");
   if (pkt == NULL) return 2;

   header = openPkt(pkt);
   if (header != NULL) {
      if (to_us(*header)==0){
         sprintf(buff, "pkt: %s", fileName);
         writeLogEntry(log, '6', buff);
	 statToss.pkts++;
         
         link = getLinkFromAddr(*config, header->origAddr);
         if (link != NULL) {
            // if passwords aren't the same don't process pkt
            // if pkt is from a System we don't have a link (incl. pwd) with
            // we process it.
            if ((link->pktPwd != NULL) && (stricmp(link->pktPwd, header->pktPassword) != 0)) pwdOK = 0;
            if (sec==secLocalInbound) pwdOK = !0; // localInbound pkts don´t need pwd
            if (pwdOK != 0) {
               while ((msg = readMsgFromPkt(pkt, header->origAddr.zone)) != NULL) {
                  rc = 4;
                  if ((sec==secProtInbound) || (msg->netMail == 1) || (pwdOK != 0))
                     processMsg(msg, header->origAddr);
                  else rc = 3;
                  freeMsgBuffers(msg);
                  if (rc==3) {
                     sprintf(buff, "pkt: %s mails found", fileName);
                     writeLogEntry(log, '1', buff);
                  }
               }
            }
            else {
               sprintf(buff, "pkt: %s Password Error for %i:%i/%i.%i",
                       fileName, header->origAddr.zone, header->origAddr.net,
                       header->origAddr.node, header->origAddr.point);
               writeLogEntry(log, '9', buff);
               rc = 1;
            } // pwdOk != 0
         } // link != NULL
         else {
            if (msg->netMail ==1) processMsg(msg, header->origAddr);
            sprintf(buff, "pkt: %s No Link for %i:%i/%i.%i, processing only Netmail",
                    fileName, header->origAddr.zone, header->origAddr.net,
                    header->origAddr.node, header->origAddr.point);
            writeLogEntry(log, '9', buff);
            rc = 1;
         }
      }
   } else {
      sprintf(buff, "pkt: %s wrong pkt-file", fileName);
      writeLogEntry(log, '9', buff);
      rc = 3;
   }

   fclose(pkt);
   return rc;
}
*/

void processDir(char *directory, e_tossSecurity sec)
{
   DIR            *dir;
   struct dirent  *file;
   char           *dummy;
   int            rc;

   if (directory==NULL) return;

   dir = opendir(directory);

   while ((file = readdir(dir)) != NULL) {
//      printf("testing %s\n", file->d_name);
      if ((patmat(file->d_name, "*.pkt") == 1) || (patmat(file->d_name, "*.PKT") == 1)) {
         dummy = (char *) malloc(strlen(directory)+strlen(file->d_name)+1);
         strcpy(dummy, directory);
         strcat(dummy, file->d_name);
         rc = processPkt(dummy, sec);

         switch (rc) {
            case 1:   // pktpwd problem
               changeFileSuffix(dummy, "sec");
               break;
            case 2:  // could not open pkt
               changeFileSuffix(dummy, "acs");
               break;
            case 3:  // not/wrong pkt
               changeFileSuffix(dummy, "bad");
               break;
            default:
               remove (dummy);
               break;
         }
         free(dummy);
      }
   }
   closedir(dir);
}

void writeTossStatsToLog() {
   char buff[100];

   writeLogEntry(log, '4', "Statistics:");
   sprintf(buff, "   pkt's: % 3d   msgs: % 5d   echoMail: % 5d   netmail: % 5d", statToss.pkts, statToss.msgs, statToss.echoMail, statToss.netMail);
   writeLogEntry(log, '4', buff); 
   sprintf(buff, "   saved: % 5d   passthrough: % 5d   exported: % 5d", statToss.saved, statToss.passthrough, statToss.exported);
   writeLogEntry(log, '4', buff);
   sprintf(buff, "   dupes: % 5d   bad: % 5d", statToss.dupes, statToss.bad);
   writeLogEntry(log, '4', buff);
}

void fillPackStatement(char *cmd, char *call, const char *archiv, const char *file) {
   char *start, *tmp, buff[256];

   tmp = strdup(call);
   
   // replace $a by archiv-filename
   start = strstr(tmp, "$a");
   *start = '%';
   *(start+1) = 's';
   sprintf(buff, tmp, archiv);

   // replace $f by fileName
   start = strstr(buff, "$f");
   *start = '%';
   *(start+1) = 's';
   sprintf(cmd, buff, file);

   free(tmp);
}

void arcmail() {
	int i;
	char cmd[256], logmsg[256], *pkt;
	int cmdexit;
	FILE *flo;
	
	for (i = 0 ; i < config->linkCount; i++) {
		
		// only create floFile if we have mail for this link
		if (config->links[i].pktFile != NULL) {
			// process if the link not busy, else do not create 12345678.?lo
			if (createOutboundFileName(&(config->links[i]), cvtFlavour2Prio(config->links[i].echoMailFlavour), FLOFILE) == 0) {
				flo = fopen(config->links[i].floFile, "a");
				if (config->links[i].packerDef != NULL)
					// there is a packer defined -> put packFile into flo
					fprintf(flo, "^%s\n", config->links[i].packFile);
				else {
					// there is no packer defined -> put pktFile into flo
					pkt = (char*) malloc(strlen(config->outbound)+1+12);
					config->links[i].pktFile += strlen(config->tempOutbound);
					strcpy(pkt, config->outbound);
					strcat(pkt, config->links[i].pktFile);
					config->links[i].pktFile -= strlen(config->tempOutbound);
					fprintf(flo, "^%s\n", pkt);
					sprintf(cmd,"mv %s %s",config->links[i].pktFile,config->outbound);
					cmdexit = system(cmd);
					free(pkt);
				}
				fclose(flo);
				free(config->links[i].floFile); config->links[i].floFile=NULL;
				
				// pack mail
				if (config->links[i].packerDef != NULL) {
					fillPackStatement(cmd,config->links[i].packerDef->call,config->links[i].packFile, config->links[i].pktFile);
					sprintf(logmsg,"Packing mail for %s",config->links[i].name);
					writeLogEntry(log, '7', logmsg);
					cmdexit = system(cmd);
					remove(config->links[i].pktFile);
				}
				remove(config->links[i].bsyFile);
				free(config->links[i].bsyFile); config->links[i].bsyFile=NULL;
			}
		}
		free(config->links[i].pktFile); config->links[i].pktFile=NULL;
		free(config->links[i].packFile); config->links[i].packFile=NULL;
	}
	return;
}

void toss()
{
   int i;
   FILE *f;

/*   createTempPktFileName(&config->links[0]);
   createTempPktFileName(&config->links[1]);
   printf("%s %s\n", config->links[0].pktFile, config->links[1].pktFile);
   printf("%s %s\n", config->links[0].packFile, config->links[1].packFile);
   exit(0);*/

   // load recoding tables if needed
   if (config->intab != NULL) getctab(&intab, config->intab);

   // set stats to 0
   memset(&statToss, sizeof(s_statToss), 0);
   writeLogEntry(log, '4', "Start tossing...");
   processDir(config->localInbound, secLocalInbound);
   processDir(config->protInbound, secProtInbound);
   arcmail();
   // only import Netmails from inboundDir
   processDir(config->inbound, secInbound);

   // write dupeFiles

   for (i = 0 ; i < config->echoAreaCount; i++) writeToDupeFile(&(config->echoAreas[i]));

   if (config->importlog != NULL) {
      // write importlog
      
      f = fopen(config->importlog, "a");
      if (f != NULL) {
         if (config->netMailArea.imported == 1) fprintf(f, "%s\n", config->netMailArea.areaName);
         for (i = 0; i < config->echoAreaCount; i++)
            if (config->echoAreas[i].imported == 1) fprintf(f, "%s\n", config->echoAreas[i].areaName);

         fclose(f);
      } else writeLogEntry(log, '5', "Could not open importlogfile");
   }

   // write statToss to Log
   writeTossStatsToLog();
}
