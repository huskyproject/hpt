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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>

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
int forwardPkt(const char *fileName, s_pktHeader *header, e_tossSecurity sec);
void processDir(char *directory, e_tossSecurity sec);

void changeFileSuffix(char *fileName, char *newSuffix) {

   int   i = 1;
   char  buff[200];

   char *beginOfSuffix = strrchr(fileName, '.')+1;
   char *newFileName;
   int  length = strlen(fileName)-strlen(beginOfSuffix)+strlen(newSuffix);

   newFileName = (char *) calloc(length+1+2, 1);
   strncpy(newFileName, fileName, length-strlen(newSuffix));
   strcat(newFileName, newSuffix);

#ifdef DEBUG_HPT
   printf("old: %s      new: %s\n", fileName, newFileName);
#endif

   while (fexist(newFileName) && (i<255)) {
      sprintf(buff, "%02x", i);
      beginOfSuffix = strrchr(newFileName, '.')+1;
      strncpy(beginOfSuffix+1, buff, 2);
      i++;
   }

   if (!fexist(newFileName))
      rename(fileName, newFileName);
   else {
      sprintf(buff, "Could not change suffix for %s. File already there and the 255 files after", fileName);
      writeLogEntry(log, '9', buff);
   }
}

int to_us(const s_addr destAddr)
{
   int i = 0;

   while (i < config->addrCount)
     if (addrComp(destAddr, config->addr[i++]) == 0)
       return 0;
   return !0;
}

XMSG createXMSG(s_message *msg, const s_pktHeader *header) {
	XMSG  msgHeader;
	struct tm *date;
	time_t    currentTime;
	union stamp_combo dosdate;
	int i,remapit;
	
	if (msg->netMail == 1) {
		// attributes of netmail must be fixed
		msgHeader.attr = msg->attributes;
		
		if (to_us(msg->destAddr)==0) {
			msgHeader.attr &= ~(MSGCRASH | MSGREAD | MSGSENT | MSGKILL | MSGLOCAL | MSGHOLD
			  | MSGFRQ | MSGSCANNED | MSGLOCKED | MSGFWD); // kill these flags
			msgHeader.attr |= MSGPRIVATE; // set this flags
		} else if (header!=NULL) msgHeader.attr |= MSGFWD; // set TRS flag, if the mail is not to us

      // Check if we must remap
      remapit=0;
      
      for (i=0;i<config->remapCount;i++)
          if ((config->remaps[i].toname==NULL ||
               stricmp(config->remaps[i].toname,msg->toUserName)==0) &&
              (config->remaps[i].oldaddr.zone==0 ||
               (config->remaps[i].oldaddr.zone==msg->destAddr.zone &&
                config->remaps[i].oldaddr.net==msg->destAddr.net &&
                config->remaps[i].oldaddr.node==msg->destAddr.node &&
                config->remaps[i].oldaddr.point==msg->destAddr.point) ) )
             {
             remapit=1;
             break;
             }

      if (remapit)
         {
         msg->destAddr.zone=config->remaps[i].newaddr.zone;              
         msg->destAddr.net=config->remaps[i].newaddr.net;
         msg->destAddr.node=config->remaps[i].newaddr.node;   
         msg->destAddr.point=config->remaps[i].newaddr.point;             
         }                                                               

   }
   else
     {
       msgHeader.attr = msg->attributes;
       msgHeader.attr &= ~(MSGCRASH | MSGREAD | MSGSENT | MSGKILL | MSGLOCAL | MSGHOLD | MSGFRQ | MSGSCANNED | MSGLOCKED); // kill these flags
     }
   
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
   memset(msgHeader.replies, 0, MAX_REPLY * sizeof(UMSGID));   // no replies
   strcpy((char *) msgHeader.__ftsc_date, msg->datetime);
   ASCII_Date_To_Binary(msg->datetime, (union stamp_combo *) &(msgHeader.date_written));

   currentTime = time(NULL);
   date = localtime(&currentTime);
   TmDate_to_DosDate(date, &dosdate);
   msgHeader.date_arrived = dosdate.msg_st;

   return msgHeader;
}

void putMsgInArea(s_area *echo, s_message *msg, int strip)
{
   char buff[70], *ctrlBuff, *textStart, *textWithoutArea;
   UINT textLength = (UINT) msg->textLength;
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

         ctrlBuff = (char *) CopyToControlBuf((UCHAR *) textWithoutArea,
				              (UCHAR **) &textStart,
				              &textLength);
         // textStart is a pointer to the first non-kludge line
         xmsg = createXMSG(msg, NULL);

         MsgWriteMsg(hmsg, 0, &xmsg, (byte *) textStart, (dword) strlen(textStart), (dword) strlen(textStart), (dword)strlen(ctrlBuff), (byte *)ctrlBuff);

         MsgCloseMsg(hmsg);
         free(ctrlBuff);

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
#ifdef DEBUG_HPT
   int i;
#endif

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

   token = strtok(seenByText, " \r\t\376");
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
      token = strtok(NULL, " \r\t\376");
   }

   //test output for reading of seenBys...
#ifdef DEBUG_HPT
   for (i=0; i < *seenByCount; i++) printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
#endif
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
#ifdef DEBUG_HPT
   int i;
#endif

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

   token = strtok(seenByText, " \r\t\376");
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
      token = strtok(NULL, " \r\t\376");
   }

   // test output for reading of paths...
#ifdef DEBUG_HPT
   for (i=0; i < *seenByCount; i++) printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
#endif
   //exit(2);

   free(seenByText);
}

int readCheck(s_area *echo, s_link *link) {

    // rc == '\x0000' access o'k
    // rc == '\x0001' no access group
    // rc == '\x0002' no access level
    // rc == '\x0003' no access export
    // rc == '\x0004' not linked
    
    int i;
    
    if (echo->group && echo->group != '\060') {
	if (link->AccessGrp) {
	    if (config->PublicGroup) {
		if (strchr(link->AccessGrp, echo->group) == NULL &&
		    strchr(config->PublicGroup, echo->group) == NULL) return 1;
	    } else if (strchr(link->AccessGrp, echo->group) == NULL) return 1;
	} else if (config->PublicGroup) {
		   if (strchr(config->PublicGroup, echo->group) == NULL) return 1;
	       } else return 1;
    }
    if (echo->levelread > link->level) return 2;
    for (i=0; i<echo->downlinkCount; i++) {
	if (link == echo->downlinks[i]->link) {
	    if (echo->downlinks[i]->export == 0) return 3;
	    break;
	}
    }
    if (i == echo->downlinkCount) return 4;
    return 0;
}

int writeCheck(s_area *echo, s_link *link) {

    // rc == '\x0000' access o'k
    // rc == '\x0001' no access group
    // rc == '\x0002' no access level
    // rc == '\x0003' no access import
    // rc == '\x0004' not linked

    int i;
    
    if (echo->group != '\060') {
	if (link->AccessGrp) {
	    if (config->PublicGroup) {
		if (strchr(link->AccessGrp, echo->group) == NULL &&
		    strchr(config->PublicGroup, echo->group) == NULL) return 1;
	    } else if (strchr(link->AccessGrp, echo->group) == NULL) return 1;
	} else if (config->PublicGroup) {
		   if (strchr(config->PublicGroup, echo->group) == NULL) return 1;
	       } else return 1;
    }
    if (echo->levelwrite > link->level) return 2;
    for (i=0; i<echo->downlinkCount; i++) {
	if (link == echo->downlinks[i]->link) {
	    if (echo->downlinks[i]->import == 0) return 3;
	    break;
	}
    }
    if (i == echo->downlinkCount) return 4;
    return 0;
}

/**
  * This function returns 0 if the link is not in seenBy else it returns 1.
  */

int checkLink(s_seenBy *seenBys, UINT seenByCount, s_link *link, s_addr pktOrigAddr)
{
   UINT i;

   if (addrComp(pktOrigAddr, link->hisAka) == 0) return 1;   // the link where we got the mail from
   
   if (link->hisAka.point != 0) return 0;                    // a point always gets the mail

   for (i=0; i < seenByCount; i++) {
      if ((link->hisAka.net == seenBys[i].net) && (link->hisAka.node == seenBys[i].node)) return 1;
   }

   return 0;
}

/**
  * This function puts all the links of the echoarea in the newLink array who does not have got the mail
  */

void createNewLinkArray(s_seenBy *seenBys, UINT seenByCount, s_area *echo, s_link ***newLinks, s_addr pktOrigAddr)
{
   UINT i, j=0;

   *newLinks = (s_link **) calloc(echo->downlinkCount, sizeof(s_link*));

   for (i=0; i < echo->downlinkCount; i++) {
      if (checkLink(seenBys, seenByCount, echo->downlinks[i]->link, pktOrigAddr)==0) {
         (*newLinks)[j] = echo->downlinks[i]->link;
         j++;
      }
   }
}

void forwardMsgToLinks(s_area *echo, s_message *msg, s_addr pktOrigAddr)
{
   s_seenBy *seenBys = NULL, *path = NULL;
   UINT     seenByCount, pathCount, i;
   char     *start, *c, *newMsgText, *seenByText = NULL, *pathText = NULL;

   FILE     *pkt;
   s_pktHeader header;
   s_link   **newLinks;  // links who does not have their aka in seenBys and thus have not got the echomail.

   createSeenByArrayFromMsg(msg, &seenBys, &seenByCount);
   createPathArrayFromMsg(msg, &path, &pathCount);

   createNewLinkArray(seenBys, seenByCount, echo, &newLinks, pktOrigAddr);

   // add seenBy for newLinks
   for (i=0; i<echo->downlinkCount; i++) {

      if (newLinks[i] == NULL) break;               // no link at this index -> break
      if (newLinks[i]->hisAka.point != 0) continue; // don't include points in SEEN-BYS

      seenBys = (s_seenBy*) realloc(seenBys, sizeof(s_seenBy) * (seenByCount)+1);
      seenBys[seenByCount].net = newLinks[i]->hisAka.net;
      seenBys[seenByCount].node = newLinks[i]->hisAka.node;
      seenByCount++;
   }

   sortSeenBys(seenBys, seenByCount);

#ifdef DEBUG_HPT
   for (i=0; i< seenByCount;i++) printf("%u/%u ", seenBys[i].net, seenBys[i].node);
#endif
   //exit(2);

   if (pathCount > 0) {
      if ((path[pathCount-1].net != echo->useAka->net) || (path[pathCount-1].node != echo->useAka->node)) {
         // add our aka to path
         path = (s_seenBy*) realloc(path, sizeof(s_seenBy) * (pathCount)+1);
         path[pathCount].net = echo->useAka->net;
         path[pathCount].node = echo->useAka->node;
         pathCount++;
      }
   } else {
      pathCount = 0;
      path = (s_seenBy*) malloc(sizeof(s_seenBy) * 1);
      path[pathCount].net = echo->useAka->net;
      path[pathCount].node = echo->useAka->node;
      pathCount = 1;
   }

#ifdef DEBUG_HPT
   for (i=0; i< pathCount;i++) printf("%u/%u ", path[i].net, path[i].node);
#endif
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

      if (newLinks[i] == NULL) break;           // no link at this index -> break;

      // does the link has read access for this echo?
      if (readCheck(echo, newLinks[i])!=0) continue;

      // create pktfile if necessary
      if (newLinks[i]->pktFile == NULL) {
         // pktFile does not exist
         if ( createTempPktFileName(newLinks[i]) ) {
            writeLogEntry(log, '9', "Could not create new pkt!\n");
            printf("Could not create new pkt!\n");
            exit(1);
         }
      } /* endif */

      makePktHeader(NULL, &header);
      header.origAddr = *(newLinks[i]->ourAka);
      header.destAddr = newLinks[i]->hisAka;
      if (newLinks[i]->pktPwd != NULL)
         strcpy(header.pktPassword, newLinks[i]->pktPwd);
      pkt = openPktForAppending(newLinks[i]->pktFile, &header);

      // an echomail msg must be adressed to the link
      msg->destAddr = header.destAddr;
      // .. and must come from us
      msg->origAddr = header.origAddr;
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
   char *fileName;
   char buff[255], myaddr[25], hisaddr[25];
   int i=0;
   s_link *creatingLink;
   s_addr *aka;

   //translating name of the area to lowercase, much better imho.
   while (*c_area != '\0') {
      *c_area=tolower(*c_area);
      if ((*c_area=='/') || (*c_area=='\\')) *c_area = '_'; // convert any path delimiters to _
      c_area++;
      i++;
   }

   while (i>0) {c_area--;i--;};

   creatingLink = getLinkFromAddr(*config, pktOrigAddr);

   fileName = creatingLink->autoCreateFile;
   if (fileName == NULL) fileName = getConfigFileName();

   f = fopen(fileName, "a");
   if (f == NULL) {
      f = fopen(getConfigFileName(), "a");
      if (f == NULL)
	 {
	    fprintf(stderr,"autocreate: cannot open config file\n");
	    return 1;
	 }
   }

   aka = creatingLink->ourAka;

   // making local address and address of uplink
   sprintf(myaddr, aka2str(*aka));
   sprintf(hisaddr, aka2str(pktOrigAddr));

   //write new line in config file
   if (stricmp(config->msgBaseDir, "passthrough")!=0) {
#ifndef MSDOS
	   sprintf(buff, "EchoArea %s %s%s -a %s Squish ", c_area, config->msgBaseDir, c_area, myaddr);
#else
	   sleep(1); // to prevent time from creating equal numbers
	   sprintf(buff,"EchoArea %s %s%8lx -a %s Squish ", c_area, config->msgBaseDir, time(NULL), myaddr);
#endif
   } else
	   sprintf(buff, "EchoArea %s Passthrough -a %s ", c_area, myaddr);
   if ((creatingLink->autoCreateDefaults != NULL) &&
       (strlen(buff)+strlen(creatingLink->autoCreateDefaults))<255) {
	   strcat(buff, creatingLink->autoCreateDefaults);
   }
   sprintf(buff+strlen(buff), " %s", hisaddr);
   if (creatingLink->export)
       if (*creatingLink->export == 0) strcat(buff, " -w");
   if (creatingLink->import)
       if (*creatingLink->import == 0) strcat(buff, " -r");
   if (creatingLink->mandatory)
       if (*creatingLink->mandatory == 1) strcat(buff, " -m");
   fprintf(f, "%s\n", buff);
//   fprintf(f, "\n");
   
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
                        if (stricmp(msg->toUserName, config->carbons[i].str)==0) {
                                putMsgInArea(area,msg,0);
                                return 0;
                        }
                        break;
                case 1:
                        if (stricmp(msg->fromUserName, config->carbons[i].str)==0) {
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
   char   *tmp, *area, *textBuff;
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

   if (echo == &(config->badArea)) writeAccess = 0;
   else writeAccess = writeCheck(echo, link);
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
         if (echo->dupeCheck == dcMove) {
            putMsgInArea(&(config->dupeArea), msg, 0);
         }
         statToss.dupes++;
      }
   }

   if (echo == &(config->badArea)) {
      if (config->carbonCount != 0) carbonCopy(msg, echo);
      // checking for autocreate option
      link = getLinkFromAddr(*config, pktOrigAddr);
      if ((link != NULL) && (link->autoAreaCreate != 0) && (writeAccess == 0)) {
         autoCreate(area, pktOrigAddr);
         echo = getArea(config, area);
         if (echo->msgbType != MSGTYPE_PASSTHROUGH)
            putMsgInArea(echo, msg, 1);
         if (echo->downlinkCount > 1) {   // if only one downlink, we've got the mail from him
            forwardMsgToLinks(echo, msg, pktOrigAddr);
            statToss.exported++;
         }

      } else {
         // no autoareaCreate -> msg to bad
         statToss.bad++;
	 
	 tmp = msg->text;
	 
	 while ((area = strchr(tmp, '\r'))) {
	     if (*(area+1) == '\x01') tmp = area+1;
	     else { tmp = area+1; break; }
	 }
	 
	 memset(textBuff, 0, tmp+1-msg->text);
	 
	 strncpy(textBuff, msg->text, tmp-msg->text);
	 
	 sprintf(textBuff+strlen(textBuff), "FROM: %u:%u/%u.%u\rREASON: ",
	                                    pktOrigAddr.zone,
	                                    pktOrigAddr.net,
					    pktOrigAddr.node,
					    pktOrigAddr.point);
	 switch (writeAccess) {
	     case 0: strcat(textBuff, "System not allowed to create new area\r");
	         break;
	     case 1: strcat(textBuff, "Sender not active for this area\r");
	         break; 
	     case 2: strcat(textBuff, "Sender not allowed to post in this area\r");
	         break;
	     case 3: strcat(textBuff, "Sender not allowed to post in this area\r");
	         break;
	     case 4: strcat(textBuff, "Sender not active for this area\r");
	         break;
	     default : strcat(textBuff, "Another error\r");
	         break;
	 }							
	 textBuff = (char*)realloc(textBuff, strlen(textBuff)+strlen(tmp)+1);
	 strcat(textBuff, tmp);
	 tmp = msg->text;
	 msg->text = textBuff;
	 textBuff = tmp;
         putMsgInArea(&(config->badArea), msg, 0);
      }
   }


   free(textBuff);
}

void processNMMsg(s_message *msg,s_pktHeader *pktHeader)
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

         msgHeader = createXMSG(msg, pktHeader);
//	   	 if ((msg->attributes & MSGKILL) == MSGKILL) msgHeader.attr |= MSGKILL;
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

void processMsg(s_message *msg, s_pktHeader *pktHeader)
{

	statToss.msgs++;
	if (msg->netMail == 1) {
		if (config->areafixFromPkt && 
			(stricmp(msg->toUserName,"areafix")==0 ||
			 stricmp(msg->toUserName,"areamgr")==0 ||
			 stricmp(msg->toUserName,"hpt")==0)) {
			processAreaFix(msg, pktHeader);
		} else
			processNMMsg(msg, pktHeader);
	} else {
		processEMMsg(msg, pktHeader->origAddr);
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
   struct stat statBuff;
   char        processIt = 0; // processIt = 1, process all mails
                              // processIt = 2, process only Netmail
                              // processIt = 0, do not process pkt

   if (stat(fileName, &statBuff) == 0) statToss.inBytes += statBuff.st_size;

   pkt = fopen(fileName, "rb");
   if (pkt == NULL) return 2;

   header = openPkt(pkt);
   if (header != NULL) {
      if (to_us(header->destAddr)==0) {
         sprintf(buff, "pkt: %s", fileName);
         writeLogEntry(log, '6', buff);
         statToss.pkts++;
         link = getLinkFromAddr(*config, header->origAddr);
	 if ((link!=NULL) && (link->pktPwd==NULL) && (header->pktPassword[0]!='\000'))
	 {
		 sprintf(buff, "Unexpected Password %s.", header->pktPassword);
		 writeLogEntry(log, '3', buff);
	 }

         switch (sec) {
            case secLocalInbound:
               processIt = 1;
               break;

            case secProtInbound:
				if ((link != NULL) && (link->pktPwd != NULL) && (stricmp(link->pktPwd, header->pktPassword)==0) ) processIt = 1;
				else if ((link != NULL) && (link->pktPwd==NULL)) processIt=1;
				else if (link == NULL) {	
					sprintf(buff, "pkt: %s No Link for %i:%i/%i.%i, processing only Netmail",
							fileName, header->origAddr.zone, header->origAddr.net,
							header->origAddr.node, header->origAddr.point);
					writeLogEntry(log, '9', buff);
					processIt = 2;
				} else {
					sprintf(buff, "pkt: %s Password Error or no link for %i:%i/%i.%i",
                          fileName, header->origAddr.zone, header->origAddr.net,
                          header->origAddr.node, header->origAddr.point);
                  writeLogEntry(log, '9', buff);
                  rc = 1;
               }
               break;

		 case secInbound:
			 if ((link != NULL) && (link->pktPwd != NULL) && (stricmp(link->pktPwd, header->pktPassword)==0) ) processIt = 1;
			 else if ((link != NULL) && (link->pktPwd==NULL)) processIt=1;
			 else if (link == NULL) {
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
                  if ((processIt == 1) || ((processIt==2) && (msg->netMail==1)))
                     processMsg(msg, header);
                  freeMsgBuffers(msg);
                  free(msg);
               }
            }
         }

      } else {
	
	  /* PKT is not for us - try to forward it to our links */

	  fclose(pkt); pkt = NULL;
	  rc = forwardPkt(fileName, header, sec);

      }
	      
      free(header);

   } else {
      sprintf(buff, "pkt: %s wrong pkt-file", fileName);
      writeLogEntry(log, '9', buff);
      rc = 3;
   }

   if (pkt != NULL) {
       fclose(pkt);
   }
   return rc;
}

void fillCmdStatement(char *cmd, const char *call, const char *archiv, const char *file, const char *path) {
   const char *start, *tmp, *add;

   *cmd = '\0';  start = NULL;
   for (tmp = call; (start = strchr(tmp, '$')) != NULL; tmp = start + 2) {
      switch(*(start + 1)) {
         case 'a': add = archiv; break;
         case 'p': add = path; break;
         case 'f': add = file; break;
         default:
            strncat(cmd, tmp, (size_t) (start - tmp + 1));
            start--; continue;
      };
      strncat(cmd, tmp, (size_t) (start - tmp));
      strcat(cmd, add);
   };
   strcat(cmd, tmp);
}

int  processArc(char *fileName, e_tossSecurity sec)
{
   int  i, j, found, cmdexit;
   FILE  *bundle;
   char buff[256];
   char cmd[256];

   if (sec == secInbound) {
      sprintf(buff, "bundle %s: tossing in unsecure inbound, security violation", fileName);
      writeLogEntry(log, '6', buff);
      return 3;
   };

   // find what unpacker to use
   for (i = 0, found = 0; (i < config->unpackCount) && !found; i++) {
      bundle = fopen(fileName, "rb");
      if (bundle == NULL) return 2;
      // is offset is negative we look at the end
      fseek(bundle, config->unpack[i].offset, config->unpack[i].offset >= 0 ? SEEK_SET : SEEK_END);
      if (ferror(bundle)) { fclose(bundle); continue; };
      for (found = 1, j = 0; j < config->unpack[i].codeSize; j++) {
         if ((getc(bundle) & config->unpack[i].mask[j]) != config->unpack[i].matchCode[j])
            found = 0;
      }
      fclose(bundle);
   }

   // unpack bundle
   if (found) {
#ifdef UNIX
      fillCmdStatement(cmd, config->unpack[i-1].call, fileName, "\\*.pkt", config->tempInbound);
#else
      fillCmdStatement(cmd, config->unpack[i-1].call, fileName, "*.pkt", config->tempInbound);
#endif
      sprintf(buff, "bundle %s: unpacking with \"%s\"", fileName, cmd);
      writeLogEntry(log, '6', buff);
      if ((cmdexit = system(cmd)) != 0) {
         sprintf(buff, "exec failed, code %d", cmdexit);
         writeLogEntry(log, '6', buff);
         return 3;
      };
   } else {
      sprintf(buff, "bundle %s: cannot find unpacker", fileName);
      writeLogEntry(log, '6', buff);
      return 3;
   };
   processDir(config->tempInbound, sec);
   return 0;
}

char *validExt[] = {"*.MO?", "*.TU?", "*.TH?", "*.WE?", "*.FR?", "*.SA?", "*.SU?"};

void processDir(char *directory, e_tossSecurity sec)
{
   DIR            *dir;
   struct dirent  *file;
   char           *dummy;
   int            rc, i;
   int            pktFile,
                  arcFile;


   if (directory==NULL) return;

   dir = opendir(directory);

   while ((file = readdir(dir)) != NULL) {
#ifdef DEBUG_HPT
      printf("testing %s\n", file->d_name);
#endif

      arcFile = pktFile = 0;

      dummy = (char *) malloc(strlen(directory)+strlen(file->d_name)+1);
      strcpy(dummy, directory);
      strcat(dummy, file->d_name);

      if (!(pktFile = patimat(file->d_name, "*.pkt") == 1)) 
         for (i = 0; i < sizeof(validExt) / sizeof(char *); i++)
            if (patimat(file->d_name, validExt[i]) == 1)
               arcFile = 1;

      if (pktFile || arcFile) {

         if (pktFile)
            rc = processPkt(dummy, sec);
         else if (arcFile)
            rc = processArc(dummy, sec);

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
            case 4:  // not to us
               changeFileSuffix(dummy, "ntu");
	       break;
            default:
               remove (dummy);
               break;
         }
      };
      free(dummy);
   }
   closedir(dir);
}

void writeTossStatsToLog(void) {
   char buff[100];
   float inMailsec, outMailsec, inKBsec;
   time_t diff = time(NULL) - statToss.startTossing;
   char logchar;

   if (statToss.pkts==0 && statToss.msgs==0)
      logchar='1';
     else
      logchar='4';

   if (diff == 0) diff = 1;

   inMailsec = ((float)(statToss.msgs)) / diff;
   outMailsec = ((float)(statToss.exported)) / diff;
   inKBsec = ((float)(statToss.inBytes)) / diff / 1024;

   writeLogEntry(log, logchar, "Statistics:");
   sprintf(buff, "   pkt's: % 3d   msgs: % 5d   echoMail: % 5d   netmail: % 5d", statToss.pkts, statToss.msgs, statToss.echoMail, statToss.netMail);
   writeLogEntry(log, logchar, buff);
   sprintf(buff, "   saved: % 5d   passthrough: % 5d   exported: % 5d", statToss.saved, statToss.passthrough, statToss.exported);
   writeLogEntry(log, logchar, buff);
   sprintf(buff, "   dupes: % 5d   bad: % 5d", statToss.dupes, statToss.bad);
   writeLogEntry(log, logchar, buff);
   sprintf(buff, "   Input: % 8.2f mails/sec   Output: % 8.2f mails/sec", inMailsec, outMailsec);
   writeLogEntry(log, logchar, buff);
   sprintf(buff, "          % 8.2f kb/sec", inKBsec);
   writeLogEntry(log, logchar, buff);
}

void arcmail() {
        int i;
        char logmsg[256], cmd[256], *pkt, *lastPathDelim, saveChar;
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
                                        pkt = (char*) malloc(strlen(config->links[i].floFile)+1);
                                        lastPathDelim = strrchr(config->links[i].floFile, PATH_DELIM);

                                        // change path of file to path of flofile
                                        saveChar = *(++lastPathDelim);
                                        *lastPathDelim = '\0';
                                        strcpy(pkt, config->links[i].floFile);
                                        *lastPathDelim = saveChar;

                                        config->links[i].pktFile += strlen(config->tempOutbound);
                                        strcat(pkt, config->links[i].pktFile);
                                        config->links[i].pktFile -= strlen(config->tempOutbound);
                                        
                                        fprintf(flo, "^%s\n", pkt);
                                        rename(config->links[i].pktFile, pkt);
                                        free(pkt);
                                                                      
                                }
                                fclose(flo);
                                free(config->links[i].floFile); config->links[i].floFile=NULL;

                                // pack mail
                                if (config->links[i].packerDef != NULL) {
                                        fillCmdStatement(cmd,config->links[i].packerDef->call,config->links[i].packFile, config->links[i].pktFile, "");
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

static int forwardedPkts = 0;

int forwardPkt(const char *fileName, s_pktHeader *header, e_tossSecurity sec)
{
    int i;
    char logmsg[512];
//    int cmdexit;
    s_link *link;
    char *newfn;
//    char zoneSuffix[4];
//    char *zoneOutbound;
    
    for (i = 0 ; i < config->linkCount; i++) {
	if (addrComp(header->destAddr, config->links[i].hisAka) == 0) {
	    /* we found a link to forward the pkt file to */
	    
	    link = config->links+i;
			
	    /* security checks */
			
	    if (link->forwardPkts==fOff) return 4;
		if ((link->forwardPkts==fSecure)&&(sec != secProtInbound)&&(sec != secLocalInbound)) return 4;
	    
            /* as we have feature freeze currently, */
	    /* I enclose the following code with an ifdef ... */

	    newfn = makeUniqueDosFileName(config->tempOutbound, "pkt", config);

	    if (move_file(fileName, newfn) == 0) {  /* move successful ! */
		    
		sprintf(logmsg,"Forwarding %s to %s as %s",
		        fileName, config->links[i].name, newfn + strlen(config->tempOutbound));
		writeLogEntry(log, '7', logmsg);

		free(newfn);
		forwardedPkts = 1;
		return 0;
	    }
	    else
	    {
		sprintf (logmsg, "Failure moving %s to %s (%s)", fileName,
			 newfn, strerror(errno));
		writeLogEntry (log, '9', logmsg);
		free(newfn);
		return 4;
	    }

	}
    }
    
    return 4;       /* PKT is not for us and we did not find a link to
		       forward the pkt file to */
}


/* According to the specs, a .QQQ file does not have two leading
   zeros. This routine checks if the file is a .QQQ file, and if so,
   it appends the zeros and renames the file to .PKT. */
   

void fix_qqq(char *filename)
{
	FILE *f;
	char buffer[2] = { '\0', '\0' };
	size_t l = strlen(filename);
	char *newname=NULL;

	if (l > 3 && newname != NULL && toupper(filename[l-1]) == 'Q' &&
	    toupper(filename[l-2]) == 'Q' && toupper(filename[l-3]) == 'Q')
	{
		newname = strdup(filename);

	        strcpy(newname + l - 3, "pkt");
                if (rename(newname, filename) == 0)
		{
			strcpy(filename, newname);

			if ((f = fopen(filename, "ab")) != NULL)
			{
				fwrite(buffer, 2, 1, f);
				fclose(f);
			}
		}
		free(newname);
	}
}


void tossTempOutbound(char *directory)
{
   DIR            *dir;
   FILE           *pkt;
   struct dirent  *file;
   char           *dummy;
   s_pktHeader    *header;
   s_link         *link;
   size_t         l;

   if (directory==NULL) return;

   dir = opendir(directory);

   while ((file = readdir(dir)) != NULL) {
	   l = strlen(file->d_name);
	   if (l > 3 && (stricmp(file->d_name + l - 3, "pkt") == 0 ||
	                 stricmp(file->d_name + l - 3, "qqq") == 0))
	   {
                   dummy = (char *) malloc(strlen(directory)+l+1);
                   strcpy(dummy, directory);
                   strcat(dummy, file->d_name);

		   fix_qqq(dummy);

                   pkt = fopen(dummy, "rb");

                   header = openPkt(pkt);
                   link = getLinkFromAddr (*config, header->destAddr);

		   if (link != NULL) {

			   createTempPktFileName(link);

			   free(link->pktFile);
			   link->pktFile = dummy;

			   fclose(pkt);
			   arcmail();
		   } else {
			   writeLogEntry(log, '9', "found non packed mail without matching link in tempOutbound");
			   fclose(pkt);
		   }
           }
   }

   closedir(dir);
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
   exit(0);
*/

   // load recoding tables if needed
   if (config->intab != NULL) getctab(intab, config->intab);

   // set stats to 0
   memset(&statToss, 0, sizeof(s_statToss));
   statToss.startTossing = time(NULL);
   writeLogEntry(log, '1', "Start tossing...");
   processDir(config->localInbound, secLocalInbound);
   processDir(config->protInbound, secProtInbound);
   processDir(config->inbound, secInbound);
   arcmail();

   // write dupeFiles

   for (i = 0 ; i < config->echoAreaCount; i++) {
      writeToDupeFile(&(config->echoAreas[i]));
      freeDupeMemory(&(config->echoAreas[i]));
   }

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

   if (forwardedPkts) {
	   tossTempOutbound(config->tempOutbound);
	   forwardedPkts = 0;
   }

   // write statToss to Log
   writeTossStatsToLog();
}
