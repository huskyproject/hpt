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

#ifdef __EMX__
#include <sys/types.h>
#ifndef _A_HIDDEN
#define _A_HIDDEN A_HIDDEN
#endif
#endif

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
#include <version.h>
#include <scanarea.h>

#include <msgapi.h>
#include <stamp.h>
#include <typedefs.h>
#include <compiler.h>
#include <progprot.h>

#ifdef __WATCOMC__
#include <dos.h>
#endif

extern s_message **msgToSysop;

s_statToss statToss;
int forwardPkt(const char *fileName, s_pktHeader *header, e_tossSecurity sec);
void processDir(char *directory, e_tossSecurity sec);
void makeMsgToSysop(char *areaName, s_addr fromAddr);

/*
 * Find the first occurrence of find in s ignoring case
 */
char *stristr(char *str, char *find)
{
	char ch, sc, *str1, *find1;

	find++;
	if ((ch = *(find-1)) != 0) {
		do {
			do {
				str++;
				if ((sc = *(str-1)) == 0) return (NULL);
			} while (tolower((unsigned char) sc) != tolower((unsigned char) ch));
			
			for(str1=str,find1=find; *find1 && *str1 && tolower(*find1)==tolower(*str1); str1++,find1++);
			
		} while (*find1);
		str--;
	}
	return ((char *)str);
}

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
   else 
      writeLogEntry(hpt_log, '9', "Could not change suffix for %s. File already there and the 255 files after", fileName);
   
}

int to_us(const s_addr destAddr)
{
   int i = 0;

   while (i < config->addrCount)
     if (addrComp(destAddr, config->addr[i++]) == 0)
       return 0;
   return !0;
}

XMSG createXMSG(s_message *msg, const s_pktHeader *header, UINT16 forceattr) {
	XMSG  msgHeader;
	struct tm *date;
	time_t    currentTime;
	union stamp_combo dosdate;
	int i,remapit;
        char *subject;
	
	if (msg->netMail == 1) {
		// attributes of netmail must be fixed
		msgHeader.attr = msg->attributes;
		
		if (to_us(msg->destAddr)==0) {
			msgHeader.attr &= ~(MSGCRASH | MSGREAD | MSGSENT | MSGKILL | MSGLOCAL | MSGHOLD
			  | MSGFRQ | MSGSCANNED | MSGLOCKED | MSGFWD); // kill these flags
			msgHeader.attr |= MSGPRIVATE; // set this flags
		} else	if (header!=NULL) {
			    msgHeader.attr |= MSGFWD; // set TRS flag, if the mail is not to us
			    msgHeader.attr &= ~MSGSENT; // and clear SENT flag
			}

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

   /* FORCED ATTRIBUTES !!! */
   msgHeader.attr |= forceattr;
   
   strcpy((char *) msgHeader.from,msg->fromUserName);
   strcpy((char *) msgHeader.to, msg->toUserName);
   subject=msg->subjectLine;
   if (((msgHeader.attr & MSGFILE) == MSGFILE) && (msg->netMail==1)) {
     int size=strlen(msg->subjectLine)+strlen(config->protInbound)+1;
     if (size < XMSG_SUBJ_SIZE) {
       subject = (char *) malloc (size);
       sprintf (subject,"%s%s",config->protInbound,msg->subjectLine);
     }
   }
   strcpy((char *) msgHeader.subj,subject);
   if (subject != msg->subjectLine)
     free(subject);
       
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

int putMsgInArea(s_area *echo, s_message *msg, int strip, UINT16 forceattr)
{
   char *ctrlBuff, *textStart, *textWithoutArea;
   UINT textLength = (UINT) msg->textLength;
   HAREA harea;
   HMSG  hmsg;
   XMSG  xmsg;
   char *slash;
   int rc = 0;

   // create Directory Tree if necessary
   if (echo->msgbType == MSGTYPE_SDM)
      createDirectoryTree(echo->fileName);
   else {
      // squish or jam area
      slash = strrchr(echo->fileName, PATH_DELIM);
      *slash = '\0';
      createDirectoryTree(echo->fileName);
      *slash = PATH_DELIM;
   }
   
   msg->destAddr.zone  = echo->useAka->zone;
   msg->destAddr.net   = echo->useAka->net;
   msg->destAddr.node  = echo->useAka->node;
   msg->destAddr.point = echo->useAka->point;

   harea = MsgOpenArea((UCHAR *) echo->fileName, MSGAREA_CRIFNEC, 
/*							  echo->fperm, echo->uid, echo->gid,*/
							  echo->msgbType | MSGTYPE_ECHO);
   if (harea != NULL) {
      hmsg = MsgOpenMsg(harea, MOPEN_CREATE, 0);
      if (hmsg != NULL) {

         // recode from TransportCharset to internal Charset
         if (config->intab != NULL) {
            if ((msg->recode & REC_HDR)==0) {
		recodeToInternalCharset((CHAR*)msg->fromUserName);
                recodeToInternalCharset((CHAR*)msg->toUserName);
                recodeToInternalCharset((CHAR*)msg->subjectLine);
	        msg->recode |= REC_HDR;
            }
	    if ((msg->recode & REC_TXT)==0) {
		recodeToInternalCharset((CHAR*)msg->text);
		msg->recode |= REC_TXT;
	    }
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
         xmsg = createXMSG(msg, NULL, forceattr);

         MsgWriteMsg(hmsg, 0, &xmsg, (byte *) textStart, (dword) strlen(textStart), (dword) strlen(textStart), (dword)strlen(ctrlBuff), (byte *)ctrlBuff);

         MsgCloseMsg(hmsg);
         free(ctrlBuff);
	 rc = 1;

      } else 
         writeLogEntry(hpt_log, '9', "Could not create new msg in %s!", echo->fileName);
      /* endif */
      MsgCloseArea(harea);
   } else 
      writeLogEntry(hpt_log, '9', "Could not open/create EchoArea %s!", echo->fileName);
   /* endif */
   return rc;
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

    for (i=0; i<echo->downlinkCount; i++) {
	if (link == echo->downlinks[i]->link) break;
    }
    if (i == echo->downlinkCount) return 4;

    // pause
    if (link->Pause) return 3;

// Do not check groups here, too much checking, use groups only for areafix
//    if (echo->group && echo->group != '\060') {
//	if (link->AccessGrp) {
//	    if (config->PublicGroup) {
//		if (strchr(link->AccessGrp, echo->group) == NULL &&
//		    strchr(config->PublicGroup, echo->group) == NULL) return 1;
//	    } else if (strchr(link->AccessGrp, echo->group) == NULL) return 1;
//	} else if (config->PublicGroup) {
//		   if (strchr(config->PublicGroup, echo->group) == NULL) return 1;
//	       } else return 1;
//    }
    
    if (echo->levelread > link->level) return 2;
    
    if (i < echo->downlinkCount) {
	if (echo->downlinks[i]->export == 0) return 3;
    }
    
    return 0;
}

int writeCheck(s_area *echo, s_addr *aka) {

    // rc == '\x0000' access o'k
    // rc == '\x0001' no access group
    // rc == '\x0002' no access level
    // rc == '\x0003' no access import
    // rc == '\x0004' not linked

    int i;

    s_link *link;
    
    if (!addrComp(*aka,*echo->useAka)) return 0;
    
    link = getLinkFromAddr (*config,*aka);
    if (link == NULL) return 4;
    
    for (i=0; i<echo->downlinkCount; i++) {
	if (link == echo->downlinks[i]->link) break;
    }
    if (i == echo->downlinkCount) return 4;
    
// Do not check groups here, too much checking, use groups only for areafix
//    if (echo->group != '\060') {
//	if (link->AccessGrp) {
//	    if (config->PublicGroup) {
//		if (strchr(link->AccessGrp, echo->group) == NULL &&
//		    strchr(config->PublicGroup, echo->group) == NULL) return 1;
//	    } else if (strchr(link->AccessGrp, echo->group) == NULL) return 1;
//	} else if (config->PublicGroup) {
//		   if (strchr(config->PublicGroup, echo->group) == NULL) return 1;
//	       } else return 1;
//    }
    
    if (echo->levelwrite > link->level) return 2;
    
    if (i < echo->downlinkCount) {
	if (echo->downlinks[i]->import == 0) return 3;
    }
    
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

      seenBys = (s_seenBy*) realloc(seenBys, sizeof(s_seenBy) * (seenByCount+1));
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
         path = (s_seenBy*) realloc(path, sizeof(s_seenBy) * (pathCount+1));
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
            writeLogEntry(hpt_log, '9', "Could not create new pkt!\n");
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

int autoCreate(char *c_area, s_addr pktOrigAddr, s_addr *forwardAddr)
{
   FILE *f;
   char *fileName, *squishFileName, *acDef;
   char buff[255], myaddr[25], hisaddr[25];
   char *msgbtype;
   s_link *creatingLink;
   s_addr *aka;
   char *description=NULL, *newAutoCreate=NULL;

   squishFileName = (char *) malloc(strlen(c_area)+1);
   strcpy(squishFileName, c_area);
   
   fileName = squishFileName;

   //translating name of the area to lowercase, much better imho.
   while (*fileName != '\0') {
      *fileName=tolower(*fileName);
      if ((*fileName=='/') || (*fileName=='\\')) *fileName = '_'; // convert any path delimiters to _
      fileName++;
   }

   creatingLink = getLinkFromAddr(*config, pktOrigAddr);

   if (creatingLink == NULL) {
      writeLogEntry(hpt_log, '!', "creatingLink == NULL !!!");
      return 1;
   }

   acDef = creatingLink->autoAreaCreateDefaults;
   newAutoCreate = (char *) calloc((acDef) ? strlen(acDef)+1 : 1, sizeof(char));
   if (acDef) strcpy (newAutoCreate, acDef);
   
   fileName = creatingLink->autoAreaCreateFile;
   if (fileName == NULL) fileName = getConfigFileName();

   f = fopen(fileName, "a");
   if (f == NULL) {
	   fprintf(stderr,"autocreate: cannot open config file\n");
	   return 1;
   }

   aka = creatingLink->ourAka;

   // making local address and address of uplink
   sprintf(myaddr, aka2str(*aka));
   sprintf(hisaddr, aka2str(pktOrigAddr));

   //write new line in config file
   msgbtype = stristr(newAutoCreate, "-b ");

   if (stricmp(config->msgBaseDir, "passthrough")!=0) {
#ifndef MSDOS
   if ((fileName=stristr(newAutoCreate, "-dosfile "))==NULL)
     sprintf(buff, "EchoArea %s %s%s -a %s%s", c_area,
			 config->msgBaseDir, squishFileName, myaddr,
			 (msgbtype) ? "" : " -b Squish");
   else {
     sleep(1); // to prevent time from creating equal numbers
     sprintf(buff,"EchoArea %s %s%8lx -a %s%s", c_area,
			 config->msgBaseDir, time(NULL), myaddr,
			 (msgbtype) ? "" : " -b Squish");
   }
#else
	   sleep(1); // to prevent time from creating equal numbers
	   sprintf(buff,"EchoArea %s %s%8lx -a %s%s", c_area,
			   config->msgBaseDir, time(NULL), myaddr,
			   (msgbtype) ? "" : " -b Squish");
#endif
   } else
	   sprintf(buff, "EchoArea %s Passthrough -a %s", c_area, myaddr);
           
   if (creatingLink->forwardRequestFile!=NULL) {
     FILE *fforw;
     
     if ((fforw=fopen(creatingLink->forwardRequestFile,"r")) == NULL) {
       fprintf(stderr,"areafix: cannot open forwardRequestFile \"%s\"\n",creatingLink->forwardRequestFile);
     }
     else {
       char *line, *copy = NULL;
       int out=0;
       
       while ((line = readLine(fforw))) {
         line = trimLine(line);
	 copy = (char*)calloc(strlen(line)+1, sizeof(char));
	 strcpy(copy, line);
	 if (*line) {
	     description=strtok(line," \t");
	     if (patimat(description,c_area)==1) {
	         out=1;
		 break;
	     }
	 }
	 free(copy);
	 free(line);
       }
       if (out) {
         if (((description=strtok(NULL," \t"))!=NULL) && (description=strstr(copy,description))!=NULL) {
           fileName=NULL;
           if ((fileName=stristr(newAutoCreate, "-d "))==NULL) {
               char *tmp;
               tmp=(char *) calloc (strlen(newAutoCreate)+strlen(description)+7,sizeof(char));
               sprintf (tmp,"%s -d \"%s\"",newAutoCreate,description);
               free(newAutoCreate);
               newAutoCreate=tmp;
           }
           else {
             char *tmp;
             
             tmp=(char *) calloc (strlen(newAutoCreate)+strlen(description)+7,sizeof(char));
             fileName[0]='\0';
             sprintf (tmp,"%s-d \"%s\"",newAutoCreate,description);
             fileName++;
             fileName=strrchr(fileName,'\"')+1;
             strcat(tmp,fileName);
             free (newAutoCreate);
             newAutoCreate=tmp;
           }  
         }
	 free(line);
	 free(copy);
       }
       fclose(fforw);
     }
   }

   if ((newAutoCreate != NULL) &&
       (strlen(buff)+strlen(newAutoCreate))<255) {
           if ((fileName=stristr(newAutoCreate, "-g")) == NULL) {
	       if (creatingLink->LinkGrp) {
	           sprintf(buff+strlen(buff), " -g %c", *(creatingLink->LinkGrp));
	       }
	   }
	   sprintf(buff+strlen(buff), " %s", newAutoCreate);
   } else if (creatingLink->LinkGrp)
	       sprintf(buff+strlen(buff), " -g %c", *(creatingLink->LinkGrp));

   free(newAutoCreate);

   sprintf(buff+strlen(buff), " %s", hisaddr);
   
   fprintf(f, "%s\n", buff);
   
   fclose(f);
   
   // add new created echo to config in memory
   parseLine(buff,config);

   writeLogEntry(hpt_log, '8', "Area '%s' autocreated by %s", c_area, hisaddr);
   
   if (forwardAddr == NULL) makeMsgToSysop(c_area, pktOrigAddr);
   else makeMsgToSysop(c_area, *forwardAddr);
   
   free(squishFileName);
   
   return 0;
}

int processExternal (s_area *echo, s_message *msg,s_carbon carbon) { 
	FILE *msgfp;
	char *fname = NULL;
	char *progname, *execstr, *p;
	int  rc;

	progname = carbon.areaName;
#ifdef HAS_POPEN	
	if (*progname == '|') {
		msgfp = popen(progname + 1, "w");
	} else
#endif
	{
		fname = tmpnam(NULL);
		msgfp = fopen(fname, "wt");
	};
	
	if (!msgfp) {
		writeLogEntry(hpt_log, '9', "external process %s: cannot create file", progname);
		return 1;
	};
	/* Output header info */
	if (!msg->netMail) fprintf(msgfp, "Area: %s\n", echo->areaName);
	fprintf(msgfp, "From: \"%s\" %s\n", msg->fromUserName, aka2str(msg->origAddr));
	fprintf(msgfp, "To:   \"%s\" %s\n", msg->toUserName, aka2str(msg->destAddr));
	fprintf(msgfp, "Date: \"%s\"\n", msg->datetime);
	/* Output msg text */
	for (p = msg->text; *p ; p++) 
		if (*p == '\r') 
			fputc('\n', msgfp);
		else
			fputc(*p, msgfp);
	fputc('\n', msgfp);
#ifdef HAS_POPEN	
	if (*progname == '|') {
		pclose(msgfp);
		rc = 0;
	} else
#endif
	{
		/* Execute external program */
		fclose(msgfp);
		execstr = malloc(strlen(progname)+strlen(fname)+2);
		sprintf(execstr, "%s %s", progname, fname);
		rc = system(execstr);
		free(execstr);
		unlink(fname);
	};
	if (rc == -1 || rc == 127) {
		writeLogEntry(hpt_log, '9', "excution of external process %s failed", progname);
	};
	return 0;

};

/* area - area to carbon messages, echo - original echo area */
int processCarbonCopy (s_area *area, s_area *echo, s_message *msg, s_carbon carbon) {
	char *p, *old_text, *reason = carbon.reason, rc = 0;
	int i, old_textLength, reasonLen = 0, export = carbon.export;

	statToss.CC++;

	old_textLength = msg->textLength;
	old_text = msg->text;
	
	i = strlen(old_text);

	if (!msg->netMail) {
		if ((!config->carbonKeepSb) && (!area->keepsb)) {
			if (NULL != (p = strstr(old_text,"SEEN-BY:"))) i -= strlen (p);
		}
	};
	
	if (reason) reasonLen = strlen(reason)+1;  /* +1 for \r */

	msg->text = malloc(i+strlen("AREA:\r * Forwarded from area ''\r\r\1")
		   +strlen(area->areaName)+strlen(echo->areaName)+reasonLen+1);
	
	//create new area-line
	if (!msg->netMail) /*FIXME: This is a dirty hack to do it.*/
		           /* I assume that you want need this line in netmail */  
		           /* better use some switches in cfg file */ 
	sprintf(msg->text, "%s%s%s * Forwarded from area '%s'\r%s%s\r\1",
			(export) ? "AREA:" : "",
			(export) ? area->areaName : "",
			(export) ? "\r" : "", echo->areaName,
			(reason) ? reason : "",
			(reason) ? "\r" : "");
	else
		*(msg->text) = '\0';
	strncat(msg->text,old_text,i); // copy rest of msg
	msg->textLength = strlen(msg->text);
	
	if (!export) {
		rc = putMsgInArea(area,msg,0,0);
		area->imported++;  // area has got new messages
	}
	else if (!msg->netMail)
		rc = processEMMsg(msg, *area->useAka, 1);
	else 
		rc = processNMMsg(msg, NULL, area, 1);
	
	free (msg->text);
	msg->textLength = old_textLength;
	msg->text = old_text;
	msg->recode &= ~REC_TXT;
	
	return rc;
}

/* Does carbon copying */
/* Return value: 0 if nothing happend, 1 if there was a carbon copy, 
   > 1 if there was a carbon move */
int carbonCopy(s_message *msg, s_area *echo)
{
	int i, rc = 0;
	char *kludge, *str=NULL;
	s_area *area;
	
	if (echo->ccoff==1) return 0;
	
	for (i=0; i<config->carbonCount; i++) {
		
		/* Dont come to use netmail on echomail and vise verse */
		if (( msg->netMail && !config->carbons[i].netMail) ||
		    (!msg->netMail &&  config->carbons[i].netMail)) 
			continue;
		
		area = config->carbons[i].area;
		
		// dont CC to the echo the mail comes from
		if (!stricmp(echo->areaName,area->areaName)) continue;
		
		switch (config->carbons[i].type) {
			
		case 0:	str=stristr(msg->toUserName,config->carbons[i].str);
			break;
		case 1:	str=stristr(msg->fromUserName,config->carbons[i].str);
			break;
		case 2:
			kludge=getKludge(*msg, config->carbons[i].str);
			str=kludge; if (kludge) free(kludge);
			break;
		case 3:	str=stristr(msg->subjectLine,config->carbons[i].str);
			break;
		case 4:	str=stristr(msg->text+strlen(area->areaName)+6,config->carbons[i].str);
			break;

		} /* end switch*/
			
		if (str) {
			/* Set value: 1 if copy 3 if move */
			rc |= config->carbons[i].move ? 3 : 1;
			
			if (config->carbons[i].extspawn) {
				processExternal(echo,msg,config->carbons[i]); 
			} else {
				if (!processCarbonCopy(area,echo,msg,config->carbons[i]))
					rc &= 1;
			};
			if (config->carbonAndQuit) return rc;
			str = NULL;
		}
		
	} /* end for */
	
	return rc;
}

int putMsgInBadArea(s_message *msg, s_addr pktOrigAddr, int writeAccess)
{
    char *tmp, *line, *textBuff, *areaName;
    
    statToss.bad++;
	 
    // get real name area
    line = strchr(msg->text, '\r');
    *line = 0;
    areaName = (char*)calloc(strlen(msg->text)+13, sizeof(char));
    sprintf(areaName, "AREANAME: %s\r\r", msg->text+5);
    *line = '\r';
	 
    tmp = msg->text;
	 
	 
    while ((line = strchr(tmp, '\r'))) {
	if (*(line+1) == '\x01') tmp = line+1;
	else { tmp = line+1; *line = 0; break; }
    }
	 
    textBuff = (char *)calloc(strlen(msg->text)+strlen(areaName)+80, sizeof(char));
    
    sprintf(textBuff, "%s\rFROM: %s\rREASON: ", msg->text, aka2str(pktOrigAddr));
    switch (writeAccess) {
	case 0: 
		strcat(textBuff, "System not allowed to create new area\r");
		break;
	case 1: 
		strcat(textBuff, "Sender not allowed to post in this area (access group)\r");
		break; 
	case 2: 
		strcat(textBuff, "Sender not allowed to post in this area (access level)\r");
	        break;
	case 3: 
		strcat(textBuff, "Sender not allowed to post in this area (access import)\r");
	        break;
	case 4: 
		strcat(textBuff, "Sender not active for this area\r");
	        break;
	default :
		strcat(textBuff, "Another error\r");
		break;
    }
    textBuff = (char*)realloc(textBuff, strlen(areaName)+strlen(textBuff)+strlen(tmp)+1);
    strcat(textBuff, areaName);
    strcat(textBuff, tmp);
    free(areaName);
    free(msg->text);
    msg->text = textBuff;
    msg->textLength = strlen(msg->text)+1;
    return putMsgInArea(&(config->badArea), msg, 0, 0);
}

void makeMsgToSysop(char *areaName, s_addr fromAddr)
{
    s_area *echo;
    char buff[81];
    int i;
    
    if (!config->ReportTo) return;

    echo = getArea(config, areaName);
    
    if (echo == &(config->badArea)) return;
    
    for (i = 0; i < config->addrCount; i++) {
	if (echo->useAka == &(config->addr[i])) {
	    if (msgToSysop[i] == NULL) {
		if (stricmp(config->ReportTo, "netmail")==0) {
		    msgToSysop[i] = makeMessage(echo->useAka, echo->useAka, versionStr, config->sysop, "Created new areas", 1);
		    msgToSysop[i]->text = (char *)calloc(300, sizeof(char));
		    createKludges(msgToSysop[i]->text, NULL, echo->useAka, echo->useAka);
		} else {
		    msgToSysop[i] = makeMessage(echo->useAka, echo->useAka, versionStr, "All", "Created new areas", 0);
		    msgToSysop[i]->text = (char *)calloc(300, sizeof(char));
		    createKludges(msgToSysop[i]->text, config->ReportTo, echo->useAka, echo->useAka);
		} /* endif */

		strcat(msgToSysop[i]->text, "Action   Name");
		strcat(msgToSysop[i]->text, print_ch(49, ' '));
		strcat(msgToSysop[i]->text, "By\r");
		strcat(msgToSysop[i]->text, print_ch(79, '-'));
		strcat(msgToSysop[i]->text, "\r");
	    }
	    sprintf(buff, "Created  %s", echo->areaName);
	    sprintf(buff+strlen(buff), "%s", print_ch(sizeof(buff)-1-strlen(buff), ' '));
	    sprintf(buff+62, "%s\r", aka2str(fromAddr));
	    msgToSysop[i]->text = (char*)realloc(msgToSysop[i]->text, strlen(msgToSysop[i]->text)+strlen(buff)+1);
	    strcat(msgToSysop[i]->text, buff);
	    break;
	}
    }
    
}

void writeMsgToSysop()
{
    char	tmp[81], *ptr, *seenByPath;
    s_area	*echo;
    int		i, ccrc = 0;
    s_seenBy	*seenBys;
    
    if (!config->ReportTo) return;
    
    for (i = 0; i < config->addrCount; i++) {
	if (msgToSysop[i]) {
	    sprintf(tmp, " \r--- %s\r * Origin: %s (%s)\r", versionStr, config->name, aka2str(msgToSysop[i]->origAddr));
	    msgToSysop[i]->text = (char*)realloc(msgToSysop[i]->text, strlen(tmp)+strlen(msgToSysop[i]->text)+1);
	    strcat(msgToSysop[i]->text, tmp);
	    msgToSysop[i]->textLength = strlen(msgToSysop[i]->text);
	    if (msgToSysop[i]->netMail == 1) processNMMsg(msgToSysop[i], NULL, NULL, 1);
	    else {
		ptr = strchr(msgToSysop[i]->text, '\r');
		strncpy(tmp, msgToSysop[i]->text+5, (ptr-msgToSysop[i]->text)-5);
		tmp[ptr-msgToSysop[i]->text-5]=0;
		echo = getArea(config, tmp);
		if (echo != &(config->badArea)) {
		    if (config->carbonCount != 0) ccrc = carbonCopy(msgToSysop[i], echo);
		    if (echo->msgbType != MSGTYPE_PASSTHROUGH && ccrc <= 1) {
        		putMsgInArea(echo, msgToSysop[i],1, 0);
        		echo->imported++;  // area has got new messages
		    }

		    seenBys = (s_seenBy*) calloc(echo->downlinkCount+1,sizeof(s_seenBy));
		    seenBys[0].net = echo->useAka->net;
		    seenBys[0].node = echo->useAka->node;
		    sortSeenBys(seenBys, 1);
   
		    seenByPath = createControlText(seenBys, 1, "SEEN-BY: ");
		    free(seenBys);
   
		    // path line
		    // only include node-akas in path
		    if (echo->useAka->point == 0) {
			sprintf(tmp, "%u/%u", echo->useAka->net, echo->useAka->node);
			seenByPath = (char *) realloc(seenByPath, strlen(seenByPath)+strlen(tmp)+1+8); // 8 == strlen("\001PATH: \r")
			strcat(seenByPath, "\001PATH: ");
			strcat(seenByPath, tmp);
			strcat(seenByPath, "\r");
		    }
		    msgToSysop[i]->text = (char*)realloc(msgToSysop[i]->text,
							 strlen(msgToSysop[i]->text)+
							 strlen(seenByPath)+1);
		    strcat(msgToSysop[i]->text, seenByPath);
		    free(seenByPath);
		    if (echo->downlinkCount > 0)
			forwardMsgToLinks(echo, msgToSysop[i], msgToSysop[i]->origAddr);
			arcmail();
		} else {
		    putMsgInBadArea(msgToSysop[i], msgToSysop[i]->origAddr, 0);
		}
	    }
	}
    }
    
}

int processEMMsg(s_message *msg, s_addr pktOrigAddr, int dontdocc)
{
   char   *area, *textBuff;
   s_area *echo;
   s_link *link;
   int    writeAccess, rc = 0, ccrc = 0;

   textBuff = (char *) malloc(strlen(msg->text)+1);
   strcpy(textBuff, msg->text);

   area = strtok(textBuff, "\r");
   area += 5;
   while (*area == ' ') area++;

   echo = getArea(config, area);
   statToss.echoMail++;

   if (echo == &(config->badArea)) writeAccess = 0;
   else writeAccess = writeCheck(echo, &pktOrigAddr);
   if (writeAccess!=0) echo = &(config->badArea);

   if (echo != &(config->badArea)) {
      if (dupeDetection(echo, *msg)==1) {
         // no dupe

         if ((echo->downlinkCount > 1) ||
	     // if only one downlink, we've got the mail from him
	     ((echo->downlinkCount > 0) && (!addrComp(pktOrigAddr,*echo->useAka))))   // or it's our own aka
	   {  
	     forwardMsgToLinks(echo, msg, pktOrigAddr);
	     statToss.exported++;
	   }
         if ((config->carbonCount != 0) && (!dontdocc)) ccrc = carbonCopy(msg, echo);

	 if (ccrc <= 1) {
           echo->imported++;  // area has got new messages
       	   if (echo->msgbType != MSGTYPE_PASSTHROUGH) {
              rc = putMsgInArea(echo, msg,1, 0);
      	      statToss.saved++;
           } 
	   else {
	       statToss.passthrough++;
	       rc = 1; //passthrough does always work
	   }
	 };


      } else {
         // msg is dupe
         if (echo->dupeCheck == dcMove) {
            rc = putMsgInArea(&(config->dupeArea), msg, 0, 0);
         } else rc = 1; // quick fix. not sure.
         statToss.dupes++;
      }

   }

   if (echo == &(config->badArea)) {
      if ((config->carbonCount != 0) && (!dontdocc)) ccrc = carbonCopy(msg, echo);

      if (ccrc <= 1) {
        // checking for autocreate option
        link = getLinkFromAddr(*config, pktOrigAddr);
        if ((link != NULL) && (link->autoAreaCreate != 0) && (writeAccess == 0)) {
           autoCreate(area, pktOrigAddr, NULL);
           echo = getArea(config, area);
	   writeAccess = writeCheck(echo, &pktOrigAddr);
	   if (writeAccess) {
	       rc = putMsgInBadArea(msg, pktOrigAddr, writeAccess);
	   } else {
	     if (dupeDetection(echo, *msg)==1) {
	       // nodupe
               if (echo->msgbType != MSGTYPE_PASSTHROUGH)
        	  rc = putMsgInArea(echo, msg, 1, 0);
               if (echo->downlinkCount > 1) {   // if only one downlink, we've got the mail from him
          	  forwardMsgToLinks(echo, msg, pktOrigAddr);
        	  statToss.exported++;
               }
	     } else {
	       // msg is dupe
	       if (echo->dupeCheck == dcMove) 
	         rc = putMsgInArea(&(config->dupeArea), msg, 0, 0);
	       else 
	         rc = 1;
	       statToss.dupes++;
	     }
	   }
        } else rc = putMsgInBadArea(msg, pktOrigAddr, writeAccess);
      };
   }

   free(textBuff);
   return rc;
}

int processNMMsg(s_message *msg, s_pktHeader *pktHeader, s_area *area, int dontdocc)
{
   HAREA  netmail;
   HMSG   msgHandle;
   UINT   len = msg->textLength;
   char   *bodyStart;             // msg-body without kludgelines start
   char   *ctrlBuf;               // Kludgelines
   XMSG   msgHeader;
   char   *slash;
   int rc = 0, ccrc = 0;
#ifdef UNIX
   char limiter = '/';
#else
   char limiter = '\\';
#endif

   if (area == NULL) {
 	area = &(config->netMailAreas[0]);
   };

   if (config->carbonCount != 0) ccrc = carbonCopy(msg, area);
   if (ccrc > 1) return 1;

   // create Directory Tree if necessary
   if (area -> msgbType == MSGTYPE_SDM)
      createDirectoryTree(area -> fileName);
   else {
      // squish area
      slash = strrchr(area -> fileName, limiter);
      *slash = '\0';
      createDirectoryTree(area -> fileName);
      *slash = limiter;
   }

   netmail = MsgOpenArea((unsigned char *) area -> fileName, MSGAREA_CRIFNEC,
/*								 config->netMailArea.fperm, config->netMailArea.uid,
								 config->netMailArea.gid, */area -> msgbType);
   
   if (netmail != NULL) {
      msgHandle = MsgOpenMsg(netmail, MOPEN_CREATE, 0);

      if (msgHandle != NULL) {
         area -> imported++; // area has got new messages

         // recode from TransportCharset to internal Charset
         if (config->intab != NULL) {
            if ((msg->recode & REC_HDR)==0) {
		recodeToInternalCharset((CHAR*)msg->fromUserName);
                recodeToInternalCharset((CHAR*)msg->toUserName);
                recodeToInternalCharset((CHAR*)msg->subjectLine);
	        msg->recode |= REC_HDR;
            }
	    if ((msg->recode & REC_TXT)==0) {
		recodeToInternalCharset((CHAR*)msg->text);
		msg->recode |= REC_TXT;
	    }
         }

         msgHeader = createXMSG(msg, pktHeader, 0);
//	   	 if ((msg->attributes & MSGKILL) == MSGKILL) msgHeader.attr |= MSGKILL;
         /* Create CtrlBuf for SMAPI */
         ctrlBuf = (char *) CopyToControlBuf((UCHAR *) msg->text, (UCHAR **) &bodyStart, &len);
         /* write message */
         MsgWriteMsg(msgHandle, 0, &msgHeader, (UCHAR *) bodyStart, len, len, strlen(ctrlBuf)+1, (UCHAR *) ctrlBuf);
         free(ctrlBuf);
         MsgCloseMsg(msgHandle);
	 rc = 1;

         writeLogEntry(hpt_log, '7', "Tossed Netmail: %u:%u/%u.%u -> %u:%u/%u.%u", msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node, msg->origAddr.point,
                         msg->destAddr.zone, msg->destAddr.net, msg->destAddr.node, msg->destAddr.point);
         statToss.netMail++;
      } else {
         writeLogEntry(hpt_log, '9', "Could not write message to NetmailArea %s", area -> areaName);
      } /* endif */

      MsgCloseArea(netmail);
   } else {
      fprintf(stderr, "msgapierr - %u\n", msgapierr);
      writeLogEntry(hpt_log, '9', "Could not open NetmailArea %s", area -> areaName);
   } /* endif */
   return rc;
}

int processMsg(s_message *msg, s_pktHeader *pktHeader)
{
  int rc;

  statToss.msgs++;
  if (msg->netMail == 1) {
    if (config->areafixFromPkt && 
	(stricmp(msg->toUserName,"areafix")==0 ||
	 stricmp(msg->toUserName,"areamgr")==0 ||
	 stricmp(msg->toUserName,"hpt")==0)) {
      rc = processAreaFix(msg, pktHeader);
    } else
      rc = processNMMsg(msg, pktHeader, NULL, 0);
  } else {
    rc = processEMMsg(msg, pktHeader->origAddr, 0);
  } /* endif */
  return rc;
}

int processPkt(char *fileName, e_tossSecurity sec)
{
   FILE        *pkt;
   s_pktHeader *header;
   s_message   *msg;
   s_link      *link;
   char        rc = 0;
   struct stat statBuff;
   char        processIt = 0; // processIt = 1, process all mails
                              // processIt = 2, process only Netmail
                              // processIt = 0, do not process pkt
   
   if ((stat(fileName, &statBuff) == 0) && (statBuff.st_size > 60)) {

       statToss.inBytes += statBuff.st_size;
       
       pkt = fopen(fileName, "rb");
       if (pkt == NULL) return 2;
       
       header = openPkt(pkt);
       if (header != NULL) {
	 if (to_us(header->destAddr)==0) {
	   writeLogEntry(hpt_log, '6', "pkt: %s", fileName);
	   statToss.pkts++;
	   link = getLinkFromAddr(*config, header->origAddr);
	   if ((link!=NULL) && (link->pktPwd==NULL) && (header->pktPassword[0]!='\000'))
	       writeLogEntry(hpt_log, '3', "Unexpected Password %s.", header->pktPassword);
	   
	   switch (sec) {
	   case secLocalInbound:
	     processIt = 1;
	     break;
	     
	   case secProtInbound:
	     if ((link != NULL) && (link->pktPwd != NULL)) {
               if (stricmp(link->pktPwd, header->pktPassword)==0) {
                  processIt = 1;
               } else {
                  if ( (header->pktPassword == NULL || header->pktPassword[0] == '\0') && (link->allowEmptyPktPwd & (eSecure | eOn)) ) {
                      writeLogEntry(hpt_log, '9', "pkt: %s Warning: missing packet password from %i:%i/%i.%i",
                              fileName, header->origAddr.zone, header->origAddr.net,
                              header->origAddr.node, header->origAddr.point);
                      processIt = 1;
                  } else {
	            writeLogEntry(hpt_log, '9', "pkt: %s Password Error for %i:%i/%i.%i",
		    fileName, header->origAddr.zone, header->origAddr.net,
		    header->origAddr.node, header->origAddr.point);
                    rc = 1;
                  }
               }
             } else if ((link != NULL) && ((link->pktPwd == NULL) || (strcmp(link->pktPwd, "")==0))) {
               processIt=1;
	     } else /* if (link == NULL) */ {	
	       writeLogEntry(hpt_log, '9', "pkt: %s No Link for %i:%i/%i.%i, processing only Netmail",
		       fileName, header->origAddr.zone, header->origAddr.net,
		       header->origAddr.node, header->origAddr.point);
	       processIt = 2;
	     }
	     break;

	   case secInbound:
	     if ((link != NULL) && (link->pktPwd != NULL)) {
               if (stricmp(link->pktPwd, header->pktPassword)==0) {
                  processIt = 1;
               } else {
                  if ( (header->pktPassword == NULL || header->pktPassword[0] == '\0') && (link->allowEmptyPktPwd & (eOn)) ) {
                      writeLogEntry(hpt_log, '9', "pkt: %s Warning: missing packet password from %i:%i/%i.%i",
                              fileName, header->origAddr.zone, header->origAddr.net,
                              header->origAddr.node, header->origAddr.point);
                      processIt = 1;
                  } else {
	            writeLogEntry(hpt_log, '9', "pkt: %s Password Error for %i:%i/%i.%i",
		    fileName, header->origAddr.zone, header->origAddr.net,
		    header->origAddr.node, header->origAddr.point);
                    rc = 1;
                  }
               }
             } else if ((link != NULL) && ((link->pktPwd == NULL) || (strcmp(link->pktPwd, "")==0))) {
               processIt=1;
	     } else /* if (link == NULL) */ {	
	       writeLogEntry(hpt_log, '9', "pkt: %s No Link for %i:%i/%i.%i, processing only Netmail",
		       fileName, header->origAddr.zone, header->origAddr.net,
		       header->origAddr.node, header->origAddr.point);
	       processIt = 2;
	     }
	     break;
	     
	   }
	   
	   if (processIt != 0) {
	     while ((msg = readMsgFromPkt(pkt, header)) != NULL) {
               if (msg != NULL) {
		 if ((processIt == 1) || ((processIt==2) && (msg->netMail==1)))
		   rc = !processMsg(msg, header) || rc == 5 ? 5 : 0;
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
		   writeLogEntry(hpt_log, '9', "pkt: %s wrong pkt-file", fileName);
		   rc = 3;
       }
       
       if (pkt) fclose(pkt);

   } else statToss.empty++;

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
   char cmd[256];

   if (sec == secInbound) {
      writeLogEntry(hpt_log, '6', "bundle %s: tossing in unsecure inbound, security violation", fileName);
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
	  fillCmdStatement(cmd,config->unpack[i-1].call,fileName,"",config->tempInbound);
      writeLogEntry(hpt_log, '6', "bundle %s: unpacking with \"%s\"", fileName, cmd);
      if ((cmdexit = system(cmd)) != 0) {
         writeLogEntry(hpt_log, '6', "exec failed, code %d", cmdexit);
         return 3;
      };
	  if (config->afterUnpack) {
		  writeLogEntry(hpt_log, '6', "afterUnpack: execute string \"%s\"", config->afterUnpack);
		  if ((cmdexit = system(config->afterUnpack)) != 0) {
			  writeLogEntry(hpt_log, '6', "exec failed, code %d", cmdexit);
		  };
	  }
   } else {
      writeLogEntry(hpt_log, '6', "bundle %s: cannot find unpacker", fileName);
      return 3;
   };
   statToss.arch++;
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
            if (patimat(file->d_name, validExt[i]) == 1
#if !defined(UNIX)
		&& !(file->d_attr & _A_HIDDEN)
#endif
					    )
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
            case 5:  // tossing problem
               changeFileSuffix(dummy, "err");
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
   int i;
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

   writeLogEntry(hpt_log, logchar, "Statistics:");
   writeLogEntry(hpt_log, logchar, "     arc: % 5d   netMail: % 4d   echoMail: % 5d         CC: % 5d",
		   statToss.arch, statToss.netMail, statToss.echoMail, statToss.CC);
   writeLogEntry(hpt_log, logchar, "   pkt's: % 5d      dupe: % 4d   passthru: % 5d   exported: % 5d",
		   statToss.pkts, statToss.dupes, statToss.passthrough, statToss.exported);
   writeLogEntry(hpt_log, logchar, "    msgs: % 5d       bad: % 4d      saved: % 5d      empty: % 5d",
		   statToss.msgs, statToss.bad, statToss.saved, statToss.empty);
   writeLogEntry(hpt_log, logchar, "   Input: % 8.2f mails/sec   Output: % 8.2f mails/sec", inMailsec, outMailsec);
   writeLogEntry(hpt_log, logchar, "          % 8.2f kb/sec", inKBsec);
   /* Now write areas summary */
   writeLogEntry(hpt_log, logchar, "Areas summary:");
   for (i = 0; i < config->netMailAreaCount; i++)
	if (config->netMailAreas[i].imported > 0)
		writeLogEntry(hpt_log, logchar, "netmail area %s - %d msgs", 
			config->netMailAreas[i].areaName, config->netMailAreas[i].imported);

   for (i = 0; i < config->echoAreaCount; i++)
	if (config->echoAreas[i].imported > 0)
		writeLogEntry(hpt_log, logchar, "echo area %s - %d msgs", 
			config->echoAreas[i].areaName, config->echoAreas[i].imported);
   for (i = 0; i < config->localAreaCount; i++)
	if (config->localAreas[i].imported > 0)
		writeLogEntry(hpt_log, logchar, "local area %s - %d msgs", 
			config->localAreas[i].areaName, config->localAreas[i].imported);
}

int find_old_arcmail(s_link *link, FILE *flo) {
	FILE *f;
	char *line, *tmp=NULL, bundle[256]="";
	char *wdays[7]={ ".su", ".mo", ".tu", ".we", ".th", ".fr", ".sa" };
	long len;
	unsigned i, as=500;

	while ((line = readLine(flo)) != NULL) {
#ifndef UNIX
		line = trimLine(line);
#endif
		
		for (i=0; (i<7) && (tmp==NULL); i++) {
			if (strstr(line,wdays[i])!=NULL) {tmp=line; break;}
		}
		
		if (tmp!=NULL) {tmp++; sprintf(bundle,"%s",tmp); tmp=NULL;}
		free(line);
	}
		
	if (bundle[0]!='\000') {
		f=fopen(bundle,"rb");
		if (f!=NULL) {
			fseek(f, 0L, SEEK_END);
			len = ftell(f);
			fclose(f);
			if (link->arcmailSize!=0) as=link->arcmailSize;
			else {
				if (config->defarcmailSize!=0) as=config->defarcmailSize;
			}
			// default 500 kb max
			if ((int)len < as*1024) {
				link->packFile=(char*)realloc(link->packFile,strlen(bundle)+1);
				strcpy(link->packFile,bundle);
				return 1;
			}
		}
	}
	
	return 0;
}

void arcmail() {
   char cmd[256], *pkt, *lastPathDelim, saveChar, sepDir[14];
   int i, cmdexit;
   FILE *flo;
   s_link *link;
   
   if (config->beforePack) {
	   writeLogEntry(hpt_log, '6', "beforePack: execute string \"%s\"", config->beforePack);
	   if ((cmdexit = system(config->beforePack)) != 0) {
		   writeLogEntry(hpt_log, '6', "exec failed, code %d", cmdexit);
	   };
   }
   
   for (i = 0 ; i < config->linkCount; i++) {
	   
	  link = &(config->links[i]);
	  
	  // only create floFile if we have mail for this link
	  if (link->pktFile != NULL) {
		  
		  // process if the link not busy, else do not create 12345678.?lo
		  if (createOutboundFileName(link,
					     cvtFlavour2Prio(link->echoMailFlavour),
					     FLOFILE) == 0) {

			 flo = fopen(link->floFile, "a+");
			 
			 if (flo == NULL) {
			   writeLogEntry(hpt_log, '!', "Cannot open flo file %s", config->links[i].floFile);
			   return;
			 }

			 if (link->packerDef != NULL) {
				 // there is a packer defined -> put packFile into flo
				 // if we are creating new arcmail bundle  ->  -//-//-
				 fseek(flo, 0L, SEEK_SET);
				 if ( find_old_arcmail(link, flo) == 0 )
					 fprintf(flo, "^%s\n", link->packFile);
			 }
			 else {
				 // there is no packer defined -> put pktFile into flo
				 pkt = (char*) malloc(strlen(link->floFile)+13+1);
				 lastPathDelim = strrchr(link->floFile, PATH_DELIM);
				 
				 // change path of file to path of flofile
				 saveChar = *(++lastPathDelim);
				 *lastPathDelim = '\0';
				 strcpy(pkt, link->floFile);
				 *lastPathDelim = saveChar;
				   
				 link->pktFile += strlen(config->tempOutbound);
				 
				 if (config->separateBundles) {

					 if (link->hisAka.point != 0)
						 sprintf (sepDir,"%08x.sep%c", link->hisAka.point, PATH_DELIM);
					 else
						 sprintf (sepDir, "%04x%04x.sep%c",
								 link->hisAka.net,
								 link->hisAka.node, 
								 PATH_DELIM);

					 strcat (pkt, sepDir);
				 }
				   
				 strcat(pkt, link->pktFile);
				 link->pktFile -= strlen(config->tempOutbound);
				   
				 fprintf(flo, "^%s\n", pkt);
				 rename(link->pktFile, pkt);
				 free(pkt);
				 
			 }
			 fclose(flo);
			 free(link->floFile); link->floFile=NULL;
			 
			 // pack mail
			 if (link->packerDef != NULL) {
				 fillCmdStatement(cmd,
								  link->packerDef->call,
								  link->packFile,
								  link->pktFile, "");
				 writeLogEntry(hpt_log, '7', "Packing mail for %s %s", aka2str(link->hisAka), link->name);
				 cmdexit = system(cmd);
//				 sprintf(logmsg,"cmd: %s\n",cmd);
// 				 writeLogEntry(hpt_log, '7', logmsg);
				 remove(link->pktFile);
			 }
			 remove(link->bsyFile);
			 free(link->bsyFile); link->bsyFile=NULL;
		  }
	  }
	  free(link->pktFile); link->pktFile=NULL;
	  free(link->packFile); link->packFile=NULL;
   }
   return;
}

static int forwardedPkts = 0;

int forwardPkt(const char *fileName, s_pktHeader *header, e_tossSecurity sec)
{
    int i;
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
		    
		writeLogEntry(hpt_log, '7', "Forwarding %s to %s as %s",
		        fileName, config->links[i].name, newfn + strlen(config->tempOutbound));

		free(newfn);
		forwardedPkts = 1;
		return 0;
	    }
	    else
	    {
		writeLogEntry (hpt_log, '9', "Failure moving %s to %s (%s)", fileName,
			 newfn, strerror(errno));
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
		   if (pkt==NULL) continue;

		   header = openPkt(pkt);
		   if (header != NULL) {
		      link = getLinkFromAddr (*config, header->destAddr);
		   } else {
	              link = NULL;
	           }
		             
		   if (link != NULL) {

			   createTempPktFileName(link);

			   free(link->pktFile);
			   link->pktFile = dummy;

			   fclose(pkt);
			   arcmail();
		   } else {
			   writeLogEntry(hpt_log, '9', "found non packed mail without matching link in tempOutbound");
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
   if (config->intab != NULL) getctab(intab, (UCHAR*) config->intab);
   
   // set stats to 0
   memset(&statToss, 0, sizeof(s_statToss));
   statToss.startTossing = time(NULL);
   writeLogEntry(hpt_log, '1', "Start tossing...");
   processDir(config->localInbound, secLocalInbound);
   processDir(config->protInbound, secProtInbound);
   processDir(config->inbound, secInbound);

#ifndef HASHDUPE
   // write dupeFiles

   for (i = 0 ; i < config->echoAreaCount; i++) {
      writeToDupeFile(&(config->echoAreas[i]));
      freeDupeMemory(&(config->echoAreas[i]));
   }
#endif

   if (config->importlog != NULL) {
      // write importlog

      f = fopen(config->importlog, "a");
      if (f != NULL) {

		  for (i = 0; i < config->netMailAreaCount; i++)
			  if (config->netMailAreas[i].imported > 0)
			  fprintf(f, "%s\n", config->netMailAreas[i].areaName);

		  for (i = 0; i < config->echoAreaCount; i++)
			  if (config->echoAreas[i].imported > 0 && 
			  config->echoAreas[i].msgbType != MSGTYPE_PASSTHROUGH)
				  fprintf(f, "%s\n", config->echoAreas[i].areaName);
		  
	          for (i = 0; i < config->localAreaCount; i++)
			 if (config->localAreas[i].imported > 0)
				 fprintf(f, "%s\n", config->localAreas[i].areaName);
		 
         fclose(f);
#ifdef UNIX
	 chown(config->importlog, config->loguid, config->loggid);
	 if (config -> logperm != -1) chmod(config->importlog, config->logperm);
#endif

      } else writeLogEntry(hpt_log, '5', "Could not open importlogfile");
   }

   if (forwardedPkts) {
	   tossTempOutbound(config->tempOutbound);
	   forwardedPkts = 0;
   }

   // write statToss to Log
   writeTossStatsToLog();
   arcmail();
}

int packBadArea(HMSG hmsg, XMSG xmsg)
{
   int		rc = 0;
   s_message    msg;
   s_area	*echo = &(config -> badArea);
   s_addr	pktOrigAddr;
   char 	*tmp, *ptmp, *line, *areaName;
   
   makeMsg(hmsg, xmsg, &msg, &(config->badArea), 2);
   
   // deleting valet string - "FROM:" and "REASON:"
   ptmp = msg.text;
   while ((line = strchr(ptmp, '\r'))) {
       /* Temporary make it \0 terminated string */
       *line = '\000';
       if (strncmp(ptmp, "FROM: ", 6) == 0 || 
	   strncmp(ptmp, "REASON: ", 8) == 0 || 
	   strncmp(ptmp, "AREANAME: ", 10) == 0) {
	   if (*ptmp == 'F')
		   /* It's from address */
		   string2addr(ptmp + 6, &pktOrigAddr);
	   /* Cut this kludges */
 	   memmove(ptmp, line+1, strlen(line+1)+1);	  
	   continue;
       } else { 
	   if (strncmp(ptmp, "AREA:", 5)==0 || strncmp(ptmp, "\001AREA:", 6)==0) {
		//translating name of the area to uppercase
		for (tmp = ptmp; *tmp != '\0'; tmp++) 
			*tmp=toupper(*tmp);
		areaName = *ptmp == '\001' ? ptmp + 4 : ptmp + 5;
		while (*areaName == ' ') areaName++;    // if the areaname begins with a space
           	echo = getArea(config, areaName);
	   };
           ptmp = line+1;
       };
       *line = '\r';
   }

   if (echo == &(config->badArea)) {
       freeMsgBuffers(&msg);
       return 1;
   }
   
   if (writeCheck(echo, &pktOrigAddr) == 0) {
      if (dupeDetection(echo, msg)==1) {
	 // no dupe
         if (config->carbonCount != 0) carbonCopy(&msg, echo);

         echo->imported++;  // area has got new messages
         if (echo->msgbType != MSGTYPE_PASSTHROUGH) {
            rc = !putMsgInArea(echo, &msg,1, 0);
//            statToss.saved++;
         } else statToss.passthrough++;

	 // recoding from internal to transport charSet
	 if (config->outtab != NULL) {
	     recodeToTransportCharset((CHAR*)msg.fromUserName);
	     recodeToTransportCharset((CHAR*)msg.toUserName);
	     recodeToTransportCharset((CHAR*)msg.subjectLine);
	     recodeToTransportCharset((CHAR*)msg.text);
	 }
   
	 if (echo->downlinkCount > 0) {
            forwardMsgToLinks(echo, &msg, pktOrigAddr);
//            statToss.exported++;
         }

      } else {
         // msg is dupe
         if (echo->dupeCheck == dcMove) {
            rc = !putMsgInArea(&(config->dupeArea), &msg, 0, 0);
         } else {
	    rc = 0;
	 };
//         statToss.dupes++;
      }

   } else {
	   rc = 1;
   };
   freeMsgBuffers(&msg);
   return rc;
}

void tossFromBadArea()
{
   HAREA area;
   HMSG  hmsg;
   XMSG  xmsg;
   dword highestMsg, i;
   int   delmsg;
   
   // load recoding tables
   if (config->outtab != NULL) getctab(outtab, (UCHAR *) config->outtab);

   area = MsgOpenArea((UCHAR *) config->badArea.fileName, MSGAREA_NORMAL, config->badArea.msgbType | MSGTYPE_ECHO);
   if (area != NULL) {
//      statScan.areas++;
      writeLogEntry(hpt_log, '1', "Scanning area: %s", config->badArea.areaName);
      i = MsgGetHighWater(area);
      highestMsg    = MsgGetHighMsg(area);

      while (i <= highestMsg) {
         hmsg = MsgOpenMsg(area, MOPEN_RW, i++);
         if (hmsg == NULL) continue;      // msg# does not exist
//         statScan.msgs++;
         MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
	 delmsg = packBadArea(hmsg, xmsg);
	 
         MsgCloseMsg(hmsg);
	 
	 if (delmsg == 0) {
	     MsgKillMsg(area, i-1);
	     i--;
//	     statScan.exported++;
	 }
      }
      
      MsgSetHighWater(area, i);

      MsgCloseArea(area);
      
      arcmail();
      
   } else 
      writeLogEntry(hpt_log, '9', "Could not open %s", config->badArea.fileName);
   /* endif */
}
