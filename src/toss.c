#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include <dir.h>
#include <pkt.h>
#include <scan.h>
#include <toss.h>
#include <global.h>
#include <patmat.h>
#include <seenby.h>
#include <dupe.h>

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

   newFileName = (char *) malloc(length+1);
   strncpy(newFileName, fileName, length-strlen(newSuffix));
   strcat(newFileName, newSuffix);

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

void putMsgInArea(s_area *echo, s_message *msg)
{
   char buff[70], *ctrlBuff, *textStart;
   UINT textLength = msg->textLength;
   HAREA harea;
   HMSG  hmsg;
   XMSG  xmsg;

   harea = MsgOpenArea((UCHAR *) echo->fileName, MSGAREA_CRIFNEC, echo->msgbType | MSGTYPE_ECHO);
   if (harea != NULL) {
      hmsg = MsgOpenMsg(harea, MOPEN_CREATE, 0);
      if (hmsg != NULL) {
         ctrlBuff = CopyToControlBuf((UCHAR *) msg->text, (UCHAR **) &textStart, &textLength);
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
   char *seenByText, *start, *token, digit[6];
   INT i;
   
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
         i = 0;
         // copy first number
         while (isdigit(*token)) digit[i++] = *token++;
         *seenBys = (s_seenBy*) realloc(*seenBys, sizeof(s_seenBy) * (*seenByCount)+1);
         if (*token++ == '/') {
            // net/node address
            (*seenBys)[*seenByCount].net = atoi(digit);
            i = 0;
            while (isdigit(*token)) digit[i++] = *token++;
            (*seenBys)[*seenByCount].node = atoi(digit);
         } else {
            // only node
            (*seenBys)[(*seenByCount)].net = (*seenBys)[(*seenByCount)-1].net;
            (*seenBys)[*seenByCount].node = atoi(digit);
         }
         (*seenByCount)++;
         memset(&digit, 0, 5);
      }
      token = strtok(NULL, " \r\t\xfe");
   }

   // test output for reading of seenBys...
   //for (i=0; i < *seenByCount; i++) printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
   //exit(2);

   free(seenByText);
}

void createPathArrayFromMsg(s_message *msg, s_seenBy *seenBys[], UINT *seenByCount)
{

   // DON'T GET MESSED UP WITH THE VARIABLES NAMED SEENBY...
   // THIS FUNCTION READS PATH!!!
   
   char *seenByText, *start, *token, digit[6];
   INT i;
   
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
         i = 0;
         // copy first number
         while (isdigit(*token)) digit[i++] = *token++;
         *seenBys = (s_seenBy*) realloc(*seenBys, sizeof(s_seenBy) * (*seenByCount)+1);
         if (*token++ == '/') {
            // net/node address
            (*seenBys)[*seenByCount].net = atoi(digit);
            i = 0;
            while (isdigit(*token)) digit[i++] = *token++;
            (*seenBys)[*seenByCount].node = atoi(digit);
         } else {
            // only node
            (*seenBys)[(*seenByCount)].net = (*seenBys)[(*seenByCount)-1].net;
            (*seenBys)[*seenByCount].node = atoi(digit);
         }
         (*seenByCount)++;
         memset(&digit, 0, 5);
      }
      token = strtok(NULL, " \r\t\xfe");
   }

   // test output for reading of paths...
   //for (i=0; i < *seenByCount; i++) printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
   //exit(2);

   free(seenByText);
}


void forwardMsgToLinks(s_area *echo, s_message *msg, s_addr pktOrigAddr)
{
   s_seenBy *seenBys = NULL, *path = NULL;
   UINT     seenByCount, pathCount, i;
   char     *start, *c, *newMsgText, *seenByText = NULL, *pathText = NULL;
   
   char     *name;
   FILE     *pkt, *flo;
   s_pktHeader header;

   createSeenByArrayFromMsg(msg, &seenBys, &seenByCount);
   // add seenBy for links
   for (i=0; i<echo->downlinkCount; i++) {
      if (echo->downlinks[i]->hisAka.point != 0) continue; // don't include points in SEEN-BYS
      
      seenBys = (s_seenBy*) realloc(seenBys, sizeof(s_seenBy) * (seenByCount)+1);
      seenBys[seenByCount].net = echo->downlinks[i]->hisAka.net;
      seenBys[seenByCount].node = echo->downlinks[i]->hisAka.node;
      seenByCount++;
   }

   sortSeenBys(seenBys, seenByCount);

   //for (i=0; i< seenByCount;i++) printf("%u/%u ", seenBys[i].net, seenBys[i].node);
   //exit(2);

   createPathArrayFromMsg(msg, &path, &pathCount);
   if (echo->useAka->point == 0) {   // only include nodes in PATH
      // add our aka to path
      path = (s_seenBy*) realloc(path, sizeof(s_seenBy) * (pathCount)+1);
      path[pathCount].net = echo->useAka->net;
      path[pathCount].node = echo->useAka->node;
      pathCount++;
   }

   //for (i=0; i< pathCount;i++) printf("%u/%u ", path[i].net, path[i].node);
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
      
      // create pktfile if necessary
      if (echo->downlinks[i]->pktFile == NULL) {
         // pktFile does not exist
         name = createTempPktFileName();
         echo->downlinks[i]->pktFile = (char *) malloc(strlen(name)+4+1); // 4 == strlen(".pkt");
         strcpy(echo->downlinks[i]->pktFile, name);
         strcat(echo->downlinks[i]->pktFile, ".pkt");
         name = createOutboundFileName(echo->downlinks[i]->hisAka, NORMAL, FLOFILE);
         flo = fopen(name, "a");
         fprintf(flo, "#%s\n", echo->downlinks[i]->pktFile);
         fclose(flo);
      } /* endif */

      makePktHeader(NULL, &header);
      header.origAddr = *(echo->downlinks[i]->ourAka);
      header.destAddr = echo->downlinks[i]->hisAka;
      strcpy(header.pktPassword, echo->downlinks[i]->pktPwd);
      pkt = openPktForAppending(echo->downlinks[i]->pktFile, &header);

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
   char buff[160], myaddr[20], hisaddr[20];
   int i=0,j=0;
   
   //translating name of the area to lowercase, much better imho.
   while (*c_area != '\0') {*c_area=tolower(*c_area);c_area++;i++;}
   while (i>0) {c_area--;i--;};
   
   f = fopen("/etc/fido/config", "a");
   
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

   //write new line in config file
   sprintf(buff,"EchoArea %s %s%s -a %s Squish %s\n",c_area,config->msgBaseDir,
           c_area,myaddr, hisaddr);
   fprintf(f,buff);
   
   fclose(f);

   // add new created echo to config in memory
   parseLine(buff,config);
   
   sprintf(buff, "Area '%s' autocreated by %s", c_area, hisaddr);
   writeLogEntry(log, '8', buff);
   return 0;
}
 
void processEMMsg(s_message *msg, s_addr pktOrigAddr)
{
   char   *area, *textBuff;
   s_area *echo;
   s_link *link;

   textBuff = (char *) malloc(strlen(msg->text)+1);
   strcpy(textBuff, msg->text);
   
   area = strtok(textBuff, "\r");
   area += 5;

   echo = getArea(config, area);
   statToss.echoMail++;

   if (echo == &(config->badArea)) {
      // checking for autocreate option
      link = getLinkFromAddr(*config, pktOrigAddr);
      if ((link != NULL) && (link->autoAreaCreate != 0)) {
         autoCreate(area, pktOrigAddr);
         echo = getArea(config, area);
      } else
         // no autoareaCreate -> msg to bad
         putMsgInArea(echo, msg);
         statToss.bad++;
   }

   if (echo != &(config->badArea)) {
      if (dupeDetection(echo, *msg)==1) {
         // no dupe

         if (echo->msgbType != MSGTYPE_PASSTHROUGH) {
            putMsgInArea(echo, msg);
	    statToss.saved++;
         } else statToss.passthrough++;
         if (echo->downlinkCount > 1) {   // if only one downlink, we've got the mail from him
            forwardMsgToLinks(echo, msg, pktOrigAddr);
            statToss.exported++;
         }
      } else {
         // msg is dupe
         if (echo->dupeCheck == move) {
            putMsgInArea(&(config->dupeArea), msg);
         }
	 statToss.dupes++;
      }
   }

   free(textBuff);
}

void processNMMsg(s_message *msg)
{
   HAREA  netmail;
   HMSG   msgHandle;
   UINT   len = msg->textLength;
   char   *bodyStart;             // msg-body without kludgelines start
   char   *ctrlBuf;               // Kludgelines
   XMSG   msgHeader;
   char   buff[36];               // buff for sprintf

   netmail = MsgOpenArea((unsigned char *) config->netMailArea.fileName, MSGAREA_CRIFNEC, config->netMailArea.msgbType);

   if (netmail != NULL) {
      msgHandle = MsgOpenMsg(netmail, MOPEN_CREATE, 0);

      if (msgHandle != NULL) {
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
      processNMMsg(msg);
   } else {
      processEMMsg(msg, pktOrigAddr);
   } /* endif */
}

int processPkt(char *fileName, int onlyNetmail)
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
         if (link != NULL)
            // if passwords aren't the same don't process pkt
            // if pkt is from a System we don't have a link (incl. pwd) with
            // we process it.
            if ((link->pktPwd != NULL) && (stricmp(link->pktPwd, header->pktPassword) != 0)) pwdOK = 0;
            if (pwdOK != 0) {
               while ((msg = readMsgFromPkt(pkt,config->addr[0].zone)) != NULL) {
                  if ((onlyNetmail == 0) || (msg->netMail == 1))
                     processMsg(msg, header->origAddr);
                  freeMsgBuffers(msg);
               } /* endwhile */
            } /* endif */
         else rc = 1;
      } /*endif */
   } else rc = 3;

   fclose(pkt);
   return rc;
}

void processDir(char *directory, int onlyNetmail)
{
   DIR            *dir;
   struct dirent  *file;
   char           *dummy;
   int            rc;

   dir = opendir(directory);

   while ((file = readdir(dir)) != NULL) {
//      printf("testing %s\n", file->d_name);
      if ((patmat(file->d_name, "*.pkt") == 1) || (patmat(file->d_name, "*.PKT") == 1)) {
         dummy = (char *) malloc(strlen(directory)+strlen(file->d_name)+1);
         strcpy(dummy, directory);
         strcat(dummy, file->d_name);
         rc = processPkt(dummy, onlyNetmail);

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

void toss()
{
   int i;

   // set stats to 0
   memset(&statToss, sizeof(s_statToss), 0);
   writeLogEntry(log, '4', "Start tossing...");
   processDir(config->protInbound, 0);
   // only import Netmails from inboundDir
   processDir(config->inbound, 1);

   // write dupeFiles

   for (i = 0 ; i < config->echoAreaCount; i++) writeToDupeFile(&(config->echoAreas[i]));

   // write statToss to Log
   writeTossStatsToLog();
}
