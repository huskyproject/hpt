/*:ts=8*/
/*****************************************************************************
 * Link for HPT (FTN NetMail/EchoMail Tosser)
 *****************************************************************************
 * Copyright (C) 1998
 *
 * Kolya Nesterov
 *
 * Fido:     2:463/7208.53
 * Kiev, Ukraine
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
/* Revision log:
   19.12.98 - first version
 */

/*
   For now reply linking is performed using the msgid/reply kludges
   TODO:
     linking flat, subject linking
     fix log numbers
     SPEEDUP!!!!!!!!!!!
     store only information after MSGID: and REPLY:
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef MSDOS
#include <fidoconfig.h>
#else
#include <fidoconf.h>
#endif
#include <typesize.h>
#include <msgapi.h>
#include <log.h>
#include <global.h>
#include <tree.h>

/* internal structure holding msg's related to link information */
/* used by linkArea */
struct msginfo {
   char *msgId;
   char *replyId;
   char *subject;

   dword msgNum;
   UMSGID msgPos;
   UMSGID replyToPos;
   UMSGID replies[MAX_REPLY];
   int freeReply;

   struct msginfo *prev;
};

typedef struct msginfo s_msginfo;

static int  compareEntries(const void *e1, const void *e2)
{
   return strcasecmp(((s_msginfo*) e1) -> msgId + 6,
                     ((s_msginfo*) e2) -> msgId + 6);
}

static int  findEntry(const void *e1, const void *e2)
{
   return strcasecmp(((s_msginfo*) e1) -> replyId + 6,
                     ((s_msginfo*) e2) -> msgId + 6);
}


static int checkEntry(void *e)
{
   char buff[256];
   sprintf(buff, "msg %ld has dupes in msgbase : trown from reply chain",
                 ((s_msginfo *) e) -> msgNum);
   writeLogEntry(log, '6', buff);
   return 1;
}

/* linking for msgid/reply */
int linkArea(s_area *area, int netMail)
{
   char buff[256];

   HAREA harea;
   HMSG  hmsg;
   XMSG  xmsg;
   dword msgsNum, i, ctlen;
   byte *ctl;

   s_msginfo  *prv, *curr, *tail, *orig;
   tree *avlTree;

   harea = MsgOpenArea((UCHAR *) area->fileName, MSGAREA_NORMAL,
                       area->msgbType | (netMail ? 0 : MSGTYPE_ECHO));
   if (harea) {
      sprintf(buff, "linking area %s", area->areaName);
      writeLogEntry(log, '6', buff);
      tree_init(&avlTree);
      msgsNum = MsgGetHighMsg(harea);
      /* Area linking is done in three passes */
      /* Pass 1st : read all message information in memory */

      for (i = 1, curr = prv = NULL; i <= msgsNum; i++, prv = curr) {
         hmsg  = MsgOpenMsg(harea, MOPEN_READ, i);
	 if (hmsg == NULL) {
            curr = prv;
	    continue;
	 }
         ctlen = MsgGetCtrlLen(hmsg);
         ctl   = (byte *) malloc(ctlen);
         curr  = calloc(1, sizeof(s_msginfo));

  if (ctl == NULL || curr == NULL) {
            sprintf(buff, "out of memory while linking on msg %ld", i);
            writeLogEntry(log, '9', buff);
            // try to free as much as possible
            // FIXME : remove blocks themselves
            tree_mung(&avlTree, NULL);
            MsgCloseMsg(hmsg);
            MsgCloseArea(harea);
            return 0;
         };

         curr -> prev = prv;
         MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, ctlen, ctl);
         curr -> msgNum = i;
         curr -> msgId   = (char *) GetCtrlToken(ctl, (byte *) "MSGID");
         curr -> replyId = (char *) GetCtrlToken(ctl, (byte *) "REPLY");
         curr -> subject = strdup(xmsg.subj);
         curr -> msgPos  = MsgMsgnToUid(harea, i);
         free(ctl);
         if (curr -> msgId != NULL)  // This msg would don't have reply links
            tree_add(&avlTree, &compareEntries, (char *) curr, &checkEntry);

         MsgCloseMsg(hmsg);
      };
      /* Pass 2nd : going from the last msg to first search for reply links and
        build relations*/
      for (tail = curr; curr != NULL; curr = curr -> prev) {
        if (curr -> replyId != NULL && (orig = (s_msginfo *) tree_srch(
            &avlTree, &findEntry, (char *) curr)) != NULL)
           if (orig -> freeReply >= MAX_REPLY) {
              sprintf(buff, "replies count for msg %ld exceeds %d, rest of the\
replies won't be linked", orig -> msgNum, MAX_REPLY);
              writeLogEntry(log, '6', buff);
           } else {
              orig -> replies[(orig -> freeReply)++] = curr -> msgPos;
              curr -> replyToPos = orig -> msgPos;
           };
      };
      /* Pass 3rd : write information back to msgbase */
      for (curr = tail; curr != NULL; ) {
         hmsg  = MsgOpenMsg(harea, MOPEN_READ, curr -> msgNum);
         MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
         memcpy(xmsg.replies, curr->replies, sizeof(UMSGID) * MAX_REPLY);
         xmsg.replyto = curr->replyToPos;
         MsgWriteMsg(hmsg, 0, &xmsg, NULL, 0, 0, 0, NULL);
         MsgCloseMsg(hmsg);
         /* free this node */
         prv = curr -> prev;
         free(curr -> msgId);
         free(curr -> replyId);
         free(curr -> subject);
         free(curr); curr = prv;
      };
      /* close everything, free all allocated memory */
      tree_mung(&avlTree, NULL);
      MsgCloseArea(harea);
   } else {
      sprintf(buff, "could not open area %s", area->areaName);
      writeLogEntry(log, '9', buff);
      return 0;
   };
   return 1;
}

void linkAreas(void)
{
   FILE *f;
   char *line;
   s_area *area;
   int i;

   // open importlog file

   if ((config->LinkWithImportlog != NULL) && (stricmp(config->LinkWithImportlog, "no")!=0)){
      f = fopen(config->importlog, "r");
   } else {
      f = NULL;
   }

   if (f == NULL) {
      // if importlog does not exist link all areas
      writeLogEntry(log, '3', "Linking all Areas.");

      /* link all echomail areas */
      for (i = 0; i < config -> echoAreaCount; i++)
         if (config -> echoAreas[i].dupeCheck != dcOff)
            linkArea(&(config -> echoAreas[i]), 0);
      /* link NetMailArea */
      linkArea(&(config->netMailArea),1);

   } else {
      writeLogEntry(log, '3', "Using importlogfile -> linking only listed Areas");

      while (!feof(f)) {
         line = readLine(f);

         if (line != NULL) {
            if(strcmp(config->netMailArea.areaName,line)==0) linkArea(&(config->netMailArea),1);
            else {
               area = getArea(config, line);
               if ((area->dupeCheck != dcOff) && (area->areaName != config->badArea.areaName)) linkArea(area,0);
               free(line);
            }
         }
      }
      fclose(f);
      if (stricmp(config->LinkWithImportlog, "kill")==0) remove(config->importlog);
   }
}
