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
   28.11.99 - write modified chains only (by L. Lisowsky 2:5020/454.2)
 */

/*
   For now reply linking is performed using the msgid/reply kludges
   TODO:
     linking flat, subject linking
     SPEEDUP!!!!!!!!!!!
   FIXME:	do better when finding if msg links need to be updated
   		The problem with original patch by Leonid was that if msg had 
		some reply links written in replies or replyto fields but
		no replies were found during linkage reply&replyto fields won't
		be cleared. I (KN) have applied some quick&dirty patch to fix this 
		problem, but it's not enough.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(MSDOS) || defined(__DJGPP__)
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
   short freeReply;
   char relinked;

   struct msginfo *prev;
};

typedef struct msginfo s_msginfo;

static int  compareEntries(const void *e1, const void *e2)
{
   return stricmp(((s_msginfo*) e1) -> msgId,
                     ((s_msginfo*) e2) -> msgId);
}

static int  findEntry(const void *e1, const void *e2)
{
   return stricmp(((s_msginfo*) e1) -> replyId,
                     ((s_msginfo*) e2) -> msgId);
}


static int checkEntry(void *e)
{
   writeLogEntry(hpt_log, '6', "msg %ld has dupes in msgbase : trown from reply chain",
                 ((s_msginfo *) e) -> msgNum);
   return 1;
}

static char *GetKludgeText(byte *ctl, char *kludge)
{
   char *pKludge, *pToken;

   pToken = (char *) GetCtrlToken(ctl, (byte *)kludge);
   if (pToken) {
      pKludge = strdup(pToken+1+strlen(kludge));
      free(pToken);
      return pKludge;
   } else
      return NULL;
}

/* linking for msgid/reply */
int linkArea(s_area *area, int netMail)
{

   HAREA harea;
   HMSG  hmsg;
   XMSG  xmsg;
   dword msgsNum, i, ctlen;
   byte *ctl;

   s_msginfo  *prv, *curr, *tail, *orig;
   tree *avlTree;

   if (area->msgbType == MSGTYPE_PASSTHROUGH) return 0;

   harea = MsgOpenArea((UCHAR *) area->fileName, MSGAREA_NORMAL,
/*							  area->fperm, area->uid, area->gid,*/
                       area->msgbType | (netMail ? 0 : MSGTYPE_ECHO));
   if (harea) {
      writeLogEntry(hpt_log, '2', "linking area %s", area->areaName);
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
         if( ctlen == 0 )
         {
             MsgCloseMsg(hmsg);
             writeLogEntry(hpt_log, '6', "msg %ld has no control information: trown from reply chain", i);
             continue;
         }

         ctl   = (byte *) malloc(ctlen + 1);
         curr  = calloc(1, sizeof(s_msginfo));

	 if (ctl == NULL || curr == NULL) {
	    writeLogEntry(hpt_log, '9', "out of memory while linking on msg %ld", i);
	    // try to free as much as possible
	    // FIXME : remove blocks themselves
	    tree_mung(&avlTree, NULL);
	    MsgCloseMsg(hmsg);
	    MsgCloseArea(harea);
            return 0;
         }

         curr -> prev = prv;
         MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, ctlen, ctl);
	 ctl[ctlen] = '\0';
         curr -> msgNum = i;
         curr -> msgId   = GetKludgeText(ctl, "MSGID");
         curr -> replyId = GetKludgeText(ctl, "REPLY");
         curr -> subject = strdup((char *)xmsg.subj);
         curr -> msgPos  = MsgMsgnToUid(harea, i);
	 /* Copy old information, maybe we don't need to write this msg */
	 curr -> replyToPos = xmsg.replyto;
	 memcpy(curr -> replies, xmsg.replies, sizeof(UMSGID) * MAX_REPLY); 
	 curr -> freeReply = 0;

         curr -> relinked = 0;
         free(ctl);
         if (curr -> msgId != NULL)  // This msg would don't have reply links
            tree_add(&avlTree, &compareEntries, (char *) curr, &checkEntry);

         MsgCloseMsg(hmsg);
      }
      /* Pass 2nd : going from the last msg to first search for reply links and
        build relations*/
      for (tail = curr; curr != NULL; curr = curr -> prev) {
	      if (curr -> replyId != NULL && (orig = (s_msginfo *) tree_srch(
 	           &avlTree, &findEntry, (char *) curr)) != NULL) {
		      if (orig -> freeReply >= MAX_REPLY) {
			      writeLogEntry(hpt_log, '6', "replies count for msg %ld exceeds %d," \
					      "rest of the replies won't be linked", orig -> msgNum, MAX_REPLY);
		      } else {
			      if (orig -> replies[orig -> freeReply] != curr -> msgPos) {
				      orig -> replies[orig -> freeReply] = curr -> msgPos;
				      orig -> relinked = 1;
			      }
			      (orig -> freeReply)++;
			      if (curr -> replyToPos != orig -> msgPos) {              
				      curr -> replyToPos = orig -> msgPos;
				      curr -> relinked = 1;
			      }
		      }
	      }
      }
      /* Pass 3rd : write information back to msgbase */
      for (curr = tail; curr != NULL; ) {
         hmsg  = MsgOpenMsg(harea, MOPEN_RW, curr -> msgNum);
         if ((hmsg != NULL) && (curr->relinked != 0)) {
             int need_write = 0;
	     MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
	     memset(curr->replies + curr->freeReply, 0, sizeof(UMSGID) * (MAX_REPLY - curr->freeReply));
	     /* FIXME: need a better solution*/
	     if (memcmp(xmsg.replies, curr->replies, sizeof(UMSGID) * MAX_REPLY)) {
		     need_write = 1;
		     memcpy(xmsg.replies, curr->replies, sizeof(UMSGID) * MAX_REPLY);
	     };
	     if	(xmsg.replyto != curr->replyToPos) {
		     need_write = 1;
		     xmsg.replyto = curr->replyToPos;
	     };
	     if (need_write) MsgWriteMsg(hmsg, 0, &xmsg, NULL, 0, 0, 0, NULL);
	     MsgCloseMsg(hmsg);
	 }
         /* free this node */
         prv = curr -> prev;
         free(curr -> msgId);
         free(curr -> replyId);
         free(curr -> subject);
         free(curr); curr = prv;
      }
      /* close everything, free all allocated memory */
      tree_mung(&avlTree, NULL);
      MsgCloseArea(harea);
   } else {
      writeLogEntry(hpt_log, '9', "could not open area %s", area->areaName);
      return 0;
   }
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
      writeLogEntry(hpt_log, '3', "Linking all Areas.");

      /* link all echomail areas */
      for (i = 0; i < config -> echoAreaCount; i++)
//         if (config -> echoAreas[i].dupeCheck != dcOff)
            linkArea(&(config -> echoAreas[i]), 0);
      /* link NetMailAreas */
      for (i = 0; i < config -> netMailAreaCount; i++)
         linkArea(&(config -> netMailAreas[i]), 1);

   } else {
      writeLogEntry(hpt_log, '3', "Using importlogfile -> linking only listed Areas");

      while (!feof(f)) {
         line = readLine(f);

         if (line != NULL) {
		 
            if ((area = getNetMailArea(config, line)) != NULL) {
	       linkArea(area,1);
	    } else {
               area = getArea(config, line);
               if /*(area->dupeCheck != dcOff) && */ (area->areaName != config->badArea.areaName) linkArea(area,0);
               free(line);
            }
         }
      }
      fclose(f);
      if (stricmp(config->LinkWithImportlog, "kill")==0) remove(config->importlog);
   }
}
