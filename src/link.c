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
		be cleared. 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef OS2
#define INCL_DOSFILEMSG /* for DosSetMaxFH() */
#include <os2.h>
#endif

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/typesize.h>

#include <smapi/msgapi.h>

#include <log.h>
#include <global.h>
#include <tree.h>
#include <fcommon.h>

/* internal structure holding msg's related to link information */
/* used by linkArea */
struct msginfo {
   char *msgId;
   char *replyId;
   HMSG msgh;
   XMSG *xmsg;
   UMSGID msgPos; 

   short freeReply;
   char relinked;
   UMSGID replyto, replynext;
   UMSGID replies[MAX_REPLY];
};

struct hashinfo {
   dword crc;
   int idx;
};

typedef struct msginfo s_msginfo;
unsigned long strcrc32(char *, unsigned long);

static s_msginfo *findMsgId(s_msginfo *entries, struct hashinfo *hash, dword hashSize, char *msgId, int add)
{
	unsigned long h, d = 1;
	dword crc;
	h = crc = strcrc32(msgId, 0xFFFFFFFFL); /* TODO: Maybe find a better hashing function */
	while (d < hashSize) {
		h %= hashSize;
		if (hash[h].idx == 0) {
			/* Found free entry */
			if (!add) return NULL;
			hash[h].idx = add;
			hash[h].crc = crc;
			return &(entries[add-1]);
		}
		if (hash[h].crc == crc && !strcmp(entries[hash[h].idx-1].msgId, msgId)) {
			/* Found it ! */
			return &(entries[hash[h].idx-1]);
		} else {
			/* Collision, resolve it */
			h++; 
			d++;
		};
	};
	return NULL;
}

static char *GetKludgeText(byte *ctl, char *kludge)
{
   char *pKludge, *pToken;
   s_addr addr;

   pToken = (char *) GetCtrlToken(ctl, (byte *)kludge);
   if (pToken) {
      pKludge = safe_strdup(pToken+1+strlen(kludge));
      nfree(pToken);
      /* convert 5D-address to 4D */
      for (pToken=pKludge; *pToken && (isdigit(*pToken) || *pToken==':' || *pToken=='/' || *pToken=='.'); pToken++);
      if (*pToken=='@') {
         string2addr(pKludge, &addr);
	 if (addr.zone && addr.net)
            *pToken = '\0';
      }
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
   s_msginfo *msgs;   
   dword msgsNum, hashNums, i, ctlen, cctlen;
   struct hashinfo *hash;
   byte *ctl;
   char *msgId;

   s_msginfo *curr;

   if (area->msgbType == MSGTYPE_PASSTHROUGH) return 0;

   if (area->nolink) {
     w_log('3', "%s has nolink option, ignoring", area->areaName);
     return 0;
   }

   harea = MsgOpenArea((UCHAR *) area->fileName, MSGAREA_NORMAL,
/*							  area->fperm, area->uid, area->gid,*/
                       (word)(area->msgbType | (netMail ? 0 : MSGTYPE_ECHO)));
   if (harea) {
      w_log('3', "linking area %s", area->areaName);
      msgsNum = MsgGetNumMsg(harea);
      if (msgsNum < 2) { /* Really nothing to link */
	      MsgCloseArea(harea);
	      return 0;
      };
#ifdef OS2
      if (area->msgbType & MSGTYPE_SDM)
#if defined(__WATCOMC__)
              _grow_handles(msgsNum+20);
#else /* EMX */
              DosSetMaxFH(msgsNum+20);
#endif
#endif

      hashNums = msgsNum + msgsNum / 10 + 10;
      hash = safe_malloc(hashNums * sizeof(*hash));
      memset(hash, '\0', hashNums * sizeof(*hash));
      msgs = safe_malloc(msgsNum * sizeof(s_msginfo));
      memset(msgs, '\0', msgsNum * sizeof(s_msginfo));
      ctl = (byte *) safe_malloc(ctlen = 1); /* Some libs don't accept relloc(NULL, ..
					 * So let it be initalized
					 */
      /* Area linking is done in three passes */
      /* Pass 1st : read all message information in memory */

      for (i = 1; i <= msgsNum; i++) {
		  hmsg  = MsgOpenMsg(harea, MOPEN_READ|MOPEN_WRITE, i);
		  if (hmsg == NULL) {
			  continue;
		  }
		  cctlen = MsgGetCtrlLen(hmsg);
		  if( ctlen == 0 )
			  {
				  MsgCloseMsg(hmsg);
				  w_log('6', "msg %ld has no control information: trown from reply chain", i);
				  continue;
			  }

		  if (cctlen > ctlen) {
			  ctlen = cctlen;
			  ctl   = (byte *) safe_realloc(ctl, cctlen + 1);
		  };

		  if (ctl == NULL) {
			  w_log('9', "out of memory while linking on msg %ld", i);
			  // try to free as much as possible
			  // FIXME : remove blocks themselves
			  nfree(ctl);
			  MsgCloseMsg(hmsg);
			  MsgCloseArea(harea);
			  return 0;
		  }

		  MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, ctlen, ctl);
		  ctl[ctlen] = '\0';
		  msgId   = GetKludgeText(ctl, "MSGID");
		  if (msgId == NULL) {
			  w_log('6', "msg %ld haven't got any MSGID, replying is not possible", i);
			  MsgCloseMsg(hmsg);
			  continue;
		  }
		  curr = findMsgId(msgs, hash, hashNums, msgId, i);
		  if (curr == NULL) {
			  w_log('6', "hash table overflow. Tell it to the developers !"); 
			  // try to free as much as possible
			  // FIXME : remove blocks themselves
			  nfree(msgId);
			  MsgCloseMsg(hmsg);
			  MsgCloseArea(harea);
			  return 0;
		  };
		  if (curr -> msgId != NULL) {
			  w_log('6', "msg %ld has dupes in msgbase :" \
							" trown from reply chain", i);
			  MsgCloseMsg(hmsg);
			  nfree(msgId);
			  continue;
		  }
		  curr -> msgId = msgId; curr -> msgh = hmsg; 
		  curr -> xmsg = memdup(&xmsg, sizeof(XMSG));
		  curr -> replyId = GetKludgeText(ctl, "REPLY");
		  curr -> msgPos  = MsgMsgnToUid(harea, i);
		  curr -> freeReply = 0;
		  curr -> relinked = 0;
		  curr -> replyto = curr -> replynext = 0;
      }

      /* Pass 2nd : search for reply links and build relations*/
      for (i = 0; i < msgsNum; i++) {
	      if (msgs[i].msgId != NULL && msgs[i].replyId != NULL) {
		      curr = findMsgId(msgs, hash, hashNums, msgs[i].replyId, 0);
		      if (curr == NULL) continue;
		      if (curr -> msgId == NULL) continue;
		      if (curr -> freeReply >= MAX_REPLY-4 &&
		          (area->msgbType & (MSGTYPE_JAM | MSGTYPE_SDM))) {
				  curr -> freeReply--;
				  curr -> replies[curr -> freeReply - 1] = curr -> replies[curr -> freeReply];
		      }
		      if (curr -> freeReply < MAX_REPLY) {
			      curr -> replies[curr -> freeReply] = i;
			      if (curr -> xmsg -> replies[curr -> freeReply] != msgs[i].msgPos) {
				      curr -> xmsg -> replies[curr -> freeReply] = msgs[i].msgPos;
				      if ((area->msgbType & MSGTYPE_SQUISH) || curr->freeReply == 0)
						  curr -> relinked = 1;
			      }
			      if (curr -> freeReply && (area->msgbType & MSGTYPE_JAM)) {
					  int replyprev = curr -> replies[curr -> freeReply - 1];
					  msgs[replyprev].replynext = msgs[i].msgPos;
					  if (msgs[replyprev].xmsg -> xmreplynext != msgs[i].msgPos) {
						  msgs[replyprev].xmsg -> xmreplynext = msgs[i].msgPos;
						  msgs[replyprev].relinked = 1;
					  }
			      }
			      (curr -> freeReply)++;
			      msgs[i].replyto = curr -> msgPos;
			      if (msgs[i].xmsg -> replyto != curr -> msgPos) {
				      msgs[i].xmsg -> replyto = curr -> msgPos;
				      msgs[i].relinked = 1;
			      }
		      } else {
			      w_log('6', "msg %ld: replies count for msg %ld exceeds %d, rest of the replies won't be linked",i+1, curr-msgs+1,MAX_REPLY);
		      }
	      }
      }

      /* Pass 3rd : write information back to msgbase */
      for (i = 0; i < msgsNum; i++) {
	if (msgs[i].msgId != NULL) {
		int j;
		for (j=0; j<MAX_REPLY && msgs[i].xmsg->replies[j]; j++);
		if (msgs[i].relinked != 0 ||
		    msgs[i].replyto != msgs[i].xmsg->replyto ||
		    ((area->msgbType & MSGTYPE_JAM) && msgs[i].replynext != msgs[i].xmsg->xmreplynext) ||
		    ((area->msgbType & MSGTYPE_SQUISH) && msgs[i].freeReply != j) ||
		    (msgs[i].freeReply == 0 && j)) {
			if (msgs[i].freeReply<MAX_REPLY)
				msgs[i].xmsg->replies[msgs[i].freeReply] = 0;
			msgs[i].xmsg->replyto = msgs[i].replyto;
			if (area->msgbType & MSGTYPE_JAM)
				msgs[i].xmsg->xmreplynext = msgs[i].replynext;
			MsgWriteMsg(msgs[i].msgh, 0, msgs[i].xmsg, NULL, 0, 0, 0, NULL);
		}
	        MsgCloseMsg(msgs[i].msgh);
	 
         /* free this node */
		nfree(msgs[i].msgId);
		nfree(msgs[i].replyId);
		nfree(msgs[i].xmsg);
	};
      }
      /* close everything, free all allocated memory */
      nfree(msgs);
      nfree(hash);
      nfree(ctl);
      MsgCloseArea(harea);
   } else {
      w_log('9', "could not open area %s", area->areaName);
      return 0;
   }
   return 1;
}

void linkAreas(char *name)
{
   FILE *f;
   char *line;
   s_area *area;
   int i;

   // link only one area
   if (name != NULL) {
	   if ((area = getNetMailArea(config, name)) != NULL) {
	       linkArea(area,1);
	   } else {
		   area = getArea(config, name);
		   if (area->areaName != config->badArea.areaName) linkArea(area,0);
		   else w_log('9', "area %s not found for link",name);
	   }
	   return;
   }

   // open importlog file
   if (config->LinkWithImportlog != lwiNo) {
      f = fopen(config->importlog, "r");
   } else {
      f = NULL;
   }

   if (f == NULL) {
      // if importlog does not exist link all areas
      w_log('3', "Linking all Areas.");

      /* link all echomail areas */
      for (i = 0; i < config -> echoAreaCount; i++)
            linkArea(&(config -> echoAreas[i]), 0);
      /* link all local areas */
      for (i = 0; i < config -> localAreaCount; i++)
            linkArea(&(config -> localAreas[i]), 0);
      /* link NetMailAreas */
      for (i = 0; i < config -> netMailAreaCount; i++)
         linkArea(&(config -> netMailAreas[i]), 1);

   } else {
      w_log('3', "Using importlogfile -> linking only listed Areas");

      while (!feof(f)) {
         line = readLine(f);

         if (line != NULL) {
		 
            if ((area = getNetMailArea(config, line)) != NULL) {
	       linkArea(area,1);
	    } else {
               area = getArea(config, line);
               if /*(area->dupeCheck != dcOff) && */ (area->areaName != config->badArea.areaName) linkArea(area,0);
               nfree(line);
            }
         }
      }
      fclose(f);
      if (config->LinkWithImportlog == lwiKill) remove(config->importlog);
   }
}
