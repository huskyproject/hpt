/*
 *      hptlink - areas linker for Highly Portable Tosser (hpt)
 *      by Serguei Revtov 2:5021/11.10 || 2:5021/19.1
 *      Some code was taken from hpt/src/link.c by Kolya Nesterov
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
 *****************************************************************************
 * $Id$
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>


#include <huskylib/compiler.h>

#ifdef HAS_IO_H
#include <io.h>
#endif

#ifdef HAS_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAS_SHARE_H
#include <share.h>
#endif

#include <smapi/msgapi.h>
#include <fidoconf/common.h>
#include <fidoconf/xstr.h>

#include <version.h>
#include <global.h>
#include "cvsdate.h"


/* internal structure holding msg's related to link information */
/* used by linkArea */
struct msginfo {
   char *replyId;
   char *msgId;
   char *subject;
   UMSGID replyToPos;
   UMSGID replies[MAX_REPLY];
   UMSGID treeId;
   int freeReply;
   UMSGID msgPos;

};
typedef struct msginfo s_msginfo;

#define reply1st replies[0]
#define replyNxt replies[1]


struct origlinks {
   UMSGID replyToPos;
   UMSGID replies[MAX_REPLY];
};
typedef struct origlinks s_origlinks;

#define LOGFILENAME "hptlink.log"

s_log        *hptlink_log = NULL;
s_fidoconfig *config;

char *version = NULL;

int singleRepl = 1;
int hardSearch = 0;
int useSubj = 1;
int useReplyId = 1;
int loglevel = 10;
int linkNew = 0;
HAREA harea;
int maxreply;


long links_msgid=0L;
long links_replid=0L;
long links_subj=0L;
long links_revmsgid=0L;
long links_total=0L;
long links_ignored=0L;

char *skipReSubj ( char *subjstr )
{
   char *ptr;

   if ( !subjstr ) return (NULL);

   if ( *subjstr != 'R' && *subjstr != 'r' ) return (NULL);
   subjstr++;

   if ( *subjstr != 'e' && *subjstr != 'E' ) return (NULL);
   subjstr++;

   if ( *subjstr == '^' ) {
      subjstr++;
      while ( isdigit (*subjstr) ) subjstr++;
   }

   if ( *subjstr != ':' ) return (NULL);
   subjstr++;

   while ( *subjstr == ' ' ) subjstr++;

   if ( (ptr = skipReSubj ( subjstr )) != NULL ) subjstr = ptr;

   return (subjstr);

}

int cmpMsgIdReply (register char *str1, register char *str2)
{
    while (*str1==*str2 && *str1) {
	if (*str1=='@') while (*str1 && *str1!=' ') str1++; /*  skip domain */
	if (*str1) str1++;
	if (*str2=='@') while (*str2 && *str2!=' ') str2++; /*  skip domain */
	if (*str2) str2++;
    }
    if (*str1=='\0' && *str2=='\0') return 0;
    return 1;
}

void linkMsgs ( s_msginfo *crepl, s_msginfo *srepl, dword i, dword j, s_msginfo *replmap )
{
    dword  linkTo;

    if (crepl -> msgId && srepl -> msgId &&
        strcmp ( crepl -> msgId, srepl -> msgId) == 0) {
        w_log( LL_WARN, "Warning: msg %ld is dupe to %ld", (long)i, (long)j);
        links_ignored++;
        return;
    }

    if (maxreply == MAX_REPLY) { /*  Squish */
      if (crepl -> freeReply >= maxreply)
      {
        w_log( LL_WARN, "replies count for msg %ld exceeds %d, rest of the replies won't be linked", (long)j, maxreply);
        links_ignored++;
      } else {
          links_total++;
          (crepl -> replies)[(crepl -> freeReply)++] = srepl->msgPos;
          srepl -> replyToPos = crepl->msgPos;
      }

    } else { /*  Jam, maybe something else? */

        if(srepl -> replyToPos) {
           w_log( LL_WARN, "Thread linking broken because of dupes");
           links_ignored++;
           return;
        }

        srepl -> replyToPos = crepl->msgPos;
        links_total++;
        if (crepl->reply1st == 0) {
            crepl->reply1st = srepl->msgPos;
            (crepl -> freeReply)++;
        } else {
            linkTo = MsgUidToMsgn(harea, crepl->reply1st, UID_EXACT) - 1;
	    if(linkTo == -1) {
		w_log( LL_WARN, "Thread linking broken. MsgUidToMsgn() returned -1");
		links_ignored++;
		return;
	    }

            while (replmap[linkTo].replyNxt) {
		linkTo = MsgUidToMsgn(harea, replmap[linkTo].replyNxt, UID_EXACT) - 1;
		if(linkTo == -1) {
		    w_log( LL_WARN, "Thread linking broken. MsgUidToMsgn() returned -1");
		    links_ignored++;
		    return;
		}
	    }
            replmap[linkTo].replyNxt = srepl->msgPos;
            replmap[linkTo].freeReply++;
        }
    }
}

static char *GetCtrlValue (char *ctl, char *kludge)
{
   char *value, *end, *out, *p;

   if ( !ctl || !kludge ) return (NULL);

   if ( (value = strstr( ctl, kludge)) == NULL ) return (NULL);

   if ( value[-1] != '\001') return (NULL);

   value += strlen(kludge); /* skip kludge name (i.e. MSGID: or REPLY:) */

   for (end = value; *end != '\001' && *end; end++);

   if ((end - value) <= 0) return (NULL);

   out = (char *) smalloc((size_t) (end - value) + 1 );
   if (out == NULL) return (NULL);

   memcpy(out, value, (size_t) (end - value));
   out[(size_t) (end - value)] = '\0';

   /*  fix for upper case msgids */
   strLower(out);
   /*  remove .0 from node address */
   if (NULL!=(p=strstr(out,".0 "))) memmove(p,p+2,strlen(p+2)+1);

   return out;

}


void linkArea(s_area *area)
{
   byte *ctl = NULL;
   dword ctlen_curr=0;
   dword ctlen;
   dword highMsg;
   dword  i, j, linkTo;
   dword newStart=0;
   HMSG  hmsg;
   XMSG  xmsg;
   s_msginfo *replmap;
   s_msginfo *crepl, *srepl;
   s_origlinks *links;
   s_origlinks *linksptr;
   dword treeLinks=0;
   int replFound;
   int replDone;
   char *ptr;

   if ((area->msgbType & MSGTYPE_PASSTHROUGH) == MSGTYPE_PASSTHROUGH) {
     w_log( LL_LINKING, "PASSTHROUGH area %s, skip", area->areaName);
     return;
   }

   if (area->nolink) {
     w_log( LL_LINKING, "area %s has nolink option, skip", area->areaName);
     return;
   }

   w_log( LL_LINKING, "linking area %s...", area->areaName);

   if (area->msgbType & MSGTYPE_JAM || area->msgbType & MSGTYPE_SDM) {
      maxreply = 2;
   } else {
      maxreply = MAX_REPLY;
   }

   harea = MsgOpenArea((byte *) area->fileName, MSGAREA_NORMAL, (word)area->msgbType);

   if (harea)
   {
	   highMsg = MsgGetHighMsg(harea);

	   if ( highMsg < 2 ) {
	      w_log( LL_LINKING, "nothing to link (%ld messages)", (long)highMsg);
	      MsgCloseArea(harea);
	      return;
	   }

	   if ( (replmap = (s_msginfo *) scalloc (highMsg, sizeof(s_msginfo))) == NULL){
	      w_log( LL_CRIT,"Out of memory. Want %ld bytes",  (long) sizeof(s_msginfo)*highMsg);
	      MsgCloseArea(harea);
	      closeLog();
              disposeConfig(config);
	      exit(EX_SOFTWARE);
	   }

	   if ( (links = (s_origlinks *) scalloc (highMsg, sizeof(s_origlinks))) == NULL){
	      w_log( LL_CRIT, "Out of memory: can't get %ld bytes",  (long) sizeof(s_origlinks)*highMsg);
	      MsgCloseArea(harea);
	      closeLog();
              disposeConfig(config);
	      exit(EX_SOFTWARE);
	   }

	   /* Pass 1: read all message information in memory */
	   w_log( LL_LINKPASS, "Pass 1 - reading");

	   for (i = 1, crepl=replmap, linksptr=links; i <= highMsg; i++, crepl++, linksptr++) {
	      hmsg  = MsgOpenMsg(harea, MOPEN_READ, i);
	      if (hmsg){
		 ctlen = MsgGetCtrlLen(hmsg);
		 if( ctlen == 0 )
		 {
		    w_log( LL_WARN, "msg %ld has no control information", (long) i);
		    MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);

		 } else {
		   if( ctl==NULL || ctlen_curr < ctlen + 1) {

		      ctl = (byte *) srealloc(ctl, ctlen + 1);
		      if (ctl == NULL) {
			w_log( LL_CRIT,"out of memory while linking on msg %ld", (long) i);
			MsgCloseArea(harea);
                        closeLog();
                        disposeConfig(config);
			exit(EX_SOFTWARE);
		      }

		      ctlen_curr = ctlen + 1;
		   }
		   MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, ctlen, ctl);

		   ctl[ctlen] = '\0';

		   if ( useReplyId ) {
		      crepl -> replyId = (char *) GetCtrlValue( (char *)ctl, "REPLY:");
		      crepl -> msgId = (char *) GetCtrlValue( (char *)ctl, "MSGID:");
		   }

		 }

		 if ( useSubj && xmsg.subj != NULL) {
		    if ( (ptr=skipReSubj((char*)xmsg.subj)) == NULL)
                  ptr = (char*) xmsg.subj;
		    crepl -> subject = sstrdup(ptr);
		 }

                 crepl->msgPos = MsgMsgnToUid(harea, i);

		 /*  Save data for comparing */
                 if (area->msgbType & MSGTYPE_JAM || area->msgbType & MSGTYPE_SDM) {
                    linksptr->reply1st = xmsg.xmreply1st;
                    linksptr->replyNxt = xmsg.xmreplynext;
                 } else {
                    memcpy(linksptr->replies, xmsg.replies, sizeof(UMSGID) * MAX_REPLY);
                 }
		 linksptr->replyToPos = xmsg.replyto;

                 if (linkNew) {
                    if (area->msgbType & MSGTYPE_JAM || area->msgbType & MSGTYPE_SDM) {
                       if (xmsg.replyto || xmsg.xmreply1st || xmsg.xmreplynext) {
                          newStart = i+1;
                          crepl->replyToPos = xmsg.replyto;
                          crepl->reply1st = xmsg.xmreply1st;
                          crepl->replyNxt = xmsg.xmreplynext;
                       }

                    } else {

                       if (xmsg.replyto || xmsg.replies[0]) {
                          newStart = i+1;
                          memcpy(crepl->replies, xmsg.replies, sizeof(UMSGID) * MAX_REPLY);
                          crepl->replyToPos = xmsg.replyto;
                          for (j=0; xmsg.replies[j] && j<MAX_REPLY; j++);
                          crepl->freeReply = j;
                       }
                    }
                 }

		 MsgCloseMsg(hmsg);
	      }
	   }

	   /* Pass 2: building relations tree, & filling tree IDs */
	   if ( loglevel >= 11 ) {
              if (linkNew)
                 w_log(LL_LINKPASS, "Pass 2: building relations for %ld messages, new from %ld", (long) i-1, (long) newStart);
              else
                 w_log(LL_LINKPASS, "Pass 2: building relations for %ld messages", (long) i-1);
           }

	   for (i = 1, crepl=replmap; i < highMsg; i++, crepl++) {
	     if (
		  crepl -> replyId ||
		  crepl -> msgId   ||
		  crepl -> subject
		) {

		replDone = 0;

                j=i+1;
                srepl=crepl+1;
                if (newStart > j) {
                   j=newStart;
                   srepl = &(replmap[j-1]);
                }
		for (; j <= highMsg && !replDone; j++, srepl++ ) {

		  replFound = 0;

		  if (!replFound &&
		      (crepl -> msgId) && (srepl -> replyId) &&
		      cmpMsgIdReply (crepl -> msgId, srepl -> replyId) == 0 ) {

		       replFound++;
		       links_msgid++;

		       if ( ! crepl -> treeId ) { /*  *crepl isn't linked */
			  if (srepl -> treeId ) { /*  *srepl linked already */
			     crepl -> treeId = srepl -> treeId;
			  } else {
                             crepl -> treeId = i; /*  top of new tree */
			  }
		       }
		       srepl -> treeId = crepl -> treeId;

		       if (singleRepl) {
			  treeLinks++;
		       } else {
			  linkMsgs ( crepl, srepl, i, j, replmap );
		       }
		  }

		  if ( !replFound &&
		       (crepl -> treeId == 0 || srepl -> treeId == 0) &&
		       crepl -> replyId && srepl -> replyId) {
		      if ( cmpMsgIdReply (crepl -> replyId, srepl -> replyId) == 0 &&
			   strcmp(crepl -> replyId, "  ffffffff")) {

			  replFound++;
			  links_replid++;

			  if ( ! crepl -> treeId ) { /*  *crepl isn't linked */
			      if (srepl -> treeId ) { /*  *srepl linked already */
				  crepl -> treeId = srepl -> treeId;
			      } else {
				  crepl -> treeId = i; /*  top of new tree */
			      }
			  }
			  srepl -> treeId = crepl -> treeId;

			  treeLinks++;
		      }
		  }

		  if (!replFound && (srepl -> msgId) && (crepl -> replyId)) {
		      if ( cmpMsgIdReply (srepl -> msgId, crepl -> replyId) == 0 ) {
			  replFound++;
			  links_revmsgid++;

		       if ( ! crepl -> treeId ) { /*  *crepl isn't linked */
			  if (srepl -> treeId ) { /*  *srepl linked already */
			     crepl -> treeId = srepl -> treeId;
			  } else {
                             crepl -> treeId = i; /*  top of new tree */
			  }
		       }
		       srepl -> treeId = crepl -> treeId;

		       if (singleRepl) {
			  treeLinks++;
		       } else {
			  linkMsgs ( srepl, crepl, j, i, replmap );
		       }
		     }
		  }

		  if ( !replFound &&
		       (srepl -> treeId == 0) &&
		       crepl -> subject && srepl -> subject ) {

		     if ( strcmp ( crepl -> subject, srepl -> subject ) == 0 ) {

		       replFound++;
		       links_subj++;

		       if ( ! crepl -> treeId ) { /*  *crepl isn't linked */
			  if (srepl -> treeId ) { /*  *srepl linked already */
			     crepl -> treeId = srepl -> treeId;
			  } else {
                             crepl -> treeId = i; /*  top of new tree */
			  }
		       }
		       srepl -> treeId = crepl -> treeId;

		       treeLinks++;

		     }
		  }

		  if (replFound && singleRepl && !hardSearch ) replDone++;

		}
	     }
	   }

	   /* Pass 3: finding unlinked messages with filled tree IDs, and link
	    * them to the tree where possible
	    */
	   w_log(LL_LINKPASS, "Pass 3: buildng relations by treeIds");

	   for (i = 1, crepl=replmap; i <= highMsg && treeLinks; i++, crepl++) {
	      if ( crepl->replyToPos == 0 && crepl->freeReply == 0 &&
                   crepl->treeId && i != crepl->treeId ) {
		 /*  Link unlinked message */

		 linkTo = (replmap[crepl -> treeId -1 ]).treeId;
		 if (linkTo > highMsg || linkTo <= 0 ) {
		    w_log(LL_CRIT,"Programming error 1 while linking linkTo=%ld", (long)linkTo);
		    closeLog();
                    disposeConfig(config);
		    exit(EX_SOFTWARE);
		 }

                 if (maxreply == MAX_REPLY) { /*  Find place to put link for Squish */
                    while ( (replmap[linkTo-1]).freeReply >= maxreply) {
                       linkTo = MsgUidToMsgn(harea,(replmap[linkTo-1]).replies[0], UID_EXACT );
                       if (linkTo > highMsg || linkTo <= 0 ) {
                          w_log(LL_CRIT,"Programming error 2 while linking linkTo=%ld", (long)linkTo);
      	                  closeLog();
                          disposeConfig(config);
                          exit(EX_SOFTWARE);
                       }
                    }
                 }
		 linkMsgs ( &(replmap[linkTo-1]), crepl, linkTo, i , replmap );
		 (replmap[crepl -> treeId - 1]).treeId = i; /*  where to link next message */
		 treeLinks--;
	      }
	   }


	   /* Pass 4: write information back to msgbase */
	   w_log(LL_LINKPASS, "Pass 4: writing");

	   for (i = 1, crepl=replmap, linksptr=links; i <= highMsg; i++, crepl++, linksptr++) {

              if (area->msgbType & MSGTYPE_JAM || area->msgbType & MSGTYPE_SDM) {

                 if( (linksptr->replyToPos != crepl->replyToPos) ||
                     (linksptr->reply1st  != crepl->reply1st) ||
                     (linksptr->replyNxt  != crepl->replyNxt) ) {

                    hmsg  = MsgOpenMsg(harea, MOPEN_RW, i);

                    if (hmsg) {

		       MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
                       xmsg.replyto = crepl->replyToPos;
                       xmsg.xmreply1st = crepl->reply1st;
                       xmsg.xmreplynext = crepl->replyNxt;
		       MsgWriteMsg(hmsg, 0, &xmsg, NULL, 0, 0, 0, NULL);
		       MsgCloseMsg(hmsg);
		    }
                 }

              } else { /*  Not Jam */

                 if ((linksptr->replyToPos != crepl->replyToPos) ||
                     memcmp(linksptr->replies, crepl->replies, sizeof(UMSGID) * maxreply)) {

                    hmsg  = MsgOpenMsg(harea, MOPEN_RW, i);

                    if (hmsg) {

                       MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
                       memcpy(xmsg.replies, crepl->replies, sizeof(UMSGID) * maxreply);
                       xmsg.replyto = crepl->replyToPos;
                       MsgWriteMsg(hmsg, 0, &xmsg, NULL, 0, 0, 0, NULL);
                       MsgCloseMsg(hmsg);
                    }
                 }
	      }

	      if(crepl -> replyId) nfree(crepl -> replyId);
	      if(crepl -> subject) nfree(crepl -> subject);
	      if(crepl -> msgId  ) nfree(crepl -> msgId  );
	   }

	   MsgCloseArea(harea);

	   nfree(ctl);
	   nfree(replmap);
	   nfree(links);

	   w_log( LL_LINKING, "Linking area \"%s\" done", area->areaName);
   } else {
	   w_log( LL_ERR, "Could not open area %s", area->areaName);
   }
}

void usage(void) {

   printf( "%s\n", versionStr );
   printf( "Usage:\n hptlink [-t] [-s] [-a] [-r] [areaname ...]\n"
          "   -t - build reply TREE\n"
          "   -s - do not use Subject\n"
          "   -a - search in all messages (for singlethread only)\n"
          "   -r - do not use REPLY:/MSGID:\n"
          "   -n Link with 'new' messages only ('new' start from last linked + 1)\n"
         );
}

int main(int argc, char **argv) {

   int i, j;
   struct _minf m;
   char **argareas=NULL;
   char *line=NULL;
   int nareas=0;
   int found;
   FILE *f;
   s_area *area;

   setvar("module", "hpt");
   xscatprintf(&line, "%u.%u.%u", VER_MAJOR, VER_MINOR, VER_PATCH);
   setvar("version", line);
   nfree(line);
   SetAppModule(M_HPT);

   versionStr = GenVersionStr( "hptlink", VER_MAJOR, VER_MINOR, VER_PATCH,
                               VER_BRANCH, cvs_date );

   for (i=1; i<argc; i++) {
     if ( argv[i][0] == '-' ) {
	switch (argv[i][1])
	  {
	     case 't': /* Tree mode */
	     case 'T':
		singleRepl = 0;
		break;

	     case 's': /* do NOT use Subject field */
	     case 'S':
		useSubj = 0;
		break;
	     case 'a': /* search in all messages */
	     case 'A':
		hardSearch = 1;
		break;
	     case 'r': /* do NOT use REPLY:/MSGID: fields */
	     case 'R':
		useReplyId = 0;
		break;
	     case 'l':
	     case 'L':
	        break; /* obsolete */
	     case 'n': /* link with 'new' messages only */
	     case 'N':
		linkNew = 1;
		break;
	     default:
		usage();
		exit(EX_USAGE);
	  }
     } else {
       /*  AreaName(s) specified by args */
       nareas++;
       argareas = (char **)srealloc ( argareas, nareas*sizeof(char *));
       argareas[nareas-1] = argv[i];
     }
   }

   config = readConfig(NULL);

   if (!config) {
      fprintf(stderr, "Could not read fido config!\n");
      return (1);
   }

   if (config->logFileDir) {
        xstrscat(&line, config->logFileDir, LOGFILENAME, NULL);
        initLog(config->logFileDir, config->logEchoToScreen, config->loglevels, config->screenloglevels);
	hptlink_log = openLog(line, versionStr, config);
	nfree(line);
   }

   w_log(LL_PRG, "%s", versionStr);

   m.req_version = 0;
   m.def_zone = (UINT16) config->addr[0].zone;
   if (MsgOpenApi(&m)!= 0) {
      w_log(LL_CRIT, "MsgOpenApi Error.");
      closeLog();
      disposeConfig(config);
      exit(EX_SOFTWARE);
   }

   if ( argareas )
   {
     /*  link only specified areas */
     w_log(LL_LINKING, "Link areas specified by args");

     for ( j=0; j<nareas; j++) {

	found=0;

	/*  EchoAreas */
	for (i=0, area=config->echoAreas;
	     i < config->echoAreaCount && !found;
	     i++, area++) {
	    if (stricmp(area->areaName, argareas[j])==0){
		if (!area->scn) {
		    linkArea(area);
		    area->scn=1;
		}
		found++;
	    }
	}

	/*  Local Areas */
	for (i=0, area=config->localAreas;
	     i < config->localAreaCount && !found;
	     i++, area++) {
	    if (stricmp(area->areaName, argareas[j])==0){
		if (!area->scn) {
		    linkArea(area);
		    area->scn=1;
		}
		found++;
	    }
	}

	/*  NetMail areas */
	for (i=0, area=config->netMailAreas;
	     i < config->netMailAreaCount && !found;
	     i++, area++) {
	    if (stricmp(area->areaName, argareas[j])==0){
		if (!area->scn) {
		    linkArea(area);
		    area->scn=1;
		}
		found++;
	    }
	}

	if(!found) w_log(LL_WARN, "Couldn't find area \"%s\"", argareas[j]);
     }

   } else {

      if (config->LinkWithImportlog != lwiNo){
	 f = fopen(config->importlog, "r");
      } else {
	 f = NULL;
      }

      if ( f ) {
	 w_log(LL_INFO, "Using importlogfile -> linking only listed Areas");
	 while (!feof(f)) {
	    line = readLine(f);

	    if (line) {

	       found=0;
	       /*  EchoAreas */
	       for (i=0, area=config->echoAreas;
		    i < config->echoAreaCount && !found;
		    i++, area++) {
		   if (stricmp(area->areaName, line)==0){
		       if (!area->scn) {
			   linkArea(area);
			   area->scn=1;
		       }
		       found++;
		   }
	       }
	       /*  Local Areas */
	       for (i=0, area=config->localAreas;
		    i < config->localAreaCount && !found;
		    i++, area++) {
		   if (stricmp(area->areaName, line)==0){
		       if (!area->scn) {
			   linkArea(area);
			   area->scn=1;
		       }
		       found++;
		   }
	       }

	       /*  NetMail areas */
	       for (i=0, area=config->netMailAreas;
		    i < config->netMailAreaCount && !found;
		    i++, area++) {
		   if (stricmp(area->areaName, line)==0){
		       if (!area->scn) {
			   linkArea(area);
			   area->scn=1;
		       }
		       found++;
		   }
	       }

	       if(!found) w_log(LL_ERR, "Couldn't find area \"%s\"", line);
	       nfree(line);
	    }

	 }
	 fclose(f);
	 if (config->LinkWithImportlog == lwiKill) remove(config->importlog);
      } else {
	 /*  importlog does not exist link all areas */
	 w_log(LL_INFO, "No ImportLog file, linking all Areas");

	 /*  NetMails */
	 for (i = 0; i < config -> netMailAreaCount; i++)
	    linkArea (&(config->netMailAreas[i]));

	 /*  EchoAreas */
	 for (i=0; i < config->echoAreaCount; i++) linkArea(&(config->echoAreas[i]));

	 /*  Local Areas */
	 for (i=0; i < config->localAreaCount; i++) linkArea(&(config->localAreas[i]));
      }
   }

   w_log(LL_STAT, "Linked by msgid/reply: %ld, replid: %ld, subj: %ld, revmsgid: %ld", (long)links_msgid, (long)links_replid, (long)links_subj, (long)links_revmsgid);
   if (links_ignored)
      w_log(LL_SUMMARY, "Linked total: %ld, Ignored: %ld", (long) links_total, (long) links_ignored);
   else
      w_log(LL_SUMMARY, "Linked total: %ld", (long) links_total);

   w_log(LL_STOP, "Done");

   MsgCloseApi();
   closeLog();
   disposeConfig(config);
   return (0);
}
