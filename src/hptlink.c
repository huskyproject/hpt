/*
 *      hptlink - areas linker for High Portable Tosser (hpt)
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
*/

#include <stdio.h>
#include <ctype.h>

#ifdef UNIX
#include <unistd.h>
#include <strings.h>
#else
#include <io.h>
#endif

#ifdef __EMX__
#include <share.h>
#include <sys/types.h>
#else
#include <fcntl.h>
#endif
#include <sys/stat.h>

#include <smapi/msgapi.h>
#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>

#include <string.h>

#if defined ( __WATCOMC__ )
#include <smapi/prog.h>
#include <share.h>
#endif

#include <stdlib.h>


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


FILE *outlog;
int singleRepl = 1;
int hardSearch = 0;
int useSubj = 1;
int useReplyId = 1;
int loglevel = 10;
int linkNew = 0;
char *version = "1.7";
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


void linkMsgs ( s_msginfo *crepl, s_msginfo *srepl, dword i, dword j, s_msginfo *replmap )
{
    dword  linkTo;

    if (crepl -> msgId && srepl -> msgId &&
        strcmp ( crepl -> msgId, srepl -> msgId) == 0) {
        if (loglevel >= 15)
            fprintf(outlog, "Warning: msg %ld is dupe to %ld\n",
                    (long)i, (long)j);
        links_ignored++;
        return;
    }

    if (maxreply == MAX_REPLY) { // Squish
        if (crepl -> freeReply >= maxreply)
        {
            if ( loglevel >= 15) {
                fprintf(outlog, "replies count for msg %ld exceeds %d,",
                        (long)j, maxreply);
                fprintf(outlog, "rest of the replies won't be linked\n");
            }
            links_ignored++;
        } else {
            links_total++;
            (crepl -> replies)[(crepl -> freeReply)++] = srepl->msgPos;
            srepl -> replyToPos = crepl->msgPos;
        }

    } else { // Jam, maybe something else?

        if(srepl -> replyToPos) {
           if (loglevel >= 15)
              fprintf(outlog, "Thread linking broken because of dupes\n");
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
		if (loglevel >= 15)
		    fprintf(outlog, "Thread linking broken. MsgUidToMsgn() returned -1\n");
		links_ignored++;
		return;
	    }

            while (replmap[linkTo].replyNxt) {
		linkTo = MsgUidToMsgn(harea, replmap[linkTo].replyNxt, UID_EXACT) - 1;
		if(linkTo == -1) {
		    if (loglevel >= 15)
			fprintf(outlog, "Thread linking broken. MsgUidToMsgn() returned -1\n");
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
   char *value, *end, *out;

   if ( !ctl || !kludge ) return (NULL);

   if ( (value = strstr( ctl, kludge)) == NULL ) return (NULL);

   if ( value[-1] != '\001') return (NULL);

   value += strlen(kludge); /* skip kludge name (i.e. MSGID: or REPLY:) */

   for (end = value; *end != '\001' && *end; end++);

   if ((end - value) <= 0) return (NULL);

   out = (char *) malloc((size_t) (end - value) + 1 );
   if (out == NULL) return (NULL);

   memcpy(out, value, (size_t) (end - value));
   out[(size_t) (end - value)] = '\0';

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



   if (loglevel>=10) fprintf(outlog, "linking area %s...", area->areaName);

   if ((area->msgbType & MSGTYPE_PASSTHROUGH) == MSGTYPE_PASSTHROUGH) {
     if (loglevel>=10) fprintf(outlog, "PASSTHROUGH, ignoring\n");
     return;
   }

   if (area->nolink) {
     if (loglevel>=10) fprintf(outlog, "has nolink option, ignoring\n");
     return;
   }

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
	      if (loglevel>=10) fprintf(outlog, "nothing to link (%ld messages)\n", (long)highMsg);
	      MsgCloseArea(harea);
	      return;
	   }

	   if ( (replmap = (s_msginfo *) calloc (highMsg, sizeof(s_msginfo))) == NULL){
	      if (loglevel>0) fprintf(outlog,"Out of memory. Want %ld bytes\n",  (long) sizeof(s_msginfo)*highMsg);
	      MsgCloseArea(harea);
	      exit(EX_SOFTWARE);
	   }

	   if ( (links = (s_origlinks *) calloc (highMsg, sizeof(s_origlinks))) == NULL){
	      if (loglevel>0) fprintf(outlog,"Can't get %ld bytes\n",  (long) sizeof(s_origlinks)*highMsg);
	      MsgCloseArea(harea);
	      exit(EX_SOFTWARE);
	   }

	   /* Pass 1: read all message information in memory */
	   if ( loglevel >= 11 ) fprintf ( outlog, "\nPass 1 - reading\n");

	   for (i = 1, crepl=replmap, linksptr=links; i <= highMsg; i++, crepl++, linksptr++) {
	      hmsg  = MsgOpenMsg(harea, MOPEN_READ, i);
	      if (hmsg){
		 ctlen = MsgGetCtrlLen(hmsg);
		 if( ctlen == 0 )
		 {
		    if ( loglevel >= 15) fprintf(outlog, "msg %ld has no control information\n", (long) i);
		    MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);

		 } else {
		   if( ctl==NULL || ctlen_curr < ctlen + 1) {

		      ctl = (byte *) realloc(ctl, ctlen + 1);
		      if (ctl == NULL) {
			if ( loglevel > 0) fprintf(outlog,"out of memory while linking on msg %ld\n", (long) i);
			MsgCloseArea(harea);
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
		    if ( (ptr=skipReSubj(xmsg.subj)) == NULL) ptr = xmsg.subj;
		    crepl -> subject = strdup(ptr);
		 }

                 crepl->msgPos = MsgMsgnToUid(harea, i);

		 // Save data for comparing
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
              fprintf (outlog, "Pass 2: building relations for %ld messages", (long) i-1);
              if (linkNew)
                 fprintf (outlog, ", new from %ld\n", (long) newStart);
              else
                 fprintf (outlog, "\n");
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
		     strcmp(crepl -> msgId, srepl -> replyId) == 0 ) {

		       replFound++;
		       links_msgid++;

		       if ( ! crepl -> treeId ) { // *crepl isn't linked
			  if (srepl -> treeId ) { // *srepl linked already
			     crepl -> treeId = srepl -> treeId;
			  } else {
                             crepl -> treeId = i; // top of new tree
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
		     if ( strcmp(crepl -> replyId, srepl -> replyId) == 0 &&
			    strcmp(crepl -> replyId, "  ffffffff")) {

		       replFound++;
		       links_replid++;

		       if ( ! crepl -> treeId ) { // *crepl isn't linked
			  if (srepl -> treeId ) { // *srepl linked already
			     crepl -> treeId = srepl -> treeId;
			  } else {
                             crepl -> treeId = i; // top of new tree
			  }
		       }
		       srepl -> treeId = crepl -> treeId;

		       treeLinks++;
		     }
		  }

		  if (!replFound && (srepl -> msgId) && (crepl -> replyId)) {
		     if ( strcmp(srepl -> msgId, crepl -> replyId) == 0 ) {
		       replFound++;
		       links_revmsgid++;

		       if ( ! crepl -> treeId ) { // *crepl isn't linked
			  if (srepl -> treeId ) { // *srepl linked already
			     crepl -> treeId = srepl -> treeId;
			  } else {
                             crepl -> treeId = i; // top of new tree
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

		       if ( ! crepl -> treeId ) { // *crepl isn't linked
			  if (srepl -> treeId ) { // *srepl linked already
			     crepl -> treeId = srepl -> treeId;
			  } else {
                             crepl -> treeId = i; // top of new tree
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
	   if ( loglevel >= 11 ) fprintf (outlog, "Pass 3: buildng relations by treeIds\n");

	   for (i = 1, crepl=replmap; i <= highMsg && treeLinks; i++, crepl++) {
	      if ( crepl->replyToPos == 0 && crepl->freeReply == 0 &&
                   crepl->treeId && i != crepl->treeId ) {
		 // Link unlinked message

		 linkTo = (replmap[crepl -> treeId -1 ]).treeId;
		 if (linkTo > highMsg || linkTo <= 0 ) {
		    if ( loglevel > 5) fprintf(outlog,"\nProgramming error 1 while linking linkTo=%ld\n", (long)linkTo);
		    exit(EX_SOFTWARE);
		 }

                 if (maxreply == MAX_REPLY) { // Find place to put link for Squish
                    while ( (replmap[linkTo-1]).freeReply >= maxreply) {
                       linkTo = MsgUidToMsgn(harea,(replmap[linkTo-1]).replies[0], UID_EXACT );
                       if (linkTo > highMsg || linkTo <= 0 ) {
                          if ( loglevel > 5) fprintf(outlog,"\nProgramming error 2 while linking linkTo=%ld\n", (long)linkTo);
                          exit(EX_SOFTWARE);
                       }
                    }
                 }
		 linkMsgs ( &(replmap[linkTo-1]), crepl, linkTo, i , replmap );
		 (replmap[crepl -> treeId - 1]).treeId = i; // where to link next message
		 treeLinks--;
	      }
	   }


	   /* Pass 4: write information back to msgbase */
	   if ( loglevel >= 11 ) fprintf ( outlog, "Pass 4: writing\n");

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

              } else { // Not Jam

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

	      if(crepl -> replyId) free(crepl -> replyId);
	      if(crepl -> subject) free(crepl -> subject);
	      if(crepl -> msgId  ) free(crepl -> msgId  );
	   }

	   MsgCloseArea(harea);

	   nfree(ctl);
	   nfree(replmap);
	   nfree(links);

	   if ( loglevel >= 10) fprintf(outlog, "done\n");
   } else {
	   if ( loglevel > 5) fprintf(outlog,"\nCould not open area %s\n", area->areaName);
   }
}

void usage(void) {

   fprintf(outlog, "hptlink %s\n", version);
   fprintf(outlog, "Usage:\n hptlink [-t] [-s] [-a] [-r] [-l loglevel] [areaname ...]\n");
   fprintf(outlog, "   -t - build reply TREE\n");
   fprintf(outlog, "   -s - do not use Subject\n");
   fprintf(outlog, "   -a - search in all messages (for singlethread only)\n");
   fprintf(outlog, "   -r - do not use REPLY:/MSGID:\n");
   fprintf(outlog, "   -l loglevel - log output level >=0. Edge values: 0,5,10,11,15. Default 10.\n");
   fprintf(outlog, "   -n Link with 'new' messages only ('new' start from last linked + 1)\n");


}

int main(int argc, char **argv) {

   s_fidoconfig *cfg;
   int i, j;
   struct _minf m;
   char **argareas=NULL;
   char *line;
   int nareas=0;
   int found;
   FILE *f;
   s_area *area;

   outlog=stderr;

   setbuf(outlog, NULL);

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
	       loglevel = -1;
	       i++;

	       if ( argv[i] == NULL || argv[i][0] == '\0') {
		  usage();
		  exit(EX_USAGE);
	       }

	       sscanf ( argv[i], "%d", &loglevel);
	       if ( loglevel < 0 ) {
		  usage();
		  exit(EX_USAGE);
	       }
	     break;
	     case 'n': /* link with 'new' messages only */
	     case 'N':
		linkNew = 1;
		break;
	     default:
		usage();
		exit(EX_USAGE);
	  }
     } else {
       // AreaName(s) specified by args
       nareas++;
       argareas = (char **)realloc ( argareas, nareas*sizeof(char *));
       argareas[nareas-1] = argv[i];
     }
   }

   if ( loglevel > 0) fprintf(outlog,"hptlink %s\n", version);

   cfg = readConfig(NULL);

   if (!cfg) {
      fprintf(outlog, "Could not read fido config\n");
      return (1);
   }

   m.req_version = 0;
   m.def_zone = (UINT16) cfg->addr[0].zone;
   if (MsgOpenApi(&m)!= 0) {
      if ( loglevel > 0) fprintf(outlog, "MsgOpenApi Error.\n");
      exit(EX_SOFTWARE);
   }

   if ( argareas )
   {
     // link only specified areas
     if ( loglevel >= 11 ) fprintf (outlog, "Linking areas specified by args\n");

     for ( j=0; j<nareas; j++) {

	found=0;

	// EchoAreas
	for (i=0, area=cfg->echoAreas;
	     i < cfg->echoAreaCount && !found;
	     i++, area++) {
	    if (stricmp(area->areaName, argareas[j])==0){
		if (!area->scn) {
		    linkArea(area);
		    area->scn=1;
		}
		found++;
	    }
	}

	// Local Areas
	for (i=0, area=cfg->localAreas;
	     i < cfg->localAreaCount && !found;
	     i++, area++) {
	    if (stricmp(area->areaName, argareas[j])==0){
		if (!area->scn) {
		    linkArea(area);
		    area->scn=1;
		}
		found++;
	    }
	}

	// NetMail areas
	for (i=0, area=cfg->netMailAreas;
	     i < cfg->netMailAreaCount && !found;
	     i++, area++) {
	    if (stricmp(area->areaName, argareas[j])==0){
		if (!area->scn) {
		    linkArea(area);
		    area->scn=1;
		}
		found++;
	    }
	}

	if (loglevel>0 && !found) fprintf(outlog, "Couldn't find area \"%s\"\n", argareas[j]);
     }

   } else {

      if (cfg->LinkWithImportlog != lwiNo){
	 f = fopen(cfg->importlog, "r");
      } else {
	 f = NULL;
      }

      if ( f ) {
	 if ( loglevel >= 11 ) fprintf (outlog, "Using importlogfile -> linking only listed Areas");
	 while (!feof(f)) {
	    line = readLine(f);

	    if (line) {

	       found=0;
	       // EchoAreas
	       for (i=0, area=cfg->echoAreas;
		    i < cfg->echoAreaCount && !found;
		    i++, area++) {
		   if (stricmp(area->areaName, line)==0){
		       if (!area->scn) {
			   linkArea(area);
			   area->scn=1;
		       }
		       found++;
		   }
	       }
	       // Local Areas
	       for (i=0, area=cfg->localAreas;
		    i < cfg->localAreaCount && !found;
		    i++, area++) {
		   if (stricmp(area->areaName, line)==0){
		       if (!area->scn) {
			   linkArea(area);
			   area->scn=1;
		       }
		       found++;
		   }
	       }

	       // NetMail areas
	       for (i=0, area=cfg->netMailAreas;
		    i < cfg->netMailAreaCount && !found;
		    i++, area++) {
		   if (stricmp(area->areaName, line)==0){
		       if (!area->scn) {
			   linkArea(area);
			   area->scn=1;
		       }
		       found++;
		   }
	       }

	       if (loglevel>0 && !found && strlen(line)) fprintf(outlog, "Couldn't find area \"%s\"\n", line);
	       nfree(line);
	    }

	 }
	 fclose(f);
	 if (cfg->LinkWithImportlog == lwiKill) remove(cfg->importlog);
      } else {
	 // importlog does not exist link all areas
	 if (loglevel>=10) fprintf(outlog, "No ImportLog file, linking all Areas\n");

	 // NetMails
	 for (i = 0; i < cfg -> netMailAreaCount; i++)
	    linkArea (&(cfg->netMailAreas[i]));

	 // EchoAreas
	 for (i=0; i < cfg->echoAreaCount; i++) linkArea(&(cfg->echoAreas[i]));

	 // Local Areas
	 for (i=0; i < cfg->localAreaCount; i++) linkArea(&(cfg->localAreas[i]));
      }
   }

   disposeConfig(cfg);

   if ( loglevel >= 11 ) fprintf (outlog, "\nLinked by msgid/reply: %ld, replid: %ld, subj: %ld, revmsgid: %ld\n", (long)links_msgid, (long)links_replid, (long)links_subj, (long)links_revmsgid);
   if ( loglevel >= 10 ) {
     fprintf (outlog, "\nLinked total: %ld", (long) links_total);
     if (links_ignored)
	fprintf (outlog, ", Ignored: %ld\n\n", (long) links_ignored);
     else
	fprintf (outlog, "\n\n");
   }

   if ( loglevel > 0) fprintf(outlog,"Done\n");
   return (0);
}
