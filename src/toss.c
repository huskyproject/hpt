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
 * Copyright (C) 1999-2001
 *
 * Max Levenkov
 *
 * Fido:     2:5000/117
 * Internet: sackett@mail.ru
 * Novosibirsk, West Siberia, Russia
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

#if (defined(__EMX__) || defined(__MINGW32__)) && defined(__NT__)
/* we can't include windows.h for several reasons ... */
#ifdef __MINGW32__
int __stdcall CharToOemA(char *, char *);
#endif
#define CharToOem CharToOemA
#endif

#include <sys/stat.h>
#if !(defined(__TURBOC__) || (defined (_MSC_VER) && (_MSC_VER >= 1200)))
#include <unistd.h>
#endif


#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/dirlayer.h>
#include <fidoconf/xstr.h>

#include <strsep.h>
#include <pkt.h>
#include <scan.h>
#include <toss.h>
#include <global.h>
#include <seenby.h>
#include <dupe.h>
#include <recode.h>
#include <areafix.h>
#include <version.h>
#include <scanarea.h>
#include <hpt.h>
#ifdef DO_PERL
#include <hptperl.h>
#endif

#include <smapi/msgapi.h>
#include <smapi/stamp.h>
#include <smapi/typedefs.h>
#include <smapi/compiler.h>
#include <smapi/progprot.h>
#include <smapi/patmat.h>

#if defined(__WATCOMC__) || defined(__TURBOC__) || defined(__DJGPP__)
#include <dos.h>
#include <process.h>
#endif

#if defined(__MINGW32__) && defined(__NT__)
/* we can't include windows.h for several reasons ... */
int __stdcall GetFileAttributesA(char *);
#define GetFileAttributes GetFileAttributesA
#endif

#if defined(__MINGW32__) || (defined(__WATCOMC__) && (__WATCOMC__ < 1100))
#define NOSLASHES
#endif


#ifdef USE_HPT_ZLIB
#   include "hpt_zlib/hptzip.h"
#endif


extern s_message **msgToSysop;
int save_err;

s_statToss statToss;
int forwardPkt(const char *fileName, s_pktHeader *header, e_tossSecurity sec);
void processDir(char *directory, e_tossSecurity sec);
void makeMsgToSysop(char *areaName, s_addr fromAddr, s_addr *uplinkAddr);

static char *get_filename(char *pathname)
{
    char *ptr;

    if (pathname == NULL || !(*pathname))
        return pathname;

    ptr = pathname + strlen(pathname) - 1;

    while (*ptr != '/' && *ptr != '\\' && *ptr != ':' && ptr != pathname)
        ptr--;

    if (*ptr == '/' || *ptr == '\\' || *ptr == ':')
        ptr++;

    return ptr;
}   

/*
 * Find the first occurrence of find in s ignoring case
 */
char *hpt_stristr(char *str, char *find)
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

char *changeFileSuffix(char *fileName, char *newSuffix) {

    int   i = 1;
    char  buff[200];

    char *beginOfSuffix = strrchr(fileName, '.')+1;
    char *newFileName;
    int  length = strlen(fileName)-strlen(beginOfSuffix)+strlen(newSuffix);

    newFileName = (char *) safe_malloc((size_t) length+1+2);
    memset(newFileName, '\0',length+1+2);
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

    if (!fexist(newFileName)) {
	rename(fileName, newFileName);
	return newFileName;
    } else {
	w_log('9', "Could not change suffix for %s. File already there and the 255 files after", fileName);
	nfree(newFileName);
	return NULL;
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

XMSG createXMSG(s_message *msg, const s_pktHeader *header, dword forceattr) 
{
    char **outbounds[4];
    XMSG  msgHeader;
    struct tm *date;
    time_t    currentTime;
    union stamp_combo dosdate;
    int i;
    char *subject=NULL, *newSubj=NULL, *token, *running;
       
    //init outbounds
    outbounds[0] = &tossDir;
    outbounds[1] = &config->protInbound;
    outbounds[2] = &config->inbound;
    outbounds[3] = NULL;

    // clear msgheader
    memset(&msgHeader, '\0', sizeof(XMSG));
	
    // attributes of netmail must be fixed
    msgHeader.attr = msg->attributes;
	
    if (msg->netMail == 1) {
	// Check if we must remap
	for (i=0;i<config->remapCount;i++)
	    if ((config->remaps[i].toname==NULL ||
		 stricmp(config->remaps[i].toname,msg->toUserName)==0) &&
		(config->remaps[i].oldaddr.zone==0 ||
		 addrComp(config->remaps[i].oldaddr,msg->destAddr)==0) ) 
		{
		    msg->destAddr.zone=config->remaps[i].newaddr.zone;
		    msg->destAddr.net=config->remaps[i].newaddr.net;
		    msg->destAddr.node=config->remaps[i].newaddr.node;
		    msg->destAddr.point=config->remaps[i].newaddr.point;
		    break;
		}
		
	if (to_us(msg->destAddr)==0) {
	    // kill these flags
	    msgHeader.attr &= ~(MSGREAD | MSGKILL | MSGFRQ | MSGSCANNED | MSGLOCKED | MSGFWD);
	    // set this flags
	    msgHeader.attr |= MSGPRIVATE;
	} else
	    if (header!=NULL) {
		// set TRS flag, if the mail is not to us(default)
		if ( config->keepTrsMail ) msgHeader.attr &= ~(MSGKILL | MSGFWD);
		else msgHeader.attr |= MSGFWD;
	    }
    } else
	// kill these flags on echomail messages
	msgHeader.attr &= ~(MSGREAD | MSGKILL | MSGFRQ | MSGSCANNED | MSGLOCKED);
   
    // always kill crash, hold, sent & local flags on netmail & echomail
    msgHeader.attr &= ~(MSGCRASH | MSGHOLD | MSGSENT | MSGLOCAL);

    /* FORCED ATTRIBUTES !!! */
    msgHeader.attr |= forceattr;
   
    strcpy((char *) msgHeader.from,msg->fromUserName);
    strcpy((char *) msgHeader.to, msg->toUserName);

    if (((msgHeader.attr & MSGFILE) == MSGFILE) 
	&& (msg->netMail==1)
	&& !strchr(msg->subjectLine, PATH_DELIM)) {

	running = msg->subjectLine;
	token = strseparate(&running, " \t");

	while (token != NULL) {
	    for (i=0;i<4;i++) {
		nfree(subject);
		if (outbounds[i] && *outbounds[i]) xstrcat(&subject, *outbounds[i]);
		xstrcat (&subject, token);
		if (fexist(subject)) break;
#if defined(__linux__) || defined(UNIX)
		subject = strLower(subject);
		if (fexist(subject)) break;
#endif
	    }
	    if (newSubj) xstrcat(&newSubj, " ");
	    xstrcat (&newSubj, subject);
	    token = strseparate(&running, " \t");
	} // end while
	nfree(subject);
    }

    if (newSubj) {
	if (strlen(newSubj) < XMSG_SUBJ_SIZE)
	    strcpy((char *) msgHeader.subj, newSubj);
	else {
	    strncpy((char *) msgHeader.subj, newSubj, XMSG_SUBJ_SIZE-1);
	    w_log('9',
		  "Long subjectLine! Some files will be not routed.");
	}
	nfree(newSubj);
    } else strcpy((char *) msgHeader.subj, msg->subjectLine);

    msgHeader.orig.zone  = (word) msg->origAddr.zone;
    msgHeader.orig.node  = (word) msg->origAddr.node;
    msgHeader.orig.net   = (word) msg->origAddr.net;
    msgHeader.orig.point = (word) msg->origAddr.point;
    msgHeader.dest.zone  = (word) msg->destAddr.zone;
    msgHeader.dest.node  = (word) msg->destAddr.node;
    msgHeader.dest.net   = (word) msg->destAddr.net;
    msgHeader.dest.point = (word) msg->destAddr.point;

    strcpy((char *) msgHeader.__ftsc_date, (char *)msg->datetime);
    ASCII_Date_To_Binary((char *)msg->datetime, (union stamp_combo *) &(msgHeader.date_written));

    currentTime = time(NULL);
    date = localtime(&currentTime);
    TmDate_to_DosDate(date, &dosdate);
    msgHeader.date_arrived = dosdate.msg_st;

    return msgHeader;
}

/* return value: 1 if success, 0 if fail */
int putMsgInArea(s_area *echo, s_message *msg, int strip, dword forceattr)
{
    char *ctrlBuff, *textStart, *textWithoutArea;
    UINT textLength = (UINT) msg->textLength;
    HAREA harea;
    HMSG  hmsg;
    XMSG  xmsg;
    char /**slash,*/ *p, *q, *tiny;
    int rc = 0;

    // create Directory Tree if necessary
/*    if (echo->msgbType == MSGTYPE_SDM)
	createDirectoryTree(echo->fileName);
    else */if (echo->msgbType==MSGTYPE_PASSTHROUGH) {
	w_log('9', "Can't put message to passthrough area %s!", echo->areaName);
	return rc;
    }/* else {
	// squish or jam area

	slash = strrchr(echo->fileName, PATH_DELIM);
	if (slash) {
	    *slash = '\0';
	    createDirectoryTree(echo->fileName);
	    *slash = PATH_DELIM;
	}

    }
*/   
    if (!msg->netMail) {
	msg->destAddr.zone  = echo->useAka->zone;
	msg->destAddr.net   = echo->useAka->net;
	msg->destAddr.node  = echo->useAka->node;
	msg->destAddr.point = echo->useAka->point;
    }

    harea = MsgOpenArea((UCHAR *) echo->fileName, MSGAREA_CRIFNEC, 
			/*echo->fperm, echo->uid, echo->gid,*/
			(word)(echo->msgbType | (msg->netMail ? 0 : MSGTYPE_ECHO)));
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

	    if ((strip==1) && (strncmp(msg->text, "AREA:", 5) == 0)) {
		// jump over AREA:xxxxx\r
		while (*(textWithoutArea) != '\r') textWithoutArea++;
		textWithoutArea++;
		textLength -= (size_t) (textWithoutArea - msg->text);
	    }

	    if (echo->killSB) {
		tiny = strrstr(textWithoutArea, " * Origin:");
		if (tiny == NULL) tiny = textWithoutArea;
		if (NULL != (p = strstr(tiny, "\rSEEN-BY: "))) {
		    p[1]='\0';
		    textLength = (size_t) (p - textWithoutArea + 1);
		}
	    } else if (echo->tinySB) {
		tiny = strrstr(textWithoutArea, " * Origin:");
		if (tiny == NULL) tiny = textWithoutArea;
		if (NULL != (p = strstr(tiny, "\rSEEN-BY: "))) {
		    p++;
		    if (NULL != (q = strstr(p,"\001PATH: "))) {
			// memmove(p,q,strlen(q)+1);
			memmove(p,q,textLength-(size_t)(q-textWithoutArea)+1);
			textLength -= (size_t) (q - p);
		    } else {
			p[0]='\0';
			textLength = (size_t) (p - textWithoutArea);
		    }
		}
	    }

	   
	    ctrlBuff = (char *) CopyToControlBuf((UCHAR *) textWithoutArea,
						 (UCHAR **) &textStart,
						 &textLength);
	    // textStart is a pointer to the first non-kludge line
	    xmsg = createXMSG(msg, NULL, forceattr);

	    if (MsgWriteMsg(hmsg, 0, &xmsg, (byte *) textStart, (dword)
			    textLength, (dword) textLength,
			    (dword)strlen(ctrlBuff), (byte*)ctrlBuff)!=0) 
		w_log('9', "Could not write msg in %s!", echo->fileName);
	    else rc = 1; // normal exit

	    if (MsgCloseMsg(hmsg)!=0) {
		w_log('9', "Could not close msg in %s!", echo->fileName);
		rc = 0;
	    }
	    nfree(ctrlBuff);
       
	} else w_log('9', "Could not create new msg in %s!", echo->fileName);
	/* endif */
	MsgCloseArea(harea);
    } else w_log('9', "Could not open/create EchoArea %s!", echo->fileName);
    /* endif */
    return rc;
}

/*
int putMsgInDupeArea(s_addr addr, s_message *msg, dword forceattr)
{
	char *textBuff=NULL, *from=NULL;
	
	xscatprintf(&from, "FROM: %s\r", aka2str(addr));
	xstrscat(&textBuff, from, msg->text, NULL);

	msg->textLength += strlen(from);
	nfree(from);
	
	nfree(msg->text);
	msg->text = textBuff;

	return putMsgInArea(&(config->dupeArea), msg, 0, forceattr);
}
*/

void createSeenByArrayFromMsg(s_area *area, s_message *msg, s_seenBy **seenBys, UINT *seenByCount)
{
    char *seenByText=NULL, *start, *token;
    unsigned long temp;
    char *endptr;
    UINT seenByAlloced;

    *seenByCount = seenByAlloced = 0;

    start = strrstr(msg->text, " * Origin:"); // jump over Origin
    if (start == NULL) start = msg->text;

    // find beginning of seen-by lines
    do {
	start = strstr(start, "SEEN-BY:");
	if (start == NULL) return;
	start += 8; // jump over SEEN-BY:

	while (*start == ' ') start++; // find first word after SEEN-BY:
    } while (!isdigit(*start));

    // now that we have the start of the SEEN-BY's we can tokenize the lines and read them in
    xstrcat(&seenByText, start);

    token = strtok(seenByText, " \r\t\376");
    while (token != NULL) {
	if (isdigit(*token)) {
	    // parse token
	    temp = strtoul(token, &endptr, 10);
	    if (*endptr==':') {
		token = endptr+1;
		temp = strtoul(token, &endptr, 10);
	    }
	    if (*endptr && *endptr != '/')
		continue;

	    // get new memory
	    if ((*seenByCount)++ >= seenByAlloced)
		(*seenBys) = (s_seenBy*) safe_realloc(*seenBys, sizeof(s_seenBy) * (seenByAlloced+=32));

	    if ((*endptr) == '\0') {
		// only node aka
		(*seenBys)[*seenByCount-1].node = (UINT16) temp;
		// use net aka of last seenBy
		(*seenBys)[*seenByCount-1].net = (*seenBys)[*seenByCount-2].net;
	    } else {
		// net and node aka
		(*seenBys)[*seenByCount-1].net = (UINT16) temp;
		// eat up '/'
		endptr++;
		(*seenBys)[*seenByCount-1].node = (UINT16) atol(endptr);
	    }
	} else if (strcmp(token,"SEEN-BY:")!=0) break; // not digit and not SEEN-BY
	   
	token = strtok(NULL, " \r\t\376");
    } // end while

    if (*seenByCount != seenByAlloced)
	(*seenBys) = (s_seenBy*) safe_realloc(*seenBys, sizeof(s_seenBy) * (*seenByCount));
    //test output for reading of seenBys...
#ifdef DEBUG_HPT
    for (i=0; i < *seenByCount; i++) printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
#endif
//   exit(2);

    nfree(seenByText);
}

void createPathArrayFromMsg(s_message *msg, s_seenBy **seenBys, UINT *seenByCount)
{

    // DON'T GET MESSED UP WITH THE VARIABLES NAMED SEENBY...
    // THIS FUNCTION READS PATH!!!

    char *seenByText=NULL, *start, *token;
    char *endptr;
    unsigned long temp;
    UINT seenByAlloced;
#ifdef DEBUG_HPT
    int i;
#endif

    *seenByCount = seenByAlloced = 0;

    start = strrstr(msg->text, " * Origin:"); // jump over Origin
    if (start == NULL) start = msg->text;

    // find beginning of path lines
    do {
	start = strstr(start, "\001PATH:");
	if (start == NULL) return;
	start += 7; // jump over PATH:

	while (*start == ' ') start++; // find first word after PATH:
    } while (!isdigit(*start));

    // now that we have the start of the PATH' so we can tokenize the lines and read them in
    xstrcat(&seenByText, start);

    token = strtok(seenByText, " \r\t\376");
    while (token != NULL) {
	if (isdigit(*token)) {
	    // parse token
	    temp = strtoul(token, &endptr, 10);
	    if (*endptr==':') {
		token = endptr+1;
		temp = strtoul(token, &endptr, 10);
	    }
	    if (*endptr && *endptr != '/')
		continue;

	    // get new memory
	    if ((*seenByCount)++ >= seenByAlloced)
		(*seenBys) = (s_seenBy*) safe_realloc(*seenBys, sizeof(s_seenBy) * (seenByAlloced+=32));

	    if ((*endptr) == '\0') {
		// only node aka
		(*seenBys)[*seenByCount-1].node = (UINT16) temp;
		// use net aka of last seenBy
		(*seenBys)[*seenByCount-1].net = (*seenBys)[*seenByCount-2].net;
	    } else {
		// net and node aka
		(*seenBys)[*seenByCount-1].net = (UINT16) temp;
		// eat up '/'
		endptr++;
		(*seenBys)[*seenByCount-1].node = (UINT16) atol(endptr);
	    }
	} else if (strcmp(token, "\001PATH:")!=0) break; // not digit and not PATH
	token = strtok(NULL, " \r\t\376");
    }

    if (*seenByCount != seenByAlloced)
	(*seenBys) = (s_seenBy*) safe_realloc(*seenBys, sizeof(s_seenBy) * (*seenByCount));

    // test output for reading of paths...
#ifdef DEBUG_HPT
    for (i=0; i < *seenByCount; i++) printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
#endif
    //exit(2);

    nfree(seenByText);
}

/**
  * This function returns 0 if the link is not in seenBy else it returns 1.
  */

int checkLink(s_seenBy *seenBys, UINT seenByCount, s_link *link,
	      s_addr pktOrigAddr, s_area *area)
{
    UINT i,j;

    // the link where we got the mail from
    if (addrComp(pktOrigAddr, link->hisAka) == 0) return 1;

    if (seenBys==NULL) return 0;

    // a point always gets the mail
    if (link->hisAka.point != 0) return 0;

    for (i=0; i < seenByCount; i++) {
	if ((link->hisAka.net==seenBys[i].net) &&
	    (link->hisAka.node==seenBys[i].node)) {
		   
	    for (j=0; j < config->ignoreSeenCount; j++) {
		if (config->ignoreSeen[j].net == seenBys[i].net &&
		    config->ignoreSeen[j].node == seenBys[i].node) {
		    link->sb = 1; // fix for double seen-bys
		    return 0;
		}
	    }
	    for (j=0; j < area->sbignCount; j++) {
		if (area->sbign[j].net == seenBys[i].net &&
		    area->sbign[j].node == seenBys[i].node) {
		    link->sb = 1; // fix for double seen-bys
		    return 0;
		}
	    }

	    return 1;
	}
    }
    return 0;
}

/*
  This function puts all the links of the echoarea in the newLink
  array who does not have got the mail, zoneLinks - the links who
  receive msg with stripped seen-by's.
*/

void createNewLinkArray(s_seenBy *seenBys, UINT seenByCount,
			s_area *echo, s_arealink ***newLinks,
			s_arealink ***zoneLinks, s_addr pktOrigAddr) {
    UINT i, j=0, k=0;
	
    *newLinks = (s_arealink **) scalloc(echo->downlinkCount,sizeof(s_arealink*));
    *zoneLinks = (s_arealink **) scalloc(echo->downlinkCount,sizeof(s_arealink*));
    if (*newLinks==NULL || *zoneLinks==NULL) exit_hpt("out of memory",1);

    for (i=0; i < echo->downlinkCount; i++) {
	// is the link in SEEN-BYs?
	if ( checkLink(seenBys, seenByCount, echo->downlinks[i]->link,
		       pktOrigAddr, echo)!=0) continue;
	// link with "export off"
	if (echo->downlinks[i]->export == 0) continue;

	if (pktOrigAddr.zone==echo->downlinks[i]->link->hisAka.zone) {
	    // links with same zone
	    (*newLinks)[j] = echo->downlinks[i];
	    j++;
	} else {
	    // links in different zones
	    (*zoneLinks)[k] = echo->downlinks[i];
	    k++;
	}
    }
}

void forwardToLinks(s_message *msg, s_area *echo, s_arealink **newLinks, 
		    s_seenBy **seenBys, UINT *seenByCount,
		    s_seenBy **path, UINT *pathCount) {
    int i, rc=0;
    long len;
    FILE *pkt, *f=NULL;
    s_pktHeader header;
    char *start, *text, *seenByText = NULL, *pathText = NULL;
    char *debug=NULL;

    if (newLinks[0] == NULL) return;

    if (echo->debug) {
	xstrscat(&debug, config->logFileDir,
		 (echo->DOSFile) ? "common" : echo->areaName,
		 ".dbg", NULL);
		
	if (config->areasFileNameCase == eLower) 
	    debug = strLower(debug);
	else
	    debug = strUpper(debug);
		
	if ((f=fopen(debug,"a"))==NULL) {
	    w_log('9',"can't open file: %s",debug);
	}
	nfree(debug);
    }

    for (i=0; i<config->addToSeenCount; i++) {
	(*seenByCount)++;
	(*seenBys) = (s_seenBy*) safe_realloc(*seenBys,sizeof(s_seenBy)*(*seenByCount));
	(*seenBys)[*seenByCount-1].net = (UINT16) config->addToSeen[i].net;
	(*seenBys)[*seenByCount-1].node = (UINT16) config->addToSeen[i].node;
    }
    for (i=0; i<echo->sbaddCount; i++) {
	(*seenByCount)++;
	(*seenBys) = (s_seenBy*) safe_realloc(*seenBys,sizeof(s_seenBy)*(*seenByCount));
	(*seenBys)[*seenByCount-1].net = (UINT16) echo->sbadd[i].net;
	(*seenBys)[*seenByCount-1].node = (UINT16) echo->sbadd[i].node;
    }

    // add our aka to seen-by (zonegating link must strip our aka)
    if (echo->useAka->point==0) {

	for (i=0; i < *seenByCount; i++) {
	    if ((*seenBys)[i].net == echo->useAka->net &&
		(*seenBys)[i].node == echo->useAka->node) break;
	}
		
	if (*seenByCount==i) {
	    (*seenBys) = (s_seenBy*)
		safe_realloc((*seenBys), sizeof(s_seenBy) * (*seenByCount+1));
	    (*seenBys)[*seenByCount].net = (UINT16) echo->useAka->net;
	    (*seenBys)[*seenByCount].node = (UINT16) echo->useAka->node;
	    (*seenByCount)++;
	}
    }

    // add seenBy for newLinks
    for (i=0; i<echo->downlinkCount; i++) {
		
	// no link at this index -> break
	if (newLinks[i] == NULL) break;
	// don't include points in SEEN-BYs
	if (newLinks[i]->link->hisAka.point != 0) continue;
	// fix for IgnoreSeen & -sbign
	if (newLinks[i]->link->sb == 1) continue;

	(*seenBys) = (s_seenBy*) safe_realloc((*seenBys), sizeof(s_seenBy) * (*seenByCount+1));
	(*seenBys)[*seenByCount].net = (UINT16) newLinks[i]->link->hisAka.net;
	(*seenBys)[*seenByCount].node = (UINT16) newLinks[i]->link->hisAka.node;
	(*seenByCount)++;
    }

    sortSeenBys((*seenBys), *seenByCount);

#ifdef DEBUG_HPT
    for (i=0; i< *seenByCount;i++) printf("%u/%u ", (*seenBys)[i].net, (*seenBys)[i].node);
#endif

    if (*pathCount > 0) {
	if (((*path)[*pathCount-1].net != echo->useAka->net) ||
	    ((*path)[*pathCount-1].node != echo->useAka->node)) {
	    // add our aka to path
	    (*path) = (s_seenBy*) safe_realloc((*path), sizeof(s_seenBy) * (*pathCount+1));
	    (*path)[*pathCount].net = (UINT16) echo->useAka->net;
	    (*path)[*pathCount].node = (UINT16) echo->useAka->node;
	    (*pathCount)++;
	}
    } else {
	(*pathCount) = 0;
	(*path) = (s_seenBy*) safe_realloc((*path),sizeof(s_seenBy));
	(*path)[*pathCount].net = (UINT16) echo->useAka->net;
	(*path)[*pathCount].node = (UINT16) echo->useAka->node;
	(*pathCount) = 1;
    }

#ifdef DEBUG_HPT
    for (i=0; i< *pathCount;i++) printf("%u/%u ", (*path)[i].net, (*path)[i].node);
#endif

    text = strrstr(msg->text, " * Origin:"); // jump over Origin
    if (text) { // origin was found
	start = strrchr(text, ')');
	if (start) start++; // normal origin
	else {
	    start = text; // broken origin
	    while(*start && *start!='\r') start++;
	}
	*start='\0';
    } else { // no Origin founded
	text = msg->text;
	start = strstr(text, "\rSEEN-BY: ");
	if (start == NULL) start = strstr(text, "SEEN-BY: ");
	if (start) *start='\0';
	// find start of PATH in Msg
	start = strstr(text, "\001PATH: ");
	if (start) *start='\0'; 
	else start = text+strlen(text);
    }
    msg->textLength = (size_t) (start - msg->text);

	// create new seenByText
    seenByText = createControlText(*seenBys, *seenByCount, "SEEN-BY: ");
    pathText   = createControlText(*path, *pathCount, "\001PATH: ");
    xstrscat(&msg->text, "\r", seenByText, pathText, NULL);
    msg->textLength += 1 + strlen(seenByText) + strlen(pathText);
    nfree(seenByText);
    nfree(pathText);

    if (echo->debug) {
	debug = (char *) GetCtrlToken(msg->text, (byte *)"MSGID");
	if (f && debug) {
	    fputs("\n[",f);
	    fputs(debug,f);
	    fputs("] ",f);
	}
	nfree(debug);
    }

    // add msg to the pkt's of the downlinks
    for (i = 0; i<echo->downlinkCount; i++) {

	// no link at this index -> break;
	if (newLinks[i] == NULL) break;

	// check packet size
	if (newLinks[i]->link->pktFile != NULL && newLinks[i]->link->pktSize != 0) {
	    len = fsize(newLinks[i]->link->pktFile);
	    if (len >= (newLinks[i]->link->pktSize * 1024L)) { // Stop writing to pkt
		nfree(newLinks[i]->link->pktFile);
		nfree(newLinks[i]->link->packFile);
	    }
	}

	// create pktfile if necessary
	if (newLinks[i]->link->pktFile == NULL) {
	    // pktFile does not exist
	    if ( createTempPktFileName(newLinks[i]->link) )
		exit_hpt("Could not create new pkt!",1);
	}

	makePktHeader(NULL, &header);
	header.origAddr = *(newLinks[i]->link->ourAka);
	header.destAddr = newLinks[i]->link->hisAka;
	if (newLinks[i]->link->pktPwd != NULL)
	    strcpy(header.pktPassword, newLinks[i]->link->pktPwd);
	pkt = openPktForAppending(newLinks[i]->link->pktFile, &header);

	// an echomail msg must be adressed to the link
	msg->destAddr = header.destAddr;
	// .. and must come from us
	msg->origAddr = header.origAddr;
	rc += writeMsgToPkt(pkt, *msg);
	if (rc) w_log('9',"can't write msg to pkt: %s",
		      newLinks[i]->link->pktFile);
	rc += closeCreatedPkt(pkt);
	if (rc) w_log('9',"can't close pkt: %s",
		      newLinks[i]->link->pktFile);
	if (f) {
	    if (rc) fputs(" failed: ",f);
	    fputs(aka2str(header.destAddr),f);
	    fputc('>',f);
	    fputs(get_filename(newLinks[i]->link->pktFile),f);
	    fputc(' ',f);
	}
	if (rc==0) statToss.exported++;
	else rc=0;
    }

    if (f) fclose(f);
    return;
}

void forwardMsgToLinks(s_area *echo, s_message *msg, s_addr pktOrigAddr)
{
    s_seenBy *seenBys = NULL, *path = NULL;
    UINT     seenByCount, pathCount;
    // links who does not have their aka in seenBys and thus have not got the echomail
    s_arealink **newLinks, **zoneLinks;

    createSeenByArrayFromMsg(echo, msg, &seenBys, &seenByCount);
    createPathArrayFromMsg(msg, &path, &pathCount);
   
    createNewLinkArray(seenBys, seenByCount, echo, &newLinks, &zoneLinks, pktOrigAddr);

    forwardToLinks(msg, echo, newLinks, &seenBys, &seenByCount, &path, &pathCount);
    if (zoneLinks!=NULL) {
	if (echo->useAka->zone != pktOrigAddr.zone) seenByCount = 0;
	forwardToLinks(msg, echo, zoneLinks, &seenBys, &seenByCount, &path, &pathCount);
    }

    nfree(seenBys);
    nfree(path);
    nfree(newLinks);
    nfree(zoneLinks);
}

void del_tok(char **ac, char *tok) {
    char *p, *q;

    q = hpt_stristr(*ac,tok);
    if (q) {
	p = q+strlen(tok);
	while (*p && !isspace(*p)) p++;
	if (*p) memmove(q, p+1, strlen(p+1)+1); // begin or middle
	else {
	    if (q > *ac) *(q-1)='\0'; // end
	    else *q='\0'; // "-token" defaults
	}
    }
}

                                /* we do NOT check for a dosish ':' here
                                   because mkdir "C:" is nonsense */

#define my_isdirsep(x) (((x) == '/') || ((x) == '\\'))

                                /* makes sure subdirectories in the pathname
                                   exist. the last part of the argument is only
                                   treated as a subdir if the argument ends
                                   with '/' (or '\\'). rv: 1=ok, 0=error
                                   basedir is not checked, filename is
                                   checked. basedir must end in separator. */

static int makealldirs(const char *basedir, const char *filename)
{
    char *buffer, *cpd;
    const char *cps = filename;
    size_t l;

    l = strlen(basedir);
    if (!(*filename)) return 1;
    if ((buffer = safe_malloc(l + strlen(filename) + 1)) == NULL) return 0;

    memcpy(buffer, basedir, l);
    cpd = buffer + l;
  
    do
	{
	    while ((!my_isdirsep(*cps)) && (*cps))
		{
		    *cpd++ = *cps++;
		}
        
	    if (my_isdirsep(*cps))
		{
		    if (!direxist(buffer))
			{
			    *cpd = '\0';
			    mymkdir(buffer); /* we can't check mkdir return code for
						portability reasons, so we do this: */
			    if (!direxist(buffer))
				{
				    free(buffer);
				    return 0;
				}
			}
		    *cpd++ = *cps++;
		}
	} while (*cps);

    free(buffer);
    return 1;
}
    
#undef my_isdirsep

int autoCreate(char *c_area, s_addr pktOrigAddr, s_addr *forwardAddr)
{
    FILE *f;
    char *fileName, *msgbFileName=NULL, *acDef;
    char *buff=NULL, *hisaddr=NULL;
    char *msgbtype, *newAC=NULL, *desc, *msgbDir;
    char *cp;                    /* temp. usage */
    s_link *creatingLink;
    s_area *area;
    int i;

    if (strlen(c_area)>60) return 11;
    if (!isValidConference(c_area) || isPatternLine(c_area)) return 7;

    msgbFileName = makeMsgbFileName(c_area);

    // translating name of the area to lowercase/uppercase
    if (config->createAreasCase == eUpper) strUpper(c_area);
    else strLower(c_area);

    // translating filename of the area to lowercase/uppercase
    if (config->areasFileNameCase == eUpper) strUpper(msgbFileName);
    else strLower(msgbFileName);

    creatingLink = getLinkFromAddr(*config, pktOrigAddr);

    if (creatingLink == NULL) {
	w_log('9', "creatingLink == NULL !!!");
	return 8;
    }

    acDef = creatingLink->autoAreaCreateDefaults;
    xscatprintf(&newAC, "%s%s", (acDef) ? " " : "", (acDef) ? acDef : "");

    fileName = creatingLink->autoAreaCreateFile;
    if (fileName == NULL) fileName = cfgFile ? cfgFile : getConfigFileName();

    f = fopen(fileName, "a");
    if (f == NULL) {
	fprintf(stderr,"autocreate: cannot open config file\n");
	return 9;
    }

    // making address of uplink
    xstrcat(&hisaddr, aka2str(pktOrigAddr));

    // write new line in config file
    msgbtype = hpt_stristr(newAC, "-b ");

    msgbDir=(creatingLink->msgBaseDir) ? creatingLink->msgBaseDir : config->msgBaseDir;

    if (stricmp(msgbDir, "passthrough")!=0 && NULL==hpt_stristr(newAC,"passthrough"))
	{
	    // we have to find a file name
	    int need_dos_file;

#ifndef MSDOS                            
	    need_dos_file = hpt_stristr(newAC, "-dosfile")!=NULL;
#else
	    need_dos_file = 1;
#endif

	    if (creatingLink->autoAreaCreateSubdirs && !need_dos_file)
		{
		    // "subdirify" the message base path if the
		    // user wants this. this currently does not
		    // work with the -dosfile option
		    for (cp = msgbFileName; *cp; cp++)
			{
			    if (*cp == '.')
				{
				    *cp = PATH_DELIM;
				}
			}

		    if (!makealldirs(msgbDir,msgbFileName))
			{
			    w_log('9', "autoAreaCreateSubdirs: Could not create some paths for %s%s", msgbDir, msgbFileName);
			    return 1;
			}
		}

	    if (!need_dos_file)
		xscatprintf(&buff, "EchoArea %s %s%s%s", c_area,
			    msgbDir, msgbFileName,
			    (msgbtype) ? "" : " -b Squish");
	    else {
		sleep(1); // to prevent time from creating equal numbers
		xscatprintf(&buff,"EchoArea %s %s%8lx%s", c_area,
			    msgbDir, (long)time(NULL),
			    (msgbtype) ? "" : " -b Squish");
	    }

	} else {
	    // passthrough
	    xscatprintf(&buff, "EchoArea %s passthrough", c_area);
       
	    del_tok(&newAC, "passthrough");
	    del_tok(&newAC, "-b ");  // del "-b msgbtype" from autocreate defaults
	    del_tok(&newAC, "-$m "); // del "-$m xxx" from autocreate defaults
	    del_tok(&newAC, "-p ");  // del "-p xxx" from autocreate defaults
       
	    del_tok(&newAC, "-killsb");
	    del_tok(&newAC, "-tinysb");
	    del_tok(&newAC, "-nopack");
	    del_tok(&newAC, "-nolink");
	    del_tok(&newAC, "-killread");
	    del_tok(&newAC, "-keepunread");
	}
   
    nfree(msgbFileName);

    if (creatingLink->LinkGrp) {
	if (hpt_stristr(newAC, " -g ")==NULL)
	    xscatprintf(&newAC, " -g %s", creatingLink->LinkGrp);
    }

    if (areaIsAvailable(c_area,creatingLink->forwardRequestFile,&desc,1)==1) {
	if (desc) {
	    if (hpt_stristr(newAC, " -d ")==NULL)
		xscatprintf(&newAC, " -d \"%s\"", desc);
	    nfree(desc);
	}
    }

    if (*newAC) xstrcat(&buff, newAC);
    nfree(newAC);

    // add new created echo to config in memory
    parseLine(buff, config);

    // subscribe uplink if he is not subscribed
    area = &(config->echoAreas[config->echoAreaCount-1]);
    if ( isLinkOfArea(creatingLink,area)==0 ) {
	xscatprintf(&buff, " %s", hisaddr);
	addlink(creatingLink, area);
    }

    fprintf(f, "%s\n", buff); // add line to config
    fclose(f);
   
    nfree(buff);

    // echoarea addresses changed by safe_reallocating of config->echoAreas[]
    carbonNames2Addr(config);

    w_log('8', "Area %s autocreated by %s", c_area, hisaddr);
   
    if (forwardAddr == NULL) makeMsgToSysop(c_area, pktOrigAddr, NULL);
    else makeMsgToSysop(c_area, *forwardAddr, &pktOrigAddr);
   
    nfree(hisaddr);

    // create flag
    if (config->aacFlag) {
	if (NULL == (f = fopen(config->aacFlag,"a")))
	    w_log('9', "Could not open autoAreaCreate flag: %s", config->aacFlag);
	else {
	    w_log('0', "Created autoAreaCreate flag: %s", config->aacFlag);
	    fclose(f);
	}
    }
   
    return 0;
}

#if defined(UNIX) || defined(__EMX__) || defined(__DJGPP__)
#define HAVE_POPEN
#endif

int processExternal (s_area *echo, s_message *msg,s_carbon carbon) 
{ 
    FILE *msgfp;
    char *fname = NULL;
    char *progname, *execstr, *p;
    int  rc;

    progname = carbon.areaName;
#ifdef HAVE_POPEN	
    if (*progname == '|') {
	msgfp = popen(progname + 1, "w");
    } else
#endif
	{
	    fname = tmpnam(NULL);
	    msgfp = fopen(fname, "wt");
	};
	
    if (!msgfp) {
	w_log('9', "external process %s: cannot create file", progname);
	return 1;
    };
    /* Output header info */
    if (!msg->netMail) fprintf(msgfp, "Area: %s\n", echo->areaName);
    fprintf(msgfp, "From: \"%s\" %s\n", msg->fromUserName, aka2str(msg->origAddr));
    fprintf(msgfp, "To:   \"%s\" %s\n", msg->toUserName, aka2str(msg->destAddr));
    fprintf(msgfp, "Date: \"%s\"\n", msg->datetime);
    fprintf(msgfp, "Subject: \"%s\"\n\n", msg->subjectLine);
    /* Output msg text */
    for (p = msg->text; *p ; p++) 
	if (*p == '\r') 
	    fputc('\n', msgfp);
	else
	    fputc(*p, msgfp);
    fputc('\n', msgfp);
#ifdef HAVE_POPEN	
    if (*progname == '|') {
	pclose(msgfp);
	rc = 0;
    } else
#endif
	{
	    /* Execute external program */
	    fclose(msgfp);
	    execstr = safe_malloc(strlen(progname)+strlen(fname)+2);
	    sprintf(execstr, "%s %s", progname, fname);
#ifdef __NT__
	    CharToOem(execstr, execstr); // this is really need?
#endif
	    rc = system(execstr);
	    nfree(execstr);
	    unlink(fname);
	};
    if (rc == -1 || rc == 127) {
	w_log('9', "excution of external process %s failed", progname);
    };
    return 0;

};

/* area - area to carbon messages, echo - original echo area */
int processCarbonCopy (s_area *area, s_area *echo, s_message *msg, s_carbon carbon) {
    char *p, *text, *old_text, *reason = carbon.reason;
    int i, old_textLength, /*reasonLen = 0,*/ export = carbon.export, rc = 0;

    statToss.CC++;

    old_textLength = msg->textLength;
    old_text = msg->text;

    // recoding from internal to transport charSet if needed
    if (config->outtab) {
	if (msg->recode & REC_TXT) {
	    recodeToTransportCharset((CHAR*)msg->text);
	    msg->recode &= ~REC_TXT;
	}
	if (msg->recode & REC_HDR) {
	    recodeToTransportCharset((CHAR*)msg->fromUserName);
	    recodeToTransportCharset((CHAR*)msg->toUserName);
	    recodeToTransportCharset((CHAR*)msg->subjectLine);
	    msg->recode &= ~REC_HDR;
	}
    }
	
    i = old_textLength;

    if (!msg->netMail) {
	if ((!config->carbonKeepSb) && (!area->keepsb)) {
	    text = strrstr(old_text, " * Origin:");
	    if (NULL != (p = strstr(text ? text : old_text,"\rSEEN-BY:")))
		i = (size_t) (p - old_text) + 1;
	}
    }

    msg->text = NULL;
    msg->textLength = 0;

    if (!msg->netMail) {
	xstrscat(&msg->text,
		 (export) ? "AREA:" : "",
		 (export) ? area->areaName : "",
		 (export) ? "\r" : "",
		 (config->carbonExcludeFwdFrom) ? "" : " * Forwarded from area '",
		 (config->carbonExcludeFwdFrom) ? "" : echo->areaName,
		 (config->carbonExcludeFwdFrom) ? "" : "'\r",
		 (reason) ? reason : "",
		 (reason) ? "\r" : "",
		 //(!config->carbonExcludeFwdFrom || reason) ? "\r" : "",
		 "\r\1", NULL);
	msg->textLength = strlen(msg->text);
    }

    xstralloc(&msg->text,i); // add i bytes
    strncat(msg->text,old_text,i); // copy rest of msg
    msg->textLength += i;
    
    if (!export) {
	if (msg->netMail) rc = putMsgInArea(area,msg,0,MSGSENT);
	else rc = putMsgInArea(area,msg,0,0);
	area->imported++;  // area has got new messages
    }
    else if (!msg->netMail) {
	rc = processEMMsg(msg, *area->useAka, 1, 0);
    } else
	rc = processNMMsg(msg, NULL, area, 1, 0);

    nfree(msg->text);
    msg->textLength = old_textLength;
    msg->text = old_text;
    msg->recode &= ~REC_TXT; // old text is always in Transport Charset

    return rc;
}


/* Does carbon copying */
/* Return value: 0 if nothing happend, 1 if there was a carbon copy, 
   > 1 if there was a carbon move or carbon delete*/
int carbonCopy(s_message *msg, XMSG *xmsg, s_area *echo)
{
    int i, rc = 0, result=0;
    char *testptr, *testptr2, *kludge;
    s_area *area;
    s_carbon *cb=&(config->carbons[0]);
    s_area **copiedTo = NULL;
    int copiedToCount = 0;
    int ncop;

    if (echo->ccoff==1)
        return 0;
    if (echo->msgbType==MSGTYPE_PASSTHROUGH && config->exclPassCC)
        return 0;

    for (i=0; i<config->carbonCount; i++,++cb) {
        /* Dont come to use netmail on echomail and vise verse */
        if (cb->move!=2 && ((msg->netMail && !cb->netMail) ||
            (!msg->netMail &&  cb->netMail))) continue;

        area = cb->area;
		
	if(!cb->rule&CC_AND)
            if (!cb->extspawn && // fix for extspawn
                cb->areaName != NULL && // fix for carbonDelete
		// dont CC to the echo the mail comes from
        	!stricmp(echo->areaName,area->areaName)
		) continue;

        switch (cb->ctype) {
        case ct_to:
            result=!stricmp(msg->toUserName,cb->str);
            break;

        case ct_from:
            result=!stricmp(msg->fromUserName,cb->str);
            break;

        case ct_kludge:
	    kludge = (char *) GetCtrlToken(msg->text, (byte *)cb->str);
	    result = (kludge!=NULL);
	    nfree(kludge);
	    break;

        case ct_subject:
            result=(NULL!=hpt_stristr(msg->subjectLine,cb->str));
            break;

        case ct_msgtext:
	    /* skip area: kludge */
            testptr=msg->text+6+strlen(echo->areaName);
            while(testptr!=NULL){
                testptr=hpt_stristr(testptr,cb->str);
                if(testptr!=NULL){
                    /* look back: a '\1' after a LF        */
                    /* means that it is a kludge           */
                    testptr2=testptr;   /* remind position */
                    while(*--testptr!='\12'); /* not LF    */
		    /* (skipped) area: kludge prevents going back too far :) */
                    if(*++testptr=='\1') /* was a kludge   */
                        testptr=testptr2+strlen(cb->str);
                    else
                        break;
                }
            }
            result=(NULL!=testptr);
            break;

        case ct_addr:
            result=!addrComp(msg->origAddr, cb->addr);
            break;

        case ct_fromarea: /* skip AREA: */
            result=!strncasecmp(msg->text+5, cb->str,strlen(cb->str));
            break;

        case ct_group:
            if(echo->group!=NULL){
		/* cb->str for example Fido,xxx,.. */
                testptr=cb->str;
                do{
                    if(NULL==(testptr=hpt_stristr(echo->group,testptr)))
                        break;
                    testptr+=strlen(echo->group);
                    result=(*testptr==',' || *testptr==' ' || !*testptr);
                    testptr-=strlen(echo->group);
                    ++testptr;
                }while(!result);
            }
            break;
        }

        if(cb->rule&CC_NOT) /* NOT on/off */
            result=!result;

        switch(cb->rule&CC_AND){ /* what operation with next result */
        case CC_OR: /* OR */
            if (result && area && cb->move!=2 && !config->carbonAndQuit) { 
                /* check if we've done cc to dest area already */
                for (ncop=0; ncop < copiedToCount && result; ncop++)
                    if (area == copiedTo[ncop]) result = 0;
                if (result) {
                    copiedTo = safe_realloc (copiedTo, (copiedToCount+1) * sizeof (s_area *));
                    copiedTo[copiedToCount] = area;
                    copiedToCount++;
                }
            }

            if(result){
                /* make cc */
                /* Set value: 1 if copy 3 if move */
                rc = cb->move ? 3 : 1;
                if(cb->extspawn)
                    processExternal(echo,msg,*cb);
                else
                    if (cb->areaName && cb->move!=2)
                        if (!processCarbonCopy(area,echo,msg,*cb))
                            rc &= 1;

		// delete CarbonMove and CarbonDelete messages
		if (cb->move && xmsg) xmsg->attr |= MSGKILL;
                if (config->carbonAndQuit)
		    /* not skip quit or delete */
                    if ((cb->areaName && *cb->areaName!='*') ||	cb->move==2) {
                        return rc;
		    }
            }
            break;
        case CC_AND: /* AND */
            if(!result){
                /* following expressions can be skipped until OR */
                for (++i,++cb; i<config->carbonCount; i++,++cb)
                    if(!cb->rule&CC_AND)
                        break; /* this is the last in the AND expr. chain */
            }
            /* else result==TRUE, so continue with next expr. */
            break;
        }
    } /* end for() */

    if (copiedTo) nfree (copiedTo);
    return rc;
}

int putMsgInBadArea(s_message *msg, s_addr pktOrigAddr, int writeAccess)
{
    char *tmp, *line, *textBuff=NULL, *areaName=NULL;
    
    statToss.bad++;
	 
    // get real name area
    line = strchr(msg->text, '\r');
    *line = 0;
    if (strncmp(msg->text,"AREA:",5)==0)
	xscatprintf(&areaName, "AREANAME: %s\r\r", msg->text+5);
    *line = '\r';

    tmp = msg->text;

    while ((line = strchr(tmp, '\r')) != NULL) {
	if (*(line+1) == '\x01') tmp = line+1;
	else { tmp = line+1; *line = 0; break; }
    }
	 
    xstrscat(&textBuff,msg->text,"\rFROM: ",aka2str(pktOrigAddr),"\rREASON: ",NULL);
    switch (writeAccess) {
    case 0: 
	xstrcat(&textBuff,"System not allowed to create new area\r");
	break;
    case 1: 
	xstrcat(&textBuff,"Sender not allowed to post in this area (access group)\r");
	break; 
    case 2: 
	xstrcat(&textBuff,"Sender not allowed to post in this area (access level)\r");
	break;
    case 3: 
	xstrcat(&textBuff,"Sender not allowed to post in this area (access import)\r");
	break;
    case 4: 
	xstrcat(&textBuff,"Sender not active for this area\r");
	break;
    case 5:
	xstrcat(&textBuff,"Rejected by filter\r");
	break;
    case 6:
	xstrcat(&textBuff,"MSGAPIERR: ");

#ifdef _MAKE_DLL_MVC_
	switch (GetMsgapiErr()) {   
#else
	switch (msgapierr) {
#endif
	case MERR_NONE: xstrcat(&textBuff,"No error\r");
	    break;
	case MERR_BADH: xstrcat(&textBuff,"Invalid handle passed to function\r");
	    break;
	case MERR_BADF: xstrcat(&textBuff,"Invalid or corrupted file\r");
	    break;
	case MERR_NOMEM: xstrcat(&textBuff,"Not enough memory for specified operation\r");
	    break;
	case MERR_NODS: 
	    xstrcat(&textBuff,"Maybe not enough disk space for operation\r");
	    w_log('9', "Maybe not enough disk space for operation\r");
	    break;
	case MERR_NOENT: xstrcat(&textBuff,"File/message does not exist\r");
	    break;
	case MERR_BADA: xstrcat(&textBuff,"Bad argument passed to msgapi function\r");
	    break;
	case MERR_EOPEN: xstrcat(&textBuff,"Couldn't close - messages still open\r");
	    break;
	case MERR_NOLOCK: xstrcat(&textBuff,"Base needs to be locked to perform operation\r");
	    break;
	case MERR_SHARE: xstrcat(&textBuff,"Resource in use by other process\r");
	    break;
	case MERR_EACCES: xstrcat(&textBuff,"Access denied (can't write to read-only, etc)\r");
	    break;
	case MERR_BADMSG: xstrcat(&textBuff,"Bad message frame (Squish)\r");
	    break;
	case MERR_TOOBIG: xstrcat(&textBuff,"Too much text/ctrlinfo to fit in frame (Squish)\r");
	    break;
	default: xstrcat(&textBuff,"Unknown error\r");
	    break;
	}

	break;
    case 7:
	xstrcat(&textBuff,"Can't create echoarea with forbidden symbols in areatag\r");
	break;
    case 8:
	xstrcat(&textBuff,"Sender not found in config file\r");
	break;
    case 9:
	xstrcat(&textBuff,"Can't open config file\r");
	break;
    case 10:
	xstrcat(&textBuff,"No downlinks for passthrough area\r");
	break;
    case 11:
	xstrcat(&textBuff,"lenght of CONFERENCE name is more than 60 symbols\r");
	break;
    default :
	xstrcat(&textBuff,"Another error\r");
	break;
    }
    if (areaName) xstrcat(&textBuff, areaName);
    xstrcat(&textBuff, tmp);
    nfree(areaName);
    nfree(msg->text);
    msg->text = textBuff;
    msg->textLength = strlen(msg->text);
    if (putMsgInArea(&(config->badArea), msg, 0, 0)) {
	config->badArea.imported++;
	return 1;
    }
    return 0;
}

void makeMsgToSysop(char *areaName, s_addr fromAddr, s_addr *uplinkAddr)
{
    s_area *echo;
    int i, netmail=0;
    char *buff=NULL;
    char *strbeg=NULL;
    
    if (config->ReportTo) {
	if (stricmp(config->ReportTo,"netmail")==0) netmail=1;
	else if (getNetMailArea(config, config->ReportTo) != NULL) netmail=1;
    } else netmail=1;

    echo = getArea(config, areaName);
    
    if (echo == &(config->badArea)) return;
    
    for (i = 0; i < config->addrCount; i++) {
	if (echo->useAka == &(config->addr[i])) {
	    if (msgToSysop[i] == NULL) {

		msgToSysop[i] = makeMessage(echo->useAka, echo->useAka, versionStr, netmail ? config->sysop : "All", "Created new areas", netmail);
		msgToSysop[i]->text = createKludges(netmail ? NULL : config->ReportTo, echo->useAka, echo->useAka);

		xstrscat(&(msgToSysop[i]->text), "Action   Name", 
			 print_ch(49, ' '), "By\r", NULL);
		// Shitty static variables ....
		xstrscat(&(msgToSysop[i]->text), print_ch(79, '-'), "\r", NULL);
		msgToSysop[i]->recode |= (REC_HDR|REC_TXT);
//		w_log('8',"Created msg to sysop");
	    }

//          New report generation
            xstrcat(&buff, aka2str(fromAddr));
            if (uplinkAddr != NULL) { // autocreation with forward request
		xstrcat(&buff, " from ");
		xstrcat(&buff, aka2str(*uplinkAddr));
            }
            xstrscat(&strbeg, "Created  ", echo->areaName, NULL);

            if (echo->description) {
		if (strlen(strbeg) + strlen(echo->description) >=77) {
		    xstrscat(&(msgToSysop[i]->text), strbeg, "\r", NULL);
		    nfree(strbeg);
		    xstrcat(&strbeg, print_ch(9, ' '));
		} else {
		    xstrcat(&strbeg, " ");
		}
		xstrscat(&strbeg, "\"", echo->description, "\"", NULL);
            }

            xstrcat(&(msgToSysop[i]->text), strbeg);

            if (strlen(strbeg) + strlen(buff) >= 79) {
		xstrscat(&(msgToSysop[i]->text), "\r", print_ch(79-strlen(buff), ' '), buff, "\r", NULL);
            } else if (strlen(strbeg) <62 && strlen(buff) < 79-62) { // most beautiful
		xstrscat(&(msgToSysop[i]->text), print_ch(62-strlen(strbeg), ' '), buff, "\r", NULL);
            } else { 
		xstrscat(&(msgToSysop[i]->text), print_ch(79-strlen(strbeg)-strlen(buff), ' '), buff, "\r", NULL);
            }
            nfree(buff);
            nfree(strbeg);

//          Old report generation
//	    xscatprintf(&(msgToSysop[i]->text), "Created  %-53s%s\r", 
//	         echo->areaName, aka2str(fromAddr));

	    break;
	}
    }
    
}

void writeMsgToSysop()
{
    char	*ptr, *seenByPath;
    s_area	*echo;
    int		i, ccrc = 0;
    s_seenBy	*seenBys;
    
    for (i = 0; i < config->addrCount; i++) {
	if (msgToSysop[i]) {
	    xscatprintf(&(msgToSysop[i]->text), " \r--- %s\r * Origin: %s (%s)\r", 
			(config->tearline) ? config->tearline : "",
			(config->origin) ? config->origin : config->name,
			aka2str(msgToSysop[i]->origAddr));
	    msgToSysop[i]->textLength = strlen(msgToSysop[i]->text);
	    
	    if (msgToSysop[i]->netMail == 1) 
		// FIXME: should be putMsgInArea 
		processNMMsg(msgToSysop[i], NULL, config->ReportTo ?
			     getNetMailArea(config, config->ReportTo) : NULL, 1, 0);
	    else {
		// get echoarea  for this msg    
		ptr = strchr(msgToSysop[i]->text, '\r');
		*ptr = '\0'; echo = getArea(config, msgToSysop[i]->text + 5); *ptr = '\r';
		
		if (echo != &(config->badArea)) {
		    if (config->carbonCount != 0) 
			ccrc = carbonCopy(msgToSysop[i], NULL, echo);
		    if (echo->msgbType != MSGTYPE_PASSTHROUGH && ccrc <= 1) {
        		putMsgInArea(echo, msgToSysop[i],1, (MSGSCANNED|MSGSENT|MSGLOCAL));
        		echo->imported++;  // area has got new messages
		    }

		    seenBys = (s_seenBy*) safe_malloc(sizeof(s_seenBy)*(echo->downlinkCount+1));
		    seenBys[0].net = (UINT16) echo->useAka->net;
		    seenBys[0].node = (UINT16) echo->useAka->node;
		    sortSeenBys(seenBys, 1);
   
		    seenByPath = createControlText(seenBys, 1, "SEEN-BY: ");
		    nfree(seenBys);
   
		    // path line
		    // only include node-akas in path
		    if (echo->useAka->point == 0) 
   			xscatprintf(&seenByPath, "\001PATH: %u/%u\r", echo->useAka->net, echo->useAka->node);
		    xstrcat(&(msgToSysop[i]->text), seenByPath);
		    nfree(seenByPath);
		    if (echo->downlinkCount > 0) {
			// recoding from internal to transport charSet
			if (config->outtab) {
			    if (msgToSysop[i]->recode & REC_HDR) {
				recodeToTransportCharset((CHAR*)msgToSysop[i]->fromUserName);
		    		recodeToTransportCharset((CHAR*)msgToSysop[i]->toUserName);
		    		recodeToTransportCharset((CHAR*)msgToSysop[i]->subjectLine);
				msgToSysop[i]->recode &= ~REC_HDR;
			    }
			    if (msgToSysop[i]->recode & REC_TXT) {
				recodeToTransportCharset((CHAR*)msgToSysop[i]->text);
				msgToSysop[i]->recode &= ~REC_TXT;
			    }
			}
			forwardMsgToLinks(echo, msgToSysop[i], msgToSysop[i]->origAddr);
			tossTempOutbound(config->tempOutbound);
		    }
		} else {
		    putMsgInBadArea(msgToSysop[i], msgToSysop[i]->origAddr, 0);
		}
	    }
	}
    }
    
}

s_arealink *getAreaLink(s_area *area, s_addr aka)
{
    UINT i;

    for (i = 0; i <area->downlinkCount; i++) {
	if (addrComp(aka, area->downlinks[i]->link->hisAka)==0) return area->downlinks[i];
    }
	
    return NULL;
}

// import: type == 0, export: type != 0 
// return value: 0 if access ok, 3 if import/export off, 4 if not linked
int checkAreaLink(s_area *area, s_addr aka, int type)
{
    s_arealink *arealink;
    int writeAccess = 0;
	
    arealink = getAreaLink(area, aka);
    if (arealink) {
	if (type==0) {
	    if (arealink->import) writeAccess = 0; else writeAccess = 3;
	} else {
	    if (arealink->export) writeAccess = 0; else writeAccess = 3;
	}
    } else {
	if (addrComp(aka, *area->useAka)==0) writeAccess = 0;
	else writeAccess = 4;
    }
	
    return writeAccess;
}

int processEMMsg(s_message *msg, s_addr pktOrigAddr, int dontdocc, dword forceattr)
{
    char   *area=NULL, *p, *q;
    s_area *echo=&(config->badArea);
    s_link *link;
    int    writeAccess = 0, rc = 0, ccrc = 0;

    p = strchr(msg->text,'\r');
    if (p) {
	*p='\0';
	q = msg->text+5;
	while (*q == ' ') q++;
	xstrcat(&area, q);
	echo = getArea(config, area);
	*p='\r';
    }

    // no area found -- trying to autocreate echoarea
    if (echo == &(config->badArea)) {
	// checking for autocreate option
	link = getLinkFromAddr(*config, pktOrigAddr);
	if ((link != NULL) && (link->autoAreaCreate != 0)) {
	    if (0 == (writeAccess = autoCreate(area, pktOrigAddr, NULL)))
		echo = getArea(config, area);
	    else rc = putMsgInBadArea(msg, pktOrigAddr, writeAccess);
	} // can't create echoarea - put msg in BadArea
	else rc = putMsgInBadArea(msg, pktOrigAddr, writeAccess);
    }

    nfree(area);

    if (echo != &(config->badArea)) {
	// area is autocreated!

	// cheking access of this link
	writeAccess = checkAreaLink(echo, pktOrigAddr, 0);
	if (writeAccess) rc = putMsgInBadArea(msg, pktOrigAddr, writeAccess);
	else { // access ok - process msg

	    if (dupeDetection(echo, *msg)==1) {
		// no dupe
		statToss.echoMail++;

		// if only one downlink, we've got the mail from him
		if ((echo->downlinkCount > 1) ||
		    ((echo->downlinkCount > 0) && 
		     // mail from us
		     (addrComp(pktOrigAddr,*echo->useAka)==0)))
		    forwardMsgToLinks(echo, msg, pktOrigAddr);

		if ((config->carbonCount!=0)&&(!dontdocc))
		    ccrc=carbonCopy(msg, NULL, echo);

		if (ccrc <= 1) {
		    echo->imported++;  // area has got new messages
		    if (echo->msgbType != MSGTYPE_PASSTHROUGH) {
			rc = putMsgInArea(echo, msg, 1, forceattr);
			statToss.saved += rc;
		    }
		    else { // passthrough
			/*
			  if (echo->downlinkCount==1 && dontdocc==0)
			  rc = putMsgInBadArea(msg, pktOrigAddr, 10);
			  else {
			  statToss.passthrough++;
			  rc = 1;
			  }
			*/
			statToss.passthrough++;
			rc = 1;
		    }
		} else rc = 1; // normal exit for carbon move & delete

	    } else {
		// msg is dupe
		if (echo->dupeCheck == dcMove) {
		    // rc = putMsgInDupeArea(pktOrigAddr, msg, forceattr);
		    rc = putMsgInArea(&(config->dupeArea), msg, 0, forceattr);
		} else rc = 1;
		statToss.dupes++;
		if (rc) config->dupeArea.imported++;
	    }
	}
    }
    return rc;
}

int processNMMsg(s_message *msg, s_pktHeader *pktHeader, s_area *area, int dontdocc, dword forceattr)
{
    HAREA  netmail;
    HMSG   msgHandle;
    UINT   len = msg->textLength;
    char   *bodyStart;             // msg-body without kludgelines start
    char   *ctrlBuf;               // Kludgelines
    XMSG   msgHeader;
//    char   *slash;
    int rc = 0, ccrc = 0, i;

    if (area == NULL) {
	area = &(config->netMailAreas[0]);
	for(i=0; i<config->netMailAreaCount; i++) {
	    if(addrComp(msg->destAddr,*(config->netMailAreas[i].useAka))==0) {
		area = &(config->netMailAreas[i]);
		break;
	    }
	}
    }

    if (dupeDetection(area, *msg)==0) {
	// msg is dupe
	if (area->dupeCheck == dcMove) {
	    rc = putMsgInArea(&(config->dupeArea), msg, 0, forceattr);
	} else rc = 1;
	statToss.dupes++;
	if (rc) config->dupeArea.imported++;
	return rc;
    }

    if ((config->carbonCount!=0)&&(!dontdocc)) ccrc = carbonCopy(msg, NULL, area);
    if (ccrc > 1) return 1; // carbon del or move
/*
    // create Directory Tree if necessary
    if (area -> msgbType == MSGTYPE_SDM)
	createDirectoryTree(area -> fileName);
    else {
	// squish or jam area
	slash = strrchr(area -> fileName, PATH_DELIM);
	if (slash) {
	    *slash = '\0';
	    createDirectoryTree(area -> fileName);
	    *slash = PATH_DELIM;
	}
    }
*/
    netmail = MsgOpenArea((unsigned char *) area -> fileName, MSGAREA_CRIFNEC,
/*								 config->netMailArea.fperm, config->netMailArea.uid,
								 config->netMailArea.gid, */(word) area -> msgbType);
   
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

	    msgHeader = createXMSG(msg, pktHeader, forceattr);
	    /* Create CtrlBuf for SMAPI */
	    ctrlBuf = (char *) CopyToControlBuf((UCHAR *) msg->text, (UCHAR **) &bodyStart, &len);
	    /* write message */
	    if (MsgWriteMsg(msgHandle, 0, &msgHeader, (UCHAR *)
			    bodyStart, len, len, strlen(ctrlBuf)+1,
			    (UCHAR *) ctrlBuf)!=0) w_log('9',"Could not write msg to NetmailArea %s",area->areaName);
	    else rc = 1; // normal exit
	    nfree(ctrlBuf);
	    if (MsgCloseMsg(msgHandle)!=0) { // can't close
		w_log('9',"Could not close msg in NetmailArea %s",area->areaName);
		rc = 0;
	    } else { // normal close
		w_log('7', "Wrote Netmail: %u:%u/%u.%u -> %u:%u/%u.%u", msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node, msg->origAddr.point, msg->destAddr.zone, msg->destAddr.net, msg->destAddr.node, msg->destAddr.point);
		statToss.netMail++;
	    }

	} else {
	    w_log('9', "Could not create new msg in NetmailArea %s", area -> areaName);
	} /* endif */

	MsgCloseArea(netmail);
    } else {
#ifdef _MAKE_DLL_MVC_
    fprintf(stderr, "msgapierr - %u\n", GetMsgapiErr());
#else
    fprintf(stderr, "msgapierr - %u\n", msgapierr);
#endif
	w_log('9', "Could not open NetmailArea %s", area -> areaName);
    } /* endif */
    return rc;
}

int processMsg(s_message *msg, s_pktHeader *pktHeader, int secure)
{
    int rc;

    statToss.msgs++;
#ifdef DO_PERL
    if ((rc = perlfilter(msg, pktHeader->origAddr, secure)) == 1)
	return putMsgInBadArea(msg, pktHeader->origAddr, 5);
    else if (rc == 2)
	return 1;
#endif
    if (msg->netMail == 1) {
	if (config->areafixFromPkt && strlen(msg->toUserName)>0 &&
	    (stricmp(msg->toUserName,"areafix")==0 ||
	     stricmp(msg->toUserName,"areamgr")==0 ||
	     stricmp(msg->toUserName,"hpt")==0 ||
	     hpt_stristr(config->areafixNames,msg->toUserName))) {
	    rc = processAreaFix(msg, pktHeader, 0);
	} else
	    rc = processNMMsg(msg, pktHeader, NULL, 0, 0);
    } else {
	rc = processEMMsg(msg, pktHeader->origAddr, 0, 0);
    } /* endif */
    return rc;
}

int processPkt(char *fileName, e_tossSecurity sec)
{
    FILE        *pkt;
    s_pktHeader *header;
    s_message   *msg;
    s_link      *link;
    int         rc = 0, msgrc = 0;
    long	pktlen;
    time_t      realtime;
    /* +AS+ */
    char        *extcmd;
    int         cmdexit;
    /* -AS- */
    char        processIt = 0; // processIt = 1, process all mails
    // processIt = 2, process only Netmail
    // processIt = 0, do not process pkt
   
    if ((pktlen = fsize(fileName)) > 60) {

	statToss.inBytes += pktlen;

	/* +AS+ */
	if (config->processPkt)
	    {
		extcmd = safe_malloc(strlen(config->processPkt)+strlen(fileName)+2);
		sprintf(extcmd,"%s %s",config->processPkt,fileName);
		w_log('6', "ProcessPkt: execute string \"%s\"",extcmd);
		if ((cmdexit = system(extcmd)) != 0)
		    w_log('9', "exec failed, code %d", cmdexit);
		nfree(extcmd);
	    }
	/* -AS- */
#ifdef DO_PERL
	if (perlpkt(fileName, (sec==secLocalInbound || sec==secProtInbound) ? 1 : 0))
	    return 6;
#endif
       
	pkt = fopen(fileName, "rb");
	if (pkt == NULL) return 2;
       
	header = openPkt(pkt);
	if (header != NULL) {
	    if ((to_us(header->destAddr)==0) || (sec == secLocalInbound)) {
		w_log('7', "pkt: %s [%s]", fileName, aka2str(header->origAddr));
		statToss.pkts++;
		link = getLinkFromAddr(*config, header->origAddr);
		if ((link!=NULL) && (link->pktPwd==NULL) && (header->pktPassword[0]!='\000'))
		    w_log('9', "Unexpected Password %s.", header->pktPassword);
	   
		switch (sec) {
		case secLocalInbound:
		    processIt = 1;
		    break;
	     
		case secProtInbound:
		    if ((link != NULL) && (link->pktPwd != NULL) && link->pktPwd[0]) {
			if (stricmp(link->pktPwd, header->pktPassword)==0) {
			    processIt = 1;
			} else {
			    if ( (header->pktPassword == NULL || header->pktPassword[0] == '\0') && (link->allowEmptyPktPwd & (eSecure | eOn)) ) {
				w_log('9', "pkt: %s Warning: missing packet password from %i:%i/%i.%i",
				      fileName, header->origAddr.zone, header->origAddr.net,
				      header->origAddr.node, header->origAddr.point);
				processIt = 1;
			    } else {
				w_log('9', "pkt: %s Password Error for %i:%i/%i.%i",
				      fileName, header->origAddr.zone, header->origAddr.net,
				      header->origAddr.node, header->origAddr.point);
				if (header->pktPassword == NULL || header->pktPassword[0] == '\0')
				    processIt = 2;
				else
				    rc = 1;
			    }
			}
		    } else if ((link != NULL) && ((link->pktPwd == NULL) || (strcmp(link->pktPwd, "")==0))) {
			processIt=1;
		    } else /* if (link == NULL) */ {	
			w_log('9', "pkt: %s No Link for %i:%i/%i.%i, processing only Netmail",
			      fileName, header->origAddr.zone, header->origAddr.net,
			      header->origAddr.node, header->origAddr.point);
			processIt = 2;
		    }
		    break;

		case secInbound:
		    if ((link != NULL) && (link->pktPwd != NULL) && link->pktPwd[0]) {

			if (header->pktPassword && stricmp(link->pktPwd, header->pktPassword)==0) {
			    processIt = 1;
			} else {
			    if ( (header->pktPassword == NULL || header->pktPassword[0] == '\0') && (link->allowEmptyPktPwd & (eOn)) ) {
				w_log('9', "pkt: %s Warning: missing packet password from %i:%i/%i.%i",
				      fileName, header->origAddr.zone, header->origAddr.net,
				      header->origAddr.node, header->origAddr.point);
				processIt = 2; /* Unsecure inbound, do not process echomail */
			    } else {
				w_log('9', "pkt: %s Password Error for %i:%i/%i.%i",
				      fileName, header->origAddr.zone, header->origAddr.net,
				      header->origAddr.node, header->origAddr.point);
				rc = 1;
			    }
			}
		    } else if ((link != NULL) && ((link->pktPwd == NULL) || (strcmp(link->pktPwd, "")==0))) {
			processIt=1;
		    } else /* if (link == NULL) */ {	
			w_log('9', "pkt: %s No Link for %i:%i/%i.%i, processing only Netmail",
			      fileName, header->origAddr.zone, header->origAddr.net,
			      header->origAddr.node, header->origAddr.point);
			processIt = 2;
		    }
		    break;
	     
		}
	   
		if (processIt != 0) {
		    realtime = time(NULL);
		    while ((msgrc = readMsgFromPkt(pkt, header, &msg)) == 1) {
			if (msg != NULL) {
			    if ((processIt == 1) || ((processIt==2) && (msg->netMail==1))) {
				if (processMsg(msg, header,
					       (sec==secLocalInbound ||
						sec==secProtInbound ||
						processIt == 1) ? 1 : 0) != 1 )
				    if (putMsgInBadArea(msg, header->origAddr, 6)==0)
					rc = 5; // can't write to badArea - rename to .err
			    } else rc = 1;
			    freeMsgBuffers(msg);
			    nfree(msg);
			}
		    }
		    if (msgrc==2) rc = 3; // rename to .bad (wrong msg format)
		    // real time of process pkt & msg without external programs
		    statToss.realTime += time(NULL) - realtime;
		}
	   
	    } else {
		realtime = time(NULL);
		while ((msgrc = readMsgFromPkt(pkt, header, &msg)) == 1) {
		    if (msg != NULL) {
			if (msg->netMail==1)
			    {   if (processMsg(msg, header, (sec==secLocalInbound || sec==secProtInbound) ? 1 : 0) !=1 )
				rc=5;
			    } else
				break;
			freeMsgBuffers(msg);
			nfree(msg);
		    }
		}
		if (msg)
		    {	/* echomail pkt not for us */
			freeMsgBuffers(msg);
			nfree(msg);
	   
	  		/* PKT is not for us - try to forward it to our links */

			w_log('9', "pkt: %s addressed to %d:%d/%d.%d but not for us", 
			      fileName, header->destAddr.zone, header->destAddr.net,       
			      header->destAddr.node, header->destAddr.point);
	   
			fclose(pkt); pkt = NULL;
			rc = forwardPkt(fileName, header, sec);	   
		    }
	    }
	 
	    nfree(header);
	 
	} else { // header == NULL
	    w_log('9', "pkt: %s wrong pkt-file", fileName);
	    rc = 3;
	}
       
	if (pkt) fclose(pkt);

    } else statToss.empty++;

#ifdef DO_PERL
    perlpktdone(fileName, rc);
#endif

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

#ifdef __WATCOMC__
void *mk_lst(char *a) {
    char *p=a, *q=a, **list=NULL, end=0, num=0;

    while (*p && !end) {
	while (*q && !isspace(*q)) q++;
	if (*q=='\0') end=1;
	*q ='\0';
	list = (char **) safe_realloc(list, ++num*sizeof(char*));
	list[num-1]=(char*)p;
	if (!end) {
	    p=q+1;
	    while(isspace(*p)) p++;
	}
	q=p;
    }
    list = (char **) safe_realloc(list, (++num)*sizeof(char*));
    list[num-1]=NULL;

    return list;
}
#endif

int  processArc(char *fileName, e_tossSecurity sec)
{
    int  i, j, found;
    signed int cmdexit;
    FILE  *bundle;
    char cmd[256];

#ifdef __WATCOMC__
    const char * const *list;
#endif

    if (sec == secInbound) {
	w_log('9', "bundle %s: tossing in unsecure inbound, security violation", fileName);
	return 1;
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
	w_log('6', "bundle %s: unpacking with \"%s\"", fileName, cmd);
    if( hpt_stristr(config->unpack[i-1].call, "zipInternal") )
    {
        cmdexit = 1;
#ifdef USE_HPT_ZLIB
        cmdexit = UnPackWithZlib(fileName, config->tempInbound);
#endif
    }
    else
    {
#ifdef __WATCOMC__
        list = mk_lst(cmd);
        cmdexit = spawnvp(P_WAIT, cmd, list);
        free((char **)list);
        if (cmdexit != 0) {
            w_log('9', "exec failed: %s, return code: %d", strerror(errno), cmdexit);
            return 3;
        }
#else
        if ((cmdexit = system(cmd)) != 0) {
            w_log('9', "exec failed, code %d", cmdexit);
            return 3;
        }
#endif
    }
	if (config->afterUnpack) {
	    w_log('6', "afterUnpack: execute string \"%s\"", config->afterUnpack);
	    if ((cmdexit = system(config->afterUnpack)) != 0) {
		w_log('9', "exec failed, code %d", cmdexit);
	    };
	}
#ifdef DO_PERL
	perlafterunp();
#endif
    } else {
	w_log('9', "bundle %s: cannot find unpacker", fileName);
	return 3;
    };
    statToss.arch++;
    remove(fileName);
    processDir(config->tempInbound, sec);
    return 7;
}


typedef struct fileInDir {
    char *fileName;
    time_t fileTime;
} s_fileInDir;
 
int filesComparer(const void *elem1, const void *elem2) {
    // File times comparer for qsort
    if (((s_fileInDir *) elem1) -> fileTime < ((s_fileInDir *) elem2) -> fileTime) return -1;
    if (((s_fileInDir *) elem1) -> fileTime == ((s_fileInDir *) elem2) -> fileTime) return 0;
    return 1;
}

char *validExt[] = {"*.MO?", "*.TU?", "*.TH?", "*.WE?", "*.FR?", "*.SA?", "*.SU?"};

void processDir(char *directory, e_tossSecurity sec)
{
    DIR            *dir;
    struct dirent  *file;
    char           *dummy = NULL;
    int            rc, i;
    int            pktFile,
	arcFile;
    s_fileInDir *files = NULL;
    int nfiles=0;
    struct stat st;
    int dirNameLen;
    int filenum;
    char *newFileName=NULL;
    char *ext[]={NULL, "sec", "asc", "bad", "ntu", "err", "flt"};

#ifndef UNIX
    unsigned fattrs;
#endif

    if (directory==NULL) return;

    tossDir = directory;

    dirNameLen = strlen(directory);

#ifdef NOSLASHES
    directory[dirNameLen-1]='\0';
#endif

    if (NULL == (dir = opendir(directory))) {
	printf("Can't open dir: %s!\n",directory);
	return;
    }

#ifdef NOSLASHES
    directory[dirNameLen-1]='\\';
#endif

    while ((file = readdir(dir)) != NULL) {
#ifdef DEBUG_HPT
	printf("testing %s\n", file->d_name);
#endif

	dummy = (char *) safe_malloc(dirNameLen + strlen(file->d_name) + 1);
	strcpy(dummy,directory);
	strcat(dummy,file->d_name);

#if !defined(UNIX)
#if defined(__TURBOC__) || defined(__DJGPP__)
	_dos_getfileattr(dummy, &fattrs);
#elif defined(__MINGW32__)
	fattrs = (GetFileAttributes(dummy) & 0x2) ? _A_HIDDEN : 0;
#else
	fattrs = file->d_attr;
#endif
	if(fattrs & _A_HIDDEN) {
	    nfree(dummy);
	} else
#endif
	    {
		nfiles++;
		files = (s_fileInDir *) safe_realloc(files,nfiles*sizeof(s_fileInDir));
		(files[nfiles-1]).fileName = dummy;

		if(stat((files[nfiles-1]).fileName, &st)==0) {
		    (files[nfiles-1]).fileTime = st.st_mtime;
		} else {
		    // FixMe - don't know what to set :(
		    (files[nfiles-1]).fileTime = 0L;
		}

	    }
    }
    closedir(dir);

    qsort (files, nfiles, sizeof(s_fileInDir), filesComparer);

    for ( filenum=0; filenum < nfiles; filenum++) {
	arcFile = pktFile = 0;
	dummy = (files[filenum]).fileName;
#ifdef DEBUG_HPT
	printf("testing sorted %s\n", dummy);
#endif
	if (!(pktFile = patimat(dummy+dirNameLen, "*.pkt") == 1))
	    for (i = 0; i < sizeof(validExt) / sizeof(char *); i++)
		if (patimat(dummy+dirNameLen, validExt[i]) == 1)
		    arcFile = 1;

	if (pktFile || (arcFile && !config->noProcessBundles)) {

	    rc = 3; // nonsence, but compiler warns
	    if (config->tossingExt != NULL &&
		(newFileName=changeFileSuffix(dummy, config->tossingExt)) != NULL){
		nfree(dummy);
		dummy = newFileName;
		newFileName=NULL;
	    }
	    if (pktFile)
		rc = processPkt(dummy, sec);
	    else // if (arcFile)
		rc = processArc(dummy, sec);

	    if (rc>=1 && rc<=6) {
		w_log('9', "Renaming pkt/arc to .%s",ext[rc]);
		newFileName=changeFileSuffix(dummy, ext[rc]);
	    } else {
		if (rc!=7) remove(dummy);
	    }
	}
	nfree(dummy);
	nfree(newFileName);
    }
    nfree(files);
}

void writeStatLog(void) {
    /* write personal mail statistic logfile if statlog is defined in config */
    /* if the log file exists, the existing value is increased */

    FILE *f;
    char buffer[256];
    int len, x, statNetmail, statCC;

    statNetmail = statToss.netMail; /* number of just received netmails */
    statCC = statToss.CC; /* number of just received personal echo mails */

    /* if there are new personal mails and statLog is defined in config */
    if (((statNetmail > 0) || (statCC > 0)) && (config->statlog != NULL)) {
	f = fopen(config->statlog, "r");
	if (f != NULL) {  /* and statLog file is readable */
	    /* then read last personal mail counter and add to actual counter */
	    while(fgets(buffer,sizeof(buffer),f)) {
		len = strlen(buffer);
		for (x=0; x!=len; x++) {
		    if (!strncasecmp(buffer+x, "netmail: ",9)) {
			/* netmail found */
			statNetmail += atoi(buffer+9);
		    }

		    if (!strncasecmp(buffer+x, "CC: ",4)) {
			/* personal echomail (CC) found */
			statCC += atoi(buffer+4);
		    }
		}
	    }

	    fclose(f);
	}

	/* and write personal mail counter for netmails and echo mails */
	f = fopen(config->statlog, "wt");
	if (f != NULL) {
	    if (statNetmail > 0) {
		fprintf(f, "netmail: %d\n", statNetmail);
	    }
	    if (statCC > 0) {
		fprintf(f, "CC: %d\n", statCC);
	    }
		 
	    fclose(f);
	}
    }
}

void writeTossStatsToLog(void) {
    int i;
    float inMailsec, outMailsec, inKBsec;
    time_t diff = statToss.realTime;
    char logchar;

    if (statToss.pkts==0 && statToss.msgs==0)
	logchar='1';
    else
	logchar='4';

    if (diff == 0) diff = 1;

    inMailsec = ((float)(statToss.msgs)) / diff;
    outMailsec = ((float)(statToss.exported)) / diff;
    inKBsec = ((float)(statToss.inBytes)) / diff / 1024;

    w_log(logchar, "Statistics:");
    w_log(logchar, "     arc: % 5d   netMail: % 4d   echoMail: % 5d         CC: % 5d",
	  statToss.arch, statToss.netMail, statToss.echoMail, statToss.CC);
    w_log(logchar, "   pkt's: % 5d      dupe: % 4d   passthru: % 5d   exported: % 5d",
	  statToss.pkts, statToss.dupes, statToss.passthrough, statToss.exported);
    w_log(logchar, "    msgs: % 5d       bad: % 4d      saved: % 5d      empty: % 5d",
	  statToss.msgs, statToss.bad, statToss.saved, statToss.empty);
    w_log(logchar, "   Input: % 8.2f mails/sec        Output: % 8.2f mails/sec", inMailsec, outMailsec);
    w_log(logchar, "          % 8.2f kb/sec", inKBsec);

    /* write personal mail statistic logfile */
    writeStatLog();

    /* Now write areas summary */
    w_log(logchar, "Areas summary:");
    for (i = 0; i < config->netMailAreaCount; i++)
	if (config->netMailAreas[i].imported > 0)
	    w_log(logchar, "netmail area %s - %d msgs", 
		  config->netMailAreas[i].areaName, config->netMailAreas[i].imported);
    if (config->dupeArea.imported) w_log(logchar, "dupe area %s - %d msgs", 
					 config->dupeArea.areaName,
					 config->dupeArea.imported);
    if (config->badArea.imported) w_log(logchar, "bad area %s - %d msgs", 
					config->badArea.areaName,
					config->badArea.imported);
    for (i = 0; i < config->echoAreaCount; i++)
	if (config->echoAreas[i].imported > 0)
	    w_log(logchar, "echo area %s - %d msgs", 
		  config->echoAreas[i].areaName, config->echoAreas[i].imported);
    for (i = 0; i < config->localAreaCount; i++)
	if (config->localAreas[i].imported > 0)
	    w_log(logchar, "local area %s - %d msgs", 
		  config->localAreas[i].areaName, config->localAreas[i].imported);
}

int find_old_arcmail(s_link *link, FILE *flo)
{
    char *line, *bundle=NULL;
    long len;
    unsigned i, as;

    while ((line = readLine(flo)) != NULL) {
#ifndef UNIX
	line = trimLine(line);
#endif
	for (i = 0; i < sizeof(validExt) / sizeof(char *); i++)
	    if (patimat(line, validExt[i]) == 1) {
		if (*line!='~') {
		    nfree(bundle);
		    // One char for first symbol in flo file
		    bundle = safe_strdup(line + 1);
		}
		break;
	    }
	nfree(line);
    }
    if (bundle == NULL) return 0;
    if (*bundle != '\000') {
	len = fsize(bundle);
	if (len != -1L) {
	    if (link->arcmailSize!=0) 
		as = link->arcmailSize;
	    else if (config->defarcmailSize!=0) 
		as = config->defarcmailSize;
	    else
		as = 500; // default 500 kb max
	    if (len < as * 1024L) {
		link->packFile=(char*) safe_realloc(link->packFile,strlen(bundle)+1);
		strcpy(link->packFile,bundle);
		nfree(bundle);
		return 1;
	    }
	}
    }
    nfree(bundle);
    return 0;
}

void arcmail(s_link *tolink) {
    char cmd[256], *pkt=NULL, *lastPathDelim, saveChar;
    int i, cmdexit, foa;
    FILE *flo;
    s_link *link;
    int startlink=0;
    int endlink = config->linkCount;
    e_bundleFileNameStyle bundleNameStyle;
#ifdef __WATCOMC__
    const char * const *list;
#endif

    if (tolink != NULL) {
	startlink = tolink - config->links;
	endlink = startlink + 1;
    }

    if (config->beforePack) {
	w_log('6', "beforePack: execute string \"%s\"", config->beforePack);
	if ((cmdexit = system(config->beforePack)) != 0) {
	    w_log('9', "exec failed, code %d", cmdexit);
	};
    }
#ifdef DO_PERL
    perlbeforepack();
#endif

    for (i = startlink ; i < endlink; i++) {

	link = &(config->links[i]);

	// only create floFile if we have mail for this link
	if (link->pktFile != NULL) {
      

	    if (needUseFileBoxForLink(link)) {

		if (!link->fileBox) link->fileBox = makeFileBoxName (link);

		if (link->packerDef != NULL) {

		    fillCmdStatement(cmd, link->packerDef->call,
				     link->packFile,
				     link->pktFile, "");
		    w_log('7', "Packing for %s %s, %s > %s",
			  aka2str(link->hisAka),
			  link->name, get_filename(link->pktFile),
			  get_filename(link->packFile));
		    w_log('6', "cmd: %s", cmd);
            if( stricmp(link->packerDef->call, "zipInternal") == 0 )
            {
                cmdexit = 1;
#ifdef USE_HPT_ZLIB
                cmdexit = PackWithZlib(link->packFile, link->pktFile);
#endif
            }
            else
            {
#ifdef __WATCOMC__
		        list = mk_lst(cmd);
		        cmdexit = spawnvp(P_WAIT, cmd, list);
		        free((char **)list);
#else
		        cmdexit = system(cmd);
#endif
            }
		    if (cmdexit==0) remove(link->pktFile);
		    else w_log('9', "Error executing packer (errorlevel==%i)", cmdexit);

		} // end packerDef
		else {
		    // there is no packer defined -> put pktFile into fileBox
		    xstrcat(&pkt, link->fileBox);
		    xstrcat(&pkt, link->pktFile + strlen(config->tempOutbound));

		    cmdexit = rename(link->pktFile, pkt);
		    if (cmdexit==0) w_log('7', "Leave non-packed mail for %s %s, %s",
					  aka2str(link->hisAka), link->name,
					  get_filename(link->pktFile));
		    else w_log('9', "error moving file for %s %s, %s->%s (errorlevel==%i)", aka2str(link->hisAka), link->name, link->pktFile, pkt, errno);
		    nfree(pkt);
		}
    
	    } else if (createOutboundFileName(link,
					      cvtFlavour2Prio(link->echoMailFlavour),
					      FLOFILE) == 0) {
		// process if the link not busy, else do not create 12345678.?lo

		flo = fopen(link->floFile, "a+");

		if (flo == NULL)
		    w_log('9', "Cannot open flo file %s",
			  config->links[i].floFile);
		else {

		    if (link->linkBundleNameStyle!=eUndef)
			bundleNameStyle=link->linkBundleNameStyle;
		    else if (config->bundleNameStyle!=eUndef)
			bundleNameStyle=config->bundleNameStyle;
		    else bundleNameStyle = eTimeStamp;

		    if (link->packerDef != NULL) {

			// there is a packer defined -> put packFile into flo
			// if we are creating new arcmail bundle  ->  -//-//-
			fseek(flo, 0L, SEEK_SET);
			foa = find_old_arcmail(link, flo);

			fillCmdStatement(cmd, link->packerDef->call,
					 link->packFile,
					 link->pktFile, "");
			w_log('7', "Packing for %s %s, %s > %s",
			      aka2str(link->hisAka), link->name,
			      get_filename(link->pktFile),
			      get_filename(link->packFile));
			w_log('6', "cmd: %s", cmd);
            if( stricmp(link->packerDef->call, "zipInternal") == 0 )
            {
                cmdexit = 1;
#ifdef USE_HPT_ZLIB
                cmdexit = PackWithZlib(link->packFile, link->pktFile);
#endif
            }
            else
            {
#ifdef __WATCOMC__
			    list = mk_lst(cmd);
			    cmdexit = spawnvp(P_WAIT, cmd, list);
			    free((char **)list);
#else
                cmdexit = system(cmd);
#endif
            }
			if (cmdexit==0) {
			    if (foa==0) {
				if (bundleNameStyle == eAddrDiff ||
				    bundleNameStyle == eAddrDiffAlways ||
				    bundleNameStyle == eAmiga)
				    fprintf(flo, "#%s\n", link->packFile);
				else
				    fprintf(flo, "^%s\n", link->packFile);
			    }
			    remove(link->pktFile);
			} else
			    w_log('9', "Error executing packer (errorlevel==%i)", 
				  cmdexit);

		    } // end packerDef
		    else {
			// there is no packer defined -> put pktFile into flo
			lastPathDelim = strrchr(link->floFile, PATH_DELIM);

			// change path of file to path of flofile
			saveChar = *(++lastPathDelim);
			*lastPathDelim = '\0';
			xstrcat(&pkt, link->floFile);
			*lastPathDelim = saveChar;

			if (config->separateBundles) {

			    if (bundleNameStyle==eAmiga)
				xscatprintf(&pkt, "%u.%u.%u.%u.sep%c", 
					    link->hisAka.zone, link->hisAka.net,
					    link->hisAka.node, link->hisAka.point,
					    PATH_DELIM);
			    else {
				if (link->hisAka.point != 0)
				    xscatprintf(&pkt,"%08x.sep%c",
						link->hisAka.point,PATH_DELIM);
				else
				    xscatprintf(&pkt, "%04x%04x.sep%c",
						link->hisAka.net,
						link->hisAka.node, 
						PATH_DELIM);
			    }
			}

			xstrcat(&pkt, link->pktFile + strlen(config->tempOutbound));

			cmdexit = rename(link->pktFile, pkt);
			if (cmdexit==0) {
			    fprintf(flo, "^%s\n", pkt);
			    w_log('7', "Leave non-packed mail for %s %s, %s",
				  aka2str(link->hisAka), link->name,
				  get_filename(link->pktFile));
			}
			else w_log('9', "error moving file for %s %s, %s->%s (errorlevel==%i)", aka2str(link->hisAka), link->name, link->pktFile, pkt, errno);
			nfree(pkt);
		    }

		    fclose(flo);
		} // end flo

		nfree(link->floFile);
		remove(link->bsyFile);
		nfree(link->bsyFile);
	    } // end outboundFileNameCreated

	    nfree(link->pktFile);
	    nfree(link->packFile);
	} // end pkt file

    } // endfor
    return;
}

static int forwardedPkts = 0;

int forwardPkt(const char *fileName, s_pktHeader *header, e_tossSecurity sec)
{
    int i;
    s_link *link;
    char *newfn;
    
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
		    
		w_log('7', "Forwarding %s to %s as %s",
		      fileName, config->links[i].name, newfn + strlen(config->tempOutbound));

		nfree(newfn);
		forwardedPkts = 1;
		return 0;
	    }
	    else
		{
		    w_log('9', "Failure moving %s to %s (%s)", fileName,
			  newfn, strerror(errno));
		    nfree(newfn);
		    return 4;
		}

	}
    }

    w_log('9', "Packet %s is not to us or our links",fileName);

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
	    newname = safe_strdup(filename);

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
	    nfree(newname);
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
#ifdef NOSLASHES
    int 		  dirNameLen;
#endif

    if (directory==NULL) return;

#ifdef NOSLASHES
    dirNameLen = strlen(directory);
    directory[dirNameLen-1]='\0';
#endif

    if (NULL == (dir = opendir(directory))) {
        printf("Can't open dir: %s!\n",directory);
	return;
    }

#ifdef NOSLASHES
    directory[dirNameLen-1]='\\';
#endif

    while ((file = readdir(dir)) != NULL) {
	l = strlen(file->d_name);
	if (l > 4 && (stricmp(file->d_name + l - 4, ".pkt") == 0 ||
		      stricmp(file->d_name + l - 4, ".qqq") == 0))
	    {
		dummy = (char *) safe_malloc(strlen(directory)+l+1);
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

		    if (link->packFile == NULL) {
			if ( createTempPktFileName(link) )
			    exit_hpt("Could not create new bundle!",1);
		    }

		    nfree(link->pktFile);
		    link->pktFile = dummy;

		    fclose(pkt);
		    arcmail(link);
		} else {
		    nfree(dummy);
		    w_log('9', "found non packed mail without matching link in tempOutbound");
		    fclose(pkt);
		}
	    }
    }

    closedir(dir);
    return;
}

void writeImportLog(void) {
    int i;
    FILE *f;
    struct stat buf;

    if (config->importlog) {

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

	} else w_log('9', "Could not open importlogfile");

	// remove empty importlog
	if (stat(config->importlog, &buf)==0) {
	    if (buf.st_size==0) remove(config->importlog);
	}
	
    }
}

void toss()
{
    FILE *f;

    // set stats to 0
    memset(&statToss, '\0', sizeof(s_statToss));
    w_log('1', "Start tossing...");
    processDir(config->localInbound, secLocalInbound);
    processDir(config->protInbound, secProtInbound);
    processDir(config->inbound, secInbound);
    nfree(globalBuffer); // free msg->text global buffer

    writeDupeFiles();
    writeImportLog();

    if (forwardedPkts) {
	tossTempOutbound(config->tempOutbound);
	forwardedPkts = 0;
    }

    // write statToss to Log
    writeTossStatsToLog();
    tossTempOutbound(config->tempOutbound);

    // create flag for netmail trackers
    if (config->netmailFlag && statToss.netMail) {
	if (NULL == (f = fopen(config->netmailFlag,"a"))) w_log('9', "Could not create netmail flag: %s", config->netmailFlag);
	else {
	    w_log('0', "Created netmail flag: %s", config->netmailFlag);
	    fclose(f);
	}
    }
}

int packBadArea(HMSG hmsg, XMSG xmsg, char force)
{
    int		rc = 0;
    s_message   msg;
    s_area	*echo = &(config -> badArea);
    s_addr	pktOrigAddr;
    char 	*ptmp, *line, *areaName, *area=NULL, noexp=0;
    s_link   *link;
   
    makeMsg(hmsg, xmsg, &msg, &(config->badArea), 2);
    memset(&pktOrigAddr,'\0',sizeof(s_addr));
    statToss.msgs++; // really processed one more msg
   
    // deleting valet string - "FROM:" and "REASON:"
    ptmp = msg.text;
    while ((line = strchr(ptmp, '\r')) != NULL) {
	/* Temporary make it \0 terminated string */
	*line = '\000';
	if (strncmp(ptmp, "FROM: ", 6) == 0 || 
	    strncmp(ptmp, "REASON: ", 8) == 0 || 
	    strncmp(ptmp, "AREANAME: ", 10) == 0) {
	    // It's from address
	    if (*ptmp == 'F') string2addr(ptmp + 6, &pktOrigAddr);
	    // Don't export to links
	    if (*ptmp == 'R') {
		if (strstr(ptmp, "MSGAPIERR: ")!=NULL) noexp=1;
	    }
	    // Cut this kludges
	    if (*ptmp=='A') {
		if (area==NULL) {
		    echo = getArea(config, ptmp+10);
		    xstrcat(&area, ptmp+10);
		}
		memmove(ptmp, line+1, strlen(line+1)+1);	  
		break;
	    } else {
		memmove(ptmp, line+1, strlen(line+1)+1);	  
		continue;
	    }
	} else { 
	    if ((strncmp(ptmp, "AREA:", 5)==0 ||
		 strncmp(ptmp, "\001AREA:", 6)==0) && area==NULL) {
		//translating name of the area to uppercase
		strUpper(ptmp);
		areaName = (*ptmp!='\001') ? ptmp+5 : ptmp+6;
		// if the areaname begins with a space
		while (*areaName == ' ') areaName++;
		echo = getArea(config, areaName);
		xstrcat(&area, areaName);
	    };
	    ptmp = line+1;
	};
	*line = '\r';
    }

    if (echo == &(config->badArea)) {
	link = getLinkFromAddr(*config, pktOrigAddr);
	if (link && link->autoAreaCreate!=0 && area) {
	    if (0 == autoCreate(area, pktOrigAddr, NULL))
		echo = getArea(config, area);
	}
    }
    nfree(area);
   
    if (echo == &(config->badArea)) {
	freeMsgBuffers(&msg);
	return rc;
    }
   
    if (checkAreaLink(echo, pktOrigAddr, 0) == 0 || force) {
	if (dupeDetection(echo, msg)==1 || noexp) {
	    // no dupe or toss whithout export to links
		   
	    if (config->carbonCount != 0) carbonCopy(&msg, NULL, echo);
		   
	    echo->imported++;  // area has got new messages
	    if (echo->msgbType != MSGTYPE_PASSTHROUGH) {
		rc = putMsgInArea(echo, &msg,1, 0);
		statToss.saved += rc;
	    } else {
		statToss.passthrough++;
		rc = 1; // passthrough always work
	    }

	    if (noexp==0) { // recode & export to links
		// recoding from internal to transport charSet
		if (config->outtab) {
		    if (msg.recode & REC_HDR) {
			recodeToTransportCharset((CHAR*)msg.fromUserName);
			recodeToTransportCharset((CHAR*)msg.toUserName);
			recodeToTransportCharset((CHAR*)msg.subjectLine);
			msg.recode &= ~REC_HDR;
		    }
		    if (msg.recode & REC_TXT) {
			recodeToTransportCharset((CHAR*)msg.text);
			msg.recode &= ~REC_TXT;
		    }
		}
   
		if (echo->downlinkCount > 0) {
		    forwardMsgToLinks(echo, &msg, pktOrigAddr);
		}
	    }

	} else {
	    // msg is dupe
	    if (echo->dupeCheck == dcMove) {
		rc = putMsgInArea(&(config->dupeArea), &msg, 0, 0);
	    } else rc = 1; // dupeCheck del
	    if (rc) config->dupeArea.imported++;
	}

    } else rc = 0;
   
    freeMsgBuffers(&msg);
    return rc;
}

void tossFromBadArea(char force)
{
    HAREA area;
    HMSG  hmsg;
    XMSG  xmsg;
    dword highestMsg, i;
    int   delmsg;
   
    area = MsgOpenArea((UCHAR *) config->badArea.fileName,
		       MSGAREA_NORMAL, (word)(config->badArea.msgbType|MSGTYPE_ECHO));
    if (area != NULL) {
	w_log('1', "Scanning area: %s", config->badArea.areaName);
	highestMsg = MsgGetHighMsg(area);

	if (config->badArea.msgbType==MSGTYPE_SDM) {
	
	    for (i=1; i<=highestMsg; i++) {
		hmsg = MsgOpenMsg(area, MOPEN_RW, i);
		if (hmsg == NULL) continue;      // msg# does not exist
		MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
		delmsg = packBadArea(hmsg, xmsg, force);
	 
		MsgCloseMsg(hmsg);
	 
		if (delmsg) MsgKillMsg(area, i);
	    }
		   
	} else { // squish & jam. FIXME: hihest msg doesn't updates in JAM.

	    for (i=1; i<=highestMsg; highestMsg--) {
		hmsg = MsgOpenMsg(area, MOPEN_RW, i);
		if (hmsg == NULL) continue;      // msg# does not exist
		MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
		delmsg = packBadArea(hmsg, xmsg, force);
	 
		MsgCloseMsg(hmsg);
	 
		if (delmsg) MsgKillMsg(area, i);
		else { i++; highestMsg++; }
	    }
	}
	   
	MsgCloseArea(area);
	   
	writeDupeFiles();
	writeImportLog();

	w_log('1', "Statistics");
	w_log('1', "    scanned: % 5d   saved: % 7d   CC: % 2d", statToss.msgs, statToss.saved, statToss.CC);
	w_log('1', "    exported: % 4d   passthru: % 4d", statToss.exported, statToss.passthrough);

	tossTempOutbound(config->tempOutbound);
	   
    } else w_log('9', "Could not open %s", config->badArea.fileName);
}
