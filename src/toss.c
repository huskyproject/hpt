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
 * Copyright (C) 1999-2002
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
 *****************************************************************************
 * $Id$
 */
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#if (defined(__EMX__) || defined(__MINGW32__)) && defined(__NT__)
/* we can't include windows.h for several reasons ... */
#define CharToOem CharToOemA
#endif

#if !(defined(__TURBOC__) || (defined (_MSC_VER) && (_MSC_VER >= 1200)))
#include <unistd.h>
#endif

#if defined(OS2)
#include <os2.h>
#endif

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/dirlayer.h>
#include <fidoconf/xstr.h>
#include <fidoconf/afixcmd.h>
#include <fidoconf/temp.h>

#if defined(A_HIDDEN) && !defined(_A_HIDDEN)
#define _A_HIDDEN A_HIDDEN
#endif

#include <pkt.h>
#include <scan.h>
#include <toss.h>
#include <global.h>
#include <seenby.h>
#include <dupe.h>
#include <fidoconf/recode.h>
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
#if (defined(_MSC_VER) && (_MSC_VER >= 1200))
#include <process.h>
#define P_WAIT		_P_WAIT
#endif

#if  defined(__NT__)
/* we can't include windows.h for several reasons ... */
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

static int nopenpkt, maxopenpkt;

s_statToss statToss;
int forwardPkt(const char *fileName, s_pktHeader *header, e_tossSecurity sec);
void processDir(char *directory, e_tossSecurity sec);
void makeMsgToSysop(char *areaName, s_addr fromAddr, s_addr *uplinkAddr);
static void setmaxopen(void);

static char *get_filename(char *pathname)
{
    char *ptr = NULL;

    if (pathname == NULL || !(*pathname))
        return pathname;

    ptr = pathname + strlen(pathname) - 1;

    while (*ptr != '/' && *ptr != '\\' && *ptr != ':' && ptr != pathname)
        ptr--;

    if (*ptr == '/' || *ptr == '\\' || *ptr == ':')
        ptr++;

    return ptr;
}


/* return value: 1 if success, 0 if fail */
int putMsgInArea(s_area *echo, s_message *msg, int strip, dword forceattr)
{
    char *ctrlBuff = NULL, *textStart = NULL, *textWithoutArea = NULL;
    UINT textLength = (UINT) msg->textLength;
    //HAREA harea = NULL;
    HMSG  hmsg;
    XMSG  xmsg;
    char /**slash,*/ *p, *q, *tiny;
    int rc = 0;

    if (echo->msgbType==MSGTYPE_PASSTHROUGH) {
        w_log(LL_ERR, "Can't put message to passthrough area %s!", echo->areaName);
        return rc;
    }

    if (!msg->netMail) {
	msg->destAddr.zone  = echo->useAka->zone;
	msg->destAddr.net   = echo->useAka->net;
	msg->destAddr.node  = echo->useAka->node;
	msg->destAddr.point = echo->useAka->point;
    }

    if (maxopenpkt == 0) setmaxopen();

    if (echo->harea == NULL) {
    w_log( LL_SRCLINE, "%s:%d opening %s", __FILE__, __LINE__,echo->fileName);
	echo->harea = MsgOpenArea((UCHAR *) echo->fileName, MSGAREA_CRIFNEC,
			/*echo->fperm, echo->uid, echo->gid,*/
			(word)(echo->msgbType | (msg->netMail ? 0 : MSGTYPE_ECHO)));
	if (echo->harea) nopenpkt+=3;
    }
    if (echo->harea != NULL) {
    w_log( LL_SRCLINE, "%s:%d creating msg", __FILE__, __LINE__);
	hmsg = MsgOpenMsg(echo->harea, MOPEN_CREATE, 0);
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
	    xmsg = createXMSG(config,msg, NULL, forceattr,tossDir);
        w_log( LL_SRCLINE, "%s:%d writing msg", __FILE__, __LINE__);
	    if (MsgWriteMsg(hmsg, 0, &xmsg, (byte *) textStart, (dword)
			    textLength, (dword) textLength,
			    (dword)strlen(ctrlBuff), (byte*)ctrlBuff)!=0)
		w_log(LL_ERR, "Could not write msg in %s!", echo->fileName);
	    else rc = 1; // normal exit

        w_log( LL_SRCLINE, "%s:%d closing msg", __FILE__, __LINE__);
	    if (MsgCloseMsg(hmsg)!=0) {
		w_log(LL_ERR, "Could not close msg in %s!", echo->fileName);
		rc = 0;
	    }
	    nfree(ctrlBuff);

	} else w_log(LL_ERR, "Could not create new msg in %s!", echo->fileName);
	/* endif */
	if (nopenpkt>=maxopenpkt-12) {
        w_log( LL_SRCLINE, "%s:%d closing %s", __FILE__, __LINE__,echo->fileName);
	    MsgCloseArea(echo->harea);
	    echo->harea = NULL;
	    nopenpkt-=3;
	}
    } else w_log(LL_ERR, "Could not open/create EchoArea %s!", echo->fileName);
    /* endif */
    w_log( LL_SRCLINE, "%s:%d end rc=%d", __FILE__, __LINE__,rc);
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


void closeOpenedPkt(void) {
    unsigned int i;

    for (i=0; i<config->linkCount; i++)
	if (config->links[i].pkt) {
	    if (closeCreatedPkt(config->links[i].pkt))
		w_log(LL_ERR,"can't close pkt: %s", config->links[i].pktFile);
	    config->links[i].pkt = NULL;
	    nopenpkt--;
	}
    for (i=0; i<config->echoAreaCount; i++)
	if (config->echoAreas[i].harea) {
        w_log( LL_SRCLINE, "%s:%d closing %s", __FILE__, __LINE__,config->echoAreas[i].fileName);
	    MsgCloseArea(config->echoAreas[i].harea);
	    config->echoAreas[i].harea = NULL;
	    nopenpkt-=3;
	}
    for (i=0; i<config->netMailAreaCount; i++)
	if (config->netMailAreas[i].harea) {
        w_log( LL_SRCLINE, "%s:%d closing %s", __FILE__, __LINE__,config->netMailAreas[i].fileName);
	    MsgCloseArea(config->netMailAreas[i].harea);
	    config->netMailAreas[i].harea = NULL;
	    nopenpkt-=3;
    }
    for (i=0; i<config->localAreaCount; i++)
    {
        if (config->localAreas[i].harea) {
            w_log( LL_SRCLINE, "%s:%d closing %s", __FILE__, __LINE__,config->localAreas[i].fileName);
            MsgCloseArea(config->localAreas[i].harea);
            config->localAreas[i].harea = NULL;
            nopenpkt-=3;
        }
    }
    if (config->badArea.harea) {
        w_log( LL_SRCLINE, "%s:%d closing %s", __FILE__, __LINE__,config->badArea.fileName);
        MsgCloseArea(config->badArea.harea);
        config->badArea.harea = NULL;
        nopenpkt-=3;
    }
    if (config->dupeArea.harea) {
        w_log( LL_SRCLINE, "%s:%d closing %s", __FILE__, __LINE__,config->dupeArea.fileName);
        MsgCloseArea(config->dupeArea.harea);
        config->dupeArea.harea = NULL;
        nopenpkt-=3;
    }
}

void forwardToLinks(s_message *msg, s_area *echo, s_arealink **newLinks,
		    s_seenBy **seenBys, UINT *seenByCount,
		    s_seenBy **path, UINT *pathCount) {
    unsigned  int i, rc=0;
    ULONG len;
    FILE *f=NULL;
    s_pktHeader header;
    char *start = NULL, *text = NULL, *seenByText = NULL, *pathText = NULL;
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
	    w_log(LL_ERR,"can't open file: %s",debug);
	}else w_log(LL_FILE,"toss.c:forwardToLinks(): opened %s (\"a\" mode)",debug);
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
	debug = (char *) GetCtrlToken((byte *)msg->text, (byte *)"MSGID");
	if (f && debug) {
	    fputs("\n[",f);
	    fputs(debug,f);
	    fputs("] ",f);
	}
	nfree(debug);
    }

    // add msg to the pkt's of the downlinks
    if (maxopenpkt == 0) setmaxopen();
    for (i = 0; i<echo->downlinkCount; i++) {
        
        // no link at this index -> break;
        if (newLinks[i] == NULL) break;
        
        // check packet size
        if (newLinks[i]->link->pktFile != NULL && newLinks[i]->link->pktSize != 0) {
            len = newLinks[i]->link->pkt ? ftell(newLinks[i]->link->pkt) : fsize(newLinks[i]->link->pktFile);
            if (len >= (newLinks[i]->link->pktSize * 1024L)) { // Stop writing to pkt
                if (newLinks[i]->link->pkt) {
                    fclose(newLinks[i]->link->pkt);
                    newLinks[i]->link->pkt = NULL;
                    nopenpkt--;
                }
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
        if (newLinks[i]->link->pkt == NULL) {
            newLinks[i]->link->pkt = openPktForAppending(newLinks[i]->link->pktFile, &header);
            nopenpkt++;
        }
        
        // an echomail msg must be adressed to the link
        msg->destAddr = header.destAddr;
        // .. and must come from us
        msg->origAddr = header.origAddr;
        rc += writeMsgToPkt(newLinks[i]->link->pkt, *msg);
        if (rc) w_log(LL_ERR,"can't write msg to pkt: %s",
            newLinks[i]->link->pktFile);
        if (nopenpkt >= maxopenpkt-12 || // std streams, in pkt, msgbase, log
            (newLinks[i]->link->pktSize && ftell(newLinks[i]->link->pkt)>=newLinks[i]->link->pktSize * 1024L)) {
            rc += closeCreatedPkt(newLinks[i]->link->pkt);
            if (rc) w_log(LL_ERR,"can't close pkt: %s",
                newLinks[i]->link->pktFile);
            newLinks[i]->link->pkt = NULL;
            nopenpkt--;
        }
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
    UINT     seenByCount = 0 , pathCount = 0;

    // links who does not have their aka in seenBys and thus have not got the echomail
    s_arealink **newLinks = NULL, **zoneLinks = NULL, **otherLinks = NULL;

    createSeenByArrayFromMsg(echo, msg, &seenBys, &seenByCount);
    createPathArrayFromMsg(msg, &path, &pathCount);

    createNewLinkArray(seenBys, seenByCount, echo, &newLinks, &zoneLinks, &otherLinks, pktOrigAddr);

    if(newLinks)
        forwardToLinks(msg, echo, newLinks, &seenBys, &seenByCount, &path, &pathCount);

    if (zoneLinks) {
        if (echo->useAka->zone != pktOrigAddr.zone) seenByCount = 0;
        forwardToLinks(msg, echo, zoneLinks, &seenBys, &seenByCount, &path, &pathCount);
    }

    if(otherLinks)
    {
        nfree(seenBys);
        seenBys = memdup( path, sizeof(s_seenBy) * pathCount );
        seenByCount = pathCount;
        forwardToLinks(msg, echo, otherLinks, &seenBys, &seenByCount, &path, &pathCount);
    }

    nfree(seenBys);
    nfree(path);
    nfree(newLinks);
    nfree(zoneLinks);
}

#if defined(UNIX) || defined(__EMX__) || defined(__DJGPP__)
#define HAVE_POPEN
#endif

int processExternal (s_area *echo, s_message *msg,s_carbon carbon)
{
    FILE *msgfp = NULL;
    char *fname = NULL;
    char *progname = NULL, *execstr = NULL, *p = NULL;
    int  rc;

    progname = carbon.areaName;
#ifdef HAVE_POPEN	
    if (*progname == '|') {
	msgfp = popen(progname + 1, "w");
    } else
#endif
	msgfp = createTempTextFile(config, &fname);
	
    if (!msgfp) {
	w_log(LL_ERR, "external process %s: cannot create file", progname);
	return 1;
    }else w_log(LL_FILE,"toss.c:processExternal() opened '%s' (\"\" mode)", fname);
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
	    nfree(fname);
	};
    if (rc == -1 || rc == 127) {
	w_log(LL_ERR, "excution of external process %s failed", progname);
    };
    return 0;

}

/* area - area to carbon messages, echo - original echo area */
int processCarbonCopy (s_area *area, s_area *echo, s_message *msg, s_carbon carbon) {
    char *p, *text, *old_text, *reason = carbon.reason;
    int i, old_textLength, export = carbon.export, rc = 0;

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
	if (reason) recodeToTransportCharset((CHAR*)reason);
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
    if (config->intab && reason) recodeToInternalCharset((CHAR*)reason);

    return rc;
}


/* Does carbon copying */
/* Return value: 0 if nothing happend, 1 if there was a carbon copy,
   > 1 if there was a carbon move or carbon delete*/
int carbonCopy(s_message *msg, XMSG *xmsg, s_area *echo)
{
    unsigned int i, rc = 0, result=0;
    char *testptr = NULL, *testptr2 = NULL, *pattern = NULL;
    s_area *area = NULL;
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
        {
            if (!cb->extspawn && // fix for extspawn
                cb->areaName != NULL && // fix for carbonDelete
                // dont CC to the echo the mail comes from
                !stricmp(echo->areaName,area->areaName)
                ) 
                continue;
        }    
        switch (cb->ctype) {
        case ct_to:
            result=patimat(msg->toUserName,cb->str);
            break;
            
        case ct_from:
            result=patimat(msg->fromUserName,cb->str);
            break;
            
        case ct_kludge:
        case ct_msgtext:
            testptr=msg->text;
            /* skip area: kludge */
            if (strncmp(testptr, "AREA:", 5) == 0)
            {
                if ((testptr = strchr(testptr, '\r')) != NULL)
                    testptr++;
            }
            /* cb->str is substring, so pattern must be "*str*" */
            pattern=safe_malloc(strlen(cb->str)+3);
            *pattern='*';
            strcpy(pattern+1, cb->str);
            strcat(pattern, "*");
            result=0;
            
            /* check the message line by line */
            while (testptr) {
                testptr2 = strchr(testptr, '\r');
                if ((*testptr == '\001' && cb->ctype == ct_kludge) ||
                    (*testptr != '\001' && cb->ctype == ct_msgtext)) {
                    if (testptr2) *testptr2 = '\0';
                    result = patimat(testptr, pattern);
                    if (testptr2) *testptr2 = '\r';
                    if (result) break;
                }
                if (testptr2)
                    testptr = testptr2+1;
                else
                    break;
            }
            nfree(pattern);
            break;
            
        case ct_subject:
            result=patimat(msg->subjectLine,cb->str);
            break;
            
        case ct_addr:
            result=!addrComp(msg->origAddr, cb->addr);
            break;
            
        case ct_fromarea:
            result=patimat(echo->areaName,cb->str);
            break;
            
        case ct_group:
            if(echo->group!=NULL){
                /* cb->str for example Fido,xxx,.. */
                testptr=cb->str;
                do{
                    if(NULL==(testptr=fc_stristr(echo->group,testptr)))
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
                    {
                        if (!processCarbonCopy(area,echo,msg,*cb))
                            rc &= 1;
                    }
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

/* return value: 1 if success, 0 if fail */
int putMsgInBadArea(s_message *msg, s_addr pktOrigAddr, int writeAccess)
{
    char *tmp = NULL, *line = NULL, *textBuff=NULL, *areaName=NULL, *reason = NULL;

    w_log(LL_FUNC, "putMsgInBadArea() begin");
    statToss.bad++;
	
    // get real name area
    line = strchr(msg->text, '\r');
    if (strncmp(msg->text,"AREA:",5)==0) {
	*line = 0;
	xstrcat(&areaName, msg->text+5);
	*line = '\r';
    }

    switch (writeAccess) {
    case 0:
	reason = "System not allowed to create new area";
	w_log(LL_ECHOMAIL, "Badmail reason: System not allowed to create new area (%s)", areaName);
	break;
    case 1:
	reason = "Sender not allowed to post in this area (access group)";
	w_log(LL_ECHOMAIL, "Badmail reason: Sender not allowed to post in area %s (access group)", areaName);
	break;
    case 2:
	reason = "Sender not allowed to post in this area (access level)";
	w_log(LL_ECHOMAIL, "Badmail reason: Sender not allowed to post in area %s (access level)", areaName);
	break;
    case 3:
	reason = "Sender not allowed to post in this area (access import)";
	w_log(LL_ECHOMAIL, "Badmail reason: Sender not allowed to post in area %s (access import)", areaName);
	break;
    case 4:
	reason = "Sender not active for this area";
	w_log(LL_ECHOMAIL, "Badmail reason: Sender not active for area %s", areaName);
	break;
    case 5:
	reason = "Rejected by filter";
	w_log(LL_ECHOMAIL, "Badmail reason: Rejected by filter");
	break;
    case 6:
	switch (msgapierr)
    {
	    case MERR_NONE: reason = "MSGAPIERR: No error";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: No error");
		break;
	    case MERR_BADH: reason = "MSGAPIERR: Invalid handle passed to function";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: Invalid handle passed to function");
		break;
	    case MERR_BADF: reason = "MSGAPIERR: Invalid or corrupted file";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: Invalid or corrupted file");
		break;
	    case MERR_NOMEM: reason = "MSGAPIERR: Not enough memory for specified operation";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: Not enough memory for specified operation");
		break;
	    case MERR_NODS:
		reason = "MSGAPIERR: Maybe not enough disk space for operation";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: Maybe not enough disk space for operation");
		w_log(LL_ERR, "Maybe not enough disk space for operation");
		break;
	    case MERR_NOENT: reason = "MSGAPIERR: File/message does not exist";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: File/message does not exist");
		break;
	    case MERR_BADA: reason = "MSGAPIERR: Bad argument passed to msgapi function";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: Bad argument passed to msgapi function");
		break;
	    case MERR_EOPEN: reason = "MSGAPIERR: Couldn't close - messages still open";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: Couldn't close - messages still open");
		break;
	    case MERR_NOLOCK: reason = "MSGAPIERR: Base needs to be locked to perform operation";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: Base needs to be locked to perform operation");
		break;
	    case MERR_SHARE: reason = "MSGAPIERR: Resource in use by other process";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: Resource in use by other process");
		break;
	    case MERR_EACCES: reason = "MSGAPIERR: Access denied (can't write to read-only, etc)";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: Access denied (can't write to read-only, etc)");
		break;
	    case MERR_BADMSG: reason = "MSGAPIERR: Bad message frame (Squish)";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: Bad message frame (Squish)");
		break;
	    case MERR_TOOBIG: reason = "MSGAPIERR: Too much text/ctrlinfo to fit in frame (Squish)";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: Too much text/ctrlinfo to fit in frame (Squish)");
		break;
	    default: reason = "MSGAPIERR: Unknown error";
		w_log(LL_ECHOMAIL, "Badmail reason: MSGAPIERR: Unknown error");
		break;
	    }

	break;
    case 7:
	reason = "Can't create echoarea with forbidden symbols in areatag";
	w_log(LL_ECHOMAIL, "Badmail reason: Can't create echoarea with forbidden symbols in areatag: '%s'", areaName);
	break;
    case 8:
	reason = "Sender not found in config file";
	w_log(LL_ECHOMAIL, "Badmail reason: Sender not found in config file");
	break;
    case 9:
	reason = "Can't open config file";
	w_log(LL_ECHOMAIL, "Badmail reason: Can't open config file");
	break;
    case 10:
	reason = "No downlinks for passthrough area";
	w_log(LL_ECHOMAIL, "Badmail reason: No downlinks for passthrough area '%s'", areaName);
	break;
    case 11:
	reason = "lenght of CONFERENCE name is more than 60 symbols";
	w_log(LL_ECHOMAIL, "Badmail reason: lenght of CONFERENCE name (areatag) is more than 60 symbols: '%s'", areaName);
	break;
    default :
	reason = "Another error";
	w_log(LL_ECHOMAIL, "Badmail reason: Another error");
	break;
    }

#ifdef DO_PERL
    if (perltossbad(msg, areaName, pktOrigAddr, reason)) {
	nfree(areaName);
	nfree(msg->text);
        w_log(LL_FUNC, "putMsgInBadArea():perltossbad OK (rc=1)");
	return 1;
    }
#endif

    tmp = msg->text;

    while ((line = strchr(tmp, '\r')) != NULL) {
	if (*(line+1) == '\x01') tmp = line+1;
	else { tmp = line+1; *line = 0; break; }
    }
	
    xstrscat(&textBuff, msg->text, "\rFROM: ", aka2str(pktOrigAddr), "\rREASON: ", reason, "\r", NULL);

    if (areaName) xscatprintf(&textBuff, "AREANAME: %s\r\r", areaName);
    xstrcat(&textBuff, tmp);
    nfree(areaName);
    nfree(msg->text);
    msg->text = textBuff;
    msg->textLength = strlen(msg->text);
    if (putMsgInArea(&(config->badArea), msg, 0, 0)) {
	config->badArea.imported++;
        w_log(LL_FUNC, "putMsgInBadArea() OK");
	return 1;
    }
    w_log(LL_FUNC, "putMsgInBadArea() failed");
    return 0;
}

void makeMsgToSysop(char *areaName, s_addr fromAddr, s_addr *uplinkAddr)
{
    s_area *echo = NULL;
    unsigned int i, netmail=0;
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
                
                msgToSysop[i] = makeMessage(echo->useAka,
                    echo->useAka,
                    versionStr,
                    netmail ? config->sysop : "All", "Created new areas",
                    netmail,
                    config->areafixKillReports);
                msgToSysop[i]->text = createKludges(config,
                    netmail ? NULL : config->ReportTo,
                    echo->useAka, echo->useAka,
                    versionStr);
                
                xstrscat(&(msgToSysop[i]->text), "\001FLAGS NPD\r",
                    "Action   Name", print_ch(49, ' '), "By\r", NULL);
                // Shitty static variables ....
                xstrscat(&(msgToSysop[i]->text), print_ch(79, '-'), "\r", NULL);
                msgToSysop[i]->recode |= (REC_HDR|REC_TXT);
                w_log(LL_NETMAIL,"Created msg to sysop");
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
            
            break;
        }
    }
    
}

void writeMsgToSysop()
{
    char	*ptr = NULL, *seenByPath = NULL;
    s_area	*echo = NULL;
    unsigned int i, ccrc = 0;
    s_seenBy	*seenBys = NULL;
    
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
                        closeOpenedPkt();
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
    s_arealink *arealink = NULL;
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

int checkRefuse(char *areaName)
{
    FILE *fp;
    char *line;

    if (config->newAreaRefuseFile == NULL)
        return 0;

    fp = fopen(config->newAreaRefuseFile, "r+b");
    if (fp == NULL) w_log(LL_ERR, "Can't open newAreaRefuseFile \"%s\" : %d\n",
                          config->newAreaRefuseFile, strerror(errno));
    while((line = readLine(fp)) != NULL)
    {
        line = trimLine(line);
        if (patimat(areaName, line)) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

int processEMMsg(s_message *msg, s_addr pktOrigAddr, int dontdocc, dword forceattr)
{
    char   *area=NULL, *p = NULL, *q = NULL;
    s_area *echo=&(config->badArea);
    s_link *link = NULL;
    int    writeAccess = 0, rc = 0, ccrc = 0;

    w_log(LL_FUNC, "%s::processEMMsg() begin", __FILE__);

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
        // check if we should not refuse this area
        if (checkRefuse(area))
        {
            // write msg to log file
            w_log(LL_WARN, "Can't create area %s : refused by NewAreaRefuseFile\n", area);
        } else
        {
            // checking for autocreate option
            link = getLinkFromAddr(config, pktOrigAddr);
            if ((link != NULL) && (link->autoAreaCreate != 0)) {
                if (0 == (writeAccess = autoCreate(area, pktOrigAddr, NULL)))
                    echo = getArea(config, area);
                else rc = putMsgInBadArea(msg, pktOrigAddr, writeAccess);
            } // can't create echoarea - put msg in BadArea
            else rc = putMsgInBadArea(msg, pktOrigAddr, writeAccess);
        }
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

                w_log( LL_SRCLINE, "%s::processEMMsg():%d", __FILE__, __LINE__);

		/* todo: remove TID from local-generated msgs by hpt post -x
		 * (if (addrComp(pktOrigAddr,*echo->useAka)==0)) */

		if ((config->carbonCount!=0)&&(!dontdocc))
		    ccrc=carbonCopy(msg, NULL, echo);

                w_log( LL_SRCLINE, "%s::processEMMsg():%d", __FILE__, __LINE__);

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
    w_log(LL_FUNC, "%s::processEMMsg() rc=%d", __FILE__, rc);
    return rc;
}

int processNMMsg(s_message *msg, s_pktHeader *pktHeader, s_area *area, int dontdocc, dword forceattr)
{
    HAREA  netmail;
    HMSG   msgHandle;
    UINT   len = 0;
    char   *bodyStart = NULL;             // msg-body without kludgelines start
    char   *ctrlBuf = NULL;               // Kludgelines
    XMSG   msgHeader;
//    char   *slash = NULL;
    unsigned int rc = 0, ccrc = 0, i;

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

	    msgHeader = createXMSG(config,msg, pktHeader, forceattr,tossDir);
	    /* Create CtrlBuf for SMAPI */
            len = msg->textLength;
	    ctrlBuf = (char *) CopyToControlBuf((UCHAR *) msg->text, (UCHAR **) &bodyStart, &len);
	    /* write message */
	    if (MsgWriteMsg(msgHandle, 0, &msgHeader, (UCHAR *)
			    bodyStart, len, len, strlen(ctrlBuf)+1,
			    (UCHAR *) ctrlBuf)!=0) w_log(LL_ERR,"Could not write msg to NetmailArea %s",area->areaName);
	    else rc = 1; // normal exit
	    nfree(ctrlBuf);
	    if (MsgCloseMsg(msgHandle)!=0) { // can't close
		w_log(LL_ERR,"Could not close msg in NetmailArea %s",area->areaName);
		rc = 0;
	    } else { // normal close
		w_log(LL_NETMAIL, "Wrote Netmail: %u:%u/%u.%u -> %u:%u/%u.%u", msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node, msg->origAddr.point, msg->destAddr.zone, msg->destAddr.net, msg->destAddr.node, msg->destAddr.point);
		statToss.netMail++;
	    }

	} else {
	    w_log(LL_ERR, "Could not create new msg in NetmailArea %s", area -> areaName);
	} /* endif */

	MsgCloseArea(netmail);
    } else {
	fprintf(stderr, "msgapierr - %u\n", msgapierr);
	w_log(LL_ERR, "Could not open NetmailArea %s", area -> areaName);
    } /* endif */
    return rc;
}

int processMsg(s_message *msg, s_pktHeader *pktHeader, int secure)
{
    int rc;

    w_log(LL_FUNC,"toss.c::processMsg()");
    statToss.msgs++;
#ifdef DO_PERL
    w_log(LL_SRCLINE, "toss.c:%u:processMsg() #ifdef DO_PERL", __LINE__);
    if ((rc = perlfilter(msg, pktHeader->origAddr, secure)) == 1)
	return putMsgInBadArea(msg, pktHeader->origAddr, 5);
    else if (rc == 2)
	return 1;
#endif
    if (msg->netMail == 1) {
        w_log(LL_NETMAIL, "Netmail from %s to %u:%u/%u.%u", aka2str(msg->origAddr),
              msg->destAddr.zone, msg->destAddr.net, msg->destAddr.node, msg->destAddr.point);
	if (config->areafixFromPkt &&
	    isOurAka(config, msg->destAddr) &&
	    strlen(msg->toUserName)>0 &&
	     fc_stristr(config->areafixNames,msg->toUserName)) {
	    rc = processAreaFix(msg, pktHeader, 0);
	} else
	    rc = processNMMsg(msg, pktHeader, NULL, 0, 0);
    } else {
	rc = processEMMsg(msg, pktHeader->origAddr, 0, 0);
    } /* endif */
    w_log(LL_FUNC,"toss.c::processMsg() rc=%d", rc);
    return rc;
}

int processPkt(char *fileName, e_tossSecurity sec)
{
    FILE        *pkt = NULL;
    s_pktHeader *header = NULL;
    s_message   *msg = NULL;
    s_link      *link = NULL;
    int         rc = 0, msgrc = 0;
    long	pktlen;
    time_t      realtime;
    /* +AS+ */
    char        *extcmd = NULL;
    int         cmdexit;
    /* -AS- */
    char        processIt = 0; // processIt = 1, process all mails
    // processIt = 2, process only Netmail
    // processIt = 0, do not process pkt

    w_log(LL_FUNC,"toss.c::processPkt()");

    if ((pktlen = fsize(fileName)) > 60) {

	statToss.inBytes += pktlen;

	/* +AS+ */
	if (config->processPkt)
	    {
		extcmd = safe_malloc(strlen(config->processPkt)+strlen(fileName)+2);
		sprintf(extcmd,"%s %s",config->processPkt,fileName);
		w_log(LL_EXEC, "ProcessPkt: execute string \"%s\"",extcmd);
		if ((cmdexit = system(extcmd)) != 0)
		    w_log(LL_ERR, "exec failed, code %d", cmdexit);
		nfree(extcmd);
	    }
	/* -AS- */
#ifdef DO_PERL
	if (perlpkt(fileName, (sec==secLocalInbound || sec==secProtInbound) ? 1 : 0))
	    return 6;
#endif

	pkt = fopen(fileName, "rb");
	if (pkt == NULL) return 2;
        w_log(LL_FILE,"toss.c:processPkt(): opened '%s' (\"rb\" mode)",fileName);

	header = openPkt(pkt);
	if (header != NULL) {
	    //if ((to_us(header->destAddr)==0) || (sec == secLocalInbound)) {
        if ( isOurAka(config,header->destAddr) || (sec == secLocalInbound)) {
		w_log(LL_PKT, "pkt: %s [%s]", fileName, aka2str(header->origAddr));
		statToss.pkts++;
		link = getLinkFromAddr(config, header->origAddr);
		if ((link!=NULL) && (link->pktPwd==NULL) && (header->pktPassword[0]!='\000'))
		    w_log(LL_ERR, "Unexpected Password %s.", header->pktPassword);

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
				w_log(LL_WARN, "pkt: %s Warning: missing packet password from %i:%i/%i.%i",
				      fileName, header->origAddr.zone, header->origAddr.net,
				      header->origAddr.node, header->origAddr.point);
				processIt = 1;
			    } else {
				w_log(LL_WARN, "pkt: %s Password Error for %i:%i/%i.%i",
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
			w_log(LL_ERR, "pkt: %s No Link for %i:%i/%i.%i, processing only Netmail",
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
				w_log(LL_ERR, "pkt: %s Warning: missing packet password from %i:%i/%i.%i",
				      fileName, header->origAddr.zone, header->origAddr.net,
				      header->origAddr.node, header->origAddr.point);
				processIt = 2; /* Unsecure inbound, do not process echomail */
			    } else {
				w_log(LL_ERR, "pkt: %s Password Error for %i:%i/%i.%i",
				      fileName, header->origAddr.zone, header->origAddr.net,
				      header->origAddr.node, header->origAddr.point);
				rc = 1;
			    }
			}
		    } else if ((link != NULL) && ((link->pktPwd == NULL) || (strcmp(link->pktPwd, "")==0))) {
			processIt=1;
		    } else /* if (link == NULL) */ {	
			w_log(LL_ERR, "pkt: %s No Link for %i:%i/%i.%i, processing only Netmail",
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

			w_log(LL_ERR, "pkt: %s addressed to %d:%d/%d.%d but not for us",
			      fileName, header->destAddr.zone, header->destAddr.net,
			      header->destAddr.node, header->destAddr.point);
	
			fclose(pkt); pkt = NULL;
			rc = forwardPkt(fileName, header, sec);	
		    }
	    }
	
	    nfree(header);
	
	} else { // header == NULL
	    w_log(LL_ERR, "pkt: %s wrong pkt-file", fileName);
	    rc = 3;
	}

	if (pkt) fclose(pkt);

    } else statToss.empty++;

#ifdef DO_PERL
    perlpktdone(fileName, rc);
#endif
    closeOpenedPkt();
    w_log(LL_FUNC,"toss.c::processPkt() OK");
    return rc;
}

#if ( (defined __WATCOMC__) || (defined(_MSC_VER) && (_MSC_VER >= 1200)) )
void *mk_lst(char *a)
{
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
    unsigned int  i;
    int   found, j;
    signed int cmdexit;
    FILE  *bundle = NULL;
    char cmd[256];

#if ( (defined __WATCOMC__) || (defined(_MSC_VER) && (_MSC_VER >= 1200)) )
    const char * const *list;
#endif

    if (sec == secInbound) {
	w_log(LL_ERR, "bundle %s: tossing in unsecure inbound, security violation", fileName);
	return 1;
    };

    // find what unpacker to use
    for (i = 0, found = 0; (i < config->unpackCount) && !found; i++) {
	bundle = fopen(fileName, "rb");
	if (bundle == NULL) return 2;
        w_log(LL_FILE,"toss.c:processArc(): opened '%s' (\"rb\" mode)",fileName);

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
	if( fc_stristr(config->unpack[i-1].call, "zipInternal") )
	    {
                w_log(LL_BUNDLE, "bundle %s: unpacking with zlib", fileName);
#ifdef USE_HPT_ZLIB
		cmdexit = UnPackWithZlib(fileName, config->tempInbound);
#else
		cmdexit = 1;
                w_log(LL_ERR, "zlib not compiled into hpt", fileName);
#endif
	    }
	else
	    {
                w_log(LL_EXEC, "bundle %s: unpacking with \"%s\"", fileName, cmd);
#if ( (defined __WATCOMC__) || (defined(_MSC_VER) && (_MSC_VER >= 1200)) )
		list = mk_lst(cmd);
		cmdexit = spawnvp(P_WAIT, cmd, list);
		nfree((char **)list);
		if (cmdexit != 0) {
		    w_log(LL_ERR, "exec failed: %s, return code: %d", strerror(errno), cmdexit);
		    return 3;
		}
#else
		if ((cmdexit = system(cmd)) != 0) {
		    w_log(LL_ERR, "exec failed, code %d", cmdexit);
		    return 3;
		}
#endif
	    }
	if (config->afterUnpack) {
	    w_log(LL_EXEC, "afterUnpack: execute string \"%s\"", config->afterUnpack);
	    if ((cmdexit = system(config->afterUnpack)) != 0) {
		w_log(LL_ERR, "exec failed, code %d", cmdexit);
	    };
	}
#ifdef DO_PERL
	perlafterunp();
#endif
    } else {
	w_log(LL_ERR, "bundle %s: cannot find unpacker", fileName);
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
    if (((s_fileInDir *) elem1) -> fileTime > ((s_fileInDir *) elem2) -> fileTime) return 1;
    return strcasecmp(((s_fileInDir *) elem1) -> fileName, ((s_fileInDir *) elem2) -> fileName);
}

char *validExt[] = {
 "[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z].SU[0-9A-Z]",
 "[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z].MO[0-9A-Z]",
 "[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z].TU[0-9A-Z]",
 "[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z].WE[0-9A-Z]",
 "[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z].TH[0-9A-Z]",
 "[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z].FR[0-9A-Z]",
 "[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z].SA[0-9A-Z]"
};

void processDir(char *directory, e_tossSecurity sec)
{
    DIR            *dir = NULL;
    struct dirent  *file = NULL;
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
	    for (i = 0; i < sizeof(validExt) / sizeof(validExt[0]); i++)
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
		w_log(LL_ERR, "Renaming pkt/arc to .%s",ext[rc]);
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

    FILE *f = NULL;
    char buffer[256];
    int len, x, statNetmail, statCC;

    statNetmail = statToss.netMail; /* number of just received netmails */
    statCC = statToss.CC; /* number of just received personal echo mails */

    /* if there are new personal mails and statLog is defined in config */
    if (((statNetmail > 0) || (statCC > 0)) && (config->statlog != NULL)) {
	f = fopen(config->statlog, "r");
	if (f != NULL) {  /* and statLog file is readable */
            w_log(LL_FILE,"toss.c:writeStatLog(): opened '%s' (\"r\" mode)",config->statlog);

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
            w_log(LL_FILE,"toss.c:writeStatLog(): opened '%s' (\"wt\" mode)",config->statlog);
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
    unsigned int i;
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
    char *line = NULL, *bundle=NULL, *p=NULL;
    ULONG len;
    unsigned i, as;

    while ((line = readLine(flo)) != NULL) {
#ifndef UNIX
	line = trimLine(line);
#endif
	for (i = 0; i < sizeof(validExt) / sizeof(validExt[0]); i++) {
	    p = strrchr(line, PATH_DELIM);
	    if (p && patimat(p+1, validExt[i]) == 1) {
		if (*line!='~') {
		    nfree(bundle);
		    // One char for first symbol in flo file
		    bundle = safe_strdup(line + 1);
		}
		break;
	    }
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
    char cmd[256], *pkt=NULL, *lastPathDelim = NULL, saveChar;
    int i, cmdexit, foa;
    FILE *flo = NULL;
    s_link *link = NULL;
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
	w_log(LL_EXEC, "beforePack: execute string \"%s\"", config->beforePack);
	if ((cmdexit = system(config->beforePack)) != 0) {
	    w_log(LL_ERR, "exec failed, code %d", cmdexit);
	};
    }
#ifdef DO_PERL
    perlbeforepack();
#endif

    for (i = startlink ; i < endlink; i++) {

	link = &(config->links[i]);

	// only create floFile if we have mail for this link
	if (link->pktFile != NULL) {


	    if (needUseFileBoxForLink(config,link)) {

		if (!link->fileBox) link->fileBox = makeFileBoxName (config,link);

		_createDirectoryTree (link->fileBox);

		if (link->packerDef != NULL) {

		    fillCmdStatement(cmd, link->packerDef->call,
				     link->packFile,
				     link->pktFile, "");
		    w_log(LL_BUNDLE, "Packing for %s %s, %s > %s",
			  aka2str(link->hisAka),
			  link->name, get_filename(link->pktFile),
			  get_filename(link->packFile));
		    w_log(LL_EXEC, "cmd: %s", cmd);
		    if( stricmp(link->packerDef->call, "zipInternal") == 0 )
			{
			    cmdexit = 1;
#ifdef USE_HPT_ZLIB
			    cmdexit = PackWithZlib(link->packFile, link->pktFile);
#endif
			} else {
#ifdef __WATCOMC__
			    list = mk_lst(cmd);
			    cmdexit = spawnvp(P_WAIT, cmd, list);
			    nfree((char **)list);
#else
			    cmdexit = system(cmd);
#endif
			}
		    if (cmdexit==0) remove(link->pktFile);
		    else w_log(LL_ERR, "Error executing packer (errorlevel==%i)", cmdexit);

		} // end packerDef
		else {
		    // there is no packer defined -> put pktFile into fileBox
		    xstrcat(&pkt, link->fileBox);
		    xstrcat(&pkt, link->pktFile + strlen(config->tempOutbound));

		    cmdexit = rename(link->pktFile, pkt);
		    if (cmdexit==0) w_log(LL_BUNDLE, "Leave non-packed mail for %s %s, %s",
					  aka2str(link->hisAka), link->name,
					  get_filename(link->pktFile));
		    else w_log(LL_ERR, "error moving file for %s %s, %s->%s (errorlevel==%i)", aka2str(link->hisAka), link->name, link->pktFile, pkt, errno);
		    nfree(pkt);
		}

	    } else if (createOutboundFileName(link,link->echoMailFlavour, FLOFILE) == 0) {
		// process if the link not busy, else do not create 12345678.?lo

		flo = fopen(link->floFile, "a+");

		if (flo == NULL)
		    w_log(LL_ERR, "Cannot open flo file %s",
			  config->links[i].floFile);
		else {
                    w_log(LL_FILE,"toss.c:arcmail(): opened '%s' (\"a+\" mode)",link->floFile);

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
			w_log(LL_BUNDLE, "Packing for %s %s, %s > %s",
			      aka2str(link->hisAka), link->name,
			      get_filename(link->pktFile),
			      get_filename(link->packFile));
			w_log(LL_EXEC, "cmd: %s", cmd);
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
				nfree((char **)list);
#else
				cmdexit = system(cmd);
#endif
			    }
			if (cmdexit==0) {
			    if (foa==0) {
				if (bundleNameStyle == eAddrDiff ||
				    bundleNameStyle == eAddrsCRC32 ||
				    bundleNameStyle == eAddrDiffAlways ||
				    bundleNameStyle == eAddrsCRC32Always ||
				    bundleNameStyle == eAmiga)
				    fprintf(flo, "#%s\n", link->packFile);
				else
				    fprintf(flo, "^%s\n", link->packFile);
			    }
			    remove(link->pktFile);
			} else
			    w_log(LL_ERR, "Error executing packer (errorlevel==%i)",
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
			    w_log(LL_BUNDLE, "Leave non-packed mail for %s %s, %s",
				  aka2str(link->hisAka), link->name,
				  get_filename(link->pktFile));
			}
			else w_log(LL_ERR, "error moving file for %s %s, %s->%s (errorlevel==%i)", aka2str(link->hisAka), link->name, link->pktFile, pkt, errno);
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
    unsigned int i;
    s_link *link = NULL;
    char *newfn = NULL;

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

	    if (move_file(fileName, newfn, 0) == 0) {  /* save if exist */
		
		w_log(LL_PKT, "Forwarding %s to %s as %s",
		      fileName, config->links[i].name, newfn + strlen(config->tempOutbound));

		nfree(newfn);
		forwardedPkts = 1;
		return 0;
	    }
	    else
		{
		    w_log(LL_ERR, "Failure moving %s to %s (%s)", fileName,
			  newfn, strerror(errno));
		    nfree(newfn);
		    return 4;
		}

	}
    }

    w_log(LL_ERR, "Packet %s is not to us or our links",fileName);

    return 4;       /* PKT is not for us and we did not find a link to
		       forward the pkt file to */
}


/* According to the specs, a .QQQ file does not have two leading
   zeros. This routine checks if the file is a .QQQ file, and if so,
   it appends the zeros and renames the file to .PKT. */


void fix_qqq(char *filename)
{
    FILE *f = NULL;
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
    DIR            *dir = NULL;
    FILE           *pkt = NULL;
    struct dirent  *file = NULL;
    char           *dummy = NULL;
    s_pktHeader    *header = NULL;
    s_link         *link = NULL;
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
		    link = getLinkFromAddr (config, header->destAddr);
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
		    w_log(LL_ERR, "found non packed mail without matching link in tempOutbound");
		    fclose(pkt);
		}
	    }
    }

    closedir(dir);
    return;
}

void writeImportLog(void) {
    unsigned int i;
    FILE *f = NULL;
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

	} else w_log(LL_ERR, "Could not open importlogfile");

	// remove empty importlog
	if (stat(config->importlog, &buf)==0) {
	    if (buf.st_size==0) remove(config->importlog);
	}
	
    }
}

#define MAXOPEN_DEFAULT 512

#if defined(OS2)

#define INCL_DOS

static void setmaxopen(void) {
    ULONG cur, add;
    maxopenpkt = MAXOPEN_DEFAULT;
    cur = add = 0;

    if (DosSetRelMaxFH(&add, &cur) == 0)
	if (cur>=maxopenpkt) return;
    if (DosSetMaxFH(maxopenpkt))
	while (cur<maxopenpkt) {
	    add = 1;
	    if (DosSetRelMaxFH(&add, &cur))
		break;
	}
#ifdef __WATCOMC__
    _grow_handles(maxopenpkt);
#endif
    cur = add = 0;
    if (DosSetRelMaxFH(&add, &cur) == 0) {
	maxopenpkt = cur;
	// return;
    }

#elif defined(UNIX)

#include <sys/resource.h>
#include <unistd.h>

static void setmaxopen(void) {
#ifdef RLIMIT_NOFILE
    struct rlimit rl;
    maxopenpkt = MAXOPEN_DEFAULT;

    if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
	if (rl.rlim_cur >= MAXOPEN_DEFAULT)
	    return;
    // try to set max open
    rl.rlim_cur = rl.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur >= MAXOPEN_DEFAULT)
	return;
    rl.rlim_cur = rl.rlim_max = maxopenpkt;
    setrlimit(RLIMIT_NOFILE, &rl);
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
	maxopenpkt = rl.rlim_cur;
	return;
    }
#endif

#else // windows or unknown OS, just test

static void setmaxopen(void) {

#endif

    {
	int i, handles[MAXOPEN_DEFAULT];
	for (i=0; i<MAXOPEN_DEFAULT; i++)
	    if ((handles[i]=dup(1)) == -1)
		break;
	maxopenpkt = i;
	for (i=0; i<maxopenpkt; i++)
	    close(handles[i]);
    }
    if (maxopenpkt == 0) maxopenpkt = 1;
}

void toss()
{
    FILE *f = NULL;

    // set stats to 0
    memset(&statToss, '\0', sizeof(s_statToss));
    w_log(LL_START, "Start tossing...");
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
	if (NULL == (f = fopen(config->netmailFlag,"a"))) w_log(LL_ERR, "Could not create netmail flag: %s", config->netmailFlag);
	else {
	    w_log(LL_FLAG, "Created netmail flag: %s", config->netmailFlag);
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
    char 	*ptmp = NULL, *line = NULL, *areaName = NULL, *area=NULL, noexp=0;
    s_link	*link = NULL;

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
	link = getLinkFromAddr(config, pktOrigAddr);
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
	w_log(LL_START, "Scanning area: %s", config->badArea.areaName);
	highestMsg = MsgGetNumMsg(area);

	for (i=1; i<=highestMsg; highestMsg--) {
	    hmsg = MsgOpenMsg(area, MOPEN_RW, i);
	    if (hmsg == NULL) continue;      // msg# does not exist
	    MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
	    delmsg = packBadArea(hmsg, xmsg, force);
	
	    MsgCloseMsg(hmsg);
	
	    if (delmsg) MsgKillMsg(area, i);
	    else { i++; highestMsg++; }
	}
	
	MsgCloseArea(area);
	
	closeOpenedPkt();
	writeDupeFiles();
	writeImportLog();

	w_log(LL_STAT, "Statistics");
	w_log(LL_STAT, "    scanned: % 5d   saved: % 7d   CC: % 2d", statToss.msgs, statToss.saved, statToss.CC);
	w_log(LL_STAT, "    exported: % 4d   passthru: % 4d", statToss.exported, statToss.passthrough);

	tossTempOutbound(config->tempOutbound);
	
    } else w_log(LL_ERR, "Could not open %s", config->badArea.fileName);
}
