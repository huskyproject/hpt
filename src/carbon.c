/******************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 ******************************************************************************
 * carbon.c : functions for making carbon copy
 *
 * by Max Chernogor <mihz@ua.fm>, 2:464/108@fidonet
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


#include <stdlib.h>
#include <string.h>

#include <smapi/compiler.h>

#ifdef HAS_PROCESS_H
#  include <process.h>
#endif

#ifdef HAS_IO_H
#include <io.h>
#endif

#ifdef HAS_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAS_DOS_H
#include <dos.h>
#endif

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/recode.h>
#include <fidoconf/temp.h>
#include <fidoconf/xstr.h>

#include "global.h"
#include "toss.h"

extern s_statToss statToss;

s_message* MessForCC(s_message *msg)
{
    s_message* CCmsg;

    if(config->carbonCount == 0)
        return NULL;

    CCmsg = (s_message*) safe_calloc(1,sizeof(s_message));

    CCmsg->origAddr.zone  = msg->origAddr.zone;
    CCmsg->origAddr.net   = msg->origAddr.net;
    CCmsg->origAddr.node  = msg->origAddr.node;
    CCmsg->origAddr.point = msg->origAddr.point;

    CCmsg->destAddr.zone  = msg->destAddr.zone;
    CCmsg->destAddr.net   = msg->destAddr.net ;
    CCmsg->destAddr.node  = msg->destAddr.node;
    CCmsg->destAddr.point = msg->destAddr.point;

    xstrcat(&(CCmsg->fromUserName), msg->fromUserName);
    xstrcat(&(CCmsg->toUserName), msg->toUserName);
    xstrcat(&(CCmsg->subjectLine), msg->subjectLine);
    xstrcat(&(CCmsg->text), msg->text);

    strcpy( (char*)CCmsg->datetime, (char*)msg->datetime );
    CCmsg->attributes = msg->attributes;
    CCmsg->textLength = msg->textLength;
    CCmsg->netMail    = msg->netMail;
    CCmsg->recode     = msg->recode;

    return CCmsg;
}

int processExternal (s_area *echo, s_message *msg,s_carbon carbon)
{
    FILE *msgfp = NULL;
    char *fname = NULL;
    char *progname = NULL, *execstr = NULL, *p = NULL;
    int  rc;

    progname = carbon.areaName;
#ifdef HAS_popen_close
    if (*progname == '|') {
	msgfp = popen(progname + 1, "wt");
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
#ifdef HAS_popen_close
    if (*progname == '|') {
      pclose(msgfp);
      rc = 0;
    } else
#endif
    {
      /* Execute external program */
      fclose(msgfp);
      execstr = safe_malloc(strlen(progname)+strlen(fname)+3);
      if (*progname == '|')
              sprintf(execstr, "%s < %s", progname+1, fname);
      else    sprintf(execstr, "%s %s", progname, fname);
#ifdef __NT__
      CharToOem(execstr, execstr); /*  this is really need? */
#endif
      rc = cmdcall(execstr);
      nfree(execstr);
      unlink(fname);
      nfree(fname);
    }
/*    if (rc == -1 || rc == 127) */
    if (rc)  /* system() return exit status returned by shell */
	w_log(LL_ERR, "Execution of external program failed. Cmd is: %s", execstr);
    return 0;

}

/* area - area to carbon messages, echo - original echo area */
int processCarbonCopy (s_area *area, s_area *echo, s_message *msg, s_carbon carbon)
{
    char *p, *text, *line, *old_text, *reason = carbon.reason;
    int i, old_textLength, export = carbon.export, rc = 0;

    statToss.CC++;

    old_textLength = msg->textLength;
    old_text = msg->text;
    i = old_textLength;

    /*  recoding from internal to transport charSet if needed */
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
    
    msg->text = NULL;
    msg->textLength = 0;

    line = old_text;

    if (strncmp(line, "AREA:", 5) == 0) {
        /*  jump over AREA:xxxxx\r */
        while (*(line) != '\r') line++;
        line++;
    }

    while(*line == '\001')
    {
        p = strchr(line, '\r');
        if(!p)
            break;
        /* Temporary make it \0 terminated string */
        *p = '\0';
        xstrcat(&msg->text,line);
        *p = '\r';
        line = p+1;
    }
    
    text = line; /* may be old_test or old_text w/o begining kluges */

    if (!msg->netMail) {
        if ((!config->carbonKeepSb) && (!area->keepsb)) {
            line = strrstr(text, " * Origin:");
            if (NULL != (p = strstr(line ? line : text,"\rSEEN-BY:")))
                i = (size_t) (p - text) + 1;
        }
	xstrscat(&msg->text,
         "\r",
		 (export) ? "AREA:" : "",
		 (export) ? area->areaName : "",
		 (export) ? "\r" : "",
		 (config->carbonExcludeFwdFrom) ? "" : " * Forwarded from area '",
		 (config->carbonExcludeFwdFrom) ? "" : echo->areaName,
		 (config->carbonExcludeFwdFrom) ? "" : "'\r",
		 (reason) ? reason : "",
		 (reason) ? "\r" : "", NULL);
	msg->textLength = strlen(msg->text);
    }

    xstralloc(&msg->text,i); /*  add i bytes */
    strncat(msg->text,text,i); /*  copy rest of msg */
    msg->textLength += i;

    if (!export) {
	if (msg->netMail) rc = putMsgInArea(area,msg,0,MSGSENT);
	else rc = putMsgInArea(area,msg,0,0);
	area->imported++;  /*  area has got new messages */
    }
    else if (!msg->netMail) {
	rc = processEMMsg(msg, *area->useAka, 1, 0);
    } else
	rc = processNMMsg(msg, NULL, area, 1, 0);

    nfree(msg->text);
    msg->textLength = old_textLength;
    msg->text = old_text;
    msg->recode &= ~REC_TXT; /*  old text is always in Transport Charset */
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

    if(!msg)
        return 0;
    if (echo->ccoff==1)
        return 0;
    if (echo->msgbType==MSGTYPE_PASSTHROUGH && config->exclPassCC)
        return 0;

    for (i=0; i<config->carbonCount; i++,++cb) {
        /* Dont come to use netmail on echomail and vise verse */
        if (cb->move!=2 && ((msg->netMail && !cb->netMail) ||
            (!msg->netMail &&  cb->netMail))) continue;

        area = cb->area;

        if(!cb->rule&CC_AND)  /* not AND & not AND-NOT */
        {
            if (!cb->extspawn && /*  fix for extspawn */
                cb->areaName != NULL && /*  fix for carbonDelete */
                /*  dont CC to the echo the mail comes from */
                !sstricmp(echo->areaName,area->areaName)
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
            sstrcpy(pattern+1, cb->str);
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
                    /*  delete CarbonMove and CarbonDelete messages */
                    if (cb->move && xmsg) xmsg->attr |= MSGKILL;
                    if (config->carbonAndQuit)
                        /* not skip quit or delete */
                        if ((cb->areaName && *cb->areaName!='*') ||	cb->move==2) {
                            return rc;
                        }
            }
            break;
        case CC_AND: /* AND & AND-NOT */
            if(!result){
                /* following expressions can be skipped until OR */
                for (++i,++cb; i<config->carbonCount; i++,++cb)
                    if(!cb->rule&CC_AND)  /* AND & AND-NOT */
                        break; /* this is the last in the AND expr. chain */
            }
            /* else result==TRUE, so continue with next expr. */
            break;
        }
    } /* end for() */

    if (copiedTo) nfree (copiedTo);
    return rc;
}



