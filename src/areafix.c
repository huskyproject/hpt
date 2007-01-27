/*****************************************************************************
 * AreaFix for HPT (FTN NetMail/EchoMail Tosser)
 *****************************************************************************
 * Copyright (C) 1998-2002
 *
 * Max Levenkov
 *
 * Fido:     2:5000/117
 * Internet: sackett@mail.ru
 * Novosibirsk, West Siberia, Russia
 *
 * Big thanks to:
 *
 * Fedor Lizunkov
 *
 * Fido:     2:5020/960
 * Moscow, Russia
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>


#include <smapi/compiler.h>

#ifdef HAS_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAS_IO_H
#include <io.h>
#endif

#ifdef HAS_UNISTD_H
#include <unistd.h>
#endif


#include <smapi/patmat.h>
#include <smapi/progprot.h>

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/xstr.h>
#include <fidoconf/areatree.h>
#include <fidoconf/afixcmd.h>
#include <fidoconf/arealist.h>
#include <fidoconf/recode.h>

#include <fcommon.h>
#include <global.h>
#include <pkt.h>
#include <version.h>
#include <toss.h>
#include <ctype.h>
#include <seenby.h>
#include <scan.h>
#include <areafix.h>
#include <scanarea.h>
#include <hpt.h>
#include <dupe.h>
#include <query.h>

unsigned char RetFix;
static int rescanMode = 0;
static int rulesCount = 0;
static char **rulesList = NULL;

char *print_ch(int len, char ch)
{
    static char tmp[256];

    if (len <= 0 || len > 255) return "";

    memset(tmp, ch, len);
    tmp[len]=0;
    return tmp;
}

/* test area-link pair to mandatory
 */
int mandatoryCheck(s_area area, s_link *link) {
    int i;

    w_log(LL_FUNC, __FILE__ "::mandatoryCheck()");

    if (grpInArray(area.group,link->optGrp,link->numOptGrp)&&link->mandatory){
      w_log(LL_FUNC, __FILE__ "::mandatoryCheck() rc=1");
      return 1;
    }
    if (link->numOptGrp==0 && link->mandatory){
      w_log(LL_FUNC, __FILE__ "::mandatoryCheck() rc=1");
      return 1;
    }
    if (area.mandatory){
      w_log(LL_FUNC, __FILE__ "::mandatoryCheck() rc=1");
      return 1;
    }
    if ((i=isAreaLink(link->hisAka, &area))!=-1){
      w_log(LL_FUNC, __FILE__ "::mandatoryCheck() rc=%d", area.downlinks[i]->mandatory);
      return area.downlinks[i]->mandatory;
    }
      w_log(LL_FUNC, __FILE__ "::mandatoryCheck() rc=0");
    return 0;
}

/* test area-link pair to manual
 */
int manualCheck(s_area area, s_link *link) {
    int i;

    w_log(LL_FUNC, __FILE__ "::manualCheck()");

    if (grpInArray(area.group,link->optGrp,link->numOptGrp)&&link->manual){
      w_log(LL_FUNC, __FILE__ "::manualCheck() rc=1");
      return 1;
    }
    if (link->numOptGrp==0 && link->manual){
      w_log(LL_FUNC, __FILE__ "::manualCheck() rc=1");
      return 1;
    }
    if (area.manual){
      w_log(LL_FUNC, __FILE__ "::manualCheck() rc=1");
      return 1;
    }
    if ((i=isAreaLink(link->hisAka, &area))!=-1){
      w_log(LL_FUNC, __FILE__ "::manualCheck() rc=%d", area.downlinks[i]->manual);
      return area.downlinks[i]->manual;
    }
      w_log(LL_FUNC, __FILE__ "::manualCheck() rc=0");
    return 0;
}


int subscribeCheck(s_area area, s_link *link)
{
    int found = 0;

    w_log( LL_FUNC, "%s::subscribeCheck() begin", __FILE__ );

    if (isLinkOfArea(link, &area)) return 0;

    if (area.group) {
	if (config->numPublicGroup)
	    found = grpInArray(area.group,config->PublicGroup,config->numPublicGroup);
	if (!found && link->numAccessGrp)
	    found = grpInArray(area.group,link->AccessGrp,link->numAccessGrp);
    } else found = 1;

    if (!found){
      w_log( LL_FUNC, "%s::subscribeCheck() end, rc=2", __FILE__ );
      return 2;
    }
    if (area.levelwrite > link->level && area.levelread > link->level){
      w_log( LL_FUNC, "%s::subscribeCheck() end, rc=2", __FILE__ );
      return 2;
    }
    w_log( LL_FUNC, "%s::subscribeCheck() end, rc=1", __FILE__ );
    return 1;
}

int subscribeAreaCheck(s_area *area, char *areaname, s_link *link)
{
    int rc=4;

    w_log( LL_SRCLINE, "%s::subscribeAreaCheck()", __FILE__ );

    if( (!areaname)||(!areaname[0]) ){
      w_log( LL_SRCLINE, "%s::subscribeAreaCheck() Failed (areaname empty) rc=%d", __FILE__, rc );
      return rc;
    }
    if (patimat(area->areaName,areaname)==1) {
	rc=subscribeCheck(*area, link);
	/*  0 - already subscribed / linked */
	/*  1 - need subscribe / not linked */
	/*  2 - no access */
    }
    /*  else: this is another area */
    w_log( LL_SRCLINE, "%s::subscribeAreaCheck() end rc=%d", __FILE__, rc );
    return rc;
}

char *getPatternFromLine(char *line, int *reversed)
{

    *reversed = 0;
    if (!line) return NULL;
    /* original string is like "%list ! *.citycat.*" or withut '!' sign*/
    if (line[0] == '%') line++; /* exclude '%' sign */
    while((strlen(line) > 0) && isspace(line[0])) line++; /* exclude spaces between '%' and command */
    while((strlen(line) > 0) && !isspace(line[0])) line++; /* exclude command */
    while((strlen(line) > 0) && isspace(line[0])) line++; /* exclude spaces between command and pattern */

    if ((strlen(line) > 2) && (line[0] == '!') && (isspace(line[1])))
    {
        *reversed = 1;
        line++;     /* exclude '!' sign */
        while(isspace(line[0])) line++; /* exclude spaces between '!' and pattern */
    }

    if (strlen(line) > 0)
        return line;
    else
        return NULL;
}

char *list(s_link *link, char *cmdline) {
    unsigned int i, active, avail, rc = 0;
    char *report = NULL;
    char *list = NULL;
    char *pattern = NULL;
    int reversed;
    ps_arealist al;
    s_area area;

    pattern = getPatternFromLine(cmdline, &reversed);
    if ((pattern) && (strlen(pattern)>60 || !isValidConference(pattern))) {
        w_log(LL_FUNC, "areafix::list() FAILED (error request line)");
        return errorRQ(cmdline);
    }

    xscatprintf(&report, "Available areas for %s\r\r", aka2str(link->hisAka));

    al = newAreaList();
    for (i=active=avail=0; i< config->echoAreaCount; i++) {
		
	area = config->echoAreas[i];
	rc = subscribeCheck(area, link);

        if (rc < 2 && (!area.hide || (area.hide && rc==0))) { /*  add line */
            if (pattern)
            {
                /* if matches pattern and not reversed (or vise versa) */
                if (patimat(area.areaName, pattern)!=reversed)
                {
                    addAreaListItem(al,rc==0, area.msgbType!=MSGTYPE_PASSTHROUGH, area.areaName,area.description);
                    if (rc==0) active++; avail++;
                }
            } else
            {
                addAreaListItem(al,rc==0, area.msgbType!=MSGTYPE_PASSTHROUGH, area.areaName,area.description);
                if (rc==0) active++; avail++;
            }
	} /* end add line */

    } /* end for */
    sortAreaList(al);
    list = formatAreaList(al,78," *R");
    if (list) xstrcat(&report,list);
    nfree(list);
    freeAreaList(al);

    xstrcat(&report,      "\r'R' = area rescanable");
    xstrcat(&report,      "\r'*' = area active");
    xscatprintf(&report,  "\r %i areas available, %i areas active",avail, active);
    xscatprintf(&report,  "\r for link:%s\r", aka2str(link->hisAka));

    if (link->afixEchoLimit) xscatprintf(&report, "\rYour limit is %u areas for subscribe\r", link->afixEchoLimit);

    w_log(LL_AREAFIX, "areafix: list sent to %s", aka2str(link->hisAka));

    return report;
}

char *linked(s_link *link) {
    unsigned int i, n, rc;
    char *report = NULL;

    xscatprintf(&report, "\r%s areas on %s\r\r",
		((link->Pause & EPAUSE) == EPAUSE) ? "Passive" : "Active", aka2str(link->hisAka));
							
    for (i=n=0; i<config->echoAreaCount; i++) {
	rc=subscribeCheck(config->echoAreas[i], link);
	if (rc==0) {
	    xscatprintf(&report, " %s\r", config->echoAreas[i].areaName);
	    n++;
	}
    }
    xscatprintf(&report, "\r%u areas linked\r", n);
    if (link->afixEchoLimit) xscatprintf(&report, "\rYour limit is %u areas for subscribe\r", link->afixEchoLimit);
    w_log(LL_AREAFIX, "areafix: linked areas list sent to %s", aka2str(link->hisAka));
    return report;
}

char *unlinked(s_link *link) {
    unsigned int i, rc;
    char *report = NULL;
    s_area *areas;

    areas=config->echoAreas;
    xscatprintf(&report, "Unlinked areas to %s\r\r", aka2str(link->hisAka));

    for (i=0; i<config->echoAreaCount; i++) {
	rc=subscribeCheck(areas[i], link);
	if (rc == 1 && !areas[i].hide) {
	    xscatprintf(&report, " %s\r", areas[i].areaName);
	}
    }
    w_log(LL_AREAFIX, "areafix: unlinked areas list sent to %s", aka2str(link->hisAka));

    return report;
}

char *help(s_link *link) {
    FILE *f;
    int i=1;
    char *help;
    long endpos;

    if (config->areafixhelp!=NULL) {
	if ((f=fopen(config->areafixhelp,"r")) == NULL) {
	    w_log (LL_ERR, "areafix: cannot open help file \"%s\": %s",
	           config->areafixhelp, strerror(errno));
	    if (!quiet)
		fprintf(stderr,"areafix: cannot open help file \"%s\": %s\n",
		        config->areafixhelp, strerror(errno));
	    return NULL;
	}
		
	fseek(f,0L,SEEK_END);
	endpos=ftell(f);

	help=(char*) safe_malloc((size_t) endpos+1);

	fseek(f,0L,SEEK_SET);
	endpos = fread(help,1,(size_t) endpos,f);

	for (i=0; i<endpos; i++) if (help[i]=='\n') help[i]='\r';
	help[endpos]='\0';

	fclose(f);

	w_log(LL_AREAFIX, "areafix: help sent to %s",link->name);

	return help;
    }
    return NULL;
}

int tag_mask(char *tag, char **mask, unsigned num) {
    unsigned int i;

    for (i = 0; i < num; i++) {
	if (patimat(tag,mask[i])) return 1;
    }

    return 0;
}

/* Process %avail command.
 *
 */
char *available(s_link *link, char *cmdline)
{
    FILE *f;
    unsigned int j=0, found;
    unsigned int k, rc;
    char *report = NULL, *line, *token, *running, linkAka[SIZE_aka2str];
    char *pattern;
    int reversed;
    s_link *uplink=NULL;
    ps_arealist al=NULL, *hal=NULL;
    unsigned int halcnt=0, isuplink;

    pattern = getPatternFromLine(cmdline, &reversed);
    if ((pattern) && (strlen(pattern)>60 || !isValidConference(pattern))) {
        w_log(LL_FUNC, "areafix::avail() FAILED (error request line)");
        return errorRQ(cmdline);
    }

    for (j = 0; j < config->linkCount; j++)
    {
	uplink = &(config->links[j]);

	found = 0;
	isuplink = 0;
	for (k = 0; k < link->numAccessGrp && uplink->LinkGrp; k++)
	    if (strcmp(link->AccessGrp[k], uplink->LinkGrp) == 0)
		found = 1;

	if ((uplink->forwardRequests && uplink->forwardRequestFile) &&
	    ((uplink->LinkGrp == NULL) || (found != 0)))
	{
	    if ((f=fopen(uplink->forwardRequestFile,"r")) == NULL) {
		w_log(LL_ERR, "areafix: cannot open forwardRequestFile \"%s\": %s",
		      uplink->forwardRequestFile, strerror(errno));
 		continue;
	    }

	    isuplink = 1;

            if ((!hal)&&(link->availlist == AVAILLIST_UNIQUEONE))
                xscatprintf(&report, "Available Area List from all uplinks:\r");

            if ((!halcnt)||(link->availlist != AVAILLIST_UNIQUEONE))
            {
              halcnt++;
              hal = realloc(hal, sizeof(ps_arealist)*halcnt);
              hal[halcnt-1] = newAreaList();
              al = hal[halcnt-1];
              w_log(LL_DEBUGW,  __FILE__ ":%u: New item added to hal, halcnt = %u", __LINE__, halcnt);
            }

            while ((line = readLine(f)) != NULL)
            {
                line = trimLine(line);
                if (line[0] != '\0')
                {
                    running = line;
                    token = strseparate(&running, " \t\r\n");
                    rc = 0;

                    if (uplink->numDfMask)
                      rc |= tag_mask(token, uplink->dfMask, uplink->numDfMask);

                    if (uplink->denyFwdFile)
                      rc |= IsAreaAvailable(token,uplink->denyFwdFile,NULL,0);

                    if (pattern)
                    {
                        /* if matches pattern and not reversed (or vise versa) */
                        if ((rc==0) &&(patimat(token, pattern)!=reversed))
                            addAreaListItem(al,0,0,token,running);
                    } else
                    {
                        if (rc==0) addAreaListItem(al,0,0,token,running);
                    }

    	        }
    	        nfree(line);
            }
            fclose(f);


            /*  warning! do not ever use aka2str twice at once! */
            sprintf(linkAka, "%s", aka2str(link->hisAka));
            w_log( LL_AREAFIX, "areafix: Available Area List from %s %s to %s",
                  aka2str(uplink->hisAka),
                  (link->availlist == AVAILLIST_UNIQUEONE) ? "prepared": "sent",
                  linkAka );
        }


 	if ((link->availlist != AVAILLIST_UNIQUEONE)||(j==(config->linkCount-1)))
 	{
 		if((hal)&&((hal[halcnt-1])->count))
 		    if ((link->availlist != AVAILLIST_UNIQUE)||(isuplink))
 		    {
 		        sortAreaListNoDupes(halcnt, hal, link->availlist != AVAILLIST_FULL);
 		        if ((hal[halcnt-1])->count)
 		        {
 			    line = formatAreaList(hal[halcnt-1],78,NULL);
 			    if (link->availlist != AVAILLIST_UNIQUEONE)
 			        xscatprintf(&report, "\rAvailable Area List from %s:\r", aka2str(uplink->hisAka));
			    if (line)
 			        xstrscat(&report, "\r", line,print_ch(77,'-'), "\r", NULL);
 			    nfree(line);
	 	        }
 		    }

            if ((link->availlist != AVAILLIST_UNIQUE)||(j==(config->linkCount-1)))
              if (hal)
              {
  	        w_log(LL_DEBUGW,  __FILE__ ":%u: hal freed, (%u items)", __LINE__, halcnt);
                for(;halcnt>0;halcnt--)
                  freeAreaList(hal[halcnt-1]);
                nfree(hal);
              }
 	}
    }	

    if (report==NULL) {
	xstrcat(&report, "\r  no links for creating Available Area List\r");
	w_log(LL_AREAFIX, "areafix: no links for creating Available Area List");
    }
    return report;
}


/*  subscribe if (act==0),  unsubscribe if (act==1), delete if (act==2) */
int forwardRequestToLink (char *areatag, s_link *uplink, s_link *dwlink, int act) {
    s_message *msg;
    char *base, pass[]="passthrough";

    if (uplink->msg == NULL) {
	msg = makeMessage(uplink->ourAka, &(uplink->hisAka), config->sysop,
        uplink->RemoteRobotName ? uplink->RemoteRobotName : "areafix",
        uplink->areaFixPwd ? uplink->areaFixPwd : "\x00", 1,
        config->areafixReportsAttr);
	msg->text = createKludges(config, NULL, uplink->ourAka, &(uplink->hisAka),
                              versionStr);
	if (config->areafixReportsFlags)
	    xstrscat(&(msg->text), "\001FLAGS ", config->areafixReportsFlags, "\r", NULL);
	uplink->msg = msg;
    } else msg = uplink->msg;
	
    if (act==0) {
    if (getArea(config, areatag) == &(config->badArea)) {
        if(config->areafixQueueFile) {
            af_CheckAreaInQuery(areatag, &(uplink->hisAka), &(dwlink->hisAka), ADDFREQ);
        }
        else {
            base = uplink->msgBaseDir;
            if (config->createFwdNonPass==0) uplink->msgBaseDir = pass;
            /*  create from own address */
            if (isOurAka(config,dwlink->hisAka)) {
                uplink->msgBaseDir = base;
            }
            strUpper(areatag);
            autoCreate(areatag, uplink->hisAka, &(dwlink->hisAka));
            uplink->msgBaseDir = base;
        }
    }
    xstrscat(&msg->text, "+", areatag, "\r", NULL);
    } else if (act==1) {
        xscatprintf(&(msg->text), "-%s\r", areatag);
    } else {
        /*  delete area */
        if (uplink->advancedAreafix)
            xscatprintf(&(msg->text), "~%s\r", areatag);
        else
            xscatprintf(&(msg->text), "-%s\r", areatag);
    }
    return 0;
}

#if 0
int delLinkFromString(char **lineOut, char *line, char *linkAddr)
{
    char *startLink, *ptr, *tmp, *origLine, *comment, *eptr=NULL, *linkStr;
    unsigned int nodeAddr=0, rc=1, endLen=0; /*  length of string where link ends */

    origLine = safe_strdup(line);
    startLink = line;
    tmp = line;
    /*  find comments */
    for (comment = line; (comment = strchr(comment+1, CommentChar)) != NULL;)
	if (*(comment-1) == ' ' || *(comment-1) == '\t')
	    break;
    /*  make search string */
    linkStr = safe_malloc(strlen(linkAddr)+3);
    strcpy(linkStr, linkAddr);
    ptr=strchr(linkStr, '.');
    if (ptr==NULL) {
	nodeAddr = 1;
        ptr=linkStr+strlen(linkStr);
    }
    strcpy(ptr, ".*");

    tmp = line;
    do {
	ptr = strstr(tmp+1, linkAddr);
	endLen = 0;
        if (ptr && comment && ptr>=comment) ptr = NULL;
        if (ptr) tmp = ptr + strlen(linkAddr);
	if (ptr && isspace(*(ptr-1))) {
            eptr = ptr+strlen(linkAddr);
	    if (isspace(*eptr) || *eptr=='\0' ||
                (nodeAddr && *eptr=='.' && eptr[1]=='0' && (isspace(eptr[2]) || eptr[2]=='\0'))) {
                startLink = ptr;
		endLen = eptr + 1 - line;
		rc = 0; /*  all ok */
	    }
	}
	ptr = strstr(tmp+1, linkStr);
        if (ptr && comment && ptr>=comment) ptr = NULL;
        if (ptr) tmp = ptr + strlen(linkAddr);
	if (ptr && isspace(*(ptr-1))) {
	    eptr = ptr+strlen(linkStr);
            if (isspace(*eptr) || *eptr=='\0') {
                startLink = ptr;
		endLen = eptr + 1 - line;
		rc = 2; /*  found, but cannot unsubscribe */
	    }
	}
    } while (!endLen && tmp);

    if (rc == 0) {
	eptr = tmp;
	if (*eptr == '.' && eptr[1] == '0') eptr+=2;
	if (*eptr && isspace(*eptr)) eptr++;
	endLen = eptr - line;
	ptr = line + endLen;
        while (ptr) {
            tmp = strseparate(&ptr, " \t"); /*  looking for link options... */
            if (tmp == NULL)  break; /*  nothing found */
            if (*tmp != '-') break; /*  this is not option */
            else { /*  found link option */
                /*  if (!strncasecmp(tmp, "-r", 2) || */
                /*     !strncasecmp(tmp, "-w", 2) || */
                /*     !strncasecmp(tmp, "-mn", 3) || */
                /*    !strncasecmp(tmp, "-def", 4)) */
                {
                    endLen = ptr ? (ptr - line) : strlen(origLine);
                    continue;
                }
            }
        }
        nfree(*lineOut);
        *lineOut = (char *) safe_calloc(strlen(origLine) + 1, 1);
        strncpy(*lineOut, origLine, startLink - line);
        if (endLen < strlen(origLine))
	    strcpy(*lineOut+(startLink-line), origLine+endLen);
    }
    nfree(origLine);
    nfree(linkStr);
    return rc;
}
#endif

/* fileName isn't freed inside this function */
int changeconfig(char *fileName, s_area *area, s_link *link, int action) {
    char *cfgline=NULL, *foundFileName = NULL, *token=NULL, *buff=0;
    char strbegfileName[MAXPATHLEN + 1];
    long strbeg = 0, strend = -1;
    int rc=0;

    e_changeConfigRet nRet = I_ERR;
    char *areaName = area->areaName;

    w_log(LL_FUNC, __FILE__ "::changeconfig(%s,...)", fileName);

    strncpy(strbegfileName, fileName, MAXPATHLEN + 1);
    /* if fileName's length is <= MAXPATHLEN
     * then strncpy will fill strbegfileName by \0 up to the last byte,
     * check it: */
    if(strbegfileName[MAXPATHLEN] != 0)
        return -1;

    if (init_conf(fileName))
        return -1;

    w_log(LL_SRCLINE, __FILE__ ":%u:changeconfig() action=%i",__LINE__,action);

    while ((cfgline = configline()) != NULL) {
        /* FIXME: use expandCfgLine instead? */
        /* FIXME: I think we shall definitely strip comments _before_
         *  modifying line (when we add link to the end) */
        cfgline = stripComment(cfgline);
        cfgline = trimLine(cfgline);
        if(cfgline[0] != 0)
        {
            char *line = NULL, *tmpPtr = NULL;
            line = sstrdup(cfgline);
            line = shell_expand(line);
            tmpPtr = line = vars_expand(line);
            token = strseparate(&tmpPtr, " \t");

            if (!stricmp(token, "echoarea")) {
                token = strseparate(&tmpPtr, " \t");
                if (*token=='\"' && token[strlen(token)-1]=='\"' && token[1]) {
                    token++;
                    token[strlen(token)-1]='\0';
                }
                if (stricmp(token, areaName)==0) {
                    foundFileName = safe_strdup(getCurConfName());
                    strend = get_hcfgPos();
                    if (strcmp(strbegfileName, foundFileName) != 0) strbeg = 0;
                    nfree(line);
                    break;
                }
            }
            nfree(line);
        }

        strbeg = get_hcfgPos();
        strncpy(strbegfileName, getCurConfName(), MAXPATHLEN + 1);
        if(strbegfileName[MAXPATHLEN] != 0)
            break;
        w_log(LL_DEBUGF, __FILE__ ":%u:changeconfig() strbeg=%ld", __LINE__, strbeg);

        nfree(cfgline);
    }
    close_conf();
    if (strend == -1) { /* error occurred */
        nfree(cfgline);
        nfree(foundFileName);
        return -1;
    }

    switch (action) {
    case 0: /*  forward Request To Link */
        if ((area->msgbType==MSGTYPE_PASSTHROUGH) &&
            (!config->areafixQueueFile) &&
            (area->downlinkCount==1) &&
            (area->downlinks[0]->link->hisAka.point == 0))
        {
            forwardRequestToLink(areaName, area->downlinks[0]->link, NULL, 0);
        }
    case 3: /*  add link to existing area */
        xscatprintf(&cfgline, " %s", aka2str(link->hisAka));
        nRet = ADD_OK;
        break;
    case 1: /*  remove link from area */
        if ((area->msgbType==MSGTYPE_PASSTHROUGH)
            && (area->downlinkCount==1) &&
            (area->downlinks[0]->link->hisAka.point == 0)) {
            forwardRequestToLink(areaName, area->downlinks[0]->link, NULL, 1);
        }
    case 7:
        if ((rc = DelLinkFromString(cfgline, link->hisAka)) == 1) {
            w_log(LL_ERR,"areafix: Unlink is not possible for %s from echo area %s",
                aka2str(link->hisAka), areaName);
            nRet = O_ERR;
        } else {
            nRet = DEL_OK;
        }
        break;
    case 2:
        /* makepass(f, foundFileName, areaName); */
    case 4: /*  delete area */
        nfree(cfgline);
        nRet = DEL_OK;
        break;
    case 5: /*  subscribe us to  passthrough */
        if ( fc_stristr(area->downlinks[0]->link->autoAreaCreateDefaults,
            "passthrough") )  {
            nRet = O_ERR;
            break;
        }
        w_log(LL_SRCLINE, __FILE__ "::changeconfig():%u",__LINE__);
        /*  get area string */
        buff = makeAreaParam(area->downlinks[0]->link , areaName, NULL );
        nRet = ADD_OK;
    case 6: /*  make area pass. */

        if(action == 6) {
            buff = makeAreaParam(area->downlinks[0]->link , areaName, "passthrough" );
            nRet = DEL_OK;
        }
        /*  add all links */
        token = NULL;
        token = strrchr(cfgline, '\"');
        if(!token) token = cfgline;
        token = strstr(token, aka2str(area->downlinks[0]->link->hisAka));
        if(!testAddr(token,area->downlinks[0]->link->hisAka))
            token = strstr(token+1, aka2str(area->downlinks[0]->link->hisAka));

        xstrcat( &buff, token-1);
        nfree(cfgline);
        cfgline = buff;
        break;
    default: break;
    } /*  switch (action) */

    w_log(LL_DEBUGF, __FILE__ ":%u:changeconfig() call InsertCfgLine(\"%s\",<cfgline>,%ld,%ld)", __LINE__, foundFileName, strbeg, strend);
    InsertCfgLine(foundFileName, cfgline, strbeg, strend);
    nfree(cfgline);
    nfree(foundFileName);
    w_log(LL_FUNC, __FILE__ "::changeconfig() rc=%i", nRet);
    return nRet;
}

static int compare_links_priority(const void *a, const void *b) {
    int ia = *((int*)a);
    int ib = *((int*)b);
    if(config->links[ia].forwardAreaPriority < config->links[ib].forwardAreaPriority) return -1;
    else if(config->links[ia].forwardAreaPriority > config->links[ib].forwardAreaPriority) return 1;
    else return 0;
}

/* Return values:
 * 0 = request is forwarded now
 * 1 = link with "forwardRequests on" not found
 * 2 = something prevent us from forwarding request
 * 3 = the area is already in the queue so forward is not necessary */
int forwardRequest(char *areatag, s_link *dwlink, s_link **lastRlink) {
    unsigned int i, rc = 1;
    s_link *uplink;
    int *Indexes;
    unsigned int Requestable = 0;
    s_query_areas *oldRequest;

    oldRequest = af_CheckAreaInQuery(areatag, NULL, NULL, FIND);
    if(oldRequest != NULL)
    {
       af_CheckAreaInQuery(areatag, NULL, &(dwlink->hisAka), ADDFREQ);
       /* there is no way to check if the call was sucessfull,
        * result is: link is included into the queue or it is already there;
        * we just return OK, because we've done all we can do. */
       /* FIXME: I think no other processing is needed
        * because the request to uplink is already issued. */
       return 3;
    }

    /* From Lev Serebryakov -- sort Links by priority */
    Indexes = safe_malloc(sizeof(int)*config->linkCount);
    for (i = 0; i < config->linkCount; i++) {
	if (config->links[i].forwardRequests) Indexes[Requestable++] = i;
    }
    qsort(Indexes,Requestable,sizeof(Indexes[0]),compare_links_priority);
    i = 0;
    if(lastRlink) { /*  try to find next requestable uplink */
        for (; i < Requestable; i++) {
            uplink = &(config->links[Indexes[i]]);
            if( addrComp(uplink->hisAka, (*lastRlink)->hisAka) == 0)
            {   /*  we found lastRequestedlink */
                i++;   /*  let's try next link */
                break;
            }
        }
    }
    for (; i < Requestable; i++) {
	uplink = &(config->links[Indexes[i]]);

    if(lastRlink) *lastRlink = uplink;

    if (uplink->forwardRequests && (uplink->LinkGrp) ?
        grpInArray(uplink->LinkGrp,dwlink->AccessGrp,dwlink->numAccessGrp) : 1)
    {
        if ( (uplink->numDfMask) &&
            (tag_mask(areatag, uplink->dfMask, uplink->numDfMask)))
        {
            rc = 2; /* not forward */
            continue;
        }
        if ( (uplink->denyFwdFile!=NULL) &&
            (IsAreaAvailable(areatag,uplink->denyFwdFile,NULL,0)))
        {
            rc = 2; /* area is listed in denyfwdfile */
            continue;
        }
        if (uplink->forwardRequestFile!=NULL) {
            /*  first try to find the areatag in forwardRequestFile */
            if (tag_mask(areatag, uplink->frMask, uplink->numFrMask) ||
                IsAreaAvailable(areatag,uplink->forwardRequestFile,NULL,0))
            {
                forwardRequestToLink(areatag,uplink,dwlink,0);
                rc = 0; /* Request is forwarded */
            }
            else
            { rc = 2; }/* found link with freqfile, but there is no areatag */
        } else {
            rc = 0;
            if (uplink->numFrMask) /*  found mask */
            {
                if (tag_mask(areatag, uplink->frMask, uplink->numFrMask))
                    forwardRequestToLink(areatag,uplink,dwlink,0);
                else rc = 2; /* area not matched areatag mask for uplink */
            } else { /*  unconditional forward request */
                if (dwlink->denyUFRA==0)
                    forwardRequestToLink(areatag,uplink,dwlink,0);
                else rc = 2; /* Deny unconditional forward requests for link */
            }
        }/* (uplink->forwardRequestFile!=NULL) */
        if (rc==0) { /*  Duplicate of end of function, may be removed */
            nfree(Indexes);
            return rc;
        }

    }/*  if (uplink->forwardRequests && (uplink->LinkGrp) ? */
    }/*  for (i = 0; i < Requestable; i++) { */

    /*  link with "forwardRequests on" not found */
    nfree(Indexes);
    return rc;
}

/* test link for areas quantity limit exceed
 * return 0 if not limit exceed
 * else return not zero
 */
int limitCheck(s_link *link) {
    register unsigned int i,n;

    w_log(LL_FUNC, __FILE__ "::limitCheck()");

    if (link->afixEchoLimit==0) return 0;
    for (i=n=0; i<config->echoAreaCount; i++)
	if (0==subscribeCheck(config->echoAreas[i], link))	
	    n++;
    i = n >= link->afixEchoLimit ;
    w_log(LL_FUNC, __FILE__ "::limitCheck() rc=%u", i);
    return i;
}

int isPatternLine(char *s) {
    if (strchr(s,'*') || strchr(s,'?')) return 1;
    return 0;
}

void fixRules (s_link *link, char *area) {
    char *fileName = NULL;

    if (!config->rulesDir) return;
    if (link->noRules) return;

    xscatprintf(&fileName, "%s%s.rul", config->rulesDir, strLower(makeMsgbFileName(config, area)));

    if (fexist(fileName)) {
        rulesCount++;
        rulesList = safe_realloc (rulesList, rulesCount * sizeof (char*));
        rulesList[rulesCount-1] = safe_strdup (area);
        /*  don't simply copy pointer because area may be */
        /*  removed while processing other commands */
    }
    nfree (fileName);
}

char *subscribe(s_link *link, char *cmd) {
    unsigned int i, rc=4, found=0, matched=0;
    char *line, *an=NULL, *report = NULL;
    s_area *area=NULL;

    w_log(LL_FUNC, "%s::subscribe(...,%s)", __FILE__, cmd);

    line = cmd;
	
    if (line[0]=='+') line++;
    while (*line==' ') line++;
    /* FIXME:  "+  +  area" isn't a well-formed line */
    if (*line=='+') line++; while (*line==' ') line++;
	
    if (strlen(line)>60 || !isValidConference(line)) {
      report = errorRQ(line);
      w_log(LL_FUNC, "%s::subscribe() FAILED (error request line) rc=%s", __FILE__, report);
      return report;
    }

    for (i=0; !found && rc!=6 && i<config->echoAreaCount; i++) {
	area = &(config->echoAreas[i]);
	an = area->areaName;

	rc=subscribeAreaCheck(area, line, link);
	if (rc==4) continue;        /* not match areatag, try next */
	if (rc==1 && manualCheck(*area, link)) rc = 5; /* manual area/group/link */

	if (rc!=0 && limitCheck(link)) rc = 6; /* areas limit exceed for link */

	switch (rc) {
	case 0:         /* already linked */
	    if (isPatternLine(line)) {
		matched = 1;
	    } else {
		xscatprintf(&report, " %s %s  already linked\r",
			    an, print_ch(49-strlen(an), '.'));
		w_log(LL_AREAFIX, "areafix: %s already linked to %s",
		      aka2str(link->hisAka), an);
		i = config->echoAreaCount;
	    }
	    break;
	case 1:         /* not linked */
        if( isOurAka(config,link->hisAka)) {
           if(area->msgbType==MSGTYPE_PASSTHROUGH) {
              int state =
                  changeconfig(cfgFile?cfgFile:getConfigFileName(),area,link,5);
              if( state == ADD_OK) {
                  af_CheckAreaInQuery(an, NULL, NULL, DELIDLE);
                  xscatprintf(&report," %s %s  added\r",an,print_ch(49-strlen(an),'.'));
                  w_log(LL_AREAFIX, "areafix: %s subscribed to %s",aka2str(link->hisAka),an);
              } else {
                  xscatprintf(&report, " %s %s  not subscribed\r",an,print_ch(49-strlen(an), '.'));
                  w_log(LL_AREAFIX, "areafix: %s not subscribed to %s , cause uplink",aka2str(link->hisAka),an);
                  w_log(LL_AREAFIX, "areafix: %s has \"passthrough\" in \"autoAreaCreateDefaults\" for %s",
                                    an, aka2str(area->downlinks[0]->link->hisAka));
              }
           } else {  /* ??? (not passthrou echo) */
                     /*   non-passthrough area for our aka means */
                     /*   that we already linked to this area */
               xscatprintf(&report, " %s %s  already linked\r",an, print_ch(49-strlen(an), '.'));
               w_log(LL_AREAFIX, "areafix: %s already linked to %s",aka2str(link->hisAka), an);
           }
        } else {
            if (changeconfig(cfgFile?cfgFile:getConfigFileName(),area,link,0)==ADD_OK) {
                Addlink(link, area, NULL);
                processPermissions(config);
                fixRules (link, area->areaName);
                af_CheckAreaInQuery(an, NULL, NULL, DELIDLE);
                xscatprintf(&report," %s %s  added\r",an,print_ch(49-strlen(an),'.'));
                w_log(LL_AREAFIX, "areafix: %s subscribed to %s",aka2str(link->hisAka),an);
                if(cmNotifyLink)
                forwardRequestToLink(area->areaName,link, NULL, 0);
            } else {
                xscatprintf(&report," %s %s  error. report to sysop!\r",an,print_ch(49-strlen(an),'.'));
                w_log(LL_AREAFIX, "areafix: %s not subscribed to %s",aka2str(link->hisAka),an);
                w_log(LL_ERR, "areafix: can't write to config file: %s!", strerror(errno));
            }/* if (changeconfig(cfgFile?cfgFile:getConfigFileName(),area,link,3)==0) */
        }
	    if (!isPatternLine(line)) i = config->echoAreaCount;
	    break;
	case 6:         /* areas limit exceed for link */
	    break;
	default : /*  rc = 2  not access */
	    if (!area->hide && !isPatternLine(line)) {
		w_log(LL_AREAFIX, "areafix: area %s -- no access for %s",
		      an, aka2str(link->hisAka));
		xscatprintf(&report," %s %s  no access\r", an,
			    print_ch(49-strlen(an), '.'));
		found=1;
	    }
	    if (area->hide && !isPatternLine(line)) found=1;
	    break;
	}
    }

    if (rc!=0 && limitCheck(link)) rc = 6; /*double!*/ /* areas limit exceed for link */

    if (rc==4 && !isPatternLine(line) && !found) { /* rc not equal 4 there! */
	if (link->denyFRA==0) {
	    /*  try to forward request */
	    if ((rc=forwardRequest(line, link, NULL))==2) {
		xscatprintf(&report, " %s %s  no uplinks to forward\r",
			    line, print_ch(49-strlen(line), '.'));
		w_log( LL_AREAFIX, "areafix: %s - no uplinks to forward", line);
	    }
	    else if (rc==0) {
		xscatprintf(&report, " %s %s  request forwarded\r",
			    line, print_ch(49-strlen(line), '.'));
		w_log( LL_AREAFIX, "areafix: %s - request forwarded", line);
		if( !config->areafixQueueFile && isOurAka(config,link->hisAka)==0)
		{
		    area = getArea(config, line);
		    if ( !isLinkOfArea(link, area) ) {
			if(changeconfig(cfgFile?cfgFile:getConfigFileName(),area,link,3)==ADD_OK) {
			    Addlink(link, area, NULL);
			    processPermissions(config);
			    fixRules (link, area->areaName);
			    w_log( LL_AREAFIX, "areafix: %s subscribed to area %s",
				aka2str(link->hisAka),line);
			} else {
			    xscatprintf( &report," %s %s  error. report to sysop!\r",
				an, print_ch(49-strlen(an),'.') );
			    w_log( LL_AREAFIX, "areafix: %s not subscribed to %s",
				aka2str(link->hisAka),an);
			    w_log(LL_ERR, "areafix: can't change config file: %s!", strerror(errno));
			}
		    } else w_log( LL_AREAFIX, "areafix: %s already subscribed to area %s",
			aka2str(link->hisAka), line );

		} else {
		    fixRules (link, line);
		}
	    }
	    else if (rc == 3)
	    {
		xscatprintf(&report, " %s %s  request forwarded\r",
			    line, print_ch(49-strlen(line), '.'));
	    }
	}
    }

    if (rc == 6) {   /* areas limit exceed for link */
	w_log( LL_AREAFIX,"areafix: area %s -- no access (full limit) for %s",
	      line, aka2str(link->hisAka));
	xscatprintf(&report," %s %s  no access (full limit)\r",
		    line, print_ch(49-strlen(line), '.'));
    }

    if (matched) {
	if (report == NULL)
	    w_log (LL_AREAFIX, "areafix: all areas matching %s are already linked", line);
	xscatprintf(&report, "All %sareas matching %s are already linked\r", report ? "other " : "", line);
    }
    else if ((report == NULL && found==0) || (found && area->hide)) {
	xscatprintf(&report," %s %s  not found\r",line,print_ch(49-strlen(line),'.'));
	w_log( LL_AREAFIX, "areafix: area %s is not found",line);
    }
    w_log(LL_FUNC, "areafix::subscribe() OK");
    return report;
}

char *errorRQ(char *line) {
    char *report = NULL;

    if (strlen(line)>48) {
	xstrscat(&report, " ", line, " .......... error line\r", NULL);
    }
    else xscatprintf(&report, " %s %s  error line\r",
		    line, print_ch(49-strlen(line),'.'));
    return report;
}

char *do_delete(s_link *link, s_area *area) {
    char *report = NULL, *an = area->areaName;
    unsigned int i=0;

    if(!link)
    {
        link = getLinkFromAddr(config, *area->useAka);
        while( !link && i < config->addrCount )
        {
            link = getLinkFromAddr( config, config->addr[i] );
            i++;
        }
        if(!link) return NULL;
    }
    /* unsubscribe from downlinks */
    xscatprintf(&report, " %s %s  deleted\r", an, print_ch(49-strlen(an), '.'));
    for (i=0; i<area->downlinkCount; i++) {
	if (addrComp(area->downlinks[i]->link->hisAka, link->hisAka))
	    forwardRequestToLink(an, area->downlinks[i]->link, NULL, 2);
    }
    /* remove area from config-file */
    if( changeconfig ((cfgFile) ? cfgFile : getConfigFileName(),  area, link, 4) != DEL_OK) {
       w_log( LL_AREAFIX, "areafix: can't remove area from config: %s", strerror(errno));
    }

    /* delete msgbase and dupebase for the area */

    /*
    if (area->msgbType!=MSGTYPE_PASSTHROUGH)
	MsgDeleteBase(area->fileName, (word) area->msgbType);
    */

    if (area->dupeCheck != dcOff && config->typeDupeBase != commonDupeBase) {
	char *dupename = createDupeFileName(area);
	if (dupename) {
	    unlink(dupename);
	    nfree(dupename);
	}
    }

    w_log( LL_AREAFIX, "areafix: area %s deleted by %s",
                  an, aka2str(link->hisAka));

    /* delete the area from in-core config */
    for (i=0; i<config->echoAreaCount; i++)
    {
        if (stricmp(config->echoAreas[i].areaName, an)==0)
            break;
    }
    if (i<config->echoAreaCount && area==&(config->echoAreas[i])) {
        fc_freeEchoArea(area);
        for (; i<config->echoAreaCount-1; i++)
            memcpy(&(config->echoAreas[i]), &(config->echoAreas[i+1]),
            sizeof(s_area));
        config->echoAreaCount--;
        RebuildEchoAreaTree(config);
    }
    return report;
}

char *delete(s_link *link, char *cmd) {
    int rc;
    char *line, *report = NULL, *an;
    s_area *area;

    for (line = cmd + 1; *line == ' ' || *line == '\t'; line++);

    if (*line == 0) return errorRQ(cmd);

    area = getArea(config, line);
    if (area == &(config->badArea)) {
	xscatprintf(&report, " %s %s  not found\r", line, print_ch(49-strlen(line), '.'));
	w_log(LL_AREAFIX, "areafix: area %s is not found", line);
	return report;
    }
    rc = subscribeCheck(*area, link);
    an = area->areaName;

    switch (rc) {
    case 0:
	break;
    case 1:
	xscatprintf(&report, " %s %s  not linked\r", an, print_ch(49-strlen(an), '.'));
	w_log(LL_AREAFIX, "areafix: area %s is not linked to %s",
	      an, aka2str(link->hisAka));
	return report;
    case 2:
	xscatprintf(&report, " %s %s  no access\r", an, print_ch(49-strlen(an), '.'));
	w_log(LL_AREAFIX, "areafix: area %s -- no access for %s", an, aka2str(link->hisAka));
	return report;
    }
    if (link->LinkGrp == NULL || (area->group && strcmp(link->LinkGrp, area->group))) {
	xscatprintf(&report, " %s %s  delete not allowed\r",
		    an, print_ch(49-strlen(an), '.'));
	w_log(LL_AREAFIX, "areafix: area %s delete not allowed for %s",
	      an, aka2str(link->hisAka));
	return report;
    }
    return do_delete(link, area);
}

char *unsubscribe(s_link *link, char *cmd) {
    unsigned int i, rc = 2, j=(unsigned int)I_ERR, from_us=0, matched = 0;
    char *line, *an, *report = NULL;
    s_area *area;

    w_log(LL_FUNC,__FILE__ ":%u:unsubscribe() begin", __LINE__);
    line = cmd;
	
    if (line[1]=='-') return NULL;
    line++;
    while (*line==' ') line++;
	
    for (i = 0; i< config->echoAreaCount; i++) {
        area = &(config->echoAreas[i]);
        an = area->areaName;

        rc = subscribeAreaCheck(area, line, link);
        if (rc==4) continue;
        if (rc==0 && mandatoryCheck(*area,link)) rc = 5;

        if (isOurAka(config,link->hisAka))
        {
            from_us = 1;
            rc = area->msgbType == MSGTYPE_PASSTHROUGH ? 1 : 0 ;
        }

        switch (rc) {
        case 0:
            if (from_us == 0) {
                unsigned int k;
                for (k=0; k<area->downlinkCount; k++)
                    if (addrComp(link->hisAka, area->downlinks[k]->link->hisAka)==0 &&
                        area->downlinks[k]->defLink)
                        return do_delete(link, area);
                    RemoveLink(link, area, NULL);
                    if ((area->msgbType == MSGTYPE_PASSTHROUGH) &&
                        (area->downlinkCount == 1) &&
                        (area->downlinks[0]->link->hisAka.point == 0))
                    {
                        if(config->areafixQueueFile)
                        {
                            af_CheckAreaInQuery(an, &(area->downlinks[0]->link->hisAka), NULL, ADDIDLE);
                            j = changeconfig(cfgFile?cfgFile:getConfigFileName(),area,link,7);
                        }
                        else
                        {
                            j = changeconfig(cfgFile?cfgFile:getConfigFileName(),area,link,1);
                        }
                    } else {

                        j = changeconfig(cfgFile?cfgFile:getConfigFileName(),area,link,7);
                    }
                    if (j != DEL_OK) {
                        w_log(LL_AREAFIX, "areafix: %s doesn't unlinked from %s",
                            aka2str(link->hisAka), an);
                    } else {
                        w_log(LL_AREAFIX,"areafix: %s unlinked from %s",aka2str(link->hisAka),an);
                        if(cmNotifyLink)
                        forwardRequestToLink(area->areaName,link, NULL, 1);
                    }
            } else { /*  unsubscribing from own address - set area passtrough */
                if (area->downlinkCount==0)
                {
                    return do_delete(getLinkFromAddr(config,*(area->useAka)), area);
                }
                else if ((area->downlinkCount==1) &&
                    (area->downlinks[0]->link->hisAka.point == 0)) {
                    if(config->areafixQueueFile) {
                        af_CheckAreaInQuery(an, &(area->downlinks[0]->link->hisAka), NULL, ADDIDLE);
                    } else {
                        forwardRequestToLink(area->areaName,
                            area->downlinks[0]->link, NULL, 1);
                    }
                }
                j = changeconfig(cfgFile?cfgFile:getConfigFileName(),area,link,6);
/*                if ( (j == DEL_OK) && area->msgbType!=MSGTYPE_PASSTHROUGH ) */
                if ( (j == DEL_OK) && area->fileName && area->killMsgBase)
                   MsgDeleteBase(area->fileName, (word) area->msgbType);
            }
            if (j == DEL_OK){
                xscatprintf(&report," %s %s  unlinked\r",an,print_ch(49-strlen(an),'.'));
            }else
                xscatprintf(&report," %s %s  error. report to sysop!\r",
                                         an, print_ch(49-strlen(an),'.') );
            break;
        case 1:
            if (isPatternLine(line)) {
                matched = 1;
                continue;
            }
            if (area->hide) {
                i = config->echoAreaCount;
                break;
            }
            xscatprintf(&report, " %s %s  not linked\r",
                an, print_ch(49-strlen(an), '.'));
            w_log(LL_AREAFIX, "areafix: area %s is not linked to %s",
                area->areaName, aka2str(link->hisAka));
            break;
        case 5:
            xscatprintf(&report, " %s %s  unlink is not possible\r",
                an, print_ch(49-strlen(an), '.'));
            w_log(LL_AREAFIX, "areafix: area %s -- unlink is not possible for %s",
                area->areaName, aka2str(link->hisAka));
            break;
        default:
            break;
        }
    }
    if(config->areafixQueueFile)
        report = af_Req2Idle(line, report, link->hisAka);
    if (report == NULL) {
        if (matched) {
            xscatprintf(&report, " %s %s  no areas to unlink\r",
                line, print_ch(49-strlen(line), '.'));
            w_log(LL_AREAFIX, "areafix: no areas to unlink");
        } else {
            xscatprintf(&report, " %s %s  not found\r",
                line, print_ch(49-strlen(line), '.'));
            w_log(LL_AREAFIX, "areafix: area %s is not found", line);
        }
    }
    w_log(LL_FUNC,__FILE__ ":%u:unsubscribe() end", __LINE__);
    return report;
}


char *pause_link(s_link *link)
{
   char *tmp, *report = NULL;

   if ((link->Pause & EPAUSE) != EPAUSE) {
      if (Changepause((cfgFile) ? cfgFile : getConfigFileName(), link, 0,EPAUSE) == 0)
         return NULL;
   }
   xstrcat(&report, " System switched to passive\r");
   tmp = linked (link);
   xstrcat(&report, tmp);
   nfree(tmp);

   return report;
}
char *resume_link(s_link *link)
{
    char *tmp, *report = NULL;

    if ((link->Pause & EPAUSE) == EPAUSE) {
	if (Changepause((cfgFile) ? cfgFile : getConfigFileName(), link,0,EPAUSE) == 0)
	    return NULL;
    }

    xstrcat(&report, " System switched to active\r");
    tmp = linked (link);
    xstrcat(&report, tmp);
    nfree(tmp);

    return report;
}

char *info_link(s_link *link)
{
    char *report=NULL, *ptr, linkAka[SIZE_aka2str];
    char hisAddr[]="Your address: ";
    char ourAddr[]="AKA used here: ";
    char Arch[]="Compression: ";
    char Rsb[]="Reduced SEEN-BY: ";
    unsigned int i;

    sprintf(linkAka,aka2str(link->hisAka));
    xscatprintf(&report, "Here is some information about our link:\r\r");
    xscatprintf(&report, "%20s%s\r%20s%s\r%20s%s\r%20s",
                hisAddr, linkAka, ourAddr, aka2str(*link->ourAka),
                Rsb, link->reducedSeenBy?"on":"off", Arch);

    if (link->packerDef==NULL)
	xscatprintf(&report, "No packer (");
    else
	xscatprintf(&report, "%s (", link->packerDef->packer);

    for (i=0; i < config->packCount; i++)
	xscatprintf(&report, "%s%s", config->pack[i].packer,
		    (i+1 == config->packCount) ? "" : ", ");
    xscatprintf(&report, ")\r\r");
    xscatprintf(&report, "Your system is %s\r", ((link->Pause & EPAUSE) == EPAUSE)?"passive":"active");
    ptr = linked (link);
    xstrcat(&report, ptr);
    nfree(ptr);
    w_log(LL_AREAFIX, "areafix: link information sent to %s", aka2str(link->hisAka));
    return report;
}

char *rescan(s_link *link, char *cmd) {
    unsigned int i, c, rc = 0;
    long rescanCount = -1, rcc;
    char *report = NULL, *line, *countstr, *an, *end;
    s_area *area;
    s_arealink *arealink;

    line = cmd;
    if (strncasecmp(cmd, "%rescan", 7)==0) line += strlen("%rescan");

    if (*line == 0) return errorRQ(cmd);

    while (*line && (*line == ' ' || *line == '\t')) line++;

    if (*line == 0) return errorRQ(cmd);

    countstr = line;
    while (*countstr && (!isspace(*countstr))) countstr++; /*  skip areatag */
    while (*countstr && (*countstr == ' ' || *countstr == '\t')) countstr++;
    if (strncasecmp(countstr, "/R",2)==0) {
	countstr += 2;
	if (*countstr == '=') countstr++;
    }
	
    if (*countstr != '\0') {
	rescanCount = strtol(countstr, NULL, 10);
    }

    end = strpbrk(line, " \t");
    if (end) *end = 0;

    if (*line == 0) return errorRQ(cmd);

    for (i=c=0; i<config->echoAreaCount; i++) {
	rc=subscribeAreaCheck(&(config->echoAreas[i]), line, link);
	if (rc == 4) continue;

	area = &(config->echoAreas[i]);
	an = area->areaName;

	switch (rc) {
	case 0:
	    if (area->msgbType == MSGTYPE_PASSTHROUGH) {
		xscatprintf(&report," %s %s  no rescan possible\r",
			    an, print_ch(49-strlen(an), '.'));
		w_log(LL_AREAFIX, "areafix: %s area no rescan possible to %s",
		      an, aka2str(link->hisAka));
	    } else {

		arealink = getAreaLink(area, link->hisAka);
		if (arealink->export) {
		    rcc = rescanEMArea(area, arealink, rescanCount);
		    tossTempOutbound(config->tempOutbound);
		} else {
		    rcc = 0;
		    xscatprintf(&report," %s %s  no access to export\r",
				an, print_ch(49-strlen(an), '.'));
		    w_log(LL_AREAFIX, "areafix: %s -- no access to export for %s",
			  an, aka2str(link->hisAka));
		}
		xscatprintf(&report," %s %s  rescanned %lu mails\r",
			    an, print_ch(49-strlen(an), '.'), rcc);
		w_log(LL_AREAFIX,"areafix: %s rescanned %lu mails to %s",
		      an, rcc, aka2str(link->hisAka));
	    }
	    if (!isPatternLine(line)) i = config->echoAreaCount;
	    break;
	case 1: if (isPatternLine(line)) continue;
	    w_log(LL_AREAFIX, "areafix: %s area not linked for rescan to %s",
		  area->areaName, aka2str(link->hisAka));
	    xscatprintf(&report, " %s %s  not linked for rescan\r",
			an, print_ch(49-strlen(an), '.'));
	    break;
	default: w_log(LL_AREAFIX, "areafix: %s area not access for %s",
		       area->areaName, aka2str(link->hisAka));
	    break;
	}
    }
    if (report == NULL) {
	xscatprintf(&report," %s %s  not linked for rescan\r",
		    line, print_ch(49-strlen(line), '.'));
	w_log(LL_AREAFIX, "areafix: %s area not linked for rescan", line);
    }
    return report;
}

char *add_rescan(s_link *link, char *line) {
    char *report=NULL, *line2=NULL, *p;

    if (*line=='+') line++; while (*line==' ') line++;

    p = fc_stristr(line, " /R");
    *p = '\0';

    report = subscribe (link, line);
    *p = ' ';

    xstrscat(&line2,"%rescan ", line, NULL);
    xstrcat(&report, rescan(link, line2));
    nfree(line2);
    *p = '\0';

    return report;
}

char *packer(s_link *link, char *cmdline) {
    char *report=NULL;
    char *was=NULL;
    char *pattern = NULL;
    int reversed;
    UINT i;
    pattern = getPatternFromLine(cmdline, &reversed);
    if(pattern)
    {
        char *packerString=NULL;
        ps_pack packerDef = NULL;
        char *confName = NULL;
        long  strbeg=0;
        long  strend=0;

        for (i=0; i < config->packCount; i++)
        {
            if (stricmp(config->pack[i].packer,pattern) == 0)
            {
                packerDef = &(config->pack[i]);
                break;
            }
        }
        if( (i == config->packCount) && (stricmp("none",pattern) != 0) )
        {
            xscatprintf(&report, "Packer '%s' was not found\r", pattern);
            return report;
        }
        if (link->packerDef==NULL)
            xstrcat(&was, "none");
        else
            xstrcat(&was, link->packerDef->packer);

        xstrcat(&confName,(cfgFile) ? cfgFile : getConfigFileName());
        FindTokenPos4Link(&confName, "Packer", link, &strbeg, &strend);
        xscatprintf(&packerString,"Packer %s",pattern);
        if( InsertCfgLine(confName, packerString, strbeg, strend) )
        {
           link->packerDef = packerDef;
        }
        nfree(confName);
        nfree(packerString);
    }

    xstrcat(  &report, "Here is some information about current & available packers:\r\r");
    xstrcat(  &report,       "Compression: ");
    if (link->packerDef==NULL)
        xscatprintf(&report, "none (");
    else
        xscatprintf(&report, "%s (", link->packerDef->packer);

    for (i=0; i < config->packCount; i++)
        xscatprintf(&report, "%s%s", config->pack[i].packer,(i+1 == config->packCount) ? "" : ", ");

    xscatprintf(&report, "%snone)\r", (i == 0) ? "" : ", ");
    if(was)
    {
        xscatprintf(&report, "        was: %s\r", was);
    }
    return report;
}

char *rsb(s_link *link, char *cmdline)
{
    int mode; /*  1 = RSB on, 0 - RSB off. */
    char *param=NULL; /*  RSB value. */
    char *report=NULL;
    char *confName = NULL;
    long  strbeg=0;
    long  strend=0;

    param = getPatternFromLine(cmdline, &mode); /*  extract rsb value (on or off) */
    if (param == NULL)
    {
        xscatprintf(&report, "Invalid request: %s\rPlease read help.\r\r", cmdline);
        return report;
    }

    param = trimLine(param);

    if ((!strcmp(param, "0")) || (!strcasecmp(param, "off")))
        mode = 0;
    else
    {
        if ((!strcmp(param, "1")) || (!strcasecmp(param, "on")))
            mode = 1;
        else
        {
            xscatprintf(&report, "Unknown parameter for areafix %rsb command: %s\r. Please read help.\r\r",
                        param);
            nfree(param);
            return report;
        }
    }
    nfree(param);
    if (link->reducedSeenBy == (UINT)mode)
    {
        xscatprintf(&report, "Redused SEEN-BYs had not been changed.\rCurrent value is '%s'\r\r",
                    mode?"on":"off");
        return report;
    }
    xstrcat(&confName,(cfgFile) ? cfgFile : getConfigFileName());
    FindTokenPos4Link(&confName, "reducedSeenBy", link, &strbeg, &strend);
    xscatprintf(&param, "reducedSeenBy %s", mode?"on":"off");
    if( InsertCfgLine(confName, param, strbeg, strend) )
    {
        xscatprintf(&report, "Redused SEEN-BYs is turned %s now\r\r", mode?"on":"off");
        link->reducedSeenBy = mode;
    }
    nfree(param);
    nfree(confName);
    return report;
}

int tellcmd(char *cmd) {
    char *line;

    if (strncmp(cmd, "* Origin:", 9) == 0) return NOTHING;

    line = cmd;
    if (line && *line && (line[1]==' ' || line[1]=='\t')) return AFERROR;

    switch (line[0]) {
    case '%':
        line++;
        if (*line == '\000') return AFERROR;
        if (strncasecmp(line,"list",4)==0) return LIST;
        if (strncasecmp(line,"help",4)==0) return HELP;
        if (strncasecmp(line,"avail",5)==0) return AVAIL;
        if (strncasecmp(line,"all",3)==0) return AVAIL;
        if (strncasecmp(line,"unlinked",8)==0) return UNLINK;
        if (strncasecmp(line,"linked",6)==0) return QUERY;
        if (strncasecmp(line,"query",5)==0) return QUERY;
        if (strncasecmp(line,"pause",5)==0) return PAUSE;
        if (strncasecmp(line,"resume",6)==0) return RESUME;
        if (strncasecmp(line,"info",4)==0) return INFO;
        if (strncasecmp(line,"packer",6)==0) return PACKER;
        if (strncasecmp(line,"compress",8)==0) return PACKER;
        if (strncasecmp(line,"rsb",3)==0) return RSB;
        if (strncasecmp(line,"rescan", 6)==0) {
            if (line[6] == '\0') {
                rescanMode=1;
                return NOTHING;
            } else {
                return RESCAN;
            }
        }
        return AFERROR;
    case '\001': return NOTHING;
    case '\000': return NOTHING;
    case '-'  :
        if (line[1]=='-' && line[2]=='-') return DONE;
        if (line[1]=='\000') return AFERROR;
        if (strchr(line,' ') || strchr(line,'\t')) return AFERROR;
        return DEL;
    case '~'  : return REMOVE;
    case '+':
        if (line[1]=='\000') return AFERROR;
    default:
        if (fc_stristr(line, " /R")!=NULL) return ADD_RSC; /*  add & rescan */
        return ADD;
    }
    return 0;/*  - Unreachable */
}

char *processcmd(s_link *link, char *line, int cmd) {

    char *report;

    w_log(LL_FUNC, __FILE__ "::processcmd()");

    switch (cmd) {

    case NOTHING: return NULL;

    case DONE: RetFix=DONE;
        return NULL;

    case LIST: report = list (link, line);
        RetFix=LIST;
        break;
    case HELP: report = help (link);
        RetFix=HELP;
        break;
    case ADD: report = subscribe (link, line);
        RetFix=ADD;
        break;
    case DEL: report = unsubscribe (link, line);
        RetFix=STAT;
        break;
    case REMOVE: report = delete (link, line);
        RetFix=STAT;
        break;
    case AVAIL: report = available (link, line);
        RetFix=AVAIL;
        break;
    case UNLINK: report = unlinked (link);
        RetFix=UNLINK;
        break;
    case QUERY: report = linked (link);
        RetFix=QUERY;
        break;
    case PAUSE: report = pause_link (link);
        RetFix=PAUSE;
        break;
    case RESUME: report = resume_link (link);
        RetFix=RESUME;
        break;
    case PACKER: report = packer (link, line);
        RetFix=PACKER;
        break;
    case RSB: report = rsb (link, line);
        RetFix=RSB;
        break;
    case INFO: report = info_link(link);
        RetFix=INFO;
        break;
    case RESCAN: report = rescan(link, line);
        RetFix=STAT;
        break;
    case ADD_RSC: report = add_rescan(link, line);
        RetFix=STAT;
        break;
    case AFERROR: report = errorRQ(line);
        RetFix=STAT;
        break;
    default: return NULL;
    }
    w_log(LL_FUNC, __FILE__ "::processcmd() OK");
    return report;
}

void preprocText(char *split, s_message *msg)
{
    char *orig = (config->areafixOrigin) ? config->areafixOrigin : config->origin;

    msg->text = createKludges(config, NULL, &msg->origAddr,
        &msg->destAddr, versionStr);
    /* xstrcat(&(msg->text), "\001FLAGS NPD DIR\r"); */
    if (config->areafixReportsFlags)
        xstrscat(&(msg->text), "\001FLAGS ", config->areafixReportsFlags, "\r", NULL);
    xscatprintf(&split, "\r--- %s areafix\r", versionStr);
    if (orig && orig[0]) {
        xscatprintf(&split, " * Origin: %s (%s)\r", orig, aka2str(msg->origAddr));
    }
    xstrcat(&(msg->text), split);
    msg->textLength=(int)strlen(msg->text);
    nfree(split);
}

char *textHead(void)
{
    char *text_head = NULL;

    xscatprintf(&text_head, " Area%sStatus\r",	print_ch(48,' '));
    xscatprintf(&text_head, " %s  -------------------------\r",print_ch(50, '-'));
    return text_head;
}

char *areaStatus(char *report, char *preport)
{
    if (report == NULL) report = textHead();
    xstrcat(&report, preport);
    nfree(preport);
    return report;
}

/* report already nfree() after this function */
void RetMsg(s_message *msg, s_link *link, char *report, char *subj)
{
    char *tab = config->intab, *text, *split, *p, *p2, *newsubj = NULL;
    char *splitStr = config->areafixSplitStr ? config->areafixSplitStr : " > message splitted...";
    int splitStrLen = strlen(splitStr);
    int len, msgsize = config->areafixMsgSize * 1024, partnum=0;
    s_message *tmpmsg;

    config->intab = NULL;

    if (msg->text)
        xstrscat(&report,"\rFollowing is the original message text\r--------------------------------------\r",msg->text,"\r--------------------------------------\r",NULL);
    else
        xstrscat(&report,"\r",NULL);

    text = report;

    while (text) {

        len = strlen(text);
        if (msgsize == 0 || len <= msgsize) {
            if(partnum) { /* last part of splitted msg */
                partnum++;
                split = (char*)safe_malloc(len + 1);
                memcpy(split, text, len + 1); /* copy last part of text with \0 */

                nfree(report);
            }
            else
                split = text; /* == report, will be freed in preprocText */

            text = NULL;
        } else {
            p = text + msgsize;
            while (p > text && *p != '\r') p--;
            if (p == text) {
                p = text + msgsize;
                while (p > text && *p != ' ' && *p != '\t') p--;
                if (p == text) p = text + msgsize;
            }
            *p = '\000';
            len = p - text;

                                                 /* len + 2*\r + splitter + \r +\000 */
            split = (char*)safe_malloc(len+splitStrLen+3+1);
            memcpy(split,text,len);              /* len */
            p2 = split + len;
            *p2 = '\r'; *++p2 = '\r';            /* +2*\r */
            memcpy(++p2, splitStr, splitStrLen); /* + splitter */
            p2 += splitStrLen; *p2 = '\r';       /* +\r */
            *++p2 = '\000';                      /* + \000 */

            text = p + 1;
            partnum++;
        }

        if (partnum) xscatprintf(&newsubj, "%s (%d)", subj, partnum);
        else newsubj = subj;

        if (config->areafixFromName == NULL)
            tmpmsg = makeMessage(link->ourAka, &(link->hisAka),
            msg->toUserName,
            msg->fromUserName, newsubj, 1,
            config->areafixReportsAttr);
        else
            tmpmsg = makeMessage(link->ourAka, &(link->hisAka),
            config->areafixFromName,
            msg->fromUserName, newsubj, 1,
            config->areafixReportsAttr);


        preprocText(split, tmpmsg);
        processNMMsg(tmpmsg, NULL, getNetMailArea(config,config->robotsArea),
            0, MSGLOCAL);

        writeEchoTossLogEntry(config->robotsArea?config->robotsArea:config->netMailAreas[0].areaName);
        closeOpenedPkt();
        freeMsgBuffers(tmpmsg);
        nfree(tmpmsg);
        if (partnum) nfree(newsubj);
    }

    config->intab = tab;
}

void RetRules (s_message *msg, s_link *link, char *areaName)
{
    FILE *f=NULL;
    char *fileName = NULL;
    char *text=NULL, *subj=NULL;
    char *msg_text;
    long len=0;
    int nrul=0;

    xscatprintf(&fileName, "%s%s.rul", config->rulesDir, strLower(makeMsgbFileName(config, areaName)));

    for (nrul=0; nrul<=9 && (f = fopen (fileName, "rb")); nrul++) {

	len = fsize (fileName);
	text = safe_malloc (len+1);
	fread (text, len, 1, f);
	fclose (f);

	text[len] = '\0';

	if (nrul==0) {
	    xscatprintf(&subj, "Rules of %s", areaName);
	    w_log(LL_AREAFIX, "areafix: send '%s' as rules for area '%s'",
		  fileName, areaName);
	} else {
	    xscatprintf(&subj, "Echo related text #%d of %s", nrul, areaName);
	    w_log(LL_AREAFIX, "areafix: send '%s' as text %d for area '%s'",
		  fileName, nrul, areaName);
	}

        /* prevent "Following original message text" in rules msgs */
        msg_text = msg->text;
        msg->text= NULL;
        RetMsg(msg, link, text, subj);
        /* preserve original message text */
        msg->text= msg_text;

	nfree (subj);
	/* nfree (text); don't free text because RetMsg() free it */

	fileName[strlen(fileName)-1] = nrul+'1';
    }

    if (nrul==0) { /*  couldn't open any rules file while first one exists! */
	w_log(LL_ERR, "areafix: can't open file '%s' for reading: %s", fileName, strerror(errno));
    }
    nfree (fileName);

}

void sendAreafixMessages()
{
    s_link *link = NULL;
    s_message *linkmsg;
    unsigned int i;

    for (i = 0; i < config->linkCount; i++) {
        if (config->links[i].msg == NULL) continue;
        link = &(config->links[i]);
        linkmsg = link->msg;

        xscatprintf(&(linkmsg->text), " \r--- %s areafix\r", versionStr);
        linkmsg->textLength = strlen(linkmsg->text);

        w_log(LL_AREAFIX, "areafix: write netmail msg for %s", aka2str(link->hisAka));

        processNMMsg(linkmsg, NULL, getNetMailArea(config,config->robotsArea),
            0, MSGLOCAL);

        closeOpenedPkt();
        freeMsgBuffers(linkmsg);
        nfree(linkmsg);
        link->msg = NULL;
    }
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

int processAreaFix(s_message *msg, s_pktHeader *pktHeader, unsigned force_pwd)
{
    unsigned int security=1, notforme = 0;
    s_link *link = NULL;
    s_link *tmplink = NULL;
    /* s_message *linkmsg; */
    s_pktHeader header;
    char *token, *report=NULL, *preport = NULL;
    char *textBuff = NULL,*tmp;
    int nr;

    w_log(LL_FUNC, __FILE__ "::processAreaFix()");

    RetFix = NOTHING;
    rescanMode = 0;

    /*  1st security check */
    if (pktHeader) security=addrComp(msg->origAddr, pktHeader->origAddr);
    else {
	makePktHeader(NULL, &header);
	pktHeader = &header;
	pktHeader->origAddr = msg->origAddr;
	pktHeader->destAddr = msg->destAddr;
	security = 0;
    }

    if (security) security=1; /* different pkt and msg addresses */

    /*  find link */
    link=getLinkFromAddr(config, msg->origAddr);

    /*  if keyword allowPktAddrDiffer for this link is on, */
    /*  we allow the addresses in PKT and MSG header differ */
    if (link!=NULL)
	if (link->allowPktAddrDiffer == pdOn)
	    security = 0;  /* OK */

    /*  is this for me? */
    if (link!=NULL)	notforme=addrComp(msg->destAddr, *link->ourAka);
    else if (!security) security=4; /*  link == NULL; unknown system */
	
    if (notforme && !security) security=5; /*  message to wrong AKA */

#if 0 /*  we're process only our messages here */
    /*  ignore msg for other link (maybe this is transit...) */
    if (notforme || (link==NULL && security==1)) {
        w_log(LL_FUNC, __FILE__ "::processAreaFix() call processNMMsg() and return");
	nr = processNMMsg(msg, pktHeader, NULL, 0, 0);
	closeOpenedPkt();
	return nr;
    }
#endif

    /*  2nd security check. link, areafixing & password. */
    if (!security && !force_pwd) {
        if (link->AreaFix==1) {
            if (link->areaFixPwd!=NULL) {
                if (stricmp(link->areaFixPwd,msg->subjectLine)==0) security=0;
                else security=3; /* password error */
            }
        } else security=2; /* areafix is turned off */
    }
    /*  remove kluges */
    tmp = msg->text;
    token = strseparate (&tmp,"\n\r");

    while(token != NULL) {
        if( !strcmp(token,"---") || !strncmp(token,"--- ",4) )
            /*  stop on tearline ("---" or "--- text") */
            break;
        if( token[0] != '\001' )
            xstrscat(&textBuff,token,"\r",NULL);
        token = strseparate (&tmp,"\n\r");
    }
    nfree(msg->text);
    msg->text = textBuff;
    if (!security) {
	textBuff = safe_strdup(msg->text);
        tmp = textBuff;
	token = strseparate (&tmp, "\n\r");
	while(token != NULL) {
	    while ((*token == ' ') || (*token == '\t')) token++;
	    while(isspace(token[strlen(token)-1])) token[strlen(token)-1]='\0';
            w_log(LL_AREAFIX, "Process command: %s", token);
	    preport = processcmd( link, token, tellcmd (token) );
	    if (preport != NULL) {
		switch (RetFix) {
		case LIST:
		    RetMsg(msg, link, preport, "Areafix reply: list request");
		    break;
		case HELP:
		    RetMsg(msg, link, preport, "Areafix reply: help request");
		    break;
		case ADD:
		    report = areaStatus(report, preport);
		    if (rescanMode) {
			preport = processcmd( link, token, RESCAN );
			if (preport != NULL)
			    report = areaStatus(report, preport);
		    }
		    break;
		case AVAIL:
		    RetMsg(msg, link, preport, "Areafix reply: available areas");
		    break;
		case UNLINK:
		    RetMsg(msg, link, preport, "Areafix reply: unlinked request");
		    break;
		case QUERY:
		    RetMsg(msg, link, preport, "Areafix reply: linked request");
		    break;
		case PAUSE:
		    RetMsg(msg, link, preport, "Areafix reply: pause request");
		    break;
		case RESUME:
		    RetMsg(msg, link, preport, "Areafix reply: resume request");
		    break;
		case INFO:
		    RetMsg(msg, link, preport, "Areafix reply: link information");
		    break;
		case PACKER:
		    RetMsg(msg, link, preport, "Areafix reply: packer change request");
		    break;
		case RSB:
		    RetMsg(msg, link, preport, "Areafix reply: redused seen-by change request");
		    break;
		case STAT:
		    report = areaStatus(report, preport);
		    break;
		default:
		    w_log(LL_ERR,"Unknown areafix command:%s", token);
		    break;
		}
	    } /* end if (preport != NULL) */
	    token = strseparate (&tmp, "\n\r");
	    if (RetFix==DONE) token=NULL;
	} /* end while (token != NULL) */
    nfree(textBuff);
    } else {
	if (link == NULL) {
	    tmplink = (s_link*) safe_malloc(sizeof(s_link));
	    memset(tmplink, '\0', sizeof(s_link));
	    tmplink->ourAka = &(msg->destAddr);
	    tmplink->hisAka.zone = msg->origAddr.zone;
	    tmplink->hisAka.net = msg->origAddr.net;
	    tmplink->hisAka.node = msg->origAddr.node;
	    tmplink->hisAka.point = msg->origAddr.point;
	    link = tmplink;
	}
	/*  security problem */
		
	switch (security) {
	case 1:
	    xscatprintf(&report, " \r different pkt and msg addresses\r");
	    break;
	case 2:
	    xscatprintf(&report, " \r areafix is turned off\r");
	    break;
	case 3:
	    xscatprintf(&report, " \r password error\r");
	    break;
	case 4:
	    xscatprintf(&report, " \r your system is unknown\r");
	    break;
	case 5:
	    xscatprintf(&report, " \r message sent to wrong AKA\r");
	    break;
	default:
	    xscatprintf(&report, " \r unknown error. mail to sysop.\r");
	    break;
	}

	RetMsg(msg, link, report, "Areafix reply: security violation");
	w_log(LL_AREAFIX, "areafix: security violation from %s", aka2str(link->hisAka));
	nfree(tmplink);
        w_log(LL_FUNC, __FILE__ ":%u:processAreaFix() rc=1", __LINE__);
	return 1;
    }

    if ( report != NULL ) {
        if (config->areafixQueryReports) {
            preport = linked (link);
            xstrcat(&report, preport);
            nfree(preport);
        }
        RetMsg(msg, link, report, "Areafix reply: node change request");
    }

    if (rulesCount) {
        for (nr=0; nr < rulesCount; nr++) {
            if (rulesList && rulesList[nr]) {
                RetRules (msg, link, rulesList[nr]);
                nfree (rulesList[nr]);
            }
        }
        nfree (rulesList);
        rulesCount=0;
    }

    w_log(LL_AREAFIX, "Areafix: successfully done for %s",aka2str(link->hisAka));

    /*  send msg to the links (forward requests to areafix) */
    sendAreafixMessages();
    w_log(LL_FUNC, __FILE__ "::processAreaFix() end (rc=1)");
    return 1;
}

void MsgToStruct(HMSG SQmsg, XMSG xmsg, s_message *msg)
{
    /*  convert header */
    msg->attributes  = xmsg.attr;

    msg->origAddr.zone  = xmsg.orig.zone;
    msg->origAddr.net   = xmsg.orig.net;
    msg->origAddr.node  = xmsg.orig.node;
    msg->origAddr.point = xmsg.orig.point;

    msg->destAddr.zone  = xmsg.dest.zone;
    msg->destAddr.net   = xmsg.dest.net;
    msg->destAddr.node  = xmsg.dest.node;
    msg->destAddr.point = xmsg.dest.point;

    strcpy((char *)msg->datetime, (char *) xmsg.__ftsc_date);
    xstrcat(&(msg->subjectLine), (char *) xmsg.subj);
    xstrcat(&(msg->toUserName), (char *) xmsg.to);
    xstrcat(&(msg->fromUserName), (char *) xmsg.from);

    msg->textLength = MsgGetTextLen(SQmsg);
    xstralloc(&(msg->text),msg->textLength+1);
    MsgReadMsg(SQmsg, NULL, 0, msg->textLength, (unsigned char *) msg->text, 0, NULL);
    msg->text[msg->textLength] = '\0';

}

void afix(hs_addr addr, char *cmd)
{
    HAREA           netmail;
    HMSG            SQmsg;
    unsigned long   highmsg, i;
    XMSG            xmsg;
    hs_addr         dest;
    s_message	    msg, *tmpmsg;
    int             k, startarea = 0, endarea = config->netMailAreaCount;
    s_area          *area;
    char            *name = config->robotsArea;
    s_link          *link;

    w_log(LL_FUNC, __FILE__ "::afix() begin");
    w_log(LL_INFO, "Start AreaFix...");

    if ((area = getNetMailArea(config, name)) != NULL) {
        startarea = area - config->netMailAreas;
        endarea = startarea + 1;
    }

    if (cmd) {
        link = getLinkFromAddr(config, addr);
        if (link) {
          if (cmd && strlen(cmd)) {
            tmpmsg = makeMessage(&addr, link->ourAka, link->name,
                link->RemoteRobotName ?
                link->RemoteRobotName : "Areafix",
                link->areaFixPwd ?
                link->areaFixPwd : "", 1,
                config->areafixReportsAttr);
            tmpmsg->text = safe_strdup(cmd);
            processAreaFix(tmpmsg, NULL, 1);
            freeMsgBuffers(tmpmsg);
	  } else w_log(LL_WARN, "areafix: empty areafix command from %s", aka2str(addr));
        } else w_log(LL_ERR, "areafix: no such link in config: %s!", aka2str(addr));
    }
    else for (k = startarea; k < endarea; k++) {

        netmail = MsgOpenArea((unsigned char *) config->netMailAreas[k].fileName,
            MSGAREA_NORMAL,
            /*config -> netMailArea.fperm,
            config -> netMailArea.uid,
            config -> netMailArea.gid,*/
            (word)config -> netMailAreas[k].msgbType);

        if (netmail != NULL) {

            highmsg = MsgGetHighMsg(netmail);
            w_log(LL_INFO,"Scanning %s",config->netMailAreas[k].areaName);

            /*  scan all Messages and test if they are already sent. */
            for (i=1; i<= highmsg; i++) {
                SQmsg = MsgOpenMsg(netmail, MOPEN_RW, i);

                /*  msg does not exist */
                if (SQmsg == NULL) continue;

                MsgReadMsg(SQmsg, &xmsg, 0, 0, NULL, 0, NULL);
                cvtAddr(xmsg.dest, &dest);

                /*  if not read and for us -> process AreaFix */
                striptwhite((char*)xmsg.to);
                if (((xmsg.attr & MSGREAD) != MSGREAD) &&
                    (isOurAka(config,dest)) && (strlen((char*)xmsg.to)>0) &&
                    fc_stristr(config->areafixNames,(char*)xmsg.to))
                {
                    memset(&msg,'\0',sizeof(s_message));
                    MsgToStruct(SQmsg, xmsg, &msg);
                    processAreaFix(&msg, NULL, 0);
                    if (config->areafixKillRequests) {
                        MsgCloseMsg(SQmsg);
                        MsgKillMsg(netmail, i--);
                    } else {
                        xmsg.attr |= MSGREAD;
                        if( 0!=MsgWriteMsg(SQmsg, 0, &xmsg, NULL, 0, 0, 0, NULL) )
                           w_log(LL_ERR, "Could not write msg in netmailarea %s! Check the wholeness of messagebase, please.", config->netMailAreas[k].areaName);
                        MsgCloseMsg(SQmsg);
                    }
                    freeMsgBuffers(&msg);
                }
                else MsgCloseMsg(SQmsg);

            }

            MsgCloseArea(netmail);
        } else {
            w_log(LL_ERR, "Could not open %s", config->netMailAreas[k].areaName);
        }
    }
    w_log(LL_FUNC, __FILE__ "::afix() end");
}

int unsubscribeFromPausedEchoAreas(s_link *link) {
    unsigned i,j;
    char *text = NULL;
    s_area *area;
    s_message *tmpmsg;

    for (i=0; i<config->echoAreaCount; i++) {
	area = &(config->echoAreas[i]);

	if ((area->msgbType & MSGTYPE_PASSTHROUGH) && isLinkOfArea(link,area)) {

	    /*  unsubscribe only if uplink & auto-paused downlink presents */
	    if (area->downlinkCount==2) {
		if ((j = isAreaLink(link->hisAka, area)) != -1) {
		    /*  don't touch mandatory links */
		    if (area->downlinks[j]->mandatory) continue;
		    /*  add area for unsubscribe */
		    xstrscat(&text,"-",area->areaName,"\r",NULL);
		}
	    }
	}
    }

    if (text) {
	tmpmsg = makeMessage(&(link->hisAka), link->ourAka, link->name,
			     "areafix", link->areaFixPwd, 1,
                 config->areafixReportsAttr);
	tmpmsg->text = text;
	processAreaFix(tmpmsg, NULL, 0);
	freeMsgBuffers(tmpmsg);
	nfree(tmpmsg);
    }

    return 0;
}

void autoPassive()
{
  time_t   time_cur, time_test;
  struct   stat stat_file;
  s_message *msg;
  FILE *f;
  char *line, *path;
  unsigned int i;

  for (i = 0; i < config->linkCount; i++) {

      if (config->links[i].autoPause==0 || (config->links[i].Pause == (EPAUSE|FPAUSE))
         ) continue;

      if (createOutboundFileName(&(config->links[i]),
				 config->links[i].echoMailFlavour,
				 FLOFILE) == 0) {
	  f = fopen(config->links[i].floFile, "rt");
	  if (f) {
	      while ((line = readLine(f)) != NULL) {
		  line = trimLine(line);
		  path = line;
		  if (!isArcMail(path)) {
		      nfree(line);
		      continue;
		  }
		  if (*path && (*path == '^' || *path == '#')) {
		      path++;
		      /*  set Pause if files stored only in outbound */
		      if (*path && strncmp(config->outbound,path,strlen(config->outbound)-1)==0 && stat(path, &stat_file) != -1) {

			  time_cur = time(NULL);
			  if (time_cur > stat_file.st_mtime) {
			      time_test = (time_cur - stat_file.st_mtime)/3600;
			  } else { /*  buggly time on file, anyway don't autopause on it */
			      time_test = 0;
			  }

			  if (time_test >= (time_t)(config->links[i].autoPause*24)) {
			      w_log(LL_AREAFIX, "autopause: the file %s is %d days old", path, time_test/24);
			      if (Changepause((cfgFile) ? cfgFile :
					      getConfigFileName(),
					      &(config->links[i]), 1,
					      config->links[i].Pause^(EPAUSE|FPAUSE))) {
				  msg = makeMessage(config->links[i].ourAka,
					    &(config->links[i].hisAka),
					    versionStr,config->links[i].name,
					    "AutoPassive", 1,
					    config->areafixReportsAttr);
				  msg->text = createKludges(config, NULL,
					    config->links[i].ourAka,
					    &(config->links[i].hisAka),
					    versionStr);
				  if (config->areafixReportsFlags)
					xstrscat(&msg->text, "\001FLAGS ", config->areafixReportsFlags, "\r", NULL);
				  xstrcat(&msg->text, "\r System switched to passive, your subscription are paused.\r\r"
					" You are being unsubscribed from echo areas with no downlinks besides you!\r\r"
					" When you wish to continue receiving echomail, please send requests\r"
					" to AreaFix containing the %RESUME command.");
				  xscatprintf(&msg->text, "\r\r--- %s autopause\r", versionStr);
				  msg->textLength = strlen(msg->text);
				  processNMMsg(msg, NULL,
					       getNetMailArea(config,config->robotsArea),
					       0, MSGLOCAL);
				  closeOpenedPkt();
				  freeMsgBuffers(msg);
				  nfree(msg);

				  /*  unsubscribe link from areas without non-paused links */
                  /* use "hptkill -y" or "hptkill -yp" to fulfill this purpose
				  unsubscribeFromPausedEchoAreas(&(config->links[i]));
                  */

			      } /*  end changepause */
			      nfree(line);
			      /* fclose(f); file closed after endwhile */
			      break;
			  }
		      } /* endif */
		  } /* endif ^# */
		  nfree(line);
	      } /* endwhile */
	      fclose(f);
	  } /* endif */
	  nfree(config->links[i].floFile);
	  remove(config->links[i].bsyFile);
	  nfree(config->links[i].bsyFile);
      }
      nfree(config->links[i].pktFile);
      nfree(config->links[i].packFile);
  } /* endfor */
}

int relink (char *straddr) {
    s_link          *researchLink = NULL;
    unsigned int    count, areasArraySize;
    s_area          **areasIndexArray = NULL;
    struct _minf m;

    /*  parse config */
    if (config==NULL) processConfig();
    if ( initSMAPI == -1 ) {
	/*  init SMAPI */
	initSMAPI = 0;
	m.req_version = 0;
	m.def_zone = (UINT16) config->addr[0].zone;
	if (MsgOpenApi(&m) != 0) {
	    exit_hpt("MsgApiOpen Error",1);
	}
    }

    w_log(LL_START, "Start relink...");

    if (straddr) researchLink = getLink(config, straddr);
    else {
	w_log(LL_ERR, "No address");
	return 1;
    }

    if ( researchLink == NULL ) {
	w_log(LL_ERR, "Unknown link address %s", straddr);
	return 1;
    }

    areasArraySize = 0;
    areasIndexArray = (s_area **) safe_malloc
	(sizeof(s_area *) * (config->echoAreaCount + config->localAreaCount + 1));

    for (count = 0; count < config->echoAreaCount; count++)
	if ( isLinkOfArea(researchLink, &config->echoAreas[count])) {
	    areasIndexArray[areasArraySize] = &config->echoAreas[count];
	    areasArraySize++;
	    w_log(LL_AREAFIX, "Echo %s from link %s refreshed",
		  config->echoAreas[count].areaName, aka2str(researchLink->hisAka));
	}

    if ( areasArraySize > 0 ) {
	s_message *msg;

	msg = makeMessage(researchLink->ourAka,
			  &researchLink->hisAka,
			  versionStr,
			  researchLink->RemoteRobotName ?
			  researchLink->RemoteRobotName : "areafix",
			  researchLink->areaFixPwd ? researchLink->areaFixPwd : "", 1,
              config->areafixReportsAttr);

	msg->text = createKludges(config,NULL,researchLink->ourAka,
                              &researchLink->hisAka,versionStr);
	if (config->areafixReportsFlags)
	    xstrscat(&(msg->text), "\001FLAGS ", config->areafixReportsFlags, "\r",NULL);

	for ( count = 0 ; count < areasArraySize; count++ ) {
	    if ((areasIndexArray[count]->downlinkCount  <= 1) &&
		(areasIndexArray[count]->msgbType & MSGTYPE_PASSTHROUGH))
		xscatprintf(&(msg->text), "-%s\r",areasIndexArray[count]->areaName);
	    else
		xscatprintf(&(msg->text), "+%s\r",areasIndexArray[count]->areaName);
	}

	xscatprintf(&(msg->text), " \r--- %s areafix\r", versionStr);
	msg->textLength = strlen(msg->text);
	w_log(LL_AREAFIX, "'Refresh' message created to `%s`",
	      researchLink->RemoteRobotName ?
	      researchLink->RemoteRobotName : "areafix");
	processNMMsg(msg, NULL,
		     getNetMailArea(config,config->robotsArea),
		     1, MSGLOCAL|MSGKILL);
	closeOpenedPkt();
	freeMsgBuffers(msg);
	nfree(msg);
	w_log(LL_AREAFIX, "Total request relink %i area(s)",areasArraySize);
    }

    nfree(areasIndexArray);

    /* deinit SMAPI */
    MsgCloseApi();

    return 0;
}
