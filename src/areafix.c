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
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#if !defined(__TURBOC__) && !(defined(_MSC_VER) && (_MSC_VER >= 1200))
#include <unistd.h>
#endif

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/xstr.h>

#include <fcommon.h>
#include <global.h>
#include <pkt.h>
#include <version.h>
#include <toss.h>
#include <smapi/patmat.h>
#include <ctype.h>
#include <smapi/progprot.h>
#include <seenby.h>
#include <scan.h>
#include <fidoconf/recode.h>
#include <areafix.h>
#include <scanarea.h>
#include <arealist.h>
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

int isarcmail (char *name)
{
    char *ext = name + strlen(name) - 4;

    if (strncasecmp(ext, ".mo", 3) == 0 || strncasecmp(ext, ".tu", 3) == 0||
        strncasecmp(ext, ".we", 3) == 0 || strncasecmp(ext, ".th", 3) == 0||
        strncasecmp(ext, ".fr", 3) == 0 || strncasecmp(ext, ".sa", 3) == 0||
        strncasecmp(ext, ".su", 3) == 0) return 1;
    else return 0;  
}

/* test area-link pair to mandatory
 */
int mandatoryCheck(s_area area, s_link *link) {
    int i;

    w_log(LL_FUNC,"areafix.c::mandatoryCheck()");

    if (grpInArray(area.group,link->optGrp,link->numOptGrp)&&link->mandatory) return 1;
    if (link->numOptGrp==0 && link->mandatory) return 1;
    if (area.mandatory) return 1;
    if ((i=isAreaLink(link->hisAka, &area))!=-1) return area.downlinks[i]->mandatory;
    return 0;
}

int subscribeCheck(s_area area, s_link *link)
{
    int found = 0;

    if (isLinkOfArea(link, &area)) return 0;

    if (area.group) {
	if (config->numPublicGroup)
	    found = grpInArray(area.group,config->PublicGroup,config->numPublicGroup);
	if (!found && link->numAccessGrp)
	    found = grpInArray(area.group,link->AccessGrp,link->numAccessGrp);
    } else found = 1;

    if (!found) return 2;
    if (area.levelwrite > link->level && area.levelread > link->level) return 2;
    return 1;
}

int subscribeAreaCheck(s_area *area, char *areaname, s_link *link)
{
    int rc=4;

    if (!areaname) return rc;
    if (patimat(area->areaName,areaname)==1) {
	rc=subscribeCheck(*area, link);
	// 0 - already subscribed / linked
	// 1 - need subscribe / not linked
	// 2 - no access
    }
    // this is another area
    return rc;
}
#if 0
// del link from area, return 0 on success, 1 on error
int delLinkFromArea(FILE *f, char *fileName, char *str)
{
    long curpos, endpos, linelen=0, len;
    char *buff, *sbuff, *ptr, *tmp, *line, *save = NULL;

    curpos = ftell(f);
    if (NULL == (buff = readLine(f))) return 1;
    buff = trimLine(buff);
    len = strlen(buff);

    sbuff = buff;

    while ( (ptr = strstr(sbuff, str)) != NULL ) {
	if (isspace(*(ptr-1)) &&
	    (isspace(ptr[strlen(str)]) ||
	     ptr[strlen(str)]=='\000')) save=ptr;
	sbuff = ptr+1;
    }
    ptr = save;
    line = ptr;

    if (ptr) {
	curpos += (ptr-buff-1);
	while (ptr) {
	    tmp = strseparate(&ptr, " \t");
	    if (ptr == NULL) {
		linelen = (buff+len+1)-line;
		break;
	    }
	    if (*ptr != '-') {
		linelen = ptr-line;
		break;
	    }
	    else {
		if (strncasecmp(ptr, "-r", 2)) {
		    if (strncasecmp(ptr, "-w", 2)) {
			if (strncasecmp(ptr, "-mn", 3)) {
			    linelen = ptr-line;
			    break;
			}
		    }
		}
	    }
	}
	fseek(f, 0L, SEEK_END);
	endpos = ftell(f);
	len = endpos-(curpos+linelen);
	buff = (char*) safe_realloc(buff, (size_t) (len+1));
	memset(buff, '\0', (size_t) (len+1));
	fseek(f, curpos+linelen, SEEK_SET);
	len = fread(buff, sizeof(char), (size_t) len, f);
 	fseek(f, curpos, SEEK_SET);
	fwrite(buff, sizeof(char), (size_t) len, f);
#if defined(__WATCOMC__) || defined(__MINGW32__)
	fflush( f );
	fTruncate( fileno(f), endpos-linelen );
	fflush( f );
#else
	truncate(fileName, endpos-linelen);
#endif
    }
    nfree(buff);
    return (save ? 0 : 1);
}

// add string to file
int addstring(FILE *f, char *aka)
{
    int rc = 0;
    char *cfg, c;
    long areapos,endpos,cfglen,len;

    /* in dos and win32 by default \n translates into 2 chars */
    fseek(f,-2L,SEEK_CUR);
    c=(char) fgetc(f);
    if (c==0x0D) fseek(f,-1L,SEEK_CUR);

    areapos=ftell(f);
	
    // end of file
    fseek(f,0L,SEEK_END);
    endpos=ftell(f);
    cfglen=endpos-areapos;
	
    // storing end of file...
    cfg = (char*) safe_malloc((size_t) cfglen+1);
    fseek(f,-cfglen,SEEK_END);
    len = fread(cfg,sizeof(char),(size_t) cfglen,f);
	
    // write config
    fseek(f,-cfglen,SEEK_END);
    rc += (fputs(" ",f) == EOF) ? 1 : 0;
    rc += (fputs(aka,f) == EOF) ? 1 : 0;
    rc += (fwrite(cfg,sizeof(char),(size_t) len,f) < len) ? 1 : 0;
    fflush(f);
	
    nfree(cfg);
    return rc;
}
#endif // if 0

void addlink(s_link *link, s_area *area)
{
    s_arealink *arealink;
    
    area->downlinks = safe_realloc (area->downlinks, sizeof(s_arealink*)*(area->downlinkCount+1));
    arealink = area->downlinks[area->downlinkCount] = (s_arealink*) safe_malloc(sizeof(s_arealink));

    memset(arealink, '\0', sizeof(s_arealink));
    arealink->link = link;

    if (link->numOptGrp > 0) {
	// default set export on, import on, mandatory off
	arealink->export = 1;
	arealink->import = 1;
	arealink->mandatory = 0;

	if (grpInArray(area->group,link->optGrp,link->numOptGrp)) {
	    arealink->export = link->export;
	    arealink->import = link->import;
	    arealink->mandatory = link->mandatory;
	}
    } else {
	arealink->export = link->export;
	arealink->import = link->import;
	arealink->mandatory = link->mandatory;
    }
    if (area->mandatory) arealink->mandatory = 1;
    if (link->level < area->levelread)	arealink->export=0;
    if (link->level < area->levelwrite) arealink->import=0;
    // paused link can't receive mail
    if (link->Pause) arealink->export = 0;

    area->downlinkCount++;
}

void removelink(s_link *link, s_area *area)
{
    int i;

    if ( (i=isAreaLink(link->hisAka, area)) != -1) {
	nfree(area->downlinks[i]);
	area->downlinks[i] = area->downlinks[area->downlinkCount-1];
	area->downlinkCount--;
    }
}

s_message *makeMessage (s_addr *origAddr, s_addr *destAddr,
			char *fromName,	char *toName, char *subject, int netmail)
{
    // netmail == 0 - echomail
    // netmail == 1 - netmail
    time_t time_cur;
    s_message *msg;

    if (toName == NULL) toName = "sysop";
    
    time_cur = time(NULL);
    
    msg = (s_message*) safe_malloc(sizeof(s_message));
    memset(msg, '\0', sizeof(s_message));
    
    msg->origAddr.zone = origAddr->zone;
    msg->origAddr.net = origAddr->net;
    msg->origAddr.node = origAddr->node;
    msg->origAddr.point = origAddr->point;

    msg->destAddr.zone = destAddr->zone;
    msg->destAddr.net = destAddr->net;
    msg->destAddr.node = destAddr->node;
    msg->destAddr.point = destAddr->point;
	
    xstrcat(&(msg->fromUserName), fromName);
    xstrcat(&(msg->toUserName), toName);
    xstrcat(&(msg->subjectLine), subject);

    msg->attributes |= MSGLOCAL;
    if (netmail) {
	msg->attributes |= MSGPRIVATE;
	msg->netMail = 1;
    }
    if (config->areafixKillReports) msg->attributes |= MSGKILL;

    strftime((char*)msg->datetime, 21, "%d %b %y  %H:%M:%S", localtime(&time_cur));

    return msg;
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

        if (rc < 2 && (!area.hide || (area.hide && rc==0))) { // add line
            if (pattern)
            {
                /* if matches pattern and not reversed (or vise versa) */
                if (patimat(area.areaName, pattern)!=reversed) 
                {
                    addAreaListItem(al,rc==0,area.areaName,area.description);
                    if (rc==0) active++; avail++;
                }
            } else
            {
                addAreaListItem(al,rc==0,area.areaName,area.description);
                if (rc==0) active++; avail++;
            }
	} /* end add line */

    } /* end for */
    sortAreaList(al);
    list = formatAreaList(al,78," *");
    if (list) xstrcat(&report,list);
    nfree(list);
    freeAreaList(al);

    xscatprintf(&report, "\r'*' = area active for %s\r%i areas available, %i areas active\r", aka2str(link->hisAka), avail, active);
    if (link->afixEchoLimit) xscatprintf(&report, "\rYour limit is %u areas for subscribe\r", link->afixEchoLimit);

    w_log('8', "areafix: list sent to %s", aka2str(link->hisAka));

    return report;
}

char *linked(s_link *link) {
    unsigned int i, n, rc;
    char *report = NULL;

    xscatprintf(&report, "\r%s areas on %s\r\r", 
		link->Pause ? "Passive" : "Active", aka2str(link->hisAka));
							
    for (i=n=0; i<config->echoAreaCount; i++) {
	rc=subscribeCheck(config->echoAreas[i], link);
	if (rc==0) {
	    xscatprintf(&report, " %s\r", config->echoAreas[i].areaName);
	    n++;
	}
    }
    xscatprintf(&report, "\r%u areas linked\r", n);
    if (link->afixEchoLimit) xscatprintf(&report, "\rYour limit is %u areas for subscribe\r", link->afixEchoLimit);
    w_log('8', "areafix: linked areas list sent to %s", aka2str(link->hisAka));
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
    w_log('8', "areafix: unlinked areas list sent to %s", aka2str(link->hisAka));

    return report;
}

char *help(s_link *link) {
    FILE *f;
    int i=1;
    char *help;
    long endpos;

    if (config->areafixhelp!=NULL) {
	if ((f=fopen(config->areafixhelp,"r")) == NULL) {
	    fprintf(stderr,"areafix: cannot open help file \"%s\"\n", 
		    config->areafixhelp);
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

	w_log('8', "areafix: help sent to %s",link->name);

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

char *available(s_link *link, char *cmdline)
{
    FILE *f;
    unsigned int j=0, found;
    unsigned int k, rc;
    char *report = NULL, *line, *token, *running, linkAka[SIZE_aka2str];
    char *pattern;
    int reversed;
    s_link *uplink=NULL;
    ps_arealist al;

    pattern = getPatternFromLine(cmdline, &reversed);
    if ((pattern) && (strlen(pattern)>60 || !isValidConference(pattern))) {
        w_log(LL_FUNC, "areafix::avail() FAILED (error request line)");
        return errorRQ(cmdline);
    }

    for (j = 0; j < config->linkCount; j++) {
	uplink = &(config->links[j]);

	found = 0;
	for (k = 0; k < link->numAccessGrp && uplink->LinkGrp; k++)
	    if (strcmp(link->AccessGrp[k], uplink->LinkGrp) == 0)
		found = 1;

	if ((uplink->forwardRequests && uplink->forwardRequestFile) &&
	    ((uplink->LinkGrp == NULL) || (found != 0))) {
	    if ((f=fopen(uplink->forwardRequestFile,"r")) == NULL) {
		w_log('8', "areafix: cannot open forwardRequestFile \"%s\"",
		      uplink->forwardRequestFile);
		return report;
	    }

	    xscatprintf(&report, "Available Area List from %s:\r",
			aka2str(uplink->hisAka));

	    al = newAreaList();
	    while ((line = readLine(f)) != NULL) {
		line = trimLine(line);
		if (line[0] != '\0') {
		    running = line;
		    token = strseparate(&running, " \t\r\n");
		    rc = 0;

		    if (uplink->numDfMask)
			rc |= tag_mask(token, uplink->dfMask, uplink->numDfMask);

		    if (uplink->denyFwdFile)
			rc |= areaIsAvailable(token,uplink->denyFwdFile,NULL,0);

                    if (pattern)
                    {
                        /* if matches pattern and not reversed (or vise versa) */
                        if ((rc==0) &&(patimat(token, pattern)!=reversed))
                            addAreaListItem(al,0,token,running);
                    } else
                    {
                        if (rc==0) addAreaListItem(al,0,token,running);
                    }

		}
		nfree(line);
	    }
	    fclose(f);

	    if(al->count) {
		sortAreaList(al);
		line = formatAreaList(al,78,NULL);
		xstrcat(&report,"\r");
		xstrcat(&report,line);
		nfree(line);
	    }

	    freeAreaList(al);

	    xscatprintf(&report, " %s\r\r",print_ch(77,'-'));

	    // warning! do not ever use aka2str twice at once!
	    sprintf(linkAka, "%s", aka2str(link->hisAka));
	    w_log('8', "areafix: Available Area List from %s sent to %s", aka2str(uplink->hisAka), linkAka);
	}
    }

    if (report==NULL) {
	xstrcat(&report, "\r  no links for creating Available Area List\r");
	w_log('8', "areafix: no links for creating Available Area List");
    }
    return report;
}                                                                               

// subscribe if (act==0),  unsubscribe if (act==1), delete if (act==2)
int forwardRequestToLink (char *areatag, s_link *uplink, s_link *dwlink, int act) {
    s_message *msg;
    char *base, pass[]="passthrough";

    if (uplink->msg == NULL) {
	msg = makeMessage(uplink->ourAka, &(uplink->hisAka), config->sysop, uplink->RemoteRobotName ? uplink->RemoteRobotName : "areafix", uplink->areaFixPwd ? uplink->areaFixPwd : "\x00", 1);
	msg->text = createKludges(NULL, uplink->ourAka, &(uplink->hisAka));
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
            // create from own address
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
        // delete area
        if (uplink->advancedAreafix)
            xscatprintf(&(msg->text), "~%s\r", areatag);
        else
            xscatprintf(&(msg->text), "-%s\r", areatag);
    }
    return 0;
}

int testAddr(char *addr, s_addr hisAka)
{
    s_addr aka;
    string2addr(addr, &aka);
    if (addrComp(aka, hisAka)==0) return 1;
    return 0;
}

char* findLinkInString(char *line, s_addr addr)
{
    char* linkpos = NULL;
    while ( (linkpos = strstr(line, aka2str(addr))) != NULL )
    {
        if(testAddr(linkpos,addr))
            break;
        line = linkpos+1;
    }
    return linkpos;
}

int changeconfig(char *fileName, s_area *area, s_link *link, int action) {
    FILE *cfgin,*cfgout;
    char *cfgline=NULL, *token=NULL, *buff=NULL, *cfgInline=NULL;
    long pos=-1, lastpos=-1, endpos=-1, len=0;
    char *tmpFileName=NULL;
    int rc=0;
    e_changeConfigRet nRet = I_ERR;
    char* areaName = area->areaName;

    w_log(LL_FUNC,"areafix.c::changeconfig()");

    if (init_conf(fileName))
		return -1;

    w_log(LL_SRCLINE,"areafix.c:%u:changeconfig() action=%i",__LINE__,action);

    while ((buff = configline()) != NULL) {
	buff = trimLine(buff);
	buff = stripComment(buff);
	if (buff[0] != 0) {
	    buff = shell_expand(buff);
	    buff = cfgline = vars_expand(buff);
	    token = strseparate(&cfgline, " \t");
	    if (stricmp(token, "echoarea")==0) {
		token = strseparate(&cfgline, " \t"); 
		if (*token=='\"' && token[strlen(token)-1]=='\"' && token[1]) {
		    token++;
		    token[strlen(token)-1]='\0';
		}
		if (stricmp(token, areaName)==0) {
		    fileName = safe_strdup(getCurConfName());
		    pos = getCurConfPos();
		    break;
		}
	    }
	}
	nfree(buff);
    }
    if (pos == -1) { // impossible // error occurred
	    close_conf();
	    return -1;
    }
    cfgin = get_hcfg();
    if((tmpFileName=tmpnam(tmpFileName)) != NULL)
        cfgout = fopen(tmpFileName,"wb"); // create result file
    else 
        cfgout = NULL;
    if ( !cfgin || !cfgout ) {
	if (cfgout) fclose(cfgout);
	if (cfgin) close_conf();
	if (!quiet) fprintf(stderr, "areafix: cannot open config file %s for reading and writing\n", fileName);
	w_log(LL_ERR,"areafix: cannot open config file \"%s\" for reading and writing", fileName);
	nRet = I_ERR; // go to end :) // error occurred
	return -1;
    }
    else {
        buff = (char*)safe_calloc( (size_t)pos ,sizeof(char) );
	fseek(cfgin, 0, SEEK_SET);
        len = fread(buff, sizeof(char), (size_t)pos, cfgin);
        fwrite(buff, sizeof(char), (size_t) len, cfgout);
        cfgInline = readLine(cfgin);
    }
    if ( cfgInline == NULL ) {
        nRet = IO_OK; // go to end
    // return -1; this is useless return!!!
    }
    else { // everithing fine. now we try to do some actions
      switch (action) {
        case 0: // forward Request To Link
            if ((area->msgbType==MSGTYPE_PASSTHROUGH) && 
                (!config->areafixQueueFile) && 
                (area->downlinkCount==1) &&
                (area->downlinks[0]->link->hisAka.point == 0))
            {
                forwardRequestToLink(areaName, area->downlinks[0]->link, NULL, 0);
            }
        case 3: // add link to existing area
            xscatprintf(&cfgInline, " %s", aka2str(link->hisAka));
            fprintf(cfgout, "%s%s", cfgInline, cfgEol()); // add line to config
            nRet = ADD_OK;
            break;
        case 1: // remove link from area
            if ((area->msgbType==MSGTYPE_PASSTHROUGH)
                && (area->downlinkCount==1) &&
                (area->downlinks[0]->link->hisAka.point == 0)) {
                forwardRequestToLink(areaName, area->downlinks[0]->link, NULL, 1);
            }
            cfgline = findLinkInString(cfgInline , link->hisAka );
            rc = 0;
            while(cfgline[rc] && !isspace(cfgline[rc++])); // search for end of addr string
            while(cfgline[rc] && !isdigit(cfgline[rc])) rc++; // search for next addrr string
            cfgline[0] = '\0';
            if(cfgline[rc]) {
                strcat(cfgInline, cfgline+rc);
            }
            else {
                rc = -1;
                while( isspace(cfgline[rc])) { cfgline[rc] = '\0'; rc--;}
            }
            fprintf(cfgout, "%s%s", cfgInline, cfgEol()); // add line to config 
            nRet = DEL_OK;
            break;
        case 2:
        //makepass(f, fileName, areaName);
        case 4: // delete area 
        // do nothing. just do not add this line to new config
            nRet = DEL_OK;
            break;
        case 5: // subscribe us to  passthrough
            if ( hpt_stristr(area->downlinks[0]->link->autoAreaCreateDefaults,
                "passthrough") )  {
                nRet = O_ERR;
                fprintf(cfgout, "%s%s", cfgInline, cfgEol()); // add line to config 
                break;
            }   
            // get area string
            buff = makeAreaParam(area->downlinks[0]->link , areaName, NULL );
            nRet = ADD_OK;
        case 6: // make area pass. 

            if(action == 6) {
            buff = makeAreaParam(area->downlinks[0]->link , areaName, "passthrough" );
            nRet = DEL_OK;
          }
          // add all links
          token = strstr(cfgline, aka2str(area->downlinks[0]->link->hisAka));
          if(!testAddr(token,area->downlinks[0]->link->hisAka))
            token = strstr(token+1, aka2str(area->downlinks[0]->link->hisAka));

          xstrcat( &buff, token-1); 
          fprintf(cfgout, "%s%s", buff, cfgEol()); // add line to config
          break;
        default: break;
      } // switch (action)
      nfree(buff);
      lastpos = ftell(cfgin);
      fseek(cfgin, 0, SEEK_END);
      endpos = ftell(cfgin);
      buff = (char*) safe_calloc((size_t) (endpos-lastpos), sizeof(char));
      fseek(cfgin, lastpos, SEEK_SET);
      len = fread(buff, sizeof(char), (size_t) endpos-lastpos, cfgin);
      fwrite(buff, sizeof(char), (size_t) len, cfgout);
    } // else of if (cfgline == NULL) {
    close_conf(); fclose(cfgout); 
    w_log(LL_FILE,"areafix.c::changeconfig(): created '%s' ",tmpFileName);
    if (nRet==I_ERR){
        w_log(LL_FUNC,"areafix.c::changeconfig() rc=-1");
    } else {
        cfgin  = fopen(tmpFileName,"rb");
        cfgout = fopen(fileName,"wb"); // result file
        if ( !cfgin || !cfgout ) {
            if (!quiet) fprintf(stderr, "areafix: cannot open config file %s for reading and writing\n", fileName);
            w_log(LL_ERR,"areafix: cannot open config file \"%s\" for reading and writing", fileName);
        } else {
            int ch;
            while( (ch=getc(cfgin)) != EOF ) putc(ch, cfgout); 
            fclose(cfgin); fclose(cfgout); 
        }
    }    
    remove(tmpFileName);
    w_log(LL_FILE,"areafix.c::changeconfig(): deleted '%s' ",tmpFileName);
    nfree(buff);
    nfree(fileName);
    nfree(cfgInline);
    return nRet;
}

int areaIsAvailable(char *areaName, char *fileName, char **desc, int retd) {
    FILE *f;
    char *line, *token, *running;

    if (fileName==NULL || areaName==NULL) return 0;
	
    if ((f=fopen(fileName,"r")) == NULL) {
	w_log('8',"areafix: cannot open file \"%s\"",fileName);
	return 0;
    }
	
    while ((line = readLine(f)) != NULL) {
	line = trimLine(line);
	if (line[0] != '\0') {

	    running = line;
	    token = strseparate(&running, " \t\r\n");

	    if (token && areaName && stricmp(token, areaName)==0) {
		// return description if needed
		if (retd) {
		    *desc = NULL;
		    if (running) {
			//strip "" at the beginning & end
			if (running[0]=='"' && running[strlen(running)-1]=='"') {
			    running++; running[strlen(running)-1]='\0';
			}
			//change " -> '
			token = running;
			while (*token!='\0') {
			    if (*token=='"') *token='\'';
			    token++;
			}
			xstrcat(&(*desc), running);
		    }
		}
		nfree(line);
		fclose(f);
		return 1;
	    }			
	}
	nfree(line);
    }	
    // not found
    fclose(f);
    return 0;
}

static int compare_links_priority(const void *a, const void *b) {
    int ia = *((int*)a);
    int ib = *((int*)b);
    if(config->links[ia].forwardAreaPriority < config->links[ib].forwardAreaPriority) return -1;
    else if(config->links[ia].forwardAreaPriority > config->links[ib].forwardAreaPriority) return 1;
    else return 0;
}

int forwardRequest(char *areatag, s_link *dwlink, s_link **lastRlink) {
    unsigned int i, rc = 1;
    s_link *uplink;
    int *Indexes;
    unsigned int Requestable = 0;

    /* From Lev Serebryakov -- sort Links by priority */
    Indexes = safe_malloc(sizeof(int)*config->linkCount);
    for (i = 0; i < config->linkCount; i++) {
	if (config->links[i].forwardRequests) Indexes[Requestable++] = i;
    }
    qsort(Indexes,Requestable,sizeof(Indexes[0]),compare_links_priority);
    i = 0;
    if(lastRlink) { // try to find next requestable uplink
        for (; i < Requestable; i++) {
            uplink = &(config->links[Indexes[i]]);
            if( addrComp(uplink->hisAka, (*lastRlink)->hisAka) == 0)
            {   // we found lastRequestedlink
                i++;   // let's try next link
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
            rc = 2;
            continue;
        }
        if ( (uplink->denyFwdFile!=NULL) &&
            (areaIsAvailable(areatag,uplink->denyFwdFile,NULL,0)))
        {
            rc = 2;
            continue;
        }
        if (uplink->forwardRequestFile!=NULL) {
            // first try to find the areatag in forwardRequestFile
            if (tag_mask(areatag, uplink->frMask, uplink->numFrMask) || 
                areaIsAvailable(areatag,uplink->forwardRequestFile,NULL,0))
            {
                forwardRequestToLink(areatag,uplink,dwlink,0);
                rc = 0;
            }
            else  
            { rc = 2; }// found link with freqfile, but there is no areatag
        } else {
            rc = 0;
            if (uplink->numFrMask) // found mask
            { 
                if (tag_mask(areatag, uplink->frMask, uplink->numFrMask))
                    forwardRequestToLink(areatag,uplink,dwlink,0);
                else rc = 2;
            } else { // unconditional forward request
                if (dwlink->denyUFRA==0)
                    forwardRequestToLink(areatag,uplink,dwlink,0);
                else rc = 2;
            }
        }//(uplink->forwardRequestFile!=NULL) 
        if (rc==0) { // ?
            nfree(Indexes);
            return rc;
        }

    }// if (uplink->forwardRequests && (uplink->LinkGrp) ?
    }// for (i = 0; i < Requestable; i++) {
    
    // link with "forwardRequests on" not found
    nfree(Indexes);
    return rc;
}

/* test link for areas quantity limit exceed
 * return 0 if not limit exceed
 * else return not zero
 */
int limitCheck(s_link *link) {
    register unsigned int i,n;

    w_log(LL_FUNC,"areafix.c::limitCheck()");

    if (link->afixEchoLimit==0) return 0;
    for (i=n=0; i<config->echoAreaCount; i++)
	if (0==subscribeCheck(config->echoAreas[i], link))	
	    n++;
    i = n >= link->afixEchoLimit ;
    w_log(LL_FUNC,"areafix.c::limitCheck() rc=%u", i);
    return i;
}

int isPatternLine(char *s) {
    if (strchr(s,'*') || strchr(s,'?')) return 1;
    return 0;
}

void fixRules (s_link *link, s_area *area) {
    char *fileName = NULL, *fn, *fn1;

    if (!config->rulesDir) return;
    if (link->noRules) return;

    if (area->fileName) {
	fn = area->fileName;
	for (fn1 = fn; *fn1; fn1++) if (*fn1=='/' || *fn1=='\\') fn = fn1+1;
	xscatprintf(&fileName, "%s%c%s.rul", config->rulesDir, PATH_DELIM, fn);
    } else {
	fn = makeMsgbFileName(area->areaName);
	xscatprintf(&fileName, "%s%c%s.rul", config->rulesDir, PATH_DELIM, fn);
	nfree (fn); // allocated by makeMsgbFileName()
    }

    if (fexist(fileName)) {
	rulesCount++;
	rulesList = safe_realloc (rulesList, rulesCount * sizeof (char*));
	rulesList[rulesCount-1] = safe_strdup (area->areaName);
	// don't simply copy pointer because area may be
	// removed while processing other commands
    }
    nfree (fileName);
}

char *subscribe(s_link *link, char *cmd) {
    unsigned int i, rc=4, found=0;
    char *line, *an=NULL, *report = NULL;
    s_area *area=NULL;

    w_log(LL_FUNC, "areafix::subscribe()");

    line = cmd;
	
    if (line[0]=='+') line++;
    while (*line==' ') line++;

    if (*line=='+') line++; while (*line==' ') line++;
	
    if (strlen(line)>60 || !isValidConference(line)) {
      w_log(LL_FUNC, "areafix::subscribe() FAILED (error request line)");
      return errorRQ(line);
    }

    for (i=0; !found && rc!=6 && i<config->echoAreaCount; i++) {
	area = &(config->echoAreas[i]);
	an = area->areaName;

	rc=subscribeAreaCheck(area, line, link);
	if (rc==4) continue;        /* not match areatag, try next */
	if (rc==1 && mandatoryCheck(*area, link)) rc = 5; /* mandatory area/group/link */

	if (rc!=0 && limitCheck(link)) rc = 6; /* areas limit exceed for link */

	switch (rc) {
	case 0:         /* already linked */
	    if (!isPatternLine(line)) {
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
                     //  non-passthrough area for our aka means 
                     //  that we already linked to this area
               xscatprintf(&report, " %s %s  already linked\r",an, print_ch(49-strlen(an), '.'));
               w_log(LL_AREAFIX, "areafix: %s already linked to %s",aka2str(link->hisAka), an);
           }
        } else {
            if (changeconfig(cfgFile?cfgFile:getConfigFileName(),area,link,0)==ADD_OK) {
                addlink(link, area);
                fixRules (link, area);
                af_CheckAreaInQuery(an, NULL, NULL, DELIDLE);
                xscatprintf(&report," %s %s  added\r",an,print_ch(49-strlen(an),'.'));
                w_log(LL_AREAFIX, "areafix: %s subscribed to %s",aka2str(link->hisAka),an);
            } else {
                xscatprintf(&report," %s %s  error. report to sysop!\r",an,print_ch(49-strlen(an),'.'));
                w_log(LL_AREAFIX, "areafix: %s not subscribed to %s",aka2str(link->hisAka),an);
                w_log(LL_ERR, "areafix: can't write to config file!");
            }//if (changeconfig(cfgFile?cfgFile:getConfigFileName(),area,link,3)==0)
        }
	    if (!isPatternLine(line)) i = config->echoAreaCount;
	    break;
	case 6:         /* areas limit exceed for link */
	    break;
	default : // rc = 2 /* not access */
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
	    // try to forward request
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
                addlink(link, area);
                fixRules (link, area);
                w_log( LL_AREAFIX, "areafix: %s subscribed to area %s",
                    aka2str(link->hisAka),line);
            } else {
                xscatprintf( &report," %s %s  error. report to sysop!\r",
                    an, print_ch(49-strlen(an),'.') );
                w_log( LL_AREAFIX, "areafix: %s not subscribed to %s",
                    aka2str(link->hisAka),an);
                w_log(LL_ERR, "areafix: can't change config file!");
            }
          } else w_log( LL_AREAFIX, "areafix: %s already subscribed to area %s",
                aka2str(link->hisAka), line );

		}
	    }
	}
    }

    if (rc == 6) {   /* areas limit exceed for link */
	w_log( LL_AREAFIX,"areafix: area %s -- no access (full limit) for %s",
	      line, aka2str(link->hisAka));
	xscatprintf(&report," %s %s  no access (full limit)\r",
		    line, print_ch(49-strlen(line), '.'));
    }

    if ((report == NULL && found==0) || (found && area->hide)) {
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
    unsigned int i;

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
       w_log( LL_AREAFIX, "areafix: can't remove area from config" );
    }

    /* delete msgbase and dupebase for the area */
    if (area->msgbType!=MSGTYPE_PASSTHROUGH)
	MsgDeleteBase(area->fileName, (word) area->msgbType);
    if (area->dupeCheck != dcOff) {
	char *dupename = createDupeFileName(area);
	if (dupename) {
	    unlink(dupename);
	    nfree(dupename);
	}
    }

    w_log( LL_AREAFIX, "areafix: area %s deleted by %s",
                  an, aka2str(link->hisAka));

    /* delete the area from in-core config */
    for (i=0; i<area->downlinkCount; i++)
	nfree(area->downlinks[i]);
    nfree(area->downlinks);
    area->downlinkCount = 0;
    for (i=0; i<config->echoAreaCount; i++)
	if (stricmp(config->echoAreas[i].areaName, an)==0)
	    break;
    if (i<config->echoAreaCount && area==&(config->echoAreas[i])) {
	nfree(area->areaName);
	nfree(area->fileName);
	nfree(area->description);
	nfree(area->group);
	for (; i<config->echoAreaCount-1; i++)
	    memcpy(&(config->echoAreas[i]), &(config->echoAreas[i+1]),
	           sizeof(s_area));
	config->echoAreaCount--;
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
	w_log('8', "areafix: area %s is not found", line);
	return report;
    }
    rc = subscribeCheck(*area, link);
    an = area->areaName;

    switch (rc) {
    case 0:
	break;
    case 1:
	xscatprintf(&report, " %s %s  not linked\r", an, print_ch(49-strlen(an), '.'));
	w_log('8', "areafix: area %s is not linked to %s",
	      an, aka2str(link->hisAka));
	return report;
    case 2:
	xscatprintf(&report, " %s %s  no access\r", an, print_ch(49-strlen(an), '.'));
	w_log('8', "areafix: area %s -- no access for %s", an, aka2str(link->hisAka));
	return report;
    }
    if (link->LinkGrp == NULL || (area->group && strcmp(link->LinkGrp, area->group))) {
	xscatprintf(&report, " %s %s  delete not allowed\r",
		    an, print_ch(49-strlen(an), '.'));
	w_log('8', "areafix: area %s delete not allowed for %s",
	      an, aka2str(link->hisAka));
	return report;
    }
    return do_delete(link, area);
}

char *unsubscribe(s_link *link, char *cmd) {
    unsigned int i, rc = 2, j, from_us=0;
    char *line, *an, *report = NULL;
    s_area *area;
	
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
        int k;
        for (k=0; i<area->downlinkCount; k++) {
            if (addrComp(link->hisAka, area->downlinks[k]->link->hisAka)==0 &&
                area->downlinks[k]->defLink)
                return do_delete(link, area);
        }
        if ((area->msgbType == MSGTYPE_PASSTHROUGH) &&
            (area->downlinkCount < 3) &&
            (area->downlinks[0]->link->hisAka.point == 0) &&
            (config->areafixQueueFile)) {
            af_CheckAreaInQuery(an, &(area->downlinks[0]->link->hisAka), NULL, ADDIDLE);
        }    
        removelink(link, area);
		j = changeconfig(cfgFile?cfgFile:getConfigFileName(),area,link,1);
		if (j != DEL_OK) {
		    w_log('8', "areafix: %s doesn't unlinked from %s",
			  aka2str(link->hisAka), an);
		} else
		    w_log('8',"areafix: %s unlinked from %s",aka2str(link->hisAka),an);
        } else { // unsubscribing from own address
            if ((area->downlinkCount==1) &&
                (area->downlinks[0]->link->hisAka.point == 0)) {
                if(config->areafixQueueFile) {
                    af_CheckAreaInQuery(an, &(area->downlinks[0]->link->hisAka), NULL, ADDIDLE);
                } else {
                    forwardRequestToLink(area->areaName,
                        area->downlinks[0]->link, NULL, 1);
                }
            }
            j = changeconfig(cfgFile?cfgFile:getConfigFileName(),area,link,6);
        }
	    if (j == DEL_OK)
		xscatprintf(&report," %s %s  unlinked\r",an,print_ch(49-strlen(an),'.'));
	    else
		xscatprintf(&report," %s %s  error. report to sysop!\r",
			    an, print_ch(49-strlen(an),'.'));
	    break;
	case 1: if (isPatternLine(line)) continue;
	    if (area->hide) {
		i = config->echoAreaCount;
		break;
	    }
	    xscatprintf(&report, " %s %s  not linked\r",
			an, print_ch(49-strlen(an), '.'));
	    w_log('8', "areafix: area %s is not linked to %s",
		  area->areaName, aka2str(link->hisAka));
	    break;
	case 5: 
	    xscatprintf(&report, " %s %s  unlink is not possible\r",
			an, print_ch(49-strlen(an), '.'));
	    w_log('8', "areafix: area %s -- unlink is not possible for %s",
		  area->areaName, aka2str(link->hisAka));
	    break;
	default:
	    break;
	}
    }
    report = af_Req2Idle(line, report, link->hisAka);
    if (report == NULL) {
        if (isPatternLine(line)) {
            xscatprintf(&report, " %s %s  no areas to unlink\r",
                line, print_ch(49-strlen(line), '.'));
            w_log('8', "areafix: no areas to unlink");
        } else {
            xscatprintf(&report, " %s %s  not found\r",
                line, print_ch(49-strlen(line), '.'));
            w_log('8', "areafix: area %s is not found", line);
        }
    }
    return report;
}

int changepause(char *confName, s_link *link, int opt)
{
    // opt = 0 - AreaFix
    // opt = 1 - AutoPause
    char *cfgline, *token;
    char *line;
    long curpos, endpos, cfglen;
    FILE *f_conf;
    
    if (init_conf(confName))
	return 0;

    while ((cfgline = configline()) != NULL) {
	cfgline = trimLine(cfgline);
	cfgline = stripComment(cfgline);
	cfgline = shell_expand(cfgline);
	cfgline = vars_expand(cfgline);
	line = cfgline;
	token = strseparate(&line, " \t");
	if (token && stricmp(token, "link") == 0) {
linkline:
	    nfree(cfgline);
	    for (;;) {
		if ((cfgline = configline()) == NULL) { 
		    close_conf();
		    return 0;
		}
		cfgline = trimLine(cfgline);
		cfgline = stripComment(cfgline);
		cfgline = shell_expand(cfgline);
		cfgline = vars_expand(cfgline);
		if (!*cfgline) {
		    nfree(cfgline);
		    continue;
		}
		line = cfgline;
		token = strseparate(&line, " \t");
		if (!token) {
		    nfree(cfgline);
		    continue;
		}
		if (stricmp(token, "link") == 0)
		    goto linkline;
		if (stricmp(token, "aka") == 0) break;
		nfree(cfgline);
	    }
	    token = strseparate(&line, " \t");
	    if (token && testAddr(token, link->hisAka)) {
		nfree(cfgline);
		//curpos = ftell(hcfg);
		curpos = get_hcfgPos();
		confName = safe_strdup(getCurConfName());
		close_conf();
		f_conf = fopen(confName, "r+b");
		if (f_conf == NULL) {
		    fprintf(stderr,"%s: cannot open config file %s \n", opt ? "autopause" : "areafix", confName);
		    nfree(confName);
		    return 0;
		}
		nfree(confName);
		fseek(f_conf, 0L, SEEK_END);
		endpos = ftell(f_conf);

		cfglen=endpos-curpos;

		line = (char*) safe_malloc((size_t) cfglen+1);
		fseek(f_conf, curpos, SEEK_SET);
		cfglen = fread(line, sizeof(char), cfglen, f_conf);
		line[cfglen]='\0';

		fseek(f_conf, curpos, SEEK_SET);
		fprintf(f_conf, "Pause%s%s", cfgEol(), line);
		fclose(f_conf);
		nfree(line);
		link->Pause = 1;
		w_log('8', "%s: system %s set passive", opt ? "autopause" : "areafix", aka2str(link->hisAka));
		return 1;
	    }
	}
	nfree(cfgline);
    }
    close_conf();
    return 0;
}

char *pause_link(s_link *link)
{
    char *tmp, *report = NULL;
    
    if (link->Pause == 0) {
	if (changepause((cfgFile) ? cfgFile : getConfigFileName(), link, 0) == 0)
	    return NULL;
    }

    xstrcat(&report, " System switched to passive\r");
    tmp = linked (link);
    xstrcat(&report, tmp);
    nfree(tmp);

    return report;
}

int changeresume(char *confName, s_link *link)
{
    char *cfgline, *token;
    char *line;
    long curpos, endpos, cfglen, remstr;
    FILE *f_conf;
    
    if (init_conf(confName))
	return 0;

    while ((cfgline = configline()) != NULL) {
	cfgline = trimLine(cfgline);
	cfgline = stripComment(cfgline);
	cfgline = shell_expand(cfgline);
	cfgline = vars_expand(cfgline);
	line = cfgline;
	token = strseparate(&line, " \t");
	if (!token || stricmp(token, "link")) {
	    nfree(cfgline);
	    continue;
	}
linkliner:
	nfree(cfgline);
	for (;;) {
	    if ((cfgline = configline()) == NULL) { 
		close_conf();
		return 0;
	    }
	    cfgline = trimLine(cfgline);
	    cfgline = stripComment(cfgline);
	    cfgline = shell_expand(cfgline);
	    cfgline = vars_expand(cfgline);
	    if (!*cfgline) {
		nfree(cfgline);
		continue;
	    }
	    line = cfgline;
	    token = strseparate(&line, " \t");
	    if (!token) {
		nfree(cfgline);
		continue;
	    }
	    if (stricmp(token, "link") == 0)
		goto linkliner;
	    if (stricmp(token, "aka") == 0) break;
	    nfree(cfgline);
	}
	token = strseparate(&line, " \t");
	if (!token || testAddr(token, link->hisAka) == 0) {
	    nfree(cfgline);
	    continue;
	}
	nfree(cfgline);
	for (;;) {
	    if ((cfgline = configline()) == NULL) { 
		close_conf();
		return 0;
	    }
	    cfgline = trimLine(cfgline);
	    cfgline = stripComment(cfgline);
	    cfgline = shell_expand(cfgline);
	    cfgline = vars_expand(cfgline);
	    if (!*cfgline) {
		nfree(cfgline);
		continue;
	    }
	    line = cfgline;
	    token = strseparate(&line, " \t");
	    if (token && stricmp(token, "link") == 0)
		goto linkliner;
	    if (token && stricmp(token, "pause") == 0) break;
	    nfree(cfgline);
	}
	// remove line
	nfree(cfgline);
	//remstr = ftell(hcfg);
	remstr = get_hcfgPos();
	curpos = getCurConfPos();
	confName = safe_strdup(getCurConfName());
	close_conf();
	if ((f_conf=fopen(confName,"r+")) == NULL)
	    {
		fprintf(stderr,"areafix: cannot open config file %s \n", confName);
		nfree(confName);
		return 0;
	    }
	fseek(f_conf, 0, SEEK_END);
	endpos = ftell(f_conf);
	cfglen=endpos-remstr;

	line = (char*) safe_malloc((size_t) cfglen+1);
	fseek(f_conf, remstr, SEEK_SET);
	cfglen = fread(line, sizeof(char), (size_t) cfglen, f_conf);
				
	fseek(f_conf, curpos, SEEK_SET);
	fwrite(line, sizeof(char), (size_t) cfglen, f_conf);
// remove after 15-03-2002
//#if defined(__WATCOMC__) || defined(__MINGW32__)
//	fflush( f_conf );
//	fTruncate( fileno(f_conf), endpos-(remstr-curpos) );
//	fflush( f_conf );
//#else
//	truncate(confName, endpos-(remstr-curpos));
//#endif
	setfsize( fileno(f_conf), endpos-(remstr-curpos) );
	nfree(line);
	nfree(confName);
	link->Pause = 0;
	w_log('8', "areafix: system %s set active",	aka2str(link->hisAka));
	return 1;
    }
    close_conf();
    return 0;
}

char *resume_link(s_link *link)
{
    char *tmp, *report = NULL;
    
    if (link->Pause) {
	if (changeresume((cfgFile) ? cfgFile : getConfigFileName(), link) == 0)
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
	unsigned int i;
    
    sprintf(linkAka,aka2str(link->hisAka));
    xscatprintf(&report, "Here is some information about our link:\r\r %s%s\r%s%s\r  %s", hisAddr, linkAka, ourAddr, aka2str(*link->ourAka), Arch);
    
    if (link->packerDef==NULL) 
	xscatprintf(&report, "No packer (");
    else
	xscatprintf(&report, "%s (", link->packerDef->packer);
    
    for (i=0; i < config->packCount; i++)
	xscatprintf(&report, "%s%s", config->pack[i].packer,
		    (i+1 == config->packCount) ? "" : ", ");
    
    xscatprintf(&report, ")\r\rYour system is %s\r", link->Pause?"passive":"active");
    ptr = linked (link);
    xstrcat(&report, ptr);
    nfree(ptr);
    w_log('8', "areafix: link information sent to %s", aka2str(link->hisAka));
    return report;
}

int repackEMMsg(HMSG hmsg, XMSG xmsg, s_area *echo, s_arealink *arealink)
{
   s_message    msg;
   UINT32       j=0;
   s_seenBy     *seenBys = NULL, *path = NULL;
   UINT         seenByCount = 0, pathCount = 0;
   s_arealink   **links;

   links = (s_arealink **) scalloc(2, sizeof(s_arealink*));
   if (links==NULL) exit_hpt("out of memory",1);
   links[0] = arealink;
   
   makeMsg(hmsg, xmsg, &msg, echo, 1);

   //translating name of the area to uppercase
   while (msg.text[j] != '\r') {msg.text[j]=(char)toupper(msg.text[j]);j++;}

   if (strncmp(msg.text+j+1,"NOECHO",6)==0) {
       freeMsgBuffers(&msg);
       nfree(links);
       return 0;
   }

   createSeenByArrayFromMsg(echo, &msg, &seenBys, &seenByCount);
   createPathArrayFromMsg(&msg, &path, &pathCount);

   forwardToLinks(&msg, echo, links, &seenBys, &seenByCount, &path, &pathCount);

   // mark msg as sent and scanned
   xmsg.attr |= MSGSENT;
   xmsg.attr |= MSGSCANNED;
   MsgWriteMsg(hmsg, 0, &xmsg, NULL, 0, 0, 0, NULL);

   freeMsgBuffers(&msg);
   nfree(links);
   nfree(seenBys);
   nfree(path);

   return 1;
}

int rescanEMArea(s_area *echo, s_arealink *arealink, long rescanCount)
{
   HAREA area;
   HMSG  hmsg;
   XMSG  xmsg;
   dword highestMsg, i;
   unsigned int rc=0;

   area = MsgOpenArea((UCHAR *) echo->fileName, MSGAREA_NORMAL, /*echo -> fperm, 
   echo -> uid, echo -> gid,*/ (word)(echo->msgbType | MSGTYPE_ECHO));
   if (area != NULL) {
       //      i = highWaterMark = MsgGetHighWater(area);
       i = 0;
       highestMsg    = MsgGetHighMsg(area);

       // if rescanCount == -1 all mails should be rescanned
       if ((rescanCount == -1) || (rescanCount > (long)highestMsg))
	   rescanCount = highestMsg;

       while (i <= highestMsg) {
	   if (i > highestMsg - rescanCount) { // honour rescanCount paramater
	       hmsg = MsgOpenMsg(area, MOPEN_RW, i);
	       if (hmsg != NULL) {     // msg# does not exist
		   MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
		   rc += repackEMMsg(hmsg, xmsg, echo, arealink);
		   MsgCloseMsg(hmsg);
	       }
	   }
	   i++;
       }

       MsgSetHighWater(area, i);

       MsgCloseArea(area);
      
   } else w_log('9', "Could not open %s", echo->fileName);

   return rc;
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
    while (*countstr && (!isspace(*countstr))) countstr++; // skip areatag
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
		w_log('8', "areafix: %s area no rescan possible to %s",
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
		    w_log('8', "areafix: %s -- no access to export for %s",
			  an, aka2str(link->hisAka));
		}
		xscatprintf(&report," %s %s  rescanned %lu mails\r",
			    an, print_ch(49-strlen(an), '.'), rcc);
		w_log('8',"areafix: %s rescanned %lu mails to %s",
		      an, rcc, aka2str(link->hisAka));
	    }
	    break;
	case 1: if (isPatternLine(line)) continue;
	    w_log('8', "areafix: %s area not linked for rescan to %s",
		  area->areaName, aka2str(link->hisAka));
	    xscatprintf(&report, " %s %s  not linked for rescan\r",
			an, print_ch(49-strlen(an), '.'));
	    break;
	default: w_log('8', "areafix: %s area not access for %s",
		       area->areaName, aka2str(link->hisAka));
	    break;
	}
    }
    if (report == NULL) {
	xscatprintf(&report," %s %s  not linked for rescan\r",
		    line, print_ch(49-strlen(line), '.'));
	w_log('8', "areafix: %s area not linked for rescan", line);
    }
    return report;
}

char *add_rescan(s_link *link, char *line) {
    char *report=NULL, *line2=NULL, *p;

    if (*line=='+') line++; while (*line==' ') line++;

    p = hpt_stristr(line, " /R");
    *p = '\0';

    report = subscribe (link, line);
    *p = ' ';

    xstrscat(&line2,"%rescan ", line, NULL);
    xstrcat(&report, rescan(link, line2));
    nfree(line2);
    *p = '\0';
    
    return report;
}

int tellcmd(char *cmd) {
    char *line;

    if (strncmp(cmd, "* Origin:", 9) == 0) return NOTHING;

    line = cmd;
    if (line && *line && (line[1]==' ' || line[1]=='\t')) return ERROR;

    switch (line[0]) {
    case '%': 
	line++;
	if (*line == '\000') return ERROR;
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
	if (strncasecmp(line, "rescan", 6)==0) {
	    if (line[6] == '\0') {
		rescanMode=1;
		return NOTHING;
	    } else {
		return RESCAN;
	    }
	}
	return ERROR;
    case '\001': return NOTHING;
    case '\000': return NOTHING;
    case '-'  :
	if (line[1]=='-' && line[2]=='-') return DONE;
	if (line[1]=='\000') return ERROR;
	if (strchr(line,' ') || strchr(line,'\t')) return ERROR;
	return DEL;
    case '~'  : return REMOVE;
    case '+':
	if (line[1]=='\000') return ERROR;
    default:
	if (hpt_stristr(line, " /R")!=NULL) return ADD_RSC; // add & rescan
	return ADD;
    }
//	return 0; - Unreachable
}

char *processcmd(s_link *link, char *line, int cmd) {
	
    char *report;

    w_log(LL_FUNC,"areafix.c::processcmd()");

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
    case INFO: report = info_link(link);
	RetFix=INFO;
	break;
    case RESCAN: report = rescan(link, line);
	RetFix=STAT;
	break;
    case ADD_RSC: report = add_rescan(link, line);
	RetFix=STAT;
	break;
    case ERROR: report = errorRQ(line);
	RetFix=STAT;
	break;
    default: return NULL;
    }
    w_log(LL_FUNC,"areafix.c::processcmd() OK");
    return report;
}

void preprocText(char *split, s_message *msg)
{
    char *orig = (config->areafixOrigin) ? config->areafixOrigin : config->origin;

    msg->text = createKludges(NULL, &msg->origAddr, &msg->destAddr);
    xscatprintf(&split, "\r--- %s areafix\r", versionStr);
    if (orig) {
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
    char *tab = config->intab, *text, *split, *p, *newsubj = NULL;
    char splitted[]=" > message splitted...";
    char *splitStr = config->areafixSplitStr;
    int len, msgsize = config->areafixMsgSize * 1024, partnum=0;
    s_message *tmpmsg;

    config->intab = NULL;

    text = report;

    while (text) {

	len = strlen(text);
	if (msgsize == 0 || len <= msgsize) {
	    split = text;
	    text = NULL;
	    if (partnum) { /* last part of splitted msg */
		partnum++;
		xstrcat(&text,split);
		split = text;
		text = NULL;
		nfree(report);
	    }
	} else {
	    p = text + msgsize;
	    while (*p != '\r') p--;
	    *p = '\000';
	    len = p - text;
	    split = (char*)safe_malloc(len+strlen(splitStr ? splitStr : splitted)+3+1);
	    memcpy(split,text,len);
	    strcpy(split+len,"\r\r");
	    strcat(split, (splitStr) ? splitStr : splitted);
	    strcat(split,"\r");
	    text = p+1;
	    partnum++;
	}

	if (partnum) xscatprintf(&newsubj, "%s (%d)", subj, partnum);
	else newsubj = subj;

	tmpmsg = makeMessage(link->ourAka, &(link->hisAka),
			     msg->toUserName,
			     msg->fromUserName, newsubj, 1);

	preprocText(split, tmpmsg);
	processNMMsg(tmpmsg, NULL, getNetMailArea(config,config->robotsArea),
		     0, MSGLOCAL);

	freeMsgBuffers(tmpmsg);
	nfree(tmpmsg);
	if (partnum) nfree(newsubj);
    }

    config->intab = tab;
}

void RetRules (s_message *msg, s_link *link, char *areaName)
{
    FILE *f;
    char *fileName = NULL, *fn, *fn1;
    char *text, *subj=NULL;
    long len;
    s_area *area;
    int nrul;


    if ((area=getArea(config, areaName)) == &(config->badArea)) {
	w_log('9', "areafix: can't find area '%s'", areaName);
	return;
    }

    if (area->fileName) {
	fn = area->fileName;
	for (fn1 = fn; *fn1; fn1++) if (*fn1=='/' || *fn1=='\\') fn = fn1+1;
	xscatprintf(&fileName, "%s%s.rul", config->rulesDir, fn);
    } else {
	fn = makeMsgbFileName(area->areaName);
	xscatprintf(&fileName, "%s%s.rul", config->rulesDir, fn);
	nfree (fn); // allocated by makeMsgbFileName()
    }

    for (nrul=0; nrul<=9 && (f = fopen (fileName, "rb")); nrul++) {

	len = fsize (fileName);
	text = safe_malloc (len+1);
	fread (text, len, 1, f);
	fclose (f);

	text[len] = '\0';

	if (nrul==0) {
	    xscatprintf(&subj, "Rules of %s", areaName);
	    w_log('7', "areafix: send '%s' as rules for area '%s'",
		  fileName, areaName);
	} else {
	    xscatprintf(&subj, "Echo related text #%d of %s", nrul, areaName);
	    w_log('7', "areafix: send '%s' as text %d for area '%s'",
		  fileName, nrul, areaName);
	}

	RetMsg(msg, link, text, subj);

	nfree (subj);
	nfree (text);

	fileName[strlen(fileName)-1] = nrul+'1';
    }

    if (nrul==0) { // couldn't open any rules file while first one exists!
	w_log('9', "areafix: can't open file '%s' for reading", fileName);
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
        
        w_log('8', "areafix: write netmail msg for %s", aka2str(link->hisAka));
        
        processNMMsg(linkmsg, NULL, getNetMailArea(config,config->robotsArea),
            0, MSGLOCAL);
        
        freeMsgBuffers(linkmsg);
        nfree(linkmsg);
        link->msg = NULL;
    }
    
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

int processAreaFix(s_message *msg, s_pktHeader *pktHeader, unsigned force_pwd)
{
    unsigned int security=1, notforme = 0;
    s_link *link = NULL;
    s_link *tmplink = NULL;
    //s_message *linkmsg;
    s_pktHeader header;
    char *token, *textBuff, *report=NULL, *preport = NULL;
    int nr;

    w_log(LL_FUNC, "areafix.c::processAreaFix()");

    RetFix = NOTHING;

    // 1st security check
    if (pktHeader) security=addrComp(msg->origAddr, pktHeader->origAddr);
    else {
	makePktHeader(NULL, &header);
	pktHeader = &header;
	pktHeader->origAddr = msg->origAddr;
	pktHeader->destAddr = msg->destAddr;
	security = 0;
    }

    if (security) security=1; /* different pkt and msg addresses */

    // find link
    link=getLinkFromAddr(config, msg->origAddr);

    // if keyword allowPktAddrDiffer for this link is on,
    // we allow the addresses in PKT and MSG header differ
    if (link!=NULL)
	if (link->allowPktAddrDiffer == pdOn)
	    security = 0;  /* OK */

    // this is for me?
    if (link!=NULL)	notforme=addrComp(msg->destAddr, *link->ourAka);
    else if (!security) security=4; // link == NULL; /* unknown system */
	
    // ignore msg for other link (maybe this is transit...)
    if (notforme || (link==NULL && security==1)) {
        w_log(LL_FUNC, "areafix.c::processAreaFix() call processNMMsg() and return");
	return processNMMsg(msg, pktHeader, NULL, 0, 0);
    }

    // 2nd security check. link, areafixing & password.
    if (!security && !force_pwd) {
	if (link->AreaFix==1) {
	    if (link->areaFixPwd!=NULL) {
		if (stricmp(link->areaFixPwd,msg->subjectLine)==0) security=0;
		else security=3; /* password error */
	    }
	} else security=2; /* areafix is turned off */
    }

    if (!security) {
	textBuff = msg->text;
	token = strseparate (&textBuff, "\n\r");
	while(token != NULL) {
	    while ((*token == ' ') || (*token == '\t')) token++;
	    while(isspace(token[strlen(token)-1])) token[strlen(token)-1]='\0';
	    preport = processcmd( link, token, tellcmd (token) );
	    if (preport != NULL) {
		switch (RetFix) {
		case LIST:
		    RetMsg(msg, link, preport, "areafix reply: list request");
		    break;
		case HELP:
		    RetMsg(msg, link, preport, "areafix reply: help request");
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
		    RetMsg(msg, link, preport, "areafix reply: available areas");
		    break;
		case UNLINK:
		    RetMsg(msg, link, preport, "areafix reply: unlinked request");
		    break;
		case QUERY:
		    RetMsg(msg, link, preport, "areafix reply: linked request");
		    break;
		case PAUSE:
		    RetMsg(msg, link, preport, "areafix reply: node change request");
		    break;
		case RESUME:
		    RetMsg(msg, link, preport, "areafix reply: node change request");
		    break;
		case INFO:
		    RetMsg(msg, link, preport, "areafix reply: link information");
		    break;
		case STAT:
		    report = areaStatus(report, preport);
		    break;
		default: break;
		}
	    } /* end if (preport != NULL) */
	    token = strseparate (&textBuff, "\n\r");
	    if (RetFix==DONE) token=NULL;
	} /* end while (token != NULL) */
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
	// security problem
		
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
	default:
	    xscatprintf(&report, " \r unknown error. mail to sysop.\r");
	    break;
	}

	RetMsg(msg, link, report, "areafix reply: security violation");
	w_log('8', "areafix: security violation from %s", aka2str(link->hisAka));
	nfree(tmplink);
        w_log(LL_FUNC, "areafix.c::processAreaFix() rc=1");
	return 1;
    }

    if ( report != NULL ) {
	if (config->areafixQueryReports) {
	    preport = linked (link);
	    xstrcat(&report, preport);
	    nfree(preport);
	}
	RetMsg(msg, link, report, "areafix reply: node change request");
    }

    if (rulesCount) {
	for (nr=0; nr < rulesCount; nr++) {
	    RetRules (msg, link, rulesList[nr]);
	    nfree (rulesList[nr]);
	}
	nfree (rulesList);
    }

    w_log('8', "areafix: sucessfully done for %s",aka2str(link->hisAka));

    // send msg to the links (forward requests to areafix)
    sendAreafixMessages();
    w_log(LL_FUNC, "areafix.c::processAreaFix() rc=1");
    return 1;
}

void MsgToStruct(HMSG SQmsg, XMSG xmsg, s_message *msg)
{
    // convert header
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

void afix(s_addr addr, char *cmd)
{
    HAREA           netmail;
    HMSG            SQmsg;
    unsigned long   highmsg, i;
    XMSG            xmsg;
    s_addr          dest;
    s_message	    msg, *tmpmsg;
    int             k, startarea = 0, endarea = config->netMailAreaCount;
    s_area          *area;
    char            *name = config->robotsArea;
    s_link          *link;

    w_log(LL_INFO, "Start AreaFix...");

    if ((area = getNetMailArea(config, name)) != NULL) {
	startarea = area - config->netMailAreas;
	endarea = startarea + 1;
    }

    if (cmd) {
	link = getLinkFromAddr(config, addr);
	if (link) {
	    tmpmsg = makeMessage(&addr, link->ourAka, link->name,
				 link->RemoteRobotName ?
				 link->RemoteRobotName : "Areafix",
				 link->areaFixPwd ?
				 link->areaFixPwd : "", 1);
	    tmpmsg->text = cmd;
	    processAreaFix(tmpmsg, NULL, 1);
	    tmpmsg->text=NULL;
	    freeMsgBuffers(tmpmsg);
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

	    // scan all Messages and test if they are already sent.
	    for (i=1; i<= highmsg; i++) {
		SQmsg = MsgOpenMsg(netmail, MOPEN_RW, i);

		// msg does not exist
		if (SQmsg == NULL) continue;

		MsgReadMsg(SQmsg, &xmsg, 0, 0, NULL, 0, NULL);
		cvtAddr(xmsg.dest, &dest);
                
		// if not read and for us -> process AreaFix
		striptwhite((char*)xmsg.to);
		if (((xmsg.attr & MSGREAD) != MSGREAD) && 
		    (isOurAka(config,dest)) && (strlen(xmsg.to)>0) &&
		    ((stricmp((char*)xmsg.to, "areafix")==0) ||
		     (stricmp((char*)xmsg.to, "areamgr")==0) ||
		     (stricmp((char*)xmsg.to, "hpt")==0) ||
		     hpt_stristr(config->areafixNames,(char*)xmsg.to))) {
		    memset(&msg,'\0',sizeof(s_message));
		    MsgToStruct(SQmsg, xmsg, &msg);
		    processAreaFix(&msg, NULL, 0);
		    if (config->areafixKillRequests) {
			MsgCloseMsg(SQmsg);
			MsgKillMsg(netmail, i);
		    } else {
			xmsg.attr |= MSGREAD;
			MsgWriteMsg(SQmsg, 0, &xmsg, NULL, 0, 0, 0, NULL);
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
}

int unsubscribeFromPausedEchoAreas(s_link *link) {
    unsigned i,j;
    char *text = NULL;
    s_area *area;
    s_message *tmpmsg;

    for (i=0; i<config->echoAreaCount; i++) {
	area = &(config->echoAreas[i]);

	if ((area->msgbType & MSGTYPE_PASSTHROUGH) && isLinkOfArea(link,area)) {

	    // unsubscribe only if uplink & auto-paused downlink presents
	    if (area->downlinkCount==2) {
		if ((j = isAreaLink(link->hisAka, area)) != -1) {
		    // don't touch mandatory links
		    if (area->downlinks[j]->mandatory) continue;
		    // add area for unsubscribe
		    xstrscat(&text,"-",area->areaName,"\r",NULL);
		}
	    }
	}
    }

    if (text) {
	tmpmsg = makeMessage(&(link->hisAka), link->ourAka, link->name,
			     "areafix", link->areaFixPwd, 1);
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

      if (config->links[i].autoPause==0 || config->links[i].Pause) continue;

      if (createOutboundFileName(&(config->links[i]),
				 cvtFlavour2Prio(config->links[i].echoMailFlavour),
				 FLOFILE) == 0) {
	  f = fopen(config->links[i].floFile, "rt");
	  if (f) {
	      while ((line = readLine(f)) != NULL) {
		  line = trimLine(line);
		  path = line;
		  if (!isarcmail(path)) {
		      nfree(line);
		      continue;
		  }
		  if (*path && (*path == '^' || *path == '#')) {
		      path++;
		      // set Pause if files stored only in outbound
		      if (*path && strncmp(config->outbound,path,strlen(config->outbound)-1)==0 && stat(path, &stat_file) != -1) {

			  time_cur = time(NULL);
			  if (time_cur > stat_file.st_mtime) {
			      time_test = (time_cur - stat_file.st_mtime)/3600;
			  } else { // buggly time on file, anyway don't autopause on it
			      time_test = 0;
			  }

			  if (time_test >= (time_t)(config->links[i].autoPause*24)) {
			      w_log('8', "autopause: the file %s is %d days old", path, time_test/24);
			      if (changepause((cfgFile) ? cfgFile :
					      getConfigFileName(),
					      &(config->links[i]), 1)) {    
				  msg = makeMessage(config->links[i].ourAka,
						    &(config->links[i].hisAka),
						    versionStr,config->links[i].name,
						    "AutoPassive", 1);
				  msg->text = createKludges(NULL,
							    config->links[i].ourAka,
							    &(config->links[i].hisAka));
				  xstrcat(&msg->text, "\r System switched to passive\r\r You are being unsubscribed from echo areas with no downlinks besides you!\r\r When you wish to continue receiving arcmail, please send request to AreaFix\r containing the \r %RESUME command.");
				  xscatprintf(&msg->text, "\r\r--- %s autopause\r", versionStr);
				  msg->textLength = strlen(msg->text);
				  processNMMsg(msg, NULL,
					       getNetMailArea(config,config->robotsArea),
					       0, MSGLOCAL);
				  freeMsgBuffers(msg);
				  nfree(msg);

				  // unsubscribe link from areas without non-paused links
				  unsubscribeFromPausedEchoAreas(&(config->links[i]));
			      } // end changepause
			      nfree(line);
			      //fclose(f); file closed after endwhile
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

    // parse config
    if (config==NULL) processConfig();
    if ( initSMAPI == -1 ) {
	// init SMAPI
	initSMAPI = 0;
	m.req_version = 0;
	m.def_zone = (UINT16) config->addr[0].zone;
	if (MsgOpenApi(&m) != 0) {
	    exit_hpt("MsgApiOpen Error",1);
	}
    }

    w_log('1', "Start relink...");

    if (straddr) researchLink = getLink(config, straddr);
    else {
	w_log('9', "No address");
	return 1;
    }

    if ( researchLink == NULL ) {
	w_log('9', "Unknown link address %s", straddr);
	return 1;
    }

    areasArraySize = 0;
    areasIndexArray = (s_area **) safe_malloc
	(sizeof(s_area *) * (config->echoAreaCount + config->localAreaCount + 1));

    for (count = 0; count < config->echoAreaCount; count++)
	if ( isLinkOfArea(researchLink, &config->echoAreas[count])) {
	    areasIndexArray[areasArraySize] = &config->echoAreas[count];
	    areasArraySize++;
	    w_log('8', "Echo %s from link %s refreshed",
		  config->echoAreas[count].areaName, aka2str(researchLink->hisAka));
	}

    if ( areasArraySize > 0 ) {
	s_message *msg;

	msg = makeMessage(researchLink->ourAka,
			  &researchLink->hisAka,
			  versionStr,
			  researchLink->RemoteRobotName ?
			  researchLink->RemoteRobotName : "areafix",
			  researchLink->areaFixPwd ? researchLink->areaFixPwd : "", 1);

	msg->text = createKludges( NULL,researchLink->ourAka,&researchLink->hisAka);

	for ( count = 0 ; count < areasArraySize; count++ ) {
	    if ((areasIndexArray[count]->downlinkCount  <= 1) &&
		(areasIndexArray[count]->msgbType & MSGTYPE_PASSTHROUGH))
		xscatprintf(&(msg->text), "-%s\r",areasIndexArray[count]->areaName);
	    else
		xscatprintf(&(msg->text), "+%s\r",areasIndexArray[count]->areaName);
	}

	xscatprintf(&(msg->text), " \r--- %s areafix\r", versionStr);
	msg->textLength = strlen(msg->text);
	w_log('8', "'Refresh' message created to `%s`",
	      researchLink->RemoteRobotName ?
	      researchLink->RemoteRobotName : "areafix");
	processNMMsg(msg, NULL,
		     getNetMailArea(config,config->robotsArea),
		     1, MSGLOCAL|MSGKILL);
	freeMsgBuffers(msg);
	nfree(msg);
	w_log('8', "Total request relink %i area(s)",areasArraySize);
    }

    nfree(areasIndexArray);

    return 0;
}
