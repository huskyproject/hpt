/*****************************************************************************
 * AreaFix for HPT (FTN NetMail/EchoMail Tosser)
 *****************************************************************************
 * Copyright (C) 1998-2000
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
#include <strsep.h>
#include <seenby.h>
#include <scan.h>
#include <recode.h>
#include <areafix.h>
#include <scanarea.h>
#include <arealist.h>
#include <hpt.h>

extern char *curconfname;
extern long curconfpos;
extern FILE *hcfg;

unsigned char RetFix;

int strncasesearch(char *strL, char *strR, int len)
{
    char *str;
    int ret;
    
    str = (char*) safe_malloc(strlen(strL)+1);
    strcpy(str, strL);
    if (strlen(str) > len) str[len] = '\0';
    ret = stricmp(str, strR);
    nfree(str);
    return ret;
}

char *print_ch(int len, char ch)
{
    static char tmp[256];

	if (len <= 0 || len > 255) return "";
    
    memset(tmp, ch, len);
    tmp[len]=0;
    return tmp;
}

int mandatoryCheck(s_area area, s_link *link) {
    int i;

    if (grpInArray(area.group,link->optGrp,link->numOptGrp) && link->mandatory) return 1;
    if (link->numOptGrp==0 && link->mandatory) return 1;
    if (area.mandatory) return 1;
    for (i = 0; i < area.downlinkCount; i++)
	if (area.downlinks[i]->link==link) return area.downlinks[i]->mandatory;
    return 0;
}

int subscribeCheck(s_area area, s_message *msg, s_link *link)
{
  int i;
  int found = 0;

  for (i = 0; i<area.downlinkCount;i++) {
    if (addrComp(msg->origAddr, area.downlinks[i]->link->hisAka)==0) return 0;
  }

  if (strcmp(area.group, "0")) {
	  if (config->numPublicGroup)
		  found = grpInArray(area.group,config->PublicGroup,config->numPublicGroup);
	  if (!found && link->numAccessGrp) 
		  found = grpInArray(area.group,link->AccessGrp,link->numAccessGrp);
  } else found = 1;

  if (!found) return 2;
  if (area.levelwrite > link->level && area.levelread > link->level) return 2;
  return 1;
}

int subscribeAreaCheck(s_area *area, s_message *msg, char *areaname, s_link *link) {
	int rc=4;
	
	if (!areaname) return rc;
	
	if (patimat(area->areaName,areaname)==1) {
		rc=subscribeCheck(*area, msg, link);
		// 0 - already subscribed / linked
		// 1 - need subscribe / not linked
		// 2 - no access
	} else rc = 4;
	
	// this is another area
	return rc;
}

// del link from area
int delLinkFromArea(FILE *f, char *fileName, char *str) {
    long curpos, endpos, linelen=0, len;
    char *buff, *sbuff, *ptr, *tmp, *line;
	
    curpos = ftell(f);
    buff = readLine(f);
    buff = trimLine(buff);
    len = strlen(buff);

	sbuff = buff;

	while ( (ptr = strstr(sbuff, str)) != NULL ) {
		if (isspace(ptr[strlen(str)]) || ptr[strlen(str)]=='\000') break;
		sbuff = ptr+1;
	}
	
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
		if (strncasesearch(ptr, "-r", 2)) {
		    if (strncasesearch(ptr, "-w", 2)) {
			if (strncasesearch(ptr, "-mn", 3)) {
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
    return 0;
}

// add string to file
int addstring(FILE *f, char *aka) {
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
	fputs(" ",f);
	fputs(aka,f);
	fwrite(cfg,sizeof(char),(size_t) len,f);
	fflush(f);
	
	nfree(cfg);
	return 0;
}

void addlink(s_link *link, s_area *area) {
    s_arealink *arealink;
    
    area->downlinks = safe_realloc(area->downlinks, sizeof(s_arealink*)*(area->downlinkCount+1));
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

void removelink(s_link *link, s_area *area) {
	int i;
	s_link *links;

	for (i=0; i < area->downlinkCount; i++) {
           links = area->downlinks[i]->link;
           if (addrComp(link->hisAka, links->hisAka)==0) break;
	}
	
	nfree(area->downlinks[i]);
	area->downlinks[i] = area->downlinks[area->downlinkCount-1];
	area->downlinkCount--;
}

s_message *makeMessage(s_addr *origAddr, s_addr *destAddr, char *fromName, char *toName, char *subject, int netmail)
{
    // netmail == 0 - echomail
    // netmail == 1 - netmail
    time_t time_cur;
    s_message *msg;

    if (toName == NULL) toName = "Sysop";
    
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


char *list(s_message *msg, s_link *link) {
	
	int i, active, avail, rc = 0;
	char *report = NULL;
	char *list = NULL;
	ps_arealist al;
	s_area area;

	xscatprintf(&report, "Available areas for %s\r\r", aka2str(link->hisAka));

	al = newAreaList();
	for (i=active=avail=0; i< config->echoAreaCount; i++) {
		
	    area = config->echoAreas[i];

	    rc=subscribeCheck(area, msg, link);
	    if (rc < 2 && !area.hide) { /* add line */

			addAreaListItem(al,rc==0,area.areaName,area.description);

			if (rc==0) active++; avail++;

	    } /* end add line */

	} /* end for */
	sortAreaList(al);
	list = formatAreaList(al,78," *");
	xstrcat(&report,list);
	free(list);
	freeAreaList(al);
	
	xscatprintf(&report, "\r'*' = area active for %s\r%i areas available, %i areas active\r", 
			aka2str(link->hisAka), avail, active);
	
	writeLogEntry(hpt_log, '8', "areafix: list sent to %s", aka2str(link->hisAka));

	return report;
}

char *linked(s_message *msg, s_link *link)
{
    int i, n, rc;
    char *report = NULL;

    xscatprintf(&report, "\r%s areas on %s\r\r", 
		    link->Pause ? "Passive" : "Active", aka2str(link->hisAka));
							
    for (i=n=0; i<config->echoAreaCount; i++) {
	rc=subscribeCheck(config->echoAreas[i], msg, link);
	if (rc==0) {
	    xscatprintf(&report, " %s\r", config->echoAreas[i].areaName);
	    n++;
	}
    }
    xscatprintf(&report, "\r%u areas linked\r", n);
    writeLogEntry(hpt_log, '8', "areafix: linked areas list sent to %s", aka2str(link->hisAka));
    return report;
}

char *unlinked(s_message *msg, s_link *link)
{
    int i, rc;
    char *report = NULL;
    s_area *areas;
    
    areas=config->echoAreas;
    
    xscatprintf(&report, "Unlinked areas to %s\r\r", 
				aka2str(link->hisAka));
    
    for (i=0; i<config->echoAreaCount; i++) {
		rc=subscribeCheck(areas[i], msg, link);
		if (rc == 1 && !areas[i].hide) {
			xscatprintf(&report, " %s\r", areas[i].areaName);
		}
    }
    writeLogEntry(hpt_log, '8', "areafix: unlinked areas list sent to %s", aka2str(link->hisAka));
	
    return report;
}

char *help(s_link *link) {
	FILE *f;
	int i=1;
	char *help;
	long endpos;

	if (config->areafixhelp!=NULL) {
		if ((f=fopen(config->areafixhelp,"r")) == NULL)
			{
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

		writeLogEntry(hpt_log, '8', "areafix: help sent to %s",link->name);

		return help;
	}

	return NULL;
}

char *available(s_link *link) {
	FILE *f;
	int j=0;
	unsigned int k;
	int found;
	char *report = NULL, *line, *token, *running, linkAka[25];
	s_link *uplink=NULL;
	ps_arealist al;


    for (j = 0; j < config->linkCount; j++) {
		uplink = &(config->links[j]);

		found = 0;
		for (k = 0; k < link->numAccessGrp && uplink->LinkGrp; k++)
		  if (strcmp(link->AccessGrp[k], uplink->LinkGrp) == 0)
		    found = 1;

		if ((uplink->forwardRequestFile!=NULL) &&
		    ((uplink->LinkGrp == NULL) || (found != 0))) {
                   if ((f=fopen(uplink->forwardRequestFile,"r")) == NULL)
				{
					writeLogEntry(hpt_log, '8', "areafix: cannot open forwardRequestFile \"%s\"", uplink->forwardRequestFile);
					return report;
				}

		   	xscatprintf(&report, "Available Area List from %s:\r", aka2str(uplink->hisAka));

		   	al = newAreaList();
			while ((line = readLine(f)) != NULL) {
				line = trimLine(line);
				if (line[0] != '\0') {
			
					running = line;
					token = strseparate(&running, " \t\r\n");

					addAreaListItem(al,0,token,running);

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
			writeLogEntry(hpt_log, '8', "areafix: Available Area List from %s sent to %s", aka2str(uplink->hisAka), linkAka);
		}
	}

	if (report==NULL) {
	    xstrcat(&report, "\r  no links for creating Available Area List\r");
            writeLogEntry(hpt_log, '8', "areafix: no links for creating Available Area List");
	}
	
	return report;
}                                                                               

// subscribe if (act==0),  unsubscribe if (act==1), delete if (act==2)
int forwardRequestToLink (char *areatag, s_link *uplink, s_link *dwlink, int act) {
    s_message *msg;
    char *base, pass[]="passthrough";
    int j;

	if (uplink->msg == NULL) {

	    msg = makeMessage(uplink->ourAka, &(uplink->hisAka), config->sysop, uplink->RemoteRobotName ? uplink->RemoteRobotName : "areafix", uplink->areaFixPwd ? uplink->areaFixPwd : "\x00", 1);

	    msg->text = createKludges(NULL, uplink->ourAka, &(uplink->hisAka));
		
	    uplink->msg = msg;
	    
	} else msg = uplink->msg;
	
	if (act==0) {
	    if (getArea(config, areatag) == &(config->badArea)) {
		base = config->msgBaseDir;
		config->msgBaseDir = pass;
                for (j = 0; j < config->addrCount; j++)
                    if (addrComp(dwlink->hisAka, config->addr[j])==0) {
                       config->msgBaseDir = base;
                       break;
                    }
		strUpper(areatag);
		autoCreate(areatag, uplink->hisAka, &(dwlink->hisAka));
		config->msgBaseDir = base;
	    }
	    xscatprintf(&(msg->text), "+%s\r", areatag);
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

int changeconfig(char *fileName, s_area *area, s_link *link, int action) {
	FILE *f;
	char *cfgline, *token, *areaName, *buff;
	long pos=-1, lastpos, endpos, len;

	areaName = area->areaName;

	if (init_conf(fileName))
		return 1;

	while ((buff = configline()) != NULL) {
		buff = trimLine(buff);
		buff = stripComment(buff);
		if (buff[0] != 0) {
			buff = cfgline = shell_expand(buff);
			token = strseparate(&cfgline, " \t");
			if (stricmp(token, "echoarea")==0) {
				token = strseparate(&cfgline, " \t"); 
				if (stricmp(token, areaName)==0) {
					fileName = safe_strdup(curconfname);
					pos = curconfpos;
					break;
				}
			}
		}
		nfree(buff);
	}
	close_conf();
	if (pos == -1) {
		return 1; // impossible
	}
	nfree(buff);

	if ((f=fopen(fileName,"r+b")) == NULL)
		{
			fprintf(stderr, "areafix: cannot open config file %s \n", fileName);
			nfree(fileName);
			return 1;
		}
	fseek(f, pos, SEEK_SET);
	cfgline = readLine(f);
	if (cfgline == NULL) {
		fclose(f);
		nfree(fileName);
		return 1;
	}

	switch (action) {
	    case 0: 
		if ((area->msgbType==MSGTYPE_PASSTHROUGH)
			&& (area->downlinkCount==1) &&
			(area->downlinks[0]->link->hisAka.point == 0)) {
			forwardRequestToLink(areaName, area->downlinks[0]->link, NULL, 0);
		}
		addstring(f, aka2str(link->hisAka));
		break;
	    case 3: 
		addstring(f, aka2str(link->hisAka));
		break;
 	    case 1:
		fseek(f, pos, SEEK_SET);
		if ((area->msgbType==MSGTYPE_PASSTHROUGH)
			&& (area->downlinkCount==1) &&
			(area->downlinks[0]->link->hisAka.point == 0)) {
		    forwardRequestToLink(areaName, area->downlinks[0]->link, NULL, 1);
		}
		delLinkFromArea(f, fileName, aka2str(link->hisAka));
		break;
	    case 2:
//		makepass(f, fileName, areaName);
		break;
	    case 4: // delete area
		lastpos = ftell(f);
		fseek(f, 0, SEEK_END);
		endpos = ftell(f);
		buff = (char*) safe_malloc((size_t) (endpos-lastpos));
		memset(buff, '\0', (size_t) (endpos-lastpos));
		fseek(f, lastpos, SEEK_SET);
		len = fread(buff, sizeof(char), (size_t) endpos-lastpos, f);
	 	fseek(f, pos, SEEK_SET);
		fwrite(buff, sizeof(char), (size_t) len, f);
		nfree(buff);
#if defined(__WATCOMC__) || defined(__MINGW32__)
		fflush( f );
		fTruncate( fileno(f), pos+len);
		fflush( f );
#else
		truncate(fileName, pos+len);
#endif
		break;
	    default: break;
	}
	nfree(cfgline);
	nfree(fileName);
	fclose(f);
	return 0;
}

int areaIsAvailable(char *areaName, char *fileName, char **desc, int retd) {
	FILE *f;
	char *line, *token, *running;

        if (fileName==NULL || areaName==NULL) return 0;
	
	if ((f=fopen(fileName,"r")) == NULL)
		{
			writeLogEntry(hpt_log,'8',"areafix: cannot open forwardRequestFile \"%s\"",fileName);
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
	if(config->links[ia].forwardAreaPriority > config->links[ib].forwardAreaPriority) return -1;
	else if(config->links[ia].forwardAreaPriority < config->links[ib].forwardAreaPriority) return 1;
	else return 0;
}

int forwardRequest(char *areatag, s_link *dwlink) {
    int i;
    s_link *uplink;
    int *Indexes;
    int Requestable = 0;

    /* From Lev Serebryakov -- sort Links by priority */
    Indexes = safe_malloc(sizeof(int)*config->linkCount);
    for (i = 0; i < config->linkCount; i++) {
		if (config->links[i].forwardRequests) Indexes[Requestable++] = i;
    }
    qsort(Indexes,Requestable,sizeof(Indexes[0]),compare_links_priority);


    for (i = 0; i < Requestable; i++) {
		uplink = &(config->links[Indexes[i]]);
		if (uplink->forwardRequests && (uplink->LinkGrp) ? 
			grpInArray(uplink->LinkGrp, dwlink->AccessGrp,
					   dwlink->numAccessGrp) : 1) {
			
			if (uplink->forwardRequestFile!=NULL) {
				// first try to find the areatag in forwardRequestFile
				if (areaIsAvailable(areatag,uplink->forwardRequestFile,NULL,0)!=0) {
					forwardRequestToLink(areatag,uplink,dwlink,0);
					nfree(Indexes);
					return 0;
				}
			} else {
				forwardRequestToLink(areatag,uplink,dwlink,0);
				nfree(Indexes);
				return 0;
			}
		}
		
    }
	
	// link with "forwardRequests on" not found
	nfree(Indexes);
	return 1;	
}

char *subscribe(s_link *link, s_message *msg, char *cmd) {
	unsigned int i, rc=4, found=0, j, from_us=0;
	char *line, *an, *report = NULL;
	s_area *area;

	line = cmd;
	
	if (line[0]=='+') line++;
	while (*line==' ') line++;
	
	for (i=0; i<config->echoAreaCount; i++) {
	    area = &(config->echoAreas[i]);
	    an = area->areaName;

	    rc=subscribeAreaCheck(area, msg, line, link);
	    if (rc==4) continue;
 		if (rc==1 && mandatoryCheck(*area, link)) rc = 5;

//		writeLogEntry(hpt_log, '8', "areafix: rc = %u",rc);
		switch (rc) {
		case 0: 
			xscatprintf(&report, " %s %s  already linked\r",
						an,	print_ch(49-strlen(an), '.'));
			writeLogEntry(hpt_log, '8', "areafix: %s already linked to %s",
						  aka2str(link->hisAka), an);
		    if (strstr(line, "*") == NULL) i = config->echoAreaCount;
        	break;
		case 1: 
			changeconfig (getConfigFileName(), area, link, 0);
			addlink(link, area);
			xscatprintf(&report, " %s %s  added\r", an, print_ch(49-strlen(an), '.'));
			writeLogEntry(hpt_log, '8', "areafix: %s subscribed to %s",
						  aka2str(link->hisAka),an);
			if (strstr(line, "*") == NULL) i = config->echoAreaCount;
			break;
		default :
			writeLogEntry(hpt_log, '8', "areafix: area %s -- no access for %s",
						  an, aka2str(link->hisAka));
			xscatprintf(&report," %s %s  no access\r", an, print_ch(49-strlen(an), '.'));
			found = 1;
			break;
		}
	}
	
	if ((rc==4) && (strstr(line,"*") == NULL) && !found) {
	    if (link->fReqFromUpLink) {
			// try to forward request
			if (forwardRequest(line, link)!=0)
				xscatprintf(&report, " %s %s  no uplinks to forward\r",
							line, print_ch(49-strlen(line), '.'));
			else {
				xscatprintf(&report, " %s %s  request forwarded\r",
							line, print_ch(49-strlen(line), '.'));
				for (j=0; j < config->addrCount; j++)
				    if (addrComp(link->hisAka, config->addr[j])==0) { from_us=1; break; }
				if (!from_us) {
				    writeLogEntry(hpt_log, '8', "areafix: %s subscribed to area %s",
							  aka2str(link->hisAka),line);
				    area = getArea(config, line);
				    changeconfig (getConfigFileName(), area, link, 3);
				    addlink(link, area);
				}
			}
	    }
	}
	
	if (report == NULL) {
	    xscatprintf(&report," %s %s  Not found\r", line, print_ch(49-strlen(line), '.'));
	    writeLogEntry(hpt_log, '8', "areafix: area %s is not found",line);
	}
	return report;
}

char *errorRQ(char *line)
{
   char *report = NULL;

   xscatprintf(&report, " %s %s  error line\r", line, print_ch(49-strlen(line), '.'));

   return report;
}

static char *do_delete(s_link *link, s_message *msg, s_area *area)
{
    char *report = NULL, *an = area->areaName;
    int i;

    xscatprintf(&report, " %s %s  deleted\r", an, print_ch(49-strlen(an), '.'));
    for (i=0; i<area->downlinkCount; i++) {
	if (addrComp(area->downlinks[i]->link->hisAka, link->hisAka))
	    forwardRequestToLink(an, area->downlinks[i]->link, NULL, 2);
    }
    changeconfig (getConfigFileName(),  area, link, 4);
    writeLogEntry(hpt_log, '8', "areafix: area %s deleted by %s",
                  an, aka2str(link->hisAka));

    return report;
}

char *delete(s_link *link, s_message *msg, char *cmd) {
    int rc;
    char *line, *report = NULL, *an;
    s_area *area;

    for (line = cmd + 1; *line == ' ' || *line == '\t'; line++);

    if (*line == 0) return errorRQ(cmd);

    area = getArea(config, line);
    if (area == &(config->badArea)) {
	xscatprintf(&report, " %s %s  not found\r", line, print_ch(49-strlen(line), '.'));
	writeLogEntry(hpt_log, '8', "areafix: area %s is not found", line);
	return report;
    }
    rc = subscribeCheck(*area, msg, link);
    an = area->areaName;
    switch (rc) {
	case 0:	break;
	case 1:	xscatprintf(&report, " %s %s  not linked\r", an, print_ch(49-strlen(an), '.'));
		writeLogEntry(hpt_log, '8', "areafix: area %s is not linked to %s",
			      an, aka2str(link->hisAka));
		return report;
	case 2:	writeLogEntry(hpt_log, '8', "areafix: area %s -- no access for %s",
			      an, aka2str(link->hisAka));
		return report;
    }
    if (link->LinkGrp == NULL || strcmp(link->LinkGrp, area->group)) {
	writeLogEntry(hpt_log, '8', "areafix: area %s delete not allowed for %s",
		      an, aka2str(link->hisAka));
	return report;
    }
    return do_delete(link, msg, area);
}

char *unsubscribe(s_link *link, s_message *msg, char *cmd) {
	int i, rc = 2, j, from_us=0;
	char *line, *an, *report = NULL;
	s_area *area;
	
	line = cmd;
	
	if (line[1]=='-') return NULL;
	line++;
	while (*line==' ') line++;
	
	for (i = 0; i< config->echoAreaCount; i++) {
		area = &(config->echoAreas[i]);
		an = area->areaName;

		rc = subscribeAreaCheck(area, msg, line, link);
		if (rc==4) continue;
		if (rc==0 && mandatoryCheck(*area,link)) rc = 5;

		for (j = 0; j < config->addrCount; j++)
		    if (addrComp(link->hisAka, config->addr[j])==0) { from_us = 1; rc = 0; break; }

		switch (rc) {
		case 0: xscatprintf(&report, " %s %s  unlinked\r", an, print_ch(49-strlen(an), '.'));
			if (from_us == 0) {
			   int i;
			   for (i=0; i<area->downlinkCount; i++)
			   	if (addrComp(link->hisAka, area->downlinks[i]->link->hisAka) == 0 &&
			   	    area->downlinks[i]->defLink)
					return do_delete(link, msg, area);
			   removelink(link, area);
			   changeconfig (getConfigFileName(),  area, link, 1);
			   writeLogEntry(hpt_log, '8', "areafix: %s unlinked from %s",aka2str(link->hisAka),an);
			} else {
			if ((area->downlinkCount==1) && (area->downlinks[0]->link->hisAka.point == 0))
				forwardRequestToLink(area->areaName, area->downlinks[0]->link, NULL, 1);
			}
			break;
		case 1: if (strstr(line, "*")) continue;
			xscatprintf(&report, " %s %s  not linked\r", an, print_ch(49-strlen(an), '.'));
			writeLogEntry(hpt_log, '8', "areafix: area %s is not linked to %s",
					area->areaName, aka2str(link->hisAka));
			break;
		case 5: xscatprintf(&report, " %s %s  unlink is not possible\r", an, print_ch(49-strlen(an), '.'));
			writeLogEntry(hpt_log, '8', "areafix: area %s -- unlink is not possible for %s",
					area->areaName, aka2str(link->hisAka));
			break;
		default: writeLogEntry(hpt_log, '8', "areafix: area %s -- no access for %s",
						 area->areaName, aka2str(link->hisAka));
			continue;
		}
	}
	if (report == NULL) {
		if (strstr(line, "*")) {
			xscatprintf(&report, " %s %s  no areas to unlink\r",
						line, print_ch(49-strlen(line), '.'));
			writeLogEntry(hpt_log, '8', "areafix: no areas to unlink");
		} else {
			xscatprintf(&report, " %s %s  not found\r", line, print_ch(49-strlen(line), '.'));
			writeLogEntry(hpt_log, '8', "areafix: area %s is not found", line);
		}
	}
	return report;
}

int testAddr(char *addr, s_addr hisAka)
{
    s_addr aka;
    string2addr(addr, &aka);
    if (addrComp(aka, hisAka)==0) return 1;
    return 0;
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
				if (!*cfgline || *cfgline == '#') {
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
				curpos = ftell(hcfg);
				confName = safe_strdup(curconfname);
				close_conf();
				f_conf = fopen(confName, "r+");
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
				fputs("Pause\n", f_conf);
				fputs(line, f_conf);
				fclose(f_conf);
				nfree(line);
				link->Pause = 1;
				writeLogEntry(hpt_log, '8', "%s: system %s set passive", opt ? "autopause" : "areafix", aka2str(link->hisAka));
				return 1;
			}
		}
		nfree(cfgline);
	}
	close_conf();
	return 0;
}

char *pause_link(s_message *msg, s_link *link)
{
    char *tmp, *report = NULL;
    
    if (link->Pause == 0) {
	if (changepause(getConfigFileName(), link, 0) == 0) return NULL;    
    }

    xstrcat(&report, " System switched to passive\r");
    tmp = linked(msg, link);
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
			if (!*cfgline || *cfgline == '#') {
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
			if (!*cfgline || *cfgline == '#') {
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
		remstr = ftell(hcfg);
		curpos = curconfpos;
		confName = safe_strdup(curconfname);
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
#if defined(__WATCOMC__) || defined(__MINGW32__)
		fflush( f_conf );
		fTruncate( fileno(f_conf), endpos-(remstr-curpos) );
		fflush( f_conf );
#else
		truncate(confName, endpos-(remstr-curpos));
#endif
		nfree(line);
		nfree(confName);
		link->Pause = 0;
		writeLogEntry(hpt_log, '8', "areafix: system %s set active",	aka2str(link->hisAka));
		return 1;
	}
	close_conf();
	return 0;
}

char *resume_link(s_message *msg, s_link *link)
{
    char *tmp, *report = NULL;
    
    if (link->Pause) {
		if (changeresume(getConfigFileName(), link) == 0) return NULL;
    }
	
    xstrcat(&report, " System switched to active\r");
    tmp = linked(msg, link);
    xstrcat(&report, tmp);
    nfree(tmp);

    return report;
}

char *info_link(s_message *msg, s_link *link)
{
    char *report=NULL, *ptr, linkAka[25];
    char hisAddr[]="Your address: ";
    char ourAddr[]="AKA used here: ";
    char Arch[]="Compression: ";
    int i;
    
    sprintf(linkAka,aka2str(link->hisAka));
    xscatprintf(&report, "Here is some information about our link:\r\r %s%s\r%s%s\r  %s", 
		    hisAddr, linkAka, ourAddr, aka2str(*link->ourAka), Arch);
    
    if (link->packerDef==NULL) 
	    xscatprintf(&report, "No packer (");
    else 
	    xscatprintf(&report, "%s (", link->packerDef->packer);
    
    for (i=0; i < config->packCount; i++)
	xscatprintf(&report, "%s%s", config->pack[i].packer,
	    (i+1 == config->packCount) ? "" : ", ");
    
    xscatprintf(&report, ")\r\rYour system is %s\r", link->Pause ? "passive" : "active");
    ptr = linked(msg, link);
    xstrcat(&report, ptr);
    nfree(ptr);
    writeLogEntry(hpt_log, '8', "areafix: link information sent to %s", aka2str(link->hisAka));
    return report;
}

void repackEMMsg(HMSG hmsg, XMSG xmsg, s_area *echo, s_link *link)
{
   s_message    msg;
   UINT32       j=0;
   s_pktHeader  header;
   FILE         *pkt;
   long         len;

   makeMsg(hmsg, xmsg, &msg, echo, 1);

   //translating name of the area to uppercase
   while (msg.text[j] != '\r') {msg.text[j]=(char)toupper(msg.text[j]);j++;}

   // link is passive?
   if (link->Pause && !echo->noPause) return;
   // check access read for link
   if (checkAreaLink(echo, link->hisAka, 1)!=0) return;

   if (link->pktFile != NULL && link->pktSize != 0) { // check packet size
	   len = fsize(link->pktFile);
	   if (len >= link->pktSize * 1024L) { // Stop writing to pkt
		   nfree(link->pktFile);
		   nfree(link->packFile);
	   }
   }
   
   if (link->pktFile == NULL) {
	   
	   // pktFile does not exist
	   if ( createTempPktFileName(link) ) {
		   exit_hpt("Could not create new pkt!",1);
	   }
	   
   } /* endif */
   
   makePktHeader(NULL, &header);
   header.origAddr = *(link->ourAka);
   header.destAddr = link->hisAka;
   if (link->pktPwd != NULL)
   strcpy(header.pktPassword, link->pktPwd);
   pkt = openPktForAppending(link->pktFile, &header);

   // an echomail messages must be adressed to the link
   msg.destAddr = header.destAddr;
   writeMsgToPkt(pkt, msg);

   closeCreatedPkt(pkt);

   // mark msg as sent and scanned
   xmsg.attr |= MSGSENT;
   xmsg.attr |= MSGSCANNED;
   MsgWriteMsg(hmsg, 0, &xmsg, NULL, 0, 0, 0, NULL);

   freeMsgBuffers(&msg);
}

int rescanEMArea(s_area *echo, s_link *link, long rescanCount)
{
   HAREA area;
   HMSG  hmsg;
   XMSG  xmsg;
   dword highestMsg, i;

   /*FIXME: the code in toss.c does createDirectoryTree. We don't*/
   area = MsgOpenArea((UCHAR *) echo->fileName, MSGAREA_NORMAL, /*echo -> fperm, 
                    echo -> uid, echo -> gid,*/ (word)(echo->msgbType | MSGTYPE_ECHO));
   if (area != NULL) {
     //      i = highWaterMark = MsgGetHighWater(area);
     i = 0;
      highestMsg    = MsgGetHighMsg(area);

      // if rescanCount == -1 all mails should be rescanned
      if ((rescanCount == -1) || (rescanCount > highestMsg))
        rescanCount = highestMsg;

      while (i <= highestMsg) {
	if (i > highestMsg - rescanCount) { // honour rescanCount paramater
	  hmsg = MsgOpenMsg(area, MOPEN_RW, i);
	  if (hmsg != NULL) {     // msg# does not exist
	    MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
	    repackEMMsg(hmsg, xmsg, echo, link);
	    MsgCloseMsg(hmsg);
	  }
	}
	i++;
      }

      MsgSetHighWater(area, i);

      MsgCloseArea(area);
      
      return rescanCount;
   }
   
   writeLogEntry(hpt_log, '9', "Could not open %s", echo->fileName);
   return 0;
}

char *rescan(s_link *link, s_message *msg, char *cmd)
{
    int i, c, rc = 0;
    long rescanCount = -1;
    char *report = NULL, *line, *countstr, *an, *end;
    s_area *area;
    
    line = cmd+strlen("%rescan");
    
    if (*line == 0) return errorRQ(cmd);
    
    while (*line && (*line == ' ' || *line == '\t')) line++;
    
    if (*line == 0) return errorRQ(cmd);

    countstr = line;
    while (*countstr && (!isspace(*countstr))) countstr++;
    while (*countstr && (*countstr == ' ' || *countstr == '\t')) countstr++;

    if (*countstr != 0)
      {
         rescanCount = strtol(countstr, NULL, 10);
      }
    
    end = strpbrk(line, " \t");
    if (end) *end = 0;
    
    if (*line == 0) return errorRQ(cmd);

    for (i=c=0; i<config->echoAreaCount; i++) {
		rc=subscribeAreaCheck(&(config->echoAreas[i]),msg,line, link);
		if (rc == 4) continue;
	    
		area = &(config->echoAreas[i]);
		an = area->areaName;
		
		switch (rc) {
		case 0: 
			if (area->msgbType == MSGTYPE_PASSTHROUGH) {
				xscatprintf(&report," %s %s  no rescan possible\r", an, print_ch(49-strlen(an), '.'));
				writeLogEntry(hpt_log, '8', "areafix: %s area no rescan possible to %s",
						area->areaName, aka2str(link->hisAka));
			} else {

			  rescanCount = rescanEMArea(area, link, rescanCount);
			  xscatprintf(&report," %s %s  rescanned %lu mails\r",
			      an, print_ch(49-strlen(an), '.'), rescanCount);
			  writeLogEntry(hpt_log,'8',"areafix: %s rescanned %lu mails to %s",
			      area->areaName, rescanCount, aka2str(link->hisAka));
//			  arcmail(link);
			  tossTempOutbound(config->tempOutbound);
			}
			break;
		case 1: if (strstr(line, "*")) continue;
			writeLogEntry(hpt_log, '8', "areafix: %s area not linked for rescan to %s",
					area->areaName, aka2str(link->hisAka));
			xscatprintf(&report, " %s %s  not linked for rescan\r", an, print_ch(49-strlen(an), '.'));
			break;
		default: writeLogEntry(hpt_log, '8', "areafix: %s area not access for %s",
						 area->areaName, aka2str(link->hisAka));
			continue;
		}
	}
    if (report == NULL) {
	xscatprintf(&report," %s %s  not linked for rescan\r", line, print_ch(49-strlen(line), '.'));
	writeLogEntry(hpt_log, '8', "areafix: %s area not linked for rescan", line);
    }
    return report;
}

int tellcmd(char *cmd) {
	char *line;

	if (strncasesearch(cmd, " * Origin:", 10) == 0) return NOTHING;
        while ((*cmd == ' ') || (*cmd == '\t')) cmd++;
   	line = strpbrk(cmd, " \t");
	if (line && *cmd != '%') *line = 0;

	line = cmd;

	switch (line[0]) {
	case '%': 
		line++;
		if (*line == 0) return ERROR;
		if (strncasecmp(line,"list",4)==0) return LIST;
		if (strncasecmp(line,"help",4)==0) return HELP;
		if (strncasecmp(line,"avail",5)==0) return AVAIL;
//		if (stricmp(line,"available")==0) return AVAIL;
		if (strncasecmp(line,"all",3)==0) return AVAIL;
		if (strncasecmp(line,"unlinked",8)==0) return UNLINK;
		if (strncasecmp(line,"linked",6)==0) return QUERY;
		if (strncasecmp(line,"query",5)==0) return QUERY;
		if (strncasecmp(line,"pause",5)==0) return PAUSE;
		if (strncasecmp(line,"resume",6)==0) return RESUME;
		if (strncasecmp(line,"info",4)==0) return INFO;
		if (strncasesearch(line, "rescan", 6)==0) return RESCAN;
		return ERROR;
	case '\001': return NOTHING;
	case '\000': return NOTHING;
	case '-'  : return DEL;
	case '~'  : return REMOVE;
	case '+': line++; if (line[0]=='\000') return ERROR;
	default: return ADD;
	}
	
	return 0;
}

char *processcmd(s_link *link, s_message *msg, char *line, int cmd) {
	
	char *report;
	
	switch (cmd) {

	case NOTHING: return NULL;

	case LIST: report = list (msg, link);
		RetFix=LIST;
		break;
	case HELP: report = help (link);
		RetFix=HELP;
		break;
	case ADD: report = subscribe (link,msg,line);
		RetFix=ADD;
		break;
	case DEL: report = unsubscribe (link,msg,line);
		RetFix=DEL;
		break;
	case REMOVE: report = delete (link,msg,line);
		RetFix=REMOVE;
		break;
	case AVAIL: report = available (link); 
		RetFix=AVAIL;
		break;
	case UNLINK: report = unlinked (msg, link);
		RetFix=UNLINK;
		break;
	case QUERY: report = linked (msg, link);
		RetFix=QUERY;
		break;
	case PAUSE: report = pause_link (msg, link);
		RetFix=PAUSE;
		break;
	case RESUME: report = resume_link (msg, link);
		RetFix=RESUME;
		break;
	case INFO: report = info_link(msg, link);
		RetFix=INFO;
		break;
	case RESCAN: report = rescan(link, msg, line);
		RetFix=RESCAN;
		break;
	case ERROR: report = errorRQ(line);
		RetFix=ERROR;
		break;
	default: return NULL;
	}
	
	return report;
}

void preprocText(char *split, s_message *msg)
{
    char *orig = (config->areafixOrigin) ? config->areafixOrigin : config->origin;

    msg->text = createKludges(NULL, &msg->origAddr, &msg->destAddr);
    xscatprintf(&split, " \r--- %s areafix\r", versionStr);
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

    if (RetFix == AVAIL || RetFix == LIST) config->intab = NULL;
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
			split = (char*) safe_malloc(len+strlen((splitStr) ? splitStr : splitted)+3+1);
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
		processNMMsg(tmpmsg, NULL, NULL, 0, MSGLOCAL);

		freeMsgBuffers(tmpmsg);
		nfree(tmpmsg);
		if (partnum) nfree(newsubj);
	}

    config->intab = tab;
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

int processAreaFix(s_message *msg, s_pktHeader *pktHeader)
{
	int i, security=1, notforme = 0;
	s_link *link = NULL;
	s_link *tmplink = NULL;
	s_message *linkmsg;
	s_pktHeader header;
	char *token, *textBuff, *report=NULL, *preport = NULL;
	
	// load recoding tables
//	if (config->outtab != NULL) getctab(outtab, (unsigned char*) config->outtab);

	// 1st security check
	if (pktHeader) security=addrComp(msg->origAddr, pktHeader->origAddr);
	else {
		makePktHeader(NULL, &header);
		pktHeader = &header;
		pktHeader->origAddr = msg->origAddr;
		pktHeader->destAddr = msg->destAddr;
		security = 0;
	}
	
	if (security) security=1;
	
	// find link
	link=getLinkFromAddr(*config, msg->origAddr);

	// if keyword allowPktAddrDiffer for this link is on,
	// we allow the addresses in PKT and MSG header differ
	if (link!=NULL)
		if (link->allowPktAddrDiffer == pdOn)
			security = 0;
	
	// this is for me?
	if (link!=NULL)	notforme=addrComp(msg->destAddr, *link->ourAka);
	else if (!security) security=4; // link == NULL;
	
	// ignore msg for other link (maybe this is transit...)
	if (notforme || (link==NULL && security==1)) {
		return processNMMsg(msg, pktHeader, NULL, 0, 0);
	}
	
	// 2nd security check. link, areafixing & password.
	if (!security) {
		if (link->AreaFix==1) {
			if (link->areaFixPwd!=NULL) {
				if (stricmp(link->areaFixPwd,msg->subjectLine)==0) security=0;
				else security=3;
			}
		} else security=2;
	}
	
	if (!security) {
		
		textBuff = msg->text;
		token = strseparate (&textBuff, "\n\r");
		while(token != NULL) {
			preport = processcmd( link, msg,  stripLeadingChars(token, " \t"), tellcmd (token) );
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
					break;
				case DEL:
				case REMOVE:
					report = areaStatus(report, preport);
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
				case RESCAN:
 					report=areaStatus(report, preport);
 					break;
				case ERROR:
					report = areaStatus(report, preport);
					break;
				default: break;
				} /* end switch */
				
			} /* end if (preport != NULL) */

			token = strseparate (&textBuff, "\n\r");
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
		writeLogEntry(hpt_log, '8', "areafix: security violation from %s", aka2str(link->hisAka));
		nfree(tmplink);
		
		return 1;
	}

	if ( report != NULL ) {
		preport=linked(msg, link);
		xstrcat(&report, preport);
		nfree(preport);
		RetMsg(msg, link, report, "areafix reply: node change request");
	}
	
	writeLogEntry(hpt_log, '8', "areafix: sucessfully done for %s",aka2str(link->hisAka));
	
	// send msg to the links (forward requests to areafix)
	for (i = 0; i < config->linkCount; i++) {
		if (config->links[i].msg == NULL) continue;
		link = &(config->links[i]);
		linkmsg = link->msg;
		
		xscatprintf(&(linkmsg->text), " \r--- %s areafix\r", versionStr);
		linkmsg->textLength = strlen(linkmsg->text);
		
		makePktHeader(NULL, &header);
		header.origAddr = *(link->ourAka);
		header.destAddr = link->hisAka;
		
		writeLogEntry(hpt_log, '8', "areafix: write netmail msg for %s", aka2str(link->hisAka));

		processNMMsg(linkmsg, &header, NULL, 0, MSGLOCAL);

		freeMsgBuffers(linkmsg);
		nfree(linkmsg);
		link->msg = NULL;
	}
	
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

void afix(void)
{
    HAREA           netmail;
    HMSG            SQmsg;
    unsigned long   highmsg, i, j;
    XMSG            xmsg;
    s_addr          dest;
    s_message	    msg;
    int             for_us;

    writeLogEntry(hpt_log, '1', "Start AreaFix...");
    
    netmail = MsgOpenArea((unsigned char *) config->netMailAreas[0].fileName, MSGAREA_NORMAL, 
						  /*config -> netMailArea.fperm, 
						  config -> netMailArea.uid,
						  config -> netMailArea.gid,*/
						  (word)config -> netMailAreas[0].msgbType);
    if (netmail != NULL) {

	highmsg = MsgGetHighMsg(netmail);
	writeLogEntry(hpt_log, '1', "Scanning NetmailArea");

	// scan all Messages and test if they are already sent.
	for (i=1; i<= highmsg; i++) {
	    SQmsg = MsgOpenMsg(netmail, MOPEN_RW, i);

	    // msg does not exist
	    if (SQmsg == NULL) continue;

	    MsgReadMsg(SQmsg, &xmsg, 0, 0, NULL, 0, NULL);
	    cvtAddr(xmsg.dest, &dest);
	    for_us = 0;
	    for (j=0; j < config->addrCount; j++)
		if (addrComp(dest, config->addr[j])==0) {for_us = 1; break;}
                
	    // if not read and for us -> process AreaFix
		if (((xmsg.attr & MSGREAD) != MSGREAD) && (for_us==1) &&
			((stricmp((char*)xmsg.to, "areafix")==0) || 
			 (stricmp((char*)xmsg.to, "areamgr")==0) ||
			 (stricmp((char*)xmsg.to, "hpt")==0) ) ) {
		    memset(&msg,0,sizeof(s_message));
		    MsgToStruct(SQmsg, xmsg, &msg);
		    processAreaFix(&msg, NULL);
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
           else
	    MsgCloseMsg(SQmsg);

	} /* endfor */

//	writeMsgToSysop(msgToSysop);
	MsgCloseArea(netmail);
    } else {
		writeLogEntry(hpt_log, '9', "Could not open NetmailArea");
    } /* endif */
}

void autoPassive()
{
   time_t   time_cur, time_test;
   struct   stat stat_file;
   s_message *msg;
   FILE *f;
   char *line, *path;
   int i;

   for (i = 0; i < config->linkCount; i++) {
      if (config->links[i].autoPause && config->links[i].Pause == 0) {
         if (createOutboundFileName(&(config->links[i]), cvtFlavour2Prio(config->links[i].echoMailFlavour), FLOFILE) == 0) {
            f = fopen(config->links[i].floFile, "rt");
            if (f) {
               while ((line = readLine(f)) != NULL) {
	          line = trimLine(line);
                  path = line;
                  if (*path && (*path == '^' || *path == '#')) {
                     path++;
                     if (stat(path, &stat_file) != -1) {
                        time_cur = time(NULL);
                        time_test = (time_cur - stat_file.st_mtime)/3600;
                        if (time_test >= (config->links[i].autoPause*24)) {
                           if (config->links[i].Pause == 0) {
                              if (changepause(getConfigFileName(), &(config->links[i]), 1)) {    
			         msg = makeMessage(config->links[i].ourAka, &(config->links[i].hisAka), versionStr, config->links[i].name, "AutoPassive", 1);
				 msg->text = createKludges(NULL, config->links[i].ourAka, &(config->links[i].hisAka));
                                 xscatprintf(&(msg->text), "\r System switched to passive\r\r When you wish to continue receiving arcmail, please send request to AreaFix\r containing the %%RESUME command.\r\r--- %s autopause\r", versionStr);
                                 msg->textLength = strlen(msg->text);
                                 processNMMsg(msg, NULL, NULL, 0, MSGLOCAL);
                                 freeMsgBuffers(msg);
				 nfree(msg);
                              }
			      nfree(line);
                              fclose(f);
                              break;
                           }
                        } else {
                        } /* endif */
                     } /* endif */
                  } /* endif */
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
      } else {
      } /* endif */
   } /* endfor */
}

int relink (char *straddr) {
	s_link          *researchLink = NULL;
	unsigned int    count, areasArraySize;
	s_area          **areasIndexArray = NULL;
	
	// parse config
	if (config==NULL) processConfig();

	writeLogEntry(hpt_log, '1', "Start relink...");

	if (straddr) researchLink = getLink(*config, straddr);
	else {
	    writeLogEntry(hpt_log, '9', "No address");
	    return 1;
	}

	if ( researchLink == NULL ) {
	    writeLogEntry(hpt_log, '9', "Unknown link address %s", straddr);
	    return 1;
	}

	areasArraySize = 0;
	areasIndexArray = (s_area **) safe_malloc
		(sizeof(s_area *) * (config->echoAreaCount  +
							 config->localAreaCount + 1));

	if ( areasIndexArray == NULL ) {
		writeLogEntry(hpt_log, '9', "No mem (to work RELINK)");
		return 1;
	}

	for (count = 0; count < config->echoAreaCount; count++) {
		if ( isLinkOfArea(researchLink, &config->echoAreas[count]) &&
                     !(config->echoAreas[count].msgbType == MSGTYPE_PASSTHROUGH && config->echoAreas[count].downlinkCount == 1) ) {
			areasIndexArray[areasArraySize] = &config->echoAreas[count];
			areasArraySize++;
			writeLogEntry(hpt_log, '8', "Echo %s from link %s refresh",
						  config->echoAreas[count].areaName,
						  aka2str(researchLink->hisAka));
		}
	}

	for ( count = 0; count < config->localAreaCount; count++) {
		if ( isLinkOfArea(researchLink, &config->localAreas[count]) &&
                     !(config->echoAreas[count].msgbType == MSGTYPE_PASSTHROUGH && config->echoAreas[count].downlinkCount == 1) ) {
			areasIndexArray[areasArraySize] = &config->localAreas[count];
			areasArraySize++;
			// to log area name (low priority)
			writeLogEntry(hpt_log, '8', "LocalEcho %s link %s refresh",
						  config->localAreas[count].areaName,
						  aka2str(researchLink->hisAka));
		}
	}

	if ( areasArraySize > 0 ) {
		s_message *msg;

		msg = makeMessage(researchLink->ourAka,
						  &researchLink->hisAka,
						  versionStr,
						  researchLink->RemoteRobotName ?
						  researchLink->RemoteRobotName : "AreaFix",
						  researchLink->areaFixPwd, 1);

		msg->text = createKludges( NULL,researchLink->ourAka,&researchLink->hisAka);

		for ( count = 0 ; count < areasArraySize; count++ ) {
			xscatprintf(&(msg->text), "+%s\r",areasIndexArray[count]->areaName);
		}

		xscatprintf(&(msg->text), " \r--- %s areafix\r", versionStr);
		msg->textLength = strlen(msg->text);
		writeLogEntry(hpt_log, '8', "'Refresh' message created to `AreaFix`");
		processNMMsg(msg, NULL, NULL, 0, MSGLOCAL);
		freeMsgBuffers(msg);
		nfree(msg);
		writeLogEntry(hpt_log, '8', "Total request relink %i area(s)",areasArraySize);
	}

	nfree(areasIndexArray);

	return 0;
}
