/*:ts=8*/
/*****************************************************************************
 * AreaFix for HPT (FTN NetMail/EchoMail Tosser)
 *****************************************************************************
 * Copyright (C) 1998-1999
 *
 * Max Levenkov
 *
 * Fido:     2:5000/117
 * Internet: ml@nsk.uland.com
 * Novosibirsk, Russia
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
#include <unistd.h>

#if !defined(MSDOS) || defined(__DJGPP__)
#include <fidoconfig.h>
#else
#include <fidoconf.h>
#endif

#include <common.h>
#include <fcommon.h>
#include <global.h>
#include <pkt.h>
#include <version.h>
#include <toss.h>
#include <patmat.h>
#include <ctype.h>
#include <progprot.h>
#include <strsep.h>
#include <seenby.h>
#include <scan.h>
#include <recode.h>
#include <areafix.h>
#include <scanarea.h>

unsigned char RetFix;
char straka[24];

int strncasesearch(char *strL, char *strR, int len)
{
    char *str;
    int ret;
    
    str = (char*)calloc(strlen(strL)+1, sizeof(char));
    strcpy(str, strL);
    if (strlen(str) > len) str[len] = 0;
    ret = stricmp(str, strR);
    free(str);
    return ret;
}

char *print_ch(int len, char ch)
{
    static char tmp[256];
    
    memset(tmp, ch, len);
    tmp[len]=0;
    return tmp;
}

char *aka2str(s_addr aka) {
    if (aka.point) sprintf(straka,"%u:%u/%u.%u",aka.zone,aka.net,aka.node,aka.point);
    else sprintf(straka,"%u:%u/%u",aka.zone,aka.net,aka.node);
	
    return straka;
}	

int subscribeCheck(s_area area, s_message *msg, s_link *link) {
	int i;
	for (i = 0; i<area.downlinkCount;i++) {
		if (addrComp(msg->origAddr, area.downlinks[i]->link->hisAka)==0) return 0;
	}
	if (area.group != '\060')
	    if (link->AccessGrp) {
			if (config->PublicGroup) {
				if (strchr(link->AccessGrp, area.group) == NULL &&
					strchr(config->PublicGroup, area.group) == NULL) return 2;
			} else if (strchr(link->AccessGrp, area.group) == NULL) return 2;
	    } else if (config->PublicGroup) {
			if (strchr(config->PublicGroup, area.group) == NULL) return 2;
		} else return 2;
	if (area.hide) return 3;
	return 1;
}

int subscribeAreaCheck(s_area *area, s_message *msg, char *areaname, s_link *link) {
	int rc=4;
	
	if (!areaname) return rc;
	
	if (patimat(area->areaName,areaname)==1) {
		rc=subscribeCheck(*area, msg, link);
		// 0 - already subscribed
		// 1 - need subscribe
		// 2 - no access group
		// 3 - area is hidden
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

	while ( (ptr = strstr(sbuff, str)) ) {
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
	buff = (char*)realloc(buff, len+1);
	memset(buff, 0, len+1);
	fseek(f, curpos+linelen, SEEK_SET);
	len = fread(buff, sizeof(char), (size_t) len, f);
 	fseek(f, curpos, SEEK_SET);
//	fputs(buff, f);
	fwrite(buff, sizeof(char), (size_t) len, f);
#ifdef __WATCOMC__
	fflush( f );
	fTruncate( fileno(f), endpos-linelen );
	fflush( f );
#else
	truncate(fileName, endpos-linelen);
#endif
    }
    free(buff);
    return 0;
}

// add string to file
int addstring(FILE *f, char *aka) {
	char *cfg;
	long areapos,endpos,cfglen,len;

	//current position
#ifndef UNIX
	/* in dos and win32 by default \n translates into 2 chars */
	fseek(f,-2,SEEK_CUR);
#else                                                   
	fseek(f,-1,SEEK_CUR);
#endif
	areapos=ftell(f);
	
	// end of file
	fseek(f,0l,SEEK_END);
	endpos=ftell(f);
	cfglen=endpos-areapos;
	
	// storing end of file...
	cfg = (char*) calloc((size_t) cfglen+1, sizeof(char));
	fseek(f,-cfglen,SEEK_END);
	len = fread(cfg,sizeof(char),(size_t) cfglen,f);
	
	// write config
	fseek(f,-cfglen,SEEK_END);
	fputs(" ",f);
	fputs(aka,f);
//	fputs(cfg,f);
	fwrite(cfg,sizeof(char),(size_t) len,f);
	fflush(f);
	
	free(cfg);
	return 0;
}

void addlink(s_link *link, s_area *area) {
    char *test = NULL;
    
    area->downlinks = realloc(area->downlinks, sizeof(s_arealink*)*(area->downlinkCount+1));
    area->downlinks[area->downlinkCount] = (s_arealink*)calloc(1, sizeof(s_arealink));
    area->downlinks[area->downlinkCount]->link = link;
    
    if (link->optGrp) test = strchr(link->optGrp, area->group);
    area->downlinks[area->downlinkCount]->export = 1;
    area->downlinks[area->downlinkCount]->import = 1;
    area->downlinks[area->downlinkCount]->mandatory = 0;
    if (link->export) if (*link->export==0) {
	    if (link->optGrp == NULL || (link->optGrp && test)) {
		area->downlinks[area->downlinkCount]->export = 0;
	    }
	} 
    if (link->import) if (*link->import==0) {
	    if (link->optGrp == NULL ||  (link->optGrp && test)) {
		area->downlinks[area->downlinkCount]->import = 0;
	    }
	} 
    if (link->mandatory) if (*link->mandatory==1) {
	    if (link->optGrp == NULL || (link->optGrp && test)) {
		area->downlinks[area->downlinkCount]->mandatory = 1;
	    }
	} 
    area->downlinkCount++;
}

void removelink(s_link *link, s_area *area) {
	int i;
	s_link *links;

	for (i=0; i < area->downlinkCount; i++) {
           links = area->downlinks[i]->link;
           if (addrComp(link->hisAka, links->hisAka)==0) break;
	}
	
	free(area->downlinks[i]);
	area->downlinks[i] = area->downlinks[area->downlinkCount-1];
	area->downlinkCount--;
}

void changeHeader(s_message *msg, s_link *link, char *subject) {
	s_addr *ourAka;
	char *toname;
	
	ourAka=link->ourAka;
	
	msg->destAddr.zone = link->hisAka.zone;
	msg->destAddr.net = link->hisAka.net;
	msg->destAddr.node = link->hisAka.node;
	msg->destAddr.point = link->hisAka.point;

	msg->origAddr.zone = ourAka->zone;
	msg->origAddr.net = ourAka->net;
	msg->origAddr.node = ourAka->node;
	msg->origAddr.point = ourAka->point;
	
	msg->subjectLine = (char*)calloc(1, strlen(subject)+1);
	strcpy(msg->subjectLine,subject);
	toname = msg->fromUserName;
	msg->fromUserName = msg->toUserName;
	msg->toUserName = toname;

	msg->netMail = 1;
	
	if (config->areafixKillReports) msg->attributes |= MSGKILL;
}

char *list(s_message *msg, s_link *link) {

	int i,active,avail,rc;
	char *report, addline[256];
	
	sprintf(addline, "Available areas for %s\r\r", aka2str(link->hisAka));

	report=(char*)calloc(strlen(addline)+1,sizeof(char));
	strcpy(report, addline);

	for (i=active=avail=0; i< config->echoAreaCount; i++) {

	    rc=subscribeCheck(config->echoAreas[i],msg, link);
	    if (rc < 2) {
			report=(char*) realloc(report, strlen(report)+
			       strlen(config->echoAreas[i].areaName)+4);
			if (rc==0) {
				strcat(report,"* ");
				active++;
				avail++;
			} else {
				strcat(report,"  ");
				avail++;
			}
			strcat(report, config->echoAreas[i].areaName);
			strcat(report,"\r");
	    }
	}
	
	sprintf(addline,"\r'*' = area active for %s\r%i areas available, %i areas active\r", aka2str(link->hisAka), avail, active);
	report=(char*) realloc(report, strlen(report)+strlen(addline)+1);
	strcat(report, addline);

	sprintf(addline,"AreaFix: list sent to %s", aka2str(link->hisAka));
	writeLogEntry(hpt_log, '8', addline);
	
	return report;
}

char *linked(s_message *msg, s_link *link)
{
    int i, n, rc;
    char *report, addline[256];

    if (link->Pause) 
        sprintf(addline, "\rPassive areas on %s\r\r", aka2str(link->hisAka));
    else
	sprintf(addline, "\rActive areas on %s\r\r", aka2str(link->hisAka));
							
    report=(char*)calloc(strlen(addline)+1, sizeof(char));
    strcpy(report, addline);
    
    for (i=n=0; i<config->echoAreaCount; i++) {
	rc=subscribeCheck(config->echoAreas[i], msg, link);
	if (rc==0) {
	    report=(char*)realloc(report, strlen(report)+
			    strlen(config->echoAreas[i].areaName)+3);
	    strcat(report, " ");
	    strcat(report, config->echoAreas[i].areaName);
	    strcat(report, "\r");
	    n++;
	}
    }
    sprintf(addline, "\r%u areas linked\r", n);
    report=(char*)realloc(report, strlen(report)+strlen(addline)+1);
    strcat(report, addline);
    return report;
}

char *unlinked(s_message *msg, s_link *link)
{
    int i, rc;
    char *report, addline[256];
    s_area *EchoAreas;
    
    EchoAreas=config->echoAreas;
    
    sprintf(addline, "Unlinked areas to %s\r\r", aka2str(link->hisAka));
    report=(char*)calloc(strlen(addline)+1, sizeof(char));
    strcpy(report, addline);
    
    for (i=0; i<config->echoAreaCount; i++) {
	rc=subscribeCheck(EchoAreas[i], msg, link);
	if (rc == 1) {
	    report=(char*)realloc(report, strlen(report)+
				strlen(EchoAreas[i].areaName)+3);
	    strcat(report, " ");
	    strcat(report, EchoAreas[i].areaName);
	    strcat(report, "\r");
	}
    }
    sprintf(addline,"AreaFix: unlinked areas list sent to %s", aka2str(link->hisAka));
    writeLogEntry(hpt_log, '8', addline);

    return report;
}

char *help(s_link *link) {
	FILE *f;
	int i=1;
	char *help, addline[256];
	long endpos;

	if (config->areafixhelp!=NULL) {
		if ((f=fopen(config->areafixhelp,"r")) == NULL)
			{
				fprintf(stderr,"areafix: cannot open help file \"%s\"\n",
						config->areafixhelp);
				return NULL;
			}
		
		fseek(f,0l,SEEK_END);
		endpos=ftell(f);
		
		help=(char*) calloc((size_t) endpos+1,sizeof(char));

		fseek(f,0l,SEEK_SET);
		fread(help,1,(size_t) endpos,f);
		
		for (i=0; i<endpos; i++) if (help[i]=='\n') help[i]='\r';

		fclose(f);

		sprintf(addline,"areafix: help sent to %s",link->name);
		writeLogEntry(hpt_log, '8', addline);

		return help;
	}

	return NULL;
}

char *available(s_link *link) {
	FILE *f;
	int i=0,j=0;
	char *avail=NULL, *report, addline[256], linkAka[25];
	long endpos;
	s_link *uplink=NULL;

	report=calloc((size_t) 1,sizeof(char));

    for (j = 0; j < config->linkCount; j++) {
		uplink = &(config->links[j]);

		if (uplink->forwardRequestFile!=NULL) {
			if ((f=fopen(uplink->forwardRequestFile,"r")) == NULL)
				{
					fprintf(stderr,"areafix: cannot open forwardRequestFile \"%s\"\n", uplink->forwardRequestFile);
					sprintf(addline,"areafix: cannot open forwardRequestFile \"%s\"\n", uplink->forwardRequestFile);
					writeLogEntry(hpt_log, '8', addline);
					return report;
				}

			sprintf(addline,"Available Area List from %s:\r", aka2str(uplink->hisAka));
			report=(char*) realloc(report,strlen(report)+strlen(addline)+1);
			if (strlen(report)==0) strcpy(report,addline); else strcat(report,addline);

			fseek(f,0l,SEEK_END);
			endpos=ftell(f);
			
			avail=(char*) calloc((size_t) endpos + 1, sizeof(char));
			
			fseek(f,0l,SEEK_SET);
			fread(avail,1,(size_t) endpos,f);
			for (i=0; i<endpos; i++) if (avail[i]=='\n') avail[i]='\r';
			
			fclose(f);

			report=(char*) realloc(report,strlen(report)+strlen(avail)+1);
			strcat (report,avail);
			free(avail);

			sprintf(addline,"  %s\r\r",print_ch(75,'-'));
			report=(char*) realloc(report,strlen(report)+strlen(addline)+1);
			strcat (report,addline);

			sprintf(linkAka, "%s", aka2str(link->hisAka));
			sprintf(addline,"areafix: Available Area List from %s sent to %s", aka2str(uplink->hisAka), linkAka);
			
			writeLogEntry(hpt_log, '8', addline);
			
		}
	}
	
	return report;
}                                                                               

/*
int delConfigLine(FILE *f, char *fileName) {
    long curpos, endpos, linelen, len;
    char *buff;
	
    curpos = ftell(f);
    buff = readLine(f);
    linelen = strlen(buff)+1;
	
	fseek(f, 0L, SEEK_END);
	endpos = ftell(f);
	len = endpos-(curpos+linelen);
	buff = (char*)realloc(buff, len+1);
	memset(buff, 0, len+1);
	fseek(f, curpos+linelen, SEEK_SET);
	
	fread(buff, len, sizeof(char), f);
 	fseek(f, curpos, SEEK_SET);
	fputs(buff, f);
	truncate(fileName, endpos-linelen);
	
    free(buff);
    return 0;
}
*/
// subscribe if (act==0),  unsubscribe if (act!=0)
int forwardRequestToLink (char *areatag, s_link *uplink, s_link *dwlink, int act) {
    time_t t;
    struct tm *tm;
    s_message *msg;
    char *base, pass[]="passthrough";

	if (uplink->msg == NULL) {

		msg = calloc (1,sizeof(s_message));

		msg->origAddr.zone  = uplink->ourAka->zone;
		msg->origAddr.net   = uplink->ourAka->net;
		msg->origAddr.node  = uplink->ourAka->node;
		msg->origAddr.point = uplink->ourAka->point;
		
		msg->destAddr.zone  = uplink->hisAka.zone;
		msg->destAddr.net   = uplink->hisAka.net;
		msg->destAddr.node  = uplink->hisAka.node;
		msg->destAddr.point = uplink->hisAka.point;
		
		msg->attributes = 1;
		
		t = time (NULL);
		tm = gmtime(&t);
		strftime(msg->datetime, 21, "%d %b %y  %T", tm);
		
		msg->netMail = 1;
		
		msg->toUserName = (char *) malloc(8);
		strcpy(msg->toUserName, "areafix");
		
		msg->fromUserName = (char *) malloc(strlen(config->sysop)+1);
		strcpy(msg->fromUserName, config->sysop);
		
		if (uplink->areaFixPwd!=NULL) {
			msg->subjectLine = (char *) malloc(strlen(uplink->areaFixPwd)+1);
			strcpy(msg->subjectLine, uplink->areaFixPwd);
		} else msg->subjectLine = (char *) calloc(1, sizeof(char));
		
		msg->text = (char *) malloc(sizeof(char)*100);
		createKludges(msg->text, NULL, uplink->ourAka, &(uplink->hisAka));
		
		uplink->msg = msg;
	} else msg = uplink->msg;
	
	msg->text = realloc (msg->text, strlen(msg->text)+1+strlen(areatag)+1+1);
	
	if (act==0) {
	    if (getArea(config, areatag) == &(config->badArea)) {
		base = config->msgBaseDir;
		config->msgBaseDir = pass;
		autoCreate(areatag, uplink->hisAka, &(dwlink->hisAka));
		config->msgBaseDir = base;
	    }
	    strcat(msg->text,"+");
	} else strcat(msg->text,"-");
	strcat(msg->text,areatag);
	strcat(msg->text,"\r");
	
	return 0;	
}

int changeconfig(char *fileName, s_area *area, s_link *link, int action) {
	FILE *f;
	char *cfgline, *token, *running, *areaName, work=1;
	long pos;
	
	areaName = area->areaName;

	if ((f=fopen(fileName,"r+")) == NULL)
		{
			fprintf(stderr,"AreaFix: cannot open config file %s \n", fileName);
			return 1;
		}
	
	while (work) {
		pos = ftell(f);
		if ((cfgline = readLine(f)) == NULL) break;
		cfgline = trimLine(cfgline);
		if ((cfgline[0] != '#') && (cfgline[0] != 0)) {
			
			running = cfgline;
			token = strseparate(&running, " \t");
			
			if (stricmp(token, "include")==0) {
				while (*running=='\t') running++;
				token=strseparate(&running, " \t");
				changeconfig(token, area, link, action);
			}			
			else if (stricmp(token, "echoarea")==0) {
				token = strseparate(&running, " \t"); 
				if (stricmp(token, areaName)==0) {
				    switch 	(action) {
				    case 0: 
					if ((area->msgbType==MSGTYPE_PASSTHROUGH)
						&& (area->downlinkCount==1) &&
						(area->downlinks[0]->link->hisAka.point == 0)) {
					    forwardRequestToLink(areaName, area->downlinks[0]->link, NULL, 0);
					}
					addstring(f,aka2str(link->hisAka));
					break;
				    case 3: 
					addstring(f,aka2str(link->hisAka));
					break;
 				    case 1:	fseek(f, pos, SEEK_SET);
					if ((area->msgbType==MSGTYPE_PASSTHROUGH)
						&& (area->downlinkCount==1) &&
						(area->downlinks[0]->link->hisAka.point == 0)) {
					    forwardRequestToLink(areaName, area->downlinks[0]->link, NULL, 1);
					}
					delLinkFromArea(f, fileName, aka2str(link->hisAka));
/*					delstring(f,fileName,straka,1);*/
					break;
				    case 2:
//					makepass(f, fileName, areaName);
					break;
					default: break;
				    }
				    work = 0;
				}
			}
			
		}
		free(cfgline);
	}
	
	fclose(f);
	return 0;
}

int areaIsAvailable(char *areaName, char *fileName) {
	FILE *f;
	char *line, *token, *running;
	
	if ((f=fopen(fileName,"r")) == NULL)
		{
			fprintf(stderr,"areafix: cannot open forwardRequestFile \"%s\"\n",fileName);
			return 0;
		}

	while ((line = readLine(f)) != NULL) {
		line = trimLine(line);
		if (line[0] != '0') {
			
			running = line;
			token = strseparate(&running, " \t\r\n");
			
			if (stricmp(token, areaName)==0) {
				free(line);
				return 1;
			}			
			free(line);
		}
	}	
	
	// not found
	fclose(f);
	return 0;
}

int forwardRequest(char *areatag, s_link *dwlink) {
    int i;
    s_link *uplink;
	
    for (i = 0; i < config->linkCount; i++) {
		uplink = &(config->links[i]);
		if (uplink->forwardRequests) {
			
			if (uplink->forwardRequestFile!=NULL) {
				// first try to find the areatag in forwardRequestFile
				if (areaIsAvailable(areatag,uplink->forwardRequestFile)!=0) {
					forwardRequestToLink(areatag,uplink,dwlink,0);
					return 0;
				}
			} else {
				forwardRequestToLink(areatag,uplink,dwlink,0);
				return 0;
			}
		}
		
    }
	
	// link with "forwardRequests on" not found
	return 1;	
}

char *subscribe(s_link *link, s_message *msg, char *cmd) {
	int i, rc=4;
	char *line, *report, addline[256], logmsg[256];
	s_area *area;

	line = cmd;
	
	if (line[0]=='+') line++;
	
	report=(char*)calloc(1, sizeof(char));
	
	for (i=0; i<config->echoAreaCount; i++) {
	    rc=subscribeAreaCheck(&(config->echoAreas[i]),msg,line, link);
	    if (rc == 4) continue;
		
	    area = &(config->echoAreas[i]);
		
		switch (rc) {
		case 0: 
			sprintf(addline,"%s Already linked\r", area->areaName);
			sprintf(logmsg,"areafix: %s already linked to %s",
					aka2str(link->hisAka), area->areaName);
			writeLogEntry(hpt_log, '8', logmsg);
		    if (strstr(line, "*") == NULL) i = config->echoAreaCount;
        	break;
		case 1: 
			changeconfig (getConfigFileName(), area, link, 0);
			addlink(link, area);
			sprintf(addline,"%s Added\r",area->areaName);
			sprintf(logmsg,"areafix: %s subscribed to %s",aka2str(link->hisAka),area->areaName);
			writeLogEntry(hpt_log, '8', logmsg);
			if (strstr(line, "*") == NULL) i = config->echoAreaCount;
			break;
		default :
			sprintf(logmsg,"areafix: area %s -- no access for %s",
					area->areaName, aka2str(link->hisAka));
			writeLogEntry(hpt_log, '8', logmsg);
			continue;
//		break;
		}
	    report=(char*)realloc(report, strlen(report)+strlen(addline)+1);
	    strcat(report, addline);
	}
	
	if ((rc==4) && (strstr(line,"*") == NULL)) {
		// try to forward request
		if (forwardRequest(line, link)!=0)
			sprintf(addline,"%s no uplinks to forward\r",line);
		else {
			sprintf(addline,"%s request forwarded\r",line);
			sprintf(logmsg,"areafix: %s subscribed to area %s",aka2str(link->hisAka),line);
			writeLogEntry(hpt_log, '8', logmsg);
			area = getArea(config, line);
			changeconfig (getConfigFileName(), area, link, 3);
			addlink(link, area);
		}
		report=(char*) realloc(report, strlen(report)+strlen(addline)+1);
		strcat(report, addline);
	}
	
	if (*report == 0) {
	    sprintf(addline,"%s Not found\r",line);
	    sprintf(logmsg,"areafix: area %s is not found",line);
		writeLogEntry(hpt_log, '8', logmsg);
	    report=(char*)realloc(report, strlen(addline)+1);
	    strcpy(report, addline);
	}
	return report;
}

char *unsubscribe(s_link *link, s_message *msg, char *cmd) {
	int i, c, rc = 2;
	char *line, addline[256], logmsg[256];
	char *report=NULL;
	s_area *area;
	
	line = cmd;
	
	if (line[1]=='-') return NULL;
	line++;
	
	report=(char*)calloc(1, sizeof(char));
	
	for (i = 0; i< config->echoAreaCount; i++) {
		rc=subscribeAreaCheck(&(config->echoAreas[i]),msg,line, link);
		if ( rc==4 ) continue;
	
		area = &(config->echoAreas[i]);
		
		for (c = 0; c<area->downlinkCount; c++) {
		    if (link == area->downlinks[c]->link) {
			if (area->downlinks[c]->mandatory) rc=5;
			break;
		    }
		}
		if (area->mandatory) rc=5;
		
		
		switch (rc) {
		case 0: removelink(link, area);
			changeconfig (getConfigFileName(),  area, link, 1);
			sprintf(addline,"%s Unlinked\r",area->areaName);
			sprintf(logmsg,"areafix: %s unlinked from %s",aka2str(link->hisAka),area->areaName);
			writeLogEntry(hpt_log, '8', logmsg);
			break;
		case 1: if (strstr(line, "*")) continue;
			sprintf(addline,"%s Not linked\r",line);
			sprintf(logmsg,"areafix: area %s is not linked to %s",
					area->areaName, aka2str(link->hisAka));
			writeLogEntry(hpt_log, '8', logmsg);
			break;
		case 5: sprintf(addline,"%s Unlink is not possible\r", area->areaName);
			sprintf(logmsg,"areafix: area %s -- unlink is not possible for %s",
					area->areaName, aka2str(link->hisAka));
			writeLogEntry(hpt_log, '8', logmsg);
			break;
		default: sprintf(logmsg,"areafix: area %s -- no access for %s",
						 area->areaName, aka2str(link->hisAka));
			writeLogEntry(hpt_log, '8', logmsg);
			continue;
//			break;
		}
		
		report=(char*)realloc(report, strlen(report)+strlen(addline)+1);
		strcat(report, addline);
	}
	if (*report == 0) {
		sprintf(addline,"%s Not found\r",line);
		sprintf(logmsg,"areafix: area %s is not found", line);
		writeLogEntry(hpt_log, '8', logmsg);
		report=(char*)realloc(report, strlen(addline)+1);
		strcpy(report, addline);
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

int changepause(char *confName, s_link *link)
{
    char *cfgline, *token;
    char *line, logmsg[256];
    long curpos, endpos, cfglen;
    int rc;
    FILE *f_conf;
    
	if ((f_conf=fopen(confName,"r+")) == NULL)
		{
			fprintf(stderr,"areafix: cannot open config file %s \n", confName);
			return 1;
		}
	
    while ((cfgline = readLine(f_conf)) != NULL) {
		cfgline = trimLine(cfgline);
		if (*cfgline == 0 || *cfgline == '#') continue;
		line = cfgline;
		token = strseparate(&line, " \t");
		if (stricmp(token, "include")==0) {
			while (*line=='\t') line++;
			token=strseparate(&line, " \t");
			changepause(token, link);
		}			
		if (stricmp(token, "link") == 0) {
			free(cfgline);
			for (rc = 0; rc == 0; ) {
				fseek(f_conf, 0L, SEEK_CUR);
				curpos = ftell(f_conf);
				if ((cfgline = readLine(f_conf)) == NULL) { 
					rc = 2;
					break;
				}
				cfgline = trimLine(cfgline);
				if (!*cfgline || *cfgline == '#') continue;
				line = cfgline;
				token = strseparate(&line, " \t");
				if (stricmp(token, "link") == 0) {
					fseek(f_conf, curpos, SEEK_SET);
					rc = 1;
				}
				if (stricmp(token, "aka") == 0) break;
				free(cfgline);
			}
			if (rc == 2) return 0;
			if (rc == 1) continue;
			token = strseparate(&line, " \t");
			if (testAddr(token, link->hisAka)) {
				
				curpos = ftell(f_conf);
				
				fseek(f_conf, 0L, SEEK_END);
				endpos = ftell(f_conf);
				
				cfglen=endpos-curpos;
				
				line = (char*)calloc(cfglen+1, sizeof(char));
				fseek(f_conf, curpos, SEEK_SET);
				fread(line, sizeof(char), cfglen, f_conf);
		
				fseek(f_conf, curpos, SEEK_SET);
				fputs("Pause\n", f_conf);
				fputs(line, f_conf);
				free(line);
				free(cfgline);
				link->Pause = 1;
				sprintf(logmsg,"areafix: system %s set passive", aka2str(link->hisAka));
				writeLogEntry(hpt_log, '8', logmsg);
				break;
			}
		}
		free(cfgline);
    }
    fclose(f_conf);
    return 1;
}

char *pause_link(s_message *msg, s_link *link)
{
    char *tmp;
    char *report=NULL;
    
    if (link->Pause == 0) {
		if (changepause(getConfigFileName(), link) == 0) return NULL;    
    }

    report = linked(msg, link);
    tmp = (char*)calloc(80, sizeof(char));
    strcpy(tmp, " System switched to passive\r");
    tmp = (char*)realloc(tmp, strlen(report)+strlen(tmp)+1);
    strcat(tmp, report);
    free(report);
    return tmp;
}

int changeresume(char *confName, s_link *link)
{
    FILE *f_conf;
    char *cfgline, *line, *token, logmsg[256];
    int rc=0;
    long curpos, remstr, endpos, cfglen;
    
	if ((f_conf=fopen(confName,"r+")) == NULL)
		{
			fprintf(stderr,"areafix: cannot open config file %s \n", confName);
			return 1;
		}
    
    while ((cfgline = readLine(f_conf)) != NULL) {
		cfgline = trimLine(cfgline);
		if (*cfgline == 0 || *cfgline == '#') continue;
		line = cfgline;
		token = strseparate(&line, " \t");
		if (stricmp(token, "include")==0) {
			while (*line=='\t') line++;
			token=strseparate(&line, " \t");
			changeresume(token, link);
		}			
		if (stricmp(token, "link") == 0) {
			free(cfgline);
			for (rc = 0; rc == 0; ) {
				fseek(f_conf, 0L, SEEK_CUR);
				curpos = ftell(f_conf);
				if ((cfgline = readLine(f_conf)) == NULL) { 
					rc = 2;
					break;
				}
				if (*cfgline == 0 || *cfgline == '#') continue;
				line = cfgline;
				token = strseparate(&line, " \t");
				if (stricmp(token, "link") == 0) {
					fseek(f_conf, curpos, SEEK_SET);
					rc = 1;
				}
				if (stricmp(token, "aka") == 0) break;
				free(cfgline);
			}
			if (rc == 2) break;
			if (rc == 1) continue;
			token = strseparate(&line, " \t");
			if (testAddr(token, link->hisAka)) {
				free(cfgline);
				for (rc = 0; rc == 0; ) {
					fseek(f_conf, 0L, SEEK_CUR);
					curpos = ftell(f_conf);
					if ((cfgline = readLine(f_conf)) == NULL) {
						rc = 1;
						break;
					}
					cfgline = trimLine(cfgline);
					if (*cfgline == 0 || *cfgline == '#') continue;
					line = cfgline;
					token = strseparate(&line, " \t");
					if (stricmp(token, "link") == 0) {
						rc = 1;
						break;
					}
					if (stricmp(token, "pause") == 0) break;
					free(cfgline);
				}
				if (rc) break;
				
				remstr = ftell(f_conf);
				
				fseek(f_conf, 0L, SEEK_END);
				endpos = ftell(f_conf);
				
				cfglen=endpos-remstr;
				
				line = (char*)calloc(cfglen+1, sizeof(char));
				fseek(f_conf, remstr, SEEK_SET);
				cfglen = fread(line, sizeof(char), (size_t) cfglen, f_conf);
				
				fseek(f_conf, curpos, SEEK_SET);
//				fputs(line, f_conf);
				fwrite(line, sizeof(char), (size_t) cfglen, f_conf);
#ifdef __WATCOMC__
				fflush( f_conf );
				fTruncate( fileno(f_conf), endpos-(remstr-curpos) );
				fflush( f_conf );
#else
				truncate(confName, endpos-(remstr-curpos));
#endif
				free(line);
				free(cfgline);
				link->Pause = 0;
				sprintf(logmsg,"areafix: system %s set active",	aka2str(link->hisAka));
				writeLogEntry(hpt_log, '8', logmsg);
				break;
    	    }
		}
		free(cfgline);
    }
    fclose(f_conf);
    if (rc) return 0;
    return 1;
}

char *resume_link(s_message *msg, s_link *link)
{
    char *tmp, *report=NULL;
    
    if (link->Pause) {
		if (changeresume(getConfigFileName(), link) == 0) return NULL;
    }
	
    report = linked(msg, link);
    tmp = (char*)calloc(80, sizeof(char));
    strcpy(tmp, " System switched to active\r");
    tmp = (char*)realloc(tmp, strlen(report)+strlen(tmp)+1);
    strcat(tmp, report);
    free(report);
    return tmp;
}

char *info_link(s_message *msg, s_link *link)
{
    char buff[256], *report, *ptr, linkAka[25];
    char hisAddr[]="Your address: ";
    char ourAddr[]="AKA used here: ";
    char Arch[]="Compression: ";
    int i;
    
	sprintf(linkAka,aka2str(link->hisAka));
    sprintf(buff, "Here is some information about our link:\r\r %s%s\r%s%s\r  %s", hisAddr, linkAka, ourAddr, aka2str(*link->ourAka), Arch);
	
    report = (char*)calloc(strlen(buff)+1, sizeof(char));
    strcpy(report, buff);
    
    if (link->packerDef==NULL) sprintf(buff, "No packer (");
    else sprintf(buff, "%s (", link->packerDef->packer);
    
    report = (char*)realloc(report, strlen(report)+strlen(buff)+1);
    strcat(report, buff);
    
    for (i=0; i < config->packCount; i++) {
        report = (char*)realloc(report, strlen(report)+strlen(config->pack[i].packer)+3);
        strcat(report, config->pack[i].packer);
        strcat(report, ", ");
    }
    
    report[strlen(report)-2] = ')';
    report[strlen(report)-1] = '\r';
	
    if (link->Pause) sprintf(buff, "\rYour system is passive\r");
    else sprintf(buff, "\rYour system is active\r");
    
    ptr = linked(msg, link);
    report = (char*)realloc(report, strlen(report)+strlen(ptr)+strlen(buff)+1);
    strcat(report, buff);
    strcat(report, ptr);
    free(ptr);
    sprintf(buff,"areafix: link information sent to %s", aka2str(link->hisAka));
    writeLogEntry(hpt_log, '8', buff);
    return report;
}

void repackEMMsg(HMSG hmsg, XMSG xmsg, s_area *echo, s_link *link)
{
   s_message    msg;
   UINT32       j=0;
   s_pktHeader  header;
   FILE         *pkt;
   
   makeMsg(hmsg, xmsg, &msg, echo, 1);

   //translating name of the area to uppercase
   while (msg.text[j] != '\r') {msg.text[j]=toupper(msg.text[j]);j++;}

   // link is passive?
   if (link->Pause && !echo->noPause) return;
   // check access read for link
   if (readCheck(echo, link)) return;
      if (link->pktFile == NULL) {
		   
	  // pktFile does not exist
	  if ( createTempPktFileName(link) ) {
		  writeLogEntry(hpt_log, '9', "Could not create new pkt.");
		  printf("Could not create new pkt.\n");
		  disposeConfig(config);
		  closeLog(hpt_log);
		  exit(1);
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

void rescanEMArea(s_area *echo, s_link *link)
{
   HAREA area;
   HMSG  hmsg;
   XMSG  xmsg;
   char  buff[50];
   dword highWaterMark, highestMsg, i;
   
   area = MsgOpenArea((UCHAR *) echo->fileName, MSGAREA_NORMAL, echo->msgbType | MSGTYPE_ECHO);
   if (area != NULL) {
      i = highWaterMark = MsgGetHighWater(area);
      highestMsg    = MsgGetHighMsg(area);

      while (i <= highestMsg) {
         hmsg = MsgOpenMsg(area, MOPEN_RW, i++);
         if (hmsg == NULL) continue;      // msg# does not exist
         MsgReadMsg(hmsg, &xmsg, 0, 0, NULL, 0, NULL);
         repackEMMsg(hmsg, xmsg, echo, link);

         MsgCloseMsg(hmsg);
      }

      MsgSetHighWater(area, i);

      MsgCloseArea(area);
   } else {
      sprintf(buff, "Could not open %s", echo->fileName);
      writeLogEntry(hpt_log, '9', buff);
   } /* endif */
}

char *rescan(s_link *link, s_message *msg, char *cmd)
{
    int i, c, rc;
    char *report, *line, addline[256], logmsg[256];
    s_area *area, **areas=NULL;
    
    line = cmd;
    
    report = strseparate(&line, " \t");
    
    report = (char*)calloc(1, sizeof(char));
    
    for (i=c=0; i<config->echoAreaCount; i++) {
		rc=subscribeAreaCheck(&(config->echoAreas[i]),msg,line, link);
		if (rc == 4) continue;
	    
		area = &(config->echoAreas[i]);
		
		switch (rc) {
		case 0: 
			if (area->msgbType == MSGTYPE_PASSTHROUGH) {
				sprintf(addline,"%s No rescan possible\r", area->areaName);
				sprintf(logmsg,"areafix: %s area no rescan possible to %s",
						area->areaName, aka2str(link->hisAka));
				writeLogEntry(hpt_log, '8', logmsg);
			} else {
				sprintf(addline,"%s Rescanned\r", area->areaName);
				sprintf(logmsg,"areafix: %s rescan area to %s",
						area->areaName, aka2str(link->hisAka));
				writeLogEntry(hpt_log, '8', logmsg);
				c++;
				areas = (s_area**)realloc(areas, c*sizeof(s_area*));
				areas[c-1] = area;
			}
			break;
		case 1: if (strstr(line, "*")) continue;
			sprintf(logmsg,"areafix: %s area not linked for rescan to %s",
					area->areaName, aka2str(link->hisAka));
			writeLogEntry(hpt_log, '8', logmsg);
			sprintf(addline,"%s Not linked for rescan\r", area->areaName);
			break;
		default: sprintf(logmsg,"areafix: %s area not access for %s",
						 area->areaName, aka2str(link->hisAka));
			writeLogEntry(hpt_log, '8', logmsg);
			continue;
//		break;
		}
		report=(char*)realloc(report, strlen(report)+strlen(addline)+1);
		strcat(report, addline);
	}
    if (*report == 0) {
		sprintf(addline,"%s Not linked for rescan\r", line);
//        sprintf(addline,"%s Not found for rescan\r",line);
//        sprintf(logmsg,"areafix: %s area not linked for rescan", line);
//        writeLogEntry(hpt_log, '8', logmsg);
		report=(char*)realloc(report, strlen(addline)+1);
		strcpy(report, addline);
    }
    if (c) {
		for (i = 0; i < c; i++) rescanEMArea(areas[i], link);
		arcmail();
    }
    free(areas);
    return report;
}

int tellcmd(char *cmd) {
	char *line;
	
	line = cmd;

	switch (line[0]) {
	case '%': 
		line++;
		if (stricmp(line,"list")==0) return 1;
		if (stricmp(line,"help")==0) return 2;
		if (stricmp(line,"avail")==0) return 5;
		if (stricmp(line,"available")==0) return 5;
		if (stricmp(line,"all")==0) return 5;
		if (stricmp(line,"unlinked")==0) return 6;
		if (stricmp(line,"pause")==0) return 7;
		if (stricmp(line,"resume")==0) return 8;
		if (stricmp(line,"info")==0) return 9;
		if (strncasesearch(line, "rescan", 6)==0) return 10;
		break;
	case '\001': return 0;
	case '\000': return 0;
	case '-'  : return 4;
	case '+': line++; if (line[0]=='\000') return 0;
	default: return 3;
	}
	
	return 0;
}

char *processcmd(s_link *link, s_message *msg, char *line, int cmd) {
	
	char *report;
	
	switch (cmd) {
	case 1:	report = list (msg, link);
		RetFix=LIST;
		break;
	case 2:	report = help (link);
		RetFix=HELP;
		break;
	case 3: report = subscribe (link,msg,line);
		RetFix=ADD;
		break;
	case 4: report = unsubscribe (link,msg,line);
		RetFix=DEL;
		break;
	case 5: report = available (link); 
		RetFix=AVAIL;
		break;
	case 6: report = unlinked (msg, link);
		RetFix=UNLINK;
		break;
	case 7: report = pause_link (msg, link);
		RetFix=PAUSE;
		break;
	case 8: report = resume_link (msg, link);
		RetFix=RESUME;
		break;
	case 9: report = info_link(msg, link);
		RetFix=INFO;
		break;
	case 10: report = rescan(link, msg, line);
		RetFix=RESCAN;
		break;
	default: return NULL;
	}
	
	return report;
}

char *areastatus(char *preport, char *text)
{
    char *pth, *ptmp, *tmp, *report, tmpBuff[256];
    pth = (char*)calloc(1, sizeof(char));
    tmp = preport;
    ptmp = strchr(tmp, '\r');
    while (ptmp) {
		*(ptmp++)=0;
        report=strchr(tmp, ' ');
		*(report++)=0;
        if (strlen(tmp) > 50) tmp[50] = 0;
		if (50-strlen(tmp) == 0) sprintf(tmpBuff, " %s  %s\r", tmp, report);
        else if (50-strlen(tmp) == 1) sprintf(tmpBuff, " %s   %s\r", tmp, report);
		else sprintf(tmpBuff, " %s %s  %s\r", tmp, print_ch(50-strlen(tmp)-1, '.'), report);
        pth=(char*)realloc(pth, strlen(tmpBuff)+strlen(pth)+1);
		strcat(pth, tmpBuff);
		tmp=ptmp;
		ptmp = strchr(tmp, '\r');
    }
    tmp = (char*)calloc(strlen(pth)+strlen(text)+1, sizeof(char));
    strcpy(tmp, text);
    strcat(tmp, pth);
    free(text);
    free(pth);
    return tmp;
}

void preprocText(char *preport, s_message *msg)
{
    char *text, tmp[80], kludge[100];
	
    sprintf(tmp, " \r--- %s areafix\r", versionStr);
	createKludges(kludge, NULL, &msg->origAddr, &msg->destAddr);
    text=(char*) malloc(strlen(kludge)+strlen(preport)+strlen(tmp)+1);
    strcpy(text, kludge);
    strcat(text, preport);
    strcat(text, tmp);
    msg->textLength=(int)strlen(text);
    msg->text=text;
}

char *textHead()
{
    char *text_head, tmpBuff[256];
    
    sprintf(tmpBuff, " Area%sStatus\r",	print_ch(48,' '));
	sprintf(tmpBuff+strlen(tmpBuff)," %s  -------------------------\r",print_ch(50, '-')); 
    text_head=(char*)calloc(strlen(tmpBuff)+1, sizeof(char));
    strcpy(text_head, tmpBuff);
    return text_head;
}

void RetMsg(s_message *tmpmsg, s_message *msg, s_link *link, char *report, char *subj)
{
    char *tab;
    
    memcpy(tmpmsg, msg, sizeof(s_message));
    changeHeader(tmpmsg,link,subj);
    preprocText(report, tmpmsg);
    
    tab = config->intab;
    
    if (RetFix == AVAIL) {
	config->intab = NULL;
    }
    
    processNMMsg(tmpmsg, NULL);
    
    config->intab = tab;
    
    free(tmpmsg->text);
    free(tmpmsg->subjectLine);
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-


int processAreaFix(s_message *msg, s_pktHeader *pktHeader)
{
	int i, security=1, notforme = 0;
	s_link *link = NULL;
	s_link *tmplink = NULL;
	s_message *linkmsg, tmpmsg;
	s_pktHeader header;
	char tmp[80], *token, *textBuff, *report=NULL, *preport;
	
	// load recoding tables
	if (config->outtab != NULL) getctab(outtab, config->outtab);

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
	link=getLinkFromAddr(*config, pktHeader->origAddr);
	
	// this is for me?
	if (link!=NULL)	notforme=addrComp(msg->destAddr, *link->ourAka);
	else security=4; // link == NULL;
	
	// ignore msg for other link (maybe this is transit...)
	if (notforme) {
		processNMMsg(msg, pktHeader);
		return 0;
	}
	
	// 2nd security ckeck. link, araefixing & password.
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
			preport = processcmd( link, msg, token, tellcmd (token) );
			if (preport != NULL) {
				switch (RetFix) {
				case LIST:
					RetMsg(&tmpmsg, msg, link, preport, "list request");
					break;
				case HELP:
					RetMsg(&tmpmsg, msg, link, preport, "help request");
					break;
				case ADD:
					if (report == NULL) report = textHead();
					report = areastatus(preport, report);
					break;
				case DEL:
					if (report == NULL) report = textHead();
					report = areastatus(preport, report);
					break;
				case AVAIL:
					RetMsg(&tmpmsg, msg, link, preport, "available areas");
					break;
				case UNLINK:
					RetMsg(&tmpmsg, msg, link, preport, "unlinked request");
					break;
				case PAUSE:
					RetMsg(&tmpmsg, msg, link, preport, "node change request");
					break;
				case RESUME:
					RetMsg(&tmpmsg, msg, link, preport, "node change request");
					break;
				case INFO:
					RetMsg(&tmpmsg, msg, link, preport, "link information");
					break;
				case RESCAN:
					if (report == NULL) report=textHead();
 					report=areastatus(preport, report);
 					break;
				default: break;
				}
				
				free(preport);
			}
			token = strseparate (&textBuff, "\n\r");
		}
		
	} else {

		if (link == NULL) {
			tmplink = (s_link*)calloc(1, sizeof(s_link));
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
			sprintf(tmp, " \r different pkt and msg addresses\r");
			break;
		case 2:
			sprintf(tmp, " \r areafix is turned off\r");
			break;
		case 3:
			sprintf(tmp, " \r password error\r");
			break;
		case 4:
			sprintf(tmp, " \r your system is unknown\r");
			break;
		default:
			sprintf(tmp, " \r unknown error. mail to sysop.\r");
			break;
		}
		
		report=(char*) malloc(strlen(tmp)+1);
		strcpy(report,tmp);
		
		RetMsg(&tmpmsg, msg, link, report, "security violation");
		free(report);
		
		sprintf(tmp,"areafix: security violation from %s", aka2str(link->hisAka));
		writeLogEntry(hpt_log, '8', tmp);
		
		free(tmplink);
		
		return 1;
	}

	if ( report != NULL ) {
		preport=linked(msg, link);
		report=(char*)realloc(report, strlen(report)+strlen(preport)+1);
		strcat(report, preport);
		free(preport);
		RetMsg(&tmpmsg, msg, link, report, "node change request");
		free(report);
	}
	
	sprintf(tmp,"areafix: sucessfully done for %s",aka2str(link->hisAka));
	writeLogEntry(hpt_log, '8', tmp);
	
	// send msg to the links (forward requests to areafix)
	for (i = 0; i < config->linkCount; i++) {
		if (config->links[i].msg == NULL) continue;
		link = &(config->links[i]);
		linkmsg = link->msg;
		
		sprintf(tmp, " \r--- %s areafix\r", versionStr);
		linkmsg->text=(char*) realloc(linkmsg->text,strlen(linkmsg->text)+strlen(tmp)+1);
		strcat(linkmsg->text, tmp);
		linkmsg->textLength = strlen(linkmsg->text);
		
		makePktHeader(NULL, &header);
		header.origAddr = *(link->ourAka);
		header.destAddr = link->hisAka;
		
		sprintf(tmp,"areafix: write netmail msg for %s", aka2str(link->hisAka));
		writeLogEntry(hpt_log, '8', tmp);

		processNMMsg(linkmsg, &header);

		freeMsgBuffers(linkmsg);
		free(linkmsg);
		linkmsg = NULL;
	}
	
	return 0;
}

void MsgToStruct(HMSG SQmsg, XMSG xmsg, s_message *msg)
{
    // convert header
    msg->attributes  = xmsg.attr;

    msg->origAddr.zone  = xmsg.orig.zone;
    msg->origAddr.net   = xmsg.orig.net;
    msg->origAddr.node  = xmsg.orig.node;
    msg->origAddr.point = xmsg.orig.point;
    msg->origAddr.domain =  NULL;

    msg->destAddr.zone  = xmsg.dest.zone;
    msg->destAddr.net   = xmsg.dest.net;
    msg->destAddr.node  = xmsg.dest.node;
    msg->destAddr.point = xmsg.dest.point;
    msg->destAddr.domain = NULL;

    strcpy(msg->datetime, (char *) xmsg.__ftsc_date);
    msg->subjectLine = (char *) malloc(strlen((char *)xmsg.subj)+1);
    msg->toUserName  = (char *) malloc(strlen((char *)xmsg.to)+1);
    msg->fromUserName = (char *) malloc(strlen((char *)xmsg.from)+1);
    strcpy(msg->subjectLine, (char *) xmsg.subj);
    strcpy(msg->toUserName, (char *) xmsg.to);
    strcpy(msg->fromUserName, (char *) xmsg.from);

    msg->textLength = MsgGetTextLen(SQmsg);
    msg->text = (char *)calloc(msg->textLength+1, sizeof(char));
    MsgReadMsg(SQmsg, NULL, 0, msg->textLength, (unsigned char *) msg->text, 0, NULL);

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
    
    netmail = MsgOpenArea((unsigned char *) config->netMailArea.fileName, MSGAREA_NORMAL, config->netMailArea.msgbType);
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
		    MsgToStruct(SQmsg, xmsg, &msg);
		    processAreaFix(&msg, NULL);
		    xmsg.attr |= MSGREAD;
		    MsgWriteMsg(SQmsg, 0, &xmsg, NULL, 0, 0, 0, NULL);
		    freeMsgBuffers(&msg);
	    }

	    MsgCloseMsg(SQmsg);

	} /* endfor */

//	writeMsgToSysop(msgToSysop);
	MsgCloseArea(netmail);
    } else {
		writeLogEntry(hpt_log, '9', "Could not open NetmailArea");
    } /* endif */
}
