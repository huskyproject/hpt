/*:ts=8*/
/*****************************************************************************
 * AreaFix for HPT (FTN NetMail/EchoMail Tosser)
 *****************************************************************************
 * Copyright (C) 1998-1999
 *
 * Max Levenkov
 *
 * Fido:     2:5000/117
 * Internet: ml@online.nsk.su
 * Novosibirsk, Russia
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
#include <scan.h>
#include <areafix.h>

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

	if (aka.point!=0) sprintf(straka,"%u:%u/%u.%u",aka.zone,aka.net,aka.node,aka.point);
	else sprintf(straka,"%u:%u/%u",aka.zone,aka.net,aka.node);
	
	return straka;
}	

int restricted (char *TossGrp, char group) {
	
	if ((group!='\060') && (TossGrp==NULL)) return 1;
	if ((group!='\060') && (TossGrp!=NULL)) {
		if (strchr(TossGrp,group)==NULL) return 1;
	}
	
	// not restricted
	return 0;
}

int subscribeCheck(s_area area, s_message *msg) {
  int i;
  
  for (i = 0; i<area.downlinkCount;i++) {
    if (addrComp(msg->origAddr, area.downlinks[i]->hisAka)==0) return 0;
  }
  
  return 1;
}

int subscribeAreaCheck(s_area *area, s_message *msg, char *areaname) {
   int rc;

   if (patimat(area->areaName,areaname)==1) {
     rc=subscribeCheck(*area, msg);
     // 0 - already subscribed
     // 1 - need subscribe
   } else rc = 2;
   
   // this is another area
   return rc;
}

// add string to file
int addstring(FILE *f, char *aka) {
	char *cfg;
	long areapos,endpos,cfglen;
	
	//current position
	fseek(f,-1,SEEK_CUR);
	areapos=ftell(f);
	
	// end of file
	fseek(f,0l,SEEK_END);
	endpos=ftell(f);
	cfglen=endpos-areapos;
	
	// storing end of file...
	cfg = (char*) calloc((size_t) cfglen+1, sizeof(char));
	fseek(f,-cfglen,SEEK_END);
	fread(cfg,sizeof(char),(size_t) cfglen,f);
	
	// write config
	fseek(f,-cfglen,SEEK_END);
	fputs(" ",f);
	fputs(aka,f);
	fputs(cfg,f);
	
	free(cfg);
	return 0;
}

int delstring(FILE *f, char *fileName, char *aka, int before_str) {
	int al,i=1;
	char *cfg, c, j='\040';
	long areapos,endpos,cfglen;

	al=strlen(aka);

	// search for the aka string
	while ((i!=0) && ((j!='\040') || (j!='\011'))) {
		for (i=al; i>0; i--) {
			fseek(f,-2,SEEK_CUR);
			c=fgetc(f);
			if (aka[i-1]!=tolower(c)) {j = c; break;}
		}
	}
	
	//current position
	areapos=ftell(f);

	// end of file
	fseek(f,0l,SEEK_END);
	endpos=ftell(f);
	cfglen=endpos-areapos-al;
	
	// storing end of file...
	cfg=(char*) calloc((size_t) cfglen+1,sizeof(char));
	fseek(f,-cfglen-1,SEEK_END);
	fread(cfg,sizeof(char),(size_t) (cfglen+1),f);
	
	// write config
	fseek(f,-cfglen-al-1-before_str,SEEK_END);
	fputs(cfg,f);

	truncate(fileName,endpos-al-before_str);
	
	fseek(f,areapos-1,SEEK_SET);

	free(cfg);
	return 0;
}

int removeMsgBase(char *fileName, char *ext) {
	char *msgBase, logmsg[80];

	msgBase = (char*) malloc (strlen(fileName)+strlen(ext)+1);
	sprintf(msgBase,"%s%s",fileName,ext);

	if (fexist(msgBase)) {
		if (remove(msgBase)==0) {
			sprintf(logmsg,"msgbase '%s' deleted",msgBase);
			fprintf(stdout, "%s\n", logmsg);
			writeLogEntry(log, '8', logmsg);
		} else {
			sprintf(logmsg,"unable to delete msgbase '%s' !!!",msgBase);
			fprintf(stderr, "%s\n", logmsg);
			writeLogEntry(log, '8', logmsg);
		}
	}

	free(msgBase);
	return 0;
}

int makepass(FILE *f, char *fileName, char *areaName) {
	s_area *area;
	char logmsg[80];

	area = getArea(config, areaName);

	if (area->msgbType == MSGTYPE_SQUISH) delstring(f, fileName, "squish", 1);

	if (area->msgbType == MSGTYPE_PASSTHROUGH) {
		sprintf(logmsg,"Area '%s' already passthrough",area->areaName);
		fprintf(stderr, "%s\n", logmsg);
		writeLogEntry(log, '8', logmsg);
	} else {
		delstring(f, fileName, area->fileName, 1);
		addstring(f, "passthrough");
		sprintf(logmsg,"Area '%s' moved to passthrough",area->areaName);
		fprintf(stdout, "%s\n", logmsg);
		writeLogEntry(log, '8', logmsg);

		removeMsgBase(area->fileName,".sqd");
		removeMsgBase(area->fileName,".sqi");
		removeMsgBase(area->fileName,".sql");
	}
	
	return 0;
}

void removelink (s_link *link, s_area *area) {
	int i;
	s_link *links;

	for (i=0; i < area->downlinkCount; i++) {
           links = area->downlinks[i];
           if (addrComp(link->hisAka, links->hisAka)==0) break;
	}
	
	area->downlinks[i] = area->downlinks[area->downlinkCount-1];
	area->downlinkCount--;
}

char *linked(s_message *msg, s_link *link)
{
    int i, n, rc;
	s_area *area;
    char *report, addline[256];
	
    if (link->Pause) sprintf(addline, "\rPassive areas on %s\r\r", aka2str(link->hisAka));
    else sprintf(addline, "\rActive areas on %s\r\r", aka2str(link->hisAka));
							
    report=(char*) malloc(strlen(addline)+1);
    strcpy(report, addline);
    
    for (i=n=0; i<config->echoAreaCount; i++) {
		rc=subscribeCheck(config->echoAreas[i], msg);
		if (!rc) {
			area = &(config->echoAreas[i]);
			report=(char*)realloc(report,strlen(report)+strlen(area->areaName)+3);
			strcat(report, " ");
			strcat(report, area->areaName);
			strcat(report, "\r");
			n++;
		}
    }
    sprintf(addline, "\r%u areas linked\r", n);
    report=(char*)realloc(report, strlen(report)+strlen(addline)+1);
    strcat(report, addline);
    return report;
}

int testAddr(char *addr, s_addr hisAka)
{
    s_addr aka;
    string2addr(addr, &aka);
    if (addrComp(aka, hisAka)==0) return 1;
    return 0;
}

char *pause_link(s_message *msg, s_link *link)
{
    FILE *f_conf;
    char *confName, *cfgline, *ptr, logmsg[256], *report=NULL;
    int rc;
    long curpos, endpos, cfglen;
    
    if (link->Pause == 0) {
		
        confName = getConfigFileName();
		
		f_conf = fopen(confName, "r+");
        if (!f_conf) {
			fprintf(stderr, "areafix: cannot open config file %s \n", confName);
			return NULL;
		}
		
        while ((cfgline = readLine(f_conf)) != NULL) {
			cfgline = trimLine(cfgline);
			if (strncasesearch(cfgline, "Link", 4) == 0) {
				free(cfgline);
				for (rc = 0; rc == 0; ) {
					fseek(f_conf, 0L, SEEK_CUR);
					curpos = ftell(f_conf);
					if ((cfgline = readLine(f_conf)) == NULL) { 
						rc = 2;
						break;
					}
					cfgline = trimLine(cfgline);
					if (strncasesearch(cfgline, "Link", 4) == 0) {
						fseek(f_conf, curpos, SEEK_SET);
						rc = 1;
					}
					if (strncasesearch(cfgline, "AKA", 3) == 0) break;
					free(cfgline);
				}
				if (rc == 2) return NULL;
				if (rc == 1) continue;
				ptr = cfgline;
				while (*ptr != ' ' && *ptr != '\t' && *ptr) ptr++;
				if (*ptr) ptr++;
				if (testAddr(ptr, link->hisAka)) {
					
					curpos = ftell(f_conf);
					
					fseek(f_conf, 0L, SEEK_END);
					endpos = ftell(f_conf);
					
					cfglen=endpos-curpos;
					
					ptr = (char*)calloc(cfglen+1, sizeof(char));
					fseek(f_conf, curpos, SEEK_SET);
					fread(ptr, sizeof(char), cfglen, f_conf);
					
					fseek(f_conf, curpos, SEEK_SET);
					fputs("Pause\n", f_conf);
					fputs(ptr, f_conf);
					free(ptr);
					free(cfgline);
					link->Pause = 1;
					sprintf(logmsg,"areafix: system %s set is passive",aka2str(link->hisAka));
					writeLogEntry(log, '8', logmsg);
					break;
				}
			}
			free(cfgline);
		}
		fclose(f_conf);
    }
    report = linked(msg, link);
    ptr = (char*)calloc(80, sizeof(char));
    strcpy(ptr, " System switched passive\r");
    ptr = (char*)realloc(ptr, strlen(report)+strlen(ptr)+1);
    strcat(ptr, report);
    free(report);
    return ptr;
}

char *resume_link(s_message *msg, s_link *link)
{
    FILE *f_conf;
    char *confName, *cfgline, *ptr, logmsg[256], *report=NULL;
    int rc;
    long curpos, remstr, endpos, cfglen;
    
    if (link->Pause) {
		
        confName = getConfigFileName();
		
		f_conf = fopen(confName, "r+");
        if (!f_conf) {
			fprintf(stderr, "areafix: cannot open config file %s \n", confName);
			return NULL;
		}
		
        while ((cfgline = readLine(f_conf)) != NULL) {
			cfgline = trimLine(cfgline);
			if (strncasesearch(cfgline, "Link", 4) == 0) {
				free(cfgline);
				for (rc = 0; rc == 0; ) {
					fseek(f_conf, 0L, SEEK_CUR);
					curpos = ftell(f_conf);
					if ((cfgline = readLine(f_conf)) == NULL) { 
						rc = 2;
						break;
					}
					if (strncasesearch(cfgline, "Link", 4) == 0) {
						fseek(f_conf, curpos, SEEK_SET);
						rc = 1;
					}
					if (strncasesearch(cfgline, "AKA", 3) == 0) break;
					free(cfgline);
				}
				if (rc == 2) break;
				if (rc == 1) continue;
				ptr = cfgline;
				while (*ptr != ' ' && *ptr != '\t' && *ptr) ptr++;
				if (*ptr) ptr++;
				if (testAddr(ptr, link->hisAka)) {
					
					for (rc = 0; rc == 0; ) {
						fseek(f_conf, 0L, SEEK_CUR);
						curpos = ftell(f_conf);
						if ((cfgline = readLine(f_conf)) == NULL) {
							rc = 1;
							break;
						}
						cfgline = trimLine(cfgline);
						if (strncasesearch(cfgline, "Link", 4) == 0) {
							rc = 1;
							break;
						}
						if (strncasesearch(cfgline, "Pause", 5) == 0) break;
						free(cfgline);
					}
					if (rc) break;
					
					remstr = ftell(f_conf);
					
					fseek(f_conf, 0L, SEEK_END);
					endpos = ftell(f_conf);
					
					cfglen=endpos-remstr;
					
					ptr = (char*)calloc(cfglen+1, sizeof(char));
					fseek(f_conf, remstr, SEEK_SET);
					fread(ptr, sizeof(char), cfglen, f_conf);
					
					fseek(f_conf, curpos, SEEK_SET);
					fputs(ptr, f_conf);
					truncate(confName, endpos-(remstr-curpos));
					free(ptr);
					free(cfgline);
					link->Pause = 0;
					sprintf(logmsg,"areafix: system %s set is active",aka2str(link->hisAka));
					writeLogEntry(log, '8', logmsg);
					break;
				}
			}
			free(cfgline);
		}
		fclose(f_conf);
    }
    report = linked(msg, link);
    ptr = (char*)calloc(80, sizeof(char));
    strcpy(ptr, " System switched active\r");
    ptr = (char*)realloc(ptr, strlen(report)+strlen(ptr)+1);
    strcat(ptr, report);
    free(report);
    return ptr;
}

char *list(s_message *msg, s_link *link) {
	
	int i,n1,n2,rc;
	char *report, addline[256];
	s_area *area;

	sprintf(addline, "Available areas for %s\r\r", aka2str(link->hisAka));

	report=(char*)calloc(strlen(addline)+1,sizeof(char));
	strcpy(report, addline);
	
	for (i=0,n1=n2=0; i< config->echoAreaCount; i++) {
		
		area = &(config->echoAreas[i]);

		if (area->hide==1) continue; // do not display hidden areas..
		if (restricted(link->TossGrp, area->group)!=0) continue;
		
		report=(char*) realloc(report, strlen(report)+strlen(area->areaName)+4);
		rc=subscribeCheck(*area, msg);
		if (!rc) {
			strcat(report,"* ");
			n1++;
		} else strcat(report,"  ");
		strcat(report, area->areaName);
		strcat(report,"\r");
		n2++;
	}
	
	sprintf(addline,"\r'*' = area active for %s\r%i areas available, %i areas active\r",
			aka2str(link->hisAka), n2, n1);
	report=(char*) realloc(report, strlen(report)+strlen(addline)+1);
	strcat(report, addline);
	
	sprintf(addline,"areafix: list sent to %s", aka2str(link->hisAka));
	writeLogEntry(log, '8', addline);

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
		
		help=(char*) calloc((size_t) endpos,sizeof(char));

		fseek(f,0l,SEEK_SET);
		fread(help,1,(size_t) endpos,f);
		
		for (i=0; i<endpos; i++) if (help[i]=='\n') help[i]='\r';

		fclose(f);

		sprintf(addline,"areafix: help sent to %s",link->name);
		writeLogEntry(log, '8', addline);

		return help;
	}

	return NULL;
}

int delarea(FILE *f, char *fileName, char *echoarea) {
	int al,i=1;
	char *cfg, c, j='\040';
	long areapos,newareapos,endpos,cfglen;
	
	//current position
	areapos=ftell(f);

	// end of file
	fseek(f,0l,SEEK_END);
	endpos=ftell(f);
	cfglen=endpos-areapos;

	// storing end of file...
	cfg=(char*) calloc((size_t) cfglen+1,sizeof(char));
	fseek(f,-cfglen,SEEK_END);
	fread(cfg,sizeof(char),(size_t) cfglen,f);
	

	// find "echoarea"
	al=strlen(echoarea);
	fseek(f,areapos,SEEK_SET);
	
	// search for the aka string
	while ((i!=0) && ((j!='\040') || (j!='\011'))) {
		for (i=al; i>0; i--) {
			fseek(f,-2,SEEK_CUR);
			c=fgetc(f);
			if (echoarea[i-1]!=tolower(c)) {j = c; break;}
		}
	}

	newareapos=ftell(f);

	// write config
	fseek(f,-1,SEEK_CUR);
	fputs(cfg,f);

	truncate(fileName,newareapos+cfglen-1);
	
//	fseek(f,areapos-1,SEEK_SET);

	free(cfg);
	return 0;
}

// subscribe if (act==0),  unsubscribe if (act!=0)
int forwardRequestToLink (char *areatag, char *aka, s_link *uplink, int act) {
    time_t t;
    struct tm *tm;
    s_message *msg;
	char *autocreateDef, *linkDef;

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
		
		msg->text = (char *) malloc(100);
		createKludges(msg->text, NULL, uplink->ourAka, &(uplink->hisAka));
	
		uplink->msg = msg;
	} else msg = uplink->msg;
	
	msg->text = realloc (msg->text, strlen(msg->text)+1+strlen(areatag)+1+1);

	if (act==0) {
		strcat(msg->text,"+");
		// add aka to autocreateDefaults
		if (uplink->autoCreateDefaults!=NULL) {
			autocreateDef = (char *) calloc(1,strlen(uplink->autoCreateDefaults)+1+strlen(aka)+1);
			strcat(autocreateDef,uplink->autoCreateDefaults);	
			strcat(autocreateDef," ");
		} 
		else autocreateDef = (char *) calloc(1,strlen(aka)+1);
		linkDef = uplink->autoCreateDefaults;
		strcat(autocreateDef,aka);
		uplink->autoCreateDefaults = autocreateDef;
		autoCreate(areatag, msg->destAddr);
		uplink->autoCreateDefaults = linkDef;
		free(autocreateDef);
	} else strcat(msg->text,"-");
	strcat(msg->text,areatag);
	strcat(msg->text,"\r");
	
	return 0;	
}

int changeconfig(char *fileName, s_area *area, s_link *link, int action) {
	FILE *f;
	char *cfgline, *token, *running, *areaName;

	if ((f=fopen(fileName,"r+")) == NULL)
		{
			fprintf(stderr,"areafix: cannot open config file %s \n", fileName);
			return 1;
		}

	areaName = area->areaName;
	
	while ((cfgline = readLine(f)) != NULL) {
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
				if (stricmp(token, areaName)==0)
					switch 	(action) {
					case 0: 
						addstring(f, aka2str(link->hisAka));
						break;
 					case 1:
						if ((area->msgbType==MSGTYPE_PASSTHROUGH) && (area->downlinkCount<=1)) {
							delarea(f,fileName,"echoarea");
							forwardRequestToLink(areaName, NULL, area->downlinks[0], 1);
							free(cfgline);
							fclose(f);
							return 0;
						} else delstring(f, fileName, aka2str(link->hisAka), 1);
						break;
					case 2:
						makepass(f, fileName, areaName);
						break;
					default: break;
					}
			}
			
		}
		free(cfgline);
	}
	
	fclose(f);
	return 0;
}

void changeHeader(s_message *msg, s_link *link, char *subject) {
	s_addr *ourAka;
	char *toname, *tmp;
	
	ourAka=link->ourAka;
	
	msg->destAddr.zone = link->hisAka.zone;
	msg->destAddr.net = link->hisAka.net;
	msg->destAddr.node = link->hisAka.node;
	msg->destAddr.point = link->hisAka.point;

	msg->origAddr.zone = ourAka->zone;
	msg->origAddr.net = ourAka->net;
	msg->origAddr.node = ourAka->node;
	msg->origAddr.point = ourAka->point;
	
	tmp = msg->subjectLine;
	tmp = (char*) realloc(tmp, strlen(subject)+1);
	strcpy(tmp,subject);
	msg->subjectLine = tmp;
	toname = msg->fromUserName;
	msg->fromUserName = msg->toUserName;
	msg->toUserName = toname;
}

int availArea(char *areaName, char *fileName) {
	FILE *f;
	char *line, *token, *running;
	
	if ((f=fopen(fileName,"r")) == NULL)
		{
			fprintf(stderr,"areafix: cannot open Available Areas file \"%s\"\n",fileName);
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

int forwardRequest(char *areatag, char *aka) {
    int i;
    s_link *uplink;
	
    for (i = 0; i < config->linkCount; i++) {
		uplink = &(config->links[i]);
		if (uplink->forwardRequests) {
			
			if (uplink->available!=NULL) {
				// first try to find the areatag in available file
				if (availArea(areatag,uplink->available)!=0) {
					forwardRequestToLink(areatag,aka,uplink,0);
					return 0;
				}
			} else {
				forwardRequestToLink(areatag,aka,uplink,0);
				return 0;
			}
		}
		
    }
	
	// link with "forwardRequests on" not found
	return 1;	
}

char *subscribe(s_link *link, s_message *msg, char *cmd) {
	int i, rc=2;
	char *line, *report, addline[256], logmsg[256];
	s_area *area=NULL;
	
	line = cmd;
	
	if (line[0]=='+') line++;
	
	report = calloc (1,sizeof(char));
	
	for (i = 0; i< config->echoAreaCount; i++) {
		rc=subscribeAreaCheck(&(config->echoAreas[i]),msg,line);

		if ( rc!=2 ) {
			area = &(config->echoAreas[i]);
			if (area->hide) continue;
		}
		
		switch (rc) {
		case 0:
			sprintf(addline,"%s already linked\r",area->areaName);
			if (strstr(line,"*") == NULL) i = config->echoAreaCount;
			break;
		case 2:	if (strstr(line,"*") != NULL) continue;
			if (i == config->echoAreaCount) sprintf(addline,"%s not found\r",line);
			break;
		case 1:
			// subscribing
			if (restricted(link->TossGrp,area->group)==0) {
				changeconfig (getConfigFileName(), area, link, 0);
				area->downlinks=realloc(area->downlinks,sizeof(s_link*)*(area->downlinkCount+1));
				area->downlinks[area->downlinkCount] = link;
				area->downlinkCount++;
				sprintf(addline,"%s subscribed\r",area->areaName);
				sprintf(logmsg,"areafix: %s subscribed to %s", aka2str(link->hisAka), area->areaName);
				writeLogEntry(log, '8', logmsg);
				if (strstr(line,"*") == NULL) i = config->echoAreaCount;
			} //else sprintf(addline,"area %s restricted\r",area->areaName);
			else addline[0]=0;
			break;
		default: continue;
		}
		
		report=(char*) realloc(report, strlen(report)+strlen(addline)+1);
		strcat(report, addline);
	}
	
	if ((rc==2) && (strstr(line,"*") == NULL)) {
		// try to forward request
		if (forwardRequest(line,aka2str(link->hisAka))!=0)
			sprintf(addline,"%s no uplinks to forward\r",line);
		else sprintf(addline,"%s request forwarded\r",line);
		report=(char*) realloc(report, strlen(report)+strlen(addline)+1);
		strcat(report, addline);
	}
	
	return report;
}

char *unsubscribe(s_link *link, s_message *msg, char *cmd) {
	int i, rc = 2;
	char *line, *report, addline[256], logmsg[256];
	s_area *area;
	
	line = cmd;
	
	if (line[1]=='-') return NULL;
	line++;
	
	report = calloc (1,sizeof(char));
	
	for (i = 0; i< config->echoAreaCount; i++) {
		rc=subscribeAreaCheck(&(config->echoAreas[i]),msg,line);
		if ( rc==2 ) continue;
		
		area = &(config->echoAreas[i]);

		switch (rc) {
		case 1: 
			if (strstr(line,"*") != NULL) continue;
			else sprintf(addline,"%s not linked\r",area->areaName);
			break;
		case 2:
			if (strstr(line,"*") != NULL) continue;
			sprintf(addline,"%s not found\r",line);
			break;
		case 0:
			removelink(link, area);
			changeconfig (getConfigFileName(), area, link, 1);
			sprintf(addline,"%s unsubscribed\r",area->areaName);
			sprintf(logmsg,"areafix: %s unsubscribed from %s",aka2str(link->hisAka),area->areaName);
			writeLogEntry(log, '8', logmsg);
			break;
		default: continue;
		}

		report=(char*) realloc(report, strlen(report)+strlen(addline)+1);
		strcat(report, addline);

	}
	return report;
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

		if (uplink->available!=NULL) {
			if ((f=fopen(uplink->available,"r")) == NULL)
				{
					fprintf(stderr,"areafix: cannot open Available Areas file \"%s\"\n", uplink->available);
					sprintf(addline,"areafix: cannot open Available Areas file \"%s\"\n", uplink->available);
					writeLogEntry(log, '8', addline);
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

			sprintf(addline,"  %s\r",print_ch('-',76));
			report=(char*) realloc(report,strlen(report)+strlen(addline)+1);
			strcat (report,addline);

			sprintf(linkAka, "%s", aka2str(link->hisAka));
			sprintf(addline,"areafix: Available Area List from %s sent to %s", aka2str(uplink->hisAka), linkAka);
			
			writeLogEntry(log, '8', addline);
			
		}
	}
	
	return report;
}                                                                               

char *areastatus(char *preport, char *text)
{
    char *pth, *ptmp=NULL, *tmp, *report, tmpBuff[256];
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
		if (EchoAreas[i].hide==1) continue;
		
		rc=subscribeCheck(EchoAreas[i], msg);
		if (rc) {
			report=(char*)realloc(report, strlen(report)+strlen(EchoAreas[i].areaName)+3);
			strcat(report, " ");
			strcat(report, EchoAreas[i].areaName);
			strcat(report, "\r");
		}
    }
    sprintf(addline,"areafix: unlinked areas list sent to %s", aka2str(link->hisAka));
    writeLogEntry(log, '8', addline);
	
    return report;
}

char *info_link(s_message *msg, s_link *link)
{
    char buff[256], *report, *ptr, linkAka[25];
    char hisAddr[]="Your address: ";
    char ourAddr[]="AKA used here: ";
    char Arch[]="Compression: ";
    int i;
    
	sprintf(linkAka,aka2str(link->hisAka));
//    sprintf(buff, "Here is some information about our link:\r\r% 16s%s\r% 16s%s\r% 16s", hisAddr, linkAka, ourAddr, aka2str(*link->ourAka), Arch);
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
    writeLogEntry(log, '8', buff);
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
	case 1:
		report = list (msg, link);
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
	default: return NULL;
	}

	return report;
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
    memcpy(tmpmsg, msg, sizeof(s_message));
    changeHeader(tmpmsg,link,subj);
    preprocText(report, tmpmsg);
    processNMMsg(tmpmsg, NULL);
    free(tmpmsg->text);
    free(tmpmsg->subjectLine);
}

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-


int processAreaFix(s_message *msg, s_pktHeader *pktHeader)
{
	int i, security=1, notforme = 0;
	s_link *link = NULL;
	s_message *linkmsg, tmpmsg;
    s_pktHeader header;
	char tmp[80], *token, *textBuff, *report=NULL, *preport;
	
	// 1st security check
	if (pktHeader!=NULL) security=addrComp(msg->origAddr, pktHeader->origAddr);
	else {
		makePktHeader(NULL, &header);
		pktHeader = &header;
		pktHeader->origAddr = msg->origAddr;
		pktHeader->destAddr = msg->destAddr;
		security = 0;
	}
	
	// find link
	link=getLinkFromAddr(*config, msg->origAddr);
	
	// this is for me?
	if (link!=NULL)	notforme=addrComp(msg->destAddr, *link->ourAka);

	// ignore msg for other link (maybe this is transit...)
	if (notforme || link==NULL) {
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
				default: break;
				}
				
				free(preport);
			}
			token = strseparate (&textBuff, "\n\r");
		}
		
	} else {

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
		default:
			sprintf(tmp, " \r unknown error. mail to sysop.\r");
			break;
		}
		
		report=(char*) malloc(strlen(tmp)+1);
		strcpy(report,tmp);
		
		RetMsg(&tmpmsg, msg, link, report, "security violation");
		free(report);
		
		sprintf(tmp,"areafix: security violation from %s", aka2str(link->hisAka));
		writeLogEntry(log, '8', tmp);
		
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
	writeLogEntry(log, '8', tmp);
	
	// send msg to the links (forward requests to areafix)
    for (i = 0; i < config->linkCount; i++) {
		if (config->links[i].msg == NULL) continue;
		link = &(config->links[i]);
		linkmsg = link->msg;
		report=linkmsg->text;

	    sprintf(tmp, " \r--- %s areafix\r", versionStr);
		report=(char*) realloc(report,strlen(report)+strlen(tmp)+1);
		strcat(report,tmp);

		makePktHeader(NULL, &header);
		header.origAddr = *(link->ourAka);
		header.destAddr = link->hisAka;
		
		sprintf(tmp,"areafix: write netmail msg for %s", aka2str(link->hisAka));
		writeLogEntry(log, '8', tmp);

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

    writeLogEntry(log, '4', "Start AreaFix...");
    
    netmail = MsgOpenArea((unsigned char *) config->netMailArea.fileName, MSGAREA_NORMAL, config->netMailArea.msgbType);
    if (netmail != NULL) {

	highmsg = MsgGetHighMsg(netmail);
	writeLogEntry(log, '1', "Scanning NetmailArea");

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
		if (((xmsg.attr & MSGREAD) != MSGREAD) && (for_us==1) && (stricmp(xmsg.to, "areafix")==0)) {
		    MsgToStruct(SQmsg, xmsg, &msg);
		    processAreaFix(&msg,NULL);
		    xmsg.attr |= MSGREAD;
		    MsgWriteMsg(SQmsg, 0, &xmsg, NULL, 0, 0, 0, NULL);
		    freeMsgBuffers(&msg);
	    }

	    MsgCloseMsg(SQmsg);

	} /* endfor */

	MsgCloseArea(netmail);
    } else {
	writeLogEntry(log, '9', "Could not open NetmailArea");
    } /* endif */
}
