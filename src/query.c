/* Areafix improvement by Max Chernogor 2:464/108  */
/*****************************************************************************
 * $Id$
 */

/* libc */
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

/* compiler.h */
#include <huskylib/compiler.h>
#include <huskylib/huskylib.h>

#ifdef HAS_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAS_DOS_H
#include <dos.h>
#endif

/* smapi */

/* fidoconf */
#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <huskylib/xstr.h>
#include <fidoconf/areatree.h>
#include <fidoconf/afixcmd.h>

/* hpt */
#include <global.h>
#include <toss.h>
#include <areafix.h>
#include <query.h>

static  time_t  tnow;
const   long    secInDay = 3600*24;
const char czFreqArea[] = "freq";
const char czIdleArea[] = "idle";
const char czKillArea[] = "kill";
const char czChangFlg[] = "changed.qfl";


extern s_query_areas *queryAreasHead;
extern s_message **msgToSysop;
extern char       *versionStr;


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

void del_tok(char **ac, char *tok) {
    char *p, *q;

    q = fc_stristr(*ac,tok);
    if (q) {
	p = q+strlen(tok);
	while (*p && !isspace(*p)) p++;
	if (*p) memmove(q, p+1, strlen(p+1)+1); /*  begin or middle */
	else {
	    if (q > *ac) *(q-1)='\0'; /*  end */
	    else *q='\0'; /*  "-token" defaults */
	}
    }
}

char* makeAreaParam(s_link *creatingLink, char* c_area, char* msgbDir)
{
    char *msgbFileName=NULL, *acDef;
    char *msgbtype, *newAC=NULL, *desc, *quote_areaname;
    char *cp, *buff=NULL;                    /* temp. usage */

    msgbFileName = makeMsgbFileName(config, c_area);

    /*  translating name of the area to lowercase/uppercase */
    if (config->createAreasCase == eUpper) strUpper(c_area);
    else strLower(c_area);

    /*  translating filename of the area to lowercase/uppercase */
    if (config->areasFileNameCase == eUpper) strUpper(msgbFileName);
    else strLower(msgbFileName);

    acDef = creatingLink->autoAreaCreateDefaults;

    xscatprintf(&newAC, "%s%s", (acDef) ? " " : "", (acDef) ? acDef : "");

    msgbtype = fc_stristr(newAC, "-b ");

    if(!msgbDir)
        msgbDir=(creatingLink->msgBaseDir) ?
        creatingLink->msgBaseDir : config->msgBaseDir;

    quote_areaname = strchr(TRUE_COMMENT "\"", *c_area) ? "\"" : "";

    if (stricmp(msgbDir, "passthrough")!=0 && NULL==fc_stristr(newAC,"passthrough"))
    {
        /*  we have to find a file name */
        int need_dos_file;

#ifndef MSDOS
        need_dos_file = fc_stristr(newAC, "-dosfile")!=NULL;
#else
        need_dos_file = 1;
#endif
        if (creatingLink->autoAreaCreateSubdirs && !need_dos_file)
        {
             /* "subdirify" the message base path if the */
             /* user wants this. this currently does not */
             /* work with the -dosfile option */
            for (cp = msgbFileName; *cp; cp++)
            {
                if (*cp == '.')
                {
                    *cp = PATH_DELIM;
                }
            }
        }
        if (!need_dos_file)
            xscatprintf(&buff, "EchoArea %s%s%s %s%s%s",
            quote_areaname, c_area, quote_areaname,
            msgbDir, msgbFileName,
            (msgbtype) ? "" : " -b Squish");
        else {
            sleep(1); /*  to prevent time from creating equal numbers */
            xscatprintf(&buff,"EchoArea %s%s%s %s%8lx%s",
                quote_areaname, c_area, quote_areaname,
                msgbDir, (long)time(NULL),
                (msgbtype) ? "" : " -b Squish");
        }

    } else {
        /*  passthrough */
        xscatprintf(&buff, "EchoArea %s%s%s passthrough",
	    quote_areaname, c_area, quote_areaname);

        del_tok(&newAC, "passthrough");
        del_tok(&newAC, "-b ");  /*  del "-b msgbtype" from autocreate defaults */
        del_tok(&newAC, "-$m "); /*  del "-$m xxx" from autocreate defaults */
        del_tok(&newAC, "-p ");  /*  del "-p xxx" from autocreate defaults */

        del_tok(&newAC, "-killsb");
        del_tok(&newAC, "-nokillsb");
        del_tok(&newAC, "-tinysb");
        del_tok(&newAC, "-notinysb");
        del_tok(&newAC, "-pack");
        del_tok(&newAC, "-nopack");
        del_tok(&newAC, "-link");
        del_tok(&newAC, "-nolink");
        del_tok(&newAC, "-killread");
        del_tok(&newAC, "-nokillread");
        del_tok(&newAC, "-keepunread");
        del_tok(&newAC, "-nokeepunread");
    }

    nfree(msgbFileName);
    if (creatingLink->LinkGrp) {
        if (fc_stristr(newAC, " -g ")==NULL)
            xscatprintf(&buff, " -g %s", creatingLink->LinkGrp);
    }

    if (IsAreaAvailable(c_area,creatingLink->forwardRequestFile,&desc,1)==1) {
        if (desc) {
            if (fc_stristr(newAC, " -d ")==NULL)
                xscatprintf(&buff, " -d \"%s\"", desc);
            nfree(desc);
        }
    }
    if (*newAC) xstrcat(&buff, newAC);
    nfree(newAC);
    return buff;
}

e_BadmailReasons autoCreate(char *c_area, hs_addr pktOrigAddr, ps_addr forwardAddr)
{
    FILE *f;
    char *fileName;
    char *buff=NULL, *hisaddr=NULL;
    char *msgbDir=NULL;
    s_link *creatingLink;
    s_area *area;
    s_query_areas* areaNode=NULL;
    size_t i=0;
    unsigned int j;
    char pass[] = "passthrough";
    char CR;

    w_log( LL_FUNC, "%s::autoCreate() begin", __FILE__ );

    if (strlen(c_area)>60){
       w_log( LL_FUNC, "%s::autoCreate() rc=11", __FILE__ );
       return BM_AREATAG_TOO_LONG;
    }
    if (!isValidConference(c_area) || isPatternLine(c_area)){
       w_log( LL_FUNC, "%s::autoCreate() rc=7", __FILE__ );
       return BM_ILLEGAL_CHARS;
    }

    if (checkRefuse(c_area))
    {
        w_log(LL_WARN, "Can't create area %s : refused by NewAreaRefuseFile\n", c_area);
        return BM_DENY_NEWAREAREFUSEFILE;
    }


    creatingLink = getLinkFromAddr(config, pktOrigAddr);

    if (creatingLink == NULL) {
	w_log(LL_ERR, "creatingLink == NULL !!!");
        w_log( LL_FUNC, "%s::autoCreate() rc=8", __FILE__ );
	return BM_SENDER_NOT_FOUND;
    }

    fileName = creatingLink->autoAreaCreateFile;
    if (fileName == NULL) fileName = cfgFile ? cfgFile : getConfigFileName();

    f = fopen(fileName, "a+b");
    if (f == NULL) {
	fprintf(stderr,"autocreate: cannot open config file\n");
        w_log( LL_FUNC, "%s::autoCreate() rc=9", __FILE__ );
	return BM_CANT_OPEN_CONFIG;
    }
    /*  setting up msgbase dir */
    if (config->createFwdNonPass == 0 && forwardAddr)
        msgbDir = pass;
    else
        msgbDir = creatingLink->msgBaseDir;

    if(config->areafixQueueFile)
    {
        areaNode = af_CheckAreaInQuery(c_area, &pktOrigAddr, NULL, FIND);
        if( areaNode ) /*  if area in query */
        {
            if( stricmp(areaNode->type,czKillArea) == 0 ){
                w_log( LL_FUNC, "%s::autoCreate() rc=4", __FILE__ );
                return BM_AREA_KILLED;  /*  area already unsubscribed */
            }
            if( stricmp(areaNode->type,czFreqArea) == 0 &&
                addrComp(pktOrigAddr, areaNode->downlinks[0])!=0)
            {
                w_log( LL_FUNC, "%s::autoCreate() rc=4", __FILE__ );
                return BM_WRONG_LINK_TO_AUTOCREATE;  /*  wrong link to autocreate from */
            }
            if( stricmp(areaNode->type,czFreqArea) == 0 )
            {
                /*  removinq area from query. it is autocreated now */
                queryAreasHead->nFlag = 1; /*  query was changed */
                areaNode->type[0] = '\0';  /*  mark as deleted */
            }
            if (config->createFwdNonPass == 0)
               msgbDir = pass;
            /*  try to find our aka in links of queried area */
            /*  if not foun area will be passthrough */
            for (i = 1; i < areaNode->linksCount; i++)
                for(j = 0; j < config->addrCount; j++)
                    if (addrComp(areaNode->downlinks[i],config->addr[j])==0)
                    {
                        msgbDir = creatingLink->msgBaseDir; break;
                    }
        }
    }

    /*  making address of uplink */
    xstrcat(&hisaddr, aka2str(pktOrigAddr));

    buff = makeAreaParam(creatingLink , c_area, msgbDir);

    /*  add new created echo to config in memory */
    parseLine(buff, config);
    RebuildEchoAreaTree(config);

    /*  subscribe uplink if he is not subscribed */
    area = &(config->echoAreas[config->echoAreaCount-1]);
    if ( !isLinkOfArea(creatingLink,area) ) {
	xscatprintf(&buff, " %s", hisaddr);
	Addlink(config, creatingLink, area);
    }

    /*  subscribe downlinks if present */
    if(areaNode) { /*  areaNode == NULL if areafixQueueFile isn't used */
        /*  prevent subscribing of defuault links */
        /*  or not existing links */
        for(i = 1; i < areaNode->linksCount; i++) {
            if( ( isAreaLink( areaNode->downlinks[i],area ) == -1 ) &&
                ( getLinkFromAddr(config,areaNode->downlinks[i])) &&
                ( !isOurAka(config,areaNode->downlinks[i]) )
            ) {
            xstrcat( &buff, " " );
            xstrcat( &buff, aka2str(areaNode->downlinks[i]) );
            Addlink(config, getLinkFromAddr(config,areaNode->downlinks[i]), area);
            }
        }
    }

    /*  fix if dummys del \n from the end of file */
    if( fseek (f, -2L, SEEK_END) == 0)
    {
        CR = getc (f); /*   may be it is CR aka '\r'  */
        if (getc(f) != '\n') {
            fseek (f, 0L, SEEK_END);  /*  not neccesary, but looks better ;) */
            fputs (cfgEol(), f);
        } else {
            fseek (f, 0L, SEEK_END);
        }
        i = ftell(f); /* config length */
        /* correct EOL in memory */
        if(CR == '\r')
            xstrcat(&buff,"\r\n"); /* DOS EOL */
        else
            xstrcat(&buff,"\n");   /* UNIX EOL */
    }
    else
    {
        xstrcat(&buff,cfgEol());   /* config depended EOL */
    }
    /*  add line to config */
    if ( fprintf(f, "%s", buff) != (int)(strlen(buff)) || fflush(f) != 0)
    {
        w_log(LL_ERR, "Error creating area %s, config write failed: %s!",
            c_area, strerror(errno));
        fseek(f, i, SEEK_SET);
        setfsize(fileno(f), i);
    }
    fclose(f);
    nfree(buff);

    /*  echoarea addresses changed by safe_reallocating of config->echoAreas[] */
    carbonNames2Addr(config);

    w_log(LL_AUTOCREATE, "Area %s autocreated by %s", c_area, hisaddr);

    if (forwardAddr == NULL) makeMsgToSysop(c_area, pktOrigAddr, NULL);
    else makeMsgToSysop(c_area, *forwardAddr, &pktOrigAddr);

    nfree(hisaddr);

    /*  create flag */
    if (config->aacFlag) {
	if (NULL == (f = fopen(config->aacFlag,"a")))
	    w_log(LL_ERR, "Could not open autoAreaCreate flag: %s", config->aacFlag);
	else {
	    w_log(LL_FLAG, "Created autoAreaCreate flag: %s", config->aacFlag);
	    fclose(f);
	}
    }

    w_log( LL_FUNC, "%s::autoCreate() end", __FILE__ );
    return 0;
}


s_query_areas*  af_AddAreaListNode(char *areatag, const char *type);
void            af_DelAreaListNode(s_query_areas* node);
void            af_AddLink(s_query_areas* node, ps_addr link);

s_query_areas* af_CheckAreaInQuery(char *areatag, ps_addr uplink, ps_addr dwlink, e_query_action act)
{
    size_t i = 0;
    int bFind = 0;
    s_query_areas *areaNode = NULL;
    s_query_areas *tmpNode  = NULL;

    if( !queryAreasHead ) af_OpenQuery();
    tmpNode = queryAreasHead;
    while(tmpNode->next && !bFind)
    {
        if( tmpNode->next->name && !stricmp(areatag, tmpNode->next->name) )
            bFind = 1;
        tmpNode = tmpNode->next;
    }

    switch( act )
    {
    case FIND:
        if( !bFind || tmpNode == queryAreasHead )
            tmpNode = NULL;
        break;
    case ADDFREQ:
        if( bFind ) {
            if( stricmp(tmpNode->type,czFreqArea) == 0 )
            {
                i = 1;
                while( i < tmpNode->linksCount && addrComp(*dwlink, tmpNode->downlinks[i])!=0)
                    i++;
                if(i == tmpNode->linksCount) {
                    af_AddLink( tmpNode, dwlink ); /*  add link to queried area */
                    tmpNode->eTime = tnow + config->forwardRequestTimeout*secInDay;
                } else {
                    tmpNode = NULL;  /*  link already in query */
                }
            } else {
                strcpy(tmpNode->type,czFreqArea); /*  change state to @freq" */
                af_AddLink( tmpNode, dwlink );
                tmpNode->eTime = tnow + config->forwardRequestTimeout*secInDay;
            }
        } else { /*  area not found, so add it */
            areaNode = af_AddAreaListNode( areatag, czFreqArea );
            if(strlen( areatag ) > queryAreasHead->linksCount) /* max areanane lenght */
                queryAreasHead->linksCount = strlen( areatag );
            af_AddLink( areaNode, uplink );
            af_AddLink( areaNode, dwlink );
            areaNode->eTime = tnow + config->forwardRequestTimeout*secInDay;
            tmpNode =areaNode;
        }
        break;
    case ADDIDLE:
        if( bFind ) {
        } else {
            areaNode = af_AddAreaListNode( areatag, czIdleArea );
            if(strlen( areatag ) > queryAreasHead->linksCount)
                queryAreasHead->linksCount = strlen( areatag );
            af_AddLink( areaNode, uplink );
            areaNode->eTime = tnow + config->idlePassthruTimeout*secInDay;
            w_log(LL_AREAFIX, "areafix: make request idle for area: %s", areaNode->name);
            tmpNode =areaNode;
        }
        break;
    case DELIDLE:
        if( bFind && stricmp(tmpNode->type,czIdleArea) == 0 )
        {
            queryAreasHead->nFlag = 1;
            tmpNode->type[0] = '\0';
            w_log( LL_AREAFIX, "areafix: idle request for %s removed from queue file",tmpNode->name);
        }
        break;

    }
    return tmpNode;
}

char* af_Req2Idle(char *areatag, char* report, hs_addr linkAddr)
{
    size_t i;
    s_query_areas *tmpNode  = NULL;
    s_query_areas *areaNode  = NULL;
    if( !queryAreasHead ) af_OpenQuery();
    tmpNode = queryAreasHead;
    while(tmpNode->next)
    {
        areaNode = tmpNode->next;
        if( ( areaNode->name ) &&
            ( stricmp(areaNode->type,czFreqArea) == 0 ) &&
            ( patimat(areaNode->name,areatag)==1) )
        {
            i = 1;
            while( i < areaNode->linksCount)
            {
                  if( addrComp(areaNode->downlinks[i],linkAddr) == 0)
                      break;
                  i++;
            }
            if( i < areaNode->linksCount )
            {
                if( i != areaNode->linksCount-1 )
                    memmove(&(areaNode->downlinks[i]),&(areaNode->downlinks[i+1]),
                    sizeof(hs_addr)*(areaNode->linksCount-i));
                areaNode->linksCount--;
                queryAreasHead->nFlag = 1; /*  query was changed */
                if(areaNode->linksCount == 1)
                {
                    strcpy(areaNode->type,czIdleArea);
                    areaNode->bTime = tnow;
                    areaNode->eTime = tnow + config->idlePassthruTimeout*secInDay;
                    w_log(LL_AREAFIX, "areafix: make request idle for area: %s", areaNode->name);
                }
                xscatprintf(&report, " %s %s  request canceled\r",
                    areaNode->name,
                    print_ch(49-strlen(areaNode->name), '.'));
                w_log(LL_AREAFIX, "areafix: request canceled for [%s] area: %s",aka2str(linkAddr),
                    areaNode->name);
            }
        }
        tmpNode = tmpNode->next;
    }
    return report;
}

char* af_GetQFlagName()
{
    char *chanagedflag = NULL;
    char *logdir       = NULL;

#ifdef DEBUG_HPT
w_log(LL_FUNC, "af_GetQFlagName(): begin");
#endif
    if (config->lockfile)
    {
       logdir = dirname(config->lockfile);  /* slash-trailed */
       xstrscat(&chanagedflag,logdir,(char*)czChangFlg,NULL);
       nfree(logdir);
    }
    else if (config->echotosslog)
    {
       logdir = dirname(config->echotosslog);  /* slash-trailed */
       xstrscat(&chanagedflag,logdir,(char*)czChangFlg,NULL);
       nfree(logdir);
    }
    else if (config->semaDir)
    {
       logdir = dirname(config->echotosslog);  /* slash-trailed */
       xstrscat(&chanagedflag,logdir,(char*)czChangFlg,NULL);
       nfree(logdir);
    }
    else
    {
        chanagedflag = safe_strdup(czChangFlg);
    }

    w_log(LL_FUNC, "af_GetQFlagName(): end");

    return chanagedflag;
}

void af_QueueReport()
{
    s_query_areas *tmpNode  = NULL;
    const char rmask[]="%-37.37s %-4.4s %11.11s %-16.16s %-7.7s\r";
    char type[5]="\0\0\0\0";
    char state[8]= "\0\0\0\0\0\0\0";
    char link1[17]= {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    char link2[17]= {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    char* report = NULL;
    char* header = NULL;
    int netmail=0;
    char *reportFlg = NULL;

    w_log(LL_FUNC, "af_QueueReport(): begin");

    if( !config->areafixQueueFile ){
      w_log(LL_WARN, "areafixQueueFile not defined in config");
      w_log(LL_FUNC, "af_QueueReport(): end");
      return;
    }

    w_log(LL_DEBUGU, __FILE__ ":%u:af_QueueReport()", __LINE__);

    reportFlg = af_GetQFlagName();

    w_log(LL_DEBUGU, __FILE__ ":%u:af_QueueReport()", __LINE__);

    if(!fexist(reportFlg))
    {
        w_log(LL_STOP, "Queue file hasn't been changed. Exiting...");
        nfree(reportFlg);
        return;
    }

    w_log(LL_DEBUGU, __FILE__":%u:af_QueueReport()", __LINE__);

    if( !queryAreasHead ) af_OpenQuery();

    tmpNode = queryAreasHead;

    w_log(LL_DEBUGU, __FILE__":%u:af_QueueReport() tmpNode=%X", __LINE__, tmpNode);

    while(tmpNode->next)
    {

    w_log(LL_DEBUGU, __FILE__":%u:af_QueueReport() tmpNode=%X", __LINE__, tmpNode);

        tmpNode = tmpNode->next;
        strcpy(link1,aka2str(tmpNode->downlinks[0]));
        strcpy(type,tmpNode->type);
        if( stricmp(tmpNode->type,czFreqArea) == 0 )
        {
            strcpy(link2,aka2str(tmpNode->downlinks[1]));
            if( strcmp(tmpNode->type,czFreqArea) == 0 )
            {
                queryAreasHead->nFlag = 1;
                strUpper(tmpNode->type);
                xscatprintf(&report,rmask, tmpNode->name, tmpNode->type,
                    link1,link2,
                    "request");
                continue;
            }
            if(tmpNode->eTime < tnow )
            {
                strcpy(state,"rr_or_d");
            }
            else
            {
                int days = (tnow - tmpNode->bTime)/secInDay;
                sprintf(state,"%2d days",days);
            }
            xscatprintf(&report,rmask, tmpNode->name, type,
                link1,link2,
                state);
        }
        if( stricmp(tmpNode->type,czKillArea) == 0 )
        {
            if( strcmp(tmpNode->type,czKillArea) == 0 )
            {
                queryAreasHead->nFlag = 1;
                strUpper(tmpNode->type);
                xscatprintf(&report,rmask, tmpNode->name, tmpNode->type,
                    link1,"",
                    "timeout");
                continue;
            }
            if(tmpNode->eTime < tnow )
            {
                strcpy(state,"to_kill");
            }
            else
            {
                int days = (tnow - tmpNode->bTime)/secInDay;
                sprintf(state,"%2d days",days);
            }
            xscatprintf(&report,rmask, tmpNode->name, type,
                link1,"",
                state);

        }
        if( stricmp(tmpNode->type,czIdleArea) == 0 )
        {
            if( strcmp(tmpNode->type,czIdleArea) == 0 )
            {
                queryAreasHead->nFlag = 1;
                strUpper(tmpNode->type);
                xscatprintf(&report,rmask, tmpNode->name, tmpNode->type,
                    link1,"",
                    "timeout");
                continue;
            }
            if(tmpNode->eTime < tnow )
            {
                strcpy(state,"to_kill");
            }
            else
            {
                int days = (tnow - tmpNode->bTime)/secInDay;
                sprintf(state,"%2d days",days);
            }
            xscatprintf(&report,rmask, tmpNode->name, type,
                link1,"",
                state);
        }
    }
    if(!report) {
        remove(reportFlg);
        nfree(reportFlg);
        return;
    }

    w_log(LL_START, "Start generating queue report");
    xscatprintf(&header,rmask,"Area","Act","From","By","Details");
    xscatprintf(&header,"%s\r", print_ch(79,'-'));
    xstrcat(&header, report);
    report = header;
    if (config->ReportTo) {
        if (stricmp(config->ReportTo,"netmail")==0)                netmail=1;
        else if (getNetMailArea(config, config->ReportTo) != NULL) netmail=1;
    } else netmail=1;

    msgToSysop[0] = makeMessage(&(config->addr[0]),&(config->addr[0]),
                                config->areafixFromName ? config->areafixFromName : versionStr,
                                netmail ? config->sysop : "All", "Requests report",
                                netmail,
                                config->areafixReportsAttr);
    msgToSysop[0]->text = createKludges(config,
                                netmail ? NULL : config->ReportTo,
                                &(config->addr[0]), &(config->addr[0]),
                                versionStr);

    msgToSysop[0]->recode |= (REC_HDR|REC_TXT);

    if (config->areafixReportsFlags)
	xstrscat( &(msgToSysop[0]->text), "\001FLAGS ", config->areafixReportsFlags, "\r", NULL);
    xstrcat( &(msgToSysop[0]->text), report );

    w_log(LL_STOP, "End generating queue report");

    writeMsgToSysop();
    freeMsgBuffers(msgToSysop[0]);
    nfree(msgToSysop[0]);
    remove(reportFlg);
    nfree(reportFlg);
    w_log(LL_FUNC, "af_QueueReport(): end");
}

void af_QueueUpdate()
{
    s_query_areas *tmpNode  = NULL;
    s_link *lastRlink;
    s_link *dwlink;

    w_log(LL_START, "Start updating queue file");
    if( !queryAreasHead ) af_OpenQuery();

    tmpNode = queryAreasHead;
    while(tmpNode->next)
    {
        tmpNode = tmpNode->next;
        if( tmpNode->eTime > tnow )
            continue;
        if( stricmp(tmpNode->type,czFreqArea) == 0 )
        {
            lastRlink = getLinkFromAddr(config,tmpNode->downlinks[0]);
            dwlink    = getLinkFromAddr(config,tmpNode->downlinks[1]);
            forwardRequestToLink(tmpNode->name, lastRlink, NULL, 2);
            w_log( LL_AREAFIX, "areafix: request for %s is canceled for node %s",
                tmpNode->name, aka2str(lastRlink->hisAka));
            if(dwlink && !forwardRequest(tmpNode->name, dwlink, &lastRlink))
            {
                tmpNode->downlinks[0] = lastRlink->hisAka;
                tmpNode->bTime = tnow;
                tmpNode->eTime = tnow + config->forwardRequestTimeout*secInDay;
                w_log( LL_AREAFIX, "areafix: request for %s is going to node %s",
                    tmpNode->name, aka2str(lastRlink->hisAka));
            }
            else
            {
                strcpy(tmpNode->type, czKillArea);
                tmpNode->bTime = tnow;
                tmpNode->eTime = tnow + config->killedRequestTimeout*secInDay;
                tmpNode->linksCount = 1;
                w_log( LL_AREAFIX, "areafix: request for %s is going to be killed",tmpNode->name);
            }
            queryAreasHead->nFlag = 1; /*  query was changed */
            continue;
        }
        if( stricmp(tmpNode->type,czKillArea) == 0 )
        {
            queryAreasHead->nFlag = 1;
            tmpNode->type[0] = '\0';
            w_log( LL_AREAFIX, "areafix: request for %s removed from queue file",tmpNode->name);
            continue;
        }
        if( stricmp(tmpNode->type,czIdleArea) == 0 )
        {
            ps_area delarea;
            queryAreasHead->nFlag = 1; /*  query was changed */
            strcpy(tmpNode->type, czKillArea);
            tmpNode->bTime = tnow;
            tmpNode->eTime = tnow + config->killedRequestTimeout*secInDay;
            tmpNode->linksCount = 1;
            w_log( LL_AREAFIX, "areafix: request for %s is going to be killed",tmpNode->name);
            delarea = getArea(config, tmpNode->name);
            if (delarea != &(config->badArea))
            {
                do_delete(NULL, delarea);
            }
        }
    }
    /*  send msg to the links (forward requests to areafix) */
    sendAreafixMessages();
    w_log(LL_STOP, "End updating queue file");
}

int af_OpenQuery()
{
    FILE *queryFile;
    char *line = NULL;
    char *token = NULL;
    struct  tm tr;
    char seps[]   = " \t\n";

    if( queryAreasHead )  /*  list already exists */
        return 0;

    time( &tnow );

    queryAreasHead = af_AddAreaListNode("\0","\0");

    if( !config->areafixQueueFile ) /* Queue File not defined in config */
    {
        w_log(LL_ERR, "areafixQueueFile not defined in config");
        return 0;
    }
    if ( !(queryFile = fopen(config->areafixQueueFile,"r")) ) /* can't open query file */
    {
       w_log(LL_ERR, "Can't open areafixQueueFile %s: %s", config->areafixQueueFile, strerror(errno) );
       return 0;
    }

    while ((line = readLine(queryFile)) != NULL)
    {
        s_query_areas *areaNode = NULL;
        token = strtok( line, seps );
        if( token != NULL )
        {
            areaNode = af_AddAreaListNode(token, "");
            if(strlen( areaNode->name ) > queryAreasHead->linksCount)
                queryAreasHead->linksCount = strlen( areaNode->name );
            token = strtok( NULL, seps );
            strncpy( areaNode->type ,token, 4);
            token = strtok( NULL, seps );
            memset(&tr, '\0', sizeof(tr));
            if(sscanf(token, "%d-%d-%d@%d:%d",
                          &tr.tm_year,
                          &tr.tm_mon,
                          &tr.tm_mday,
                          &tr.tm_hour,
                          &tr.tm_min
                  ) != 5)
            {
                af_DelAreaListNode(areaNode);
                continue;
            } else {
                tr.tm_year -= 1900;
                tr.tm_mon--;
                tr.tm_isdst =- 1;
                areaNode->bTime = mktime(&tr);
            }
            token = strtok( NULL, seps );
            memset(&tr, '\0', sizeof(tr));
            if(sscanf(token, "%d-%d-%d@%d:%d",
                          &tr.tm_year,
                          &tr.tm_mon,
                          &tr.tm_mday,
                          &tr.tm_hour,
                          &tr.tm_min
                  ) != 5)
            {
                af_DelAreaListNode(areaNode);
                continue;
            } else {
                tr.tm_year -= 1900;
                tr.tm_mon--;
                tr.tm_isdst =- 1;
                areaNode->eTime = mktime(&tr);
            }

            token = strtok( NULL, seps );
            while( token != NULL )
            {

                areaNode->linksCount++;
                areaNode->downlinks =
                safe_realloc( areaNode->downlinks,
                              sizeof(hs_addr)*areaNode->linksCount );
                string2addr(token ,
                            &(areaNode->downlinks[areaNode->linksCount-1]));
                token = strtok( NULL, seps );
            }
        }
        nfree(line);
    }
    fclose(queryFile);
    return 0;
}

int af_CloseQuery()
{
    char buf[2*1024] = "";
    char *p;
    int nSpace = 0;
    size_t i = 0;
    struct  tm t1,t2;
    int writeChanges = 0;
    FILE *queryFile=NULL;
    s_query_areas *delNode = NULL;
    s_query_areas *tmpNode  = NULL;
    char *chanagedflag = NULL;
    FILE *QFlag        = NULL;

    w_log(LL_FUNC, __FILE__ ":%u:af_CloseQuery() begin", __LINE__);

    if( !queryAreasHead ) {  /*  list does not exist */
        w_log(LL_FUNC, __FILE__ ":%u:af_CloseQuery() end", __LINE__);
        return 0;
    }

    if(queryAreasHead->nFlag == 1) {
        writeChanges = 1;
    }
    if (writeChanges)
    {
        if ((queryFile = fopen(config->areafixQueueFile,"w")) == NULL)
        {
            w_log(LL_ERR,"areafix: areafixQueueFile not saved");
            writeChanges = 0;
        }
        else
        {
            if( (chanagedflag = af_GetQFlagName()) )
            {
              if( (QFlag = fopen(chanagedflag,"w")) )
                fclose(QFlag);
              nfree(chanagedflag);
            }
        }
    }

    tmpNode = queryAreasHead->next;
    nSpace = queryAreasHead->linksCount+1;
    p = buf+nSpace;
    while(tmpNode) {
        if(writeChanges && tmpNode->type[0] != '\0')    {
            memset(buf, ' ' ,nSpace);
            memcpy(buf, tmpNode->name, strlen(tmpNode->name));
            t1 = *localtime( &tmpNode->bTime );
            t2 = *localtime( &tmpNode->eTime );
            sprintf( p , "%s %d-%02d-%02d@%02d:%02d\t%d-%02d-%02d@%02d:%02d" ,
                tmpNode->type,
                t1.tm_year + 1900,
                t1.tm_mon  + 1,
                t1.tm_mday,
                t1.tm_hour,
                t1.tm_min,
                t2.tm_year + 1900,
                t2.tm_mon  + 1,
                t2.tm_mday,
                t2.tm_hour,
                t2.tm_min   );
            p = p + strlen(p);
            for(i = 0; i < tmpNode->linksCount; i++) {
                strcat(p," ");
                strcat(p,aka2str(tmpNode->downlinks[i]));
            }
            strcat(buf, "\n");
            fputs( buf , queryFile );
            p = buf+nSpace;
        }
        delNode = tmpNode;
        tmpNode = tmpNode->next;
        af_DelAreaListNode(delNode);
    }

    nfree(queryAreasHead->name);
    nfree(queryAreasHead->downlinks);
    nfree(queryAreasHead->report);
    nfree(queryAreasHead);

    if(queryFile) fclose(queryFile);

    w_log(LL_FUNC, __FILE__ ":%u:af_CloseQuery() end", __LINE__);
    return 0;
}

s_query_areas* af_MakeAreaListNode()
{
    s_query_areas *areaNode =NULL;
    areaNode = (s_query_areas*)safe_malloc( sizeof(s_query_areas) );
    memset( areaNode ,'\0', sizeof(s_query_areas) );
    return areaNode;
}

s_query_areas* af_AddAreaListNode(char *areatag, const char *type)
{
    s_query_areas *tmpNode      = NULL;
    s_query_areas *tmpPrevNode  = NULL;
    s_query_areas *newNode  = af_MakeAreaListNode();

    newNode->name = sstrlen(areatag) > 0 ? safe_strdup(areatag) : NULL;
    strcpy( newNode->type ,type);

    tmpPrevNode = tmpNode = queryAreasHead;

    while(tmpNode)
    {
        if( tmpNode->name && strlen(tmpNode->name) > 0 )
            if( stricmp(areatag,tmpNode->name) < 0 )
                break;
        tmpPrevNode = tmpNode;
        tmpNode = tmpNode->next;
    }
    if(tmpPrevNode)
    {
        tmpPrevNode->next = newNode;
        newNode->next     = tmpNode;
    }
    return newNode;
}

void af_DelAreaListNode(s_query_areas* node)
{
    s_query_areas* tmpNode = queryAreasHead;

    while(tmpNode->next && tmpNode->next != node)
    {
        tmpNode = tmpNode->next;
    }
    if(tmpNode->next)
    {
        tmpNode->next = node->next;
        nfree(node->name);
        nfree(node->downlinks);
        nfree(node->report);
        nfree(node);
    }
}

void af_AddLink(s_query_areas* node, ps_addr link)
{
    node->linksCount++;
    node->downlinks =
        safe_realloc( node->downlinks, sizeof(hs_addr)*node->linksCount );
    memcpy( &(node->downlinks[node->linksCount-1]) ,link, sizeof(hs_addr) );
    node->bTime = tnow;
    queryAreasHead->nFlag = 1; /*  query was changed */
}
