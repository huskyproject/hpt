/* Arefix improvement by Max Chernogor 2:464/108  */

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/xstr.h>
#include <global.h>
#include <toss.h>
#include <areafix.h>
#include <query.h>
//#include <hpt.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#if !defined(__TURBOC__) && !(defined(_MSC_VER) && (_MSC_VER >= 1200))
#include <unistd.h>
#endif
#if (defined (__WATCOMC__) && defined (__NT__)) || defined(__TURBOC__)
#include <dos.h>
#endif

#define nbufSize 2*1024

static  time_t  when;
static  time_t  tnow;
const   long    secInDay = 3600*24;
const char czFreqArea[] = "freq";
const char czIdleArea[] = "idle";
const char czKillArea[] = "kill";
const int  cnDaysToKeepFreq = 5;

extern s_query_areas *queryAreasHead;
extern s_message **msgToSysop;
extern char       *versionStr;
extern void makeMsgToSysop(char *areaName, s_addr fromAddr, s_addr *uplinkAddr);

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

char* makeAreaParam(s_link *creatingLink, char* c_area, char* msgbDir)
{
    char *msgbFileName=NULL, *acDef;
    char *msgbtype, *newAC=NULL, *desc, *quote_areaname;
    char *cp, *buff=NULL;                    /* temp. usage */

    msgbFileName = makeMsgbFileName(c_area);

    // translating name of the area to lowercase/uppercase
    if (config->createAreasCase == eUpper) strUpper(c_area);
    else strLower(c_area);

    // translating filename of the area to lowercase/uppercase
    if (config->areasFileNameCase == eUpper) strUpper(msgbFileName);
    else strLower(msgbFileName);

    acDef = creatingLink->autoAreaCreateDefaults;
    xscatprintf(&newAC, "%s%s", (acDef) ? " " : "", (acDef) ? acDef : "");

    msgbtype = hpt_stristr(newAC, "-b ");

    if(!msgbDir)
        msgbDir=(creatingLink->msgBaseDir) ? 
        creatingLink->msgBaseDir : config->msgBaseDir;

    quote_areaname = strchr(TRUE_COMMENT "\"", *c_area) ? "\"" : "";

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
             //"subdirify" the message base path if the
             //user wants this. this currently does not
             //work with the -dosfile option
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
            sleep(1); // to prevent time from creating equal numbers
            xscatprintf(&buff,"EchoArea %s%s%s %s%8lx%s",
	        quote_areaname, c_area, quote_areaname,
                msgbDir, (long)time(NULL),
                (msgbtype) ? "" : " -b Squish");
        }

    } else {
        // passthrough
        xscatprintf(&buff, "EchoArea %s%s%s passthrough",
	    quote_areaname, c_area, quote_areaname);

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
    return buff; 
}

int autoCreate(char *c_area, s_addr pktOrigAddr, s_addr *forwardAddr)
{
    FILE *f;
    char *fileName;
    char *buff=NULL, *hisaddr=NULL;
    char *msgbDir=NULL;
    s_link *creatingLink;
    s_area *area; 
    s_query_areas* areaNode=NULL;
    size_t i;
    unsigned int j;
    char pass[] = "passthrough";


    if (strlen(c_area)>60) return 11;
    if (!isValidConference(c_area) || isPatternLine(c_area)) return 7;

    creatingLink = getLinkFromAddr(config, pktOrigAddr);

    if (creatingLink == NULL) {
	w_log('9', "creatingLink == NULL !!!");
	return 8;
    }

    fileName = creatingLink->autoAreaCreateFile;
    if (fileName == NULL) fileName = cfgFile ? cfgFile : getConfigFileName();

    f = fopen(fileName, "a+b");
    if (f == NULL) {
	fprintf(stderr,"autocreate: cannot open config file\n");
	return 9;
    }
   
    if(config->areafixQueueFile)
    {
        areaNode = af_CheckAreaInQuery(c_area, &pktOrigAddr, NULL, FIND);
        if( areaNode ) // if area in query
        {
            if( stricmp(areaNode->type,czKillArea) == 0 )
                return 4;  // area already unsubscribed
            if( stricmp(areaNode->type,czFreqArea) == 0 && 
                addrComp(pktOrigAddr, areaNode->downlinks[0])!=0)
                return 4;  // wrong link to autocreate from
            if( stricmp(areaNode->type,czFreqArea) == 0 )
            {
                // removinq area from query. it is autocreated now
                queryAreasHead->nFlag = 1; // query was changed
                areaNode->type[0] = '\0';  // mark as deleted
            }
            // setting up msgbase dir
            if (config->createFwdNonPass==0)
                msgbDir = pass;
            else
                msgbDir = creatingLink->msgBaseDir;
            // try to find our aka in links of queried area
            // if not foun area will be passthrough
            for (i = 1; i < areaNode->linksCount; i++)
                for(j = 0; j < config->addrCount; j++)
                    if (addrComp(areaNode->downlinks[i],config->addr[j])==0)
                    {
                        msgbDir = creatingLink->msgBaseDir; break;
                    }
        }
    }

    // making address of uplink
    xstrcat(&hisaddr, aka2str(pktOrigAddr));
        
    buff = makeAreaParam(creatingLink , c_area, msgbDir);

    // add new created echo to config in memory
    parseLine(buff, config);

    // subscribe uplink if he is not subscribed
    area = &(config->echoAreas[config->echoAreaCount-1]);
    if ( isAreaLink(creatingLink->hisAka,area)==-1 ) {
	xscatprintf(&buff, " %s", hisaddr);
	addlink(creatingLink, area);
    }

    // subscribe downlinks if present
    if(areaNode) { // areaNode == NULL if areafixQueueFile isn't used
        // prevent subscribing of defuault links
        // or not existing links
        for(i = 1; i < areaNode->linksCount; i++) {
            if( ( isAreaLink( areaNode->downlinks[i],area ) == -1 ) &&
                ( getLinkFromAddr(config,areaNode->downlinks[i])) &&
                ( !isOurAka(areaNode->downlinks[i]) )
            ) {
            xstrcat( &buff, " " );
            xstrcat( &buff, aka2str(areaNode->downlinks[i]) );
            addlink(getLinkFromAddr(config,areaNode->downlinks[i]), area);
            }
        }
    }

    // fix if dummys del \n from the end of file
    fseek (f, -1L, SEEK_END);
    if (getc(f) != '\n') {
	fseek (f, 0L, SEEK_END);  // not neccesary, but looks better ;)
	putc ( '\n', f);
    } else {
    fseek (f, 0L, SEEK_END);
    }
    fprintf(f, "%s%s", buff, cfgEol()); // add line to config
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


s_query_areas*  af_AddAreaListNode(char *areatag, const char *type);
void            af_DelAreaListNode(s_query_areas* node);
void            af_AddLink(s_query_areas* node, s_addr *link);

s_query_areas* af_CheckAreaInQuery(char *areatag, s_addr *uplink, s_addr *dwlink, e_query_action act)
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
                    af_AddLink( tmpNode, dwlink ); // add link to queried area
                } else {
                    tmpNode = NULL;  // link already in query
                }
            } else {
                strcpy(tmpNode->type,czFreqArea); // change state to @freq"
                af_AddLink( tmpNode, dwlink );
            }
        } else { // area not found, so add it
            areaNode = af_AddAreaListNode( areatag, czFreqArea );
            if(strlen( areatag ) > queryAreasHead->linksCount) //max areanane lenght
                queryAreasHead->linksCount = strlen( areatag );
            af_AddLink( areaNode, uplink );
            af_AddLink( areaNode, dwlink );
        }
        break;
    case ADDDELETED:
        if( bFind ) {
        } else {
            areaNode = af_AddAreaListNode( areatag, czKillArea );
            if(strlen( areatag ) > queryAreasHead->linksCount)
                queryAreasHead->linksCount = strlen( areatag );
            af_AddLink( areaNode, uplink );
        }
        break;
    }
    return tmpNode;
}

char* af_Req2Idle(char *areatag, char* report, s_addr linkAddr)
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
                    sizeof(s_addr)*(areaNode->linksCount-i));
                areaNode->linksCount--;
                queryAreasHead->nFlag = 1; // query was changed
                if(areaNode->linksCount == 1)
                {
                    strcpy(areaNode->type,czIdleArea);
                    areaNode->bTime = tnow;
                    areaNode->eTime = when;
                    w_log('8', "areafix: make request idle for area: %s", areaNode->name);
                }
                xscatprintf(&report, " %s %s  request canceled\r",
                    areaNode->name, 
                    print_ch(49-strlen(areaNode->name), '.'));
                w_log('8', "areafix: request canceled for [%s] area: %s",aka2str(linkAddr),
                    areaNode->name);
            }
        }
        tmpNode = tmpNode->next;
    }
    return report;
}

void af_QueueReport()
{
    s_query_areas *tmpNode  = NULL;
    const char rmask[]="%-37.37s %-4.4s %11.11s %-16.16s %-7.7s\r";
    char type[5]="";
    char state[8]="";
    char link1[17]="";
    char link2[17]="";
    char* report = NULL;
    char* header = NULL;

    int netmail=0;
    if( !queryAreasHead ) af_OpenQuery();

    tmpNode = queryAreasHead;
    while(tmpNode->next)
    {
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
    if(!report)
        return;
    xscatprintf(&header,rmask,"Area","Act","From","By","Details");
    xscatprintf(&header,"%s\r", print_ch(79,'-'));
    xstrcat(&header, report);
    report = header;
    if (config->ReportTo) {
	if (stricmp(config->ReportTo,"netmail")==0) netmail=1;
	else if (getNetMailArea(config, config->ReportTo) != NULL) netmail=1;
    } else netmail=1;

    msgToSysop[0] = makeMessage(&(config->addr[0]),&(config->addr[0]), 
        versionStr, netmail ? config->sysop : "All", "requests report", netmail);
    msgToSysop[0]->text = createKludges(netmail ? NULL : config->ReportTo, 
        &(config->addr[0]), &(config->addr[0]));
    
    msgToSysop[0]->recode |= (REC_HDR|REC_TXT);

    xstrcat( &(msgToSysop[0]->text), report );
    
    writeMsgToSysop();
    freeMsgBuffers(msgToSysop[0]);
    nfree(msgToSysop[0]);
}

void af_QueueUpdate()
{
    s_query_areas *tmpNode  = NULL;

    if( !queryAreasHead ) af_OpenQuery();

    tmpNode = queryAreasHead;
    while(tmpNode->next)
    {
        tmpNode = tmpNode->next;
        if( tmpNode->eTime > tnow )
            continue;
        if( stricmp(tmpNode->type,czFreqArea) == 0 )
        {
            queryAreasHead->nFlag = 1; // query was changed
            strcpy(tmpNode->type, czKillArea);
            w_log( LL_AREAFIX, "Request for %s removed is going to be killed",tmpNode->name);
            continue;
        }
        if( stricmp(tmpNode->type,czKillArea) == 0 )
        {
            queryAreasHead->nFlag = 1;
            tmpNode->type[0] = '\0';
            w_log( LL_AREAFIX, "Request for %s removed from queue file",tmpNode->name);
            continue;
        }
        if( stricmp(tmpNode->type,czIdleArea) == 0 )
        {
            queryAreasHead->nFlag = 1; // query was changed
            strcpy(tmpNode->type, czKillArea);
            w_log( LL_AREAFIX, "Request for %s removed is going to be killed",tmpNode->name);
        }
    }
}

int af_OpenQuery()
{
    FILE *queryFile;
    char *line = NULL;
    char *token = NULL;
    struct  tm tr;
    char seps[]   = " \t\n";
    s_query_areas *areaNode = NULL;

    if( queryAreasHead )  // list already exists
        return 0;

    time( &tnow );
    when = tnow + cnDaysToKeepFreq*secInDay;

    queryAreasHead = af_AddAreaListNode("","");

    if ((queryFile = fopen(config->areafixQueueFile,"r")) == NULL) // empty query file
        return 0;

    while ((line = readLine(queryFile)) != NULL)
    {
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
                areaNode->eTime = mktime(&tr);
            }

            token = strtok( NULL, seps );            
            while( token != NULL )
            {
                
                areaNode->linksCount++;
                areaNode->downlinks = 
                safe_realloc( areaNode->downlinks,
                              sizeof(s_addr)*areaNode->linksCount );
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
    char buf[nbufSize] = "";
    char *p;
    int nSpace = 0;
    size_t i = 0;
    struct  tm t1,t2;
    int writeChanges = 0;
    char *tmpFileName=NULL;
    
    FILE *queryFile=NULL, *resQF;
    s_query_areas *delNode = NULL;
    s_query_areas *tmpNode  = NULL;

    
    if( !queryAreasHead ) {  // list does not exist
        return 0;
    }

    if(queryAreasHead->nFlag == 1) {
        writeChanges = 1;
    }
    if((tmpFileName=tmpnam(tmpFileName)) != NULL) {
        if (writeChanges) queryFile = fopen(tmpFileName,"w");
    } else {
        w_log('9',"areafix: cannot create tmp file");
        writeChanges = 0;
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
    af_DelAreaListNode(queryAreasHead);
    queryAreasHead = NULL;
    if(writeChanges)  {
        fclose(queryFile);
        w_log(LL_FILE,"query.c::af_CloseQuery(): created '%s' ",tmpFileName);
        queryFile = fopen(tmpFileName,"r");
        resQF     = fopen(config->areafixQueueFile,"w");
    if ( !queryFile && !resQF ) {
	if (!quiet) fprintf(stderr, "areafix: cannot write to Queue File \"%s\" \n", config->areafixQueueFile);
	w_log(LL_ERR,"areafix: cannot write to Queue File \"%s\" ", config->areafixQueueFile);
    } else {
        int ch;
        while( (ch=getc(queryFile)) != EOF ) putc(ch, resQF); 
        fclose(queryFile); fclose(resQF); 
    }
    }
    if(writeChanges) 
    {   
        remove(tmpFileName);
        w_log(LL_FILE,"query.c::af_CloseQuery(): deleted '%s' ",tmpFileName);
    }
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
    
    newNode->name = safe_strdup(areatag);
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

void af_AddLink(s_query_areas* node, s_addr *link)
{
    node->linksCount++;
    node->downlinks = 
        safe_realloc( node->downlinks, sizeof(s_addr)*node->linksCount );
    memcpy( &(node->downlinks[node->linksCount-1]) ,link, sizeof(s_addr) );
    node->bTime = tnow;
    node->eTime = when;
    queryAreasHead->nFlag = 1; // query was changed
}
