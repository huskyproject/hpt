/*****************************************************************************
* Post for HPT (FTN NetMail/EchoMail Tosser)
*****************************************************************************
* Copyright (C) 1998-99
*
* Kolya Nesterov
*
* Fido:     2:463/7208.53
* Kiev, Ukraine
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
/* Revision log:
16.12.98 - first version, written at ~1:30, in the middle of doing
calculation homework on Theoretical Electrics, you understood ;)
18.12.98 - woops forgot copyright notice, minor fixes
tearline generation added
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef UNIX
#include <sysexits.h>
#endif

#include <version.h>
#include <toss.h>
#include <post.h>
#include <global.h>
#include <version.h>
#include <areafix.h>
#include <hpt.h>
#include <fidoconf/recode.h>
#include <scanarea.h>

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/xstr.h>
#include <smapi/progprot.h>

#if (defined(__EMX__) || defined(__MINGW32__)) && defined(__NT__)
/* we can't include windows.h for several reasons ... */
#ifdef __MINGW32__
int __stdcall CharToOemA(char *, char *);
#endif
#define CharToOem CharToOemA
#endif

#define MAX_LINELEN 45
#define LINPERSECTION 150

#define ENCODE_BYTE(b) (((b) == 0) ? 0x60 : ((b) + 0x20))

void print_help(void) {
    fprintf(stdout,"\n       Post a message to area:\n");
    fprintf(stdout,"              hpt post [options] file\n\n");
    fprintf(stdout,"              options are:\n\n");
    fprintf(stdout,"              -nf \"name from\"\n");
    fprintf(stdout,"                 message sender's name, if not included post  use\n");
    fprintf(stdout,"                 sysop name (see fidoconfig)\n\n");
    fprintf(stdout,"              -nt \"name to\"\n");
    fprintf(stdout,"                 message  receiver's  name,  if not included post\n");
    fprintf(stdout,"                 use \"All\"\n\n");
    fprintf(stdout,"              -af \"address from\"\n");
    fprintf(stdout,"                 message sender's address, if not  included  post\n");
    fprintf(stdout,"                 use first system address (see fidoconfig)\n\n");
    fprintf(stdout,"              -at \"address to\"\n");
    fprintf(stdout,"                 message receiver's address, *MUST BE PRESENT*\n\n");
    fprintf(stdout,"              -s \"subject\"\n");
    fprintf(stdout,"                 subject line, if not included then assumed to be\n");
    fprintf(stdout,"                 empty\n\n");
    fprintf(stdout,"              -e \"echo area\"\n");
    fprintf(stdout,"                 area to  post  echomail  message  into,  if  not\n");
    fprintf(stdout,"                 included message is posted to netmail\n\n");
    fprintf(stdout,"              -z \"tearline\"\n");
    fprintf(stdout,"                 tearline, if not included then assumed to be\n");
    fprintf(stdout,"                 empty line\n\n");
    fprintf(stdout,"              -o \"origin\"\n");
    fprintf(stdout,"                 origin, if not included then assumed to be name\n");
    fprintf(stdout,"                 of station in config-file\n\n");
    fprintf(stdout,"              -f flags(s)\n");
    fprintf(stdout,"                 flags  to  set  to the posted msg. possible ones\n");
    fprintf(stdout,"                 are: pvt, crash, read, sent, att,  fwd,  orphan,\n");
    fprintf(stdout,"                 k/s, loc, hld, xx2,  frq, rrq, cpt, arq, urq;\n");
    fprintf(stdout,"                 use it without trailing brackets like this:  pvt\n");
    fprintf(stdout,"                 loc k/s\n\n");
    fprintf(stdout,"              -x export message to echo links\n\n");
    fprintf(stdout,"              -d erase input file after posting\n\n");
    fprintf(stdout,"              -u uue-multipart posting \n\n");
    fprintf(stdout,"              -h get help\n\n");
    fprintf(stdout,"              file - text file to post into echo or \"-\" for stdin\n\n");
    exit(EX_OK);
}

void post(int c, unsigned int *n, char *params[])
{
    char *area = NULL, *tearl = NULL, *origin = NULL;
    FILE *text = NULL;
    FILE *tmpfile = NULL;
    char *tmpname = NULL;
    char *fname = NULL;
    s_area *echo = NULL;
    long attr;
    int  sections=0;
    int part = 0;
    struct _minf m;
    
    s_message msg;
    
    CHAR *textBuffer = NULL;
    
    int quit;
    int export=0;
    int erasef=0;
    int uuepost=0;
    
    time_t t = time (NULL);
    struct tm *tm;
    
    if (params[*n]!='\0' && params[*n][1]=='h') print_help();
    
    if (config==NULL) processConfig();
    if ( initSMAPI == -1 ) {
        // init SMAPI
        initSMAPI = 0;
        m.req_version = 0;
        m.def_zone = (UINT16) config->addr[0].zone;
        if (MsgOpenApi(&m) != 0) {
            exit_hpt("MsgApiOpen Error",1);
        } /*endif */
    }
    
    memset(&msg, 0, sizeof(s_message));
    
    for (quit = 0;*n < c && !quit; (*n)++) {
        if (*params[*n] == '-' && params[*n][1] != '\0') {
            switch(params[*n][1]) {
            case 'a':    // address
                switch(params[*n][2]) {
                case 't':
                    string2addr(params[++(*n)], &(msg.destAddr));
                    break;
                case 'f':
                    string2addr(params[++(*n)], &(msg.origAddr));
                    break;
                default:
                    quit = 1;
                    break;
                }; break;
                case 'n':    // name
                    switch(params[*n][2]) {
                    case 't':
                        msg.toUserName = (char *) safe_malloc(strlen(params[++(*n)]) + 1);
                        strcpy(msg.toUserName, params[*n]);
#ifdef __NT__
                        CharToOem(msg.toUserName, msg.toUserName);
#endif
                        break;
                    case 'f':
                        msg.fromUserName = (char *) safe_malloc(strlen(params[++(*n)]) + 1);
                        strcpy(msg.fromUserName, params[*n]);
#ifdef __NT__
                        CharToOem(msg.fromUserName, msg.fromUserName);
#endif
                        break;
                    default:
                        quit = 1;
                        break;
                    }; break;
                    case 'f':    // flags
                        for ((*n)++; params[*n]!=NULL && (attr=str2attr(params[*n]))!=-1L;) {
                            msg.attributes |= attr;
                            (*n)++;
                        }
                        (*n)--;
                        break;
                    case 'e':    // echo name
                        area = params[++(*n)];
                        echo = getArea(config, area);
                        strUpper(area);
                        strUpper(echo->areaName);
                        break;
                    case 's':    // subject
                        msg.subjectLine = (char *) safe_malloc(strlen(params[++(*n)]) + 1);
                        strcpy(msg.subjectLine, params[*n]);
#ifdef __NT__
                        CharToOem(msg.subjectLine, msg.subjectLine);
#endif
                        break;
                    case 'x':    // export message
                        export=1;
                        break;
                    case 'd':    // erase input file after posting
                        erasef=1;
                        break;
                    case 'u':    // uue-multipart posting
                        uuepost=1;
                        break;
                    case 'z':
                        tearl = (char *) safe_malloc(strlen(params[++(*n)]) + 1);
                        strcpy(tearl, params[*n]);
                        break;
                    case 'o':
                        origin = (char *) safe_malloc(strlen(params[++(*n)]) + 1);
                        strcpy(origin, params[*n]);
                        break;
                    default:
                        w_log(LL_ERROR, "post: unknown switch %s", params[*n]);
                        quit = 1;
                        break;
            };
        } else if (textBuffer == NULL) {
            if (strcmp(params[*n], "-")) {
                if(fexist(params[*n])) 
                    text = fopen(params[*n], "rt");
            }
            else
                text = stdin;
            if (text != NULL) {
                if( uuepost && text != stdin)
                {
                    long lines = 1;
                    int	linelen;
                    int linecnt;
                    UCHAR inbuf [MAX_LINELEN];
                    UCHAR *inbytep;
                    char outbuf [5];
                    
                    xstrscat(&tmpname, config->tempOutbound, "hptucode.$$$",NULL);
                    text = freopen(params[*n], "rb", text);
                    tmpfile = fopen (tmpname, "wt");
                    if (tmpfile == NULL)
                    {
                        exit_hpt("Couldn't open tmpfile file", 1);
                    }
                    fname = GetFilenameFromPathname(params[*n]);
                    /* Write the 'begin' line, giving it a mode of 0600 */
                    fprintf (tmpfile, "begin 600 %s\n", fname);
                    do
                    {
                        
                        linelen = fread (inbuf, 1, MAX_LINELEN, text);
                        fputc (ENCODE_BYTE (linelen), tmpfile);
                        
                        /* Encode the line */
                        for (linecnt = linelen, inbytep = inbuf;
                        linecnt > 0;
                        linecnt -= 3, inbytep += 3)
                        {
                            /* Encode 3 bytes from the input buffer */
                            outbuf [0] = ENCODE_BYTE ((inbytep [0] & 0xFC) >> 2);
                            outbuf [1] = ENCODE_BYTE (((inbytep [0] & 0x03) << 4) +
                                ((inbytep [1] & 0xF0) >> 4));
                            outbuf [2] = ENCODE_BYTE (((inbytep [1] & 0x0F) << 2) +
                                ((inbytep [2] & 0xC0) >> 6));
                            outbuf [3] = ENCODE_BYTE (inbytep [2] & 0x3F);
                            outbuf [4] = '\0';
                            
                            /* Write the 4 encoded bytes to the file */
                            fprintf (tmpfile, "%s", outbuf);
                        }
                        
                        fprintf (tmpfile, "\n");
                        lines++;
                    } while (linelen != 0);
                    
                    fprintf (tmpfile, "end\n");
                    lines++;
                    sections = (lines%LINPERSECTION==0) ?
                        lines/LINPERSECTION : lines/LINPERSECTION+1;
                    
                    fclose (tmpfile);
                    tmpfile = freopen (tmpname, "rt",tmpfile);
                    textBuffer = safe_malloc(4*(MAX_LINELEN/3 + 1));
                }
                else
                {
                    int c, cursize=TEXTBUFFERSIZE;
                    /* reserve 512kb + 1 (or 32kb+1) text Buffer */
                    textBuffer = safe_malloc(cursize);
                    for (msg.textLength = 0;; msg.textLength++) {
                        if (msg.textLength >= cursize)
                            textBuffer = safe_realloc(textBuffer, 
                            cursize += TEXTBUFFERSIZE);
                        c = getc(text);
                        if (c == EOF || c == 0) {
                            textBuffer[msg.textLength] = 0;
                            break;
                        }
                        textBuffer[msg.textLength] = (char)c;
                        if ('\r' == textBuffer[msg.textLength])
                            msg.textLength--;
                        if ('\n' == textBuffer[msg.textLength])
                            textBuffer[msg.textLength] = '\r';
                    }
                } /* endfor */
                while (!feof(text))
                    getc(text);
                if (strcmp(params[*n], "-"))
                    fclose(text);
                if (strcmp(params[*n], "-")&&erasef==1)
                    remove(params[*n]);
                if( uuepost && text == stdin)
                {
                    quit = 1;
                    nfree(textBuffer);
                }
            } else {
                w_log(LL_ERROR, "post: failed to open input file %s", params[*n]);
                quit = 1;
            }
        } else {
            w_log(LL_ERROR, "post: several input files on cmd line");
            quit = 1;
        }
    }
    // won't be set in the msgbase, because the mail is processed if it were received
    (*n)--; tm = localtime(&t);
    strftime((char *)msg.datetime, 21, "%d %b %y  %H:%M:%S", tm);
    if ((msg.destAddr.zone != 0 || area) && (textBuffer != NULL) && !quit) {
        // Dumbchecks
        if (msg.origAddr.zone == 0) // maybe origaddr isn't specified ?
            msg.origAddr = config->addr[0];
        if (msg.fromUserName == NULL)
            msg.fromUserName = safe_strdup(config->sysop);
        if (msg.toUserName == NULL)
            msg.toUserName = safe_strdup("All");
        if (msg.subjectLine == NULL)
            msg.subjectLine = safe_strdup("");
        
        msg.netMail = (char)(area == NULL);
        /*FIXME*/
        if (msg.netMail) echo=&(config->netMailAreas[0]);
        
        
        w_log('1', "Start posting...");
        part = 0; 
        do
        {
            
            if(!msg.netMail) memset(&msg.destAddr, '\0', sizeof(s_addr));

            msg.text = createKludges(area, &msg.origAddr, &msg.destAddr);

            if( uuepost )
            {
                char *res;
                int i; 
                xscatprintf(&msg.text, "\rsection %d of %d of file %s < %s >\r\r",
                            part+1,sections,fname,versionStr);
                for(i = 0; i < LINPERSECTION; i++)
                {
                    res = fgets(textBuffer,4*(MAX_LINELEN/3 + 1),tmpfile);
                    if(res)
                        xscatprintf(&msg.text,"%s\r",textBuffer);
                    else
                        break;
                }
                part++;
            }
            else
            {
                xstrcat((char **)(&(msg.text)), (char *)textBuffer);
            }

            xscatprintf(&msg.text, "\r--- %s\r * Origin: %s (%s)\r",
                (tearl) ? tearl : (config->tearline) ? config->tearline : "",
                (origin) ? origin : (config->origin) ? config->origin : config->name,
                aka2str(msg.origAddr));
            
            msg.textLength = strlen(msg.text);

            if ((msg.destAddr.zone + msg.destAddr.net +
                msg.destAddr.node + msg.destAddr.point)==0)
                w_log('5',
                "Posting msg from %u:%u/%u.%u -> %s in area: %s",
                msg.origAddr.zone, msg.origAddr.net,
                msg.origAddr.node, msg.origAddr.point,
                msg.toUserName,
                (area) ? area : echo->areaName);
            else w_log('5',
                "Posting msg from %u:%u/%u.%u -> %u:%u/%u.%u in area: %s",
                msg.origAddr.zone, msg.origAddr.net,
                msg.origAddr.node, msg.origAddr.point,
                msg.destAddr.zone, msg.destAddr.net,
                msg.destAddr.node, msg.destAddr.point,
                (area) ? area : echo->areaName);
            
            if (!export && echo->fileName) {
                msg.recode |= (REC_HDR|REC_TXT); // msg already in internal Charset
                putMsgInArea(echo, &msg, 1, msg.attributes);
            }
            else {
                // recoding from internal to transport charSet
                if (config->outtab != NULL) {
                    recodeToTransportCharset((CHAR*)msg.fromUserName);
                    recodeToTransportCharset((CHAR*)msg.toUserName);
                    recodeToTransportCharset((CHAR*)msg.subjectLine);
                    recodeToTransportCharset((CHAR*)msg.text);
                }
                if (msg.netMail) {
                    processNMMsg(&msg, NULL, NULL, 0, MSGLOCAL);
                    cmPack = 1;
                }
                else {
                    processEMMsg(&msg, msg.origAddr, 1, (MSGSCANNED|MSGSENT|MSGLOCAL));
                }
            }
            nfree(msg.text);
        } while (part < sections);

        nfree(tearl); nfree(origin);
        if( uuepost )
        {
            fclose(tmpfile);
            remove(tmpname);
        }
        if ((config->echotosslog) && (!export)) {
            FILE *f=fopen(config->echotosslog, "a");
            if (f==NULL)
                w_log(LL_ERROR, "Could not open or create EchoTossLogFile.");
            else {
                fprintf(f, "%s\n", echo->areaName);
                fclose(f);
            }
        }
    }
    
    if (textBuffer == NULL && !quit) {
        w_log(LL_CRIT, "post: no input source specified");
        //exit(EX_NOINPUT);
    }
    else if (msg.destAddr.zone == 0 && !quit) {
        w_log(LL_CRIT,"post: attempt to post netmail msg without specifyng dest address");
        //exit(EX_USAGE);
    }
    nfree(textBuffer);
    freeMsgBuffers(&msg);
}
