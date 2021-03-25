/*****************************************************************************
 * Posting text files to pkt.
 *****************************************************************************
 * (c) 1999-2002 Husky team
 *
 * This file is part of HPT, part of Husky project.
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
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA
 * or download it from http://www.gnu.org site.
 *****************************************************************************
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
/* compiler.h */
#include <huskylib/compiler.h>
#include <huskylib/huskylib.h>

#ifdef HAS_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAS_DOS_H
#include <dos.h>
#endif

#if defined (HAS_SYS_SYSEXITS_H)
#include <sys/sysexits.h>
#endif
#if defined (HAS_SYSEXITS_H)
#include <sysexits.h>
#endif

#if (defined (__EMX__) || defined (__MINGW32__)) && defined (__NT__)
/* we can't include windows.h to prevent type redefinitions ... */
#define CharToOem CharToOemA
#endif
/*  fidoconf */
#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <huskylib/xstr.h>
#include <fidoconf/afixcmd.h>
#include <huskylib/recode.h>

#include <areafix/areafix.h>
/* hpt */
#include <global.h>
#include <pkt.h>
#include <version.h>
#include "../cvsdate.h"

#define clean_exit(exitcode) { \
        nfree(msg.fromUserName); \
        nfree(msg.toUserName); \
        nfree(msg.subjectLine); \
        exit(exitcode); \
}
static int quiet_mode = 0; /* quiet mode flag */
int main(int argc, char * argv[])
{
    s_pktHeader header;
    s_message msg;
    FILE * pkt;
    time_t t;
    struct tm * tm;
    char * area = NULL, * passwd = NULL, * tearl = NULL, * orig = NULL, * dir = NULL;
    FILE * text = NULL;
    int quit = 0, n = 1;
    char * textBuffer = NULL;
    char * versionStr = NULL;
    char * tmp = NULL, * fileName = NULL;
    char * cfgFile = NULL;

    memset(&header, '\0', sizeof(s_pktHeader));
    memset(&msg, '\0', sizeof(s_message));
    versionStr = GenVersionStr("txt2pkt", VER_MAJOR, VER_MINOR, VER_PATCH, VER_BRANCH, cvs_date);

    if(argc == 1)
    {
        printf("%s\n\n", versionStr);
        printf(
            "Usage: txt2pkt [options] <file>|-\n" "Options:\n" "\t -q          \t- quiet mode\n" "\t -c \"<file>\" \t- configuration file\n" "\t -xf \"<arg>\" \t- packet from address\n" "\t -xt \"<arg>\" \t- packet to address\n" "\t -p  \"<arg>\" \t- packet password\n" "\t -af \"<arg>\" \t- message from address\n" "\t -at \"<arg>\" \t- message to address\n" "\t -nf \"<arg>\" \t- message from name\n" "\t -nt \"<arg>\" \t- message to name\n"
                                                                                                                                                                                                                                                                                                                                                                                                                   "\t -e  \"<arg>\" \t- message echo name\n");
        printf(
            "\t -t  \"<arg>\" \t- message tearline\n" "\t -o  \"<arg>\" \t- message origin\n" "\t -s  \"<arg>\" \t- message subject\n" "\t -d  \"<path>\" \t- output directory\n"
                                                                                                                                       "\t <file> or -\t- text file to post. the '-' sign for standard input\n");
        exit(EX_OK);
    }

    for( ; n < argc; n++)
    {
        if(*argv[n] == '-' && argv[n][1])
        {
            switch(argv[n][1])
            {
                case 'c': /*  config  */

                    if(argv[n][2])
                    {
                        cfgFile = argv[n] + 2;
                    }
                    else if(++n < argc)
                    {
                        cfgFile = argv[n];
                    }
                    else
                    {
                        fprintf(stderr, "-c: Parameter (filename) is required\n");
                        clean_exit(EX_USAGE);
                    }

                    break;

                case 'a': /*  address */

                    switch(argv[n][2])
                    {
                        case 'f':

                            if(argv[n][3])
                            {
                                tmp = argv[n] + 3;
                            }
                            else if(++n < argc)
                            {
                                tmp = argv[n];
                            }
                            else
                            {
                                fprintf(stderr, "-af: Parameter (FTN address) is required\n");
                                clean_exit(EX_USAGE);
                            }

                            if(parseFtnAddrZS(tmp, &(msg.origAddr)) & FTNADDR_ERROR)
                            {
                                fprintf(stderr, "-af: Invalid FTN address\n");
                                clean_exit(EX_USAGE);
                            }

                            tmp = NULL;
                            break;

                        case 't':

                            if(argv[n][3])
                            {
                                tmp = argv[n] + 3;
                            }
                            else if(++n < argc)
                            {
                                tmp = argv[n];
                            }
                            else
                            {
                                fprintf(stderr, "-at: Parameter (FTN address) is required\n");
                                clean_exit(EX_USAGE);
                            }

                            if(parseFtnAddrZS(tmp, &(msg.destAddr)) & FTNADDR_ERROR)
                            {
                                fprintf(stderr, "-at: Invalid FTN address\n");
                                clean_exit(EX_USAGE);
                            }

                            tmp = NULL;
                            break;

                        default:
                            quit = 1;
                            break;
                    } /* switch */
                    break;

                case 'x': /*  address */

                    switch(argv[n][2])
                    {
                        case 'f':

                            if(argv[n][3])
                            {
                                tmp = argv[n] + 3;
                            }
                            else if(++n < argc)
                            {
                                tmp = argv[n];
                            }
                            else
                            {
                                fprintf(stderr, "-xf: Parameter (FTN address) is required\n");
                                clean_exit(EX_USAGE);
                            }

                            if(parseFtnAddrZS(tmp, &(header.origAddr)) & FTNADDR_ERROR)
                            {
                                fprintf(stderr, "-xf: Invalid FTN address\n");
                                clean_exit(EX_USAGE);
                            }

                            tmp = NULL;
                            break;

                        case 't':

                            if(argv[n][3])
                            {
                                tmp = argv[n] + 3;
                            }
                            else if(++n < argc)
                            {
                                tmp = argv[n];
                            }
                            else
                            {
                                fprintf(stderr, "-xt: Parameter (FTN address) is required\n");
                                clean_exit(EX_USAGE);
                            }

                            if(parseFtnAddrZS(tmp, &(header.destAddr)) & FTNADDR_ERROR)
                            {
                                fprintf(stderr, "-xt: Invalid FTN address\n");
                                clean_exit(EX_USAGE);
                            }

                            tmp = NULL;
                            break;

                        default:
                            quit = 1;
                            break;
                    } /* switch */
                    break;

                case 'n': /*  name */

                    switch(argv[n][2])
                    {
                        case 't':

                            if(argv[n][3])
                            {
                                tmp = argv[n] + 3;
                            }
                            else if(++n < argc)
                            {
                                tmp = argv[n];
                            }
                            else
                            {
                                fprintf(stderr, "-nt: Parameter (name) is required\n");
                                clean_exit(EX_USAGE);
                            }

                            if(strlen(tmp) > 36) /* Max "to" name, see FTS-1 */
                            {
                                fprintf(stderr,
                                        "-nt: Name too long, truncated to 36 characters.\n");
                                tmp[36] = '\0';
                            }

                            msg.toUserName = sstrdup(tmp);
                            tmp            = NULL;
#ifdef __NT__
                            CharToOem(msg.toUserName, msg.toUserName);
#endif
                            break;

                        case 'f':

                            if(argv[n][3])
                            {
                                tmp = argv[n] + 3;
                            }
                            else if(++n < argc)
                            {
                                tmp = argv[n];
                            }
                            else
                            {
                                fprintf(stderr, "-nf: Parameter (name) is required\n");
                                clean_exit(EX_USAGE);
                            }

                            if(strlen(tmp) > 36) /* Max "from" name, see FTS-1 */
                            {
                                fprintf(stderr,
                                        "-nf: Name too long, truncated to 36 characters.\n");
                                tmp[36] = '\0';
                            }

                            msg.fromUserName = sstrdup(tmp);
                            tmp = NULL;
#ifdef __NT__
                            CharToOem(msg.fromUserName, msg.fromUserName);
#endif
                            break;

                        default:
                            quit = 1;
                            break;
                    } /* switch */
                    break;

                case 'e': /*  echo name */

                    if(argv[n][2])
                    {
                        area = argv[n] + 2;
                    }
                    else if(++n < argc)
                    {
                        area = argv[n];
                    }
                    else
                    {
                        fprintf(stderr, "-e: Parameter (areatag) is required\n");
                        clean_exit(EX_USAGE);
                    }

                    for(tmp = area; *tmp; tmp++)
                    {
                        if(iscntrl(*tmp) || isspace(*tmp))
                        {
                            fprintf(stderr,
                                    "-e: Areatag is contains invalid character '%c'\n",
                                    *tmp);
                            clean_exit(EX_USAGE);
                        }
                    }
                    tmp = NULL;
                    break;

                case 'p': /*  password */

                    if(argv[n][2])
                    {
                        passwd = argv[n] + 2;
                    }
                    else if(++n < argc)
                    {
                        passwd = argv[n];
                    }
                    else
                    {
                        fprintf(stderr, "-p: Parameter (passowrd, 8 chars) is required\n");
                        clean_exit(EX_USAGE);
                    }

                    if(strlen(passwd) > 8)
                    {
                        fprintf(stderr, "Password too long, truncated to 8 characters\n");
                        passwd[8] = '\0';
                    }

                    break;

                case 't': /*  tearline */

                    if(argv[n][2])
                    {
                        tearl = argv[n] + 2;
                    }
                    else if(++n < argc)
                    {
                        tearl = argv[n];
                    }
                    else
                    {
                        fprintf(stderr, "-t: Parameter (tearline text) is required\n");
                        clean_exit(EX_USAGE);
                    }

#ifdef __NT__
                    CharToOem(tearl, tearl);
#endif
                    break;

                case 'o': /*  origin */

                    if(argv[n][2])
                    {
                        orig = argv[n] + 2;
                    }
                    else if(++n < argc)
                    {
                        orig = argv[n];
                    }
                    else
                    {
                        fprintf(stderr, "-o: Parameter (origin) is required\n");
                        clean_exit(EX_USAGE);
                    }

#ifdef __NT__
                    CharToOem(orig, orig);
#endif
                    break;

                case 'd': /*  directory */

                    if(argv[n][2])
                    {
                        dir = argv[n] + 2;
                    }
                    else if(++n < argc)
                    {
                        dir = argv[n];
                    }
                    else
                    {
                        fprintf(stderr, "-d: Parameter (directory name) is required\n");
                        clean_exit(EX_USAGE);
                    }

                    break;

                case 's': /*  subject */

                    if(argv[n][2])
                    {
                        tmp = argv[n] + 2;
                    }
                    else if(++n < argc)
                    {
                        tmp = argv[n];
                    }
                    else
                    {
                        fprintf(stderr, "-s: Parameter (subject) is required\n");
                        clean_exit(EX_USAGE);
                    }

                    if(strlen(tmp) > 72) /* Max "subject", see FTS-1 */
                    {
                        fprintf(stderr,
                                "-s: Subject line too long, truncated to 72 characters.\n");
                        tmp[72] = '\0';
                    }

                    msg.subjectLine = sstrdup(tmp);
                    tmp             = NULL;
#ifdef __NT__
                    CharToOem(msg.subjectLine, msg.subjectLine);
#endif
                    break;

                case 'q': /* quiet mode */
                    quiet_mode = 1;
                    break;

                default:
                    quit = 1;
                    break;
            } /* switch */

            if(quit)
            {
                fprintf(stderr, "Unknown option '%s', exit.\n", argv[n]);
                clean_exit(EX_USAGE);
            }
        }
        else
        {
            if(strcmp(argv[n], "-") == 0)
            {
                text = stdin;
            }
            else
            {
                text = fopen(argv[n], "rt");
            }

            if(text != NULL)
            {
                int cursize = TEXTBUFFERSIZE, c;
                /* reserve 512kb + 1 (or 32kb+1) text Buffer */
                textBuffer = safe_malloc(cursize);

                for(msg.textLength = 0; ; msg.textLength++)
                {
                    if(msg.textLength >= cursize)
                    {
                        textBuffer = safe_realloc(textBuffer, cursize += TEXTBUFFERSIZE);
                    }

                    c = getc(text);

                    if(c == EOF || c == 0)
                    {
                        textBuffer[msg.textLength] = 0;
                        break;
                    }

                    textBuffer[msg.textLength] = (char)c;

                    if('\r' == textBuffer[msg.textLength])
                    {
                        msg.textLength--;
                    }

                    if('\n' == textBuffer[msg.textLength])
                    {
                        textBuffer[msg.textLength] = '\r';
                    }
                } /* endfor */

                while(!feof(text))
                {
                    getc(text);
                }

                if(strcmp(argv[n], "-"))
                {
                    fclose(text);
                }
            }
            else
            {
                fprintf(stderr, "Text file not found, exit\n");
                exit(EX_NOINPUT);
            }
        }
    }

    if(!textBuffer)
    {
        fprintf(stderr, "Text file not specified, exit\n");
        exit(EX_NOINPUT);
    }

    config = readConfig(cfgFile);

    if(NULL == config)
    {
        fprintf(stderr, "Config not found, exit\n");
        exit(EX_UNAVAILABLE);
    }

    if(!quiet_mode)
    {
        printf("%s\n\n", versionStr);
    }

    header.hiProductCode   = HPT_PRODCODE_HIGHBYTE;
    header.loProductCode   = HPT_PRODCODE_LOWBYTE;
    header.majorProductRev = VER_MAJOR;
    header.minorProductRev = VER_MINOR;

    if(passwd != NULL)
    {
        strcpy(header.pktPassword, passwd);
    }

    header.pktCreated     = time(NULL);
    header.capabilityWord = 1;
    header.prodData       = 0;

    if(header.origAddr.zone == 0)
    {
        header.origAddr = msg.origAddr;
    }

    if(header.destAddr.zone == 0)
    {
        header.destAddr = msg.destAddr;
    }

#ifdef __UNIX__
    xstrcat(&tmp, (dir) ? dir : "./");

    if(tmp[strlen(tmp) - 1] != '/')
    {
        xstrcat(&tmp, "/");
    }

#else
    xstrcat(&tmp, (dir) ? dir : ".\\");

    if(tmp[strlen(tmp) - 1] != '\\')
    {
        xstrcat(&tmp, "\\");
    }

#endif

    /* Make pkt name */
    if(config->seqDir == NULL)
    {
        time_t tm   = time(NULL);
        int pathlen = strlen(tmp);
        char * tmpp;
        xscatprintf(&tmp, "%08lx.pkt", (long)tm++);
        tmpp = tmp + pathlen;
        pkt  = createPkt(tmp, &header);

        while(pkt == NULL)
        {
            sprintf(tmpp, "%08lx.pkt", (long)tm++);
            pkt = createPkt(tmp, &header);
        }

        if(!quiet_mode)
        {
            printf("%s\n", tmp);
        }
    }
    else
    {
        do
        {
            nfree(fileName);
            xscatprintf(&fileName, "%s%08x.pkt", tmp, GenMsgId(config->seqDir, config->seqOutrun));
        }
        while((pkt = createPkt(fileName, &header)) == NULL);

        if(!quiet_mode)
        {
            printf("%s\n", fileName);
        }
    }

    if(pkt != NULL)
    {
        t  = time(NULL);
        tm = localtime(&t);
        fts_time((char *)msg.datetime, tm);

        if(tearl || config->tearline)
        {
            *tmp = '\0';
            xscatprintf(&tmp, "\r--- %s\r", (tearl) ? tearl : config->tearline);
            xstrcat(&textBuffer, tmp);
        }

        if(msg.origAddr.zone == 0 && msg.origAddr.net == 0 && msg.origAddr.node == 0 &&
           msg.origAddr.point == 0)
        {
            msg.origAddr = config->addr[0];
        }

        if(area != NULL)
        {
            msg.attributes = 0;
            msg.netMail    = 0;
            *tmp           = '\0';
            strUpper(area);
            xscatprintf(&tmp,
                        " * Origin: %s (%d:%d/%d.%d)\r",
                        (orig) ? orig : (config->origin) ? config->origin : "",
                        msg.origAddr.zone,
                        msg.origAddr.net,
                        msg.origAddr.node,
                        msg.origAddr.point);
            xstrcat(&textBuffer, tmp);
            *tmp = '\0';
            xscatprintf(&tmp,
                        "SEEN-BY: %d/%d\r\1PATH: %d/%d\r",
                        header.origAddr.net,
                        header.origAddr.node,
                        header.origAddr.net,
                        header.origAddr.node);
            xstrcat(&textBuffer, tmp);
        }
        else
        {
            msg.attributes = 1;
            msg.netMail    = 1;
        }

        msg.text = createKludges(config, area, &msg.origAddr, &msg.destAddr, versionStr);

        if(!config->disableTID)
        {
            xscatprintf(&(msg.text), "\001TID: %s\r", versionStr);
        }

        xstrcat(&(msg.text), textBuffer);

        if(area == NULL)
        {
            time(&t);
            tm = gmtime(&t);
            xscatprintf(&(msg.text),
                        "\001Via %u:%u/%u.%u @%04u%02u%02u.%02u%02u%02u.UTC %s\r",
                        header.origAddr.zone,
                        header.origAddr.net,
                        header.origAddr.node,
                        header.origAddr.point,
                        tm->tm_year + 1900,
                        tm->tm_mon + 1,
                        tm->tm_mday,
                        tm->tm_hour,
                        tm->tm_min,
                        tm->tm_sec,
                        versionStr);
        }

        msg.textLength = strlen(textBuffer);
        nfree(textBuffer);
        nfree(versionStr);

        if(msg.fromUserName == NULL)
        {
            xstrcat(&msg.fromUserName, "Sysop");
        }

        if(msg.toUserName == NULL)
        {
            xstrcat(&msg.toUserName, "All");
        }

        if(msg.subjectLine == NULL)
        {
            xstrcat(&msg.subjectLine, "");
        }

        /*  load recoding tables */
        initCharsets();
        getctabs(NULL, config->outtab);

        if(config->outtab != NULL)
        {
            /*  recoding text to TransportCharSet */
            recodeToTransportCharset((char *)msg.text);
            recodeToTransportCharset((char *)msg.subjectLine);
            recodeToTransportCharset((char *)msg.fromUserName);
            recodeToTransportCharset((char *)msg.toUserName);
        }

        writeMsgToPkt(pkt, &msg);
        closeCreatedPkt(pkt);
/*      sleep(1); */
    }
    else
    {
        fprintf(stderr, "Could not create pkt, error message: %s", strerror(errno));
    } /* endif */

    doneCharsets();
    disposeConfig(config);
    return 0;
} /* main */
