/*****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 * Copyright (C) 1997-1999
 *
 * Matthias Tichy
 *
 * Fido:     2:2433/1245 2:2433/1247 2:2432/605.14
 * Internet: mtt@tichy.de
 *
 * Grimmestr. 12         Buchholzer Weg 4
 * 33098 Paderborn       40472 Duesseldorf
 * Germany               Germany
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
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>

#include <huskylib/compiler.h>
#include <huskylib/huskylib.h>

#ifdef HAS_IO_H
#include <io.h>
#endif

#ifdef HAS_UNISTD_H
#include <unistd.h>
#endif

#if defined (HAS_SYS_SYSEXITS_H)
#include <sys/sysexits.h>
#endif
#if defined (HAS_SYSEXITS_H)
#include <sysexits.h>
#endif

#include <smapi/msgapi.h>

#include <fidoconf/fidoconf.h>
#include <huskylib/xstr.h>
#include <fidoconf/common.h>
#include <huskylib/dirlayer.h>
#include <fidoconf/afixcmd.h>
#include <huskylib/log.h>
#include <huskylib/recode.h>
#include <fidoconf/version.h>
#include <fidoconf/stat.h>
#include <areafix/areafix.h>
#include <areafix/afglobal.h>
#include <areafix/query.h>

#ifdef USE_HPTZIP
#   include <hptzip/hptzip.h>
#endif

#include "version.h"
#include "../cvsdate.h"
#include "pkt.h"
#include "global.h"
#include "hpt.h"
#include "hptafix.h"
#include "toss.h"
#include "scan.h"
#include "fcommon.h"
#include "post.h"
#include "link.h"

#ifdef DO_PERL
#include "hptperl.h"
#endif
#ifdef _MSC_VER
#ifdef DO_PERL
#include "delayimp.h"
/*  This is the failure hook, dliNotify = {dliFailLoadLib|dliFailGetProc} */
#if defined (__cplusplus)
extern "C"
#endif
extern PfnDliHook
#if (_MSC_VER >= 1300)
__pfnDliFailureHook2;
#else
__pfnDliFailureHook;
#endif
#endif
#endif

s_log * hpt_log         = NULL;
s_message ** msgToSysop = NULL;
char * scanParmA;
char * scanParmF;
char force = 0;
char ** hpt_environ = NULL;
/* kn: I've really tried not to break it.
   FIXME: if there is pack and scan options on cmd line - one set
   of options are lost */
int processExportOptions(int * i, int argc, char ** argv)
{
    int rc = 0;

    while((*i) < argc - 1)
    {
        if(argv[(*i) + 1][0] == '-' && (argv[(*i) + 1][1] == 'w' || argv[(*i) + 1][1] == 'W'))
        {
            noHighWaters = 1;
            (*i)++;
            continue;
        } /* endif */

        if(argv[(*i) + 1][0] == '-' && (argv[(*i) + 1][1] == 'f' || argv[(*i) + 1][1] == 'F'))
        {
            if(stricmp(argv[(*i) + 1], "-f") == 0)
            {
                (*i)++;
                scanParmF = argv[(*i) + 1];
            }
            else
            {
                scanParmF = argv[(*i) + 1] + 2;
            } /* endif */

            rc |= 2;
            (*i)++;
            continue;
        }
        else if(argv[(*i) + 1][0] == '-' && (argv[(*i) + 1][1] == 'a' || argv[(*i) + 1][1] == 'A'))
        {
            if(stricmp(argv[(*i) + 1], "-a") == 0)
            {
                (*i)++;
                scanParmA = argv[(*i) + 1];
            }
            else
            {
                scanParmA = argv[(*i) + 1] + 2;
            } /* endif */

            rc |= 4;
            (*i)++;
            continue;
        } /* endif */

        break;
    } /* endwhile */
    return rc != 0 ? rc : 1;
} /* processExportOptions */

void start_help(void)
{
    printf("%s\n\n", versionStr);
    printf("Usage: hpt [-c config] [options]\n");
    printf("   hpt toss - toss mail\n");
    printf("   hpt toss -b[f] - toss mail from badarea [force]\n");
    printf("   hpt scan - scan echomail\n");
    printf("   hpt scan -w - scan echomail without highwaters\n");
    printf("   hpt scan -a <pattern> - scan echomail from areas matching\n");
    printf("                        the pattern\n");
    printf("   hpt scan -f [filename] - scan only areas listed in this file\n");
    printf("   hpt post [options] file - post a message (for details run \"hpt post -h\")\n");
    printf("   hpt pack - pack netmail\n");
    printf("   hpt pack -a <pattern> - pack netmail only from areas matching <pattern>\n");
    printf("   hpt pack -f [filename] - pack netmail only from areas listed in this file\n");
    printf("   hpt link [areamask] - link messages\n");
    printf("   hpt link -j [areamask] - link jam areas using CRC (quicker)\n");
    printf("   hpt afix [-f] [-s] [<addr> command] - send command to our areafix\n");
    printf("                                         from the name of <addr>\n");
    printf("             -f - also send the same command to the link's areafix\n");
    printf("             -s - do not send reply from our areafix to the link\n");
    printf("   hpt qupd - update queue file and do some areafix jobs\n");
    printf("   hpt qrep - make report based on information from queue file\n");
    printf("   hpt qrep -d - make report containing only changes\n");
    printf("   hpt relink <pattern> <addr> - refresh subscription for areas matching\n");
    printf("                        the pattern\n");
    printf("   hpt relink -f [filename] <addr> - refresh only areas listed in this file\n");
    printf("   hpt resubscribe <pattern> <fromaddr> <toaddr> - move subscription from\n");
    printf("                        one link to another for the areas matching the pattern\n");
    printf("   hpt resubscribe -f [file] <fromaddr> <toaddr> - move subscription from one\n");
    printf("                        link to another for the areas matching the area patterns\n");
    printf("                        listed in this file with one pattern on a line\n");
    printf("   hpt pause - set pause for links who don't poll our system\n");
    printf("   hpt -q [options] - quiet mode (no screen output)\n");
} /* start_help */

e_exitCode processCommandLine(int argc, char ** argv)
{
    int i         = 0;
    e_exitCode rc = ex_OK;

    if(argc == 1)
    {
        start_help();
        rc = ex_Help;
    }

    while(i < argc - 1)
    {
        i++;

        if(0 == stricmp(argv[i], "toss"))
        {
            cmToss = 1;

            if(i < argc - 1)
            {
                if(stricmp(argv[i + 1], "-b") == 0)
                {
                    cmToss = 2;
                    break;
                }
                else if(stricmp(argv[i + 1], "-bf") == 0)
                {
                    cmToss = 2;
                    force  = 1;
                    break;
                }
            }

            continue;
        }
        else if(stricmp(argv[i], "scan") == 0)
        {
            cmScan = processExportOptions(&i, argc, argv);
            continue;
        }
        else if(stricmp(argv[i], "pack") == 0)
        {
            cmPack = processExportOptions(&i, argc, argv);
            continue;
        }
        else if(stricmp(argv[i], "link") == 0)
        {
            if(i < argc - 1 && stricmp(argv[i + 1], "-j") == 0)
            {
                i++;
                linkJamByCRC = 1;
            }

            if(i < argc - 1)
            {
                i++;
                xstrcat(&linkName, argv[i]);
            }

            cmLink = 1;
            continue;
        }
        else if(stricmp(argv[i], "afix") == 0)
        {
            while(i + 1 < argc && *(argv[i + 1]) == '-')
            {
                i++;

                if(stricmp(argv[i], "-f") == 0)
                {
                    cmNotifyLink = 1;
                }
                else if(stricmp(argv[i], "-s") == 0)
                {
                    silent_mode = 1;
                }
                else
                {
                    fprintf(stderr, "Unknown afix option \"%s\"!\n", argv[i]);
                    rc = ex_Error;
                }
            }

            if(i + 1 < argc)
            {
                i++;

                if(parseFtnAddrZS(argv[i], &afixAddr) & FTNADDR_ERROR)
                {
                    fprintf(stderr,
                            "Parameter \"%s\" after afix command is not valid ftn address\n",
                            argv[i]);
                    rc = ex_Error;
                    memset(&afixAddr, 0, sizeof(afixAddr));
                    i--;
                }
                else if(i < argc - 1)
                {
                    i++;
                    xstrcat(&afixCmd, argv[i]);
                }
                else
                {
                    fprintf(stderr, "Parameter missing after \"%s\"!\n", argv[i]);
                    rc = ex_Error;
                }
            }

            cmAfix = 1;
            continue;
        }
        else if(stricmp(argv[i], "post") == 0)
        {
            ++i;
            post(argc, (unsigned *)&i, argv);
        }
        else if(stricmp(argv[i], "qupd") == 0)
        {
            cmQueue |= 2;
        }
        else if(stricmp(argv[i], "qrep") == 0)
        {
            cmQueue |= 4;

            if(i < argc - 1 && stricmp(argv[i + 1], "-d") == 0)
            {
                i++;
                report_changes = 1;
            }
        }
        else if(stricmp(argv[i], "relink") == 0)
        {
            if(i < argc - 1)
            {
                i++;
                xstrcat(&relinkPattern, argv[i]);

                if(i < argc - 1)
                {
                    i++;
                    parseFtnAddrZS(argv[i], &relinkFromAddr);
                    cmRelink = modeRelink;
                }
                else
                {
                    fprintf(stderr, "Address missing after \"%s\"!\n", argv[i]);
                    rc = ex_Error;
                }
            }
            else
            {
                fprintf(stderr, "Pattern missing after \"%s\"!\n", argv[i]);
                rc = ex_Error;
            }
        }
        else if(stricmp(argv[i], "resubscribe") == 0)
        {
            if(i < argc - 1)
            {
                i++;

                if(stricmp(argv[i], "-f") == 0)
                {
                    if(i < argc - 1)
                    {
                        i++;

                        if(fexist(argv[i]))
                        {
                            if(fsize(argv[i]) == 0)
                            {
                                fprintf(stderr, "File \"%s\" is empty\n", argv[i]);
                                rc = ex_Error;
                            }
                            else
                            {
                                xstrcat(&resubscribePatternFile, argv[i]);
                                cmRelink = modeResubsribeWithFile;
                            }
                        }
                        else
                        {
                            fprintf(stderr, "File \"%s\" does not exist\n", argv[i]);
                            rc = ex_Error;
                        }
                    }
                    else
                    {
                        fprintf(stderr, "Path missing after -f\n");
                        rc = ex_Error;
                    }
                }
                else
                {
                    xstrcat(&relinkPattern, argv[i]);
                    cmRelink = modeResubsribeWithPattern;
                }

                if(i < argc - 1)
                {
                    i++;
                    parseFtnAddrZS(argv[i], &relinkFromAddr);

                    if(i < argc - 1)
                    {
                        i++;
                        parseFtnAddrZS(argv[i], &relinkToAddr);
                    }
                    else
                    {
                        fprintf(stderr, "Address missing after \"%s\"!\n", argv[i]);
                        rc = ex_Error;
                    }
                }
                else
                {
                    fprintf(stderr, "Address missing after \"%s\"!\n", argv[i]);
                    rc = ex_Error;
                }
            }
            else
            {
                fprintf(stderr, "Pattern missing after \"%s\"!\n", argv[i]);
                rc = ex_Error;
            }
        }
        else if(stricmp(argv[i], "-c") == 0)
        {
            i++;

            if(argv[i] != NULL)
            {
                xstrcat(&cfgFile, argv[i]);
            }
            else
            {
                fprintf(stderr, "Parameter missing after \"%s\"!\n", argv[i - 1]);
                rc = ex_Error;
            }

            continue;
        }
        else if(stricmp(argv[i], "-q") == 0)
        {
            quiet = 1;
            continue;
        }
        else if(stricmp(argv[i], "-h") == 0)
        {
            start_help();
            return ex_Help;
        }
        else if(stricmp(argv[i], "pause") == 0)
        {
            cmPause = 1;
            continue;
        }
        else
        {
            fprintf(stderr, "Unrecognized commandline option \"%s\"!\n", argv[i]);
            rc = ex_Error;
        }
    } /* endwhile */

    return rc;
} /* processCommandLine */

void allDiff(char * nam, char * var, ...)
{
    va_list ap;
    char * ptr;
    struct diffCmp
    {
        char * name;
        char * var;
    } * diffData;
    int ncmp, i, j;

    for(va_start(ap, var), ncmp = 1; va_arg(ap, char *) != NULL; )
    {
        ptr = va_arg(ap, char *); /* variable may be set to NULL */
        ncmp++;
    }
    va_end(ap);
    diffData         = safe_malloc(ncmp * sizeof(struct diffCmp));
    diffData[0].name = nam;
    diffData[0].var  = var;

    for(va_start(ap, var), i = 1; i < ncmp; i++)
    {
        diffData[i].name = va_arg(ap, char *);
        diffData[i].var  = va_arg(ap, char *);
    }
    va_end(ap);
    ptr = NULL;

    for(i = 0; i < ncmp - 1; i++)
    {
        if(diffData[i].var)
        {
            for(j = i + 1; j < ncmp; j++)
            {
                if(diffData[j].var && strcmp(diffData[i].var, diffData[j].var) == 0)
                {
                    xscatprintf(&ptr,
                                "%s & %s must be different",
                                diffData[i].name,
                                diffData[j].name);
                    nfree(diffData);
                    exit_hpt(ptr, 1);
                }
            }
        }
    }
    nfree(diffData);
} /* allDiff */

void processConfig(void)
{
    char * buff = NULL;

/* #if !defined(__OS2__) && !defined(UNIX) */
/*    time_t   time_cur, locklife = 0; */
/*    struct   stat stat_file; */
/* #endif */
/*    unsigned long pid; */
/*    FILE *f; */
    setvar("module", "hpt");
    xscatprintf(&buff, "%u.%u.%u", VER_MAJOR, VER_MINOR, VER_PATCH);
    setvar("version", buff);
    nfree(buff);
    SetAppModule(M_HPT);
    config = readConfig(cfgFile);

    if(NULL == config)
    {
        nfree(cfgFile);
        fprintf(stderr, "Config not found\n");
        exit(EX_UNAVAILABLE);
    }

#if 0

    /*  lock... */
    if(config->lockfile != NULL && fexist(config->lockfile))
    {
        if((f = fopen(config->lockfile, "rt")) == NULL)
        {
            fprintf(stderr, "Can't open file: \"%s\"\n", config->lockfile);
            exit_hpt("Can't open lock-file", 0);
        }

        fscanf(f, "%lu\n", &pid);
        fclose(f);
        /*  Checking process PID */
#ifdef __OS2__

        if(DosKillProcess(DKP_PROCESSTREE, pid) == ERROR_NOT_DESCENDANT)
        {
#elif UNIX

        if(kill(pid, 0) == 0)
        {
#else

        if(stat(config->lockfile, &stat_file) != -1)
        {
            time_cur = time(NULL);
            locklife = (time_cur - stat_file.st_mtime) / 60;
        }

        if(locklife < 180)
        {
#endif
            fprintf(stderr, "lock file found! exit...\n");
            disposeConfig(config);
            exit(1);
        }
        else
        {
            remove(config->lockfile);
            createLockFile(config->lockfile);
        }
    }
    else if(config->lockfile != NULL)
    {
        createLockFile(config->lockfile);
    }

#endif /* if 0 */

    if(config->lockfile)
    {
        lock_fd = lockFile(config->lockfile, config->advisoryLock);

        if(lock_fd < 0)
        {
            disposeConfig(config);
            exit(EX_CANTCREAT);
        }
    }

    /*  open Logfile */
    if(config->logFileDir)
    {
        xstrscat(&buff, config->logFileDir, LogFileName, NULLP);
        initLog(config->logFileDir,
                config->logEchoToScreen,
                config->loglevels,
                config->screenloglevels);
        setLogDateFormat(config->logDateFormat);
        hpt_log = openLog(buff, versionStr);

        if(hpt_log && quiet)
        {
            hpt_log->logEcho = 0;             /* Don't display messages */
        }

        nfree(buff);
    }
    else
    {
        fprintf(stderr, "logFileDir not defined, there will be no log created!\n");
    }

    if(config->addrCount == 0)
    {
        exit_hpt("at least one addr must be defined", 1);
    }

    if(config->linkCount == 0)
    {
        exit_hpt("at least one link must be specified", 1);
    }

    if(config->outbound == NULL)
    {
        exit_hpt("you must set Outbound in fidoconfig first", 1);
    }

    if(config->tempOutbound == NULL)
    {
        exit_hpt("you must set tempOutbound in fidoconfig first", 1);
    }

    if(config->inbound == NULL && config->protInbound == NULL)
    {
        exit_hpt("you must set Inbound or protInbound in fidoconfig first", 1);
    }

    if(config->tempInbound == NULL)
    {
        exit_hpt("you must set tempInbound in fidoconfig first", 1);
    }

    if(config->msgBaseDir == NULL)
    {
        exit_hpt("No msgBaseDir specified in config file!", 1);
    }

    if(config->dupeHistoryDir == NULL)
    {
        exit_hpt("No dupeHistoryDir specified in config file!", 1);
    }

    if(config->dupeArea.areaName == NULL)
    {
        exit_hpt("you must define DupeArea!", 1);
    }

    if(config->dupeArea.fileName == NULL)
    {
        exit_hpt("DupeArea can not be passthrough!", 1);
    }

    if(config->badArea.areaName == NULL)
    {
        exit_hpt("you must define BadArea!", 1);
    }

    if(config->badArea.fileName == NULL)
    {
        exit_hpt("BadArea can not be passthrough!", 1);
    }

    if(config->netMailAreaCount > 0)
    {
        if(config->netMailAreas[0].fileName == NULL)
        {
            exit_hpt("First NetmailArea can not be passthrough!", 1);
        }
    }
    else
    {
        exit_hpt("You must define NetmailArea!", 1);
    }

    allDiff("Inbound",
            config->inbound,
            "tempInbound",
            config->tempInbound,
            "protInbound",
            config->protInbound,
            "localInbound",
            config->localInbound,
            "outbound",
            config->outbound,
            "tempOutbound",
            config->tempOutbound,
            NULL);
    /*  load recoding tables */
    initCharsets();
    getctabs(config->intab, config->outtab);
    w_log(LL_START, "Start");
} /* processConfig */

int isFreeSpace(char * path)
{
    unsigned long sp;

    sp = husky_GetDiskFreeSpace(path) / 1024;

    if(sp < config->minDiskFreeSpace)
    {
        fprintf(stderr,
                "no free space in %s! (needed %d mb, available %u mb).\n",
                path,
                config->minDiskFreeSpace,
                (unsigned)(sp));
        exit_hpt("no free disk space!", 0);
    }

    return 0;
}

#ifdef _MSC_VER
#ifdef DO_PERL
FARPROC WINAPI ourhook(unsigned dliNotify, PDelayLoadInfo pdli)
{
    /* print error message and exit */
    char msg[128];

    unused(dliNotify);
    memset(msg, 0, sizeof(msg));
    sprintf(msg, "Loading of %s failed - exiting ", pdli->szDll);
    w_log(LL_CRIT, msg);

    /* standart deinit sequence */
    /*  deinit SMAPI */
    MsgCloseApi();
    w_log(LL_STOP, "End");
    closeLog(hpt_log);
    doneCharsets();
    nfree(versionStr);

    if(config->lockfile)
    {
        close(lock_fd);
        remove(config->lockfile);
    }

    disposeConfig(config);
    nfree(cfgFile);
    exit(EX_UNAVAILABLE);
} /* ourhook */

#endif /* ifdef DO_PERL */
#endif /* ifdef _MSC_VER */

#ifndef __WATCOMC__

static char ** save_envp(char ** envp)
{
    int envc;
    char ** envp_copy;

    if(*envp == NULL)
    {
        return NULL;
    }

    for(envc = 0; envp[envc]; envc++)
    {}
    envp_copy = safe_malloc((envc + 1) * sizeof(*envp_copy));

    for(envc = 0; envp[envc]; envc++)
    {
        envp_copy[envc] = safe_strdup(envp[envc]);
    }
    envp_copy[envc] = NULL;
    return envp_copy;
}

void free_envp(char ** envp)
{
    int ii = 0;

    if(envp == NULL)
    {
        return;
    }

    while(envp[ii] != NULL)
    {
        nfree(envp[ii]);
        ++ii;
    }
    nfree(envp);
}

#endif

#ifdef __WATCOMC__
    /*
     *  A third 'envp' parameter for main() isn't supported by Watcom. The code
     *  compiles without warning but HPT.EXE will segfault when envp is read.
     *
     *  In any case envp/hpt_environ is only used when hooking Perl, which the
     *  Watcom build doesn't do!
     */
int main(int argc, char ** argv)
#else
int main(int argc, char ** argv, char ** envp)
#endif
{
    struct _minf m;
    unsigned int i;
    e_exitCode rc;

#if defined (__NT__)
    #define TITLESIZE 256
    char * title = NULL, oldtitle[TITLESIZE];
#endif

#if defined (__NT__) && !defined (DEBUG)
    SetUnhandledExceptionFilter(&UExceptionFilter);
#endif
#if defined (__MSVC__) && defined (DEBUG)
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);
#endif

    versionStr = GenVersionStr("hpt", VER_MAJOR, VER_MINOR, VER_PATCH, VER_BRANCH, cvs_date);
    rc         = processCommandLine(argc, argv);

    if((rc != ex_OK) && config != NULL)
    {
        if(config->lockfile)
        {
            close(lock_fd);
            remove(config->lockfile);
            disposeConfig(config);
            doneCharsets();
        }
    }

    if(rc == ex_Help)
    {
        nfree(versionStr);
        exit(EX_OK);
    }

    if(rc == ex_Error)
    {
        nfree(versionStr);
        exit(EX_USAGE);
    }

#ifndef __WATCOMC__
    hpt_environ = save_envp(envp);
#endif

    if(config == NULL)
    {
        processConfig();
    }

#if defined (__NT__)

    if(config->setConsoleTitle)
    {
        GetConsoleTitleA(oldtitle, TITLESIZE);

        if(versionStr)
        {
            xstrscat(&title, "Highly Portable Tosser ", versionStr + 4, NULLP); /* versionStr is
                                                                                   "hpt ..." */
            SetConsoleTitleA(title);
            nfree(title);
        }
        else
        {
            SetConsoleTitleA("Highly Portable Tosser");
        }
    }

#endif
    /* get current time */
    globalTime = time(NULL);

    if(globalTime == (time_t)-1)
    {
        exit_hpt("Can't get current time", 1);
    }

    /*  check for free space */
    if(config->minDiskFreeSpace)
    {
        isFreeSpace(config->tempInbound);

        if(stricmp(config->msgBaseDir, "passthrough") != 0)
        {
            isFreeSpace(config->msgBaseDir);
        }

        for(i = 0; i < config->linkCount; i++)
        {
            if(config->links[i]->areafix.baseDir &&
               stricmp(config->links[i]->areafix.baseDir, "passthrough") != 0)
            {
                isFreeSpace(config->links[i]->areafix.baseDir);
            }
        }
    }

    /* init areafix */
    if(!init_hptafix())
    {
        exit_hpt("Can't init Areafix library", 1);
    }

    if(initSMAPI == -1)
    {
        /*  init SMAPI */
        initSMAPI     = 0;
        m.req_version = 2;
        m.def_zone    = (UINT16)config->addr[0].zone;

        if(MsgOpenApi(&m) != 0)
        {
            exit_hpt("MsgApiOpen Error", 1);
        }
    }

#ifdef USE_HPTZIP
    {
        unsigned int zi_pack = config->packCount, zi_unpack = config->unpackCount;

        for(i = 0; i < config->unpackCount; i++)
        {
            if(fc_stristr(config->unpack[i].call, ZIPINTERNAL) == 0)
            {
                zi_unpack = i;
                break;
            }
        }

        for(i = 0; i < config->packCount; i++)
        {
            if(fc_stristr(config->pack[i].call, ZIPINTERNAL) == 0)
            {
                zi_pack = i;
                break;
            }
        }

        if((zi_pack < config->packCount || zi_unpack < config->unpackCount) && !init_hptzip())
        {
            w_log(LL_ERR, "can't load zlib.dll, zipInternal disabled");

            if(zi_pack < config->packCount)
            {
                nfree(config->pack[zi_pack].packer);
                nfree(config->pack[zi_pack].call);

                if(zi_pack != config->packCount)
                {
                    memmove(config->pack + zi_pack, config->pack + zi_pack + 1,
                            sizeof(s_pack) * (config->packCount - zi_pack - 1));
                }

                config->packCount--;
                /*config->pack = srealloc(config->pack, config->packCount * sizeof(s_pack));*/
            }

            if(zi_unpack < config->unpackCount)
            {
                nfree(config->unpack[zi_unpack].call);
                nfree(config->unpack[zi_unpack].matchCode);
                nfree(config->unpack[zi_unpack].mask);

                if(zi_unpack != config->unpackCount)
                {
                    memmove(config->unpack + zi_unpack, config->unpack + zi_unpack + 1,
                            sizeof(s_unpack) * (config->unpackCount - zi_unpack - 1));
                }

                config->unpackCount--;
                /*config->unpack = srealloc(config->unpack, config->unpackCount *
                   sizeof(s_unpack));*/
            }
        }
    }
#endif /* ifdef USE_HPTZIP */

#ifdef _MSC_VER
#ifdef DO_PERL
#if _MSC_VER >= 1300
    __pfnDliFailureHook2 = ourhook;
#else
    __pfnDliFailureHook = ourhook;
#endif
    /* attempt to start Perl */
    PerlStart();
#endif
#endif
    msgToSysop = (s_message **)safe_malloc(config->addrCount * sizeof(s_message *));

    for(i = 0; i < config->addrCount; i++)
    {
        /* Some results of wrong patching ? A memleak anyway
         * msgToSysop[i] = (s_message*)malloc(sizeof(s_message));
         */
        msgToSysop[i] = NULL;
    }
    tossTempOutbound(config->tempOutbound);

    if(1 == cmToss)
    {
        toss();
    }

    if(cmToss == 2)
    {
        tossFromBadArea(force);
    }

    if(cmScan == 1)
    {
        scanExport(SCN_ALL | SCN_ECHOMAIL, NULL);
    }

    if(cmScan & 2)
    {
        scanExport(SCN_FILE | SCN_ECHOMAIL, scanParmF);
    }

    if((cmScan & 4) && scanParmA)
    {
        scanExport(SCN_NAME | SCN_ECHOMAIL, scanParmA);
    }

    if(cmAfix == 1)
    {
        afix(afixAddr, afixCmd);
    }

    nfree(afixCmd);

    if(cmRelink != modeNone)
    {
        int ret;
        char * line = NULL, * fromCmd = NULL, * toCmd = NULL, * toPrint = NULL;
        unsigned int count = 0;
        w_log(LL_START, "%s has started", cmRelink == modeRelink ? "Relinking" : "Resubscribing");

        if(cmRelink != modeResubsribeWithFile)
        {
            /* modeRelink or modeResubsribeWithPattern */
            ret = relink(cmRelink,
                         relinkPattern,
                         relinkFromAddr,
                         relinkToAddr,
                         &fromCmd,
                         &toCmd,
                         &count);
            nfree(relinkPattern);

            if(ret)
            {
                return 1;
            }
        }
        else
        {
            /* modeResubsribeWithFile */
            FILE * f;
            f = fopen(resubscribePatternFile, "r");

            if(f == NULL)
            {
                fprintf(stderr, "Cannot open file \"%s\"!\n", resubscribePatternFile);
                nfree(resubscribePatternFile);
                return 1;
            }
            else
            {
                while((line = readLine(f)) != NULL)
                {
                    xstrcat(&relinkPattern, line);
                    ret = relink(cmRelink,
                                 relinkPattern,
                                 relinkFromAddr,
                                 relinkToAddr,
                                 &fromCmd,
                                 &toCmd,
                                 &count);
                    nfree(relinkPattern);

                    if(ret)
                    {
                        fclose(f);
                        nfree(resubscribePatternFile);
                        return 1;
                    }
                }
                fclose(f);
                nfree(resubscribePatternFile);
            }
        }

        if(fromCmd)
        {
            if(cmRelink == modeRelink)
            {
                sendRelinkMsg(cmRelink, relinkFromAddr, fromCmd, smodeSubscribe);
            }
            else
            {
                sendRelinkMsg(cmRelink, relinkFromAddr, fromCmd, smodeUnsubscribe);
            }

            nfree(fromCmd);
        }

        if(toCmd)
        {
            sendRelinkMsg(cmRelink, relinkToAddr, toCmd, smodeSubscribe);
            nfree(toCmd);
        }

        xscatprintf(&toPrint, "%i ", count);
        count == 1 ? xscatprintf(&toPrint, "%s has been", af_robot->strA) : xscatprintf(&toPrint,
                                                                                        "%ss have been",
                                                                                        af_robot->strA);
        w_log(LL_AREAFIX, "%s %s", toPrint, cmRelink == modeRelink ? "relinked" : "resubscribed");
        nfree(toPrint);
    }

    if(cmPack == 1)
    {
        scanExport(SCN_ALL | SCN_NETMAIL, NULL);
    }

    if(cmPack & 2)
    {
        scanExport(SCN_FILE | SCN_NETMAIL, scanParmF);
    }

    if((cmPack & 4) && scanParmA)
    {
        scanExport(SCN_NAME | SCN_NETMAIL, scanParmA);
    }

    if(cmLink == 1)
    {
        if(linkName && (strchr(linkName, '*') || strchr(linkName, '?')))
        {
            for(i = 0; i < config->echoAreaCount; i++)
            {
                if(patimat(config->echoAreas[i].areaName, linkName))
                {
                    linkAreas(config->echoAreas[i].areaName);
                }
            }

            for(i = 0; i < config->localAreaCount; i++)
            {
                if(patimat(config->localAreas[i].areaName, linkName))
                {
                    linkAreas(config->localAreas[i].areaName);
                }
            }

            for(i = 0; i < config->netMailAreaCount; i++)
            {
                if(patimat(config->netMailAreas[i].areaName, linkName))
                {
                    linkAreas(config->netMailAreas[i].areaName);
                }
            }
        }
        else
        {
            linkAreas(linkName);
        }
    }

    nfree(linkName);
    writeMsgToSysop();

    for(i = 0; i < config->addrCount; i++)
    {
        if(msgToSysop[i])
        {
            freeMsgBuffers(msgToSysop[i]);
        }

        nfree(msgToSysop[i]);
    }

    if(cmPause || config->autoPassive)
    {
        autoPassive();
    }

    if(cmQueue & 2)
    {
        af_QueueUpdate();
    }

    if(cmQueue & 4)
    {
        af_QueueReport();
    }

    /*  save forward requests info */
    af_CloseQuery();
    nfree(msgToSysop);

#ifdef DO_PERL
    perldone();
#endif
#ifdef ADV_STAT

    if(config->advStatisticsFile != NULL)
    {
        upd_stat(config->advStatisticsFile);
    }

#endif
    /*  deinit SMAPI */
    MsgCloseApi();
    w_log(LL_STOP, "End");
    closeLog();
    doneCharsets();
    nfree(versionStr);

    if(config->lockfile)
    {
        FreelockFile(config->lockfile, lock_fd);
    }

#if defined (__NT__)

    if(config->setConsoleTitle)
    {
        SetConsoleTitleA(oldtitle);
    }

#endif
    disposeConfig(config);
    nfree(cfgFile);
    /* Keep memory leaks detector happy */
#ifndef __WATCOMC__
    free_envp(hpt_environ);
#endif
    return 0;
} /* main */
