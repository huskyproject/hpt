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
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <huskylib/compiler.h>

#ifdef HAS_PROCESS_H
#  include <process.h>
#endif

#ifdef HAS_UNISTD_H
#   include <unistd.h>
#endif

#ifdef HAS_IO_H
#   include <io.h>
#endif

#ifdef HAS_SYS_SYSEXITS_H
#include <sys/sysexits.h>
#endif
#ifdef HAS_SYSEXITS_H
#include <sysexits.h>
#endif

#ifdef HAS_DOS_H
#include <dos.h>
#endif

#if defined (__TURBOC__) || defined (__IBMC__)

#if !defined (S_ISDIR)
#define S_ISDIR(a) (((a) & S_IFDIR) != 0)
#endif

#endif

#include <huskylib/huskylib.h>
#include <huskylib/cvtdate.h>
#include <huskylib/xstr.h>
#include <huskylib/dirlayer.h>
#include <huskylib/recode.h>
#include <huskylib/crc.h>

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>

#include <areafix/areafix.h>

#include <global.h>
#include <fcommon.h>
#include <dupe.h>

void writeDupeFiles(void)
{
    unsigned i;

    /*  write dupeFiles */
    for(i = 0; i < config->echoAreaCount; i++)
    {
        writeToDupeFile(&(config->echoAreas[i]));
        freeDupeMemory(&(config->echoAreas[i]));
    }

    for(i = 0; i < config->netMailAreaCount; i++)
    {
        writeToDupeFile(&(config->netMailAreas[i]));
        freeDupeMemory(&(config->netMailAreas[i]));
    }
}

void exit_hpt(char * logstr, int print)
{
    w_log(LL_FUNC, "exit_hpt()");
    w_log(LL_CRIT, logstr);

    if(!config->logEchoToScreen && print)
    {
        fprintf(stderr, "%s\n", logstr);
    }

    writeDupeFiles();
    doneCharsets();
    w_log(LL_STOP, "Exit");
    closeLog();

    if(config->lockfile)
    {
        FreelockFile(config->lockfile, lock_fd);
    }

    disposeConfig(config);
    exit(EX_SOFTWARE);
}

/* this function has no calls
   int createLockFile(char *lockfile) {
        int fd;
        char *pidstr = NULL;

        w_log(LL_FUNC,"createLockFile()");
        if ( (fd=open(lockfile, O_CREAT | O_RDWR | O_EXCL, S_IREAD | S_IWRITE)) < 0 )
           {
                   fprintf(stderr,"createLockFile: cannot create lock file\"%s\"\n",lockfile);
                   w_log(LL_ERR, "createLockFile: cannot create lock file \"%s\"m", lockfile);
                   return 1;
           }

        xscatprintf(&pidstr, "%u\n", (unsigned)getpid());
        write (fd, pidstr, strlen(pidstr));

        close(fd);
    nfree(pidstr);
        w_log(LL_FUNC,"createLockFile() OK");
        return 0;
   }
 */
/*
   e_prio cvtFlavour2Prio(e_flavour flavour)
   {
   switch (flavour) {
      case hold:      return HOLD;
      case normal:    return NORMAL;
      case direct:    return DIRECT;
      case crash:     return CRASH;
      case immediate: return IMMEDIATE;
      default:        return NORMAL;
   }
   return NORMAL;
   }
 */
#if 1
/* This old code will be removed once the new one proves to be reliable */
int fileNameAlreadyUsed(char * pktName, char * packName)
{
    UINT i;

    for(i = 0; i < config->linkCount; i++)
    {
        if((config->links[i]->pktFile != NULL) && (pktName != NULL))
        {
            if((stricmp(pktName, config->links[i]->pktFile) == 0))
            {
                return 1;
            }
        }

        if((config->links[i]->packFile != NULL) && (packName != NULL))
        {
            if((stricmp(packName, config->links[i]->packFile) == 0))
            {
                return 1;
            }
        }
    }
    return 0;
}

static char * wdays[7] =
{
    "su", "mo", "tu", "we", "th", "fr", "sa"
};
void cleanEmptyBundles(char * pathName, size_t npos, char * wday)
/*  Removing old empty bundles when bundleNameStyle == addDiff */
{
    char * ptr, * tmpfile, * pattern, savech;
    husky_DIR * dir;
    char * filename;
    struct stat stbuf;
    unsigned pathlen;

    if(npos >= strlen(pathName))
    {
        w_log(LL_CRIT, "fcommon.c:cleanEmptyBundles(): 'npos' too big! Can't work.");
        return;
    }

    pathlen = strlen(pathName) + 4;
    tmpfile = safe_malloc(pathlen);
    strcpy(tmpfile, pathName);
    savech = tmpfile[npos - 1]; /*  there must be path delimiter */

    tmpfile[npos - 1] = '\0';

    if((dir = husky_opendir(tmpfile)) == NULL)  /*  nothing to clean */
    {
        nfree(tmpfile);
        return;
    }

    tmpfile[npos - 1] = savech;
    pattern           = safe_malloc(strlen(tmpfile + npos) + 4);
    strcpy(pattern, tmpfile + npos);

    for(ptr = pattern; *ptr; ptr++)
    {}
    ptr[0] = '*';
    ptr[1] = '\0';

    while((filename = husky_readdir(dir)) != NULL)
    {
        if(patimat(filename,
                   pattern) == 1 && strncasecmp(filename + (ptr - pattern), wday, 2) != 0)
        {
            strcpy(tmpfile + npos, filename);

            if(stat(tmpfile, &stbuf) == 0 && stbuf.st_size == 0)
            {
                remove(tmpfile);     /*  old empty bundle */
            }
        }
    }
    husky_closedir(dir);
    nfree(pattern);
    nfree(tmpfile);
} /* cleanEmptyBundles */

/* old algorythm, use it if used didn't set SeqDir */
int createTempPktFileName_legasy(s_link * link)
{
    char * fileName = NULL; /*  pkt file in tempOutbound */
    time_t aTime    = time(NULL); /* get actual time */
    int counter;

    counter = pkt_count;
    aTime  %= 0xffffff;  /* only last 24 bit count */

    /* Making pkt name */
    for( ; ; )
    {
        do
        {
            nfree(fileName);
            xscatprintf(&fileName, "%s%06lx%02x.pkt", config->tempOutbound, (long)aTime, counter);
            counter++;
        }
        while((fexist(fileName) || fileNameAlreadyUsed(fileName, NULL)) && (counter <= 255));

        if(counter <= 256)
        {
            break;
        }
        else
        {
            counter = 0;

            if(pkt_aTime == aTime)
            {
                sleep(1);
                aTime  = time(NULL);
                aTime %= 0xffffff;
            }
        }
    }
    pkt_count = counter;
    pkt_aTime = aTime;
    nfree(link->pktFile);
    link->pktFile = fileName;
    w_log(LL_CREAT, "pktFile %s created for [%s]", link->pktFile, aka2str(&link->hisAka));
    return 0;
} /* createTempPktFileName_legasy */

int createTempPktFileName(s_link * link)
{
    char * fileName = NULL; /*  pkt file in tempOutbound */

    if(config->seqDir == NULL)
    {
        return createTempPktFileName_legasy(link);
    }

    /* Making pkt name */
    do
    {
        nfree(fileName);
        xscatprintf(&fileName, "%s%08x.pkt", config->tempOutbound,
                    GenMsgId(config->seqDir, config->seqOutrun));
    }
    while(fexist(fileName) || fileNameAlreadyUsed(fileName, NULL));
    nfree(link->pktFile);
    link->pktFile = fileName;
    w_log(LL_CREAT, "pktFile %s created for [%s]", link->pktFile, aka2str(&link->hisAka));
    return 0;
}

int createPackFileName(s_link * link)
{
    char * pfileName = NULL; /*  name of the arcmail bundle */
    char * tmp       = NULL; /*  temp name of the arcmail bundle */
    char * tmp2      = NULL; /* temp string */
    int minFreeExt;
    size_t npos;
    char limiter = PATH_DELIM;
    time_t tr, aTime;
    char * wday;
    struct tm * tp;
    int i;
    struct stat stbuf;
    static char ext3[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    int numExt         = sizeof(ext3) - 1;
    int counter;
    hs_addr * aka;
    char * str_hisAka, * str_Aka;
    e_bundleFileNameStyle bundleNameStyle = eTimeStamp;

    tr      = aTime = time(NULL);
    aTime  %= 0xffffff;
    tp      = localtime(&tr);
    counter = pkt_count;
    wday    = wdays[tp->tm_wday];
    aka     = SelectPackAka(link);

    if(link->linkBundleNameStyle != eUndef)
    {
        bundleNameStyle = link->linkBundleNameStyle;
    }
    else if(config->bundleNameStyle != eUndef)
    {
        bundleNameStyle = config->bundleNameStyle;
    }

    /*  fileBoxes support */
    if(needUseFileBoxForLinkAka(config, link, aka))
    {
        if(!link->fileBox)
        {
            link->fileBox = makeFileBoxNameAka(config, link, aka);
        }

        xstrcat(&tmp, link->fileBox);
        _createDirectoryTree(tmp);
    }
    else
    {
        xstrcat(&tmp, config->outbound);

        /*  add suffix for other zones */
        if(aka->zone != config->addr[0].zone && bundleNameStyle != eAmiga)
        {
            tmp[strlen(tmp) - 1] = '\0';
            xscatprintf(&tmp, ".%03x%c", aka->zone, limiter);
        }

        /*  path to bundle */
        if(bundleNameStyle != eAmiga)
        {
            if(aka->point)
            {
                xscatprintf(&tmp, "%04x%04x.pnt%c", aka->net, aka->node, limiter);
            }

            /*  separate bundles */
            if(config->separateBundles)
            {
                if(aka->point)
                {
                    xscatprintf(&tmp, "%08x.sep%c", aka->point, limiter);
                }
                else
                {
                    xscatprintf(&tmp, "%04x%04x.sep%c", aka->net, aka->node, limiter);
                }
            }
        }
    } /*  link->fileBox */

    npos = strlen(tmp);

    /* bundle file name */
    switch(bundleNameStyle)
    {
        case eAddrsCRC32:
        case eAddrsCRC32Always:
        case eAddrDiff:
        case eAddrDiffAlways:

            if(bundleNameStyle == eAddrsCRC32 || bundleNameStyle == eAddrsCRC32Always)
            {
                xscatprintf(&tmp2, "hpt %s ", aka2str(&config->addr[0]));
                xstrcat(&tmp2, aka2str(aka));
                xscatprintf(&tmp, "%08x.", strcrc32(tmp2, 0xFFFFFFFFUL));
                nfree(tmp2);
            }
            else
            {
                if(aka->point == 0 && config->addr[0].point == 0)
                {
                    xscatprintf(&tmp,
                                "%04hx%04hx.",
                                config->addr[0].net - aka->net,
                                config->addr[0].node - aka->node);
                }
                else
                {
                    xscatprintf(&tmp,
                                "%04hx%04hx.",
                                config->addr[0].node - aka->node,
                                config->addr[0].point - aka->point);
                }
            }

            w_log(LL_FILENAME, "bundle name generating: %s", tmp);

        case eAmiga:

            if(bundleNameStyle == eAmiga)
            {
                xscatprintf(&tmp, "%u.%u.%u.%u.", aka->zone, aka->net, aka->node, aka->point);
            }

            if(!needUseFileBoxForLinkAka(config, link, aka))
            {
                cleanEmptyBundles(tmp, npos, wday);
            }

            counter    = 0;
            minFreeExt = -1;

            for(i = 0; i < numExt; i++)
            {
                xstrscat(&pfileName, tmp, wday, NULLP);
                xscatprintf(&pfileName, "%c", ext3[i]);

                if(stat(pfileName, &stbuf) == 0)
                {
                    if(tr - stbuf.st_mtime < 60 * 60 * 48)
                    {
                        /*  today's bundle */
                        counter = i + 1;

                        if(stbuf.st_size == 0 &&
                           (counter < numExt || bundleNameStyle == eAddrDiffAlways ||
                            bundleNameStyle == eAddrsCRC32Always || bundleNameStyle == eAmiga))
                        {
                            remove(pfileName);
                        }
                    }
                    else
                    {
                        /*  old bundle */
                        if(stbuf.st_size == 0)
                        {
                            remove(pfileName);
                        }
                        else
                        {
                            counter = i + 1;
                        }
                    }
                }
                else if(errno == ENOENT)
                {
                    if(minFreeExt < 0)
                    {
                        minFreeExt = i;
                    }
                }

                nfree(pfileName);
            }

            if(counter >= numExt)
            {
                if((bundleNameStyle == eAddrDiffAlways || bundleNameStyle == eAddrsCRC32Always ||
                    bundleNameStyle == eAmiga) && minFreeExt >= 0)
                {
                    counter = minFreeExt;
                }
                else
                {
                    w_log(LL_ERR, "Can't use more than %d extensions for bundle names", numExt);
                    nfree(pfileName);
                    nfree(tmp);
                    /*  Switch link to TimeStamp style */
                    link->linkBundleNameStyle = eTimeStamp;
                    i = createPackFileName(link);
                    link->linkBundleNameStyle = bundleNameStyle;
                    return i;
                }
            }

            xstrscat(&pfileName, tmp, wday, NULLP);
            xscatprintf(&pfileName, "%c", ext3[counter]);
            break;

        case eTimeStamp:
            counter = 0;

            do
            {
                nfree(pfileName);
                xscatprintf(&pfileName,
                            "%s%06lx%02x.%s%c",
                            tmp,
                            (long)aTime,
                            counter % 256,
                            wday,
                            ext3[counter / 256]);
                counter++;
            }
            while((fexist(pfileName) ||
                   fileNameAlreadyUsed(NULL, pfileName)) && (counter < numExt * 256));

            if(counter >= numExt * 256)
            {
                w_log(LL_STAT, "created %d bundles/sec!", numExt * 256);
            }

            break;

        default:
            w_log(LL_ERR, "Unknown bundleNameStyle (non-compatible fidoconfig library?)");
            exit(EX_SOFTWARE);
            break;
    } /* switch */
    nfree(tmp);

    if(!fexist(pfileName))
    {
        nfree(link->packFile);
        link->packFile = pfileName;
        str_hisAka     = aka2str5d(link->hisAka);
        str_Aka        = aka2str5d(*aka);
        w_log(LL_CREAT, "packFile %s created for [%s via %s]", link->packFile, str_hisAka,
              str_Aka);
        nfree(str_hisAka);
        nfree(str_Aka);
        return 0;
    }
    else
    {
        nfree(pfileName);
        w_log(LL_ERR, "can't create arcmail bundles any more!");
        return 1;
    }
}/* createPackFileName() */

#endif /* if 1 */

#if 0
/* filenames are not FTSC compliant, some links have problems :-( */
int createTempPktFileName(s_link * link)
{
    char * filename = NULL;     /* pkt file in tempOutbound */
    char * pfilename;           /* name of the arcmail bundle */
    char limiter = PATH_DELIM;
    char ext[4];                /* week-day based extension of the pack file */
    char zoneSuffix[6] = "\0";
    char * zoneOutbound;        /* this contains the correct outbound directory
                                   including zones */
    char uniquestring[9];       /* the unique part of filename */
    time_t tr;
    static char * wdays[7] =
    {
        "su", "mo", "tu", "we", "th", "fr", "sa"
    };
    struct tm * tp;

    tr = time(NULL);
    tp = localtime(&tr);
    sprintf(ext, "%s0", wdays[tp->tm_wday]);
    pfilename = (char *)malloc(strlen(config->outbound) + 13 + 13 + 12 + 1);

    if(link->hisAka.zone != config->addr[0].zone)
    {
        sprintf(zoneSuffix, ".%03x%c", link->hisAka.zone, PATH_DELIM);
        zoneOutbound = safe_malloc(strlen(config->outbound) - 1 + strlen(zoneSuffix) + 1);
        strcpy(zoneOutbound, config->outbound);
        strcpy(zoneOutbound + strlen(zoneOutbound) - 1, zoneSuffix);
    }
    else
    {
        zoneOutbound = safe_strdup(config->outbound);
    }

    do
    {
        nfree(filename);
        filename = makeUniqueDosFileName(config->tempOutbound, "pkt", config);
        memcpy(uniquestring, filename + strlen(config->tempOutbound), 8);
        uniquestring[8] = '\0';

        if(link->hisAka.point == 0)
        {
            if(config->separateBundles)
            {
                sprintf(pfilename,
                        "%s%04x%04x.sep%c%s.%s",
                        zoneOutbound,
                        link->hisAka.net,
                        link->hisAka.node,
                        limiter,
                        uniquestring,
                        ext);
            }
            else
            {
                sprintf(pfilename, "%s%s.%s", zoneOutbound, uniquestring, ext);
            }
        }
        else
        {
            if(config->separateBundles)
            {
                sprintf(pfilename,
                        "%s%04x%04x.pnt%c%08x.sep%c%s.%s",
                        zoneOutbound,
                        link->hisAka.net,
                        link->hisAka.node,
                        limiter,
                        link->hisAka.point,
                        limiter,
                        uniquestring,
                        ext);
            }
            else
            {
                sprintf(pfilename,
                        "%s%04x%04x.pnt%c%s.%s",
                        zoneOutbound,
                        link->hisAka.net,
                        link->hisAka.node,
                        limiter,
                        uniquestring,
                        ext);
            }
        }
    }
    while(fexist(filename) || fexist(pfilename));
    nfree(zoneOutbound);
    nfree(link->packFile);
    nfree(link->pktFile);
    link->packFile = pfilename;
    link->pktFile  = filename;
    return 0;
} /* createTempPktFileName */

/*  this function moved to smapi has name _createDirectoryTree */
int createDirectoryTree(const char * pathName)
{
    char * start, * slash;
    char limiter = PATH_DELIM;
    int i;

    start = (char *)safe_malloc(strlen(pathName) + 2);
    strcpy(start, pathName);
    i = strlen(start) - 1;

    if(start[i] != limiter)
    {
        start[i + 1] = limiter;
        start[i + 2] = '\0';
    }

    slash = start;

#ifndef __UNIX__

    /*  if there is a drivename, jump over it */
    if(slash[1] == ':')
    {
        slash += 2;
    }

#endif
    /*  jump over first limiter */
    slash++;

    while((slash = strchr(slash, limiter)) != NULL)
    {
        *slash = '\0';

        if(!direxist(start))
        {
            if(!fexist(start))
            {
                /*  this part of the path does not exist, create it */
                if(mymkdir(start) != 0)
                {
                    w_log(LL_ERR, "Could not create directory %s", start);
                    nfree(start);
                    return 1;
                }
            }
            else
            {
                w_log(LL_ERR, "%s is a file not a directory", start);
                nfree(start);
                return 1;
            }
        }

        *slash++ = limiter;
    }
    nfree(start);
    return 0;
} /* createDirectoryTree() */

#endif /* if 0 */

int createOutboundFileNameAka(s_link * link, e_flavour prio, e_pollType typ, hs_addr * aka)
{
    int nRet = NCreateOutboundFileNameAka(config, link, prio, typ, aka);

    if(nRet == -1)
    {
        exit_hpt("cannot create *.bsy file!", 0);
    }

    return nRet;
}

int createOutboundFileName(s_link * link, e_flavour prio, e_pollType typ)
{
    return createOutboundFileNameAka(link, prio, typ, &(link->hisAka));
}

void * safe_malloc(size_t size)
{
    void * ptr = malloc(size);

    if(ptr == NULL)
    {
        exit_hpt("out of memory (safe_malloc())", 1);
    }

    return ptr;
}

void * safe_calloc(size_t nmemb, size_t size)
{
    void * ptr = safe_malloc(size * nmemb);

    memset(ptr, '\0', size * nmemb);
    return ptr;
}

void * safe_realloc(void * ptr, size_t size)
{
    void * newptr = realloc(ptr, size);

    if(newptr == NULL)
    {
        free(ptr);
        ptr = NULL;
        exit_hpt("out of memory (safe_realloc())", 1);
    }

    return newptr;
}

char * safe_strdup(const char * src)
{
    char * ptr = NULL;

    if(src)
    {
        if((ptr = strdup(src)) == NULL)     /* use sstrdup() from fidoconfig library */
        {
            exit_hpt("out of memory (safe_strdup())", 1);
        }
    }

    return ptr;
}

void writeEchoTossLogEntry(char * areaName)
{
    if(areaName && config->echotosslog)
    {
        FILE * f = fopen(config->echotosslog, "a");

        if(f == NULL)
        {
            w_log(LL_ERROR, "Could not open or create EchoTossLogFile.");
        }
        else
        {
            fprintf(f, "%s\n", areaName);
            fclose(f);
        }
    }
}
