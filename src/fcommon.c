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
 *****************************************************************************/
#include <time.h>
#include <fcommon.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef __EMX__
#include <sys/types.h>
#endif
#include <sys/stat.h>
#if !defined(__TURBOC__) && !(defined (_MSC_VER) && (_MSC_VER >= 1200))
#include <unistd.h>
#endif
#if defined (__TURBOC__)
#include <process.h>
#include <dir.h>
#include <io.h>
#include <dos.h>
#endif
#ifdef __IBMC__
#include <direct.h>
#endif
#ifdef __WATCOMC__
#include <fcntl.h>
#define AW_S_ISDIR(a) (((a) & S_IFDIR) != 0)
#include <process.h>
#include <dos.h>
#endif
#include <fcntl.h>
#include <errno.h>

#include <global.h>
#include <recode.h>
#include <dupe.h>
#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/xstr.h>

#include <smapi/typedefs.h>
#include <smapi/compiler.h>
#include <smapi/stamp.h>
#include <smapi/progprot.h>

void writeDupeFiles(void)
{
	unsigned i;

	// write dupeFiles
	for (i = 0 ; i < config->echoAreaCount; i++) {
		writeToDupeFile(&(config->echoAreas[i]));
		freeDupeMemory(&(config->echoAreas[i]));
	}
	for (i = 0 ; i < config->netMailAreaCount; i++) {
		writeToDupeFile(&(config->netMailAreas[i]));
		freeDupeMemory(&(config->netMailAreas[i]));
	}
}

void exit_hpt(char *logstr, int print) {

    if (!config->logEchoToScreen && print) fprintf(stderr, "%s\n", logstr);

    writeDupeFiles();
    if (config->lockfile != NULL) remove(config->lockfile);
    writeLogEntry(hpt_log, '9', logstr);
    writeLogEntry(hpt_log, '1', "End");
    closeLog(hpt_log);
    disposeConfig(config);
    doneCharsets();
    exit(1);
}

int createLockFile(char *lockfile) {
        int fd;
        char *pidstr = NULL;

        if ( (fd=open(lockfile, O_CREAT | O_RDWR | O_EXCL, S_IREAD | S_IWRITE)) < 0 )
           {
                   fprintf(stderr,"createLockFile: cannot create lock file\"%s\"\n",lockfile);
                   writeLogEntry(hpt_log, '9', "createLockFile: cannot create lock file \"%s\"m", lockfile);
                   return 1;
           }

        xscatprintf(&pidstr, "%u\n", (unsigned)getpid());
        write (fd, pidstr, strlen(pidstr));

        close(fd);
	nfree(pidstr);
        return 0;
}

#if defined(__TURBOC__) || defined(__IBMC__) || (defined(_MSC_VER) && (_MSC_VER >= 1200))

#include <io.h>
#include <fcntl.h>

#if !defined(S_ISDIR)
#define S_ISDIR(a) (((a) & S_IFDIR) != 0)
#endif

#endif

#if defined(__TURBOC__) || defined(__IBMC__) || defined(__WATCOMC__) || (defined(_MSC_VER) && (_MSC_VER >= 1200))

int truncate(const char *fileName, long length)
{
   int fd = open(fileName, O_RDWR | O_BINARY);
   if (fd != -1) {
          lseek(fd, length, SEEK_SET);
          chsize(fd, tell(fd));
          close(fd);
          return 1;
   };
   return 0;
}

int fTruncate( int fd, long length )
{
   if( fd != -1 )
   {
      lseek(fd, length, SEEK_SET);
      chsize(fd, tell(fd) );
      return 1;
   }
   return 0;
}

#endif

#ifdef __MINGW32__
int fTruncate (int fd, long length)
{
   if( fd != -1 )
   {
      lseek(fd, length, SEEK_SET);
      chsize(fd, tell(fd) );
      return 1;
   }
   return 0;
}
#endif

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

#if 1
/* This old code will be removed once the new one proves to be reliable */

int fileNameAlreadyUsed(char *pktName, char *packName) {
   int i;

   for (i=0; i < config->linkCount; i++) {
      if ((config->links[i].pktFile != NULL) && (pktName != NULL))
         if ((stricmp(pktName, config->links[i].pktFile)==0)) return 1;
      if ((config->links[i].packFile != NULL) && (packName != NULL))
         if ((stricmp(packName, config->links[i].packFile)==0)) return 1;
   }

   return 0;
}

int createTempPktFileName(s_link *link)
{
    /* pkt file in tempOutbound */
    char  *fileName = (char *) safe_malloc(strlen(config->tempOutbound)+12+1);
    /* name of the arcmail bundle */
    char  *pfileName = (char *) safe_malloc(strlen(config->outbound)+13+13+12+1);
    /* temp name of the arcmail bundle */
    char  *tmpPFileName = (char *) safe_malloc(strlen(config->outbound)+13+13+12+1);
    time_t aTime = time(NULL);  /* get actual time */
    int counter = 0;
    char *wdays[7]={ "su", "mo", "tu", "we", "th", "fr", "sa" };
    char limiter=PATH_DELIM;
    char zoneSuffix[6] = "\0";

    char *zoneOutbound;         /* this contains the correct outbound directory
                                   including zones */

    time_t tr;
    char *wday;
    struct tm *tp;


    tr=time(NULL);
    tp=localtime(&tr);
    counter = count;

    wday=wdays[tp->tm_wday];

    aTime %= 0xffffff;   /* only last 24 bit count */

    if (link->hisAka.zone != config->addr[0].zone) {
        sprintf(zoneSuffix, ".%03x%c", link->hisAka.zone, PATH_DELIM);
        zoneOutbound = safe_malloc(strlen(config->outbound)-1+strlen(zoneSuffix)+1);
        strcpy(zoneOutbound, config->outbound);
        strcpy(zoneOutbound+strlen(zoneOutbound)-1, zoneSuffix);
    } else
        zoneOutbound = safe_strdup(config->outbound);


   /* There is a problem here: Since we use the tmpOutbound fileName for
    duplicate checking, links with different zones who does not have problems
    with duplicate pfileName´s increment the counter. We can run out of
    counters without using them.  Has anybody understand that? :-) This is no
    big problem, but a big system with many links and many zones may encounter
    problems */

	while(1) {
		do {
			sprintf(fileName, "%s%06lx%02x.pkt",
					config->tempOutbound, (long)aTime, counter);

			if ( link->hisAka.point == 0 ) {

				if (config->separateBundles) {
					sprintf(tmpPFileName,"%s%04x%04x.sep%c%06lx%02x.%s",
							zoneOutbound, link->hisAka.net, link->hisAka.node,
							limiter, (long)aTime, counter, wday);
				} else {
					sprintf(tmpPFileName,"%s%06lx%02x.%s",zoneOutbound,
							(long)aTime,counter,wday);
				}
			} else {

				if (config->separateBundles) {
					sprintf(tmpPFileName,"%s%04x%04x.pnt%c%08x.sep%c%06lx%02x.%s",
							zoneOutbound, link->hisAka.net,	link->hisAka.node,
							limiter,link->hisAka.point, limiter, (long)aTime,
							counter, wday);
				} else {
					sprintf(tmpPFileName,"%s%04x%04x.pnt%c%06lx%02x.%s",
							zoneOutbound, link->hisAka.net,	link->hisAka.node,
							limiter, (long)aTime, counter, wday);
				}
			}

			counter++;

		} while ((fexist(fileName) || fileNameAlreadyUsed(fileName, NULL)) &&
				 (counter<=255));

		if (counter<=255) break;
		else {
			writeLogEntry(hpt_log,'7',"created 256 pkt's/sec!");
			sleep(1);
			aTime = time(NULL);
			aTime %= 0xffffff;
			counter=0;
		}
	}
	nfree(zoneOutbound);
	count = counter;

	counter = 0;
	do {
 		sprintf(pfileName, "%s%01x", tmpPFileName, counter);
		counter++;
	} while ((fexist(pfileName) || fileNameAlreadyUsed(NULL, pfileName)) &&
			 (counter <= 15));
	nfree(tmpPFileName);

	if (counter > 15) writeLogEntry(hpt_log,'7',"created 16 bundles/sec!");

    if ((!fexist(fileName)) && (!fexist(pfileName))) {
        nfree(link->packFile);
        nfree(link->pktFile);
        link->packFile = pfileName;
        link->pktFile = fileName;
        return 0;
    }
    else {
        nfree(fileName);
        nfree(pfileName);
		writeLogEntry(hpt_log,'7',"can't create arcmail bundles any more!");
        return 1;
    }
}
#endif

#if 0
/* filenames are not FTSC compliant, some links have problems :-( */
int createTempPktFileName(s_link *link)
{
    char  *filename = NULL;     /* pkt file in tempOutbound */
    char  *pfilename;           /* name of the arcmail bundle */
    char   limiter = PATH_DELIM;
    char   ext[4];              /* week-day based extension of the pack file */
    char   zoneSuffix[6]="\0";
    char  *zoneOutbound;        /* this contains the correct outbound directory
                                   including zones */
    char   uniquestring[9];     /* the unique part of filename */

    time_t       tr;
    static char *wdays[7]={ "su", "mo", "tu", "we", "th", "fr", "sa" };
    struct tm   *tp;

    tr=time(NULL);
    tp=localtime(&tr);
    sprintf(ext,"%s0", wdays[tp->tm_wday]);

    pfilename = (char *) malloc(strlen(config->outbound)+13+13+12+1);

    if (link->hisAka.zone != config->addr[0].zone) {
        sprintf(zoneSuffix, ".%03x%c", link->hisAka.zone, PATH_DELIM);
        zoneOutbound = safe_malloc(strlen(config->outbound)-1+strlen(zoneSuffix)+1);
        strcpy(zoneOutbound, config->outbound);
        strcpy(zoneOutbound+strlen(zoneOutbound)-1, zoneSuffix);
    } else
        zoneOutbound = safe_strdup(config->outbound);

    do
    {
        nfree(filename);
        filename = makeUniqueDosFileName(config->tempOutbound, "pkt", config);
        memcpy(uniquestring, filename + strlen(config->tempOutbound), 8);
        uniquestring[8] = '\0';

        if (link->hisAka.point == 0)
        {
            if (config->separateBundles)
            {
                sprintf(pfilename,"%s%04x%04x.sep%c%s.%s",
                        zoneOutbound, link->hisAka.net, link->hisAka.node,
                        limiter, uniquestring, ext);
            } else
            {
                sprintf(pfilename,"%s%s.%s",zoneOutbound,
                        uniquestring, ext);
            }
        } else
        {
            if (config->separateBundles)
            {
                sprintf(pfilename,"%s%04x%04x.pnt%c%08x.sep%c%s.%s",
                        zoneOutbound, link->hisAka.net, link->hisAka.node,
                        limiter, link->hisAka.point, limiter,
                        uniquestring, ext);
            } else
            {
                sprintf(pfilename,"%s%04x%04x.pnt%c%s.%s",
                        zoneOutbound, link->hisAka.net, link->hisAka.node,
                        limiter, uniquestring, ext);
            }
        }
    } while (fexist(filename) || fexist(pfilename));

    nfree(zoneOutbound);

    nfree(link->packFile);
    nfree(link->pktFile);

    link->packFile = pfilename;
    link->pktFile = filename;
    return 0;
}

#endif

int createDirectoryTree(const char *pathName) {

   struct stat buf;
   char *start, *slash;

   char limiter=PATH_DELIM;

   int i;

   start = (char *) safe_malloc(strlen(pathName)+2);
   strcpy(start, pathName);
   i = strlen(start)-1;
   if (start[i] != limiter) {
      start[i+1] = limiter;
      start[i+2] = '\0';
   }
   slash = start;

#ifndef UNIX
   // if there is a drivename, jump over it
   if (slash[1] == ':') slash += 2;
#endif

   // jump over first limiter
   slash++;

   while ((slash = strchr(slash, limiter)) != NULL) {
      *slash = '\0';

      if (stat(start, &buf) != 0) {
         // this part of the path does not exist, create it
         if (mymkdir(start) != 0) {
            writeLogEntry(hpt_log, '9', "Could not create directory %s", start);
            nfree(start);
            return 1;
         }
/*    by AW 27.09.99    */
#ifdef __WATCOMC__
      } else if(!AW_S_ISDIR(buf.st_mode)) {
#else
      } else if(!S_ISDIR(buf.st_mode)) {
#endif
         writeLogEntry(hpt_log, '9', "%s is a file not a directory", start);
         nfree(start);
         return 1;
      }

      *slash++ = limiter;
   }

   nfree(start);

   return 0;
}

int createOutboundFileName(s_link *link, e_prio prio, e_type typ)
{
   int fd; // bsy file for current link
   int save_errno;
   char name[13], bsyname[13], zoneSuffix[6], pntDir[14];
   char	*sepDir, sepname[13];

   char limiter=PATH_DELIM;

   if (link->hisAka.point != 0) {
      sprintf(pntDir, "%04x%04x.pnt%c", link->hisAka.net, link->hisAka.node, limiter);
      sprintf(name, "%08x.flo", link->hisAka.point);
   } else {
      pntDir[0] = 0;
      sprintf(name, "%04x%04x.flo", link->hisAka.net, link->hisAka.node);
   }

   if (link->hisAka.zone != config->addr[0].zone) {
      // add suffix for other zones
      sprintf(zoneSuffix, ".%03x%c", link->hisAka.zone, limiter);
   } else {
      zoneSuffix[0] = 0;
   }

   switch (typ) {
      case PKT:
         name[9] = 'o'; name[10] = 'u'; name[11] = 't';
         break;
      case REQUEST:
         name[9] = 'r'; name[10] = 'e'; name[11] = 'q';
         break;
      case FLOFILE: break;
   } /* endswitch */

   if (typ != REQUEST) {
      switch (prio) {
         case CRASH :    name[9] = 'c';
                         break;
         case HOLD  :    name[9] = 'h';
                         break;
	 case DIRECT:    name[9] = 'd';
	                 break;
	 case IMMEDIATE: name[9] = 'i';
	                 break;
         case NORMAL:    break;
      } /* endswitch */
   } /* endif */

   // create floFile
   link->floFile = (char *) safe_malloc(strlen(config->outbound)+strlen(pntDir)+strlen(zoneSuffix)+strlen(name)+1);
   link->bsyFile = (char *) safe_malloc(strlen(config->outbound)+strlen(pntDir)+strlen(zoneSuffix)+strlen(name)+1);
   strcpy(link->floFile, config->outbound);
   if (zoneSuffix[0] != 0) strcpy(link->floFile+strlen(link->floFile)-1, zoneSuffix);
   strcat(link->floFile, pntDir);
   createDirectoryTree(link->floFile); // create directoryTree if necessary
   strcpy(link->bsyFile, link->floFile);
   strcat(link->floFile, name);

   // separate bundles
   if (config->separateBundles) {

	   if (link->hisAka.point != 0) sprintf(sepname, "%08x.sep", link->hisAka.point);
	   else sprintf(sepname, "%04x%04x.sep", link->hisAka.net, link->hisAka.node);

	   sepDir = (char *) safe_malloc(strlen(link->bsyFile)+strlen(sepname)+2);
	   sprintf(sepDir,"%s%s%c",link->bsyFile,sepname,limiter);

	   createDirectoryTree(sepDir);
	   nfree(sepDir);
   }

   // create bsyFile
   strcpy(bsyname, name);
   strcpy(&bsyname[9], "bsy");
   strcat(link->bsyFile, bsyname);

   // maybe we have session with this link?
   if (fexist(link->bsyFile)) {

           writeLogEntry(hpt_log, '7', "link %s is busy.", link->name);
           nfree(link->floFile);
           nfree(link->bsyFile);

           return 1;

   } else {

           if ( (fd=open(link->bsyFile, O_CREAT | O_RDWR | O_EXCL, S_IREAD | S_IWRITE)) < 0 ) {
              save_errno = errno;

              if (!fexist(link->bsyFile)) {

                 writeLogEntry(hpt_log, '7', "cannot create *.bsy file \"%s\" for %s (errno %d)\n", link->bsyFile, link->name, (int)save_errno);
                 exit_hpt("cannot create *.bsy file!",0);

              } else {

                 writeLogEntry(hpt_log, '7', "link %s is busy (2nd check).", link->name);
                 nfree(link->floFile);
                 nfree(link->bsyFile);

                 return 1;
              }

           } else close(fd);
   }

   return 0;
}

void *safe_malloc(size_t size)
{
    void *ptr = malloc (size);
    if (ptr == NULL) exit_hpt("out of memory", 1);
    return ptr;
}

void *safe_calloc(size_t nmemb, size_t size)
{
    void *ptr = safe_malloc (size*nmemb);
    memset(ptr,'\0',size*nmemb);
    return ptr;
}

void *safe_realloc(void *ptr, size_t size)
{
    void *newptr = realloc (ptr, size);
    if (newptr == NULL) exit_hpt("out of memory", 1);
    return newptr;
}

char *safe_strdup(const char *src)
{
    char *ptr = strdup (src);
    if (ptr == NULL) exit_hpt("out of memory", 1);
    return ptr;
}
