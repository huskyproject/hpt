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
#endif
#ifdef __WATCOMC__
#include <fcntl.h>
#define AW_S_ISDIR(a) (((a) & S_IFDIR) != 0)
#include <process.h>
#include <dos.h>
#endif
#include <fcntl.h>
#include <errno.h>

#if defined(__TURBOC__) || defined(__IBMC__) || (defined(_MSC_VER) && (_MSC_VER >= 1200))

#include <io.h>
#include <fcntl.h>

#if !defined(S_ISDIR)
#define S_ISDIR(a) (((a) & S_IFDIR) != 0)
#endif

#endif

#include <global.h>
#include <fcommon.h>
#include <recode.h>
#include <dupe.h>
#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/xstr.h>
#include <fidoconf/dirlayer.h>

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
    if (config->lockfile) {
	close(lock_fd);
	remove(config->lockfile);
    }
    w_log('9', logstr);
    w_log('1', "End");
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
                   w_log('9', "createLockFile: cannot create lock file \"%s\"m", lockfile);
                   return 1;
           }

        xscatprintf(&pidstr, "%u\n", (unsigned)getpid());
        write (fd, pidstr, strlen(pidstr));

        close(fd);
	nfree(pidstr);
        return 0;
}

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


static char *wdays[7]={ "su", "mo", "tu", "we", "th", "fr", "sa" };

void cleanEmptyBundles(char *pathName, int npos)
// Removing old empty bundles when bundleNameStyle == addDiff
{
   char           *ptr, *tmpfile, *pattern, savech;
   DIR            *dir;
   struct dirent  *file;
   struct stat stbuf;
   time_t tr;

   tmpfile = safe_malloc(strlen(pathName) + 4);

   strcpy(tmpfile, pathName);
   savech = tmpfile[npos-1]; // there must be path delimiter
   tmpfile[npos-1] = '\0';

   if(!(dir = opendir(tmpfile))) { // nothing to clean
      nfree(tmpfile);
      return;
   }

   tmpfile[npos-1] = savech;

   pattern = safe_malloc(strlen(tmpfile+npos) + 4);
   strcpy(pattern, tmpfile+npos);

   for (ptr=pattern; *ptr; ptr++);
   ptr[0]='*';
   ptr[1]='\0';

   tr = time(NULL);

   while ((file = readdir(dir)) != NULL) {

	   if ( patimat(file->d_name, pattern) == 1 ) {

		   strcpy(tmpfile+npos, file->d_name);

		   if ( stat(tmpfile, &stbuf) == 0) {

               if (tr - stbuf.st_mtime >= 60*60*24 && stbuf.st_size == 0 ) {

				   remove (tmpfile); // old empty bundle

               }
		   }
	   }
   }

   closedir(dir);
   nfree(pattern);
   nfree(tmpfile);
}

int createTempPktFileName(s_link *link)
{
	char *fileName=NULL; // pkt file in tempOutbound
	char *pfileName=NULL; // name of the arcmail bundle
	char *tmp=NULL; // temp name of the arcmail bundle
    time_t aTime = time(NULL);  /* get actual time */
    int counter, minFreeExt, npos;
    char limiter=PATH_DELIM;
	
    e_bundleFileNameStyle bundleNameStyle = eTimeStamp;

    time_t tr;
    char *wday;
    struct tm *tp;

	int i;
	struct stat stbuf;
	static char *ext3 = "0123456789abcdefghijklmnopqrstuvwxyz";
	int numExt = strlen(ext3);

    tr=time(NULL);
    tp=localtime(&tr);
    counter = pkt_count;

    wday=wdays[tp->tm_wday];

    aTime %= 0xffffff;   /* only last 24 bit count */

    if (link->linkBundleNameStyle!=eUndef) bundleNameStyle=link->linkBundleNameStyle;
    else if (config->bundleNameStyle!=eUndef) bundleNameStyle=config->bundleNameStyle;

	xstrcat(&tmp, config->outbound);

	// add suffix for other zones
	if (link->hisAka.zone != config->addr[0].zone && bundleNameStyle != eAmiga) {
		tmp[strlen(tmp)-1]='\0';
		xscatprintf(&tmp, ".%03x%c", link->hisAka.zone, limiter);
	}

	/* Making pkt name */
	while(1) {
		do {
			xscatprintf(&fileName, "%s%06lx%02x.pkt",
						config->tempOutbound, (long)aTime, counter);
			counter++;

		} while ((fexist(fileName) || fileNameAlreadyUsed(fileName, NULL)) &&
				 (counter<=255));

		if (counter<=256) break;
		else {
			counter=0;
			nfree(fileName);
			if (pkt_aTime==aTime) {
				w_log('7',"created 256 pkt's/sec!");
				sleep(1);
				aTime = time(NULL);
				aTime %= 0xffffff;
			}
		}
	}
	pkt_count = counter;
	pkt_aTime = aTime;

	// path to bundle
	if (bundleNameStyle!=eAmiga) {
		if (link->hisAka.point)
			xscatprintf(&tmp, "%04x%04x.pnt%c",
						link->hisAka.net, link->hisAka.node, limiter);

		// separate bundles
		if (config->separateBundles) {
			if (link->hisAka.point) xscatprintf(&tmp, "%08x.sep%c", 
												link->hisAka.point, limiter);
			else xscatprintf(&tmp, "%04x%04x.sep%c", link->hisAka.net,
							 link->hisAka.node, limiter);
		}
	}

	npos = strlen(tmp);

	/* bundle file name */
	switch ( bundleNameStyle ) {

	case eAddrDiff:
	case eAddrDiffAlways:

		if ( link->hisAka.point == 0 && config->addr[0].point == 0) {
			xscatprintf (&tmp, "%04hx%04hx.",
						 config->addr[0].net - link->hisAka.net,
						 config->addr[0].node - link->hisAka.node);
		} else {
			xscatprintf (&tmp, "%04hx%04hx.",
						 config->addr[0].node - link->hisAka.node,
						 config->addr[0].point- link->hisAka.point);
		}

	case eAmiga:
		if (bundleNameStyle==eAmiga) {
			xscatprintf (&tmp, "%u.%u.%u.%u.",
						 link->hisAka.zone, link->hisAka.net,
						 link->hisAka.node, link->hisAka.point);
		}

		cleanEmptyBundles(tmp,npos);

		counter = 0;
		minFreeExt = -1;
		for (i=0; i<numExt; i++) {

			xstrscat(&pfileName, tmp, wday, NULL);
			xscatprintf(&pfileName, "%c", ext3[i]);
			
			if (stat(pfileName, &stbuf) == 0) {

				if (tr - stbuf.st_mtime < 60*60*24) {
					// today's bundle
					counter = i+1;
					if (stbuf.st_size==0 && (counter<numExt ||
											 bundleNameStyle==eAddrDiffAlways ||
											 bundleNameStyle==eAmiga))
						remove (pfileName);
				} else {
					// old bundle
					if (stbuf.st_size == 0)	remove (pfileName);
					else counter = i+1;
				}
			} else {
				if (minFreeExt <0) minFreeExt = i;
			}
			
			nfree(pfileName);
		}

		if (counter >= numExt) {
			if ((bundleNameStyle==eAddrDiffAlways || bundleNameStyle==eAmiga)
				&& minFreeExt>=0) {
				counter = minFreeExt;
			} else {
				w_log('7',"Can't use more than %d extensions for bundle names",numExt);
				nfree(fileName);
				nfree(pfileName);
				nfree(tmp);

				// Switch link to TimeStamp style
				link->linkBundleNameStyle = eTimeStamp;
				i = createTempPktFileName(link);
				return i;
			}
		}
		
		xstrscat(&pfileName, tmp, wday, NULL);
		xscatprintf(&pfileName, "%c", ext3[counter]);

		break;

	case eTimeStamp:
		xscatprintf(&tmp, "%06lx%02x.%s", (long)aTime, counter, wday);
		counter = 0;
		do {
			xstrcat(&pfileName, tmp);
			xscatprintf(&pfileName, "%c", ext3[counter]);
			counter++;
		} while ((fexist(pfileName) || fileNameAlreadyUsed(NULL, pfileName))
				 && (counter < numExt));

		if (counter >= numExt) w_log('7',"created %d bundles/sec!", numExt);

		break;

	default:
		w_log('9', "Unknown bundleNameStyle (non-compatible fidoconfig library?)");
		exit(-1);
		break;
	}
	nfree(tmp);

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
		w_log('7',"can't create arcmail bundles any more!");
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
            w_log('9', "Could not create directory %s", start);
            nfree(start);
            return 1;
         }
/*    by AW 27.09.99    */
#ifdef __WATCOMC__
      } else if(!AW_S_ISDIR(buf.st_mode)) {
#else
      } else if(!S_ISDIR(buf.st_mode)) {
#endif
         w_log('9', "%s is a file not a directory", start);
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
   char *name=NULL, *sepDir=NULL, limiter=PATH_DELIM, *tmpPtr;
   e_bundleFileNameStyle bundleNameStyle = eUndef;
   
   if (link->linkBundleNameStyle!=eUndef) bundleNameStyle=link->linkBundleNameStyle;
   else if (config->bundleNameStyle!=eUndef) bundleNameStyle=config->bundleNameStyle;
   
   if (bundleNameStyle != eAmiga) {
	   if (link->hisAka.point) xscatprintf(&name, "%08x.", link->hisAka.point);
	   else xscatprintf(&name, "%04x%04x.", link->hisAka.net, link->hisAka.node);
   } else {
	   xscatprintf(&name, "%u.%u.%u.%u.", link->hisAka.zone,
				   link->hisAka.net, link->hisAka.node, link->hisAka.point);
   }

   if (typ != REQUEST) {
	   switch (prio) {
	   case CRASH :     xstrcat(&name, "c");
		   break;
	   case HOLD :      xstrcat(&name, "h");
		   break;
	   case DIRECT :    xstrcat(&name, "d");
		   break;
	   case IMMEDIATE : xstrcat(&name, "i");
		   break;
	   case NORMAL :    xstrcat(&name, (typ==PKT) ? "o" : "f");
		   break;
	   }
   } else xstrcat(&name, "req");

   switch (typ) {
   case PKT :     xstrcat(&name, "ut");
	   break;
   case FLOFILE : xstrcat(&name, "lo");
	   break;
   case REQUEST :
	   break;
   }

   // create floFile
   xstrcat(&link->floFile, config->outbound);

   // add suffix for other zones
   if (link->hisAka.zone != config->addr[0].zone && bundleNameStyle != eAmiga) {
	   link->floFile[strlen(link->floFile)-1]='\0';
	   xscatprintf(&link->floFile, ".%03x%c", link->hisAka.zone, limiter);
   }

   if (link->hisAka.point && bundleNameStyle != eAmiga)
	   xscatprintf(&link->floFile, "%04x%04x.pnt%c",
				   link->hisAka.net, link->hisAka.node, limiter);
   
   createDirectoryTree(link->floFile); // create directoryTree if necessary
   xstrcat(&link->bsyFile, link->floFile);
   xstrcat(&link->floFile, name);

   // separate bundles

   if (config->separateBundles && (bundleNameStyle!=eAmiga || (bundleNameStyle==eAmiga && link->packerDef==NULL))) {

	   xstrcat(&sepDir, link->bsyFile);
	   if (bundleNameStyle==eAmiga) 
		   xscatprintf(&sepDir, "%u.%u.%u.%u.sep%c", 
					   link->hisAka.zone, link->hisAka.net,
					   link->hisAka.node ,link->hisAka.point, limiter);
	   else if (link->hisAka.point) xscatprintf(&sepDir, "%08x.sep%c", 
												link->hisAka.point, limiter);
	   else xscatprintf(&sepDir, "%04x%04x.sep%c", link->hisAka.net,
						link->hisAka.node, limiter);
	   
	   createDirectoryTree(sepDir);
	   nfree(sepDir);
   }

   // create bsyFile
   if ((tmpPtr=strrchr(name, '.')) != NULL) *tmpPtr = '\0';
   xstrscat(&link->bsyFile, name, ".bsy", NULL);
   nfree(name);

   // maybe we have session with this link?
   if ( (fd=open(link->bsyFile, O_CREAT | O_RDWR | O_EXCL, S_IREAD | S_IWRITE)) < 0 ) {

#if !defined(__WATCOMC__)	   
	   int save_errno = errno;
	   
	   if (save_errno != EEXIST) {
		   w_log('7', "cannot create *.bsy file \"%s\" for %s (errno %d)\n", link->bsyFile, link->name, (int)save_errno);
		   exit_hpt("cannot create *.bsy file!",0);
		   
	   } else {
#endif
		   w_log('7', "link %s is busy.", link->name);
		   nfree(link->floFile);
		   nfree(link->bsyFile);
		   
		   return 1;
#if !defined(__WATCOMC__)	   
	   }
#endif
   } else close(fd);

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
