/*:ts=8*/
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
#include <unistd.h>
#ifdef __IBMC__
#include <direct.h>
#endif
#ifdef __WATCOMC__
#include <fcntl.h>
#define AW_S_ISDIR(a) (((a) & S_IFDIR) != 0)
#endif

#include <global.h>
#include <fidoconfig.h>

#include <typedefs.h>
#include <compiler.h>
#include <stamp.h>
#include <progprot.h>

int createLockFile(char *lockfile) {
        FILE *f;

        if ((f=fopen(lockfile,"a")) == NULL)
           {
                   fprintf(stderr,"createLockFile: cannot create lock file\"%s\"\n",lockfile);
                   writeLogEntry(hpt_log, '9', "createLockFile: cannot create lock file");
                   return 1;
           }

#ifndef __NT__	   
        fprintf(f, "%u\n", getpid());
#endif

        fclose(f);
        return 0;
}

#if defined(__TURBOC__) || defined(__IBMC__)

#include <io.h>
#include <fcntl.h>

#define S_ISDIR(a) (((a) & S_IFDIR) != 0)

#endif

#if defined(__TURBOC__) || defined(__IBMC__) || defined(__WATCOMC__)

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
   // pkt file in tempOutbound
   char   *fileName = (char *) malloc(strlen(config->tempOutbound)+12+1);
   // name of the arcmail bundle
   char   *pfileName = (char *) malloc(strlen(config->outbound)+13+13+12+1);
   // temp name of the arcmail bundle
   char   *tmpPFileName = (char *) malloc(strlen(config->outbound)+13+13+12+1);
   time_t aTime = time(NULL);  // get actual time
   int counter = 0;
   char *wdays[7]={ "su", "mo", "tu", "we", "th", "fr", "sa" };
#ifdef UNIX
   char limiter='/';
#else
   char limiter='\\';
#endif
   char zoneSuffix[6] = "\0";

   char *zoneOutbound; // this contains the correct outbound directory including zones

   time_t tr;
   char *wday;
   struct tm *tp;


   tr=time(NULL);
   tp=localtime(&tr);
   counter = 0;

   wday=wdays[tp->tm_wday];

   aTime %= 0xffffff;   // only last 24 bit count

   if (link->hisAka.zone != config->addr[0].zone) {
      sprintf(zoneSuffix, ".%03x%c", link->hisAka.zone, PATH_DELIM);
      zoneOutbound = malloc(strlen(config->outbound)-1+strlen(zoneSuffix)+1);
      strcpy(zoneOutbound, config->outbound);
      strcpy(zoneOutbound+strlen(zoneOutbound)-1, zoneSuffix);
   } else
      zoneOutbound = strdup(config->outbound);


   // There is a problem here: Since we use the tmpOutbound fileName for duplicate checking, links with different zones who does not
   // have problems with duplicate pfileName´s increment the counter. We can run out of counters without using them.
   // Has anybody understand that? :-)
   // This is no big problem, but a big system with many links and many zones may encounter problems

   do {
	   
	   sprintf(fileName, "%s%06lx%02x.pkt", config->tempOutbound, aTime, counter);
	   
	   if ( link->hisAka.point == 0 ) {

		   if (config->separateBundles) sprintf(tmpPFileName,
												"%s%04x%04x.sep%c%06lx%02x.%s",
												zoneOutbound, link->hisAka.net,
												link->hisAka.node, limiter,
												aTime, counter, wday);
		   
		   else sprintf(tmpPFileName,"%s%06lx%02x.%s",zoneOutbound,aTime,counter,wday);

	   } else {
		   
		   if (config->separateBundles) sprintf(tmpPFileName,
												"%s%04x%04x.pnt%c%08x.sep%c%06lx%02x.%s",
												zoneOutbound, link->hisAka.net,
												link->hisAka.node, limiter,
												link->hisAka.point, limiter,
												aTime, counter, wday);
		   else sprintf(tmpPFileName,
						"%s%04x%04x.pnt%c%06lx%02x.%s",
						zoneOutbound, link->hisAka.net,
						link->hisAka.node, limiter,
						aTime, counter, wday);
	   }
	   
	   counter++;
	   
   } while ((fexist(fileName) || fileNameAlreadyUsed(fileName, NULL)) && (counter<=255));

   counter = 0;
   do {
      sprintf(pfileName, "%s%0x", tmpPFileName, counter);
      counter++;
   } while ((fexist(pfileName) || fileNameAlreadyUsed(NULL, pfileName)) && (counter <= 15));

   free(tmpPFileName);

   if ((!fexist(fileName)) && (!fexist(pfileName))) {
           link->packFile = pfileName;
           link->pktFile = fileName;
           return 0;
   }
   else {
      free(fileName);
      free(pfileName);
      return 1;
   }
}

int createDirectoryTree(const char *pathName) {

   struct stat buf;
   char *start, *slash;
   char *buff;

#ifdef UNIX
   char limiter='/';
#else
   char limiter='\\';
#endif

   int i;

   start = (char *) malloc(strlen(pathName)+2);
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
            buff = (char *) malloc(strlen(start)+30);
            sprintf(buff, "Could not create directory %s", start);
            writeLogEntry(hpt_log, '5', buff);
            free(buff);
            free(start);
            return 1;
         }
/*    by AW 27.09.99    */
#ifdef __WATCOMC__
      } else if(!AW_S_ISDIR(buf.st_mode)) {
#else
      } else if(!S_ISDIR(buf.st_mode)) {
#endif
         buff = (char *) malloc(strlen(start)+30);
         sprintf(buff, "%s is a file not a directory", start);
         writeLogEntry(hpt_log, '5', buff);
         free(buff);
         free(start);
         return 1;
      }

      *slash++ = limiter;
   }

   free(start);

   return 0;
}

int createOutboundFileName(s_link *link, e_prio prio, e_type typ)
{
   FILE *f; // bsy file for current link
   char name[13], bsyname[13], zoneSuffix[6], pntDir[14], *tolog;
   char	*sepDir, sepname[13];

#ifdef UNIX
   char limiter='/';
#else
   char limiter='\\';
#endif

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
   link->floFile = (char *) malloc(strlen(config->outbound)+strlen(pntDir)+strlen(zoneSuffix)+strlen(name)+1);
   link->bsyFile = (char *) malloc(strlen(config->outbound)+strlen(pntDir)+strlen(zoneSuffix)+strlen(name)+1);
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

	   sepDir = (char *) malloc(strlen(link->bsyFile)+strlen(sepname)+2);
	   sprintf(sepDir,"%s%s%c",link->bsyFile,sepname,limiter);

	   createDirectoryTree(sepDir);
	   free(sepDir);
   }

   // create bsyFile
   strcpy(bsyname, name);
   bsyname[9]='b';bsyname[10]='s';bsyname[11]='y';
   strcat(link->bsyFile, bsyname);

   // maybe we have session with this link?
   if (fexist(link->bsyFile)) {

           tolog = (char*) malloc (strlen(link->name)+40+1);
           sprintf(tolog,"link %s is busy.", link->name);

           writeLogEntry(hpt_log, '7', tolog);
           free (link->floFile); link->floFile = NULL;
           free (link->bsyFile); link->bsyFile = NULL;
           free (tolog);

           return 1;

   } else {

           if ((f=fopen(link->bsyFile,"a")) == NULL)
                   {
                           fprintf(stderr,"cannot create *.bsy file for %s\n",link->name);
                           if (config->lockfile != NULL) {
                                   remove(link->bsyFile);
                                   free(link->bsyFile);
                                   link->bsyFile=NULL;
                           }
                           writeLogEntry(hpt_log, '9', "cannot create *.bsy file");
                           writeLogEntry(hpt_log, '1', "End");
                           closeLog(hpt_log);
                           disposeConfig(config);
                           exit(1);
                   }
           fclose(f);
   }

   return 0;
}

