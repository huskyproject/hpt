/*:ts=8*/
/*****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 * Copyright (C) 1997-1998
 *
 * Matthias Tichy
 *
 * Fido:     2:2433/1245 2:2433/1247 2:2432/601.29
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
#include <sys/stat.h>
#include <unistd.h>

#include <global.h>
#include <fidoconfig.h>

#include <typedefs.h>
#include <compiler.h>
#include <stamp.h>
#include <progprot.h>

e_prio cvtFlavour2Prio(e_flavour flavour)
{
   switch (flavour) {
      case hold:   return HOLD;;
                   break;
      case normal: return NORMAL;
                   break;
      default:     return CRASH;
                   break;
   }
   return NORMAL;
}

int createTempPktFileName(s_link *link)
{
   char   *fileName = (char *) malloc(strlen(config->outbound)+1+12);
   char   *pfileName = (char *) malloc(strlen(config->outbound)+1+12);
   time_t aTime = time(NULL);  // get actual time
   int counter = 0;
   char *wdays[7]={ "su", "mo", "tu", "we", "th", "fr", "sa" };

   time_t tr;
   char *wday;
   struct tm *tp;
   tr=time(NULL);
   tp=localtime(&tr);
   
   wday=wdays[tp->tm_wday];

   aTime %= 0xffffff;   // only last 24 bit count

   do {
      sprintf(fileName, "%s%06lx%02x.pkt", config->outbound, aTime, counter);
      sprintf(pfileName, "%s%06lx%02x.%s0", config->outbound, aTime, counter,wday);
      counter++;
   } while (fexist(fileName) && (counter<=256));

   if (!fexist(fileName)) {
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
#ifdef UNIX
         if (mkdir(start, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
#else
         if (mkdir(start) != 0) {
#endif
            buff = (char *) malloc(strlen(start)+30);
            sprintf(buff, "Could not create directory %s", start);
            writeLogEntry(log, '5', buff);
            free(buff);
            free(start);
            return 1;
         }
      } else if(!S_ISDIR(buf.st_mode)) {
         buff = (char *) malloc(strlen(start)+30);
         sprintf(buff, "%s is a file not a directory", start);
         writeLogEntry(log, '5', buff);
         free(buff);
         free(start);
         return 1;
      }

      *slash++ = limiter;
   }

   free(start);

   return 0;
}

char *createOutboundFileName(s_addr aka, e_prio prio, e_type typ)
{
   char name[13], zoneSuffix[5], pntDir[14];
   char *fileName;

   if (aka.point != 0) {
      sprintf(pntDir, "%04x%04x.pnt\\", aka.net, aka.node);
#ifdef UNIX
      pntDir[12] = '/';
#endif
      sprintf(name, "%08x.flo", aka.point);
   } else {
      pntDir[0] = 0;
      sprintf(name, "%04x%04x.flo", aka.net, aka.node);
   }

   if (aka.zone != config->addr[0].zone) {
      // add suffix for other zones
      sprintf(zoneSuffix, ".%03x\\", aka.zone);
#ifdef UNIX
      zoneSuffix[4] = '/';
#endif
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
         case CRASH : name[9] = 'c';
                      break;
         case HOLD  : name[9] = 'h';
                      break;
         case NORMAL: break;
      } /* endswitch */
   } /* endif */

   fileName = (char *) malloc(strlen(config->outbound)+strlen(pntDir)+strlen(zoneSuffix)+strlen(name)+1);
   strcpy(fileName, config->outbound);
   if (zoneSuffix[0] != 0) strcpy(fileName+strlen(fileName)-1, zoneSuffix);
   strcat(fileName, pntDir);
   createDirectoryTree(fileName); // create directoryTree if necessary
   strcat(fileName, name);
   
   return fileName;
}
