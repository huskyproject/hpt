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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifndef __IBMC__
#include <unistd.h>
#endif

#include <msgapi.h>
#include <progprot.h>

#include <version.h>
#include <pkt.h>

#ifndef MSDOS
#include <fidoconfig.h>
#else
#include <fidoconf.h>
#endif

#include <log.h>

#include <global.h>
#include <hpt.h>
#include <toss.h>
#include <scan.h>
#include <fcommon.h>
#include <dir.h>
#include <patmat.h>
#include <post.h>

void processCommandLine(int argc, char **argv)
{
   unsigned int i = 0;

   if (argc == 1) {
      printf("\nUsage:\n");
      printf("   hpt toss - tossing mail\n");
      printf("   hpt scan - scanning echomail\n");
      printf("   hpt pack - packing netmail\n");
      printf("   hpt post - posting a mail\n");
   }

   while (i < argc-1) {
      i++;
      if (0 == stricmp(argv[i], "toss")) {
         cmToss = 1;
         continue;
      } else if (stricmp(argv[i], "scan") == 0) {
         cmScan = 1;
         continue;
      } else if (stricmp(argv[i], "pack") == 0) {
         cmPack = 1;
         continue;
      } else if (stricmp(argv[i], "post") == 0) {
         ++i; post(argc, &i, argv);
      } else printf("Unrecognized Commandline Option %s!\n", argv[i]);

   } /* endwhile */
}

void processConfig()
{
   char *buff;

   config = readConfig();
   if (NULL == config) {
      printf("Config not found\n");
      exit(1);
   }

   // lock...
   if (config->lockfile!=NULL && fexist(config->lockfile)) {
           printf("lock file found! exit...\n");
           disposeConfig(config);
           exit(1);
   }
   else if (config->lockfile!=NULL) createLockFile(config->lockfile);

   // open Logfile
   buff = (char *) malloc(strlen(config->logFileDir)+7+1); // 7 for hpt.log
   strcpy(buff, config->logFileDir),
   strcat(buff, "hpt.log");
   log  = openLog(buff, versionStr, "123456789");
   if (log==NULL) printf("Could not open logfile: %s\n", buff);
   writeLogEntry(log, '1', "Start");

   if (config->addrCount == 0) printf("at least one addr must be defined\n");
   if (config->linkCount == 0) printf("at least one link must be specified\n");
   if (config->routeCount == 0) printf("at least one route must be specified\n");
   if (config->tempOutbound == NULL) printf("you must set tempOutbound in fidoconfig first\n");
   if (config->tempInbound == NULL) printf("you must set tempInbound in fidoconfig first\n");

   if (config->addrCount == 0 ||
       config->linkCount == 0 ||
       config->linkCount == 0 ||
       config->tempInbound == NULL ||
       config->tempOutbound == NULL) {
      if (config->lockfile != NULL) remove(config->lockfile);
      writeLogEntry(log, '9', "wrong config file");
      writeLogEntry(log, '1', "End");
      closeLog(log);
      disposeConfig(config);
      exit(1);
   }
}

void tossTempOutbound(char *directory)
{
   DIR            *dir;
   FILE           *pkt;
   struct dirent  *file;
   char           *dummy;
   s_pktHeader    *header;
   s_link         *link;

   if (directory==NULL) return;

   dir = opendir(directory);

   while ((file = readdir(dir)) != NULL) {
           if ((patmat(file->d_name, "*.pkt") == 1) || (patmat(file->d_name, "*.PKT") == 1)) {
                   dummy = (char *) malloc(strlen(directory)+strlen(file->d_name)+1);
                   strcpy(dummy, directory);
                   strcat(dummy, file->d_name);

                   pkt = fopen(dummy, "rb");

                   header = openPkt(pkt);
                   link = getLinkFromAddr (*config, header->destAddr);
                   createTempPktFileName(link);

                   free(link->pktFile);
                   link->pktFile = dummy;

                   writeLogEntry(log, '7', "found non packed mail in tempOutbound");
                   fclose(pkt);
                   arcmail();
           }
   }

   closedir(dir);
   return;
}

int main(int argc, char **argv)
{
   struct _minf m;

   sprintf(versionStr, "hpt v%u.%02u", VER_MAJOR, VER_MINOR);

   printf("Highly Portable Toss v%u.%02u\n", VER_MAJOR, VER_MINOR);

   processConfig();
   processCommandLine(argc, argv);

   // init SMAPI
   m.req_version = 0;
   m.def_zone = config->addr[0].zone;
   if (MsgOpenApi(&m) != 0) {
      writeLogEntry(log, '9', "MsgApiOpen Error");
          if (config->lockfile != NULL) remove(config->lockfile);
      closeLog(log);
      disposeConfig(config);
      exit(1);
   } /*endif */

   tossTempOutbound(config->tempOutbound);
   if (1 == cmToss) toss();
   if (cmScan == 1) scan();
   if (cmPack == 1) pack();

   // deinit SMAPI
   MsgCloseApi();

   if (config->lockfile != NULL) remove(config->lockfile);
   writeLogEntry(log, '1', "End");
   closeLog(log);
   disposeConfig(config);
   return 0;
}
