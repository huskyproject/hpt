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
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>

#include <msgapi.h>
#include <progprot.h>

#include <version.h>
#include <pkt.h>

#if !defined(MSDOS) || defined(__DJGPP__)
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
#include <dirlayer.h>
#include <patmat.h>
#include <post.h>
#include <link.h>
#include <areafix.h>
#include <recode.h>

#if defined ( __WATCOMC__ ) && defined ( __NT__ )
int __stdcall SetConsoleTitleA( const char* lpConsoleTitle );
#endif

s_message **msgToSysop = NULL;
char *scanParmA;
char *scanParmF;


/* kn: I've really tried not to break it. 
   FIXME: if there is pack and scan options on cmd line - one set 
   of options are lost */
int  processExportOptions(unsigned int *i, int argc, char **argv)
{ 
  int rc = 0;
  while ((*i) < argc-1) {
     if (argv[(*i)+1][0] == '-' && (argv[(*i)+1][1] == 'w' || argv[(*i)+1][1] == 'W')) {
        noHighWaters = 1;
        (*i)++;
        continue;
     } /* endif */
     if (argv[(*i)+1][0] == '-' && (argv[(*i)+1][1] == 'f' || argv[(*i)+1][1] == 'F')) {
        if (stricmp(argv[(*i)+1], "-f") == 0) {
           (*i)++;
           scanParmF = argv[(*i)+1];
        } else {
           scanParmF = argv[(*i)+1]+2;
        } /* endif */
        rc |= 2;
        (*i)++;
        continue;
     } else if (argv[(*i)+1][0] == '-' && (argv[(*i)+1][1] == 'a' || argv[(*i)+1][1] == 'A')) {
        if (stricmp(argv[(*i)+1], "-a") == 0) {
           (*i)++;
           scanParmA = argv[(*i)+1];
        } else {
           scanParmA = argv[(*i)+1]+2;
        } /* endif */
        rc |= 4;
        (*i)++;
        continue;
     } /* endif */
     break;
  } /* endwhile */
  return rc != 0 ? rc : 1;
}

int processCommandLine(int argc, char **argv)
{
   unsigned int i = 0;

   if (argc == 1) {
      printf("\nUsage:\n");
      printf("   hpt toss    - tossing mail\n");
      printf("   hpt toss -b - tossing mail from badarea\n");
      printf("   hpt scan    - scanning echomail\n");
      printf("   hpt scan -w - scanning echomail without highwaters\n");
      printf("   hpt scan -a <areaname> - scanning echomail from <areaname> area\n");
      printf("   hpt scan -f <filename> - scanning echomail from alternative echotoss file\n");
      printf("   hpt post [options] file - posting a mail (for details run \"hpt post -h\")\n");
      printf("   hpt pack    - packing netmail\n");
      printf("   hpt link    - links messages\n");
      printf("   hpt afix    - process areafix\n");
   }

   while (i < argc-1) {
      i++;
      if (0 == stricmp(argv[i], "toss")) {
         cmToss = 1;
         if (i < argc-1) if (stricmp(argv[i+1], "-b") == 0) {
             cmToss = 2;
             break;
//             i++;
         }
         continue;
      } else if (stricmp(argv[i], "scan") == 0) {
 	 cmScan = processExportOptions(&i, argc, argv);
         continue;
      } else if (stricmp(argv[i], "pack") == 0) {
         cmPack = processExportOptions(&i, argc, argv);
         continue;
      } else if (stricmp(argv[i], "link") == 0) {
         cmLink = 1;
         continue;
      } else if (stricmp(argv[i], "afix") == 0) {
         cmAfix = 1;
         continue;
      } else if (stricmp(argv[i], "post") == 0) {
         ++i; post(argc, &i, argv);
      } else printf("Unrecognized Commandline Option %s!\n", argv[i]);

   } /* endwhile */

   return argc;
}

void processConfig()
{
#if !defined(__OS2__) && !defined(UNIX)
   time_t   time_cur, locklife = 0;
   struct   stat stat_file;
#endif
   char *buff = NULL;
   unsigned long pid;
   
   FILE *f;

   config = readConfig();
   if (NULL == config) {
      printf("Config not found\n");
      exit(1);
   }

   // lock...
   if (config->lockfile!=NULL && fexist(config->lockfile)) {
      f = fopen(config->lockfile, "rt");
      fscanf(f, "%lu\n", &pid);
      fclose(f);
      /* Checking process PID */
#ifdef __OS2__
      if (DosKillProcess(DKP_PROCESSTREE, pid) == ERROR_NOT_DESCENDANT) {
#elif UNIX
      if (kill(pid, 0) == 0) {
#else
      if (stat(config->lockfile, &stat_file) != -1) {
          time_cur = time(NULL);
	  locklife = (time_cur - stat_file.st_mtime)/60;
      }
      if (locklife < 180) {
#endif
           printf("lock file found! exit...\n");
           disposeConfig(config);
           exit(1);
      } else {
         remove(config->lockfile);
         createLockFile(config->lockfile);
      } /* endif */
   }
   else if (config->lockfile!=NULL) createLockFile(config->lockfile);
   

   // open Logfile
   hpt_log = NULL;
   if (config->logFileDir != NULL) {
     buff = (char *) malloc(strlen(config->logFileDir)+7+1); /* 7 for hpt.log */
     strcpy(buff, config->logFileDir),
     strcat(buff, "hpt.log");
     if (config->loglevels==NULL)                           
        hpt_log = openLog(buff, versionStr, "123456789", config->logEchoToScreen);
       else                                                 
        hpt_log = openLog(buff, versionStr, config->loglevels, config->logEchoToScreen);
   } else printf("You have no logFileDir in your config, there will be no log created");
   if (hpt_log==NULL) printf("Could not open logfile: %s\n", buff);
   writeLogEntry(hpt_log, '1', "Start");
   free(buff);

   if (config->addrCount == 0) printf("at least one addr must be defined\n");
   if (config->linkCount == 0) printf("at least one link must be specified\n");
   if (config->tempOutbound == NULL) printf("you must set tempOutbound in fidoconfig first\n");
   if (config->tempInbound == NULL) printf("you must set tempInbound in fidoconfig first\n");

   if (config->addrCount == 0 ||
       config->linkCount == 0 ||
       config->tempInbound == NULL ||
       config->tempOutbound == NULL) {
      if (config->lockfile != NULL) remove(config->lockfile);
      writeLogEntry(hpt_log, '9', "wrong config file");
      writeLogEntry(hpt_log, '1', "End");
      closeLog(hpt_log);
      disposeConfig(config);
      exit(1);
   }
}

int main(int argc, char **argv)
{
   struct _minf m;
   int i;
#if defined ( __WATCOMC__ ) && defined ( __NT__ )
   char title[ 256 ];
#endif

#ifdef __linux__
   sprintf(versionStr, "hpt %u.%u.%u/lnx $Date$", VER_MAJOR, VER_MINOR, VER_PATCH);
#elif __freebsd__
   sprintf(versionStr, "hpt %u.%u.%u/BSD", VER_MAJOR, VER_MINOR, VER_PATCH);
#elif __OS2__
    sprintf(versionStr, "hpt %u.%u.%u/OS2", VER_MAJOR, VER_MINOR, VER_PATCH);
#elif __NT__
    sprintf(versionStr, "hpt %u.%u.%u/NT", VER_MAJOR, VER_MINOR, VER_PATCH);
#elif __sun__
    sprintf(versionStr, "hpt %u.%u.%u/SUN", VER_MAJOR, VER_MINOR, VER_PATCH);
#else
    sprintf(versionStr, "hpt %u.%u.%u", VER_MAJOR, VER_MINOR, VER_PATCH);
#endif

   printf("Highly Portable Toss %u.%u.%u\n", VER_MAJOR, VER_MINOR, VER_PATCH);
#if defined ( __WATCOMC__ ) && defined ( __NT__ )
   sprintf( title, "Highly Portable Toss %u.%u.%u", VER_MAJOR, VER_MINOR, VER_PATCH);
   SetConsoleTitleA( title );
#endif
   initCharsets();

   if (processCommandLine(argc, argv)==1) exit(0);
   if (config==NULL) processConfig();

   // init SMAPI
   m.req_version = 0;
   m.def_zone = config->addr[0].zone;
   if (MsgOpenApi(&m) != 0) {
      writeLogEntry(hpt_log, '9', "MsgApiOpen Error");
          if (config->lockfile != NULL) remove(config->lockfile);
      closeLog(hpt_log);
      disposeConfig(config);
      exit(1);
   } /*endif */
   
   msgToSysop = (s_message**)calloc(config->addrCount, sizeof(s_message*));
   for (i = 0; i < config->addrCount; i++) {
	   
       /* Some results of wrong patching ? A memleak anyway
	* msgToSysop[i] = (s_message*)malloc(sizeof(s_message));
	*/
       msgToSysop[i] = NULL;
   }

   tossTempOutbound(config->tempOutbound);
   if (1 == cmToss) toss();
   if (cmToss == 2) tossFromBadArea();

   if (cmScan == 1) scanExport(SCN_ALL  | SCN_ECHOMAIL, NULL);
   if (cmScan &  2) scanExport(SCN_FILE | SCN_ECHOMAIL, scanParmF);
   if (cmScan &  4) scanExport(SCN_NAME | SCN_ECHOMAIL, scanParmA);
   if (cmAfix == 1) afix();
    
   if (cmPack == 1) scanExport(SCN_ALL  | SCN_NETMAIL, NULL);
   if (cmPack &  2) scanExport(SCN_FILE | SCN_NETMAIL, scanParmF);
   if (cmPack &  4) scanExport(SCN_NAME | SCN_NETMAIL, scanParmA);
   
   if (cmLink == 1) linkAreas();
   
   writeMsgToSysop();
   
   for (i = 0; i < config->addrCount; i++) {
       if (msgToSysop[i]) freeMsgBuffers(msgToSysop[i]);
       free(msgToSysop[i]);
   }
   free(msgToSysop);

   autoPassive();

   // deinit SMAPI
   MsgCloseApi();
   
   if (config->lockfile != NULL) remove(config->lockfile);
   writeLogEntry(hpt_log, '1', "End");
   closeLog(hpt_log);
   disposeConfig(config);
   doneCharsets();
   return 0;
}
