#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <msgapi.h>

#include <version.h>
#include <pkt.h>
#include <fidoconfig.h>
#include <log.h>

#include <global.h>
#include <hpt.h>
#include <toss.h>
#include <scan.h>

void processCommandLine(int argc, char **argv)
{
   int i = 0;

   if (argc == 1) {
      printf("\nUsage:\n");
      printf("   hpt toss - tossing mail\n");
      printf("   hpt scan - scaning mail\n");
   }

   while (i < argc-1) {
      i++;
      if (0 == strcmp(argv[i], "toss")) {
         cmToss = 1;
         continue;
      } else if (strcmp(argv[i], "scan") == 0) {
         cmScan = 1;
         continue;
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

   // open Logfile
   buff = (char *) malloc(strlen(config->logFileDir)+7+1); // 7 for hpt.log
   strcpy(buff, config->logFileDir),
   strcat(buff, "hpt.log");
   log  = openLog(buff, versionStr, "123456789");
   if (log==NULL) printf("Could not open logfile: %s\n", buff);
   writeLogEntry(log, '1', "Start");

   if (0 == config->addrCount) {
      printf("at least one addr must be defined\n");
      exit(1);
   } /* endif */

   if (config->linkCount == 0) {
      printf("at least one link must be specified\n");
      exit(1);
   } /* endif */

   if (config->routeCount == 0) {
      printf("at least one route must be specified\n");
      exit(1);
   }
}

int main(int argc, char **argv)
{
   struct _minf m;

   sprintf(versionStr, "hpt v%u.%02u", VER_MAJOR, VER_MINOR);

   printf("High Portable Toss v%u.%02u\n", VER_MAJOR, VER_MINOR);

   processCommandLine(argc, argv);
   processConfig();

   // init SMAPI
   m.req_version = 0;
   m.def_zone = config->addr[0].zone;
   if (MsgOpenApi(&m) != 0) {
      writeLogEntry(log, '9', "MsgApiOpen Error");
      closeLog(log);
      disposeConfig(config);
      exit(1);
   } /*endif */

   if (1 == cmToss) toss();
   if (cmScan == 1) scan();

   // deinit SMAPI
   MsgCloseApi();

   writeLogEntry(log, '1', "End");
   closeLog(log);
   disposeConfig(config);
   return 0;
}
