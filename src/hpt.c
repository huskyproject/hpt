#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <msgapi.h>

#include <version.h>
#include <pkt.h>
#include <config.h>
#include <log.h>

#include <global.h>
#include <hpt.h>
#include <toss.h>
#include <scan.h>

void getConfigPaths(char *def, char **data)
{
   char *buff;
//   wordexp_t word;

   buff = getConfigEntry(config, def, FIRST);
   if (NULL != buff) {
/*      #ifdef UNIX
      if (wordexp(buff, &word, 0) == 0) {
         buff = word.we_wordv[0];
         wordfree(&word);
      }
      #endif*/
      #ifdef UNIX
      if (buff[strlen(buff)-1] != '/') {
      #else
      if (buff[strlen(buff)-1] != '\\') {
      #endif
         *data = (char *) malloc(strlen(buff)+2);
         strcpy(*data, buff);
         #ifdef UNIX
         strcat(*data, "/");
         #else
         strcat(*data, "\\");
         #endif
      } else {
         *data = (char *) malloc(strlen(buff)+1);
         strcpy(*data, buff);
      } /* endif */
   } else {
      printf("%s not defined\n",def);
      exit(1);
   } /* endif */
}

s_link *getLink(char *str)
{
   UINT   i;
   s_addr aka;

   string2addr(str, &aka);
   for (i=0;i<linkCount;i++)
      if (addrComp(aka, links[i].hisAka)==0) return &(links[i]);
   return NULL;
}

int existAddr(s_addr aka)
{
   UINT i;

   for (i=0; i<addrCount; i++) {
      if(addrComp(aka, addr[i])==0) return 1;
   }
   return 0;
}

void parseAreaString(char *str, s_area *area)
{
   char   *token;
   s_link *link;

   area->downlinkCount = 0;
   area->msgbType = MSGTYPE_SDM;
   area->useAka = addr[0];
   // get filename
   token = strtok(str, " ÿ\t");
   if (token != NULL) {
      // get areaname
      area->name     = (char *) malloc(strlen(token)+1);
      token = strUpper(token);
      strcpy(area->name, token);

      token = strtok(NULL, " ÿ\t");
      if (token != NULL) {
         area->filename = (char *) malloc(strlen(token)+1);
         strcpy(area->filename, token);
      }
      while ((token = strtok(NULL, " ÿ\t")) != NULL) {

        // if we find "Squish" the area is a Squish type msgbase
        if (stricmp(token, "Squish")==0) area->msgbType = MSGTYPE_SQUISH;

        // if first character is a digit, then this is the address of an downlink
        if (isdigit(token[0]) != 0) {
           // get mem for an additional s_addr
           link = getLink(token);
           if (link != NULL) {
              area->downlinks = (s_link **) realloc(area->downlinks, (++area->downlinkCount) * (sizeof (s_link*)));
              area->downlinks[area->downlinkCount-1] = link;
           } else {
              printf("Link %s not found\n", token);
              exit(1);
           } /* endif */
           
        } /* endif */

        if (strcmp(token, "aka")==0) {
           token = strtok(str, " \xfe\t");
           string2addr(token, &(area->useAka));
           if (existAddr(area->useAka)!=0) area->useAka = addr[0];
        }

      }/* endwhile */
   } /* endif */
}

void parseRouteStatement(char *buff, s_route *route)
{
   char   *token;
   s_link *link;

   token = strtok(buff, " \xfe\t");
   if (token != NULL) {
      link = getLink(token);
      if (link != NULL) {
         route->link = link;
         token = strtok(NULL, " \xfe\t");
         route->pattern = (char *) malloc(strlen(token)+1);
         strcpy(route->pattern, token);
      } else {
         printf("Link %s not found\n", buff);
         exit(1);
      }
   } /* endif */
}

void getAreas(void)
{
   char *buff;
   UINT i;

   // get NetmailArea
   buff = getConfigEntry(config, "NetmailArea", FIRST);
   parseAreaString(buff, &netArea);

   // get DupeArea
   buff = getConfigEntry(config, "DupeArea", FIRST);
   parseAreaString(buff, &dupeArea);

   // get BadArea
   buff = getConfigEntry(config, "BadArea", FIRST);
   parseAreaString(buff, &badArea);

   // reserve mem for EchoAreas
   echoAreaCount = getConfigEntryCount(config, "EchoArea");
   echoAreas = (s_area *) malloc(echoAreaCount * sizeof (s_area));
   // get first EchoArea
   buff = getConfigEntry(config, "EchoArea", FIRST);
   parseAreaString(buff, &(echoAreas[0]));
   // get the rest
   for (i=1;i<echoAreaCount;i++) {
      buff = getConfigEntry(config, "EchoArea", NEXT);
      parseAreaString(buff, &(echoAreas[i]));
   } /* endfor */
}

void parseLinkStatement(char *buff, s_link *link)
{
   char *token;

   link->pktFile = NULL;

   token = strtok(buff, " ÿ\t");
   if (token != NULL) {
      string2addr(token, &(link->hisAka));
      token = strtok(NULL, " ÿ\t");
      if (token != NULL) {
         string2addr(token, &(link->ourAka));
         if (existAddr(link->ourAka)==0) {
            printf("Link: %s not our aka", token);
            exit(1);
         }
         token = strtok(NULL, " \xfe\t");
         if (token != NULL) {
            strncpy(link->pwd, token, 8);
            link->pwd[8] = '\0';
         } /* endif */
         else printf("Error in Linkstatement\n");
      } /* endif */
      else printf("Error in Linkstatement\n");
   }  /* endif */
   else printf("Error in Linkstatement\n");
}

void processCommandLine(int argc, char **argv)
{
   int i = 0;

   while (i < argc-1) {
      i++;
      if (0 == strcmp(argv[i], "-c")) {                   // new configFile
         i++;
         configFile = (char *) malloc (strlen(argv[i]));  // copy configFile
         strcpy(configFile, argv[i]);
         continue;
      } /* endif */
      if (0 == strcmp(argv[i], "toss")) {
         cmToss = 1;
         continue;
      } /* endif */
      if (strcmp(argv[i], "scan") == 0) {
         cmScan = 1;
         continue;
      } /* endif */
   } /* endwhile */
}

void processConfig()
{
   char *buff;

   if (NULL != configFile) {                    // if -c option used
      config = openConfig(configFile);          // load configFile
   } else {                                     // else
      config = openConfig("hpt.cfg");           // try .\hpt.cfg
   } /* endif */
   if (NULL == config) {
      printf("Config not found\n");
      exit(1);
   }

   // read Logfile
   buff = getConfigEntry(config, "LogFile", FIRST);
   log  = openLog(buff, versionStr, "123456789");
   writeLogEntry(log, '1', "Start");

   // read Address statements.
   addr = (s_addr *) malloc(sizeof(s_addr) * getConfigEntryCount(config, "Addr"));

   buff = getConfigEntry(config, "Addr", FIRST);
   addrCount = 0;
   while (NULL != buff) {
      string2addr(buff, &(addr[addrCount]));
      addrCount++;
      buff = getConfigEntry(config, "Addr", NEXT);
   }  /* endWhile */
   if (0 == addrCount) {
      printf("at least one addr must be defined\n");
      exit(1);
   } /* endif */

   // read links
   links = (s_link *) malloc(sizeof(s_link) * getConfigEntryCount(config, "Link"));
   buff = getConfigEntry(config, "Link", FIRST);
   linkCount = 0;
   while (buff != NULL) {
      parseLinkStatement(buff, &(links[linkCount]));
      linkCount++;
      buff = getConfigEntry(config, "Link", NEXT);
   } /* endwhile */
   if (linkCount == 0) {
      printf("at least one link must be specified\n");
      exit(1);
   } /* endif */

   // read routes
   routes = (s_route *) malloc(sizeof(s_route) * getConfigEntryCount(config, "Route"));
   buff = getConfigEntry(config, "Route", FIRST);
   routeCount = 0;
   while (buff != NULL) {
      parseRouteStatement(buff, &(routes[routeCount]));
      routeCount++;
      buff = getConfigEntry(config, "Route", NEXT);
   } /* endwhile */
   if (routeCount == 0) {
      printf("at least one route must be specified\n");
      exit(1);
   }

   // read dirs
   getConfigPaths("InboundDir", &inboundDir);
   getConfigPaths("InboundDirSec", &inboundDirSec);
   getConfigPaths("OutboundDir", &outboundDir);

   getAreas();
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
   m.def_zone = addr[0].zone;
   if (MsgOpenApi(&m) != 0) {
      writeLogEntry(log, '9', "MsgApiOpen Error");
      closeLog(log);
      freeConfig(config);
      exit(1);
   } /*endif */

   if (1 == cmToss) toss();
   if (cmScan == 1) scan();

   // deinit SMAPI
   MsgCloseApi();

   writeLogEntry(log, '1', "End");
   closeLog(log);
   freeConfig(config);
   return 0;
}
