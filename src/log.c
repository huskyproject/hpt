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
#include <stdlib.h>
#include <string.h>

#include <log.h>

s_log *openLog(char *fileName, char *appN, char *keys)
{
   s_log      *temp;
   time_t     currentTime;
   struct tm  *locTime;

   temp = (s_log *) malloc(sizeof(s_log));
   temp->logFile = fopen(fileName, "a");
   if (NULL == temp->logFile) {
      free(temp);
      return NULL;
   } /* endif */

   temp->open = 1;

   /* copy all informations */
   temp->appName = (char *) malloc (strlen(appN)+1);
   strcpy(temp->appName, appN);

   temp->keysAllowed = (char *) malloc (strlen(keys)+1);
   strcpy(temp->keysAllowed, keys);

   /* make first line of log */
   fprintf(temp->logFile, "----------  ");

   currentTime = time(NULL);
   locTime = localtime(&currentTime);
   switch (locTime->tm_wday) {
   case 0: fprintf(temp->logFile, "Sun");
      break;
   case 1: fprintf(temp->logFile, "Mon");
      break;
   case 2: fprintf(temp->logFile, "Tue");
      break;
   case 3: fprintf(temp->logFile, "Wed");
      break;
   case 4: fprintf(temp->logFile, "Thu");
      break;
   case 5: fprintf(temp->logFile, "Fri");
      break;
   case 6: fprintf(temp->logFile, "Sat");
      break;
   default:
     break;
   } /* endswitch */

   fprintf(temp->logFile, " %2u ", locTime->tm_mday);

   switch (locTime->tm_mon) {
   case 0: fprintf(temp->logFile, "Jan");
      break;
   case 1: fprintf(temp->logFile, "Feb");
      break;
   case 2: fprintf(temp->logFile, "Mar");
      break;
   case 3: fprintf(temp->logFile, "Apr");
      break;
   case 4: fprintf(temp->logFile, "May");
      break;
   case 5: fprintf(temp->logFile, "Jun");
      break;
   case 6: fprintf(temp->logFile, "Jul");
      break;
   case 7: fprintf(temp->logFile, "Aug");
      break;
   case 8: fprintf(temp->logFile, "Sep");
      break;
   case 9: fprintf(temp->logFile, "Oct");
      break;
   case 10: fprintf(temp->logFile, "Nov");
      break;
   case 11: fprintf(temp->logFile, "Dec");
      break;
   default:
     break;
   } /* endswitch */

   fprintf(temp->logFile, " %02u, %s\n", locTime->tm_year % 100, appN);
   return temp;
}

void closeLog(s_log *log)
{
   if (log != NULL) {
      if (log->open != 0) {
         fprintf(log->logFile, "\n");
         fclose(log->logFile);
         log->open = 0;
      } /* endif */
      free(log->appName);
      free(log->keysAllowed);
      free(log);
      log = NULL;
   }
}

void writeLogEntry(s_log *log, char key, char *logString)
{
   time_t     currentTime;
   struct tm  *locTime;
   if (NULL != log) {
     if ((0 != log->open) && (NULL != strchr(log->keysAllowed, key))) {
        currentTime = time(NULL);
        locTime = localtime(&currentTime);
        fprintf(log->logFile, "%c %02u.%02u.%02u  %s\n", key, locTime->tm_hour, locTime->tm_min, locTime->tm_sec, logString);
        fflush(log->logFile);
     } /* endif */
   } /* endif */
}
