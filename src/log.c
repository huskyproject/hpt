/*****************************************************************************
 * HTICK --- FTN Ticker / Request Processor
 *****************************************************************************
 * Copyright (C) 1999 by
 *
 * Gabriel Plutzar
 *
 * Fido:     2:31/1
 * Internet: gabriel@hit.priv.at
 *
 * Vienna, Austria, Europe
 *
 * This file is part of HTICK, which is based on HPT by Matthias Tichy, 
 * 2:2432/605.14 2:2433/1245, mtt@tichy.de
 *
 * HTICK is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * HTICK is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with HTICK; see the file COPYING.  If not, write to the Free
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *****************************************************************************/

#include <time.h>
#include <stdlib.h>
#include <string.h>

#include <log.h>
#include <fidoconfig.h>
#include <global.h>
#include <fcommon.h>
#include <prog.h>

s_log *openLog(char *fileName, char *appN, char *keys, unsigned int echoLog)
{
   s_log      *temp;

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

   temp->firstLinePrinted=0;

   temp->logEcho = echoLog;

   return temp;
}

void closeLog(s_log *hpt_log)
{
   if (hpt_log != NULL) {
      if (hpt_log->open != 0) {
         if (hpt_log->firstLinePrinted)
            fprintf(hpt_log->logFile, "\n");
         fclose(hpt_log->logFile);
         hpt_log->open = 0;
      } /* endif */
      free(hpt_log->appName);
      free(hpt_log->keysAllowed);
      free(hpt_log);
      hpt_log = NULL;
   }
}

void writeLogEntry(s_log *hpt_log, char key, char *logString)
{
   time_t     currentTime;
   struct tm  *locTime;

   if (NULL != hpt_log) {
     if (0 != hpt_log->open && NULL != strchr(hpt_log->keysAllowed, key)) 
        {
        if (!hpt_log->firstLinePrinted)
           {
           /* make first line of log */
           fprintf(hpt_log->logFile, "----------  ");

           currentTime = time(NULL);
           locTime = localtime(&currentTime);
           switch (locTime->tm_wday) {
           case 0: fprintf(hpt_log->logFile, "Sun");
              break;
           case 1: fprintf(hpt_log->logFile, "Mon");
              break;
           case 2: fprintf(hpt_log->logFile, "Tue");
              break;
           case 3: fprintf(hpt_log->logFile, "Wed");
              break;
           case 4: fprintf(hpt_log->logFile, "Thu");
              break;
           case 5: fprintf(hpt_log->logFile, "Fri");
              break;
           case 6: fprintf(hpt_log->logFile, "Sat");
              break;
           default:
             break;
           } /* endswitch */

           fprintf(hpt_log->logFile, " %2u ", locTime->tm_mday);

           switch (locTime->tm_mon) {
           case 0: fprintf(hpt_log->logFile, "Jan");
              break;
           case 1: fprintf(hpt_log->logFile, "Feb");
              break;
           case 2: fprintf(hpt_log->logFile, "Mar");
              break;
           case 3: fprintf(hpt_log->logFile, "Apr");
              break;
           case 4: fprintf(hpt_log->logFile, "May");
              break;
           case 5: fprintf(hpt_log->logFile, "Jun");
              break;
           case 6: fprintf(hpt_log->logFile, "Jul");
              break;
           case 7: fprintf(hpt_log->logFile, "Aug");
              break;
           case 8: fprintf(hpt_log->logFile, "Sep");
              break;
           case 9: fprintf(hpt_log->logFile, "Oct");
              break;
           case 10: fprintf(hpt_log->logFile, "Nov");
              break;
           case 11: fprintf(hpt_log->logFile, "Dec");
              break;
           default:
             break;
           } /* endswitch */

           fprintf(hpt_log->logFile, " %02u, %s\n", locTime->tm_year % 100,
                   hpt_log->appName);

           hpt_log->firstLinePrinted=1;
           }

        currentTime = time(NULL);
        locTime = localtime(&currentTime);
        fprintf(hpt_log->logFile, "%c %02u.%02u.%02u  %s\n", key, locTime->tm_hour, locTime->tm_min, locTime->tm_sec, logString);
        fflush(hpt_log->logFile);
		if (hpt_log->logEcho) fprintf(stdout, "%c %02u.%02u.%02u  %s\n", key, locTime->tm_hour, locTime->tm_min, locTime->tm_sec, logString);
     } /* endif */
   } /* endif */
}
