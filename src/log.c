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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <log.h>
#include <global.h>
#include <fcommon.h>

#include <fidoconf/xstr.h>
#include <smapi/prog.h>

static char *mnames[] = {
"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"
};
static char *wdnames[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};

#ifdef __MINGW32__
#ifdef open
#undef open
#endif
#endif

s_log *openLog(char *fileName, char *appN)
{
   s_log      *temp;

   temp = (s_log *) malloc(sizeof(s_log));
   memset(temp, '\0', sizeof(s_log));
   temp->logFile = fopen(fileName, "a");
   if (NULL == temp->logFile) {
      free(temp);
      return NULL;
   } /* endif */

   temp->open = 1;

   /* copy all informations */
   xstrcat(&temp->appName, appN);

   if (config->loglevels != NULL) 
	   xstrcat(&temp->keysAllowed, config->loglevels);
   else
	   xstrcat(&temp->keysAllowed, "123456789");

   if (config->screenloglevels != NULL) 
	   xstrcat(&temp->keysPrinted, config->screenloglevels);
   else
	   xstrcat(&temp->keysPrinted, "123456789");

   temp->firstLinePrinted=0;

   temp->logEcho = config->logEchoToScreen;

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
      free(hpt_log->keysPrinted);
      free(hpt_log);
      hpt_log = NULL;
   }
}

void writeLogEntry(s_log *hpt_log, char key, char *logString, ...)
{
	time_t     currentTime;
	struct tm  *locTime;
	va_list	   ap;
	UINT       log=0, screen=0;

	if (hpt_log) {
		if (hpt_log->open && strchr(hpt_log->keysAllowed, key)) log=1;
		if (hpt_log->logEcho && strchr(hpt_log->keysPrinted, key)) screen=1;
	}

	if (log || screen) {
		currentTime = time(NULL);
		locTime = localtime(&currentTime);

		if (log && !hpt_log->firstLinePrinted)	{
			/* make first line of log */
			fprintf(hpt_log->logFile, "----------  ");
			fprintf(hpt_log->logFile, "%3s %02u %3s %02u, %s\n",
					wdnames[locTime->tm_wday], locTime->tm_mday,
					mnames[locTime->tm_mon],locTime->tm_year%100,hpt_log->appName);
			hpt_log->firstLinePrinted=1;
		}

		if (log) {
			fprintf(hpt_log->logFile, "%c %02u.%02u.%02u  ",
					key, locTime->tm_hour, locTime->tm_min, locTime->tm_sec);
			va_start(ap, logString);
			vfprintf(hpt_log->logFile, logString, ap);
			va_end(ap);
			fputc('\n', hpt_log->logFile); 
			fflush(hpt_log->logFile);
		}

		if (screen) {
			fprintf(stdout, "%c %02u.%02u.%02u  ",
					key, locTime->tm_hour, locTime->tm_min, locTime->tm_sec);
			va_start(ap, logString);
			vfprintf(stdout, logString, ap);
			va_end(ap);
			fputc('\n', stdout);
		}
	}
}
