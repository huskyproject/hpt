/*****************************************************************************
 * Post for HPT (FTN NetMail/EchoMail Tosser)
 *****************************************************************************
 * Copyright (C) 1998-99
 *
 * Kolya Nesterov
 *
 * Fido:     2:463/7208.53
 * Kiev, Ukraine
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
/* Revision log:
   16.12.98 - first version, written at ~1:30, in the middle of doing 
              calculation homework on Theoretical Electrics, you understood ;)
   18.12.98 - woops forgot copyright notice, minor fixes
	      tearline generation added
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(MSDOS) || defined(__DJGPP__)
#include <fidoconfig.h>
#else
#include <fidoconf.h>
#endif
#include <common.h>

#include <version.h>
#include <toss.h>
#include <post.h>
#include <global.h>
#include <version.h>
#include <areafix.h>
#include <hpt.h>

void post(int c, unsigned int *n, char *params[])
{
   char *area = NULL;
   FILE *text = NULL;
   s_area *echo = NULL;
   FILE *f = NULL;
   long attr;
   
   s_message msg;

   UCHAR *textBuffer = NULL;

   int quit;
   int export=0;

   time_t t = time (NULL);
   struct tm *tm;

   if (config==NULL) processConfig();

   memset(&msg, 0, sizeof(s_message));

   for (quit = 0;*n < c && !quit; (*n)++) {
      if (*params[*n] == '-' && params[*n][1] != '\0') {
         switch(params[*n][1]) {
            case 'a':    // address
               switch(params[*n][2]) {
                  case 't':
                     string2addr(params[++(*n)], &(msg.destAddr));
                     break;
                  case 'f':
                     string2addr(params[++(*n)], &(msg.origAddr));
                     break;
                  default:
                     quit = 1;
                     break;
               }; break;
            case 'n':    // name
               switch(params[*n][2]) {
                  case 't':
                     msg.toUserName = (char *) malloc(strlen(params[++(*n)]) + 1);
                     strcpy(msg.toUserName, params[*n]);
                     break;
                  case 'f':
                     msg.fromUserName = (char *) malloc(strlen(params[++(*n)]) + 1);
                     strcpy(msg.fromUserName, params[*n]);
                     break;
                  default:
                     quit = 1;
                     break;
               }; break;
            case 'f':    // flags
	       while ((attr = str2attr(params[++(*n)])) != -1L) 
		       msg.attributes |= attr;
	       (*n)--;		       
               break;
            case 'e':    // echo name
               area = params[++(*n)];
               echo = getArea(config, area);
               break;
            case 's':    // subject
               msg.subjectLine = (char *) malloc(strlen(params[++(*n)]) + 1);
               strcpy(msg.subjectLine, params[*n]);
               break;
            case 'x':    // export message
               export=1; (*n)++;
               break;
	    default:
               fprintf(stderr, "hpt post: unknown switch %s\n", params[*n]);
               quit = 1;
               break;
         };
      } else if (textBuffer == NULL) {
	 if (strcmp(params[*n], "-"))
            text = fopen(params[*n], "rt");
         else
            text = stdin;
         if (text != NULL) {
            /* reserve 512kb + 1 (or 32kb+1) text Buffer */
            textBuffer = (UCHAR *) malloc(TEXTBUFFERSIZE+1); 
            for (msg.textLength = 0; msg.textLength < (long) TEXTBUFFERSIZE; msg.textLength++) {
               if ((textBuffer[msg.textLength] = getc(text)) == 0)
                  break;
               if (feof(text)) {
                  textBuffer[++msg.textLength] = 0;
                  break;
               }; /* endif */
               if ('\n' == textBuffer[msg.textLength])
                  textBuffer[msg.textLength] = '\r';
            }; /* endfor */
            textBuffer[msg.textLength-1] = 0;
            fclose(text);
         } else {
            fprintf(stderr, "hpt post: failed to open input file %s\n", params[*n]);
        };
      } else {
         fprintf(stderr, "hpt post: several input files on cmd line\n");
         quit = 1;
      };  
   };
   //msg.attributes |= MSGLOCAL; // Always set bit for LOCAL
   // won't be set in the msgbase, because the mail is processed if it were received
   (*n)--; tm = localtime(&t);
   strftime(msg.datetime, 21, "%d %b %y  %T", tm);
   if ((msg.destAddr.zone != 0 || area) && (textBuffer != NULL) && !quit) {
      // Dumbchecks
      if (msg.origAddr.zone == 0) // maybe origaddr isn't specified ?
         msg.origAddr = config->addr[0];
      if (msg.fromUserName == NULL)
          msg.fromUserName = strdup(config->sysop);
      if (msg.toUserName == NULL)
          msg.toUserName = strdup("All");
      if (msg.subjectLine == NULL)
          msg.subjectLine = strdup("");

      msg.netMail = area == NULL;
      /*FIXME*/
      if (msg.netMail) echo=&(config->netMailAreas[0]);

      /* reserve mem for the real text */
      /* !!! warning - I suppose that 512 bytes will be enough
      for kludges and tearline + origin */
      msg.text = (char *) malloc(msg.textLength + 1 + 512);
      createKludges(msg.text, area, &msg.origAddr, &msg.destAddr);

      strcat(msg.text, textBuffer);
      
      free(textBuffer);

      sprintf(msg.text + strlen(msg.text), "\r--- %s\r * Origin: %s (%s)",
              versionStr, config->name, aka2str(msg.origAddr));

      msg.textLength = strlen(msg.text);
      
      writeLogEntry (hpt_log, '1', "Start posting...");

      if (!export)
        putMsgInArea(echo, &msg, 1, msg.attributes);
      else {
        if (msg.netMail) 
	  processNMMsg(&msg, NULL, NULL, 0);
        else
          processEMMsg(&msg, msg.origAddr, 1);
      } 
    if (textBuffer == NULL) {
       fprintf(stderr, "hpt post: no input source specified\n");
    }
    if (msg.destAddr.zone == 0) {
       fprintf(stderr, "hpt post: attempt to post netmail msg without specifyng dest address\n");
    }
      writeLogEntry (hpt_log, '2', "Posting msg. from %u:%u/%u.%u -> %s in area: %s",
                  msg.origAddr.zone, msg.origAddr.net, msg.origAddr.node,
                  msg.origAddr.point, aka2str(msg.destAddr), area);
      
      if ((config->echotosslog) && (!export)) {
        f=fopen(config->echotosslog, "a");
      
        if (f==NULL)
          writeLogEntry (hpt_log, '9', "Could not open or create EchoTossLogFile.");
        else {
          fprintf(f,"%s\n",area);
          fclose(f);
        }
      }
      
   };
   freeMsgBuffers(&msg);
}
