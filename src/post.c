/*:ts=8*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef MSDOS
#include <fidoconfig.h>
#else
#include <fidoconf.h>
#endif
#include <common.h>

#include <toss.h>
#include <post.h>
#include <global.h>

/* Warning : the code is totaly untested */

void post(int c, int *n, char *params[])
{
   char *area = NULL;
   FILE *text = NULL;

   s_message msg;

   CHAR *textBuffer = NULL;
   CHAR tmp[256];

   int quit;

   time_t t = time (NULL);
   struct tm *tm;

   memset(&msg, 0, sizeof(s_message));

   for (quit = 0;*n < c && !quit; (*n)++) {
      if (*params[*n] == '-') {
         switch(params[*n][1]) {
            case 'a':    // address
               switch(params[*n][2]) {
                  case 'd':
                     string2addr(params[++(*n)], &(msg.destAddr));
                     break;
                  case 'o':
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
               msg.attributes = atoi(params[++(*n)]) | 0x0100;
               // Always set bit for LOCAL
               break;
            case 'e':    // echo name
               area = params[++(*n)];
               break;
            case 's':    // subject
               msg.subjectLine = (char *) malloc(strlen(params[++(*n)]) + 1);
               strcpy(msg.subjectLine, params[*n]);
               break;
	    default:
               quit = 1;
               break;
         };
      } else {
         if ((text = fopen(params[*n], "rt")) != NULL) {
            /* reserve 512kb + 1 (or 32kb+1) text Buffer */
            textBuffer = (CHAR *) malloc(TEXTBUFFERSIZE+1); 
            for (msg.textLength = 0; msg.textLength < (long) TEXTBUFFERSIZE; msg.textLength++) {
               textBuffer[msg.textLength] = getc(text);
               if (feof(text)) {
                  textBuffer[++msg.textLength] = 0;
                  break;
               }; /* endif */
               if (0 == textBuffer[msg.textLength]) break;
               if ('\n' == textBuffer[msg.textLength])
                  textBuffer[msg.textLength] = '\r';
            }; /* endfor */
            textBuffer[msg.textLength] = 0;
            fclose(text);
         };
      };  
   };
   (*n)--; tm = gmtime(&t);
   strftime(msg.datetime, 21, "%d %b %y  %T", tm);
   if ((msg.destAddr.zone != 0) && (textBuffer != NULL)) { 
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

      createKludges(tmp, area, &msg.origAddr, &msg.destAddr);

      /* reserve mem for the real text */
      msg.text = (CHAR *) malloc(msg.textLength + strlen(tmp) + 1);
      strcpy(msg.text, tmp);
      strcat(msg.text, textBuffer);
      msg.textLength += strlen(tmp);
      free(textBuffer);

      if (msg.netMail)
         processNMMsg(&msg, msg.origAddr);
      else
         processEMMsg(&msg, msg.origAddr);
   };
   freeMsgBuffers(&msg);
}