/*****************************************************************************
 * Posting text files to pkt.
 *****************************************************************************
 * (c) 1999-2002 Husky team
 *
 * This file is part of HPT, part of Husky project.
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
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA
 * or download it from http://www.gnu.org site.
 *****************************************************************************
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef UNIX
#include <sysexits.h>
#endif

#if !defined (__TURBOC__) && !(defined(_MSC_VER) && (_MSC_VER >= 1200))
#include <unistd.h>
#else
#include <dos.h>
#endif

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/xstr.h>
#include <fidoconf/afixcmd.h>

#include <global.h>
#include <version.h>
#include <pkt.h>
#include <fidoconf/recode.h>
#include <smapi/progprot.h>

#if (defined (__WATCOMC__) && defined (__NT__)) || defined(__TURBOC__)
#include <dos.h>
#endif

#if (defined(__EMX__) || defined(__MINGW32__)) && defined(__NT__)
/* we can't include windows.h for several reasons ... */
#ifdef __MINGW32__
int __stdcall CharToOemA(char *, char *);
#endif
#define CharToOem CharToOemA
#endif

int main(int argc, char *argv[])
{
    s_pktHeader  header;
    s_message    msg;
    FILE         *pkt;
    time_t       t;
    struct tm    *tm;
    char *area = NULL, *passwd = NULL, *tearl = NULL, *orig = NULL, *dir = NULL;
    FILE *text = NULL;
    int quit=0, n = 1;
    CHAR *textBuffer = NULL;
    char *tmp=NULL;

    memset (&header,'\0',sizeof(s_pktHeader));
    memset (&msg,'\0',sizeof(s_message));

   if (argc == 1) {
      printf( "\nUsage:\n"
              "txt2pkt [-xf \"<pkt from address>\"] [-xt \"<pkt to address>\"]"
              " [-af \"<from address>\"] [-at \"<to address>\"]"
              " [-nf \"<from name>\"] [-nt \"<to name>\"] [-e \"echo name\"]"
              " [-p \"password\"] [-t \"tearline\"] [-o \"origin\"]"
              " [-s \"subject\"] [-d \"<directory>\"] (<text file>|-)\n" );
      exit(EX_OK);
   }

   for (; n < argc; n++) {
      if (*argv[n] == '-' && argv[n][1]) {
         switch(argv[n][1]) {
            case 'a':    // address
               switch(argv[n][2]) {
                  case 'f':
                     string2addr(argv[++n], &(msg.origAddr));
                     break;
                  case 't':
                     string2addr(argv[++n], &(msg.destAddr));
                     break;
                  default:
                     quit = 1;
                     break;
               } 
               break;
            case 'x':    // address
               switch(argv[n][2]) {
                  case 'f':
                     string2addr(argv[++n], &(header.origAddr));
                     break;
                  case 't':
                     string2addr(argv[++n], &(header.destAddr));
                     break;
                  default:
                     quit = 1;
                     break;
               } 
               break;
            case 'n':    // name
               switch(argv[n][2]) {
                  case 't':
                     msg.toUserName = (char *) safe_malloc(strlen(argv[++n]) + 1);
                     strcpy(msg.toUserName, argv[n]);
#ifdef __NT__
                     CharToOem(msg.toUserName, msg.toUserName);
#endif
                     break;
                  case 'f':
                     msg.fromUserName = (char *) safe_malloc(strlen(argv[++n]) + 1);
                     strcpy(msg.fromUserName, argv[n]);
#ifdef __NT__
                     CharToOem(msg.fromUserName, msg.fromUserName);
#endif
                     break;
                  default:
                     quit = 1;
                     break;
               }
               break;
            case 'e':    // echo name
               area = argv[++n];
               break;
            case 'p':    // password
               passwd = argv[++n];
               break;
            case 't':    // tearline
               tearl = argv[++n];
#ifdef __NT__
               CharToOem(tearl, tearl);
#endif
               break;
            case 'o':    // origin
               orig = argv[++n];
#ifdef __NT__
               CharToOem(orig, orig);
#endif
               break;
            case 'd':    // directory
               dir = argv[++n];
               break;
            case 's':    // subject
               msg.subjectLine = (char *) safe_malloc(strlen(argv[++n]) + 1);
               strcpy(msg.subjectLine, argv[n]);
#ifdef __NT__
               CharToOem(msg.subjectLine, msg.subjectLine);
#endif
               break;
	    default:
               quit = 1;
               break;
         }
         if (quit) {
            fprintf(stderr,"Unknown option '%s', exit.\n", argv[n]);
            nfree(msg.fromUserName);
            nfree(msg.toUserName);
            nfree(msg.subjectLine);
            exit(EX_USAGE);
         }
      } else {
         if (strcmp(argv[n], "-") == 0)
            text = stdin;
         else
            text = fopen(argv[n], "rt");

         if (text != NULL) {
            int cursize = TEXTBUFFERSIZE, c;
            /* reserve 512kb + 1 (or 32kb+1) text Buffer */
            textBuffer = safe_malloc(cursize);
            for (msg.textLength = 0;; msg.textLength++) {
                if (msg.textLength >= cursize)
                    textBuffer = safe_realloc(textBuffer, cursize += TEXTBUFFERSIZE);
                c = getc(text);
                if (c == EOF || c == 0) {
                    textBuffer[msg.textLength] = 0;
                    break;
                }
                textBuffer[msg.textLength] = (char)c;
                if ('\r' == textBuffer[msg.textLength])
                    msg.textLength--;
                if ('\n' == textBuffer[msg.textLength])
                    textBuffer[msg.textLength] = '\r';
            } /* endfor */
            while (!feof(text))
                getc(text);
            if (strcmp(argv[n], "-"))
            fclose(text);
         } else {
	    fprintf(stderr,"Text file not found, exit\n");
	    exit(EX_NOINPUT);
	 }
      }
   }

   config = readConfig(NULL);
   if (NULL == config) {
      fprintf(stderr,"Config not found, exit\n");
      exit(EX_UNAVAILABLE);
   }


   header.hiProductCode  = 0;
   header.loProductCode  = 0xfe;
   header.majorProductRev = 0;
   header.minorProductRev = 26;
   if (passwd!=NULL) strcpy(header.pktPassword, passwd);
   header.pktCreated = time(NULL);

   header.capabilityWord = 1;
   header.prodData = 0;

#ifdef UNIX
   xstrcat(&tmp, (dir) ? dir : "./");
   if (tmp[strlen(tmp)-1] != '/') xstrcat(&tmp,"/");
#else
   xstrcat(&tmp, (dir) ? dir : ".\\");
   if (tmp[strlen(tmp)-1] != '\\')  xstrcat(&tmp,"\\");
#endif
   xscatprintf(&tmp,"%08lx.pkt",(long)time(NULL));

   if (header.origAddr.zone==0) header.origAddr = msg.origAddr;
   if (header.destAddr.zone==0) header.destAddr = msg.destAddr;

   pkt = createPkt(tmp, &header);

   if (pkt != NULL) {

      msg.attributes = 1;

      t = time (NULL);
      tm = localtime(&t);
      fts_time((char *)msg.datetime, tm);

      msg.netMail = 1;

      if (tearl || config->tearline) {
         *tmp='\0';
         xscatprintf(&tmp, "\r--- %s\r", (tearl) ? tearl : config->tearline);
         xstrcat(&textBuffer, tmp);
      }

      if (msg.origAddr.zone==0 && msg.origAddr.net==0 && 
           msg.origAddr.node==0 && msg.origAddr.point==0)
	   msg.origAddr = config->addr[0];

      if (area != NULL) {
         *tmp='\0';
         strUpper(area);
         xscatprintf(&tmp, " * Origin: %s (%d:%d/%d.%d)\r",
                 (orig) ? orig : (config->origin) ? config->origin : "",
		 msg.origAddr.zone, msg.origAddr.net,
                 msg.origAddr.node, msg.origAddr.point);
         xstrcat(&textBuffer, tmp);
         *tmp='\0';
         xscatprintf(&tmp,"SEEN-BY: %d/%d\r\1PATH: %d/%d\r",
	         header.origAddr.net,header.origAddr.node,
		 header.origAddr.net,header.origAddr.node);
         xstrcat(&textBuffer, tmp);
      }
      xstrcat(&versionStr,"txt2pkt");
      msg.text = createKludges(config->disableTID,
                               area, &msg.origAddr, &msg.destAddr,
                               versionStr);
      xstrcat(&(msg.text), textBuffer);
      if (area == NULL) {
         time(&t);
         tm = gmtime(&t);
         xscatprintf(&(msg.text), "\001Via %u:%u/%u.%u @%04u%02u%02u.%02u%02u%02u.UTC %s\r",
                 header.origAddr.zone, header.origAddr.net, header.origAddr.node, header.origAddr.point,
                 tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, versionStr);
      }
      
      msg.textLength=strlen(textBuffer);
      nfree(textBuffer);
      nfree(versionStr);

      if (msg.fromUserName==NULL) xstrcat(&msg.fromUserName, "Sysop");
      if (msg.toUserName==NULL)  xstrcat(&msg.toUserName, "All");
      if (msg.subjectLine==NULL) xstrcat(&msg.subjectLine, "(none)");

      // load recoding tables
      initCharsets();
      if (config->outtab) getctab(outtab, (unsigned char*) config->outtab);
      if (config->intab) getctab(intab, (unsigned char*) config->intab);

      if (config->outtab != NULL) {
         // recoding text to TransportCharSet
         recodeToTransportCharset((CHAR*)msg.text);
         recodeToTransportCharset((CHAR*)msg.subjectLine);
         recodeToTransportCharset((CHAR*)msg.fromUserName);
         recodeToTransportCharset((CHAR*)msg.toUserName);
      }

      writeMsgToPkt(pkt, msg);

      closeCreatedPkt(pkt);
      sleep(1);
   } else {
      printf("Could not create pkt");
   } /* endif */

   doneCharsets();
   disposeConfig(config);

   return 0;
}
