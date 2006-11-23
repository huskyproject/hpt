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
#include <errno.h>

/* compiler.h */
#include <smapi/compiler.h>

#ifdef HAS_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAS_DOS_H
#include <dos.h>
#endif

#if defined(HAS_SYS_SYSEXITS_H)
#include <sys/sysexits.h>
#endif
#if defined(HAS_SYSEXITS_H)
#include <sysexits.h>
#endif

#if (defined(__EMX__) || defined(__MINGW32__)) && defined(__NT__)
/* we can't include windows.h to prevent type redefinitions ... */
#define CharToOem CharToOemA
#endif

/* smapi */
#include <smapi/progprot.h>

/*  fidoconf */
#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/xstr.h>
#include <fidoconf/afixcmd.h>
#include <fidoconf/recode.h>

/* hpt */
#include <global.h>
#include <pkt.h>
#include <version.h>
#include <cvsdate.h>

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
    char *textBuffer = NULL;
    char *versionStr=NULL;
    char *tmp=NULL;

    memset (&header,'\0',sizeof(s_pktHeader));
    memset (&msg,'\0',sizeof(s_message));

   if (argc == 1) {
      versionStr = GenVersionStr( "txt2pkt", VER_MAJOR, VER_MINOR, VER_PATCH,
                               VER_BRANCH, cvs_date );

      printf("%s\n\n", versionStr);

      printf("Usage: txt2pkt [options] <file>|-\n"
             "Options: -xf \"<arg>\" \t- packet from address\n"
             "\t -xt \"<arg>\" \t- packet to address\n"
             "\t -p  \"<arg>\" \t- packet password\n"
             "\t -af \"<arg>\" \t- message from address>\n"
             "\t -at \"<arg>\" \t- message to address\n"
             "\t -nf \"<arg>\" \t- message from name\n"
             "\t -nt \"<arg>\" \t- message to name\n"
             "\t -e  \"<arg>\" \t- message echo name\n"
             "\t -t  \"<arg>\" \t- message tearline\n"
             "\t -o  \"<arg>\" \t- message origin\n"
             "\t -s  \"<arg>\" \t- message subject\n"
             "\t -d  \"<path>\" \t- output directory\n");
      printf("\t <file> or -\t- text file to post. the '-' sign for standard input\n");
      exit(EX_OK);
   }

   for (; n < argc; n++) {
      if (*argv[n] == '-' && argv[n][1]) {
         switch(argv[n][1]) {
            case 'a':    /*  address */
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
            case 'x':    /*  address */
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
            case 'n':    /*  name */
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
            case 'e':    /*  echo name */
               area = argv[++n];
               break;
            case 'p':    /*  password */
               passwd = argv[++n];
               break;
            case 't':    /*  tearline */
               tearl = argv[++n];
#ifdef __NT__
               CharToOem(tearl, tearl);
#endif
               break;
            case 'o':    /*  origin */
               orig = argv[++n];
#ifdef __NT__
               CharToOem(orig, orig);
#endif
               break;
            case 'd':    /*  directory */
               dir = argv[++n];
               break;
            case 's':    /*  subject */
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
   if (text == NULL) {
	  fprintf(stderr,"Text file not specified, exit\n");
	  exit(EX_NOINPUT);
   }

   config = readConfig(NULL);
   if (NULL == config) {
      fprintf(stderr,"Config not found, exit\n");
      exit(EX_UNAVAILABLE);
   }


   header.hiProductCode  = HPT_PRODCODE_HIGHBYTE;
   header.loProductCode  = HPT_PRODCODE_LOWBYTE;
   header.majorProductRev = VER_MAJOR;
   header.minorProductRev = VER_MINOR;
   if (passwd!=NULL) strcpy(header.pktPassword, passwd);
   header.pktCreated = time(NULL);

   header.capabilityWord = 1;
   header.prodData = 0;

#ifdef __UNIX__
   xstrcat(&tmp, (dir) ? dir : "./");
   if (tmp[strlen(tmp)-1] != '/') xstrcat(&tmp,"/");
#else
   xstrcat(&tmp, (dir) ? dir : ".\\");
   if (tmp[strlen(tmp)-1] != '\\')  xstrcat(&tmp,"\\");
#endif
   { time_t tm = time(NULL);
     int pathlen = strlen(tmp);
     char* tmpp;
     xscatprintf(&tmp,"%08lx.pkt",(long)tm++);
     tmpp = tmp+pathlen;
     pkt = createPkt(tmp, &header);
     while(pkt==NULL){
       sprintf(tmpp,"%08lx.pkt",(long)tm++);
       pkt = createPkt(tmp, &header);
     }
   }

   if (header.origAddr.zone==0) header.origAddr = msg.origAddr;
   if (header.destAddr.zone==0) header.destAddr = msg.destAddr;


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
      msg.text = createKludges(config,
                               area, &msg.origAddr, &msg.destAddr,
                               versionStr);
      if (!config->disableTID)
         xscatprintf(&(msg.text), "\001TID: %s\r", versionStr);
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
      if (msg.subjectLine==NULL) xstrcat(&msg.subjectLine, "");

      /*  load recoding tables */
      initCharsets();
      if (config->outtab) getctab(outtab, (unsigned char*) config->outtab);
      if (config->intab) getctab(intab, (unsigned char*) config->intab);

      if (config->outtab != NULL) {
         /*  recoding text to TransportCharSet */
         recodeToTransportCharset((CHAR*)msg.text);
         recodeToTransportCharset((CHAR*)msg.subjectLine);
         recodeToTransportCharset((CHAR*)msg.fromUserName);
         recodeToTransportCharset((CHAR*)msg.toUserName);
      }

      writeMsgToPkt(pkt, msg);

      closeCreatedPkt(pkt);
/*      sleep(1); */
   } else {
      printf("Could not create pkt, error message: %s", strerror(errno));
   } /* endif */

   doneCharsets();
   disposeConfig(config);

   return 0;
}
