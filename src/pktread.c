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
#include <stdlib.h>
#include <stdio.h>
#if !defined(__FreeBSD__)
#include <malloc.h>
#endif
#include <string.h>
#include <ctype.h>

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>

#include <log.h>
#include <global.h>

#include <pkt.h>
#include <xstr.h>

time_t readPktTime(FILE *pkt)
{
  struct tm time;

  time.tm_year  = getUINT16(pkt) - 1900; /* years since 1900 */
  time.tm_mon   = getUINT16(pkt);
  time.tm_mday  = getUINT16(pkt);
  time.tm_hour  = getUINT16(pkt);
  time.tm_min   = getUINT16(pkt);
  time.tm_sec   = getUINT16(pkt);
  time.tm_isdst = 0;                    /* disable daylight saving */

  return mktime(&time);
}

void readPktPassword(FILE *pkt, UCHAR *password)
{
   int i;

   for (i=0 ;i<8 ;i++ ) {
     password[i] = (UCHAR) getc(pkt); /* no EOF check :-( */
   } /* endfor */
   password[8] = 0;
}

s_pktHeader *openPkt(FILE *pkt)
{
  s_pktHeader *header;
  UINT16      pktVersion, capWord;

  header = (s_pktHeader *) calloc(1,sizeof(s_pktHeader));
  header->origAddr.node = getUINT16(pkt);
  header->destAddr.node = getUINT16(pkt);
  header->origAddr.domain = NULL;
  header->destAddr.domain = NULL;
  header->pktCreated = readPktTime(pkt); // 12 bytes

  getUINT16(pkt); /* read 2 bytes for the unused baud field */

  pktVersion = getUINT16(pkt);
  if (pktVersion != 2) {
    free(header);
    header = NULL;
    return NULL;
  } /* endif */

  header->origAddr.net = getUINT16(pkt);
  header->destAddr.net = getUINT16(pkt);
  
  header->loProductCode = (UCHAR) getc(pkt);
  header->majorProductRev = (UCHAR) getc(pkt);

  readPktPassword(pkt, (UCHAR *)header->pktPassword); // 8 bytes

  header->origAddr.zone = getUINT16(pkt);
  header->destAddr.zone = getUINT16(pkt);

  header->auxNet = getUINT16(pkt);

  header->capabilityWord = (UINT16)((fgetc(pkt) << 8) + fgetc(pkt));
  header->hiProductCode = (UCHAR) getc(pkt);
  header->minorProductRev = (UCHAR) getc(pkt);

  capWord = getUINT16(pkt);

  if (!config->ignoreCapWord) {
	  /* if both capabilitywords aren't the same, abort */
	  /* but read stone-age pkt */
	  if (capWord!=header->capabilityWord && header->capabilityWord!=0) {
		  free(header);
		  header = NULL;
		  return NULL;
	  } /* endif */
  }
  
  getUINT16(pkt); getUINT16(pkt); /* read the additional zone info */

  header->origAddr.point = getUINT16(pkt);
  header->destAddr.point = getUINT16(pkt);

  getUINT16(pkt); getUINT16(pkt); /* read ProdData */

  if (header->origAddr.net == 65535) {
	  if (header->origAddr.point) header->origAddr.net = header->auxNet;
	  else header->origAddr.net = header->destAddr.net; // not in FSC !
  }

  return header;
}

void correctEMAddr(s_message *msg)
{
   char *start = NULL, buffer[47];
   int i;

   start = strrstr(msg->text, " * Origin:");
   if (NULL != start) {
      while ((*(start) !='\r') && (*(start) != '\n')) start++;  // get to end of line

      if (*(start-1) == ')') {                        // if there is no ')', there is no origin
         while (*(--start)!='(');                     // find beginning '('
         start++;                                     // and skip it
         i=0;
   
         while ((*start != ')') && (*start != '\r') && (*start != '\n') && (i < 47)) {
	    if (isdigit(*start) || *start==':' || *start=='/' || *start=='.') {
	        buffer[i] = *start;
    		i++;
	    }
	    start++;
         } /* endwhile */
         buffer[i]   = '\0';
         string2addr(buffer, &(msg->origAddr));
      }
   } 
}

void correctNMAddr(s_message *msg, s_pktHeader *header)
{
   char *start, *copy, *text=NULL, buffer[35]; //FIXME: static buffer
   int valid_intl_kludge = 0;
   int zonegated = 0;
   s_addr intl_from, intl_to;
   int i;

   copy = buffer;
   start = strstr(msg->text, "FMPT");
   if (start) {
      start += 6;                  /* skip "FMPT " */
      while (isdigit(*start)) {     /* copy all digit data */
         *copy = *start;
         copy++;
         start++;
      } /* endwhile */
      *copy = '\0';                /* don't forget to close the string with 0 */

      msg->origAddr.point = atoi(buffer);
   } else {
      msg->origAddr.point = 0;
   } /* endif */

   /* and the same for TOPT */
   copy = buffer;
   start = strstr(msg->text, "TOPT");
   if (start) {
      start += 6;                  /* skip "TOPT " */
      while (isdigit(*start)) {     /* copy all digit data */
         *copy = *start;
         copy++;
         start++;
      } /* endwhile */
      *copy = '\0';                /* don't forget to close the string with 0 */

      msg->destAddr.point = atoi(buffer);
   } else {
      msg->destAddr.point = 0;
   } /* endif */

   /* Parse the INTL Kludge */

   start = strstr(msg->text, "INTL ");
   if (start) {
      
      start += 6;                 // skip "INTL "

      while(1)
      {
          while (*start && isspace(*start)) start++;
          if (!*start) break;

          copy = buffer;
          while (*start && !isspace(*start)) *copy++ = *start++;
          *copy='\0';
          if (strchr(start,':')==NULL || strchr(start,'/')==NULL) break;
          string2addr(buffer, &intl_to);
          
          while (*start && isspace(*start)) start++;
          if (!*start) break;

          copy = buffer;
          while (*start && !isspace(*start)) *copy++ = *start++;
          *copy='\0';
          if (strchr(start,':')==NULL || strchr(start,'/')==NULL) break;
          string2addr(buffer, &intl_from);

          intl_from.point = msg->origAddr.point;
          intl_to.point = msg->destAddr.point;

          valid_intl_kludge = 1;
      }
   }

   /* now interpret the INTL kludge */

   if (valid_intl_kludge)
   {
      /* the from part is easy - we can always use it */

      msg->origAddr.zone = intl_from.zone;
      msg->origAddr.net  = intl_from.net;
      msg->origAddr.node = intl_from.node;

      /* the to part is more complicated */

      zonegated = 0;

      if (msg->destAddr.net == intl_from.zone &&
          msg->destAddr.node == intl_to.zone)
      {
         zonegated = 1;

         /* we want to ignore the zone gating if we are the zone gate */

         for (i = 0; i < config->addrCount; i++)
         {
            if (config->addr[i].zone == msg->destAddr.net &&
                config->addr[i].net == msg->destAddr.net &&
                config->addr[i].node == msg->destAddr.node &&
                config->addr[i].point == 0)
            {
               zonegated = 0;
            }
         }
      }

      if (zonegated)
      {
         msg->destAddr.zone = intl_from.zone;
         msg->destAddr.net  = intl_from.zone;
         msg->destAddr.node = intl_to.zone;
      }
      else
      {
         msg->destAddr.zone = intl_to.zone;
         msg->destAddr.net  = intl_to.net;
         msg->destAddr.node = intl_to.node;
      }

   } else {
      
      /* no INTL kludge */

      msg->destAddr.zone = header->destAddr.zone;
      msg->origAddr.zone = header->origAddr.zone;

      xscatprintf(&text,"\1INTL %u:%u/%u %u:%u/%u\r",msg->destAddr.zone,msg->destAddr.net,
	      msg->destAddr.node,msg->origAddr.zone,msg->origAddr.net,msg->origAddr.node);
      xstrcat(&text,msg->text);
      free(msg->text);
      msg->text = text;
      msg->textLength=strlen(msg->text);
      
      writeLogEntry(hpt_log, '2', "Mail without INTL-Kludge. Assuming %i:%i/%i.%i -> %i:%i/%i.%i",
		    msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node, msg->origAddr.point,
		    msg->destAddr.zone, msg->destAddr.net, msg->destAddr.node, msg->destAddr.point);
   } /* endif */
}

void correctAddr(s_message *msg,s_pktHeader *header)
{
   if (strncmp(msg->text, "AREA:",5) != 0) {
      correctNMAddr(msg,header);
      msg->netMail = 1;
   } else {
      correctEMAddr(msg);
      msg->netMail = 0;
   } /* endif */
}

int correctDateTime(char *msgdate) {
    int dd, yy, mo, hh, mm, ss;
    char temp[22];
    
    if (sscanf(msgdate, "%d %s %d %d:%d:%d", &dd, temp, &yy, &hh, &mm, &ss) == 6)
	return 1;
    else if (sscanf(msgdate, "%d %s %d %d:%d", &dd, temp, &yy, &hh, &mm) == 5)
	return 1;
    else if (sscanf(msgdate, "%*s %d %s %d %d:%d", &dd, temp, &yy, &hh, &mm) == 5)
	return 1;
    else if (sscanf(msgdate, "%d/%d/%d %d:%d:%d", &mo, &dd, &yy, &hh, &mm, &ss) == 6)
	return 1;

    else return 0;
}

s_message *readMsgFromPkt(FILE *pkt, s_pktHeader *header)
{
   s_message *msg;
   UCHAR     *textBuffer;
   int       len;

   if (2 != getUINT16(pkt)) {
      return NULL;              /* no packed msg */
   } /* endif */

   msg = (s_message*) calloc(1,sizeof(s_message));
   if (msg==NULL) {
      return NULL;
   } /* endif */

   msg->origAddr.node   = getUINT16(pkt);
   msg->destAddr.node   = getUINT16(pkt);
   msg->origAddr.net    = getUINT16(pkt);
   msg->destAddr.net    = getUINT16(pkt);
   msg->attributes      = getUINT16(pkt);
   msg->origAddr.domain = NULL;
   msg->destAddr.domain = NULL;

   getc(pkt); getc(pkt);                // read unused cost fields (2bytes)

//   fgets(msg->datetime, 21, pkt);
   fgetsUntil0 (msg->datetime, 22, pkt);

   textBuffer = (UCHAR *) malloc(74);   // reserve mem space
   len = fgetsUntil0 ((UCHAR *) textBuffer, 37, pkt);
   msg->toUserName = (char *) malloc(len);
   strcpy((char *)msg->toUserName, (char *) textBuffer);

   len = fgetsUntil0((UCHAR *) textBuffer, 37, pkt);
   msg->fromUserName = (char *) malloc(len);
   strcpy((char *)msg->fromUserName, (char *) textBuffer);

   len = fgetsUntil0((UCHAR *) textBuffer, 73, pkt);
   msg->subjectLine = (char *) malloc(len);
   strcpy((char *)msg->subjectLine, (char *)textBuffer);

   free(textBuffer);                   // free mem space

   textBuffer = (UCHAR *) malloc(TEXTBUFFERSIZE+1); /* reserve 512kb + 1 (or 32kb+1) text Buffer */
   msg->textLength = fgetsUntil0((unsigned char *) textBuffer, TEXTBUFFERSIZE+1 , pkt);

   msg->text = (char *) malloc(msg->textLength); /* reserve mem for the real text */
   strcpy((char *)msg->text, (char *)textBuffer);

   free(textBuffer);

   correctAddr(msg, header);

   return msg;
}

void freeMsgBuffers(s_message *msg)
{
  if (msg->text) free(msg->text);
  free(msg->subjectLine);
  free(msg->toUserName);
  free(msg->fromUserName);
//  if (msg->destAddr.domain) free(msg->destAddr.domain);
  // do not free the domains of the adresses of the message, because they
  // come from fidoconfig structures and are needed more than once.
}

char *getKludge(s_message msg, char *what) {

    // taken from smapi
   
    char *end, *found, *out, *where = msg.text;

    found = NULL;

    if (where != NULL)
    {
        found = (char *) strstr((char *) where, (char *) what);
    }

    if (where != NULL && found != NULL && found[-1] == '\001')
    {
        end = (char *) strchr((char *) found, '\r');

        if (!end)
        {
            end = found + strlen((char *) found);
        }

        out = malloc((size_t) (end - found) + 1);
        if (out == NULL)
        {
            return NULL;
        }

        memmove(out, found, (size_t) (end - found));
        out[(size_t) (end - found)] = '\0';
        return out;
    }

    return NULL;
}
