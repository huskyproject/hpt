/*:ts=8*/
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


#include <fidoconfig.h>
#include <common.h>

#include <log.h>
#include <global.h>

#include <pkt.h>

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
     password[i] = getc(pkt);
   } /* endfor */
   password[8] = 0;
}

s_pktHeader *openPkt(FILE *pkt)
{
  s_pktHeader *header;
  UINT16      pktVersion, capWord;

  header = (s_pktHeader *) malloc(sizeof(s_pktHeader));
  header->origAddr.node = getUINT16(pkt);
  header->destAddr.node = getUINT16(pkt);
  header->origAddr.domain = NULL;
  header->destAddr.domain = NULL;
  header->pktCreated = readPktTime(pkt);

  getc(pkt); getc(pkt); /* read 2 bytes for the unused baud field */

  pktVersion = getUINT16(pkt);
  if (pktVersion != 2) {
    free(header);
    header = NULL;
    return NULL;
  } /* endif */

  header->origAddr.net = getUINT16(pkt);
  header->destAddr.net = getUINT16(pkt);
  if (header->origAddr.net == 65535) header->origAddr.net = header->destAddr.net; // bugfix for some braindead point software
  
  header->loProductCode = getc(pkt);
  header->majorProductRev = getc(pkt);

  readPktPassword(pkt, (UCHAR *)header->pktPassword);

  header->origAddr.zone = getUINT16(pkt);
  header->destAddr.zone = getUINT16(pkt);

  getc(pkt); getc(pkt); /* read 2 fill bytes */

  header->capabilityWord = fgetc(pkt) * 256 + fgetc(pkt);
  header->hiProductCode = getc(pkt);
  header->minorProductRev = getc(pkt);

  capWord = getUINT16(pkt);
  if (capWord!=header->capabilityWord) { /* if both capabilitywords */
    free(header);                        /* aren't the same, abort */
    header = NULL;
    return NULL;
  } /* endif */

  getc(pkt); getc(pkt); getc(pkt); getc(pkt); /* read the additional zone info */

  header->origAddr.point = getUINT16(pkt);
  header->destAddr.point = getUINT16(pkt);

  getc(pkt); getc(pkt); getc(pkt); getc(pkt); /* read ProdData */

  return header;
}

void correctEMAddr(s_message *msg)
{
   char *start = NULL, buffer[47];
   int i;

   start = strrstr(msg->text, " * Origin:");
   if (NULL != start) {
//      while (*(start++)!='\r');                       // get to end of line
      while ((*(start) !='\r') && (*(start) != '\n')) start++;  // get to end of line

      if (*(start-1) == ')') {                        // if there is no ')', there is no origin
         while (*(--start)!='(');                     // find beginning '('
         start++;                                     // and skip it
         i=0;
   
         while ((*start != ')') && (*start != '\r') && (*start != '\n') && (i < 47)) {
            buffer[i] = *start;
            i++; start++;
         } /* endwhile */
         buffer[i]   = '\0';
         string2addr(buffer, &(msg->origAddr));
      }
   } 
}

void correctNMAddr(s_message *msg, UINT16 def_zone)
{
   char *start, *copy;
   char buffer[35];
   char buff[200];

   copy = buffer;
   start = strstr(msg->text, "FMPT");
   if (NULL!=start) {
      start += 5;                  /* skip "FMPT " */
      while ('\r' != *start) {     /* copy all data until cr occurs */
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
   if (NULL!=start) {
      start += 5;                  /* skip "TOPT " */
      while ('\r' != *start) {     /* copy all data until cr occurs */
         *copy = *start;
         copy++;
         start++;
      } /* endwhile */
      *copy = '\0';                /* don't forget to close the string with 0 */

      msg->destAddr.point = atoi(buffer);
   } else {
      msg->destAddr.point = 0;
   } /* endif */

   /* INTL Kludge processing */
   copy = buffer;
   start = strstr(msg->text, "INTL");
   if (NULL != start) {
      start += 6;                 // skip INTL
      while (':' != *start) {     // copy all data until ':'
         *copy = *start;
         copy++;
         start++;
      } /* endwhile */
      *copy = '\0';
      msg->destAddr.zone = atoi(buffer);

      while (*start != ' ') start++; // walk to next zone info

      while (':' != *start) {     // copy all data until ':'
         *copy = *start;
         copy++;
         start++;
      } /* endwhile */
      *copy = '\0';
      msg->origAddr.zone = atoi(buffer);
   } else {

      msg->destAddr.zone = def_zone;     // FIX-ME! there seems a problem here
      msg->origAddr.zone = def_zone;     //
      sprintf(buff, "Mail without INTL-Kludge. Assuming %i:%i/%i.%i -> %i:%i/%i.%i",
              msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node, msg->origAddr.point,
              msg->destAddr.zone, msg->destAddr.net, msg->destAddr.node, msg->destAddr.point);
      writeLogEntry(hpt_log, '2', buff);
   } /* endif */
}

void correctAddr(s_message *msg,UINT16 def_zone)
{
   if (strncmp(msg->text, "AREA:",5) != 0) {
      correctNMAddr(msg,def_zone);
      msg->netMail = 1;
   } else {
      correctEMAddr(msg);
      msg->netMail = 0;
   } /* endif */
}

s_message *readMsgFromPkt(FILE *pkt,UINT16 def_zone)
{
   s_message *msg;
   CHAR      *textBuffer;
   INT       len;

   if (2 != getUINT16(pkt)) {
      return NULL;              /* no packed msg */
   } /* endif */

   msg = (s_message*) malloc(sizeof(s_message));
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
   fgets(msg->datetime, 21, pkt);

   textBuffer = (CHAR *) malloc(74);   // reserve mem space
   len = fgetsUntil0(textBuffer, 37, pkt);
   msg->toUserName = (CHAR *) malloc(len);
   strcpy(msg->toUserName, textBuffer);

   len = fgetsUntil0(textBuffer, 37, pkt);
   msg->fromUserName = (CHAR *) malloc(len);
   strcpy(msg->fromUserName, textBuffer);

   len = fgetsUntil0(textBuffer, 73, pkt);
   msg->subjectLine = (CHAR *) malloc(len);
   strcpy(msg->subjectLine, textBuffer);

   free(textBuffer);                   // free mem space

   textBuffer = (CHAR *) malloc(TEXTBUFFERSIZE+1); /* reserve 512kb + 1 (or 32kb+1) text Buffer */
   msg->textLength = fgetsUntil0(textBuffer, TEXTBUFFERSIZE+1 , pkt);

   msg->text = (CHAR *) malloc(msg->textLength); /* reserve mem for the real text */
   strcpy(msg->text, textBuffer);

   free(textBuffer);

   correctAddr(msg,def_zone);

   msg->recode = 0;

   return msg;
}

void freeMsgBuffers(s_message *msg)
{
  free(msg->text);
  free(msg->subjectLine);
  free(msg->toUserName);
  free(msg->fromUserName);
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
