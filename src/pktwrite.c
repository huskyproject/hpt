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
#if (defined (__WATCOMC__) && defined (__NT__)) || defined(__TURBOC__)
#include <dos.h>
#endif
#include <string.h>
#if !defined(__TURBOC__) && !(defined (_MSC_VER) && (_MSC_VER >= 1200))
#include <unistd.h>
#endif

#include <fidoconf/fidoconf.h>
#include <fidoconf/xstr.h>
#include <fidoconf/common.h>

#include <pkt.h>
#include <global.h>

#include <smapi/stamp.h>
#include <smapi/typedefs.h>
#include <smapi/compiler.h>
#include <smapi/progprot.h>
#include <version.h>

FILE *createPkt(char *filename, s_pktHeader *header)
{
  FILE       *pkt;
  struct tm  *pktTime;
  int        i;
  UCHAR      dummy;

  pkt = fopen(filename, "wb");
  if (pkt != NULL) {

     fputUINT16(pkt, (UINT16)header->origAddr.node);
     fputUINT16(pkt, (UINT16)header->destAddr.node);

     // create pkt time
     pktTime = localtime(&(header->pktCreated));

     // write time
     fputUINT16(pkt, (UINT16)(pktTime->tm_year + 1900));  // struct tm stores the years since 1900
     fputUINT16(pkt, (UINT16) pktTime->tm_mon);
     fputUINT16(pkt, (UINT16) pktTime->tm_mday);
     fputUINT16(pkt, (UINT16) pktTime->tm_hour);
     fputUINT16(pkt, (UINT16) pktTime->tm_min);
     fputUINT16(pkt, (UINT16) pktTime->tm_sec);

     // write unused baud field
     fputUINT16(pkt, 0);

     // write pktver == 2
     fputUINT16(pkt, 2);

     // write net info
     fputUINT16(pkt, (UINT16) header->origAddr.net);
     fputUINT16(pkt, (UINT16) header->destAddr.net);

     fputc(header->loProductCode, pkt);   // put lowByte of Prod-Id
     fputc(header->majorProductRev, pkt); // put major version number

     // write PKT pwd, if strlen(pwd) < 8, fill the rest with \0
     for (i=0; i < strlen((char *) header->pktPassword); i++) fputc(header->pktPassword[i], pkt);
     for (i=strlen((char *) header->pktPassword); i<8; i++) fputc(0, pkt);

     // write qzone info
     fputUINT16(pkt, (UINT16) header->origAddr.zone);
     fputUINT16(pkt, (UINT16) header->destAddr.zone);

     fputUINT16(pkt, 0); // filler

     // write byte swapped capability Word
     dummy = (UCHAR)(header->capabilityWord / 256);
     fputc(dummy, pkt);
     dummy = (UCHAR)(header->capabilityWord % 256);
     fputc(dummy, pkt);

     fputc(header->hiProductCode, pkt);      // put hiByte of Prod-Id
     fputc(header->minorProductRev, pkt);    // put minor version number

     fputUINT16(pkt, header->capabilityWord);

     fputUINT16(pkt, (UINT16) header->origAddr.zone);
     fputUINT16(pkt, (UINT16) header->destAddr.zone);

     fputUINT16(pkt, (UINT16) header->origAddr.point);
     fputUINT16(pkt, (UINT16) header->destAddr.point);

     fputUINT16(pkt, 0); fputUINT16(pkt, 0); // write prodData

     return pkt;
  }
  return NULL;
}

int writeMsgToPkt(FILE *pkt, s_message msg)
{

  // write type 2 msg
  fputc(2, pkt);
  fputc(0, pkt);

  // write net/node info
  fputUINT16(pkt, (UINT16) msg.origAddr.node);
  fputUINT16(pkt, (UINT16) msg.destAddr.node);
  fputUINT16(pkt, (UINT16) msg.origAddr.net);
  fputUINT16(pkt, (UINT16) msg.destAddr.net);

  // write attribute info
  fputUINT16(pkt, (UINT16) msg.attributes);

  // write cost info
  fputUINT16(pkt, 0);

  // write date...info
  fwrite(msg.datetime, 20, 1, pkt);

  // write userNames
  if (strlen(msg.toUserName) >= 36) fwrite(msg.toUserName, 35, 1, pkt);      // max 36 bytes
  else fputs(msg.toUserName, pkt);
  fputc(0, pkt);

  if (strlen(msg.fromUserName) >= 36) fwrite(msg.fromUserName, 35, 1, pkt);  // max 36 bytes
  else fputs(msg.fromUserName, pkt);
  fputc(0, pkt);

  // write subject
  if (strlen(msg.subjectLine) >= 72) fwrite(msg.subjectLine, 71, 1, pkt);
  else fputs(msg. subjectLine, pkt);
  fputc(0, pkt);

  // write text
  fputs(msg.text, pkt);
  fputc(0, pkt);

  return 0;
}

int closeCreatedPkt(FILE *pkt)
{
   fputc(0, pkt); fputc(0, pkt);
   fclose(pkt);
   return 0;
}

FILE *openPktForAppending(char *fileName, s_pktHeader *header)
{
   FILE *pkt;
   
   if (fexist(fileName)) {
      pkt = fopen(fileName, "r+b");
      openPkt(pkt);
      fseek(pkt, -2, SEEK_END);        // go to \0\0 to add a new msg.
   } else {
      pkt = createPkt(fileName, header);
   } /* endif */

   return pkt;
}

/* Note:
 * This is a simply msgid without any hash function...
 * Imho it is not necessary to create better msgid for this purpose.
 */

char *createKludges(const char *area, const s_addr *ourAka, const s_addr *destAka) {
   
   char *buff = NULL;
	
   if (area) xscatprintf(&buff, "AREA:%s\r", area);
   else {
	   xscatprintf(&buff, "\1INTL %u:%u/%u %u:%u/%u\r",
			   destAka->zone, destAka->net, destAka->node,
			   ourAka->zone,  ourAka->net,  ourAka->node);
      if (ourAka->point) xscatprintf(&buff, "\1FMPT %d\r", ourAka->point);
      if (destAka->point) xscatprintf(&buff, "\1TOPT %d\r", destAka->point);
   }

   sleep(1);
   if (ourAka->point)
      xscatprintf(&buff, "\1MSGID: %u:%u/%u.%u %08lx\r",
              ourAka->zone,ourAka->net,ourAka->node,ourAka->point,time(NULL));
   else
      xscatprintf(&buff, "\1MSGID: %u:%u/%u %08lx\r",
              ourAka->zone,ourAka->net,ourAka->node,time(NULL));

   if (!config->disableTID) xscatprintf(&buff, "\1PID: %s\r", versionStr);
   xstrcat(&buff, "\1FLAGS NPD\r");

   return buff;
}
