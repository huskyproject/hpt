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
#ifndef _PKT_H
#define _PKT_H

#include <time.h>
#include <stdio.h>

#include <typesize.h>
#include <fcommon.h>

#ifndef __DOS__
   #define TEXTBUFFERSIZE 512*1024    // for real os
#else
   #define TEXTBUFFERSIZE 32*1024     // for Dose
#endif

struct pktHeader {
   /* Address block */
   s_addr destAddr, origAddr;

   /* product specific */
   UCHAR  hiProductCode,
          loProductCode;
   UCHAR  majorProductRev,
          minorProductRev;

   /* date */
   time_t pktCreated;

   UINT16 capabilityWord;

   UINT32 prodData;

   char  pktPassword[9]; /* password + \0 */
};

struct message {
   /*Address block */
   s_addr destAddr, origAddr;

   UINT16 attributes;
   CHAR   datetime[21];
   CHAR   netMail;
   INT32  textLength;

   CHAR   *toUserName, *fromUserName, *subjectLine;
   CHAR   *text;
};

typedef struct pktHeader s_pktHeader;
typedef struct message   s_message;

FILE        *createPkt(char *filename, s_pktHeader *header);
/*DOC
  Input:  filename is the name of the pkt.
          header contains information about writing the pkt header
  Output: createPkt returns NULL if the pkt could not be created
          else the pointer to a open FILE is returned.
  FZ:     createPkt creates the pkt and writes the header in a way conforming to
          FSC0039 (2+)
*/

int         writeMsgToPkt(FILE *pkt, s_message msg);
/*DOC
  Input:  pkt is a pointer to a file opened by createPkt
          msg contains the message to be written.
  Output: writeMsgToPkt return 0 if all is ok, else 1 is returned.
  FZ:     writeMsgToPkt appends the message to the pkt file.
*/

int         closeCreatedPkt(FILE *pkt);
/*DOC
  Input:  pkt is a pointer to a file opened by createPkt
  OutPut: closeCreatedPkt returns 0 if all is ok, else 1 is returned.
  FZ:     closeCreatedPkt appends \0\0 to the pkt and closes the file.
*/
FILE        *openPktForAppending(char *fileName, s_pktHeader *header);
/*DOC
  Input:  fileName is the name of the pkt which should be opened.
          header: If the pkt does not exist, header is used as pktHeader.
  Output: openPktForAppending returns a file stream opened for writing.
  FZ:     if the fileName does exist the pkt is opened using openPkt and
          the file position indicator is set to the \0\0  to allow appending
          to the pkt. If the file does not exist it is created using
          createPkt and te param header.
*/

s_pktHeader *openPkt(FILE *pkt);
/*DOC
  Input:  pkt is a pointer to a FILE which is already open.
          openPkt will read from the current position of the filepointer
  Output: openPkt returns a pointer to a s_pktHeader struct or NULL if
          pkt is not a PKT which conforms to FSC0039 (2+)
  FZ:     openPkt reads the pkt and transforms the binary data to the struct.
          it reads the data as an 2+ packet.
*/

s_message   *readMsgFromPkt(FILE *pkt, UINT16 def_zone);
/*DOC
  Input:  pkt is a pointer to a FILE which is already open.
          readMsgFromPkt will read from the current position of the filepointer
          def_zone, when in a netmail no intl kludge is found, def_zone will be used
          as zone-info for both directions (from & to).
  Output: readMsgFromPkt returns a pointer to a s_message struct or NULL if
          pkt does not include a message or a wrong message.
  FZ:     readMsgFromPkt reads a message out of the pkt and transforms the data
          to the struct.
*/

void        freeMsgBuffers(s_message *msg);
/*DOC
  Input:  a pointer to a s_message which is created by readMsgFromPkt.
  Output: ./.
  FZ:     all memory reserved by readMsgFromPkt will be freed.
*/
#endif

char        *getKludge(s_message msg, char *what);
/*DOC
  Input:  a s_message struct
          the kludge which is searched for
  Output: getKludge returns a pointer to the text which followed the kludge
          If the kludge does not exist it returns NULL
*/
  