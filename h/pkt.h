/* $Id$ */

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
#ifndef _PKT_H
#define _PKT_H

#include <time.h>
#include <stdio.h>

#include <fidoconf/fidoconf.h>
#include <fcommon.h>

/* note that 128K - work buffer, not the max text length */
#if !defined(__DOS__) && !defined(__MSDOS__)
#define TEXTBUFFERSIZE 512*1024    // for real os
#define BUFFERSIZE 128*1024        // work buffer for msg text in pktread
#else
/* under ms-dos  message will be stripped to 32K */
#define TEXTBUFFERSIZE 32*1024     // for Dose
#define BUFFERSIZE 32*1024         // work buffer for msg text in pktread
#endif

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

int readMsgFromPkt(FILE *pkt, s_pktHeader *header, s_message **message);
/*DOC
  Input:  pkt is a pointer to a FILE which is already open.
          readMsgFromPkt will read from the current position of the filepointer
          header, when in a netmail no intl kludge is found, header will be used
          to assume intl kludge
		  message from pkt reading into *message structure, NULL if no msg 
  Output: number of msg was read (1 or 0), or 2 if error while reading
  FZ:     readMsgFromPkt reads a message out of the pkt and transforms the data
          to the struct.
*/


int correctDateTime(char *datetime);

#endif
