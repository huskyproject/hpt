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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <pkt.h>
#include <version.h>

int displayPkt(char *name)
{
   s_pktHeader *header;
   s_message   *msg;
   FILE *pkt;

   pkt = fopen(name, "rb");
   if (pkt==NULL) {
      printf("couldn't open %s\n", name);
      return 2;
   }

   header = openPkt(pkt);

   if (header==NULL) {
      printf("wrong or no pkt\n");
      return 3;
   }
   printf("Pkt-Name:     %s\n", name);

   printf("OrigAddr:     %u:%u/%u.%u\n", header->origAddr.zone, header->origAddr.net, header->origAddr.node, header->origAddr.point);
   printf("DestAddr:     %u:%u/%u.%u\n", header->destAddr.zone, header->destAddr.net, header->destAddr.node, header->destAddr.point);
   printf("pkt created:  %s", ctime(&header->pktCreated));
   printf("pkt Password: %s\n", header->pktPassword);
   /*  printf("pktVersion:   %u\n", header->pktVersion);*/
   printf("prodCode:     %02x%02x\n", header->hiProductCode, header->loProductCode);
   printf("prodRevision  %u.%u\n", header->majorProductRev, header->minorProductRev);
   printf("----------------------------------------\n");
   while (NULL != (msg = readMsgFromPkt(pkt,0))) {
      printf("Msg: %u:%u/%u.%u -> %u:%u/%u.%u\n", msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node, msg->origAddr.point,
             msg->destAddr.zone, msg->destAddr.net, msg->destAddr.node, msg->destAddr.point);
      freeMsgBuffers(msg);
      free(msg);
   } /* endwhile */

   free (header);
   fclose(pkt);

   printf("\n\n");

   return 0;
}

int main(int argc, char *argv[])
{
  int          i;

  printf("PktInfo v%u.%02u\n",VER_MAJOR, VER_MINOR);
  if (argc==1) {
    printf("usage: pktInfo <pktNames>\n");
    return 1;
  }

  for (i = 1; i < argc; i++)
  {
     displayPkt(argv[i]);
  }

  return 0;
}
