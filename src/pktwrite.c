#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>

#include <pkt.h>

#include <recode.h>

#include <stamp.h>
#include <typedefs.h>
#include <compiler.h>
#include <progprot.h>

FILE *createPkt(char *filename, s_pktHeader *header)
{
  FILE       *pkt;
  struct tm  *pktTime;
  int        i;
  UCHAR      dummy;

  pkt = fopen(filename, "wb");
  if (pkt != NULL) {

     fputUINT16(pkt, header->origAddr.node);
     fputUINT16(pkt, header->destAddr.node);

     // create pkt time
     pktTime = localtime(&(header->pktCreated));

     // write time
     fputUINT16(pkt, pktTime->tm_year + 1900);  // struct tm stores the years since 1900
     fputUINT16(pkt, pktTime->tm_mon);
     fputUINT16(pkt, pktTime->tm_mday);
     fputUINT16(pkt, pktTime->tm_hour);
     fputUINT16(pkt, pktTime->tm_min);
     fputUINT16(pkt, pktTime->tm_sec);

     // write unused baud field
     fputUINT16(pkt, 0);

     // write pktver == 2
     fputUINT16(pkt, 2);

     // write net info
     fputUINT16(pkt, header->origAddr.net);
     fputUINT16(pkt, header->destAddr.net);

     fputc(header->loProductCode, pkt);   // put lowByte of Prod-Id
     fputc(header->majorProductRev, pkt); // put major version number

     // write PKT pwd, if strlen(pwd) < 8, fill the rest with \0
     for (i=0; i < strlen((char *) header->pktPassword); i++) fputc(header->pktPassword[i], pkt);
     for (i=strlen((char *) header->pktPassword); i<8; i++) fputc(0, pkt);

     // write qzone info
     fputUINT16(pkt, header->origAddr.zone);
     fputUINT16(pkt, header->destAddr.zone);

     fputUINT16(pkt, 0); // filler

     // write byte swapped capability Word
     dummy = header->capabilityWord / 256;
     fputc(dummy, pkt);
     dummy = header->capabilityWord % 256;
     fputc(dummy, pkt);

     fputc(header->hiProductCode, pkt);      // put hiByte of Prod-Id
     fputc(header->minorProductRev, pkt);    // put minor version number

     fputUINT16(pkt, header->capabilityWord);

     fputUINT16(pkt, header->origAddr.zone);
     fputUINT16(pkt, header->destAddr.zone);

     fputUINT16(pkt, header->origAddr.point);
     fputUINT16(pkt, header->destAddr.point);

     fputUINT16(pkt, 0); fputUINT16(pkt, 0); // write prodData

     return pkt;
  }
  return NULL;
}

int writeMsgToPkt(FILE *pkt, s_message msg)
{

  // recoding from internal charset to transport charset
  recodeToTransportCharset(msg.subjectLine);
  recodeToTransportCharset(msg.text);
   
  // write type 2 msg
  fputc(2, pkt);
  fputc(0, pkt);

  // write net/node info
  fputUINT16(pkt, msg.origAddr.node);
  fputUINT16(pkt, msg.destAddr.node);
  fputUINT16(pkt, msg.origAddr.net);
  fputUINT16(pkt, msg.destAddr.net);

  // write attribute info
  fputUINT16(pkt, msg.attributes);

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

