#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <pkt.h>
#include <version.h>

int main(int argc, char *argv[])
{
  s_pktHeader  *header;
  s_message    *msg;
  FILE         *pkt;

  printf("PktInfo v%u.%02u\n",VER_MAJOR, VER_MINOR);
  if (argc==1) {
    printf("usage: pktInfo <pktName>\n");
    return 1;
  }

  pkt = fopen(argv[1], "rb");
  if (pkt==NULL) {
    printf("couldn't open %s\n", argv[1]);
    return 2;
  }

  header = openPkt(pkt);

  if (header==NULL) {
    printf("wrong or no pkt\n");
    return 3;
  }

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

  return 0;
}
