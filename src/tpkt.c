#include <pkt.h>
#include <typesize.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int main()
{
   s_pktHeader  header;
   s_message    msg;
   FILE         *pkt;
   time_t       t;
   struct tm    *tm;

   header.origAddr.zone  = 2;
   header.origAddr.net   = 2433;
   header.origAddr.node  = 1245;
   header.origAddr.point = 100;

   header.destAddr.zone  = 2;
   header.destAddr.net   = 2433;
   header.destAddr.node  = 1245;
   header.destAddr.point = 1;

   header.hiProductCode  = 0;
   header.loProductCode  = 0xfe;
   header.majorProductRev = 0;
   header.minorProductRev = 6;

   header.pktPassword[0] = 0;
   header.pktCreated = time(NULL);

   header.capabilityWord = 1;
   header.prodData = 0;

   pkt = createPkt("test.pkt", &header);
   if (pkt != NULL) {
      msg.origAddr.zone  = 2;
      msg.origAddr.net   = 2433;
      msg.origAddr.node  = 1245;
      msg.origAddr.point = 100;

      msg.destAddr.zone  = 2;
      msg.destAddr.net   = 2433;
      msg.destAddr.node  = 1245;
      msg.destAddr.point = 1;

      msg.attributes = 1;

      t = time (NULL);
      tm = gmtime(&t);
      strftime(msg.datetime, 21, "%d %b %y  %T", tm);

      msg.netMail = 1;
      msg.text = (char *) malloc(300);
      strcpy(msg.text, "FMPT 100\rTOPT 1\rINTL 2:2433/1245 2:2433/1245\r\rEdde Budde Edde\r\r text text\r---");
      msg.toUserName = (char *) malloc(15);
      strcpy(msg.toUserName, "Matthias Tichy");
      msg.fromUserName = (char *) malloc(10);
      strcpy(msg.fromUserName, "Hpt Test");
      msg.subjectLine = (char *) malloc(5);
      strcpy(msg.subjectLine, "Test");
      msg.textLength = strlen(msg.text);

      writeMsgToPkt(pkt, msg);

      closeCreatedPkt(pkt);
   } else {
      printf("Could not create pkt");
   } /* endif */

   return 0;
}
