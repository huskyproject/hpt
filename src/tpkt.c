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
   header.origAddr.net   = 2432;
   header.origAddr.node  = 601;
   header.origAddr.point = 0;

   header.destAddr.zone  = 2;
   header.destAddr.net   = 2432;
   header.destAddr.node  = 601;
   header.destAddr.point = 29;

   header.hiProductCode  = 0;
   header.loProductCode  = 0xfe;
   header.majorProductRev = 0;
   header.minorProductRev = 24;

   //header.pktPassword[0] = 0;
   strcpy(header.pktPassword, "irkutsk");
   header.pktCreated = time(NULL);

   header.capabilityWord = 1;
   header.prodData = 0;

   pkt = createPkt("test.pkt", &header);
   if (pkt != NULL) {
      msg.origAddr.zone  = 2;
      msg.origAddr.net   = 2432;
      msg.origAddr.node  = 601;
      msg.origAddr.point = 0;

      msg.destAddr.zone  = 2;
      msg.destAddr.net   = 2432;
      msg.destAddr.node  = 601;
      msg.destAddr.point = 29;

      msg.attributes = 1;

      t = time (NULL);
      tm = gmtime(&t);
      strftime(msg.datetime, 21, "%d %b %y  %T", tm);

      msg.netMail = 1;
      msg.text = (char *) malloc(300);
      strcpy(msg.text, "\001TOPT 29\r-tolkien.ger");
      msg.toUserName = (char *) malloc(15);
      strcpy(msg.toUserName, "areafix");
      msg.fromUserName = (char *) malloc(10);
      strcpy(msg.fromUserName, "Hpt Test");
      msg.subjectLine = (char *) malloc(5);
      strcpy(msg.subjectLine, "irkutsk");
      msg.textLength = strlen(msg.text);

      writeMsgToPkt(pkt, msg);

      closeCreatedPkt(pkt);
   } else {
      printf("Could not create pkt");
   } /* endif */

   return 0;
}
