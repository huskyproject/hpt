#include <seenby.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


int compare(const void *first, const void *second)
{
   if ( ((s_seenBy*) first)->net < ((s_seenBy*) second)->net) return -1;
   else
      if ( ((s_seenBy*) first)->net > ((s_seenBy*) second)->net) return 1;
      else if ( ((s_seenBy*) first)->node < ((s_seenBy*) second)->node) return -1;
           else if ( ((s_seenBy*) first)->node > ((s_seenBy*) second)->node) return 1;
   return 0;
}

void sortSeenBys(s_seenBy *seenBys, UINT count)
{
   qsort(seenBys, count, sizeof(s_seenBy), &compare);
}

char *createControlText(s_seenBy seenBys[], UINT seenByCount, char *lineHeading)
{
   int  size = 81, i;
   char *text, addr2d[12];

   if (seenByCount==0) return NULL; // don't generate empty control line
       
   sprintf(addr2d, "%u/%u", seenBys[0].net, seenBys[0].node);
   text = (char *) malloc(size);
   strcpy(text, lineHeading);
   strcat(text, addr2d);
   for (i=1; i < seenByCount; i++) {

      if (seenBys[i-1].net == seenBys[i].net)
         sprintf(addr2d, " %u", seenBys[i].node);
      else
         sprintf(addr2d, " %u/%u", seenBys[i].net, seenBys[i].node);

      if (strlen(text)+strlen(addr2d) +1 > size) {
         size += 80;
         text = (char *) realloc(text, size);
         strcat(text, "\r");
         strcat(text, lineHeading);
         // start new line with full 2d information
         sprintf(addr2d, "%u/%u", seenBys[i].net, seenBys[i].node);
      }
      strcat(text, addr2d);
   }

   text = (char *) realloc(text, strlen(text)+2); // reserve only needed space + ending \r
                           
   strcat(text, "\r");

   return text;
}
