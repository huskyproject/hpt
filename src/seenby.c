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
   char *text, *line, addr2d[13];
   
   if (seenByCount==0) {              //return empty control line
      text = malloc(strlen(lineHeading)+1+1);
      strcpy(text, lineHeading);
   } else {
       
      line = calloc (size,sizeof(char));

      sprintf(addr2d, "%u/%u", seenBys[0].net, seenBys[0].node);
      text = (char *) calloc(size,sizeof(char));
      strcpy(line, lineHeading);
      strcat(line, addr2d);
      for (i=1; i < seenByCount; i++) {

         if (seenBys[i-1].net == seenBys[i].net)
            sprintf(addr2d, " %u", seenBys[i].node);
         else
            sprintf(addr2d, " %u/%u", seenBys[i].net, seenBys[i].node);

         if (strlen(line)+strlen(addr2d) +1 > 79) {
            //if line would be greater than 79 characters, make new line
            strcat(text,line);
            strcat(text, "\r");
            text = (char *) realloc(text,strlen(text)+size);
            strcpy(line, lineHeading);
            // start new line with full 2d information
            sprintf(addr2d, "%u/%u", seenBys[i].net, seenBys[i].node);
         }
         strcat(line, addr2d);
      }
	  // reserve only needed space + ending \r
          text = (char *) realloc(text, strlen(text)+strlen(line)+2);
	  strcat(text,line);
	  free(line);
   }
                           
   strcat(text, "\r");

   return text;
}
