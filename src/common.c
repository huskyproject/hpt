#include <time.h>
#include <common.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <global.h>

#include <typedefs.h>
#include <compiler.h>
#include <stamp.h>
#include <progprot.h>

int  addrComp(const s_addr a1, const s_addr a2)
{
   int rc = 0;

   rc =  a1.zone  != a2.zone;
   rc += a1.net   != a2.net;
   rc += a1.node  != a2.node;
   rc += a1.point != a2.point;

   return rc;
}

char *strrstr(const char *HAYSTACK, const char *NEEDLE)
{
   char *start = NULL, *temp = NULL;

   temp = strstr(HAYSTACK, NEEDLE);
   while (temp  != NULL) {
      start = temp;
      temp = strstr(temp+1,NEEDLE);
   }
   return start;
}

void string2addr(char *string, s_addr *addr)
{
  char *start = string;
  char buffer[7];
  int  i = 0;

  while ((*start != ':')&&(*start != ' ')) {    // copy zone info or preceding domain
      buffer[i] = *(start++);
      i++;
   } /* endwhile */
   buffer[i] = '\0';
   if (!isdigit(buffer[0])) {
      // Domain name could be in front of the addr, not FTS-compatbible!!!!!
      // software that such crap is generating should be xxxx
      addr->domain = (char *) malloc(strlen(buffer)+1);
      strcpy(addr->domain, buffer);
   } else addr->zone = atoi(buffer);

   i = 0;
   start++;

   if (strchr(start, '/')!= NULL) {
      while (*start != '/') {                           // copy net info
         buffer[i] = *(start++);
         i++;
      } /* endwhile */
      buffer[i] = '\0';
      addr->net = atoi(buffer);

      i = 0;
      start++;
   }

   while ((*start != '.') && (*start != '\0') && (*start != '@')) {      // copy node info
      buffer[i] = *(start++);
      i++;
   } /* endwhile */
   buffer[i] = '\0';
   addr->node = atoi(buffer);

   i = 0;

   switch (*start) {
   case '\0':                            // no point/domain info
      start++;
      addr->point = 0;
      break;
   case '@':                            // no point, but domain info
      start++;
      while (*start != '\0') {
         buffer[i] = *start;
         i++; start++;
      } /* endwhile */
      buffer[i] = '\0';
      addr->domain = (CHAR *) malloc(strlen(buffer)+1);
      strcpy(addr->domain, buffer);
      break;
   case '.':                            // point info / maybe domain info
      start++;
      while ((*start != '@') && (*start != '\0')) {           // copy point info
         buffer[i] = *(start++);
         i++;
      } /* endwhile */
      buffer[i] = '\0';
      addr->point = atoi(buffer);
      i = 0;
      if (*start == '@') {                                   // copy domain info
         start++;
         while (*start != '\0') {
            buffer[i] = *start;
            i++; start++;
         } /* endwhile */
         buffer[i] = '\0';
         addr->domain = (CHAR *) malloc(strlen(buffer)+1);
         strcpy(addr->domain, buffer);
      } /* endif */
      break;
   default:
     break;
   } /* endswitch */
   return;
}

UINT16 getUINT16(FILE *in)
{
   UCHAR dummy;

   dummy = (UCHAR) getc(in);
   return (dummy + (UCHAR ) getc(in) * 256);
}

int fputUINT16(FILE *out, UINT16 word)
{
  UCHAR dummy;

  dummy = word % 256;        // write high Byte
  fputc(dummy, out);
  dummy = word / 256;        // write low Byte
  return fputc(dummy, out);
}

INT   fgetsUntil0(CHAR *str, int n, FILE *f)
{
   int i;

   for (i=0;i<n-1 ;i++ ) {
      str[i] = getc(f);

      if (feof(f)) {
         str[i+1] = 0;
         return i+2;
      } /* endif */

      if (0 == str[i]) {
         return i+1;
      } /* endif */

   } /* endfor */

   str[n-1] = 0;
   return n;
}

char *stripLeadingChars(char *str, const char *chr)
{
   char *i = str;

   while (NULL != strchr(chr, *i)) {       // *i is in chr
      i++;
   } /* endwhile */                        // i points to the first occurences
                                           // of a character not in chr
   strcpy(str, i);
   return str;
}

char *strUpper(char *str)
{
   char *temp = str;
   
   while(*str != 0) {
      *str = toupper(*str);
      str++;
   }
   return temp;
}

char *createTempPktFileName()
{
   char   *fileName = (char *) malloc(strlen(outboundDir)+1+12);
   time_t aTime = time(NULL);  // get actual time
   int counter = 0;

   aTime %= 0xffffff;   // only last 24 bit count

   do {
      sprintf(fileName, "%s%06lx%02x.pkt", outboundDir, aTime, counter);
      counter++;
   } while (fexist(fileName) && (counter<=256));

   if (!fexist(fileName)) return fileName;
   else {
      free(fileName);
      return NULL;
   }
}

char *createOutboundFileName(s_addr aka, e_prio prio, e_type typ)
{
   char name[13], zoneSuffix[5], pntDir[14];
   char *fileName;

   if (aka.point != 0) {
      sprintf(pntDir, "%04x%04x.pnt\\", aka.net, aka.node);
#ifdef UNIX
      pntDir[12] = '/';
#endif
      sprintf(name, "%08x.flo", aka.point);
   } else {
      pntDir[0] = 0;
      sprintf(name, "%04x%04x.flo", aka.net, aka.node);
   }

   if (aka.zone != addr[0].zone) {
      // add suffix for other zones
      sprintf(zoneSuffix, ".%03x\\", aka.zone);
#ifdef UNIX
      zoneSuffix[4] = '/';
#endif
   } else {
      zoneSuffix[0] = 0;
   }

   switch (typ) {
      case PKT:
         name[9] = 'o'; name[10] = 'u'; name[11] = 't';
         break;
      case REQUEST:
         name[9] = 'r'; name[10] = 'e'; name[11] = 'q';
         break;
      case FLOFILE: break;
   } /* endswitch */

   if (typ != REQUEST) {
      switch (prio) {
         case CRASH : name[9] = 'c';
                      break;
         case HOLD  : name[9] = 'h';
                      break;
         case NORMAL: break;
      } /* endswitch */
   } /* endif */

   fileName = (char *) malloc(strlen(outboundDir)+strlen(pntDir)+strlen(zoneSuffix)+strlen(name)+1);
   strcpy(fileName, outboundDir);
   if (zoneSuffix[0] != 0) strcpy(fileName+strlen(fileName)-1, zoneSuffix);
   strcat(fileName, pntDir);
   strcat(fileName, name);
   
   return fileName;
}