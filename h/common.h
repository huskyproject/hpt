#ifndef _COMMON_H
#define _COMMON_H

#include <typesize.h>
#include <stdio.h>

struct addr {

   UINT16 zone, net, node, point;
   CHAR   *domain;

};

enum prio {CRASH, HOLD, NORMAL};
enum type {PKT, REQUEST, FLOFILE};
typedef enum prio e_prio;
typedef enum type e_type;

typedef struct addr s_addr;

/* common functions */

int  addrComp(const s_addr a1, const s_addr a2);
/*DOC
  Input:  two addresses
  Output: 0, or !0
  FZ:     0 ist returned if the two addresses are the same, !0 else
*/

char *strrstr(const char *HAYSTACK, const char *NEEDLE);

/*DOC
  Input:  two constant null-terminated strings
  Output: NULL or the point to a null-terminated string
  FZ:     finds the LAST occurence of NEEDLE in HAYSTACK
          (same as strstr but last occurence
*/

void string2addr(char *string, s_addr *addr);
/*DOC
  Input:  string is an \0-terminated array of chars. is a pointer to a struct addr.
  Output: ./.
  FZ:     string2addr converts a char[] to an addr. If string is not an addr NULL ist returned.
*/

UINT16 getUINT16(FILE *in);
/*DOC
  Input:  in is an file stream opened for reading.
  Output: getUINT16 returns an UINT16
  FZ:     the UINT15 is read from the stream using the method lowByte, highByte.
*/

int    fputUINT16(FILE *out, UINT16 word);
/*DOC
  Input:  out is an file opened for writing.
          word is the UINT16 which should be written
  Output: fputUIN16 returns the return of the second fputc call.
  FZ:     fputUINT16 writes word into the stream using the order lowByte, highByte.
*/

INT    fgetsUntil0(CHAR *str, INT n, FILE *f);
/*DOC
  Input:  n-1 chars are read at most.
          str is a buffer with the length n.
          f is a file stream opened for reading.
  Output: fgetsUntil0 returns the number of chars read including the last \0
  FZ:     fgetsUntil0 reads chars into the buffer until eof(f) || n-1 are read || a \0 is encountered.
*/

char   *stripLeadingChars(char *str, const char *chr);
/*DOC
  Input:  str is a \0-terminated string
          chr contains a list of characters.
  Output: stripLeadingChars returns a pointer to a string
  FZ:     all leading characters which are in chr are deleted.
          str is changed and returned.
*/

char   *strUpper(char *str);
/*DOC
  Input:  str is a \0 terminated string
  Output: a pointer to a \0 terminated string is returned.
  FZ:     strUpper converts the string from lower case to upper case.
*/

char   *createTempPktFileName();
/*DOC
  Input:  ./.
  Output: a pointer to a \0 terminated string is returned.
  FZ:     createTempPktFile tries to compose a new, not used pktfilename.
          It takes the least 24bit of the actual time. The last 2 Bytes
          area filled with a counter. So you can get up to 256 different files
          in a second and have the same timestamp only every 291 days.
          Remember to free the space of the retutrend string.
*/
  
char   *createOutboundFileName(s_addr aka, e_prio prio, e_type typ);
/*DOC
  Input:  aka is the addr whose OutboundFileName should be created.
          prio is some kind of CRASH, HOLD, NORMAL
          typ is some kind of PKT, REQUEST, FLOFILE
  Output: a pointer to a char is returned.
  FZ:     if the fileName could not be created NULL is returned, else the pointer to the fileName.
          Remember to free it.
          If you specify PKT a *.?UT is created.
          If you specify REQUEST a *.REQ is created.
          IF you specify FLOFILE a *.?LO is created.
*/
#endif
