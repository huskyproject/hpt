#ifndef _FCOMMON_H
#define _FCOMMON_H

#include <typesize.h>
#include <stdio.h>
#include <common.h>


enum prio {CRASH, HOLD, NORMAL};
enum type {PKT, REQUEST, FLOFILE};
typedef enum prio e_prio;
typedef enum type e_type;

/* common functions */

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
