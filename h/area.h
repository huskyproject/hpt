#ifndef AREA_H
#define AREA_H
#include <common.h>
#include <link.h>

struct area {
   char    *name;
   char    *filename;
   int     msgbType;      // MSGTYPE_SDM, MSGTYPE_SQUISH
   s_addr  useAka;
   s_link  **downlinks;   // array of pointer to s_link
   UINT    downlinkCount;
};

typedef struct area s_area;

#endif
