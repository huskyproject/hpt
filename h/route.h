#ifndef ROUTE_H
#define ROUTE_H
#include <fcommon.h>

struct route {
   s_link *link;
   char   *pattern;
};

typedef struct route s_route;
#endif
