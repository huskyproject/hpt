#ifndef SEENBY_H
#define SEENBY_H
#include <typesize.h>

struct seenBy {
   UINT16 net, node;
};

typedef struct seenBy s_seenBy;

void sortSeenBys(s_seenBy *seenBys, UINT count);

char *createControlText(s_seenBy seenBys[], UINT seenByCount, char *lineHeading);

#endif