#ifndef _AREALIST_H
#define _AREALIST_H

#include <fcommon.h>

typedef struct arealisttiem {
	int active;
	char *tag;
	char *desc;
} s_arealistitem, *ps_arealistitem;

typedef struct arealist {
	int count;
	int maxcount;
	ps_arealistitem areas;
} s_arealist, *ps_arealist;

ps_arealist newAreaList();
void freeAreaList(ps_arealist al);
int addAreaListItem(ps_arealist al, int active, char *tag, char *desc);
void sortAreaList(ps_arealist al);
char *formatAreaList(ps_arealist al, int maxlen, char *activechars);

#endif
