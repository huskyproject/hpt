/* $Id$ */

#ifndef _SCANAREA_H
#define _SCANAREA_H

void makeMsg(HMSG hmsg, XMSG xmsg, s_message *msg, s_area *echo, int action);
/* char *createSeenByPath(s_area *echo); */
int rescanEMArea(s_area *echo, s_arealink *arealink, long rescanCount);

#endif
