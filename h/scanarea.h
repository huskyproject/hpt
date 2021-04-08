/* $Id$ */

#ifndef _SCANAREA_H
#define _SCANAREA_H

#define MAX_AREA_LEN 60

typedef enum scanAction
{
    actScanArea,
    actRescanArea,
    actRescanBadarea
} e_scanAction;

void makeMsg(HMSG hmsg, const XMSG * pxmsg, s_message * msg, s_area * echo, e_scanAction action);

/* char *createSeenByPath(s_area *echo); */
int rescanEMArea(s_area * echo, s_arealink * arealink, long rescanCount, long rescanAfter);

#endif
