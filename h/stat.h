#ifndef _STAT_H
#define _STAT_H

#define ADV_STAT

/* stat record type */
typedef enum { stNORM, stBAD, stDUPE, stOUT } st_type;

void put_stat(s_area *echo, hs_addr *link, st_type type, long len);
void upd_stat(char *file);

#endif
