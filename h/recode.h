#ifndef RECODE_H
#define RECODE_H

#include <fcommon.h>

VOID recodeToInternalCharset( CHAR *string);
VOID recodeToTransportCharset( CHAR *string);
void getctab(CHAR *dest,  UCHAR *charMapFileName);

extern CHAR intab[], outtab[];

#endif
