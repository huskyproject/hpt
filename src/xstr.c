/*****************************************************************************
 * String utilities for HPT (FTN NetMail/EchoMail Tosser)
 *****************************************************************************
 * Copyright (C) 1997-2000
 *
 * Kolya Nesterov
 *
 * Fido:     2:463/567
 * Kiev, Ukraine
 *
 * This file is part of HPT.
 *
 * HPT is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * HPT is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with HPT; see the file COPYING.  If not, write to the Free
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <xstr.h>

#define N_PRINTFBUF	512


char *xstralloc(char **s, size_t add) 
{
    int n;
    if (*s == NULL) {
        *s = malloc(add + 1); **s = '\0'; n = 0;
    } else {
        *s = realloc(*s, (n = strlen(*s)) + add + 1);
    };
    if (*s == NULL) {
	fprintf(stderr, "out of memory");
	abort();
    }
    return *s + n;
}

char *xstrcat(char **s, char *add)
{
    return strcat(xstralloc(s, strlen(add)), add);
}

char *xstrscat(char **s, ...)
{
    va_list	ap;
    char	*q, *p;
    int	ncat;
    for (va_start(ap, s), ncat = 0; (p = va_arg(ap, char *)) != NULL; ) 
	    ncat += strlen(p);
    p = xstralloc(s, ncat);
    for (va_start(ap, s); (q = va_arg(ap, char *)) != NULL; ) 
	    p = strcat(p, q);
    return p;
}

int xscatprintf(char **s, const char *format, ...) 
{
    va_list ap;
#ifdef HAS_VASPRINTF
    char *addline;
#elif HAS_VSNPRINTF
    char *addline;
    int  nmax;
#else
    char addline[N_PRINTFBUF];
#endif
    int  nprint;
    
    va_start(ap, format);
#ifdef HAS_VASPRINTF
    vasprintf(&addline, format, ap);
#elif HAS_VSNPRINTF
    for (nmax = N_PRINTFBUF; ; ) {
	    xstralloc(&addline, nmax);
	    nprint = vsnprintf(addline, nmax, format, ap);
	    /* If that worked, return the string. */
	    if (nprint > -1 && nprint < nmax)
                 break;
	    /* Else try again with more space. */
	    if (nprint > -1)
		 nmax = nprint+1;  /* precisely what is needed */
	    else
		 nmax += N_PRINTFBUF;        /* twice the old size */
    };
#else
    nprint = vsprintf(addline, format, ap);
    if (nprint > N_PRINTFBUF) {
	    fprintf(stderr, "sprintf buffer overflow at xscatprintf.\n" \
			    "used %d bytes instead of %d\n" \
			    "format leading to this was : %s\n"\
			    "please tell the developers\n", nprint, 
			    N_PRINTFBUF, format);
	    abort();
    };
#endif
    va_end(ap);
    xstrcat(s, addline);
#if defined(HAS_VASPRINTF) || defined(HAS_VSNPRINTF)
    free(addline);
#endif
    return nprint;
}

#ifdef TEST

int main(void)
{
	char *s = NULL;
	xstralloc(&s, 10);
	strcpy(s, "1234567890");
	xstrcat(&s, " test");
	xstrscat(&s, " this", " one", NULL);
	xscatprintf(&s, " %d %d", 3, 4);
	printf("%s", s);
	return strcmp(s, "1234567890 test this one 3 4");
}

#endif 
