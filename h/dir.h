/*
 *  dirent.h    Defines the types and structures used by the directory routines
 */
#ifndef DIR_H

#ifndef __IBMC__     /* all other include their own dirent.h */
  #ifndef __WATCOMC__
    #ifdef __EMX__
      #include <sys/types.h>
    #endif
    #include <dirent.h>
  #endif
#endif

#ifdef __WATCOMC__
#include <direct.h>  /* watcom knows this as direct.h */
#endif

#ifdef __IBMC__   /* only define it for IBM VisualAge C++ */
#define DIR_H

#include <direct.h>   /* include the other things out of direct.h */
#ifdef OS_2
#ifdef EXPENTRY
#undef EXPENTRY
#endif
#endif
#define INCL_DOSERRORS
#define INCL_DOSFILEMGR
#include <os2.h>

#define NAME_MAX        255             /* maximum filename */

typedef struct dirent {
    char        d_attr;                 /* file's attribute */
//  NOT IMPLEMENTED!!!!
//    unsigned short int d_time;          /* file's time */
//    unsigned short int d_date;          /* file's date */
    long        d_size;                 /* file's size */
    char        d_name[ NAME_MAX + 1 ]; /* file's name */
    HDIR        d_hdir;                 /* save OS/2 hdir */
    char        d_first;                /* flag for 1st time */
} DIR;

/* File attribute constants for d_attr field */

#define _A_NORMAL       0x00    /* Normal file - read/write permitted */
#define _A_RDONLY       0x01    /* Read-only file */
#define _A_HIDDEN       0x02    /* Hidden file */
#define _A_SYSTEM       0x04    /* System file */
#define _A_VOLID        0x08    /* Volume-ID entry */
#define _A_SUBDIR       0x10    /* Subdirectory */
#define _A_ARCH         0x20    /* Archive file */

extern int      closedir( DIR * );
extern DIR      *opendir( const char * );
extern struct dirent *readdir( DIR * );

#endif
#endif
