#if !defined    (_TYPESIZE_H)
#define _TYPESIZE_H

//
//  typesize.h                         written by tom schlangen
//  ----------                         modified by TJW
//
//  this is an attempt to somewhat reduce problems by unifying
//  compiler dependend type sizes.
//
//  the basic set/list of unified types required to be present
//  for each compiler is:
//
//  --------+-----------------+-------+-----------------------
//  name    | description     | bytes | range
//  --------+-----------------+-------+-----------------------
//  CHAR    | signed char     | 1     | -128..127
//  UCHAR   | unsigned char   | 1     | 0..255
//  INT16   | signed word     | 2     | -32768..32767
//  UINT16  | unsigned word   | 2     | 0..65535
//  INT32   | signed dword    | 4     | -2147483648..2147483647
//  UINT32  | unsigned dword  | 4     | 0..4294967295
//  --------+-----------------+-------+-----------------------
//
//  besides that, there are some further general purpose types
//  with guaranteed (either by ANSI C or by us) sizes/ranges.
//  these should be used with care, since beneath their
//  guaranteed size they are strictly compiler specific. so if
//  you use them, make sure you do so only within the
//  guaranteed range. also take care not to use them in byte-
//  aligned (`packed') structures, since the size of the re-
//  resulting structures may vary from compiler to compiler,
//  which may cause hazzard on in certain cases.
//
//  --------+-------------------------------------------------
//  name    | description
//  --------+-------------------------------------------------
//  INT     | general purpose compiler specific `signed int'.
//          | ANSI C guarantees at least 2 bytes,
//          | range -32768..32767 for this type.
//  UINT    | general purpose compiler specific `unsigned int',
//          | we guarantee at least 2 bytes,
//          | range 0..65535 for this type.
//  LONG    | general purpose compiler specific `signed long'.
//          | ANSI C * guarantees at least 4 bytes,
//          | range -2147483648..2147483647 for this type.
//  ULONG   | general purpose compiler specific `unsigned long'.
//          | we guarantee at least 4 bytes,
//          | range 0..4294967295 for this type.
//  --------+-------------------------------------------------
//
//  the following definition blocks are in alphabetical order
//  of the various compilers identification defines. please add
//  the definitions for your compiler, if not already present.
//

#ifdef __cplusplus
extern "C" {
#endif

//  the EMX/GNU 32bit compilers

#if defined(__EMX__)
#ifndef __OS2_H__       // os2.h defines it already
typedef          char       CHAR;               // 1 byte
typedef unsigned char      UCHAR;               // 1 byte
#endif
typedef          short      INT16;              // 2 byte
typedef unsigned short     UINT16;              // 2 byte
typedef          int        INT32;              // 4 byte
typedef unsigned int       UINT32;              // 4 byte
// --------------------------------------------------------------------------
#ifndef __OS2_H__       // os2.h defines it already
typedef          int        INT;                // 4 byte
typedef unsigned int       UINT;                // 4 byte
typedef          long       LONG;               // 4 byte
typedef unsigned long      ULONG;               // 4 byte
typedef          void       VOID;
#endif
#endif                                          // #if defined(__EMX__)

#if defined(__linux__)
typedef          char       CHAR;               // 1 byte
typedef unsigned char      UCHAR;               // 1 byte
typedef          short      INT16;              // 2 byte
typedef unsigned short     UINT16;              // 2 byte
typedef          int        INT32;              // 4 byte
typedef unsigned int       UINT32;              // 4 byte
// --------------------------------------------------------------------------
typedef          int        INT;                // 4 byte
typedef unsigned int       UINT;                // 4 byte
typedef          long       LONG;               // 4 byte
typedef unsigned long      ULONG;               // 4 byte
typedef          void       VOID;
#endif

// the Borland compiler family - valid for DOS, OS/2 and Win32 versions

#if defined(__BORLANDC__)
typedef signed   char       CHAR;               // 1 byte
typedef unsigned char      UCHAR;               // 1 byte
typedef signed   short      INT16;              // 2 byte
typedef unsigned short     UINT16;              // 2 byte
typedef signed   long       INT32;              // 4 byte
typedef unsigned long      UINT32;              // 4 byte
// --------------------------------------------------------------------------
typedef signed   int        INT;                // 2/4 byte
typedef unsigned int       UINT;                // 2/4 byte
typedef signed   long       LONG;               // 4 byte
typedef unsigned long      ULONG;               // 4 byte
typedef          void       VOID;
#endif                                          // #if defined(__BORLANDC__)


//  the IBM 32bit CSet/VAC++ compilers

#if defined(__IBMC__) || defined(__IBMCPP__)
#ifndef __OS2_H__       // os2.h defines it already
typedef          char       CHAR;               // 1 byte
typedef unsigned char      UCHAR;               // 1 byte
#endif
typedef          short      INT16;              // 2 byte
typedef unsigned short     UINT16;              // 2 byte
typedef          int        INT32;              // 4 byte
typedef unsigned int       UINT32;              // 4 byte
// --------------------------------------------------------------------------
#ifndef __OS2_H__       // os2.h defines it already
typedef          int        INT;                // 4 byte
typedef unsigned int       UINT;                // 4 byte
typedef          long       LONG;               // 4 byte
typedef unsigned long      ULONG;               // 4 byte
typedef          void       VOID;
#endif
#endif                                          // #if defined(__IBMC(PP)__)

//  the uSoft 16bit compiler family for DOS

#if defined(_MSC_VER)
typedef          char       CHAR;               // 1 byte
typedef unsigned char      UCHAR;               // 1 byte
typedef          int       INT16;               // 2 byte
typedef unsigned int       UINT16;              // 2 byte
typedef          long       INT32;              // 4 byte
typedef unsigned long      UINT32;              // 4 byte
// --------------------------------------------------------------------------
typedef          int        INT;                // 2 byte
typedef unsigned int       UINT;                // 2 byte
typedef          long       LONG;               // 4 byte
typedef unsigned long      ULONG;               // 4 byte
typedef          void       VOID;
#endif                                          // #if defined(_MSC_VER)

//  the Watcom 16/32bit compilers

#if defined(__WATCOMC__)
#ifndef __OS2_H__       // os2.h defines it already
typedef signed   char       CHAR;               // 1 byte
typedef unsigned char      UCHAR;               // 1 byte
#endif
typedef signed   short int  INT16;              // 2 byte
typedef unsigned short int UINT16;              // 2 byte
typedef signed   long  int  INT32;              // 4 byte
typedef unsigned long  int UINT32;              // 4 byte
// --------------------------------------------------------------------------
#ifndef __OS2_H__       // os2.h defines it already
typedef signed   int        INT;                // 2/4 byte
typedef unsigned int       UINT;                // 2/4 byte
typedef signed   long       LONG;               // 4 byte
typedef unsigned long      ULONG;               // 4 byte
typedef          void       VOID;
#endif
#endif                                          // #if defined(__WATCOMC__)

#ifdef __cplusplus
}
#endif

#endif                                          // #if !defined(_TYPESIZE_H)

