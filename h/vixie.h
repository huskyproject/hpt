/* vixie.h - include file to define general vixie-type things
 * v1.0 vix 21jun86 [broken out of as.h]
 */

#ifdef  DOCUMENTATION

There are two macros you can define before including this file which can
change the things defined by this file.

DEBUG:  if defined, will cause enter/exit messages to be printed by the
        ENTER/EXIT/EXITV macros.  If not defined, causes ENTER to do nothing,
        and EXIT/EXITV to generate 'return' without any messages.

        If defined, should be set to the name of the including module.

MAIN:   Should be defined for a program containing a main() function which
        is linked with other modules which include this file.

        Value is not important, only existence/nonexistence matters.

#endif  /*DOCUMENTATION*/


#ifndef _VIXIE_FLAG
#define _VIXIE_FLAG


                                                /*--- debugging stuff ---*/
#define MAXPROC 256

#ifdef DEBUG
#define ENTER(proc) { \
                        APC_PROCS[I_PROC] = proc; \
                        printf("ENTER(%d:%s.%s)\n", \
                                I_PROC, DEBUG, APC_PROCS[I_PROC]); \
                        I_PROC++; \
                }
#define EXIT(value) { \
                        I_PROC--; \
                        printf("EXIT(%d:%s.%s)\n", \
                                I_PROC, DEBUG, \
                                APC_PROCS[I_PROC]); \
                        return value; \
                }
#define EXITV { \
                        I_PROC--; \
                        printf("EXITV(%d:%s.%s)\n", \
                                I_PROC, DEBUG, \
                                APC_PROCS[I_PROC]); \
                        return value; \
                }
#else
#define ENTER(proc)
#define EXIT(value)     {return value;}
#define EXITV           return;
#endif

#ifdef MAIN
int     I_PROC = 0;
char    *APC_PROCS[MAXPROC];
#else
extern  int     I_PROC;
extern  char    *APC_PROCS[MAXPROC];
#endif


                        /*--- why didn't k&r put these into stdio.h? ---*/
#define TRUE            1
#define FALSE           0
#if !defined(__TURBOC__) && !defined(__IBMC__) && !defined(_AIX)
//extern  char            *malloc(), *calloc();
#endif


#endif /* _VIXIE_FLAG*/
