/*****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 *
 * hpt perl hooks interface by val khokhlov, 2:550/180@fidonet
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
/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _MSC_VER
#include <sys/wait.h>
#endif
#ifdef __OS2__
#define INCL_DOSPROCESS
#include <os2.h>
#endif

#ifdef _MSC_VER
#undef __STDC__
#include <sys/types.h>
#endif

#include <huskylib/compiler.h>
#include <huskylib/huskylib.h>

#if defined(__NT__) && !defined(WIN32) /* WIN32 needed for perl-core include files */
#  define WIN32
#endif


#include <fidoconf/common.h>
#include <huskylib/xstr.h>
#include <huskylib/crc.h>
#include <fidoconf/afixcmd.h>
#include <fidoconf/arealist.h>
#include <areafix/areafix.h>
int getPause(s_link* link) { return link->Pause & ECHOAREA; }

#include <fcommon.h>
#include <pkt.h>
#include <global.h>
#include <version.h>
#include <toss.h>
#include <hptperl.h>

#if defined(__cplusplus)
extern "C" {
#endif

#include <EXTERN.h>
#include <perl.h>
#ifdef _MSC_VER
# define NO_XSLOCKS
#endif
#ifndef _MSC_VER
# include <unistd.h>
#endif
#include <XSUB.h>
#ifdef _MSC_VER
# include "win32iop.h"
#endif
#if defined(__cplusplus)
}     /* extern "C" closed */
# ifndef EXTERN_C
#    define EXTERN_C extern "C"
#  endif
#else
#  ifndef EXTERN_C
#    define EXTERN_C extern
#  endif
#endif

/* perl prior to 5.6 support */
#ifndef get_sv
#define get_sv perl_get_sv
#endif
  
#ifndef newSVuv
#define newSVuv newSViv
#endif

#ifndef sv_undef
# define sv_undef PL_sv_undef
#endif

#ifndef min
# define min(a, b)      ((a) < (b) ? (a) : (b))
#endif

#ifdef __GNUC__
# define Perl___notused Perl___notused __attribute__ ((unused))
#endif

#ifndef LL_PERL
# define LL_PERL LL_EXEC
#endif

/* for alike */
#define MAX_LDIST_LEN      40 /*  max word len to compair */
#define ADDITION           1  /*  penality for needing to add a character */
#define CHANGE             1  /*  penality for needing to modify a character */
#define DELETION           1  /*  penality for needing to delete a character */
#define ALIKE              1
#define NOT_ALIKE          0
#define LENGTH_MISMATCH    32767
static int l_dist_list(char *key, char **list, char **match, int dist[], int match_limit, int *threshold);
static int l_dist_raw(char *str1, char *str2, int len1, int len2);

static PerlInterpreter *perl = NULL;
static int  do_perl=1;

/* val: to update perl vars */
static int  perl_vars_invalid = PERL_CONF_MAIN|PERL_CONF_LINKS|PERL_CONF_AREAS;

int skip_addvia = 0;			/* val: skip via adding */
int perl_setattr= 0;			/* val: perl manages msg attr */
int perl_subs   = -1;			/* val: defined subs */
#ifdef _MSC_VER
  EXTERN_C void xs_init (pTHXo);
  EXTERN_C void boot_DynaLoader (pTHXo_ CV* cv);
  EXTERN_C void perl_putMsgInArea(pTHXo_ CV* cv);
  EXTERN_C void perl_log(pTHXo_ CV* cv);
  EXTERN_C void perl_str2attr(pTHXo_ CV* cv);
  EXTERN_C void perl_myaddr(pTHXo_ CV* cv);
  EXTERN_C void perl_nodelistDir(pTHXo_ CV* cv);
  EXTERN_C void perl_crc32(pTHXo_ CV* cv);
  EXTERN_C void perl_alike(pTHXo_ CV* cv);
#endif

/* ----- val: some utility functions */
/* const for kludge processing */
typedef enum { MODE_NOADD=0, MODE_REPLACE=1, MODE_SMART=2, MODE_UPDATE=3 } mmode_t;
/* flag names */
char *flag_name[] = { "PVT", "CRA", "RCV", "SNT", "ATT", "TRS", "ORP", "K/S", 
                      "LOC", "HLD", "RSV", "FRQ", "RRQ", "RRC", "ARQ", "URQ",
                      /* flags in ^aFLAGS */
                      "A/S", "DIR", "ZON", "HUB", "IMM", "XMA", "KFS", "TFS",
                      "LOK", "CFM", "HIR", "COV", "SIG", "LET" };
int reuse_line(char **ptext, char *pos, mmode_t mode);
/* flag to flavour */
static e_flavour flag2flv(unsigned long attr) {
  if (attr & 0x100000) return immediate;
  else if ((attr & 0x20000) || (attr & 0x202) == 0x202) return direct;
  else if (attr & 0x200) return hold;
  else if (attr & 2) return crash;
  else return normal;
}
/* flavour to flag */
static unsigned long flv2flag(e_flavour flv) {
  switch (flv) {
    case immediate: return 0x100000;
    case direct:    return 0x20000;
    case hold:      return 0x200;
    case crash:     return 2;
    default:        return 0;
  }
}
/* flavour to string */
static char* flv2str(e_flavour flv) {
  switch (flv) {
    case immediate: return "immediate";
    case direct:    return "direct";
    case hold:      return "hold";
    case crash:     return "crash";
    default:        return "normal";
  }
}
/* smart string flavour parsing */
static e_flavour str2flv(char *flv) {
struct flv_data_s { e_flavour f; char c; char *s1; char *s2; };
const struct flv_data_s flv_data[] = { { normal, 'n', "norm", "normal" },
                                       { hold, 'h', "hld", "hold" },
                                       { crash, 'c', "cra", "crash" },
                                       { direct, 'd', "dir", "direct" },
                                       { immediate, 'i', "imm", "immediate" } 
                                     };
register unsigned char i;
   for (i = 0; i < sizeof(flv_data)/sizeof(flv_data[0]); i++)
      if ( ((*flv | 0x20) == flv_data[i].c) && (flv[1] == '\0') ) return flv_data[i].f;
   for (i = 0; i < sizeof(flv_data)/sizeof(flv_data[0]); i++)
      if (stricmp(flv, flv_data[i].s1) == 0 ||
          stricmp(flv, flv_data[i].s2) == 0) return flv_data[i].f;
   return -1;
}
/* fts1 date to unixtime, 0 on failure */
static time_t fts2unix(const char *s, int *ret) {
struct tm tm;
int flags;
char ss[32];
  strncpy(ss, s, sizeof(ss)-1); ss[sizeof(ss)-1] = '\0';
  flags = parse_ftsc_date(&tm, ss);
  tm.tm_isdst = -1;
  /* free(ss); */
  if (ret != NULL) *ret = flags;
  return (flags & FTSC_BROKEN) ? 0 : mktime(&tm);
}
/* parse ^aflags into corresponding mask */
static unsigned long parse_flags(const char *s) {
register unsigned char i;
register char *flgs;
register unsigned long attr = 0UL;
  flgs = strstr(s, "\001FLAGS ");
  if (flgs == NULL || (flgs != s && *(flgs-1) != '\r')) return 0;
  flgs += 7;
  while (*flgs && *flgs != '\r') {
    while (*flgs == ' ' || *flgs == '\t') flgs++;
    for (i = 16; i < sizeof(flag_name)/sizeof(flag_name[0]); i++)
      if (memcmp(flgs, flag_name[i], 3) == 0) attr |= (1UL<<i);
    while (*flgs && *flgs != '\r' && *flgs != ' ' && *flgs != '\t') flgs++;
  }
  return attr;
}
/* make ^aflags value from flags */
static char* make_flags(const unsigned long attr) {
register unsigned char i;
char *flgs = NULL;
  for (i = 16; i < sizeof(flag_name)/sizeof(flag_name[0]); i++)
      if (attr & (1<<i)) xscatprintf(&flgs, " %s", flag_name[i]);
  return flgs;
}
/* update ^aflags only if binary flags differ from kludge, return new text
   if mode == MODE_SMART then it's ok when (kludge=>attr) == 1 */
static char* update_flags(char *s, const unsigned long a,
                          mmode_t mode) {
register unsigned long klattr, attr;
char *news = NULL, *flags, *pos, ch;
  klattr = parse_flags(s) & 0xffff0000UL;
  attr = a & 0xffff0000UL;
  if ((mode == MODE_REPLACE && klattr != attr) ||
      (mode == MODE_SMART && ((klattr ^ attr) & ~klattr))) {
    reuse_line(&s, pos = strstr(s, "\001FLAGS "), MODE_REPLACE);
    if (!attr) return s;
    flags = make_flags(mode == MODE_REPLACE ? attr : attr | klattr);
    if (flags == NULL) return s;
    /* try to insert ^aflags to the same place or to the end of kludges */
    if (pos == NULL) {
      pos = s;
      if (strncmp(pos, "AREA:", 5) == 0) while (*pos && *(pos++) != '\r');
      while (*pos) 
        if (*pos == '\001') while (*pos && *(pos++) != '\r'); else break;
    }
    ch = *pos; *pos = '\0';

    /* xscatprintf(&news, "\001FLAGS%s\r%s", flags, s); */
    if (pos != s) xscatprintf(&news, "%s\r\001FLAGS%s\r", s, flags);
      else  xscatprintf(&news, "\001FLAGS%s\r", flags);
    if (ch != '\0') { *pos = ch; xscatprintf(&news, "%s", pos); }
    free(flags);
    return news;
  }
  else return NULL;
}
/* insert a line into message to the specified place */
static void insert_line(char **s, char *sub, char *pos) {
char ch, *news = NULL;
  if (pos == NULL) {
    pos = *s;
    if (strncmp(pos, "AREA:", 5) == 0) while (*pos && *(pos++) != '\r');
  }
  ch = *pos; *pos = '\0';
  xscatprintf(&news, "%s%s", *s, sub);
  if (ch != '\0') { *pos = ch; xscatprintf(&news, "%s", pos); }
  free(*s); *s = news;
}
/* update addresses: ^aintl, ^afmpt, ^atopot */
static void update_addr(s_message *msg) {
char *intl = NULL, *topt = NULL, *fmpt = NULL, *pos = NULL;
  xscatprintf(&intl, "\001INTL %u:%u/%u %u:%u/%u\r",
              msg->destAddr.zone, msg->destAddr.net, msg->destAddr.node,
              msg->origAddr.zone,  msg->origAddr.net,  msg->origAddr.node);
  if (msg->destAddr.point) {
    xscatprintf(&topt, "\001TOPT %d\r", msg->destAddr.point);
    if (strstr(msg->text, topt) == NULL) {
      reuse_line(&(msg->text), pos = strstr(msg->text, "\001TOPT "), MODE_REPLACE);
      insert_line(&(msg->text), topt, pos);
    }
  }
  if (msg->origAddr.point) {
    xscatprintf(&fmpt, "\001FMPT %d\r", msg->origAddr.point);
    if (strstr(msg->text, fmpt) == NULL) {
      reuse_line(&(msg->text), pos = strstr(msg->text, "\001FMPT "), MODE_REPLACE);
      insert_line(&(msg->text), fmpt, pos);
    }
  }
  pos = strstr(msg->text, "\001INTL ");
  if (strstr(msg->text, intl) == NULL && pos != NULL) {
    reuse_line(&(msg->text), pos, MODE_REPLACE);
    insert_line(&(msg->text), intl, pos);
  }
  msg->textLength = strlen(msg->text);
}
/* ---- /val */

#ifdef _MSC_VER
  EXTERN_C void perl_log(pTHXo_ CV* cv)
#else
  static XS(perl_log)
#endif
{
  dXSARGS;
  char *level, *str, lvl;
  STRLEN n_a;

  unused(cv);
  unused(my_perl);

  if (items != 1 && items != 2)
  { w_log(LL_ERR, "wrong params number to log (need 1 or 2, exist %d)", items);
    XSRETURN_EMPTY;
  }
  if (items == 2) {
    level = (char *)SvPV(ST(0), n_a); if (n_a == 0) level = "";
    lvl   = *level;
    str   = (char *)SvPV(ST(1), n_a); if (n_a == 0) str   = "";
  } else {
    lvl   = LL_PERL;
    str   = (char *)SvPV(ST(0), n_a); if (n_a == 0) str   = "";
  }
  w_log(lvl, "%s", str);
  XSRETURN_EMPTY;
}

int l_dist_list(char *key,
                char **list,
                char **match,
                int dist[],
                int match_limit,
                int *threshold)
{
   int i, j, k, key_len, l_dist, len, num;
   key_len = strlen(key);
   key_len = min(key_len, MAX_LDIST_LEN);
   *threshold = 1 + ((key_len + 2) / 4);
   num = 0;
   for (k=0; list[k][0]; k++)
   {
      len = strlen(list[k]);
      len = min(len, MAX_LDIST_LEN);
      if (abs(key_len-len) <= *threshold)
      {
         /*  calculate the distance */
         l_dist = l_dist_raw(key, list[k], key_len, len);
         /*  is this acceptable? */
         if (l_dist <= *threshold)        /*  is it in range to consider */
         {
            /*  search the list to see where we should insert this result */
            for (i=j=0; i<num && !j; )
               if (l_dist < dist[i])
                  j = 1;
               else
                  i++;        /*  do not increment when we find a match */
            /*  i points to the next higher valued result if j=1, otherwise */
            /*  i points to the end of the list, insert at i if in range */
            /*  found a higher valued (worse) result or list not full */
            if (j || i < match_limit-1)
            {                             /*  insert in front of higher results */
               for (j=min(match_limit-2,num-1); j>=i; j--)
               {
                  match[j+1] = match[j];
                  dist[j+1]  = dist[j];
               }
               match[i] = list[k];
               dist[i]  = l_dist;
               if (num < match_limit) num++;
            }
         }  /*  if l_dist <= threshold */
      }  /*  if len diff <= threshold */
   }  /*  for k */
   return(num);
}
#define SMALLEST_OF(x,y,z)       ( (x<y) ? min(x,z) : min(y,z) )
#define ZERO_IF_EQUAL(ch1,ch2)   ( (ch1==ch2) ? 0 : CHANGE )
static int l_dist_raw(char *str1, char *str2, int len1, int len2)
{
   register int i, j;
   unsigned int dist_im1[MAX_LDIST_LEN+1];
   unsigned int dist_i_j=0, dist_i_jm1, dist_j0;
   char *p1, *p2;
   for (i=1, dist_im1[0]=0; i<=MAX_LDIST_LEN; i++)
      dist_im1[i] = dist_im1[i-1] + ADDITION;
   dist_j0 = 0;

   for (i=1, p1=str1; i<=len1; i++, p1++)
   {
      dist_i_jm1 = dist_j0 += DELETION;
      for (j=1, p2=str2; j<=len2; j++, p2++)
      {
         dist_i_j = SMALLEST_OF(dist_im1[j-1] + ZERO_IF_EQUAL(*p1, *p2),
                                dist_i_jm1    + ADDITION,
                                dist_im1[j]   + DELETION );
         dist_im1[j-1] = dist_i_jm1;
         dist_i_jm1 = dist_i_j;
      }
      dist_im1[j] = dist_i_j;
   }
   return(dist_i_j);
}

#ifdef _MSC_VER
EXTERN_C void perl_alike(pTHXo_ CV* cv)
#else
static XS(perl_alike)
#endif
{
  /* calculate length from word to word by Levenshtein algorythm
     0 - words matching
  */
  dXSARGS;
  char * str1;
  char * str2;
  int len1,len2,threshold,ldist;
  STRLEN n_a;

  unused(cv);
  unused(my_perl);

  if (items!=2)
  {
    w_log(LL_ERR,"wrong number of params to alike(need 2, exist %d)", items);
    XSRETURN_EMPTY;
  }
  str1=(char *)SvPV(ST(0),n_a);if (n_a==0) str1="";
  str2=(char *)SvPV(ST(1),n_a);if (n_a==0) str2="";
  len1 = strlen(str1);
  len2 = strlen(str2);
  threshold = 1 + ((len1 + 2) / 4);
  ldist = LENGTH_MISMATCH;
  len1 = min(len1, MAX_LDIST_LEN);
  len2 = min(len2, MAX_LDIST_LEN);
  ldist = l_dist_raw(str1, str2, len1, len2);
  XSRETURN_IV(ldist);
}
/* val: better create_kludges :) */
void copy_line(char **dest, char *s) {
char *pos;
int len;
    pos = strchr(s, '\r');
    len = (pos != NULL) ? pos-s : strlen(s);
    if (pos != NULL) *pos = 0;
    xscatprintf(dest, "%s\r", s);
    if (pos != NULL) *pos = '\r';
}

int reuse_line(char **ptext, char *pos, mmode_t mode) {
char *pos2;
int  len, frg;
    /* not found - add */
    if (pos == NULL) return 0;
    /* found, but not at the line start - add */
    else if (pos != *ptext && *(pos-1) != '\r') return 0;
    /* found and keep - don't add */
    if (mode != MODE_REPLACE) return 1;
    /* found and replace - delete, then add */
    pos2 = strchr(pos, '\r');
    if (pos2 != NULL) {
        frg = ++pos2 - pos; len = strlen(pos2);
        memcpy(pos, pos2, len+1);
    }
    else *pos = 0;
    return 0;
}

char *create_kludges(s_message *msg, char **ptext, char *area, long attr, 
                     mmode_t mode)
{
char *buff = NULL;
char *flgs = NULL;
char *pos, *text = *ptext, *pos2;
int i;
unsigned long msgid;
   /* echomail */
   if (area) {
       pos = strstr(text, "AREA:");
       if (reuse_line(ptext, pos, mode)) ;/*copy_line(&buff, pos);*/
         else xscatprintf(&buff, "AREA:%s\r", area);
   }
   /* netmail */
   else {
      pos = strstr(text, "\001INTL ");
      if (reuse_line(ptext, pos, mode)) ;/*copy_line(&buff, pos);*/
      else
	   xscatprintf(&buff, "\001INTL %u:%u/%u %u:%u/%u\r",
			   msg->destAddr.zone, msg->destAddr.net, msg->destAddr.node,
			   msg->origAddr.zone,  msg->origAddr.net,  msg->origAddr.node);

      pos = strstr(text, "\001FMPT ");
      if (reuse_line(ptext, pos, mode)) ;/*copy_line(&buff, pos);*/
      else if (msg->origAddr.point) xscatprintf(&buff, "\001FMPT %d\r", msg->origAddr.point);

      pos = strstr(text, "\001TOPT ");
      if (reuse_line(ptext, pos, mode)) ;/*copy_line(&buff, pos);*/
      if (msg->destAddr.point) xscatprintf(&buff, "\001TOPT %d\r", msg->destAddr.point);

      pos = strstr(text, "\001FLAGS ");
      if (reuse_line(ptext, pos, mode)) { 
          copy_line(&flgs, pos+6); *(pos2 = strchr(flgs, '\r')) = 0;
          reuse_line(ptext, pos, MODE_REPLACE);
      }
      if (attr & 0xffff0000UL) {
          for (i = 16; i < sizeof(flag_name)/sizeof(flag_name[0]); i++) {
              if ((attr & (1<<i)) && (flgs == NULL || strstr(flgs, flag_name[i]) == NULL)) 
                  xscatprintf(&flgs, " %s", flag_name[i]);
          }
      }
      if (flgs != NULL) { xscatprintf(&buff, "\001FLAGS%s\r", flgs); free(flgs); }
   }
   /* msgid */
   pos = strstr(text, "\001MSGID: ");
   if (reuse_line(ptext, pos, mode)) ;/*copy_line(&buff, pos);*/
   else {
       msgid = GenMsgId(config->seqDir, config->seqOutrun);
       if (msg->origAddr.point)
          xscatprintf(&buff, "\001MSGID: %u:%u/%u.%u %08lx\r",
                  msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node,
                  msg->origAddr.point, msgid);
       else
          xscatprintf(&buff, "\001MSGID: %u:%u/%u %08lx\r",
                  msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node,
                  msgid);
   }
   /* tid */
   pos = strstr(text, "\001TID: ");
   if (reuse_line(ptext, pos, mode)) ;/*copy_line(&buff, pos);*/
   else if (!config->disableTID) xscatprintf(&buff, "\001TID: %s\r", versionStr);

   return buff;
}

/* val: end */
#ifdef _MSC_VER
EXTERN_C void perl_putMsgInArea(pTHXo_ CV* cv)
#else
static XS(perl_putMsgInArea)
#endif
{
  dXSARGS;
  char *area, *fromname, *toname, *fromaddr, *toaddr;
  char *subject, *sdate = NULL, *sattr = NULL, *text;
  long attr = -1L, date = 0;
  int  addkludges;
  char *p;
  STRLEN n_a;
  UINT narea, rc;
  s_area *echo;
  s_message msg;

  unused(cv);
  unused(my_perl);

  if (items != 9 && items != 10)
  { w_log(LL_ERR, "wrong params number to putMsgInArea (need 9 or 10, exist %d)", items);
    XSRETURN_PV("Invalid arguments");
  }
  area     = (char *)SvPV(ST(0), n_a); if (n_a == 0) area     = "";
  fromname = (char *)SvPV(ST(1), n_a); if (n_a == 0) fromname = "";
  toname   = (char *)SvPV(ST(2), n_a); if (n_a == 0) toname   = "";
  fromaddr = (char *)SvPV(ST(3), n_a); if (n_a == 0) fromaddr = "";
  toaddr   = (char *)SvPV(ST(4), n_a); if (n_a == 0) toaddr   = "";
  subject  = (char *)SvPV(ST(5), n_a); if (n_a == 0) subject  = "";
  if (SvTYPE(ST(6)) == SVt_PV) {
     sdate = (char *)SvPV(ST(6), n_a); if (n_a == 0) sdate    = "";
  } else date = SvUV(ST(6));
  if (SvTYPE(ST(7)) == SVt_PV) {
     sattr = (char *)SvPV(ST(7), n_a); if (n_a == 0) sattr    = "";
  } else attr = SvUV(ST(7));
  text     = (char *)SvPV(ST(8), n_a); if (n_a == 0) text     = "";
  /*addkludges = SvTRUE(ST(9));*/
  addkludges = (items > 9) ? SvIV(ST(9)) : MODE_SMART;

  memset(&msg, '\0', sizeof(msg));
#if 0
  echo = getArea(config, area);
  if (echo == NULL)
    XSRETURN_PV("Unknown area");
#else
  echo = NULL;
  if (!area || !*area)
  { echo=&(config->netMailAreas[0]);
    msg.netMail = 1;
  }
  for (narea=0; narea < config->echoAreaCount && !echo; narea++) {
    if (stricmp(area, config->echoAreas[narea].areaName)==0) {
      echo = &(config->echoAreas[narea]);
    }
  }
  for (narea=0; narea < config->localAreaCount && !echo; narea++) {
    if (stricmp(area, config->localAreas[narea].areaName)==0) {
      echo = &(config->localAreas[narea]);
      if (toaddr && *toaddr)
        msg.netMail = 1;
    }
  }
  for (narea=0; narea < config->netMailAreaCount && !echo; narea++) {
    if (stricmp(area, config->netMailAreas[narea].areaName)==0) {
      echo = &(config->netMailAreas[narea]);
      msg.netMail = 1;
    }
  }
  if (echo == NULL)
    XSRETURN_PV("Unknown area");
#endif
  if (fromaddr && *fromaddr)
    string2addr(fromaddr, &(msg.origAddr));
  else
    memcpy(&msg.origAddr, echo->useAka, sizeof(msg.origAddr));
  if (msg.netMail)
    string2addr(toaddr, &(msg.destAddr));

  if (!sdate || !*sdate)
  { time_t t = (date != 0) ? (time_t)date : time(NULL);
    fts_time((char *)msg.datetime, localtime(&t));
  }
  else
  { strncpy(msg.datetime, sdate, sizeof(msg.datetime));
    msg.datetime[sizeof(msg.datetime)-1] = '\0';
  }

  msg.subjectLine = safe_strdup(subject);
  msg.toUserName  = safe_strdup(toname);
  msg.fromUserName= safe_strdup(fromname);
  text = safe_strdup(text);

  if (attr != -1) msg.attributes = (dword) (attr & 0xffff);
  else if (sattr && *sattr) {
      sattr=safe_strdup(sattr);
      for (p=strtok(sattr, " "); p; p=strtok(NULL, " "))
      { dword _attr;
        if ((_attr = str2attr(p)) != (dword)-1)
          msg.attributes |= _attr;
      }
      free(sattr);
  }

  if ( !strstr(text, "\r\n") ) for (p = text; (p = strchr(p, '\n')); *p = '\r');
  else {
    int len = strlen(p = text);
    while ( (p = strchr(p, '\n')) )
      if (p > text && *(p-1) == '\r') memmove(p, p+1, (len--)-(p-text));
      else *p = '\r';
  }
  if (addkludges == MODE_UPDATE) {
    char *text2 = (attr != -1) ? update_flags(text, attr, MODE_REPLACE) : NULL;
    msg.text = (text2 != NULL) ? text2 : text;
    if (msg.text != text) nfree(text);
    update_addr(&msg);
  }
  else if (addkludges != MODE_NOADD) {
    msg.text = create_kludges(&msg, &text, msg.netMail ? NULL : area, attr, addkludges);
    xstrcat((char **)(&(msg.text)), text);
    nfree(text);
  }
  else msg.text = text;

  msg.textLength = strlen(msg.text);
  rc = putMsgInArea(echo, &msg, 1, msg.attributes);
  freeMsgBuffers(&msg);
  if (rc)
    XSRETURN_UNDEF;
  else
    XSRETURN_PV("Unable to post message");
}

#ifdef _MSC_VER
EXTERN_C void perl_str2attr(pTHXo_ CV* cv)
#else
static XS(perl_str2attr)
#endif
{
  dXSARGS;
  char *attr;
  STRLEN n_a;

  unused(cv);
  unused(my_perl);

  w_log(LL_WARN, "str2attr() deprecated, use numeric attributes instead");
  if (items != 1)
  { w_log(LL_ERR, "wrong params number to str2attr (need 1, exist %d)", items);
    XSRETURN_IV(-1);
  }
  attr = (char *)SvPV(ST(0), n_a); if (n_a == 0) attr = "";
  XSRETURN_IV(str2attr(attr));
}
#ifdef _MSC_VER
EXTERN_C void perl_attr2str(pTHXo_ CV* cv)
#else
static XS(perl_attr2str)
#endif
{
  dXSARGS;
  char *s = NULL, buf[4];
  register unsigned char i = 0;
  register unsigned long attr;

  unused(cv);
  unused(my_perl);

  if (items != 1)
  { w_log(LL_ERR, "wrong params number to attr2str (need 1, exist %d)", items);
    XSRETURN_UNDEF;
  }
  attr = SvUV(ST(0));
  for (i = 0; i < sizeof(flag_name)/sizeof(flag_name[0]); i++)
    if (attr & (1UL<<i)) { 
      memcpy(buf, flag_name[i], 4); strLower(buf+1);
      xstrscat(&s, " ", buf, NULL); 
    }
  XSRETURN_PV(s == NULL ? "" : s+1);
}
#ifdef _MSC_VER
EXTERN_C void perl_flv2str(pTHXo_ CV* cv)
#else
static XS(perl_flv2str)
#endif
{
  dXSARGS;

  unused(cv);
  unused(my_perl);

  if (items != 1)
  { w_log(LL_ERR, "wrong params number to flv2str (need 1, exist %d)", items);
    XSRETURN_UNDEF;
  }
  XSRETURN_PV( flv2str( flag2flv(SvUV(ST(0))) ) );
}

#ifdef _MSC_VER
EXTERN_C void perl_fts_date(pTHXo_ CV* cv)
#else
static XS(perl_fts_date)
#endif
{
  dXSARGS;
  char *date;
  time_t t;
  STRLEN n_a;

  unused(cv);
  unused(my_perl);

  w_log(LL_WARN, "fts_date() deprecated, use numeric unixtime instead");
  if (items != 1)
  { w_log(LL_ERR, "wrong params number to fts_date (need 1, exist %d)", items);
    XSRETURN_UNDEF;
  }
  date = (char *)SvPV(ST(0), n_a); 
  if (!n_a || !(t = fts2unix(date, NULL))) XSRETURN_UNDEF;
    else XSRETURN_IV( (unsigned long)t );
}

#ifdef _MSC_VER
EXTERN_C void perl_date_fts(pTHXo_ CV* cv)
#else
static XS(perl_date_fts)
#endif
{
  dXSARGS;
  time_t t;
  char date[21];
  struct tm *tm;

  unused(cv);
  unused(my_perl);

  w_log(LL_WARN, "date_fts() deprecated, use numeric unixtime instead");
  if (items != 1)
  { w_log(LL_ERR, "wrong params number to date_fts (need 1, exist %d)", items);
    XSRETURN_UNDEF;
  }
  t = (time_t)SvUV(ST(0));
  tm = localtime(&t);
  make_ftsc_date(date, tm);
  XSRETURN_PV(date);
}

#ifdef _MSC_VER
EXTERN_C void perl_myaddr(pTHXo_ CV* cv)
#else
static XS(perl_myaddr)
#endif
{
  UINT naddr;
  dXSARGS;

  unused(cv);
  unused(my_perl);

  w_log(LL_WARN, "myaddr() deprecated, use @{$config{addr}} instead");
  if (items != 0)
  { w_log(LL_ERR, "wrong params number to myaddr (need 0, exist %d)", items);
    XSRETURN_UNDEF;
  }
  EXTEND(SP, (int)config->addrCount);
  for (naddr=0; naddr<config->addrCount; naddr++)
  {
    ST(naddr) = sv_newmortal();
    sv_setpv((SV*)ST(naddr), aka2str(config->addr[naddr]));
  }
  XSRETURN(naddr);
}
#ifdef _MSC_VER
EXTERN_C void perl_nodelistDir(pTHXo_ CV* cv)
#else
static XS(perl_nodelistDir)
#endif
{
  dXSARGS;

  unused(cv);
  unused(my_perl);

  w_log(LL_WARN, "nodelistDir() deprecated, use $config{nodelistDir} instead");
  if (items != 0)
  { w_log(LL_ERR, "wrong params number to nodelistDir (need 0, exist %d)", items);
    XSRETURN_UNDEF;
  }
  EXTEND(SP, 1);
  XSRETURN_PV(config->nodelistDir ? config->nodelistDir : "");
}


#ifdef _MSC_VER
EXTERN_C void perl_crc32(pTHXo_ CV* cv)
#else
static XS(perl_crc32)
#endif
{
  dXSARGS;
  STRLEN n_a;
  char *str;

  unused(cv);
  unused(my_perl);

  if (items != 1)
  { w_log(LL_ERR, "wrong params number to crc32 (need 1, exist %d)", items);
    XSRETURN_IV(0);
  }
  str = (char *)SvPV(ST(0), n_a);
  XSRETURN_IV(memcrc32(str, n_a, 0xFFFFFFFFul));
}

#ifdef _MSC_VER
EXTERN_C void perl_mktime(pTHXo_ CV* cv)
#else
static XS(perl_mktime)
#endif
{
  dXSARGS;
  struct tm tm;

  unused(cv);
  unused(my_perl);

  if (items < 6 || items > 9)
  { w_log(LL_ERR, "wrong params number to mktime (need 6 to 9, exist %d)", items);
    XSRETURN_UNDEF;
  }
  tm.tm_sec  = SvUV(ST(0));
  tm.tm_min  = SvUV(ST(1));
  tm.tm_hour = SvUV(ST(2));
  tm.tm_mday = SvUV(ST(3));
  tm.tm_mon  = SvUV(ST(4));
  tm.tm_year = SvUV(ST(5)); 
  if (tm.tm_year < 70) tm.tm_year += 100;
  else if (tm.tm_year > 1900) tm.tm_year -= 1900;
  tm.tm_wday  = (items > 6) ? SvIV(ST(6)) : -1;
  tm.tm_yday  = (items > 7) ? SvIV(ST(7)) : -1;
  tm.tm_isdst = -1/*(items > 8) ? SvIV(ST(8)) : -1*/;
  XSRETURN_IV( mktime(&tm) );
}

#ifdef _MSC_VER
EXTERN_C void perl_strftime(pTHXo_ CV* cv)
#else
static XS(perl_strftime)
#endif
{
  dXSARGS;
  struct tm tm;
  char buf[64];
  STRLEN n_a;

  unused(cv);
  unused(my_perl);

  if (items != 1 && items != 2 && (items < 7 || items > 10))
  { w_log(LL_ERR, "wrong params number to strftime (need 1, 2, 7..10, exist %d)", items);
    XSRETURN_UNDEF;
  }
  if (items > 2) {
    tm.tm_sec  = SvUV(ST(1));
    tm.tm_min  = SvUV(ST(2));
    tm.tm_hour = SvUV(ST(3));
    tm.tm_mday = SvUV(ST(4));
    tm.tm_mon  = SvUV(ST(5));
    tm.tm_year = SvUV(ST(6)); 
    if (tm.tm_year < 70) tm.tm_year += 100;
    else if (tm.tm_year > 1900) tm.tm_year -= 1900;
    tm.tm_wday  = (items > 7) ? SvIV(ST(8)) : -1;
    tm.tm_yday  = (items > 8) ? SvIV(ST(9)) : -1;
    tm.tm_isdst = -1 /*(items > 9) ? -1 SvIV(ST(10)) : -1*/;
    mktime(&tm); /* make it valid */
    strftime(buf, sizeof(buf), SvPV(ST(0), n_a), &tm);
  } else { 
    time_t t = (items == 2) ? (time_t)SvUV(ST(1)) : time(NULL);
    strftime(buf, sizeof(buf), SvPV(ST(0), n_a), localtime(&t));
  }
  XSRETURN_PV(buf);
}

#ifdef _MSC_VER
EXTERN_C void perl_gmtoff(pTHXo_ CV* cv)
#else
static XS(perl_gmtoff)
#endif
{
  dXSARGS;
  struct tm loc, gmt;
  double offs;
  time_t t;

  unused(cv);
  unused(my_perl);

  if (items > 1)
  { w_log(LL_ERR, "wrong params number to gmtoff (need 0 or 1, exist %d)", items);
    XSRETURN_UNDEF;
  }
  if (items) t = (time_t)SvUV(ST(0)); else t = time(NULL);
  memcpy(&loc, localtime(&t), sizeof(loc));
  memcpy(&gmt, gmtime(&t), sizeof(gmt));
  offs = loc.tm_hour-gmt.tm_hour;
  if (offs > 12) offs -= 24; else if (offs < -12) offs += 24;
  if (loc.tm_min != gmt.tm_min) offs = offs + (double)(loc.tm_min-gmt.tm_min)/60;
  XSRETURN_NV(offs);
}

void perl_warn_str (char* str) {
  while (str && *str) {
    char* cp = strchr (str, '\n');
    char  c  = 0;
    if (cp) { c = *cp; *cp = 0; }
    w_log (LL_PERL, "PERL: %s", str);
    if (cp) *cp = c;
    else break;
    str = cp + 1;
  }
}
void perl_warn_sv (SV* sv) {
  STRLEN n_a;
  char * str = (char *) SvPV (sv, n_a);
  perl_warn_str (str);
}
#ifdef _MSC_VER
EXTERN_C void perl_warn(pTHXo_ CV* cv)
#else
static XS(perl_warn)
#endif
{
  dXSARGS;

  unused(cv);
  unused(my_perl);

  if (items == 1) perl_warn_sv (ST(0));
  XSRETURN_EMPTY;
}

#ifdef _MSC_VER
EXTERN_C void boot_DynaLoader (pTHXo_ CV* cv);
#else
XS(boot_DynaLoader);
void boot_DB_File(CV *cv);
void boot_Fcntl(CV *cv);
void boot_POSIX(CV *cv);
void boot_SDBM_File(CV *cv);
void boot_IO(CV *cv);
void boot_OS2__Process(CV *cv);
void boot_OS2__ExtAttr(CV *cv);
void boot_OS2__REXX(CV *cv);
#endif

#ifdef _MSC_VER
EXTERN_C void xs_init (pTHXo)
#else
#ifdef pTHXo
static void xs_init(pTHXo)
#else
static void xs_init(void)
#endif
#endif
{
  static char *file = __FILE__;

  unused(my_perl);

#ifndef DO_HPM
#if defined(__OS2__)
  newXS("DB_File::bootstrap", boot_DB_File, file);
  newXS("Fcntl::bootstrap", boot_Fcntl, file);
  newXS("POSIX::bootstrap", boot_POSIX, file);
  newXS("SDBM_File::bootstrap", boot_SDBM_File, file);
  newXS("IO::bootstrap", boot_IO, file);
  newXS("OS2::Process::bootstrap", boot_OS2__Process, file);
  newXS("OS2::ExtAttr::bootstrap", boot_OS2__ExtAttr, file);
  newXS("OS2::REXX::bootstrap", boot_OS2__REXX, file);
#else
  dXSUB_SYS;
#endif
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
#endif	/* !DO_HPM */
  newXS("w_log", perl_log, file);
  newXS("putMsgInArea",  perl_putMsgInArea,  file);
  newXS("str2attr",      perl_str2attr,      file);
  newXS("myaddr",        perl_myaddr,        file);
  newXS("nodelistDir",   perl_nodelistDir,   file);
  newXS("crc32",         perl_crc32,         file);
  newXS("alike",         perl_alike,         file);
  newXS("date_fts",      perl_date_fts,      file);
  newXS("fts_date",      perl_fts_date,      file);
  newXS("mktime",        perl_mktime,        file);
  newXS("strftime",      perl_strftime,      file);
  newXS("gmtoff",        perl_gmtoff,        file);
  newXS("flv2str",       perl_flv2str,       file);
  newXS("attr2str",      perl_attr2str,      file);
  newXS("hpt_warn",      perl_warn,          file);
}

/* mark a part of current config as invalid in order to update it */
void perl_invalidate(e_perlconftype confType) { perl_vars_invalid |= confType; }
/* set %config, %links */
void perl_setvars(void) {
   UINT i, j;
   struct sv 		*sv;
   struct hv 		*hv, *hv2, *hv3;
   struct av 		*av;

   if (!do_perl || perl == NULL) return;
   w_log( LL_FUNC, "perl.c::perl_setvars()" );

#define VK_ADD_HASH_sv(_hv,_sv,_name)                  \
    if (_sv != NULL) {                                 \
      SvREADONLY_on(_sv);                              \
      hv_store(_hv, _name, strlen(_name), _sv, 0);     \
    }
#define VK_ADD_HASH_str(_hv,_sv,_name,_value)                            \
    if ( (_value != NULL) && (_sv = newSVpv(_value, 0)) != NULL ) {      \
      SvREADONLY_on(_sv);                                                \
      hv_store(_hv, _name, strlen(_name), _sv, 0);                       \
    }
#define VK_ADD_HASH_intz(_hv,_sv,_name,_value)                           \
    if ( (_sv = newSViv(_value)) != NULL ) {                             \
      SvREADONLY_on(_sv);                                                \
      hv_store(_hv, _name, strlen(_name), _sv, 0);                       \
    }
#define VK_ADD_HASH_int(_hv,_sv,_name,_value)                            \
    if (_value) {                                                        \
      VK_ADD_HASH_intz(_hv,_sv,_name,_value)                             \
    } else {                                                             \
      VK_ADD_HASH_intz(_hv,_sv,_name,0)                                  \
    }

   /* set main config */
   if (perl_vars_invalid & PERL_CONF_MAIN) {

     w_log( LL_SRCLINE, "%s:%d setting Perl variables (main)", __FILE__, __LINE__);

     if ((sv = get_sv("hpt_ver", TRUE)) != NULL) {
       char *vers = NULL;
       xscatprintf(&vers, "hpt %u.%u.%u", VER_MAJOR, VER_MINOR, VER_PATCH);
       #ifdef __linux__
          xstrcat(&vers, "/lnx");
       #elif defined(__FreeBSD__) || defined(__NetBSD__)
          xstrcat(&vers, "/bsd");
       #elif defined(__OS2__) || defined(OS2)
          xstrcat(&vers, "/os2");
       #elif defined(__NT__)
          xstrcat(&vers, "/w32");
       #elif defined(__sun__)
          xstrcat(&vers, "/sun");
       #elif defined(MSDOS)
          xstrcat(&vers, "/dos");
       #elif defined(__BEOS__)
          xstrcat(&vers, "/beos");
       #endif
       SvREADONLY_off(sv); sv_setpv(sv, vers); SvREADONLY_on(sv);
     }
     if ((sv = get_sv("hpt_version", TRUE)) != NULL) {
       SvREADONLY_off(sv); sv_setpv(sv, versionStr); SvREADONLY_on(sv);
     }
     hv = perl_get_hv("config", TRUE); 
     SvREADONLY_off(hv); hv_clear(hv);
     VK_ADD_HASH_str(hv, sv, "inbound", config->inbound);
     VK_ADD_HASH_str(hv, sv, "protInbound", config->protInbound);
     VK_ADD_HASH_str(hv, sv, "localInbound", config->localInbound);
     VK_ADD_HASH_str(hv, sv, "outbound", config->outbound);
     VK_ADD_HASH_str(hv, sv, "name", config->name);
     VK_ADD_HASH_str(hv, sv, "sysop", config->sysop);
     VK_ADD_HASH_str(hv, sv, "origin", config->origin);
     VK_ADD_HASH_str(hv, sv, "logDir", config->logFileDir);
     VK_ADD_HASH_str(hv, sv, "dupeHistoryDir", config->dupeHistoryDir);
     VK_ADD_HASH_str(hv, sv, "nodelistDir", config->nodelistDir);
     VK_ADD_HASH_str(hv, sv, "tempDir", config->tempDir);
     VK_ADD_HASH_int(hv, sv, "sortEchoList", config->listEcho);
     VK_ADD_HASH_int(hv, sv, "areafixFromPkt", config->areafixFromPkt);
     VK_ADD_HASH_str(hv, sv, "areafixNames", robot->names);
     VK_ADD_HASH_str(hv, sv, "robotsArea", config->robotsArea);
     VK_ADD_HASH_str(hv, sv, "reportTo", config->ReportTo);
     VK_ADD_HASH_int(hv, sv, "keepTrsMail", config->keepTrsMail);
     VK_ADD_HASH_int(hv, sv, "keepTrsFiles", config->keepTrsFiles);
     VK_ADD_HASH_str(hv, sv, "fileBoxesDir", config->fileBoxesDir);
     VK_ADD_HASH_str(hv, sv, "rulesDir", robot->rulesDir);
     if (config->packCount) {
       char *packlist = NULL;
       for (j = 0; j < config->packCount; j++)
           xstrscat(&packlist, " ", config->pack[j].packer, NULL);
       VK_ADD_HASH_str(hv, sv, "packers", packlist+1);
       nfree(packlist);
     }
     av = newAV();
     for (i = 0; i < config->addrCount; i++)
        if ( (sv = newSVpv(aka2str(config->addr[i]), 0)) != NULL ) {
            SvREADONLY_on(sv); av_push(av, sv);
        }
     SvREADONLY_on(av);
     sv = newRV_noinc((struct sv*)av); 
     /*SvPOK_on(sv); sv_setpv(aka2str(config->addr[0]), 0); SvREADONLY_on(sv);*/
     VK_ADD_HASH_sv(hv, sv, "addr");
     SvREADONLY_on(hv);

     hv = perl_get_hv("groups", TRUE);
     SvREADONLY_off(hv); hv_clear(hv);
     for (i = 0; i < config->groupCount; i++) {
        VK_ADD_HASH_str(hv, sv, config->group[i].name, config->group[i].desc);
     }
     SvREADONLY_on(hv);
   }

   /* set links config */
   if (perl_vars_invalid & PERL_CONF_LINKS) {

     w_log( LL_SRCLINE, "%s:%d setting Perl variables (links)", __FILE__, __LINE__);

     hv = perl_get_hv("links", TRUE); 
     SvREADONLY_off(hv); hv_clear(hv);
     for (i = 0; i < config->linkCount; i++) {
        hv2 = newHV();
        VK_ADD_HASH_str(hv2, sv, "name", config->links[i]->name);
        VK_ADD_HASH_str(hv2, sv, "aka", aka2str(*config->links[i]->ourAka));
        VK_ADD_HASH_str(hv2, sv, "password", config->links[i]->defaultPwd);
        VK_ADD_HASH_str(hv2, sv, "filebox", config->links[i]->fileBox);
        VK_ADD_HASH_str(hv2, sv, "robot", config->links[i]->areafix.name);
        VK_ADD_HASH_int(hv2, sv, "flavour", flv2flag(config->links[i]->netMailFlavour));
        VK_ADD_HASH_int(hv2, sv, "eflavour", flv2flag(config->links[i]->echoMailFlavour));
        VK_ADD_HASH_int(hv2, sv, "pause", getPause( config->links[i] ));
        VK_ADD_HASH_int(hv2, sv, "level", config->links[i]->level);
        VK_ADD_HASH_int(hv2, sv, "advAfix", config->links[i]->advancedAreafix);
        VK_ADD_HASH_int(hv2, sv, "echoLimit", config->links[i]->areafix.echoLimit);
        VK_ADD_HASH_int(hv2, sv, "forwreqs", config->links[i]->areafix.forwardRequests);
        VK_ADD_HASH_str(hv2, sv, "forwreqsFile", config->links[i]->areafix.fwdFile);
        VK_ADD_HASH_int(hv2, sv, "forwreqsPrio", config->links[i]->areafix.forwardPriority);
        VK_ADD_HASH_int(hv2, sv, "reducedSeenBy", config->links[i]->reducedSeenBy);
        VK_ADD_HASH_int(hv2, sv, "noRules", config->links[i]->areafix.noRules);
        VK_ADD_HASH_int(hv2, sv, "pktSize", config->links[i]->pktSize);
        VK_ADD_HASH_int(hv2, sv, "arcmailSize", (config->links[i]->arcmailSize ?
                                                   config->links[i]->arcmailSize :
                                                   (config->defarcmailSize ? config->defarcmailSize : 500) ));
        if (config->links[i]->packerDef) VK_ADD_HASH_str(hv2, sv, "packer", config->links[i]->packerDef->packer);
        if (config->links[i]->AccessGrp) {
          char *grplist = NULL;
          for (j = 0; j < config->links[i]->numAccessGrp; j++)
            if (config->links[i]->AccessGrp[j])
              xstrscat(&grplist, " ", config->links[i]->AccessGrp[j], NULL);
          if (grplist) VK_ADD_HASH_str(hv2, sv, "groups", grplist+1);
          nfree(grplist);
        }
        /* val r/o: SvREADONLY_on(hv2); */
        sv = newRV_noinc((struct sv*)hv2);
        VK_ADD_HASH_sv(hv, sv, aka2str(config->links[i]->hisAka));
     }
     /* val: seems to cause problems: SvREADONLY_on(hv); */
   }

   /* set areas config */
   if (perl_vars_invalid & PERL_CONF_AREAS) {

     w_log( LL_SRCLINE, "%s:%d setting Perl variables (areas)", __FILE__, __LINE__);

     hv = perl_get_hv("areas", TRUE); 
     SvREADONLY_off(hv); hv_clear(hv);
     for (i = 0; i < config->echoAreaCount; i++) {
        hv2 = newHV();
        VK_ADD_HASH_str(hv2, sv, "desc", config->echoAreas[i].description);
        VK_ADD_HASH_str(hv2, sv, "aka", aka2str(*config->echoAreas[i].useAka));
        VK_ADD_HASH_str(hv2, sv, "group", config->echoAreas[i].group);
        VK_ADD_HASH_int(hv2, sv, "hide", config->echoAreas[i].hide);
        VK_ADD_HASH_int(hv2, sv, "passthrough", config->echoAreas[i].msgbType == MSGTYPE_PASSTHROUGH);
        VK_ADD_HASH_int(hv2, sv, "mandatory", config->echoAreas[i].mandatory);
        VK_ADD_HASH_int(hv2, sv, "manual", config->echoAreas[i].manual);
        VK_ADD_HASH_int(hv2, sv, "lvl_r", config->echoAreas[i].levelread);
        VK_ADD_HASH_int(hv2, sv, "lvl_w", config->echoAreas[i].levelwrite);
        VK_ADD_HASH_int(hv2, sv, "paused", config->echoAreas[i].paused);
        if (config->echoAreas[i].downlinks) {
          hv3 = newHV();
          for (j = 0; j < config->echoAreas[i].downlinkCount; j++) {
            VK_ADD_HASH_int(hv3, sv, 
                            aka2str(config->echoAreas[i].downlinks[j]->link->hisAka),
                            1 | config->echoAreas[i].downlinks[j]->defLink << 1
                            | config->echoAreas[i].downlinks[j]->manual << 2
                            | config->echoAreas[i].downlinks[j]->mandatory << 3
                            | config->echoAreas[i].downlinks[j]->import << 4
                            | config->echoAreas[i].downlinks[j]->export << 5
                           );
          }
          /* val r/o: SvREADONLY_on(hv3); */
          sv = newRV_noinc((struct sv*)hv3);
          VK_ADD_HASH_sv(hv2, sv, "links");
        }
        /* val r/o: SvREADONLY_on(hv2); */
        sv = newRV_noinc((struct sv*)hv2);
        VK_ADD_HASH_sv(hv, sv, config->echoAreas[i].areaName);
     }
     SvREADONLY_on(hv);
   }

   perl_vars_invalid = 0;
}

int PerlStart(void)
{
   int rc, i;
   char *perlfile;
   char *perlargs[]={"", NULL, NULL, NULL};
   char *cfgfile, *cfgpath=NULL, *patharg=NULL;
   STRLEN n_a;

   if (config->hptPerlFile != NULL)
      perlfile = config->hptPerlFile;
   else
   {
      do_perl=0;
      return 1;
   }
   i = 1;
   /* val: try to find out the actual path to perl script and set dir to -I */
   cfgfile = (cfgFile) ? cfgFile : getConfigFileName();
   if ( strchr(perlfile, PATH_DELIM) ) {
      cfgpath = GetDirnameFromPathname(perlfile);
      xstrscat(&patharg, "-I", cfgpath, NULL);
      nfree(cfgpath);
   }
   else if ( strchr(cfgfile, PATH_DELIM) ) {
      cfgpath = GetDirnameFromPathname(cfgfile);
      xstrscat(&patharg, "-I", cfgpath, NULL);
      nfree(cfgpath);
   }
   if (patharg) perlargs[i++] = patharg;
   perlargs[i++] = "-e";
   perlargs[i++] = "0";
#ifdef _MSC_VER
   if (_access(perlfile, R_OK))
#else
   if (access(perlfile, R_OK))
#endif
   { w_log(LL_ERR, "Can't read %s: %s, perl filtering disabled",
                   perlfile, strerror(errno));
     do_perl=0;
     nfree(patharg);
     return 1;
   }

   /* Start perl interpreter */
#ifdef     DO_HPM
#ifndef     aTHXo
#define     aTHXo
#endif   /*!aTHXo*/
   xs_init (aTHXo);
   perl = (void*) -1;
   rc   = 0;
#else  /* !DO_HPM */
   perl = perl_alloc();
   perl_construct(perl);
   rc = perl_parse (perl, xs_init, i, perlargs, NULL);
#endif /* !DO_HPM */
   if (!rc) {
     char* cmd = NULL;
     SV* sv;

     /* val: start constants definition */
#define VK_MAKE_CONST(_name,_value)                    \
     newCONSTSUB(PL_defstash, _name, newSVuv(_value)); \
     sv_setuv( get_sv(_name, TRUE), _value );
     for (i = 0; i < sizeof(flag_name)/sizeof(flag_name[0]); i++) {
       char ss[4];
       strcpy(ss, flag_name[i]); if (ss[1] == '/') ss[1] = '_'; ss[3]=0;
       VK_MAKE_CONST(ss, (unsigned long)1<<i);
     }

     /* val: start config importing */
     perl_setvars();

     /* Set warn and die hook */
     if (PL_warnhook) SvREFCNT_dec (PL_warnhook);
     if (PL_diehook ) SvREFCNT_dec (PL_diehook );
     PL_warnhook = newRV_inc ((SV*) perl_get_cv ("hpt_warn", TRUE));
     PL_diehook  = newRV_inc ((SV*) perl_get_cv ("hpt_warn", TRUE));

     /* Parse and execute hptPerlFile */
     xstrscat (&cmd, "do '", perlfile, "'; $@ ? $@ : '';", NULL);
     sv = perl_eval_pv (cmd, TRUE);
     if (!SvPOK(sv)) {
       w_log(LL_PERL,"Syntax error in internal perl expression: %s",cmd);
       rc = 1;
     } else if (SvTRUE (sv)) {
       perl_warn_sv (sv);
       rc = 1;
     }
     nfree (cmd);
   }
   if (rc)
   { w_log(LL_ERR, "Can't parse %s, perl filtering disabled",
                   perlfile);
#ifndef DO_HPM
     perl_destruct(perl);
     perl_free(perl);
#endif  /* !DO_HPM */
     perl=NULL;
     do_perl=0;
     nfree(patharg);
     return 1;
   }
/* val: look which subs present */
   if (perl_get_cv(PERLFILT      , FALSE) == NULL)
					perl_subs &= ~SUB_FILTER;
   if (perl_get_cv(PERLFILT2     , FALSE) == NULL)
					perl_subs &= ~SUB_FILTER2;
   if (perl_get_cv(PERLPKT       , FALSE) == NULL)
					perl_subs &= ~SUB_PROCESS_PKT;
   if (perl_get_cv(PERLPKTDONE   , FALSE) == NULL)
					perl_subs &= ~SUB_PKT_DONE;
   if (perl_get_cv(PERLAFTERUNP  , FALSE) == NULL)
					perl_subs &= ~SUB_AFTER_UNPACK;
   if (perl_get_cv(PERLBEFOREPACK, FALSE) == NULL)
					perl_subs &= ~SUB_BEFORE_PACK;
   if (perl_get_cv(PERLSTART     , FALSE) == NULL)
					perl_subs &= ~SUB_HPT_START;
   if (perl_get_cv(PERLEXIT      , FALSE) == NULL)
					perl_subs &= ~SUB_HPT_EXIT;
   if (perl_get_cv(PERLROUTE     , FALSE) == NULL)
					perl_subs &= ~SUB_ROUTE;
   if (perl_get_cv(PERLSCAN      , FALSE) == NULL)
					perl_subs &= ~SUB_SCAN;
   if (perl_get_cv(PERLTOSSBAD   , FALSE) == NULL)
					perl_subs &= ~SUB_TOSSBAD;
   if (perl_get_cv(PERLONECHOLIST, FALSE) == NULL)
					perl_subs &= ~SUB_ON_ECHOLIST;
   if (perl_get_cv(PERLONAFIXCMD , FALSE) == NULL)
					perl_subs &= ~SUB_ON_AFIXCMD;
   if (perl_get_cv(PERLONAFIXREQ , FALSE) == NULL)
					perl_subs &= ~SUB_ON_AFIXREQ;
   if (perl_get_cv(PERLPUTMSG    , FALSE) == NULL)
					perl_subs &= ~SUB_PUTMSG;
   if (perl_get_cv(PERLEXPORT    , FALSE) == NULL)
					perl_subs &= ~SUB_EXPORT;
   if (perl_get_cv(PERLROBOTMSG  , FALSE) == NULL)
					perl_subs &= ~SUB_ON_ROBOTMSG;
/* val: run hpt_start() */
   if (perl_subs & SUB_HPT_START) {
      { dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        PUTBACK;
        perl_call_pv(PERLSTART, G_EVAL|G_VOID);
        SPAGAIN;
        PUTBACK;
        FREETMPS;
        LEAVE;
      }
      if (SvTRUE(ERRSV))
      {
        w_log(LL_ERR, "Perl hpt_start() eval error: %s\n", SvPV(ERRSV, n_a));
      }
   }
/* val: end config importing */
   nfree(patharg);
   return 0;
}

#define VK_START_HOOK(name, code, ret)                           \
   if (do_perl && perl == NULL)                                  \
     if (PerlStart()) return ret;                                \
   if (!perl || !do_##name || (perl_subs & code) == 0)           \
     return ret;                                                 \
   w_log(LL_SRCLINE, "%s:%d starting Perl hook "#name, __FILE__, __LINE__); \
   if (perl_vars_invalid) perl_setvars();

void perldone(void)
{
  static int do_perldone=1;

  VK_START_HOOK(perldone, SUB_HPT_EXIT, )

  { dSP;
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    PUTBACK;
    perl_call_pv(PERLEXIT, G_EVAL|G_SCALAR);
    SPAGAIN;
    PUTBACK;
    FREETMPS;
    LEAVE;
#ifndef DO_HPM
    perl_destruct(perl);
    perl_free(perl);
#endif  /* !DO_HPM */
    perl=NULL;
  }
}

int perlscanmsg(char *area, s_message *msg)
{
   static int do_perlscan = 1;
   char *prc, *ptr;
   unsigned long attr;
   time_t date;
   SV *svfromname, *svfromaddr, *svtoname, *svtoaddr, *svattr;
   SV *svdate, *svtext, *svarea, *svsubj, *svret, *svchange;
   SV *svaddvia, *svkill;
   STRLEN n_a;
   int result = 0;

   VK_START_HOOK(perlscan, SUB_SCAN, 0)

   { dSP;
     svfromname = perl_get_sv("fromname", TRUE);
     svfromaddr = perl_get_sv("fromaddr", TRUE);
     svtoname   = perl_get_sv("toname",   TRUE);
     svdate     = perl_get_sv("date",     TRUE);
     svsubj     = perl_get_sv("subject",  TRUE);
     svtext     = perl_get_sv("text",     TRUE);
     svchange   = perl_get_sv("change",   TRUE);
     svkill     = perl_get_sv("kill",     TRUE);
     svarea     = perl_get_sv("area",     TRUE);
     svtoaddr   = perl_get_sv("toaddr",   TRUE);
     svattr     = perl_get_sv("attr",     TRUE);
     svaddvia   = perl_get_sv("addvia",   TRUE);
     sv_setpv(svfromname, msg->fromUserName);
     sv_setpv(svfromaddr, aka2str(msg->origAddr));
     sv_setpv(svtoname,   msg->toUserName);

     sv_setuv(svdate,     (unsigned long)fts2unix(msg->datetime, NULL) );
     sv_setpv(svdate,     msg->datetime);
     SvIOK_on(svdate);

     sv_setpv(svsubj,     msg->subjectLine);
     sv_setpv(svtext,     msg->text);
     sv_setsv(svchange,   &sv_undef);
     sv_setsv(svkill,     &sv_undef);
     sv_setuv(svattr,     msg->attributes | parse_flags(msg->text));
     sv_setiv(svaddvia, 1);

     if (area)
       sv_setpv(svarea,   area);
     else
       sv_setsv(svarea,   &sv_undef);
     if (msg->netMail)
       sv_setpv(svtoaddr, aka2str(msg->destAddr));
     else
       sv_setsv(svtoaddr, &sv_undef);
     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     PUTBACK;
     perl_call_pv(PERLSCAN, G_EVAL|G_SCALAR);
     SPAGAIN;
     svret=POPs;
     if (SvTRUE(svret))
       prc = safe_strdup(SvPV(svret, n_a));
     else
       prc = NULL;
     PUTBACK;
     FREETMPS;
     LEAVE;
     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl scan eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlscan = 0;
       return 0;
     }
     svchange = perl_get_sv("change", FALSE);
     if (svchange && SvTRUE(svchange))
     { /* change */
       freeMsgBuffers(msg);
       ptr = SvPV(perl_get_sv("text", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->text = safe_strdup(ptr);
       msg->textLength = strlen(msg->text);
       ptr = SvPV(perl_get_sv("toname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->toUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("fromname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->fromUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("subject", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->subjectLine = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("toaddr", FALSE), n_a);
       if (n_a > 0) string2addr(ptr, &(msg->destAddr));
       ptr = SvPV(perl_get_sv("fromaddr", FALSE), n_a);
       if (n_a > 0) string2addr(ptr, &(msg->origAddr));
       /* update message kludges, if needed */
       update_addr(msg);
       /* process flags, update message if needed */
       attr = SvUV(perl_get_sv("attr", FALSE));
       msg->attributes = attr & 0xffff;
       if ((ptr = update_flags(msg->text, attr, MODE_REPLACE)) != NULL) {
           if (ptr != msg->text) { free(msg->text); msg->text = ptr; }
           msg->textLength = strlen(msg->text);
       }
       /* process date */
       svdate = perl_get_sv("date", FALSE);
       if ( (SvIOK(svdate)) && (SvUV(svdate) > 0) ) {
              date = SvUV(svdate);
              make_ftsc_date(msg->datetime, localtime(&date));
       }
       else if ( SvPOK(svdate) ) {
              ptr = SvPV(svdate, n_a); if (n_a == 0) ptr = "";
              if (fts2unix(ptr, NULL) > 0) {
                  strncpy(msg->datetime, ptr, sizeof(msg->datetime));
                  msg->datetime[sizeof(msg->datetime)-1] = '\0';
              }
       }
     }

     skip_addvia = 0;
     svaddvia = get_sv("addvia", FALSE);
     if (svaddvia != NULL) skip_addvia = (SvIV(svaddvia) == 0);
     /*  kill after processing */
     if (msg->netMail && svkill && SvTRUE(svkill)) result |= 0x80;
     /*  change route and flavour */
     if (prc)
     {
       if (msg->netMail)
         w_log(LL_PERL, "PerlScan: NetMail from %s %u:%u/%u.%u to %s %u:%u/%u.%u: %s",
                       msg->fromUserName,
                       msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node, msg->origAddr.point,
                       msg->toUserName,
                       msg->destAddr.zone, msg->destAddr.net, msg->destAddr.node, msg->destAddr.point,
                       prc);
       else
         w_log(LL_PERL, "PerlScan: Area %s from %s %u:%u/%u.%u: %s",
                       area, msg->fromUserName,
                       msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node, msg->origAddr.point,
                       prc);
       nfree(prc);
       return result | 1;
     }
   }
   return result | 0;
}

s_route *perlroute(s_message *msg, s_route *defroute)
{
   static int do_perlroute = 1;

   VK_START_HOOK(perlroute, SUB_ROUTE, NULL)

   { SV *svaddr, *svattr, *svflv, *svfrom, *svret, *svroute;
     SV *svfromname, *svtoname, *svsubj, *svtext, *svdate;
     SV *svaddvia, *svchange;
     char *routeaddr, *prc, *ptr;
     unsigned long attr;
     time_t date;
     STRLEN n_a;
     static s_route route;
     dSP;
     svaddr  = perl_get_sv("addr",    TRUE);
     svfrom  = perl_get_sv("from",    TRUE);
     svroute = perl_get_sv("route",   TRUE);
     svflv   = perl_get_sv("flavour", TRUE);
     svattr  = perl_get_sv("attr",    TRUE);
     svsubj  = perl_get_sv("subj",    TRUE);
     svtext  = perl_get_sv("text",    TRUE);
     svdate  = perl_get_sv("date",    TRUE);
     svtoname= perl_get_sv("toname",  TRUE);
     svfromname = perl_get_sv("fromname", TRUE);
     svchange   = perl_get_sv("change",   TRUE);
     sv_setpv(svaddr,     aka2str(msg->destAddr));
     sv_setpv(svfrom,     aka2str(msg->origAddr));
     sv_setpv(svfromname, msg->fromUserName);
     sv_setpv(svtoname,   msg->toUserName);

     sv_setuv(svdate,     (unsigned long)fts2unix(msg->datetime, NULL) );
     sv_setpv(svdate,     msg->datetime);
     SvIOK_on(svdate);

     sv_setpv(svsubj,     msg->subjectLine);
     sv_setpv(svtext,     msg->text);
     sv_setuv(svattr,     msg->attributes | parse_flags(msg->text));
     sv_setsv(svchange,   &sv_undef);
     if (defroute)
     {
        if (defroute->target)
                sv_setpv(svroute, aka2str(defroute->target->hisAka));
        else /* noroute */
                sv_setpv(svroute, aka2str(msg->destAddr));
        if (defroute->flavour==normal)
            sv_setpv(svflv, "normal");
        else if (defroute->flavour==hold)
            sv_setpv(svflv, "hold");
        else if (defroute->flavour==direct)
            sv_setpv(svflv, "direct");
        else if (defroute->flavour==crash)
            sv_setpv(svflv, "crash");
        else if (defroute->flavour==immediate)
            sv_setpv(svflv, "immediate");
     }
     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     PUTBACK;
     perl_call_pv(PERLROUTE, G_EVAL|G_SCALAR);
     SPAGAIN;
     svret=POPs;
     if (SvTRUE(svret))
       routeaddr = safe_strdup(SvPV(svret, n_a));
     else
       routeaddr = NULL;
     PUTBACK;
     FREETMPS;
     LEAVE;

     svaddvia = get_sv("addvia", FALSE);
     if (svaddvia != NULL) skip_addvia = (SvIV(svaddvia) == 0);

     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl route eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlroute = 0;
     }
     else {
         svchange = perl_get_sv("change", FALSE);
         if (svchange && SvTRUE(svchange)) {
           /* change */
           freeMsgBuffers(msg);
           prc = SvPV(perl_get_sv("text", FALSE), n_a);
           if (n_a == 0) prc = "";
           msg->text = safe_strdup(prc);
           msg->textLength = strlen(msg->text);
           prc = SvPV(perl_get_sv("toname", FALSE), n_a);
           if (n_a == 0) prc = "";
           msg->toUserName = safe_strdup(prc);
           prc = SvPV(perl_get_sv("fromname", FALSE), n_a);
           if (n_a == 0) prc = "";
           msg->fromUserName = safe_strdup(prc);
           prc = SvPV(perl_get_sv("subj", FALSE), n_a);
           if (n_a == 0) prc = "";
           msg->subjectLine = safe_strdup(prc);
           prc = SvPV(perl_get_sv("addr", FALSE), n_a);
           if (n_a > 0) string2addr(prc, &(msg->destAddr));
           prc = SvPV(perl_get_sv("from", FALSE), n_a);
           if (n_a > 0) string2addr(prc, &(msg->origAddr));
           /* update message kludges, if needed */
           update_addr(msg);
           /* process flags, update message if needed */
           attr = SvUV(perl_get_sv("attr", FALSE));
           msg->attributes = attr & 0xffff;
           if ((ptr = update_flags(msg->text, attr, MODE_REPLACE)) != NULL) {
               if (ptr != msg->text) { free(msg->text); msg->text = ptr; }
               msg->textLength = strlen(msg->text);
           }
           /* process date */
           svdate = perl_get_sv("date", FALSE);
           if ( (SvIOK(svdate)) && (SvUV(svdate) > 0) ) {
                  date = SvUV(svdate);
                  make_ftsc_date(msg->datetime, localtime(&date));
           }
           else if ( SvPOK(svdate) ) {
                  ptr = SvPV(svdate, n_a); if (n_a == 0) ptr = "";
                  if (fts2unix(ptr, NULL) > 0) {
                      strncpy(msg->datetime, ptr, sizeof(msg->datetime));
                      msg->datetime[sizeof(msg->datetime)-1] = '\0';
                  }
           }
         }

         if (routeaddr)
         {
           char *flv;
           static char srouteaddr[32];
           svflv = perl_get_sv("flavour", FALSE);

           memset(&route, 0, sizeof(route));
           if ((route.target = getLink(config, routeaddr)) == NULL) {
             route.routeVia = route_extern;
             route.viaStr = srouteaddr;
             strncpy(srouteaddr, routeaddr, sizeof(srouteaddr));
             srouteaddr[sizeof(srouteaddr)-1] = '\0';
           }

           if ((SvIOK(svflv)) && (SvUV(svflv) > 0)) route.flavour = flag2flv(SvUV(svflv));
           else {
               flv = SvPV(svflv, n_a); if (n_a == 0) flv = "";
               if (flv == NULL || *flv == '\0')
               {
                 if (route.target)
                   route.flavour = route.target->echoMailFlavour;
                 else
                   route.flavour = hold;
               }
    #if 1
               else if ( (route.flavour = str2flv(flv)) != -1 ) ;
    #else
               else if (stricmp(flv, "normal") == 0)
                 route.flavour = normal;
               else if (stricmp(flv, "hold") == 0)
                 route.flavour = hold;
               else if (stricmp(flv, "crash") == 0)
                 route.flavour = crash;
               else if (stricmp(flv, "direct") == 0)
                 route.flavour = direct;
               else if (stricmp(flv, "immediate") == 0)
                 route.flavour = immediate;
    #endif
               else {
                 w_log(LL_PERL, "Perl route unknown flavour %s, set to hold", flv);
                 route.flavour = hold;
               }
           }
           free(routeaddr);
           return &route;
         }

     }
   }
   return NULL;
}

int perlfilter(s_message *msg, hs_addr pktOrigAddr, int secure)
{
   char *area = NULL, *prc;
   int rc = 0;
   unsigned long attr;
   time_t date;
   SV *svfromname, *svfromaddr, *svtoname, *svtoaddr, *svpktfrom, *svkill;
   SV *svdate, *svtext, *svarea, *svsubj, *svsecure, *svret;
   SV *svchange, *svattr;
   STRLEN n_a;
   static int do_perlfilter=1, do_perlfilter2=1;
   char *sorig;
   char _cur[2] = {0, 0};

   if (secure < 0) { VK_START_HOOK(perlfilter2, SUB_FILTER2, 0) }
   else { VK_START_HOOK(perlfilter, SUB_FILTER, 0) }

   _cur[0] = secure < 0 ? '2' : 0;

   perl_setattr = 0;
   if (msg->netMail != 1) {
     char *p, *p1;
     p = msg->text+5;
     while (*p == ' ') p++;
     p1=strchr(p, '\r');
     if (p1 == NULL) p1=p+strlen(p);
     area = safe_malloc(p1-p+1);
     memcpy(area, p, p1-p);
     area[p1-p] = '\0';
   }
   { dSP;
     svfromname = perl_get_sv("fromname", TRUE);
     svfromaddr = perl_get_sv("fromaddr", TRUE);
     svtoname   = perl_get_sv("toname",   TRUE);
     svdate     = perl_get_sv("date",     TRUE);
     svsubj     = perl_get_sv("subject",  TRUE);
     svtext     = perl_get_sv("text",     TRUE);
     svpktfrom  = perl_get_sv("pktfrom",  TRUE);
     svkill     = perl_get_sv("kill",     TRUE);
     svchange   = perl_get_sv("change",   TRUE);
     svarea     = perl_get_sv("area",     TRUE);
     svtoaddr   = perl_get_sv("toaddr",   TRUE);
     svsecure   = perl_get_sv("secure",   TRUE);
     svattr     = perl_get_sv("attr",     TRUE);
     sv_setpv(svfromname, msg->fromUserName);
     sv_setpv(svfromaddr, aka2str(msg->origAddr));
     sv_setpv(svtoname,   msg->toUserName);

     sv_setuv(svdate,     (unsigned long)fts2unix(msg->datetime, NULL) );
     sv_setpv(svdate,     msg->datetime);
     SvIOK_on(svdate);

     sv_setpv(svsubj,     msg->subjectLine);
     sv_setpv(svtext,     msg->text);
     sv_setpv(svpktfrom,  aka2str(pktOrigAddr));
     sv_setsv(svkill,     &sv_undef);
     sv_setsv(svchange,   &sv_undef);
     sv_setuv(svattr,     msg->attributes | parse_flags(msg->text));
     if (secure > 0)
       sv_setiv(svsecure, 1);
     else
       sv_setsv(svsecure, &sv_undef);
     if (area)
     { sv_setpv(svarea,   area);
       sv_setsv(svtoaddr, &sv_undef);
     }
     else
     { sv_setsv(svarea,   &sv_undef);
       sv_setpv(svtoaddr, aka2str(msg->destAddr));
     }
     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     PUTBACK;
     perl_call_pv(secure >= 0 ? PERLFILT : PERLFILT2, G_EVAL|G_SCALAR);
     SPAGAIN;
     svret=POPs;
     if (SvTRUE(svret))
       prc = safe_strdup(SvPV(svret, n_a));
     else
       prc = NULL;
     PUTBACK;
     FREETMPS;
     LEAVE;
     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl filter%s eval error: %s\n", _cur, SvPV(ERRSV, n_a));
       if (secure < 0) do_perlfilter2 = 0; else do_perlfilter = 0;
       nfree(area);
       return 0;
     }
     svkill = perl_get_sv("kill", FALSE);
     if (svkill && SvTRUE(svkill))
     { /*  kill */
       sorig = aka2str5d(msg->origAddr);
       if (area)
         w_log(LL_PERL, "PerlFilter%s: Area %s from %s %s killed%s%s", _cur,
                       area, msg->fromUserName, sorig,
                       prc ? ": " : "", prc ? prc : "");
       else
         w_log(LL_PERL, "PerlFilter%s: NetMail from %s %s to %s %s killed%s%s", _cur,
                       msg->fromUserName, sorig,
                       msg->toUserName, aka2str(msg->destAddr),
                       prc ? ": " : "", prc ? prc : "");
       nfree(sorig);
       nfree(prc);
       nfree(area);
       return 2;
     }
     svchange = perl_get_sv("change", FALSE);
     if (svchange && SvTRUE(svchange))
     { /*  change */
       char *ptr;
       freeMsgBuffers(msg);
       ptr = SvPV(perl_get_sv("text", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->text = safe_strdup(ptr);
       msg->textLength = strlen(msg->text);
       ptr = SvPV(perl_get_sv("toname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->toUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("fromname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->fromUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("subject", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->subjectLine = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("toaddr", FALSE), n_a);
       if (n_a > 0) string2addr(ptr, &(msg->destAddr));
       ptr = SvPV(perl_get_sv("fromaddr", FALSE), n_a);
       if (n_a > 0) string2addr(ptr, &(msg->origAddr));
       /* update message kludges, if needed */
       update_addr(msg);
       /* process flags, update message if needed */
       attr = SvUV(perl_get_sv("attr", FALSE));
       msg->attributes = attr & 0xffff; perl_setattr = 1;
       if ((ptr = update_flags(msg->text, attr, MODE_REPLACE)) != NULL) {
           if (ptr != msg->text) { free(msg->text); msg->text = ptr; }
           msg->textLength = strlen(msg->text);
       }
       /* process date */
       svdate = perl_get_sv("date", FALSE);
       if ( (SvIOK(svdate)) && (SvUV(svdate) > 0) ) {
              date = SvUV(svdate);
              make_ftsc_date(msg->datetime, localtime(&date));
       }
       else if ( SvPOK(svdate) ) {
              ptr = SvPV(svdate, n_a); if (n_a == 0) ptr = "";
              if (fts2unix(ptr, NULL) > 0) {
                  strncpy(msg->datetime, ptr, sizeof(msg->datetime));
                  msg->datetime[sizeof(msg->datetime)-1] = '\0';
              }
       }
     }
     if (prc)
     {
       sorig = aka2str5d(msg->origAddr);
       if (area)
         w_log(LL_PERL, "PerlFilter%s: Area %s from %s %s: %s", _cur,
                       area, msg->fromUserName, sorig, prc);
       else
         w_log(LL_PERL, "PerlFilter%s: NetMail from %s %s to %s %s: %s", _cur,
                       msg->fromUserName, sorig,
                       msg->toUserName, aka2str(msg->destAddr), prc);
       rc = 1;
       nfree(sorig);
       nfree(prc);
     }
   }
   nfree(area);
   return rc;
}

int perlpkt(const char *fname, int secure)
{
   static int do_perlpkt = 1;
   char *prc = NULL;
   STRLEN n_a;
   SV *svpktname, *svsecure, *svret;

   VK_START_HOOK(perlpkt, SUB_PROCESS_PKT, 0)

   svpktname = perl_get_sv("pktname", TRUE);
   svsecure  = perl_get_sv("secure",  TRUE);
   { dSP;
     sv_setpv(svpktname, fname);
     if (secure) sv_setiv(svsecure, 1);
     else sv_setsv(svsecure, &sv_undef);
     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     PUTBACK;
     perl_call_pv(PERLPKT, G_EVAL|G_SCALAR);
     SPAGAIN;
     svret=POPs;
     if (SvTRUE(svret))
       prc = safe_strdup(SvPV(svret, n_a));
     else
       prc = NULL;
     PUTBACK;
     FREETMPS;
     LEAVE;
     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl pkt eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlpkt = 0;
     }
     else if (prc)
     {
       w_log(LL_PERL, "Packet %s rejected by perl filter: %s", fname, prc);
       nfree(prc);
       return 1;
     }
   }
   return 0;
}

void perlpktdone(const char *fname, int rc)
{
  const char *res[] = {NULL, "Security violation", "Can't open pkt",
                       "Bad pkt format", "Not to us", "Msg tossing problem",
                       "Unknown error", "Unknown error (pkt already removed)"};
   static int do_perlpktdone = 1;
   STRLEN n_a;
   SV *svpktname, *svrc, *svres;

   VK_START_HOOK(perlpktdone, SUB_PKT_DONE, )

   { dSP;
     svpktname = perl_get_sv("pktname", TRUE);
     svrc      = perl_get_sv("rc",  TRUE);
     svres     = perl_get_sv("res", TRUE);
     sv_setpv(svpktname, fname);
     sv_setiv(svrc,  rc);
     if (rc)
       sv_setpv(svres, res[rc]);
     else
       sv_setsv(svres, &sv_undef);
     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     PUTBACK;
     perl_call_pv(PERLPKTDONE, G_EVAL|G_SCALAR);
     SPAGAIN;
     PUTBACK;
     FREETMPS;
     LEAVE;
     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl pktdone eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlpktdone = 0;
     }
   }
}

void perlafterunp(void)
{
   static int do_perlafterunp = 1;
   STRLEN n_a;

   VK_START_HOOK(perlafterunp, SUB_AFTER_UNPACK, )

   { dSP;
     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     PUTBACK;
     perl_call_pv(PERLAFTERUNP, G_EVAL|G_SCALAR);
     SPAGAIN;
     PUTBACK;
     FREETMPS;
     LEAVE;
     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl afterunp eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlafterunp = 0;
     }
   }
}

void perlbeforepack(void)
{
   static int do_perlbeforepack = 1;
   STRLEN n_a;

   VK_START_HOOK(perlbeforepack, SUB_BEFORE_PACK, )

   { dSP;
     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     PUTBACK;
     perl_call_pv(PERLBEFOREPACK, G_EVAL|G_SCALAR);
     SPAGAIN;
     PUTBACK;
     FREETMPS;
     LEAVE;
     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl beforepack eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlbeforepack = 0;
     }
   }
}

int perltossbad(s_message *msg, char *areaName, hs_addr pktOrigAddr, char *reason)
{
   char *prc, *sorig;
   unsigned long attr;
   time_t date;
   SV *svfromname, *svfromaddr, *svtoname, *svtoaddr, *svpktfrom;
   SV *svdate, *svtext, *svarea, *svsubj, *svret, *svchange, *svattr;
   SV *svreason;
   STRLEN n_a;
   static int do_perltossbad=1;

   VK_START_HOOK(perltossbad, SUB_TOSSBAD, 0)

   { dSP;
     svfromname = perl_get_sv("fromname", TRUE);
     svfromaddr = perl_get_sv("fromaddr", TRUE);
     svtoname   = perl_get_sv("toname",   TRUE);
     svdate     = perl_get_sv("date",     TRUE);
     svsubj     = perl_get_sv("subject",  TRUE);
     svtext     = perl_get_sv("text",     TRUE);
     svpktfrom  = perl_get_sv("pktfrom",  TRUE);
     svchange   = perl_get_sv("change",   TRUE);
     svarea     = perl_get_sv("area",     TRUE);
     svtoaddr   = perl_get_sv("toaddr",   TRUE);
     svattr     = perl_get_sv("attr",     TRUE);
     svreason   = perl_get_sv("reason",   TRUE);
     sv_setpv(svfromname, msg->fromUserName);
     sv_setpv(svfromaddr, aka2str(msg->origAddr));
     sv_setpv(svtoname,   msg->toUserName);

     sv_setuv(svdate,     (unsigned long)fts2unix(msg->datetime, NULL) );
     sv_setpv(svdate,     msg->datetime);
     SvIOK_on(svdate);

     sv_setpv(svsubj,     msg->subjectLine);
     sv_setpv(svtext,     msg->text);
     sv_setpv(svpktfrom,  aka2str(pktOrigAddr));
     sv_setsv(svchange,   &sv_undef);
     sv_setuv(svattr,     msg->attributes | parse_flags(msg->text));
     sv_setpv(svreason,   reason);
     if (areaName)
     { sv_setpv(svarea,   areaName);
       sv_setsv(svtoaddr, &sv_undef);
     }
     else
     { sv_setsv(svarea,   &sv_undef);
       sv_setpv(svtoaddr, aka2str(msg->destAddr));
     }
     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     PUTBACK;
     perl_call_pv(PERLTOSSBAD, G_EVAL|G_SCALAR);
     SPAGAIN;
     svret=POPs;
     if (SvTRUE(svret))
       prc = safe_strdup(SvPV(svret, n_a));
     else
       prc = NULL;
     PUTBACK;
     FREETMPS;
     LEAVE;
     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl tossbad eval error: %s\n", SvPV(ERRSV, n_a));
       do_perltossbad = 0;
       return 0;
     }
     if (prc)
     { /*  kill */
       sorig = aka2str5d(msg->origAddr);
       if (areaName)
         w_log(LL_PERL, "PerlFilter: Area %s from %s %s killed: %s",
                      areaName, msg->fromUserName, sorig, prc);
       else
         w_log(LL_PERL, "PerlFilter: NetMail from %s %s to %s %s killed: %s",
                      msg->fromUserName, sorig,
                      msg->toUserName, aka2str(msg->destAddr), prc);
       nfree(sorig);
       nfree(prc);
       return 1;
     }
     svchange = perl_get_sv("change", FALSE);
     if (svchange && SvTRUE(svchange))
     { /*  change */
       char *ptr;
       freeMsgBuffers(msg);
       ptr = SvPV(perl_get_sv("text", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->text = safe_strdup(ptr);
       msg->textLength = strlen(msg->text);
       ptr = SvPV(perl_get_sv("toname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->toUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("fromname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->fromUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("subject", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->subjectLine = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("toaddr", FALSE), n_a);
       if (n_a > 0) string2addr(ptr, &(msg->destAddr));
       ptr = SvPV(perl_get_sv("fromaddr", FALSE), n_a);
       if (n_a > 0) string2addr(ptr, &(msg->origAddr));
       /* update message kludges, if needed */
       update_addr(msg);
       /* process flags, update message if needed */
       attr = SvUV(perl_get_sv("attr", FALSE));
       msg->attributes = attr & 0xffff;
       if ((ptr = update_flags(msg->text, attr, MODE_REPLACE)) != NULL) {
           if (ptr != msg->text) { free(msg->text); msg->text = ptr; }
           msg->textLength = strlen(msg->text);
       }
       /* process date */
       svdate = perl_get_sv("date", FALSE);
       if ( (SvIOK(svdate)) && (SvUV(svdate) > 0) ) {
              date = SvUV(svdate);
              make_ftsc_date(msg->datetime, localtime(&date));
       }
       else if ( SvPOK(svdate) ) {
              ptr = SvPV(svdate, n_a); if (n_a == 0) ptr = "";
              if (fts2unix(ptr, NULL) > 0) {
                  strncpy(msg->datetime, ptr, sizeof(msg->datetime));
                  msg->datetime[sizeof(msg->datetime)-1] = '\0';
              }
       }
     }
   }
   return 0;

}

int perl_echolist(char **report, s_listype type, ps_arealist al, char *aka)
{
   int i, rc, len, max;
   char *s;
   AV *av;
   SV *svreport, *svlist, *svret;
   STRLEN n_a;
   static int do_perlecholist = 1;

   VK_START_HOOK(perlecholist, SUB_ON_ECHOLIST, 0)

   { dSP;
     svreport   = perl_get_sv("report", TRUE);
     sv_setpv(svreport, *report);
     av = newAV();
     for (max = i = 0; i < al->count; i++) {
       len = strlen(al->areas[i].tag);
       if (len > max) max = len;
       av_push(av, newSVpvn(al->areas[i].tag, len));
     }
     svlist = newRV_inc((struct sv*)av);

     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     XPUSHs(sv_2mortal(newSViv(type)));   /* $_[0]: type (0:all,1:lnk,2:unl) */
     XPUSHs(sv_2mortal(svlist));          /* $_[1]: pointer to array of tags */
     XPUSHs(sv_2mortal(newSVpv(aka, 0))); /* $_[2]: address of client */
     XPUSHs(sv_2mortal(newSViv(max)));    /* $_[3]: max echotag length */
     PUTBACK;
     perl_call_pv(PERLONECHOLIST, G_EVAL|G_SCALAR);
     SPAGAIN;
     svret = POPs;
     if (!SvOK(svret)) rc = 0; else rc = SvIV(svret);
     PUTBACK;
     FREETMPS;
     LEAVE;
     av_clear(av); av_undef(av);
     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl on_echolist eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlecholist = 0;
       return 0;
     }
     switch (rc) {
       case 1:                         /* set report to $report only */
       case 2:                         /* set report to $report, append footer */
         s = SvPV(perl_get_sv("report", FALSE), n_a);
         if (n_a == 0) s = "";
         *report = sstrdup(s);
         return (rc == 1);
       default:                        /* don't change report */
         return 0;
     }
   }
   return 0;
}

int perl_afixcmd(char **report, int cmd, char *aka, char *line)
{
   int rc;
   SV *svreport, *svret;
   STRLEN n_a;
   static int do_perlafixcmd = 1;

   VK_START_HOOK(perlafixcmd, SUB_ON_AFIXCMD, 0)

   { dSP;
     svreport   = perl_get_sv("report", TRUE);
     if (*report) sv_setpv(svreport, *report);

     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     XPUSHs(sv_2mortal(newSViv(cmd)));     /* $_[0]: command */
     XPUSHs(sv_2mortal(newSVpv(aka, 0)));  /* $_[1]: aka */
     XPUSHs(sv_2mortal(newSVpv(line, 0))); /* $_[2]: request line */
     PUTBACK;
     perl_call_pv(PERLONAFIXCMD, G_EVAL|G_SCALAR);
     SPAGAIN;
     svret = POPs;
     if (!SvOK(svret)) rc = 0; else rc = SvIV(svret);
     PUTBACK;
     FREETMPS;
     LEAVE;
     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl on_afixcmd eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlafixcmd = 0;
       return 0;
     }
     if (rc) {
       char *s = SvPV(perl_get_sv("report", FALSE), n_a);
       if (n_a == 0 || s == NULL) s = "";
       *report = sstrdup(s);
       return 1;
     }
     else return 0;
   }
   return 0;
}

int perl_afixreq(s_message *msg, hs_addr pktOrigAddr)
{
   int rc = 0;
   SV *svfromname, *svfromaddr, *svtoname, *svtoaddr, *svpktfrom;
   SV *svtext, *svsubj, *svret;
   STRLEN n_a;
   static int do_perlafixreq=1;

   VK_START_HOOK(perlafixreq, SUB_ON_AFIXREQ, 0)

   { dSP;
     svfromname = perl_get_sv("fromname", TRUE);
     svfromaddr = perl_get_sv("fromaddr", TRUE);
     svtoname   = perl_get_sv("toname",   TRUE);
     svtoaddr   = perl_get_sv("toaddr",   TRUE);
     svsubj     = perl_get_sv("subject",  TRUE);
     svtext     = perl_get_sv("text",     TRUE);
     svpktfrom  = perl_get_sv("pktfrom",  TRUE);
     sv_setpv(svfromname, msg->fromUserName);
     sv_setpv(svfromaddr, aka2str(msg->origAddr));
     sv_setpv(svtoname,   msg->toUserName);
     sv_setpv(svtoaddr,   aka2str(msg->destAddr));
     sv_setpv(svsubj,     msg->subjectLine);
     sv_setpv(svtext,     msg->text);
     sv_setpv(svpktfrom,  aka2str(pktOrigAddr));

     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     PUTBACK;
     perl_call_pv(PERLONAFIXREQ, G_EVAL|G_SCALAR);
     SPAGAIN;
     svret=POPs;
     if (!SvOK(svret)) rc = 0; else rc = SvIV(svret);
     PUTBACK;
     FREETMPS;
     LEAVE;
     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl on_afixreq eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlafixreq = 0;
       return 0;
     }
     if (rc)
     { /*  change */
       char *ptr;
       freeMsgBuffers(msg);
       ptr = SvPV(perl_get_sv("text", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->text = safe_strdup(ptr);
       msg->textLength = strlen(msg->text);
       ptr = SvPV(perl_get_sv("toname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->toUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("fromname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->fromUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("subject", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->subjectLine = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("toaddr", FALSE), n_a);
       if (n_a > 0) string2addr(ptr, &(msg->destAddr));
       ptr = SvPV(perl_get_sv("fromaddr", FALSE), n_a);
       if (n_a > 0) string2addr(ptr, &(msg->origAddr));
       return 1;
     }
   }
   return 0;
}

int perl_putmsg(s_area *echo, s_message *msg)
{
   int rc = 1;
   unsigned long attr;
   time_t date;
   SV *svfromname, *svfromaddr, *svtoname, *svtoaddr;
   SV *svdate, *svtext, *svarea, *svnetmail, *svsubj, *svret;
   SV *svchange, *svattr;
   STRLEN n_a;
   static int do_perlputmsg=1;

   VK_START_HOOK(perlputmsg, SUB_PUTMSG, 1)

   { dSP;
     svfromname = perl_get_sv("fromname", TRUE);
     svfromaddr = perl_get_sv("fromaddr", TRUE);
     svtoname   = perl_get_sv("toname",   TRUE);
     svdate     = perl_get_sv("date",     TRUE);
     svsubj     = perl_get_sv("subject",  TRUE);
     svtext     = perl_get_sv("text",     TRUE);
     svchange   = perl_get_sv("change",   TRUE);
     svarea     = perl_get_sv("area",     TRUE);
     svtoaddr   = perl_get_sv("toaddr",   TRUE);
     svattr     = perl_get_sv("attr",     TRUE);
     svnetmail  = perl_get_sv("netmail",  TRUE);
     sv_setpv(svfromname, msg->fromUserName);
     sv_setpv(svfromaddr, aka2str(msg->origAddr));
     sv_setpv(svtoname,   msg->toUserName);
     sv_setpv(svtoaddr,   aka2str(msg->destAddr));

     sv_setuv(svdate,     (unsigned long)fts2unix(msg->datetime, NULL) );
     sv_setpv(svdate,     msg->datetime);
     SvIOK_on(svdate);

     sv_setpv(svsubj,     msg->subjectLine);
     sv_setpv(svtext,     msg->text);
     sv_setsv(svchange,   &sv_undef);
     sv_setuv(svattr,     msg->attributes | parse_flags(msg->text));
     sv_setpv(svarea,     echo->areaName);
     /* todo: maybe replace to better criteria */
     sv_setiv(svnetmail,  msg->netMail);

     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     PUTBACK;
     perl_call_pv(PERLPUTMSG, G_EVAL|G_SCALAR);
     SPAGAIN;
     svret=POPs;
     if (!SvOK(svret)) rc = 1; else rc = SvIV(svret);
     PUTBACK;
     FREETMPS;
     LEAVE;
     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl putmsg eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlputmsg = 0;
       return 1;
     }
     svchange = perl_get_sv("change", FALSE);
     if (rc && svchange && SvTRUE(svchange))
     { /*  change */
       char *ptr;
       freeMsgBuffers(msg);
       ptr = SvPV(perl_get_sv("text", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->text = safe_strdup(ptr);
       msg->textLength = strlen(msg->text);
       ptr = SvPV(perl_get_sv("toname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->toUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("fromname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->fromUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("subject", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->subjectLine = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("toaddr", FALSE), n_a);
       if (n_a > 0) string2addr(ptr, &(msg->destAddr));
       ptr = SvPV(perl_get_sv("fromaddr", FALSE), n_a);
       if (n_a > 0) string2addr(ptr, &(msg->origAddr));
       /* update message kludges, if needed */
       if (msg->netMail) update_addr(msg);
       /* process flags, update message if needed */
       attr = SvUV(perl_get_sv("attr", FALSE));
       msg->attributes = attr & 0xffff;
       if (msg->netMail)
         if ((ptr = update_flags(msg->text, attr, MODE_REPLACE)) != NULL) {
             if (ptr != msg->text) { free(msg->text); msg->text = ptr; }
             msg->textLength = strlen(msg->text);
         }
       /* process date */
       svdate = perl_get_sv("date", FALSE);
       if ( (SvIOK(svdate)) && (SvUV(svdate) > 0) ) {
              date = SvUV(svdate);
              make_ftsc_date(msg->datetime, localtime(&date));
       }
       else if ( SvPOK(svdate) ) {
              ptr = SvPV(svdate, n_a); if (n_a == 0) ptr = "";
              if (fts2unix(ptr, NULL) > 0) {
                  strncpy(msg->datetime, ptr, sizeof(msg->datetime));
                  msg->datetime[sizeof(msg->datetime)-1] = '\0';
              }
       }
     }
   }
   return rc;
}

int perl_export(s_area *echo, s_link *link, s_message *msg)
{
   char *prc;
   unsigned long attr;
   time_t date;
   SV *svfromname, *svtoname, *svtoaddr, *svsubj, *svattr, *svdate, *svtext;
   SV *svarea, *svchange, *svret;
   STRLEN n_a;
   static int do_perlexport=1;

   VK_START_HOOK(perlexport, SUB_EXPORT, 1)

   { dSP;
     svtoaddr   = perl_get_sv("toaddr",   TRUE);
     svfromname = perl_get_sv("fromname", TRUE);
     svtoname   = perl_get_sv("toname",   TRUE);
     svdate     = perl_get_sv("date",     TRUE);
     svsubj     = perl_get_sv("subject",  TRUE);
     svtext     = perl_get_sv("text",     TRUE);
     svchange   = perl_get_sv("change",   TRUE);
     svarea     = perl_get_sv("area",     TRUE);
     svattr     = perl_get_sv("attr",     TRUE);
     sv_setpv(svtoaddr,   aka2str(link->hisAka));
     sv_setpv(svfromname, msg->fromUserName);
     sv_setpv(svtoname,   msg->toUserName);

     sv_setuv(svdate,     (unsigned long)fts2unix(msg->datetime, NULL) );
     sv_setpv(svdate,     msg->datetime);
     SvIOK_on(svdate);

     sv_setpv(svsubj,     msg->subjectLine);
     sv_setpv(svtext,     msg->text);
     sv_setsv(svchange,   &sv_undef);
     sv_setpv(svarea,     echo->areaName);
     sv_setuv(svattr,     msg->attributes | parse_flags(msg->text));

     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     PUTBACK;
     perl_call_pv(PERLEXPORT, G_EVAL|G_SCALAR);
     SPAGAIN;
     svret=POPs;
     if (SvTRUE(svret))
       prc = safe_strdup(SvPV(svret, n_a));
     else
       prc = NULL;
     PUTBACK;
     FREETMPS;
     LEAVE;
     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl export eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlexport = 0;
       return 1;
     }

     if (prc)
     {
       w_log(LL_PERL, "PerlExport: Area %s, link %s: %s",
                     echo->areaName, aka2str(link->hisAka), prc);
       return 0;
     }

     svchange = perl_get_sv("change", FALSE);
     if (svchange && SvTRUE(svchange))
     { /*  change */
       char *ptr;
       freeMsgBuffers(msg);
       ptr = SvPV(perl_get_sv("text", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->text = safe_strdup(ptr);
       msg->textLength = strlen(msg->text);
       ptr = SvPV(perl_get_sv("toname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->toUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("fromname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->fromUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("subject", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->subjectLine = safe_strdup(ptr);
       /* process flags, update message if needed */
       attr = SvUV(perl_get_sv("attr", FALSE));
       msg->attributes = attr & 0xffff;
       if (msg->netMail)
         if ((ptr = update_flags(msg->text, attr, MODE_REPLACE)) != NULL) {
             if (ptr != msg->text) { free(msg->text); msg->text = ptr; }
             msg->textLength = strlen(msg->text);
         }
       /* process date */
       svdate = perl_get_sv("date", FALSE);
       if ( (SvIOK(svdate)) && (SvUV(svdate) > 0) ) {
              date = SvUV(svdate);
              make_ftsc_date(msg->datetime, localtime(&date));
       }
       else if ( SvPOK(svdate) ) {
              ptr = SvPV(svdate, n_a); if (n_a == 0) ptr = "";
              if (fts2unix(ptr, NULL) > 0) {
                  strncpy(msg->datetime, ptr, sizeof(msg->datetime));
                  msg->datetime[sizeof(msg->datetime)-1] = '\0';
              }
       }
     }
   }
   return 1;
}

int perl_robotmsg(s_message *msg, char *type)
{
   int rc = 0;
   SV *svfromname, *svfromaddr, *svtoname, *svtoaddr;
   SV *svtext, *svsubj, *svret, *svtype;
   STRLEN n_a;
   static int do_perlrobotmsg = 1;

   VK_START_HOOK(perlrobotmsg, SUB_ON_ROBOTMSG, 0)

   { dSP;
     svtype     = perl_get_sv("type",      TRUE);
     svfromname = perl_get_sv("fromname",  TRUE);
     svfromaddr = perl_get_sv("fromaddr",  TRUE);
     svtoname   = perl_get_sv("toname",    TRUE);
     svtoaddr   = perl_get_sv("toaddr",    TRUE);
     svsubj     = perl_get_sv("subject",   TRUE);
     svtext     = perl_get_sv("text",      TRUE);

     if (type) sv_setpv(svtype, type); else sv_setsv(svtype, &sv_undef);
     sv_setpv(svfromname,  msg->fromUserName);
     sv_setpv(svfromaddr,  aka2str(msg->origAddr));
     sv_setpv(svtoname,    msg->toUserName);
     sv_setpv(svtoaddr,    aka2str(msg->destAddr));
     sv_setpv(svsubj,      msg->subjectLine);
     sv_setpv(svtext,      msg->text);

     ENTER;
     SAVETMPS;
     PUSHMARK(SP);
     PUTBACK;
     perl_call_pv(PERLROBOTMSG, G_EVAL|G_SCALAR);
     SPAGAIN;
     svret=POPs;
     if (!SvOK(svret)) rc = 0; else rc = SvIV(svret);
     PUTBACK;
     FREETMPS;
     LEAVE;
     if (SvTRUE(ERRSV))
     {
       w_log(LL_ERR, "Perl on_robotmsg eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlrobotmsg = 0;
       return 0;
     }
     if (rc)
     { /*  change */
       char *ptr;
       freeMsgBuffers(msg);
       ptr = SvPV(perl_get_sv("text", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->text = safe_strdup(ptr);
       msg->textLength = strlen(msg->text);
       ptr = SvPV(perl_get_sv("toname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->toUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("fromname", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->fromUserName = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("subject", FALSE), n_a);
       if (n_a == 0) ptr = "";
       msg->subjectLine = safe_strdup(ptr);
       ptr = SvPV(perl_get_sv("toaddr", FALSE), n_a);
       if (n_a > 0) string2addr(ptr, &(msg->destAddr));
       ptr = SvPV(perl_get_sv("fromaddr", FALSE), n_a);
       if (n_a > 0) string2addr(ptr, &(msg->origAddr));
       return 1;
     }
   }
   return 0;
}

#ifdef __OS2__
char *strdup(const char *src)
{
  char *dest = malloc(strlen(src)+1);
  if (dest) strcpy(dest, src);
  return dest;
}
#endif
