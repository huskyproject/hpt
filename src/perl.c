#include <stdio.h>
#include <time.h>
#include <sys/wait.h>
#ifdef OS2
#define INCL_DOSPROCESS
#include <os2.h>
#endif

#include <fidoconf/common.h>
#include <fidoconf/xstr.h>
#include <fcommon.h>
#include <pkt.h>
#include <global.h>
#include <toss.h>
#include <hptperl.h>

#include <EXTERN.h>
#include <perl.h>
#include <unistd.h>
#include <XSUB.h>

#ifndef sv_undef
#define sv_undef PL_sv_undef
#endif

static PerlInterpreter *perl = NULL;
static int  do_perl=1;

static XS(perl_writeLogEntry)
{
  dXSARGS;
  char *level, *str;
  STRLEN n_a;

  if (items != 2)
  { writeLogEntry(hpt_log, 9, "wrong params number to writeLogEntry (need 2, exist %d)", items);
    XSRETURN_EMPTY;
  }
  level = (char *)SvPV(ST(0), n_a); if (n_a == 0) level = "";
  str   = (char *)SvPV(ST(1), n_a); if (n_a == 0) str   = "";
  writeLogEntry(hpt_log, *level, "%s", str);
  XSRETURN_EMPTY;
}

static XS(perl_putMsgInArea)
{
  dXSARGS;
  char *area, *fromname, *toname, *fromaddr, *toaddr;
  char *subject, *date, *sattr, *text;
  int  addkludges;
  char *p;
  STRLEN n_a;
  int narea, rc;
  s_area *echo;
  s_message msg;

  if (items != 10)
  { writeLogEntry(hpt_log, 9, "wrong params number to putMsgInArea (need 10, exist %d)", items);
    XSRETURN_PV("Invalid arguments");
  }
  area     = (char *)SvPV(ST(0), n_a); if (n_a == 0) area     = "";
  fromname = (char *)SvPV(ST(1), n_a); if (n_a == 0) fromname = "";
  toname   = (char *)SvPV(ST(2), n_a); if (n_a == 0) toname   = "";
  fromaddr = (char *)SvPV(ST(3), n_a); if (n_a == 0) fromaddr = "";
  toaddr   = (char *)SvPV(ST(4), n_a); if (n_a == 0) toaddr   = "";
  subject  = (char *)SvPV(ST(5), n_a); if (n_a == 0) subject  = "";
  date     = (char *)SvPV(ST(6), n_a); if (n_a == 0) date     = "";
  sattr    = (char *)SvPV(ST(7), n_a); if (n_a == 0) sattr    = "";
  text     = (char *)SvPV(ST(8), n_a); if (n_a == 0) text     = "";
  addkludges = SvTRUE(ST(9));

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
  if (!date || !*date)
  { time_t t = time(NULL);
    strftime((char *)msg.datetime, 21, "%d %b %y  %H:%M:%S", localtime(&t));
  }
  else
  { strncpy(msg.datetime, date, sizeof(msg.datetime));
    msg.datetime[sizeof(msg.datetime)-1] = '\0';
  }
  msg.subjectLine = safe_strdup(subject);
  msg.toUserName  = safe_strdup(toname);
  msg.fromUserName= safe_strdup(fromname);
  sattr=safe_strdup(sattr);
  for (p=strtok(sattr, " "); p; p=strtok(NULL, " "))
  { dword attr;
    if ((attr = str2attr(p)) != (dword)-1)
      msg.attributes |= attr;
  }
  free(sattr);
  if (addkludges)
    msg.text = createKludges(msg.netMail ? NULL : area, &msg.origAddr, &msg.destAddr);
  text = safe_strdup(text);
  if (strchr(text, '\r') == NULL)
    for (p=text; *p; p++)
      if (*p == '\n')
        *p = '\r';
  xstrcat((char **)(&(msg.text)), text);
  free(text);
  msg.textLength = strlen(msg.text);
  rc = putMsgInArea(echo, &msg, 1, msg.attributes);
  freeMsgBuffers(&msg);
  if (rc)
    XSRETURN_UNDEF;
  else
    XSRETURN_PV("Unable to post message");
}

static XS(perl_str2attr)
{
  dXSARGS;
  char *attr;
  STRLEN n_a;
  if (items != 1)
  { writeLogEntry(hpt_log, 9, "wrong params number to str2attr (need 1, exist %d)", items);
    XSRETURN_IV(-1);
  }
  attr = (char *)SvPV(ST(0), n_a); if (n_a == 0) attr = "";
  XSRETURN_IV(str2attr(attr));
}

static XS(perl_myaddr)
{
  int naddr;
  dXSARGS;
  if (items != 0)
  { writeLogEntry(hpt_log, 9, "wrong params number to myaddr (need 0, exist %d)", items);
    XSRETURN_UNDEF;
  }
  EXTEND(SP, config->addrCount);
  for (naddr=0; naddr<config->addrCount; naddr++)
  { 
    ST(naddr) = sv_newmortal();
    sv_setpv((SV*)ST(naddr), aka2str(config->addr[naddr]));
  }
  XSRETURN(naddr);
}

static XS(perl_nodelistDir)
{
  dXSARGS;
  if (items != 0)
  { writeLogEntry(hpt_log, 9, "wrong params number to nodelistDir (need 0, exist %d)", items);
    XSRETURN_UNDEF;
  }
  EXTEND(SP, 1);
  XSRETURN_PV(config->nodelistDir ? config->nodelistDir : "");
}

unsigned long memcrc32(char *str, int size, unsigned long initcrc);

static XS(perl_crc32)
{
  dXSARGS;
  STRLEN n_a;
  char *str;
  if (items != 1)
  { writeLogEntry(hpt_log, 9, "wrong params number to crc32 (need 1, exist %d)", items);
    XSRETURN_IV(0);
  }
  str = (char *)SvPV(ST(0), n_a);
  XSRETURN_IV(memcrc32(str, n_a, 0xFFFFFFFFul));
}

void boot_DynaLoader(CV *cv);
void boot_DB_File(CV *cv);
void boot_Fcntl(CV *cv);
void boot_POSIX(CV *cv);
void boot_SDBM_File(CV *cv);
void boot_IO(CV *cv);
void boot_OS2__Process(CV *cv);
void boot_OS2__ExtAttr(CV *cv);
void boot_OS2__REXX(CV *cv);

static void xs_init(void)
{
  static char *file = __FILE__;
#if defined(OS2)
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
  newXS("writeLogEntry", perl_writeLogEntry, file);
  newXS("putMsgInArea",  perl_putMsgInArea,  file);
  newXS("str2attr",      perl_str2attr,      file);
  newXS("myaddr",        perl_myaddr,        file);
  newXS("nodelistDir",   perl_nodelistDir,   file);
  newXS("crc32",         perl_crc32,         file);
}

static void exitperl(void)
{
  if (perl)
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
    perl_destruct(perl);
    perl_free(perl);
    perl=NULL;
  }
}

#if defined(OS2)
static void perlthread(ULONG arg)
{
  FILE *f;
  char str[256], *p;
  if ((f=fdopen((int)arg, "r")) == NULL)
    return;
  while (fgets(str, sizeof(str), f))
  { if ((p = strchr(str, '\n')) != NULL)
      *p = '\0';
    writeLogEntry(hpt_log, '8', "PERL: %s", str);
  }
  fclose(f);
}
#endif

static int handleperlerr(int *saveerr)
{
   int perlpipe[2], pid;

#if defined(UNIX)
   pipe(perlpipe);
perl_fork:
   if ((pid=fork())>0)
   {
     *saveerr=dup(fileno(stderr));
     dup2(perlpipe[1], fileno(stderr));
     close(perlpipe[0]);
     close(perlpipe[1]);
   }
   else if (pid==0)
   { FILE *f;
     char str[256];
     close(perlpipe[1]);
     f=fdopen(perlpipe[0], "r");
     while (fgets(str, sizeof(str), f))
     { char *p = strchr(str, '\n');
       if (p) *p = '\0';
       writeLogEntry(hpt_log, '8', "PERL: %s", str);
     }
     fclose(f);
     fflush(stdout);
     _exit(0); 
   }
   else
   { if (errno==EINTR)
       goto perl_fork;
     writeLogEntry(hpt_log, '9', "Can't fork(): %s!", strerror(errno));
     close(perlpipe[1]);
     close(perlpipe[0]);
     return 0;
   }
#elif defined(OS2)
   pipe(perlpipe);
   *saveerr=dup(fileno(stderr));
   dup2(perlpipe[1], fileno(stderr));
   close(perlpipe[1]);
   DosCreateThread((PTID)&pid, perlthread, perlpipe[0], 0, 65536);
#else
   *saveerr=dup(fileno(stderr));
   perlpipe[0]=open("/dev/null", O_WRONLY);
   if (perlpipe[0]!=-1)
   { dup2(perlpipe[0], fileno(stderr));
     close(perlpipe[0]);
   }
   pid=0;
#endif
   return pid;
}

static void restoreperlerr(int saveerr, int pid)
{
   dup2(saveerr, fileno(stderr));
   close(saveerr);
   if (pid == 0)
     return;
#if defined(UNIX)
   waitpid(pid, &pid, 0);
#elif defined(OS2)
   DosWaitThread((PTID)&pid, DCWW_WAIT);
#endif
}

static int PerlStart(void)
{
   int rc;
   char *perlargs[]={"", PERLFILE, NULL};
   int saveerr, pid;

   if (access(PERLFILE, R_OK))
   { writeLogEntry(hpt_log, '8', "Can't read " PERLFILE ": %s, perl filtering disabled",
                   strerror(errno));
     do_perl=0;
     return 1;
   }
   perl = perl_alloc();
   perl_construct(perl);
   pid=handleperlerr(&saveerr);
   rc=perl_parse(perl, xs_init, 2, perlargs, NULL);
   restoreperlerr(saveerr, pid);
   if (rc)
   { writeLogEntry(hpt_log, '9', "Can't parse " PERLFILE ", perl filtering disabled");
     perl_destruct(perl);
     perl_free(perl);
     perl=NULL;
     do_perl=0;
     return 1;
   }
   atexit(exitperl);
   return 0;
}

int perlscanmsg(char *area, s_message *msg)
{
   static int do_perlscan = 1;
   char *prc;
   int pid, saveerr;
   SV *svfromname, *svfromaddr, *svtoname, *svtoaddr, *svattr;
   SV *svdate, *svtext, *svarea, *svsubj, *svret, *svchange;
   STRLEN n_a;

   if (do_perl && perl == NULL)
     PerlStart();
   if (!perl || !do_perlscan)
     return 0;

   pid = handleperlerr(&saveerr);
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
     sv_setpv(svfromname, msg->fromUserName);
     sv_setpv(svfromaddr, aka2str(msg->origAddr));
     sv_setpv(svtoname,   msg->toUserName);
     sv_setpv(svdate,     msg->datetime);
     sv_setpv(svsubj,     msg->subjectLine);
     sv_setpv(svtext,     msg->text);
     sv_setsv(svchange,   &sv_undef);
     sv_setiv(svattr,     msg->attributes);
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
     restoreperlerr(saveerr, pid);
     if (SvTRUE(ERRSV))
     {
       writeLogEntry(hpt_log, '8', "Perl scan eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlscan = 0;
       return 0;
     }
     svchange = perl_get_sv("change", FALSE);
     if (prc)
     {
       if (msg->netMail)
         writeLogEntry(hpt_log, '8', "PerlScan: NetMail from %s %u:%u/%u.%u to %s %u:%u/%u.%u: %s",
                       msg->fromUserName,
                       msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node, msg->origAddr.point,
                       msg->toUserName,
                       msg->destAddr.zone, msg->destAddr.net, msg->destAddr.node, msg->destAddr.point,
                       prc);
       else
         writeLogEntry(hpt_log, '8', "PerlScan: Area %s from %s %u:%u/%u.%u: %s",
                       area, msg->fromUserName,
                       msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node, msg->origAddr.point,
                       prc);
       free(prc);
       return 1;
     }
     else if (svchange && SvTRUE(svchange))
     { // change
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
       prc = SvPV(perl_get_sv("subject", FALSE), n_a);
       if (n_a == 0) prc = "";
       msg->subjectLine = safe_strdup(prc);
       prc = SvPV(perl_get_sv("toaddr", FALSE), n_a);
       if (n_a > 0) string2addr(prc, &(msg->destAddr));
       prc = SvPV(perl_get_sv("fromaddr", FALSE), n_a);
       if (n_a > 0) string2addr(prc, &(msg->origAddr));
       msg->attributes = SvIV(perl_get_sv("attr", FALSE));
     }
   }
   return 0;
}

s_route *perlroute(s_message *msg)
{
   static int do_perlroute = 1;
   int pid, saveerr;

   if (do_perl && perl==NULL)
     PerlStart();
   if (!perl || !do_perlroute)
     return NULL;
   pid = handleperlerr(&saveerr);
   { SV *svaddr, *svattr, *svflv, *svfrom, *svret;
     char *routeaddr;
     STRLEN n_a;
     static s_route route;
     dSP;
     svaddr  = perl_get_sv("addr",    TRUE);
     svfrom  = perl_get_sv("from",    TRUE);
     svflv   = perl_get_sv("flavour", TRUE);
     svattr  = perl_get_sv("attr",    TRUE);
     sv_setpv(svaddr, aka2str(msg->destAddr));
     sv_setpv(svfrom, aka2str(msg->origAddr));
     sv_setiv(svattr, msg->attributes);
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
     restoreperlerr(saveerr, pid);
     if (SvTRUE(ERRSV))
     {
       writeLogEntry(hpt_log, '8', "Perl route eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlroute = 0;
     }
     else if (routeaddr)
     {
       char *flv = SvPV(perl_get_sv("flavour", FALSE), n_a);
       static char srouteaddr[32];
       if (n_a == 0) flv = "";
       memset(&route, 0, sizeof(route));
       if ((route.target = getLink(*config, routeaddr)) == NULL) {
         route.routeVia = route_extern;
         route.viaStr = srouteaddr;
         strncpy(srouteaddr, routeaddr, sizeof(srouteaddr));
         srouteaddr[sizeof(srouteaddr)-1] = '\0';
       }
       if (flv == NULL || *flv == '\0')
       {
         if (route.target)
           route.flavour = route.target->echoMailFlavour;
         else
           route.flavour = hold;
       }
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
       else {
         writeLogEntry(hpt_log, '8', "Perl route unknown flavour %s, set to hold", flv);
         route.flavour = hold;
       }
       free(routeaddr);
       return &route;
     }
   }
   return NULL;
}

int perlfilter(s_message *msg, s_addr pktOrigAddr, int secure)
{
   char *area = NULL, *prc;
   int rc = 0;
   SV *svfromname, *svfromaddr, *svtoname, *svtoaddr, *svpktfrom, *svkill;
   SV *svdate, *svtext, *svarea, *svsubj, *svsecure, *svret; 
   SV *svchange, *svattr;
   STRLEN n_a;
   static int do_perlfilter=1;
   int pid, saveerr;

   if (do_perl && perl==NULL)
     if (PerlStart())
       return 0;
   if (!perl || !do_perlfilter)
     return 0;

   pid = handleperlerr(&saveerr);
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
     sv_setpv(svdate,     msg->datetime);
     sv_setpv(svsubj,     msg->subjectLine);
     sv_setpv(svtext,     msg->text);
     sv_setpv(svpktfrom,  aka2str(pktOrigAddr));
     sv_setsv(svkill,     &sv_undef);
     sv_setsv(svchange,   &sv_undef);
     sv_setiv(svattr,     msg->attributes);
     if (secure)
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
     perl_call_pv(PERLFILT, G_EVAL|G_SCALAR);
     SPAGAIN;
     svret=POPs;
     if (SvTRUE(svret))
       prc = safe_strdup(SvPV(svret, n_a));
     else
       prc = NULL;
     PUTBACK;
     FREETMPS;
     LEAVE;
     restoreperlerr(saveerr, pid);
     if (SvTRUE(ERRSV))
     {
       writeLogEntry(hpt_log, '8', "Perl filter eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlfilter = 0;
       if (area) free(area);
       return 0;
     }
     svchange = perl_get_sv("change", FALSE);
     if (prc)
     {
       if (area)
         writeLogEntry(hpt_log, '8', "PerlFilter: Area %s from %s %u:%u/%u.%u: %s",
                       area, msg->fromUserName,
                       msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node, msg->origAddr.point,
                       prc);
       else
         writeLogEntry(hpt_log, '8', "PerlFilter: NetMail from %s %u:%u/%u.%u to %s %u:%u/%u.%u: %s",
                       msg->fromUserName,
                       msg->origAddr.zone, msg->origAddr.net, msg->origAddr.node, msg->origAddr.point,
                       msg->toUserName,
                       msg->destAddr.zone, msg->destAddr.net, msg->destAddr.node, msg->destAddr.point,
                       prc);
       svkill = perl_get_sv("kill", FALSE);
       if (svkill && SvTRUE(svkill))
         rc = 2;
       else
         rc = 1;
       free(prc);
     }
     else if (svchange && SvTRUE(svchange))
     { // change
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
       prc = SvPV(perl_get_sv("subject", FALSE), n_a);
       if (n_a == 0) prc = "";
       msg->subjectLine = safe_strdup(prc);
       prc = SvPV(perl_get_sv("toaddr", FALSE), n_a);
       if (n_a > 0) string2addr(prc, &(msg->destAddr));
       prc = SvPV(perl_get_sv("fromaddr", FALSE), n_a);
       if (n_a > 0) string2addr(prc, &(msg->origAddr));
       msg->attributes = SvIV(perl_get_sv("attr", FALSE));
     }
   }
   if (area) free(area);
   return rc;
}

int perlpkt(const char *fname, int secure)
{
   static int do_perlpkt = 1;
   char *prc = NULL;
   STRLEN n_a;
   SV *svpktname, *svsecure, *svret;
   int pid, saveerr;

   if (do_perl && perl==NULL)
     if (PerlStart())
       return 0;
   if (!perl || !do_perlpkt)
     return 0;
   pid = handleperlerr(&saveerr);
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
     restoreperlerr(saveerr, pid);
     if (SvTRUE(ERRSV))
     {
       writeLogEntry(hpt_log, '8', "Perl pkt eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlpkt = 0;
     }
     else if (prc)
     {
       writeLogEntry(hpt_log, '8', "Packet %s rejected by perl filter: %s", fname, prc);
       free(prc);
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
   int pid, saveerr;

   if (do_perl && perl==NULL)
     if (PerlStart())
       return;
   if (!perl || !do_perlpktdone)
     return;
   pid = handleperlerr(&saveerr);
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
     restoreperlerr(saveerr, pid);
     if (SvTRUE(ERRSV))
     {
       writeLogEntry(hpt_log, '8', "Perl pktdone eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlpktdone = 0;
     }
   }
}

void perlafterunp(void)
{
   static int do_perlafterunp = 1;
   STRLEN n_a;
   int pid, saveerr;

   if (do_perl && perl==NULL)
     if (PerlStart())
       return;
   if (!perl || !do_perlafterunp)
     return;
   pid = handleperlerr(&saveerr);
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
     restoreperlerr(saveerr, pid);
     if (SvTRUE(ERRSV))
     {
       writeLogEntry(hpt_log, '8', "Perl afterunp eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlafterunp = 0;
     }
   }
}

void perlbeforepack(void)
{
   static int do_perlbeforepack = 1;
   STRLEN n_a;
   int pid, saveerr;

   if (do_perl && perl==NULL)
     if (PerlStart())
       return;
   if (!perl || !do_perlbeforepack)
     return;
   pid = handleperlerr(&saveerr);
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
     restoreperlerr(saveerr, pid);
     if (SvTRUE(ERRSV))
     {
       writeLogEntry(hpt_log, '8', "Perl beforepack eval error: %s\n", SvPV(ERRSV, n_a));
       do_perlbeforepack = 0;
     }
   }
}

#ifdef OS2
char *strdup(const char *src)
{
  char *dest = malloc(strlen(src)+1);
  if (dest) strcpy(dest, src);
  return dest;
}
#endif
