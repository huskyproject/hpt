/*****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 * Copyright (C) 1997-1999
 *
 * Matthias Tichy
 *
 * Fido:     2:2433/1245 2:2433/1247 2:2432/605.14
 * Internet: mtt@tichy.de
 *
 * Grimmestr. 12         Buchholzer Weg 4
 * 33098 Paderborn       40472 Duesseldorf
 * Germany               Germany
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
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#ifdef UNIX
#include <sysexits.h>
#endif

#if !defined(__IBMC__) && !defined(__TURBOC__) && !(defined(_MSC_VER) && (_MSC_VER >= 1200))
#include <unistd.h>
#endif
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>

#include <smapi/msgapi.h>
#include <smapi/progprot.h>

#include <version.h>
#include <pkt.h>

#include <fidoconf/fidoconf.h>
#include <fidoconf/dirlayer.h>
#include <fidoconf/xstr.h>
#include <fidoconf/common.h>
 
#include <fidoconf/log.h>

#include <global.h>
#include <hpt.h>
#include <toss.h>
#include <scan.h>
#include <fcommon.h>
#include <smapi/patmat.h>
#include <post.h>
#include <link.h>
#include <areafix.h>
#include <fidoconf/recode.h>
#include <cvsdate.h>
#include <query.h>

#ifdef _MSC_VER
#ifdef DO_PERL
#include <delayimp.h>
// This is the failure hook, dliNotify = {dliFailLoadLib|dliFailGetProc}
#if defined(__cplusplus)
extern "C"
#endif
extern
PfnDliHook   __pfnDliFailureHook;
#endif
#endif

s_log         *hpt_log = NULL;
s_message    **msgToSysop = NULL;
s_query_areas *queryAreasHead = NULL;
char *scanParmA;
char *scanParmF;
char force = 0;

/* kn: I've really tried not to break it. 
   FIXME: if there is pack and scan options on cmd line - one set 
   of options are lost */
int  processExportOptions(int *i, int argc, char **argv)
{ 
  int rc = 0;
  while ((*i) < argc-1) {
     if (argv[(*i)+1][0] == '-' && (argv[(*i)+1][1] == 'w' || argv[(*i)+1][1] == 'W')) {
        noHighWaters = 1;
        (*i)++;
        continue;
     } /* endif */
     if (argv[(*i)+1][0] == '-' && (argv[(*i)+1][1] == 'f' || argv[(*i)+1][1] == 'F')) {
        if (stricmp(argv[(*i)+1], "-f") == 0) {
           (*i)++;
           scanParmF = argv[(*i)+1];
        } else {
           scanParmF = argv[(*i)+1]+2;
        } /* endif */
        rc |= 2;
        (*i)++;
        continue;
     } else if (argv[(*i)+1][0] == '-' && (argv[(*i)+1][1] == 'a' || argv[(*i)+1][1] == 'A')) {
        if (stricmp(argv[(*i)+1], "-a") == 0) {
           (*i)++;
           scanParmA = argv[(*i)+1];
        } else {
           scanParmA = argv[(*i)+1]+2;
        } /* endif */
        rc |= 4;
        (*i)++;
        continue;
     } /* endif */
     break;
  } /* endwhile */
  return rc != 0 ? rc : 1;
}

void start_help(void) {
  fprintf(stdout,"%s",versionStr);
  fprintf(stdout,"\nUsage: hpt [-c config] [options]\n");
  fprintf(stdout,"   hpt toss - tossing mail\n");
  fprintf(stdout,"   hpt toss -b[f] - tossing mail from badarea [force]\n");
  fprintf(stdout,"   hpt scan - scanning echomail\n");
  fprintf(stdout,"   hpt scan -w - scanning echomail without highwaters\n");
  fprintf(stdout,"   hpt scan -a <areaname> - scanning echomail from <areaname> area\n");
  fprintf(stdout,"   hpt scan -f <filename> - scanning echomail from alternative echotoss file\n");
  fprintf(stdout,"   hpt post [options] file - posting a mail (for details run \"hpt post -h\")\n");
  fprintf(stdout,"   hpt pack - packing netmail\n");
  fprintf(stdout,"   hpt pack -a <areaname> - packing netmail from <areaname> area\n");
  fprintf(stdout,"   hpt pack -f <filename> - packing netmail from alternative echotoss file\n");
  fprintf(stdout,"   hpt link [areamask] - links messages\n");
  fprintf(stdout,"   hpt afix [<addr> command] - process areafix\n");
  fprintf(stdout,"   hpt relink <addr> - refresh area subsription\n");
  fprintf(stdout,"   hpt pause - set pause for links who don't poll our system\n");
  fprintf(stdout,"   hpt -q [options] - quiet mode (no screen output)\n");
}

int processCommandLine(int argc, char **argv)
{
   int i = 0;

   if (argc == 1) start_help();

   while (i < argc-1) {
      i++;
      if (0 == stricmp(argv[i], "toss")) {
         cmToss = 1;
         if (i < argc-1) {
	     if (stricmp(argv[i+1], "-b") == 0) {
                cmToss = 2;
                break;
	     } else 
	     if (stricmp(argv[i+1], "-bf") == 0) {
                cmToss = 2;
		force = 1;
                break;
	     }
         }
         continue;
      } else if (stricmp(argv[i], "scan") == 0) {
 	 cmScan = processExportOptions(&i, argc, argv);
         continue;
      } else if (stricmp(argv[i], "pack") == 0) {
         cmPack = processExportOptions(&i, argc, argv);
         continue;
      } else if (stricmp(argv[i], "link") == 0) {
		  if (i < argc-1) {
			  i++;
			  xstrcat(&linkName,argv[i]);
		  }
		  cmLink = 1;
		  continue;
      } else if (stricmp(argv[i], "afix") == 0) {
		  if (i < argc-1) {
			  i++;
			  string2addr(argv[i], &afixAddr);
			  if (i < argc-1) {
				  i++;
				  xstrcat(&afixCmd,argv[i]);
			  } else printf("parameter missing after \"%s\"!\n", argv[i]);
		  }
		  cmAfix = 1;
		  continue;
      } else if (stricmp(argv[i], "post") == 0) {
         ++i; post(argc, &i, argv);
      } else if (stricmp(argv[i], "relink") == 0) {
         i++; relink(argv[i]);
      } else if (stricmp(argv[i], "qupdate") == 0) {
          cmQueue = 1;
      } else if (stricmp(argv[i], "qreport") == 0) {
          cmQueue = 2;
      } else if (stricmp(argv[i], "-c") == 0) {
		  i++;
		  if (argv[i]!=NULL) xstrcat(&cfgFile, argv[i]);
		  else printf("parameter missing after \"%s\"!\n", argv[i-1]);
		  continue;
      } else if (stricmp(argv[i], "-q") == 0) {
		  quiet = 1;
		  continue;
      } else if (stricmp(argv[i], "-h") == 0) {
		  start_help();
		  return 1;
      } else if (stricmp(argv[i], "pause") == 0) {
		  cmPause = 1;
		  continue;
      } else {
		  printf("Unrecognized commandline option \"%s\"!\n", argv[i]);
		  return EX_USAGE;
	  }

   } /* endwhile */

   return argc;
}

void allDiff(char *nam, char *var, ...)
{
   va_list	ap;
   char	*ptr;

   struct diffCmp {
      char *name;
      char *var;
   } *diffData;

   int	ncmp, i, j;

   for (va_start(ap, var), ncmp = 1; va_arg(ap, char *) != NULL; ) {
      ptr = va_arg(ap, char *); // variable may be set ti NULL
      ncmp++;
   }

   diffData = safe_malloc(ncmp * sizeof(struct diffCmp));

   diffData[0].name = nam;
   diffData[0].var  = var;

   for (va_start(ap, var), i=1; i<ncmp; i++) {
      diffData[i].name = va_arg(ap, char *);
      diffData[i].var  = va_arg(ap, char *);
   }
   ptr = NULL;

   for (i=0; i < ncmp-1; i++) {
      if (diffData[i].var) {
         for (j=i+1; j < ncmp; j++) {
            if (diffData[j].var && strcmp (diffData[i].var, diffData[j].var) == 0) {
               xscatprintf(&ptr, "%s & %s must be different", diffData[i].name, diffData[j].name);
               nfree(diffData);
               exit_hpt(ptr, 1);
            }
         }
      }
   }   

   nfree(diffData);
}


void processConfig()
{
   char *buff = NULL;
//#if !defined(__OS2__) && !defined(UNIX)
//   time_t   time_cur, locklife = 0;
//   struct   stat stat_file;
//#endif
//   unsigned long pid;
//   FILE *f;

   setvar("module", "hpt");
   xscatprintf(&buff, "%u.%u.%u", VER_MAJOR, VER_MINOR, VER_PATCH);
   setvar("version", buff);
   nfree(buff);
   config = readConfig(cfgFile);
   if (NULL == config) {
       nfree(cfgFile);
       fprintf(stderr,"Config not found\n");
       exit(EX_UNAVAILABLE);
   }

/*
   // lock...
   if (config->lockfile!=NULL && fexist(config->lockfile)) {
	   if ((f = fopen(config->lockfile, "rt"))==NULL) {
		   fprintf(stderr,"Can't open file: \"%s\"\n",config->lockfile);
		   exit_hpt("Can't open lock-file",0);
	   }
	   fscanf(f, "%lu\n", &pid);
	   fclose(f);
	   // Checking process PID
#ifdef __OS2__
      if (DosKillProcess(DKP_PROCESSTREE, pid) == ERROR_NOT_DESCENDANT) {
#elif UNIX
      if (kill(pid, 0) == 0) {
#else
      if (stat(config->lockfile, &stat_file) != -1) {
          time_cur = time(NULL);
	  locklife = (time_cur - stat_file.st_mtime)/60;
      }
      if (locklife < 180) {
#endif
           fprintf(stderr,"lock file found! exit...\n");
           disposeConfig(config);
           exit(1);
      } else {
         remove(config->lockfile);
         createLockFile(config->lockfile);
      }
   }
   else if (config->lockfile!=NULL) createLockFile(config->lockfile);
*/
   if (config->lockfile) {
       _lockfile = safe_strdup(config->lockfile);
       if (config->advisoryLock) {
	   if ((lock_fd=open(config->lockfile,O_CREAT|O_RDWR,S_IREAD|S_IWRITE))<0) {
	       fprintf(stderr,"cannot open/create lock file: %s\n",config->lockfile);
	       disposeConfig(config);
	       exit(EX_CANTCREAT);
	   } else {
	       if (write(lock_fd," ", 1)!=1) {
		   fprintf(stderr,"can't write to lock file! exit...\n");
		   disposeConfig(config);
		   exit(EX_IOERR);
	       }
	       if (lock(lock_fd,0,1)<0) {
		   fprintf(stderr,"lock file used by another process! exit...\n");
		   disposeConfig(config);
		   exit(EX_TEMPFAIL);
	       }
	   }
       } else { // normal locking
	   if ((lock_fd=open(config->lockfile,
			     O_CREAT|O_RDWR|O_EXCL,S_IREAD|S_IWRITE))<0) {
	       fprintf(stderr,"cannot create new lock file: %s\n",config->lockfile);
	       fprintf(stderr,"lock file probably used by another process! exit...\n");
	       disposeConfig(config);
	       exit(EX_CANTCREAT);
	   }
       }
   }   

   // open Logfile
   if (config->logFileDir) {
	xstrscat(&buff, config->logFileDir, LogFileName, NULL);
	hpt_log = openLog(buff, versionStr, config);
	if (hpt_log && quiet) hpt_log->logEcho=0; /* Don't display messages */
	nfree(buff);
   } else 
     fprintf(stderr,"logFileDir not defined, there will be no log created!\n");
   
   if (config->addrCount == 0) exit_hpt("at least one addr must be defined",1);
   if (config->linkCount == 0) exit_hpt("at least one link must be specified",1);
   if (config->outbound == NULL) exit_hpt("you must set outbound in fidoconfig first",1);
   if (config->tempOutbound == NULL) exit_hpt("you must set tempOutbound in fidoconfig first",1);
   if (config->inbound == NULL && config->protInbound == NULL)
	   exit_hpt("you must set Inbound or protInbound in fidoconfig first",1);
   if (config->tempInbound == NULL) exit_hpt("you must set tempInbound in fidoconfig first",1);
   if (config->msgBaseDir==NULL) exit_hpt("No msgBaseDir specified in config file!",1);
   if (config->dupeHistoryDir==NULL) exit_hpt("No dupeHistoryDir specified in config file!",1);
   if (config->dupeArea.areaName==NULL) exit_hpt("you must define DupeArea!",1);
   if (config->dupeArea.fileName==NULL) exit_hpt("DupeArea can not be passthrough!",1);
   if (config->badArea.areaName==NULL) exit_hpt("you must define BadArea!",1);
   if (config->badArea.fileName==NULL) exit_hpt("BadArea can not be passthrough!",1);

   allDiff ( "Inbound",      config->inbound,
			 "tempInbound",  config->tempInbound,
			 "protInbound",  config->protInbound,
			 "localInbound", config->localInbound,
			 "outbound",     config->outbound,
			 "tempOutbound", config->tempOutbound,
			 NULL);
   
   // load recoding tables
   initCharsets();
   if (config->outtab) getctab(outtab, (unsigned char*) config->outtab);
   if (config->intab) getctab(intab, (unsigned char*) config->intab);
}

int isFreeSpace(char *path) {
	unsigned long sp;

	sp = getfree(path);	
	if (sp < config->minDiskFreeSpace*1024) {
		fprintf(stderr, "no free space in %s! (needed %d mb, available %d mb).\n",
				path, config->minDiskFreeSpace, (unsigned)(sp/1024));
		exit_hpt("no free disk space!",0);
	}

	return 0;
}


#ifdef _MSC_VER
#ifdef DO_PERL
FARPROC WINAPI ourhook(unsigned dliNotify,PDelayLoadInfo pdli)
{
  //print error message and exit
  char msg[128];
  memset(msg,0,sizeof(msg));
  sprintf(msg,"perSupport is On but loading of %s failed - exiting ",pdli->szDll);
  w_log('8',msg);
  //standart deinit sequence
  // deinit SMAPI
  MsgCloseApi();
  w_log('1', "End");

  closeLog(hpt_log);
  doneCharsets();
  nfree(versionStr);
  if (config->lockfile) {
	   close(lock_fd);
	   remove(config->lockfile);
  }

  disposeConfig(config);
  nfree(cfgFile);
  exit(EX_UNAVAILABLE);
   return 0; 
}
#endif 
#endif

int main(int argc, char **argv)
{
   struct _minf m;
   unsigned int i, rc;
   char *version = NULL;
#if defined ( __NT__ )
   #define TITLESIZE 256
   char title[ TITLESIZE ], oldtitle[ TITLESIZE ];
#endif

xscatprintf(&version, "%u.%u.%u%s%s", VER_MAJOR, VER_MINOR, VER_PATCH, VER_SERVICE, VER_BRANCH);

#ifdef __linux__
   xstrcat(&version, "/lnx");
#elif defined(__FreeBSD__) || defined(__NetBSD__)
   xstrcat(&version, "/bsd");
#elif defined(__OS2__) || defined(OS2)
   xstrcat(&version, "/os2");
#elif defined(__NT__)
   xstrcat(&version, "/w32");
#elif defined(__sun__)
   xstrcat(&version, "/sun");
#elif defined(MSDOS)
   xstrcat(&version, "/dos");
#elif defined(__BEOS__)
   xstrcat(&version, "/beos");
#endif


   if (strcmp(VER_BRANCH,"-stable")!=0) xscatprintf(&version, " %s", cvs_date);
   xscatprintf(&versionStr,"hpt %s", version);
   rc = processCommandLine(argc, argv);
   if (rc==1){ nfree(version); nfree(versionStr); exit(EX_OK); }
   if (rc==EX_USAGE){ nfree(version); nfree(versionStr); exit(EX_USAGE); }

//   if (quiet==0) fprintf(stdout, "Highly Portable Tosser %s\n", version);

   if (config==NULL) processConfig();
   w_log(LL_START, "Start");

#if defined ( __NT__ )
   if (config->setConsoleTitle) {
	   sprintf( title, "Highly Portable Tosser %s", version);
	   GetConsoleTitleA( oldtitle, 256 );
	   SetConsoleTitleA( title );
   }
#endif
   nfree(version);

   // check for free space
   if (config->minDiskFreeSpace) {
	   isFreeSpace(config->tempInbound);
	   if (stricmp(config->msgBaseDir,"passthrough")!=0)
		   isFreeSpace(config->msgBaseDir);
	   for (i=0; i<config->linkCount; i++) {
		   if (config->links[i].msgBaseDir && 
			   stricmp(config->links[i].msgBaseDir,"passthrough")!=0)
			   isFreeSpace(config->links[i].msgBaseDir);
	   }
   }

   if ( initSMAPI == -1 ) {
       // init SMAPI
       initSMAPI = 0;
       m.req_version = 2;
       m.def_zone = (UINT16) config->addr[0].zone;
       if (MsgOpenApi(&m) != 0) {
	   exit_hpt("MsgApiOpen Error",1);
       }
   }
#ifdef _MSC_VER
#ifdef DO_PERL
   __pfnDliFailureHook=ourhook;
   //attempt to start Perl
   if (config->perlSupport) PerlStart();
#endif 
#endif
   msgToSysop = (s_message**) safe_malloc(config->addrCount * sizeof(s_message*));
   for (i = 0; i < config->addrCount; i++) {
	   
       /* Some results of wrong patching ? A memleak anyway
	* msgToSysop[i] = (s_message*)malloc(sizeof(s_message));
	*/
       msgToSysop[i] = NULL;
   }

   tossTempOutbound(config->tempOutbound);

   if (1 == cmToss) toss();
   if (cmToss == 2) tossFromBadArea(force);

   if (cmScan == 1) scanExport(SCN_ALL  | SCN_ECHOMAIL, NULL);
   if (cmScan &  2) scanExport(SCN_FILE | SCN_ECHOMAIL, scanParmF);
   if ((cmScan &  4) && scanParmA) scanExport(SCN_NAME | SCN_ECHOMAIL, scanParmA);

   if (cmAfix == 1) afix(afixAddr, afixCmd);
   nfree(afixCmd);

   if (cmPack == 1) scanExport(SCN_ALL  | SCN_NETMAIL, NULL);
   if (cmPack &  2) scanExport(SCN_FILE | SCN_NETMAIL, scanParmF);
   if ((cmPack &  4) && scanParmA) scanExport(SCN_NAME | SCN_NETMAIL, scanParmA);

   if (cmLink == 1) {
	   if (linkName && (strstr(linkName,"*")||strstr(linkName,"?"))) {
		   for (i=0; i < config->echoAreaCount; i++) 
			   if (patimat(config->echoAreas[i].areaName, linkName))
				   linkAreas(config->echoAreas[i].areaName);
		   for (i=0; i < config->localAreaCount; i++) 
			   if (patimat(config->localAreas[i].areaName, linkName))
				   linkAreas(config->localAreas[i].areaName);
		   for (i=0; i < config->netMailAreaCount; i++) 
			   if (patimat(config->netMailAreas[i].areaName, linkName))
				   linkAreas(config->netMailAreas[i].areaName);
	   } else linkAreas(linkName);
   }
   nfree(linkName);

   writeMsgToSysop();

   for (i = 0; i < config->addrCount; i++) {
       if (msgToSysop[i]) freeMsgBuffers(msgToSysop[i]);
       nfree(msgToSysop[i]);
   }
   if (cmPause || config->autoPassive) autoPassive();

   if (cmQueue == 1) af_QueueUpdate();
   if (cmQueue == 2) af_QueueReport();

   // save forward requests info
   af_CloseQuery();
   
   nfree(msgToSysop);
   
   // deinit SMAPI
   MsgCloseApi();

   w_log(LL_STOP, "End");
   closeLog();
   doneCharsets();
   nfree(versionStr);

   if (config->lockfile) {
	close(lock_fd);
	remove(config->lockfile);
   }

#if defined ( __NT__ )
   if (config->setConsoleTitle) SetConsoleTitleA(oldtitle);
#endif
   disposeConfig(config);
   nfree(cfgFile);
   nfree(_lockfile);

   return 0;
}
