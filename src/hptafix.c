/*****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 *
 * hpt-to-libareafix interface by val khokhlov, 2:550/180@fidonet
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

#include <string.h>
#include <huskylib/xstr.h>
#include <smapi/msgapi.h>
#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/afixcmd.h>
#include <areafix/areafix.h>
#include <areafix/afglobal.h>
#include <areafix/callback.h>
#include <areafix/query.h>
#include "global.h"
#include "fcommon.h"
#include "hpt.h"
#include "dupe.h"
#include "scanarea.h"
#include "toss.h"
#ifdef DO_PERL
#include "hptperl.h"
#endif

extern s_message **msgToSysop;

s_area *afGetArea(char *areaName) {
    s_area *area = getArea(config, areaName);
    return area != &(config->badArea) ? area : NULL;
}

int afIsValidConference(const char *s) {
    if (!s || strlen(s) > 60) return BM_AREATAG_TOO_LONG;
    /*  according to FSC-0074 with lowercase symbols */
    /*  lowercase symbols only for internal use */
    while (*s) {
        if ( !(*s >= 33 && *s <= 126) ) return BM_ILLEGAL_CHARS;
        s++;
    }
    return 0;
}

int afSendMsg(s_message *tmpmsg) {
        processNMMsg(tmpmsg, NULL, getRobotsArea(config), 0, MSGLOCAL);
        writeEchoTossLogEntry(getRobotsArea(config)->areaName);
        closeOpenedPkt();
        freeMsgBuffers(tmpmsg);
  return 1;
}

int afWriteMsgToSysop(s_message *msg) {
  msgToSysop[0] = msg;
  writeMsgToSysop();
  freeMsgBuffers(msg);
  msgToSysop[0] = NULL;
  return 1;  
}

void afReportAutoCreate(char *c_area, char *descr, hs_addr pktOrigAddr, ps_addr forwardAddr) {
#if 0 /* val: don't know why is was here; so trying to fix */
  if (forwardAddr == NULL) makeMsgToSysop(c_area, pktOrigAddr, NULL);
  else makeMsgToSysop(c_area, *forwardAddr, &pktOrigAddr);
#else
  makeMsgToSysop(c_area, pktOrigAddr, forwardAddr);
#endif
}

int afDeleteArea(s_link *link, s_area *area) {
   if (area->dupeCheck != dcOff && config->typeDupeBase != commonDupeBase) {
     char *dupename = createDupeFileName(area);
     if (dupename) {
       unlink(dupename);
       nfree(dupename);
     }
   }
   return 1;
}

int afRescanArea(char **report, s_link *link, s_area *area, long rescanCount, long rescanAfter) {
  char *an = area->areaName;
  s_arealink *arealink;
  long rcc;

            arealink = getAreaLink(area, link->hisAka);

            if ((area->msgbType == MSGTYPE_PASSTHROUGH) || (!arealink->rescan)) {
                xscatprintf(report," %s %s  no rescan possible\r",
                            an, print_ch(49-strlen(an), '.'));
                w_log(LL_AREAFIX, "areafix: %s area no rescan possible to %s",
                      an, aka2str(link->hisAka));
            } else {
                if (link->rescanLimit) {
                  if (rescanCount < 0 || rescanCount > link->rescanLimit)
                    rescanCount = link->rescanLimit;
                }
                if (arealink->export) {
                    rcc = rescanEMArea(area, arealink, rescanCount, rescanAfter);
                    tossTempOutbound(config->tempOutbound);
                } else {
                    rcc = 0;
                    xscatprintf(report," %s %s  no access to export\r",
                                an, print_ch(49-strlen(an), '.'));
                    w_log(LL_AREAFIX, "areafix: %s -- no access to export for %s",
                          an, aka2str(link->hisAka));
                }
                xscatprintf(report," %s %s  rescanned %lu mails\r",
                            an, print_ch(49-strlen(an), '.'), rcc);
                w_log(LL_AREAFIX,"areafix: %s rescanned %lu mails to %s",
                      an, rcc, aka2str(link->hisAka));
            }
  return rcc;
}

s_link_robot *getLinkRobot(s_link *link) {
    return &(link->areafix);
}

void autoPassive()
{
  time_t   time_cur, time_test;
  struct   stat stat_file;
  s_message *msg;
  FILE *f;
  char *line, *path;
  unsigned int i, rc = 0;

  for (i = 0; i < config->linkCount; i++) {

      if (config->links[i]->autoPause==0 || (config->links[i]->Pause == (ECHOAREA|FILEAREA))
         ) continue;

      if (createOutboundFileName(config->links[i],
                                 config->links[i]->echoMailFlavour,
                                 FLOFILE) == 0) {
          f = fopen(config->links[i]->floFile, "rt");
          if (f) {
              while ((line = readLine(f)) != NULL) {
                  line = trimLine(line);
                  path = line;
                  if (!isArcMail(path)) {
                      nfree(line);
                      continue;
                  }
                  if (*path && (*path == '^' || *path == '#')) {
                      path++;
                      /*  set Pause if files stored only in outbound */
                      if (*path && strncmp(config->outbound,path,strlen(config->outbound)-1)==0 && stat(path, &stat_file) != -1) {

                          time_cur = time(NULL);
                          if (time_cur > stat_file.st_mtime) {
                              time_test = (time_cur - stat_file.st_mtime)/3600;
                          } else { /*  buggly time on file, anyway don't autopause on it */
                              time_test = 0;
                          }

                          if (time_test >= (time_t)(config->links[i]->autoPause*24)) {
                              w_log(LL_AREAFIX, "autopause: the file %s is %d days old", path, time_test/24);
                              if (Changepause((cfgFile) ? cfgFile :
                                              getConfigFileName(),
                                              config->links[i], 1,
                                              config->links[i]->Pause^(ECHOAREA|FILEAREA))) {
                                  UINT j, k;
                                  int mask = config->links[i]->areafix.reportsAttr ? config->links[i]->areafix.reportsAttr : robot->reportsAttr;
                                  msg = makeMessage(config->links[i]->ourAka,
                                            &(config->links[i]->hisAka),
                                            robot->fromName ? robot->fromName : versionStr,
                                            config->links[i]->name,
                                            "AutoPassive", 1,
                                            MSGPRIVATE | MSGLOCAL | (mask & (MSGKILL|MSGCPT)) );
                                  msg->text = createKludges(config, NULL,
                                            config->links[i]->ourAka,
                                            &(config->links[i]->hisAka),
                                            versionStr);
                                  xstrcat(&msg->text, "\r System switched to passive, your subscription is paused.\r\r"
                                        " You are being unsubscribed from echo areas with no downlinks besides you!\r\r"
                                        " When you wish to continue receiving echomail, please send requests\r"
                                        " to AreaFix containing the %RESUME command.");
                                  xscatprintf(&msg->text, "\r\r--- %s autopause\r", versionStr);
                                  msg->textLength = strlen(msg->text);
#ifdef DO_PERL
                                  perl_robotmsg(msg, robot->name);
#endif
                                  processNMMsg(msg, NULL, getRobotsArea(config), 0, MSGLOCAL);
                                  writeEchoTossLogEntry(getRobotsArea(config)->areaName);
                                  closeOpenedPkt();
                                  freeMsgBuffers(msg);
                                  nfree(msg);

                                  /* update arealink access */
                                  for (k = 0; k < config->echoAreaCount; k++)
                                      for (j = 0; j < config->echoAreas[k].downlinkCount; j++)
                                          if (config->links[i] == config->echoAreas[k].downlinks[j]->link)
                                          {
                                              setLinkAccess(config, &(config->echoAreas[k]), config->echoAreas[k].downlinks[j]);
                                              break;
                                          }

                                  /* pause areas with one link alive while others are paused */
                                  if (robot->autoAreaPause)
                                      rc += pauseArea(ACT_PAUSE, config->links[i], NULL);
#ifdef DO_PERL
                                  /* update perl vars */
                                  perl_invalidate(PERL_CONF_LINKS|PERL_CONF_AREAS);
#endif
                              } /*  end changepause */
                              nfree(line);
                              /* fclose(f); file closed after endwhile */
                              break;
                          }
                      } /* endif */
                  } /* endif ^# */
                  nfree(line);
              } /* endwhile */
              fclose(f);
          } /* endif */
          nfree(config->links[i]->floFile);
          remove(config->links[i]->bsyFile);
          nfree(config->links[i]->bsyFile);
      }
      nfree(config->links[i]->pktFile);
      nfree(config->links[i]->packFile);
  } /* endfor */

  /* send created messages to links */
  if (rc) sendAreafixMessages();
}

int init_hptafix(void) {
  /* vars */
  af_config      = config;
  af_cfgFile     = cfgFile;
  af_app         = &theApp;
  af_versionStr  = versionStr;
  af_quiet       = quiet;
  af_silent_mode = silent_mode;
  af_report_changes = report_changes;
  af_send_notify = cmNotifyLink;
  af_pause = ECHOAREA;
  /* callbacks and hooks */
  call_sstrdup  = &safe_strdup;
  call_smalloc  = &safe_malloc;
  call_srealloc = &safe_realloc;

  call_getArea  = &afGetArea;
  call_isValid  = &afIsValidConference;
  call_sendMsg  = &afSendMsg;
  call_writeMsgToSysop = &afWriteMsgToSysop;
  call_getLinkRobot = &getLinkRobot;
  hook_onDeleteArea = &afDeleteArea;
  hook_onRescanArea = &afRescanArea;
  hook_onAutoCreate = &afReportAutoCreate;
#ifdef DO_PERL
  hook_onConfigChange = &perl_invalidate;
  hook_echolist       = &perl_echolist;
  hook_afixcmd        = &perl_afixcmd;
  hook_afixreq        = &perl_afixreq;
  hook_robotmsg       = &perl_robotmsg;
#endif
  robot = getRobot(config, "areafix", 0); /* !!! val: change this later !!! */
  return init_areafix("areafix");
}
