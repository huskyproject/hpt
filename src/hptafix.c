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
  if (forwardAddr == NULL) makeMsgToSysop(c_area, pktOrigAddr, NULL);
  else makeMsgToSysop(c_area, *forwardAddr, &pktOrigAddr);
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

int afRescanArea(char **report, s_link *link, s_area *area, long rescanCount) {
  char *an = area->areaName;
  s_arealink *arealink;
  long rcc;

            if (area->msgbType == MSGTYPE_PASSTHROUGH) {
                xscatprintf(report," %s %s  no rescan possible\r",
                            an, print_ch(49-strlen(an), '.'));
                w_log(LL_AREAFIX, "areafix: %s area no rescan possible to %s",
                      an, aka2str(link->hisAka));
            } else {

                arealink = getAreaLink(area, link->hisAka);
                if (arealink->export) {
                    rcc = rescanEMArea(area, arealink, rescanCount);
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
                                  int mask = config->links[i]->areafixReportsAttr ? config->links[i]->areafixReportsAttr : config->areafixReportsAttr;
                                  msg = makeMessage(config->links[i]->ourAka,
                                            &(config->links[i]->hisAka),
                                            config->areafixFromName ? config->areafixFromName : versionStr,
                                            config->links[i]->name,
                                            "AutoPassive", 1,
                                            MSGPRIVATE | MSGLOCAL | (mask & (MSGKILL|MSGCPT)) );
                                  msg->text = createKludges(config, NULL,
                                            config->links[i]->ourAka,
                                            &(config->links[i]->hisAka),
                                            versionStr);
                                  xstrcat(&msg->text, "\r System switched to passive, your subscription are paused.\r\r"
                                        " You are being unsubscribed from echo areas with no downlinks besides you!\r\r"
                                        " When you wish to continue receiving echomail, please send requests\r"
                                        " to AreaFix containing the %RESUME command.");
                                  xscatprintf(&msg->text, "\r\r--- %s autopause\r", versionStr);
                                  msg->textLength = strlen(msg->text);
                                  processNMMsg(msg, NULL,
                                               getRobotsArea(config),
                               0, MSGLOCAL);
                  writeEchoTossLogEntry(getRobotsArea(config)->areaName);
                                  closeOpenedPkt();
                                  freeMsgBuffers(msg);
                                  nfree(msg);

                                  /* pause areas with one link alive while others are paused */
                                  if (config->autoAreaPause)
                                      rc += pauseAreas(0,config->links[i],NULL);

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

int relink (char *straddr) {
    s_link          *researchLink = NULL;
    unsigned int    count, areasArraySize;
    s_area          **areasIndexArray = NULL;
    struct _minf m;

    /*  parse config */
    if (config==NULL) processConfig();
    if ( initSMAPI == -1 ) {
        /*  init SMAPI */
        initSMAPI = 0;
        m.req_version = 0;
        m.def_zone = (UINT16) config->addr[0].zone;
        if (MsgOpenApi(&m) != 0) {
            exit_hpt("MsgApiOpen Error",1);
        }
    }

    w_log(LL_START, "Start relink...");

    if (straddr) researchLink = getLink(config, straddr);
    else {
        w_log(LL_ERR, "No address");
        return 1;
    }

    if ( researchLink == NULL ) {
        w_log(LL_ERR, "Unknown link address %s", straddr);
        return 1;
    }

    areasArraySize = 0;
    areasIndexArray = (s_area **) safe_malloc
        (sizeof(s_area *) * (config->echoAreaCount + config->localAreaCount + 1));

    for (count = 0; count < config->echoAreaCount; count++)
        if ( isLinkOfArea(researchLink, &config->echoAreas[count])) {
            areasIndexArray[areasArraySize] = &config->echoAreas[count];
            areasArraySize++;
            w_log(LL_AREAFIX, "EchoArea %s from link %s is relinked",
                  config->echoAreas[count].areaName, aka2str(researchLink->hisAka));
        }

    if ( areasArraySize > 0 ) {
        s_message *msg;

        msg = makeMessage(researchLink->ourAka,
                          &researchLink->hisAka,
                          config->sysop,
                          researchLink->RemoteRobotName ?
                          researchLink->RemoteRobotName : "areafix",
                          researchLink->areaFixPwd ? researchLink->areaFixPwd : "", 1,
                          researchLink->areafixReportsAttr ? researchLink->areafixReportsAttr : config->areafixReportsAttr);

        msg->text = createKludges(config,NULL,researchLink->ourAka,
                              &researchLink->hisAka,versionStr);
        if (researchLink->areafixReportsFlags)
            xstrscat(&(msg->text), "\001FLAGS ", researchLink->areafixReportsFlags, "\r",NULL);
        else if (config->areafixReportsFlags)
            xstrscat(&(msg->text), "\001FLAGS ", config->areafixReportsFlags, "\r",NULL);

        for ( count = 0 ; count < areasArraySize; count++ ) {
            if ((areasIndexArray[count]->downlinkCount  <= 1) &&
                (areasIndexArray[count]->msgbType & MSGTYPE_PASSTHROUGH))
                xscatprintf(&(msg->text), "-%s\r",areasIndexArray[count]->areaName);
            else
                xscatprintf(&(msg->text), "+%s\r",areasIndexArray[count]->areaName);
        }

        xscatprintf(&(msg->text), " \r--- %s areafix\r", versionStr);
        msg->textLength = strlen(msg->text);
        w_log(LL_AREAFIX, "'Relink' message created to `%s`",
              researchLink->RemoteRobotName ?
              researchLink->RemoteRobotName : "areafix");
        processNMMsg(msg, NULL,
                     getRobotsArea(config),
                 1, MSGLOCAL|MSGKILL);
    writeEchoTossLogEntry(getRobotsArea(config)->areaName);
        closeOpenedPkt();
        freeMsgBuffers(msg);
        nfree(msg);
        w_log(LL_AREAFIX, "Relinked %i area(s)",areasArraySize);
    }

    nfree(areasIndexArray);

    /* deinit SMAPI */
    MsgCloseApi();

    return 0;
}

int resubscribe (char *pattern, char *strFromAddr, char *strToAddr) {
    s_link          *fromLink = NULL;
    s_link          *toLink = NULL;
    unsigned int    count, fromArraySize, toArraySize;
    s_area          **fromIndexArray = NULL;
    s_area          **toIndexArray = NULL;
    struct _minf    m;
    char            *fromAddr, *toAddr;

    /*  parse config */
    if (config==NULL) processConfig();
    if ( initSMAPI == -1 ) {
        /*  init SMAPI */
        initSMAPI = 0;
        m.req_version = 0;
        m.def_zone = (UINT16) config->addr[0].zone;
        if (MsgOpenApi(&m) != 0) {
            exit_hpt("MsgApiOpen Error",1);
        }
    }

    w_log(LL_START, "Start resubscribe...");

    if ( pattern == NULL ) {
        w_log(LL_ERR, "Areas pattern is not defined");
        return 1;
    }

    if (strFromAddr) fromLink = getLink(config, strFromAddr);
    else {
        w_log(LL_ERR, "No address to resubscribe from");
        return 1;
    }

    if ( fromLink == NULL ) {
        w_log(LL_ERR, "Unknown link address %s", strFromAddr);
        return 1;
    }

    fromArraySize = 0;
    fromIndexArray = (s_area **) safe_malloc
        (sizeof(s_area *) * (config->echoAreaCount + config->localAreaCount + 1));

    if (strToAddr) toLink = getLink(config, strToAddr);
    else {
        w_log(LL_ERR, "No address to resubscribe to");
        return 1;
    }

    if ( toLink == NULL ) {
        w_log(LL_ERR, "Unknown link address %s", strToAddr);
        return 1;
    }

    toArraySize = 0;
    toIndexArray = (s_area **) safe_malloc
        (sizeof(s_area *) * (config->echoAreaCount + config->localAreaCount + 1));

    for (count = 0; count < config->echoAreaCount; count++)
        if (isLinkOfArea(fromLink, &config->echoAreas[count])) {
            int rc;

            if(patimat(config->echoAreas[count].areaName, pattern)==0)
                continue;

            rc = changeconfig(cfgFile?cfgFile:getConfigFileName(),
                              &config->echoAreas[count],fromLink,1);

            if (rc != DEL_OK) {
                w_log(LL_AREAFIX, "areafix: %s can't unlink %s from area ",
                      aka2str(fromLink->hisAka), config->echoAreas[count].areaName);
                continue;
            }

            fromIndexArray[fromArraySize] = &config->echoAreas[count];
            fromArraySize++;
            RemoveLink(fromLink, &config->echoAreas[count]);

            if (isLinkOfArea(toLink, &config->echoAreas[count])) {
                w_log(LL_AREAFIX, "Link %s is already subscribed to area %s",
                      aka2str(toLink->hisAka), config->echoAreas[count].areaName);
                continue;
            }

            rc = changeconfig(cfgFile?cfgFile:getConfigFileName(),
                              &config->echoAreas[count],toLink,0);

            if (rc != ADD_OK) {
                w_log(LL_AREAFIX, "areafix: %s is not subscribed to %s",
                      aka2str(toLink->hisAka), config->echoAreas[count].areaName);
                continue;
            }

            Addlink(config, toLink, &config->echoAreas[count]);
            toIndexArray[toArraySize] = &config->echoAreas[count];
            toArraySize++;

            fromAddr = safe_strdup(aka2str(fromLink->hisAka));
            toAddr   = safe_strdup(aka2str(toLink->hisAka));
            w_log(LL_AREAFIX, "EchoArea %s resubscribed from link %s (old link was %s)",
                  config->echoAreas[count].areaName, fromAddr, toAddr);
            nfree(fromAddr);
            nfree(toAddr);
        }

    if ( fromArraySize > 0 ) {
        s_message *msg;

        msg = makeMessage(fromLink->ourAka,
                          &fromLink->hisAka,
                          config->sysop,
                          fromLink->RemoteRobotName ?
                          fromLink->RemoteRobotName : "areafix",
                          fromLink->areaFixPwd ? fromLink->areaFixPwd : "", 1,
                          fromLink->areafixReportsAttr ? fromLink->areafixReportsAttr : config->areafixReportsAttr);

        msg->text = createKludges(config,NULL,fromLink->ourAka,
                                  &fromLink->hisAka,versionStr);
        if (fromLink->areafixReportsFlags)
            xstrscat(&(msg->text), "\001FLAGS ", fromLink->areafixReportsFlags, "\r",NULL);
        else if (config->areafixReportsFlags)
            xstrscat(&(msg->text), "\001FLAGS ", config->areafixReportsFlags, "\r",NULL);

        for ( count = 0 ; count < fromArraySize; count++ ) {
            if (toLink!=NULL) {
                xscatprintf(&(msg->text), "-%s\r",fromIndexArray[count]->areaName);
            } else {
                xscatprintf(&(msg->text), "+%s\r",fromIndexArray[count]->areaName);
            }
        }

        xscatprintf(&(msg->text), " \r--- %s areafix\r", versionStr);
        msg->textLength = strlen(msg->text);
        processNMMsg(msg, NULL, getRobotsArea(config), 1, MSGLOCAL|MSGKILL);
        writeEchoTossLogEntry(getRobotsArea(config)->areaName);
        closeOpenedPkt();
        freeMsgBuffers(msg);
        nfree(msg);

        w_log(LL_AREAFIX, "Unlinked %i area(s) from %s",
              fromArraySize, aka2str(fromLink->hisAka));
    }

    nfree(fromIndexArray);

    if (toArraySize > 0) {
        s_message *msg;

        msg = makeMessage(toLink->ourAka,
                          &toLink->hisAka,
                          config->sysop,
                          toLink->RemoteRobotName ?
                          toLink->RemoteRobotName : "areafix",
                          toLink->areaFixPwd ? toLink->areaFixPwd : "", 1,
                          toLink->areafixReportsAttr ? toLink->areafixReportsAttr : config->areafixReportsAttr);

        msg->text = createKludges(config,NULL,toLink->ourAka,
                                  &toLink->hisAka,versionStr);
        if (toLink->areafixReportsFlags)
            xstrscat(&(msg->text), "\001FLAGS ", toLink->areafixReportsFlags, "\r",NULL);
        else if (config->areafixReportsFlags)
            xstrscat(&(msg->text), "\001FLAGS ", config->areafixReportsFlags, "\r",NULL);

        for ( count = 0 ; count < toArraySize; count++ ) {
            xscatprintf(&(msg->text), "+%s\r",toIndexArray[count]->areaName);
        }

        xscatprintf(&(msg->text), " \r--- %s areafix\r", versionStr);
        msg->textLength = strlen(msg->text);
        processNMMsg(msg, NULL, getRobotsArea(config), 1, MSGLOCAL|MSGKILL);
        writeEchoTossLogEntry(getRobotsArea(config)->areaName);
        closeOpenedPkt();
        freeMsgBuffers(msg);
        nfree(msg);
        w_log(LL_AREAFIX, "Linked %i area(s) to %s",
              toArraySize, aka2str(toLink->hisAka));
    }

    nfree(toIndexArray);

    /* deinit SMAPI */
    MsgCloseApi();

    return 0;
}

int init_hptafix(void) {
  /* vars */
  af_config      = config;
  af_cfgFile     = cfgFile;
  af_versionStr  = versionStr;
  af_quiet       = quiet;
  af_silent_mode = silent_mode;
  af_report_changes = report_changes;
  af_send_notify = cmNotifyLink;
  /* callbacks and hooks */
  call_sstrdup  = &safe_strdup;
  call_smalloc  = &safe_malloc;
  call_srealloc = &safe_realloc;

  call_sendMsg  = &afSendMsg;
  call_writeMsgToSysop = &afWriteMsgToSysop;
  hook_onDeleteArea = &afDeleteArea;
  hook_onRescanArea = &afRescanArea;
#ifdef DO_PERL
  hook_onConfigChange = &perl_setvars;
  hook_echolist       = &perl_echolist;
  hook_afixcmd        = &perl_afixcmd;
  hook_afixreq        = &perl_afixreq;
#endif
  return init_areafix();
}
