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
 *****************************************************************************
 * $Id$
 */

#include <fidoconf/fidoconf.h>
#include <areafix/areafix.h>
#include <global.h>

s_fidoconfig * config = NULL;
char * cfgFile        = NULL;
s_robot * robot       = NULL;
int initSMAPI         = -1;
/* basic version number */
/*
   const int   hpt_VER_MAJOR   = 1;
   const int   hpt_VER_MINOR   = 3;
   const int   hpt_VER_PATCH   = 0;
 */
/* branch is "" for CVS current, "-stable" for the release candiate branch  */
/*const char *hpt_VER_BRANCH  = ""; */
/* The service version string is empty for the first release done from a    */
/* release candidate branch.  If subsequent service releases are necessary, */
/* single letters are used, like "a", "b", ...                              */
/*const char *VER_SERVICE = "";*/
char * versionStr     = NULL;
char * tossDir        = NULL;
char * linkName       = NULL;
UCHAR * globalBuffer  = NULL;
time_t pkt_aTime      = 0;
int cmToss            = 0;
int cmScan            = 0;
int cmPack            = 0;
int cmLink            = 0;
int cmAfix            = 0;
int cmNotifyLink      = 0;
int cmPause           = 0;
int cmQueue           = 0;
int noHighWaters      = 0;
int pkt_count         = 0;
int quiet             = 0;
e_relinkType cmRelink = modeNone;
hs_addr afixAddr      =
{
    0, 0, 0, 0
};
char * afixCmd         = NULL;
hs_addr relinkFromAddr =
{
    0, 0, 0, 0
};
hs_addr relinkToAddr =
{
    0, 0, 0, 0
};
char * relinkPattern          = NULL;
char * resubscribePatternFile = NULL;
int lock_fd;
int silent_mode    = 0;
int report_changes = 0;
time_t globalTime;        /* time when hpt was started */
