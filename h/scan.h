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
#ifndef SCAN_H
#define SCAN_H
#include <fidoconfig.h>

struct statScan {
   int areas, msgs;
   int exported;
};
typedef struct statScan s_statScan;

extern s_statScan statScan;

#define	SCN_FILE	0x0001
#define	SCN_ALL		0x0002
#define	SCN_NAME	0x0004
#define	SCN_ECHOMAIL	0x0008
#define	SCN_NETMAIL	0x0010

void scanExport(int type, char *str);
void scanEMArea(s_area *echo);
void makePktHeader(s_link *link, s_pktHeader *header);
void cvtAddr(const NETADDR aka1, s_addr *aka2);

#endif
