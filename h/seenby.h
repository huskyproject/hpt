/* $Id$ */

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
#ifndef SEENBY_H
#define SEENBY_H
#include <fidoconf/typesize.h>

struct seenBy {
   UINT16 net, node;
};

#define MAX_ZONE 32768

typedef struct seenBy s_seenBy;

struct seenByZone {
    s_seenBy *seenByArray;
    UINT16 seenByCount;
};

typedef struct seenByZone s_seenByZone;
extern s_seenByZone seenBysZone[MAX_ZONE];

void sortSeenBys(s_seenBy *seenBys, UINT count);

char *createControlText(s_seenBy seenBys[], UINT seenByCount, char *lineHeading);

void createSeenByArrayFromMsg(s_message *msg, s_seenBy
							  **seenBys, UINT *seenByCount);

void createPathArrayFromMsg(s_message *msg, s_seenBy **seenBys, UINT *seenByCount);


void zero_seenBysZone();
void free_seenBysZone();
void attachTo_seenBysZone(int zone, s_seenBy **seenBys, int count);
void addTo_seenByZone(UINT16 zone, UINT16 net, UINT16 node);
void deleteFrom_seenByZone(UINT16 zone, UINT16 net, UINT16 node);
void createNewLinksArray(s_area *echo, s_arealink ***newLinks,
                         hs_addr pktOrigAddr, int rsb);
void addLinksTo_seenByZone(s_arealink **newLinks, int count);
void addAkasTo_seenByZone();
void processAutoAdd_seenByZone(s_area *echo);
void cleanDupes_seenByZone();

#endif
