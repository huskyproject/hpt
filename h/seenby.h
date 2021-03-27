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
#include <huskylib/typesize.h>

struct seenBy
{
    UINT16 net, node;
};

typedef struct seenBy s_seenBy;
void sortSeenBys(s_seenBy * seenBys, UINT count);
char * createControlText(s_seenBy seenBys[], UINT seenByCount, char * lineHeading);
void createSeenByArrayFromMsg(s_area * area,
                              s_message * msg,
                              s_seenBy ** seenBys,
                              UINT * seenByCount);
void createPathArrayFromMsg(s_message * msg, s_seenBy ** seenBys, UINT * seenByCount);

/*
   This function puts all the links of the echoarea in the newLink
   array who does not have got the mail, zoneLinks - the links who
   receive msg with stripped seen-by's.
 */
void createNewLinkArray(s_seenBy * seenBys,
                        UINT seenByCount,
                        s_area * echo,
                        s_arealink *** newLinks,
                        s_arealink *** zoneLinks,
                        s_arealink *** otherLinks,
                        const hs_addr * pktOrigAddr);
void createFilteredSeenByArray(s_seenBy * seenBys,
                               UINT seenByCount,
                               s_seenBy ** newSeenBys,
                               UINT * newSeenByCount,
                               ps_addr addr,
                               unsigned int addrCount);
void stripSeenByArray(s_seenBy ** seenBys, UINT * seenByCount, ps_addr addr,
                      unsigned int addrCount);

#endif
