/* $Id$ */

/*****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 * Copyright (C) 1997-2000
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
 * Hash Dupe and other typeDupeBase (C) 2000
 *
 * Alexander Vernigora
 *
 * Fido:     2:4625/69              
 * Internet: alexv@vsmu.vinnica.ua
 *
 * Yunosty 79, app.13 
 * 287100 Vinnitsa   
 * Ukraine
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
#ifndef DUPE_H
#define DUPE_H

#include <fidoconf/typesize.h>
#include <fidoconf/fidoconf.h>
#include <fidoconf/tree.h>
#include <pkt.h>

/* This header file contains the structures of the dupe file */

struct textDupeEntry {
  time_t  TimeStampOfDupe;
  char *from, *to, *subject, *msgid;
};

typedef struct textDupeEntry s_textDupeEntry;

/*
  A DupeEntry on disk is written in the following way :
  time_t TimeStampOfDupe
  UCHAR  fromLength
  char   from[fromLength];
  UCHAR  toLength
  char   to[toLength];
  UCHAR  subjectLength
  char   subject[subjectLength+1];
  UCHAR  msgidLength
  char   msgid[msgidLength+1];
  */

struct hashDupeEntry {
   time_t  TimeStampOfDupe;
   UINT32  CrcOfDupe;
};

typedef struct hashDupeEntry s_hashDupeEntry;


struct hashMDupeEntry {
   time_t  TimeStampOfDupe;
   UINT32  CrcOfDupe;
   char   *msgid;
};

typedef struct hashMDupeEntry s_hashMDupeEntry;

struct dupeMemory {
  tree *avlTree;
};

typedef struct dupeMemory s_dupeMemory;


int writeToDupeFile(s_area *area);
void freeDupeMemory(s_area *area);
int dupeDetection(s_area *area, const s_message msg);
char *createDupeFileName(s_area *area);

#endif /* DUPE_H */
