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
 * Hash Dupe
 * Copyright (C) 1999
 *
 * Oleg Zrozhevsky
 *
 * Fido:     2:5096/1.359 2:5020/359
 * Internet: zoa@cea.ru
 *
 * Radio 17, app.129
 * 144003 Electrostal
 * Russia
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

#ifndef HASHDUPE
#include <tree.h>
#include <typesize.h>
#include <fidoconfig.h>
#include <pkt.h>

/* This header file contains the structures of the dupe file */

#define DUPE_MAJOR_VER 0
#define DUPE_MINOR_VER 2

struct dupeFileHeader {
   UINT16  fileHeaderSize;
   UCHAR   majorVer, minorVer;
   UINT32  dupePackHeaderSize, noOfPacks;
};

typedef struct dupeFileHeader s_dupeFileHeader;

struct dupePackHeader {
   UINT32  noOfEntries;
   UCHAR   time_tSize;
   time_t  packTime;
};

typedef struct dupePackHeader s_dupePackHeader;

struct dupeEntry {
  char *from, *to, *subject, *msgid;
};

typedef struct dupeEntry s_dupeEntry;

/*
  A DupeEntry on disk is written in the following way :

  UCHAR fromLength
  char  from[fromLength];
  UCHAR toLength
  char  to[toLength];
  UCHAR subjectLength
  char  subject[subjectLength+1];
  UCHAR msgidLength
  char  msgid[msgidLength+1];
  */

struct dupeMemory {
  tree *avlTree;
};

typedef struct dupeMemory s_dupeMemory;

/* the index file consists of several offsets
the first long is the offset of the first dupePack :

1st long ->  offset(1st dupepackheader)
2nd long ->  offset(2nd dupePackheader)
...
*/

int writeToDupeFile(s_area *area);
void freeDupeMemory(s_area *area);
int dupeDetection(s_area *area, const s_message msg);
char *createDupeFileName(s_area *area);
void addIndex(s_area *echo, UINT32 index);

#else /* HASHDUPE */
#include <typesize.h>
#include <fidoconfig.h>
#include <pkt.h>

/* This header file contains the structures of the dupe file */

struct _SQHheader {
  UCHAR  signature[3],
         size;
  UINT32 maxage,
         maxdupes,
	 lastUMSGID;
};

typedef struct _SQHheader SQHheader;

struct _SQHentry {
  UINT16 preventry,
         nextentry;
  UINT32 hash,
         timestamp,
         UMSGID;
};

typedef struct _SQHentry SQHentry;

int dupeDetection(s_area *area, const s_message msg);

#endif /* HASHDUPE */
#endif /* DUPE_H */
