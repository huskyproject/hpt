#ifndef DUPE_H
#define DUPE_H
#include <typesize.h>
#include <fidoconfig.h>
#include <pkt.h>

/* This header file contains the structures of the dupe file */

#define DUPE_MAJOR_VER 0
#define DUPE_MINOR_VER 1

struct dupeFileHeader {
   UINT16  fileHeaderSize;
   UCHAR   majorVer, minorVer;
   UINT32  dupePackHeaderSize, noOfPacks;
};

typedef struct dupeFileHeader s_dupeFileHeader;

struct dupePackHeader {
   UINT16  entrySize;
   UINT32  noOfEntries;
   UCHAR   time_tSize;
   time_t  packTime;
};

typedef struct dupePackHeader s_dupePackHeader;

struct dupeEntry {
   UINT32 hash;
};

typedef struct dupeEntry s_dupeEntry;

struct dupeMemory {
   UINT16 entrySize;
   UINT32 noOfEntries;
   s_dupeEntry *entries;
};

typedef struct dupeMemory s_dupeMemory;

//s_dupeMemory *readDupeFile(s_area *area);
int writeToDupeFile(s_area *area, s_dupeMemory newDupeEntries);
int dupeDetection(s_area *area, const s_message msg);

#endif