#ifndef DUPE_H
#define DUPE_H
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
int dupeDetection(s_area *area, const s_message msg);
char *createDupeFileName(s_area *area);
void addIndex(s_area *echo, UINT32 index);

#endif