/*:ts=8*/
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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#include <pkt.h>

#include <global.h>

#include <compiler.h>
#include <dupe.h>

#ifndef HASHDUPE
#include <msgapi.h>
#include <stamp.h>
#include <progprot.h>

FILE *fDupe;
#else

FILE *SQHf;
UINT32 MaxEntryN, MaxAge, MaxDupes;

unsigned long strcrc32(char *, unsigned long);
#endif

char *strtolower(char *string) {
  register int cont;
  int l;
  char *tmp;
    
  l=strlen(string);
  tmp=(char *) malloc (l+1);
  for (cont=0;cont<=l;cont++)
    tmp[cont]=tolower(string[cont]);
  
  return tmp;
}

char *createDupeFileName(s_area *area) {
   char *aux;
   char *name;
   char *afname;

#ifndef MSDOS
  if (!area->DOSFile) {
    name = (char *) malloc(strlen(config->dupeHistoryDir)+strlen(area->areaName)+5);
  }
  else {
    name = (char *) malloc(strlen(config->dupeHistoryDir)+5+9);
  }
#else
    name = (char *) malloc(strlen(config->dupeHistoryDir)+5+9);
#endif

   strcpy(name, config->dupeHistoryDir);

   if (!area->DOSFile) {
     strcat(name, aux=strtolower(area->areaName));
   }
   else {
     strcat(name, (afname = strrchr(area->fileName, PATH_DELIM)) != NULL ? (aux=strtolower(afname + 1)) : (aux=strtolower(area->fileName)));
   }

   free(aux);
   strcat(name,
#ifndef HASHDUPE
   ".dup");
#else
   ".sqh");
#endif

   return name;
}

#ifndef HASHDUPE
void addIndex(s_area *area, UINT32 offset) {

   FILE *f;
   char *fileName = createDupeFileName(area);
   char *ext;

   fileName = realloc(fileName, strlen(fileName)+6+1);
#ifndef MSDOS
  if (!area->DOSFile)
    strcat(fileName, ".index");
  else
    strcpy((ext = strrchr(fileName, '.'))  != NULL ? ext :
           fileName + strlen(fileName), ".idx");
#else
   strcpy((ext = strrchr(fileName, '.'))  != NULL ? ext :
          fileName + strlen(fileName), ".idx");
#endif

   f = fopen(fileName, "a");
   fwrite(&offset, sizeof(long), 1, f);
   fclose(f);
   
   free(fileName);
}

int compareEntries(const void *e1, const void *e2) {
   const s_dupeEntry *a, *b;
   int rc;

   a = e1; b = e2;

   rc = strcmp(a->from, b->from);
   if (rc == 0) rc = strcmp(a->to, b->to);
   if (rc == 0) rc = strcmp(a->subject, b->subject);
   if ((rc == 0) && (a->msgid != NULL) && (b->msgid != NULL)) rc = strcmp(a->msgid, b->msgid);

   return rc;
}

int writeEntry(s_dupeEntry *entry) {
   fputc(strlen(entry->from), fDupe); fputs(entry->from, fDupe);
   fputc(strlen(entry->to), fDupe); fputs(entry->to, fDupe);
   fputc(strlen(entry->subject), fDupe); fputs(entry->subject, fDupe);
   if (entry->msgid != NULL) {
      fputc(strlen(entry->msgid), fDupe);
      fputs(entry->msgid, fDupe);
   }
   else fputc(0, fDupe);
   
   return 1;
}
   
int deleteEntry(s_dupeEntry *entry) {
   free(entry->to);
   free(entry->from);
   free(entry->subject);
   free(entry->msgid);
   free(entry);
   return 1;
}

void doReading(FILE *f, s_dupeMemory *mem) {
   // read Header
   s_dupeFileHeader *fileHeader;
   s_dupePackHeader *packHeader;
   s_dupeEntry      *entry;
   UCHAR   length;
   UINT16 headerSize;
   UINT32 i, j;

   // read correct size
   fread(&headerSize, sizeof(UINT16), 1, f);
   fseek(f, 0, SEEK_SET);

   // alloc memory and read struct
   fileHeader = malloc(headerSize);
   fread(fileHeader, headerSize, 1, f);

   // process all packs
   for (i = 0; i < fileHeader->noOfPacks; i++) {
      packHeader = malloc(fileHeader->dupePackHeaderSize);
      fread(packHeader, fileHeader->dupePackHeaderSize, 1, f);

      // process all entries
      for (j = 0; j < packHeader->noOfEntries; j++) {
         if (feof(f)) break;
         entry = malloc(sizeof(s_dupeEntry));
         
         length = getc(f);
         entry->from = malloc(length+1);
         fgets(entry->from, length+1, f);

         length = getc(f);
         entry->to = malloc(length+1);
         fgets(entry->to, length+1, f);

         length = getc(f);
         entry->subject = malloc(length+1);
         fgets(entry->subject, length+1, f);

         length = getc(f);
         entry->msgid = malloc(length+1);
         fgets(entry->msgid, length+1, f);
         tree_add(&(mem->avlTree), &compareEntries, (char *) entry, &deleteEntry);
      }
      
      free(packHeader);
   }

   free(fileHeader);
}

s_dupeMemory *readDupeFile(s_area *area) {
   FILE *f;
   char *fileName;
   s_dupeMemory *dupeMemory;

   writeLogEntry(hpt_log, '2', "Reading dupes of %s.", area->areaName);
   
   dupeMemory = malloc(sizeof(s_dupeMemory));
   tree_init(&(dupeMemory->avlTree));

   fileName = createDupeFileName(area);
   f = fopen(fileName, "rb");
   if (f != NULL) {
      // readFile
      doReading(f, dupeMemory);
      fclose(f);
   } else writeLogEntry(hpt_log, '2', "Error reading dupes.");
   
   free(fileName);

   return dupeMemory;
}

int appendToDupeFile(s_area *area, char *name, s_dupeMemory newDupeEntries) {
   FILE *f;
   UINT16 fileHeaderSize;
   s_dupeFileHeader *fileHeader;
   s_dupePackHeader packHeader;
   UINT32 index;

   f = fopen(name, "rb+");

   if (f == NULL) return 1;

   // modify fileHeader
   fread(&fileHeaderSize, sizeof(UINT16), 1, f);
   fileHeader = malloc(fileHeaderSize);
   fseek(f, 0, SEEK_SET);
   fread(fileHeader, fileHeaderSize, 1, f);

   fileHeader->noOfPacks++;
   fseek(f, 0, SEEK_SET);
   fwrite(fileHeader, fileHeaderSize, 1, f);
   free(fileHeader);

   // add new packet to end of file
   fseek(f, 0, SEEK_END);
   // and write index
   index = ftell(f);
   addIndex(area, index);
   packHeader.noOfEntries = tree_count(&(newDupeEntries.avlTree));
   packHeader.time_tSize  = sizeof(time_t);
   packHeader.packTime    = time(NULL);
   fwrite(&packHeader, sizeof(s_dupePackHeader), 1, f);

   // add entries
   fDupe = f;
   tree_trav(&(newDupeEntries.avlTree), &writeEntry);
   fDupe = NULL;
         
   fclose(f);

   return 0;
}

int createDupeFile(s_area *area, char *name, s_dupeMemory newDupeEntries) {
   FILE *f;
   s_dupeFileHeader fileHeader;
   s_dupePackHeader packHeader;
   UINT32 index;

   f = fopen(name, "wb");
   if (f!= NULL) {

      // create dupeFileHeader
      fileHeader.fileHeaderSize = sizeof(s_dupeFileHeader);
      fileHeader.majorVer       = DUPE_MAJOR_VER;
      fileHeader.minorVer       = DUPE_MINOR_VER;
      fileHeader.dupePackHeaderSize = sizeof(s_dupePackHeader);
      fileHeader.noOfPacks      = 1;

      // writeDupeFileHeader
      fwrite(&fileHeader, sizeof(s_dupeFileHeader), 1, f);

      // create only one pack, since this is a new dupeFile
      // and write index
      index = ftell(f);
      addIndex(area, index);
      packHeader.noOfEntries   = tree_count(&(newDupeEntries.avlTree));
      packHeader.time_tSize    = sizeof(time_t);
      packHeader.packTime      = time(NULL);
      fwrite(&packHeader, sizeof(s_dupePackHeader), 1, f);

      // write new Entries
      fDupe = f;
      tree_trav(&(newDupeEntries.avlTree), &writeEntry);
      fDupe = NULL;
      fclose(f);
      
      return 0;
   } else return 1;
}

int writeToDupeFile(s_area *area) {
   char *fileName;
   int  rc = 0;
   s_dupeMemory *newDupes = area->newDupes;

   if (newDupes != NULL) {

      if (tree_count(&(newDupes->avlTree)) > 0) {

         fileName = createDupeFileName(area);

         if(fexist(fileName)) rc = appendToDupeFile(area, fileName, *newDupes);
         else rc = createDupeFile(area, fileName, *newDupes);

         free(fileName);
      }

   }

   return rc;
}

void freeDupeMemory(s_area *area) {

   s_dupeMemory *dupes = area -> dupes, *newDupes = area -> newDupes;

   if (dupes != NULL) {
      tree_mung(&(dupes -> avlTree), &deleteEntry);
      free(area -> dupes); area -> dupes = NULL;
   };
   if (newDupes != NULL) {
      tree_mung(&(newDupes -> avlTree), &deleteEntry);
      free(area -> newDupes); area -> newDupes = NULL;
   };

}

int isDupe(s_area area, s_dupeEntry *entry) {
   s_dupeMemory *dupes = area.dupes, *newDupes = area.newDupes;

   return (
           (tree_srch(&(dupes->avlTree), &compareEntries, (char *) entry)!= NULL)
   ||      (tree_srch(&(newDupes->avlTree), &compareEntries, (char *) entry) != NULL) );
}

int dupeDetection(s_area *area, const s_message msg) {
   s_dupeMemory *newDupes = area->newDupes;
   s_dupeEntry  *entry;
   char         *str;

   if (area->dupeCheck == dcOff) return 1; // no dupeCheck return 1 "no dupe"
   if ((str=getKludge(msg, "MSGID:"))==NULL) return 1; // msgs without MSGID are no dupes!

   // test if dupeDatabase is already read
   if (area->dupes == NULL) {
      //read Dupes
      area->dupes = readDupeFile(area);
   }
   // test if newDupes area already built up
   if (area->newDupes == NULL) {
      //make newDupes "NULL-struct"
      newDupes = malloc(sizeof(s_dupeMemory));
      tree_init(&(newDupes->avlTree));
      area->newDupes = newDupes;
   }

   entry = malloc(sizeof(s_dupeEntry));

   entry->from    = malloc(strlen(msg.fromUserName)+1); strcpy(entry->from, msg.fromUserName);
   entry->to      = malloc(strlen(msg.toUserName)+1); strcpy(entry->to, msg.toUserName);
   entry->subject = malloc(strlen(msg.subjectLine)+1); strcpy(entry->subject, msg.subjectLine);
   entry->msgid   = malloc(strlen(str)+1-7); strcpy(entry->msgid, str+7);
   free(str);

   if (!isDupe(*area, entry)) {
      // add to newDupes
      tree_add(&(newDupes->avlTree), &compareEntries, (char *) entry, &deleteEntry);
      return 1;
   }
   // it is a dupe do nothing but return 0; and free dupe entry
   else {
      deleteEntry(entry);
      return 0;
   }
}

#else

int AppendEntry(UINT32 BaseEntryN, SQHentry *NewEntry, UINT32 LastUMSGID, UINT32 LastTimeStamp) {
  SQHentry Entry, NextEntry;
  UINT32 EntryN=BaseEntryN, NextEntryN;
  UINT16 count;
  int success=0;

  for (count=1; count<MaxEntryN && count<65535; ++count) {
    ++EntryN;
    EntryN &= MaxEntryN;
    fread(&Entry, sizeof(SQHentry), 1, SQHf);
    if (Entry.UMSGID + MaxDupes < LastUMSGID ||
        Entry.timestamp + MaxAge < LastTimeStamp) {
      /* We found expired entry */
      if (Entry.preventry != 0) {
        /* Unlink it from previous entry */
        NextEntryN = (EntryN - Entry.preventry) & MaxEntryN;
        fseek(SQHf, NextEntryN*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
        fread(&NextEntry, sizeof(SQHentry), 1, SQHf);
        NextEntry.nextentry = 0;
        fseek(SQHf, NextEntryN*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
        fwrite(&NextEntry, sizeof(SQHentry), 1, SQHf);
      }

      if (Entry.nextentry != 0) {
        /* Unlink it from next entry */
        NextEntryN = (EntryN + Entry.nextentry) & MaxEntryN;
        fseek(SQHf, NextEntryN*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
        fread(&NextEntry, sizeof(SQHentry), 1, SQHf);
        NextEntry.preventry = 0;
        fseek(SQHf, NextEntryN*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
        fwrite(&NextEntry, sizeof(SQHentry), 1, SQHf);
      }

      NewEntry->nextentry = 0;
      NewEntry->preventry = count;
      fseek(SQHf, EntryN*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
      fwrite(NewEntry, sizeof(SQHentry), 1, SQHf);

      fseek(SQHf, BaseEntryN*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
      fread(&Entry, sizeof(SQHentry), 1, SQHf);
      Entry.nextentry = count;
      fseek(SQHf, BaseEntryN*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
      fwrite(&Entry, sizeof(SQHentry), 1, SQHf);
      success = 1;
      break;
    }
  }
  return success;
}

int CheckDupe(s_area *area, const s_message msg) {
  char *fileName, *str, *msgid;
  SQHheader sqhh;
  SQHentry sqhe, sqheNew, sqheNext;
  UINT32 HeadEntryN, currententry, nextentry, hash, LastUMSGID, LastTimeStamp;
  UINT16 success = 0;
  int wrapcount = 2;
  
  /* msgs without MSGID are no dupes! */
  if ((str=getKludge(msg, "MSGID:"))==NULL) return 0;

  msgid = malloc(strlen(str)+1-7);
  strcpy(msgid, str+7);
  free(str);

  fileName = createDupeFileName(area);
  SQHf = fopen(fileName, "rb+");
  
  if (SQHf == NULL) {
    /* no dupefile found, create new dupefile */
    SQHf = fopen(fileName, "wb+");
    if (SQHf != NULL) {
      strncpy(sqhh.signature, "SqH", 3);
      sqhh.size = area->dupeSize;
      sqhh.maxage = area->dupeHistory*86400;
      sqhh.lastUMSGID = sqhh.maxdupes = 1 << sqhh.size;
      fwrite(&sqhh, sizeof(SQHheader), 1, SQHf);
      memset(&sqheNew, 0, sizeof(SQHentry));
      fseek(SQHf, (sqhh.maxdupes*2 - 1)*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
      fwrite(&sqheNew, sizeof(SQHentry), 1, SQHf);
    }
  }

  free(fileName);
  
  fread(&sqhh, sizeof(SQHheader), 1, SQHf);
  /* in tommorow need check signature of *.SQH-file */
  MaxAge = sqhh.maxage;
  MaxDupes = sqhh.maxdupes;

  sqheNew.preventry = 0;
  sqheNew.nextentry = 0;
  sqheNew.hash = hash = strcrc32(msgid, 0xFFFFFFFFL);
  sqheNew.timestamp = LastTimeStamp = time (NULL);
  sqheNew.UMSGID = LastUMSGID = ++sqhh.lastUMSGID;

  MaxEntryN = ((1 << (sqhh.size+1)) - 1);
  HeadEntryN = currententry = hash & MaxEntryN;
  fseek(SQHf, currententry*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
  fread(&sqhe, sizeof(SQHentry), 1, SQHf);
  if (sqhe.preventry == 0) {
    /* We select head entry */
    for (;;) {
      if (sqhe.hash == hash) {
        /* YES! Hashes is equal, and message is dupe */
	++success;
	break;
      }

      if (sqhe.nextentry == 0) {
        /* This is a last entry in chain. Dupe not found. Insert new entry */
        fseek(SQHf, 0, SEEK_SET);
        fwrite(&sqhh, sizeof(SQHheader), 1, SQHf);
	for (currententry=HeadEntryN;;currententry = (currententry + sqheNew.nextentry) & MaxEntryN) {
          fseek(SQHf, currententry*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
          fread(&sqhe, sizeof(SQHentry), 1, SQHf);
	  sqheNew.preventry = sqhe.preventry;
	  sqheNew.nextentry = sqhe.nextentry;
          fseek(SQHf, currententry*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
          fwrite(&sqheNew, sizeof(SQHentry), 1, SQHf);
          if (sqhe.UMSGID+MaxDupes < LastUMSGID ||
              sqhe.timestamp+MaxAge < LastTimeStamp)
	    break;
	  sqheNew.hash = sqhe.hash;
	  sqheNew.timestamp = sqhe.timestamp;
	  sqheNew.UMSGID = sqhe.UMSGID;
	  if (sqhe.nextentry == 0) {
	    AppendEntry(currententry, &sqheNew, LastUMSGID, LastTimeStamp);
	    break;
	  }
	}
	/* Inserted new entry. Exit */
        break;
      }
      
      /* Select next entry in chain */
      nextentry = (currententry + sqhe.nextentry) & MaxEntryN;
      fseek(SQHf, nextentry*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
      fread(&sqhe, sizeof(SQHentry), 1, SQHf);
      if (nextentry<currententry && --wrapcount) {
        /* Oops! We come full circle. */
        writeLogEntry(hpt_log, '5', "Too long chain of collision entries for AREA: `%s', entry: `%08xH'", area->areaName, HeadEntryN);
        break;
      }
      currententry = nextentry;
    }
  }

  else {
    /* We select collision entry. Dupe not found. */
    fseek(SQHf, 0, SEEK_SET);
    fwrite(&sqhh, sizeof(SQHheader), 1, SQHf);

    fseek(SQHf, HeadEntryN*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
    fwrite(&sqheNew, sizeof(SQHentry), 1, SQHf);

    nextentry = (HeadEntryN - sqhe.preventry) & MaxEntryN;
    fseek(SQHf, nextentry*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
    fread(&sqheNext, sizeof(SQHentry), 1, SQHf);
    if (sqhe.nextentry) {
      /* We replace midle entry in chain */
      sqheNext.nextentry += sqhe.nextentry;
      fseek(SQHf, nextentry*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
      fwrite(&sqheNext, sizeof(SQHentry), 1, SQHf);

      nextentry = (HeadEntryN + sqhe.nextentry) & MaxEntryN;
      fseek(SQHf, nextentry*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
      fread(&sqheNext, sizeof(SQHentry), 1, SQHf);
      sqheNext.preventry += sqhe.preventry;
      
      if (sqhe.UMSGID + sqhh.maxdupes < LastUMSGID ||
          sqhe.timestamp + sqhh.maxage < LastTimeStamp) {
	/* Entry expired. Reallocation not need. Repair collision chain. */
        fseek(SQHf, nextentry*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
        fwrite(&sqheNext, sizeof(SQHentry), 1, SQHf);
      }
      else /* Reallocate replaced collision entry. */
       for (currententry=nextentry;;) {
	  /* sqhe -- replacing entry, sqheNext - replaced entry */
	  sqhe.preventry = sqheNext.preventry;
	  sqhe.nextentry = sqheNext.nextentry;
          fseek(SQHf, currententry*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
          fwrite(&sqhe, sizeof(SQHentry), 1, SQHf);
          if (sqheNext.UMSGID+MaxDupes < LastUMSGID ||
              sqheNext.timestamp+MaxAge < LastTimeStamp)
	    break;
	  sqhe.hash = sqheNext.hash;
	  sqhe.timestamp = sqheNext.timestamp;
	  sqhe.UMSGID = sqheNext.UMSGID;
	  if (sqhe.nextentry == 0) {
	    AppendEntry(currententry, &sqhe, LastUMSGID, LastTimeStamp);
	    break;
	  }
	  currententry = (currententry + sqhe.nextentry) & MaxEntryN;
          fseek(SQHf, currententry*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
          fread(&sqheNext, sizeof(SQHentry), 1, SQHf);
        }
    }
    else {
      /* We replace last entry in chain */
      if (sqhe.UMSGID + sqhh.maxdupes < LastUMSGID ||
          sqhe.timestamp + sqhh.maxage < LastTimeStamp) {
	/* Entry expired. Reallocation not need. Repair collision chain. */
        sqheNext.nextentry = 0;
        fseek(SQHf, nextentry*sizeof(SQHentry)+sizeof(SQHheader), SEEK_SET);
        fwrite(&sqheNext, sizeof(SQHentry), 1, SQHf);
      }
      else /* Reallocate replaced collision entry. */
        AppendEntry(nextentry, &sqhe, LastUMSGID, LastTimeStamp);
    }

  }
  
  fclose(SQHf);
  free(msgid);
  return success;
}

int dupeDetection(s_area *area, const s_message msg) {
   int  rc;

   if (area->dupeCheck == dcOff) return 1; // no dupeCheck return 1 "no dupe"
   
   if (CheckDupe(area, msg))
      // it is a dupe do nothing but return 0
      rc = 0;
   else
      rc = 1;

   return rc;
}

#endif
