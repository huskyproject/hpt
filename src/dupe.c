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

#include <pkt.h>

#include <global.h>
#include <msgapi.h>

#include <compiler.h>
#include <stamp.h>
#include <progprot.h>
#include <dupe.h>

FILE *fDupe;

char *createDupeFileName(s_area *area) {
   char *name;
   #ifdef MSDOS
   char *afname;
   #endif

   
   name = (char *) malloc(strlen(config->dupeHistoryDir)+
   #ifndef MSDOS
   strlen(area->areaName)+5
   #else
   5+9
   #endif
   );

   strcpy(name, config->dupeHistoryDir);
   #ifndef MSDOS
   strcat(name, area->areaName);
   #else
   strcat(name, (afname = strrchr(area->fileName, '\\'))  != NULL ? afname + 1 : area->fileName);
   #endif
   strcat(name, ".dup");

   return name;
}

void addIndex(s_area *area, UINT32 offset) {

   FILE *f;
   char *fileName = createDupeFileName(area)
   #ifdef MSDOS
	, *ext
   #endif
   ;

   fileName = realloc(fileName, strlen(fileName)+6+1);
   #ifndef MSDOS
   strcat(fileName, ".index");
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
   if ((rc == 0) && (a->msgid != NULL && b->msgid != NULL)) rc = strcmp(a->msgid, b->msgid);

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
   char *buff;

   buff = (char *) malloc(strlen(area->areaName)+1+18);
   sprintf(buff, "Reading dupes of %s.", area->areaName);
   writeLogEntry(log, '2', buff);
   free(buff);
   
   dupeMemory = malloc(sizeof(s_dupeMemory));
   tree_init(&(dupeMemory->avlTree));

   fileName = createDupeFileName(area);
   f = fopen(fileName, "rb");
   if (f != NULL) {
      // readFile
      doReading(f, dupeMemory);
      fclose(f);
   } else writeLogEntry(log, '2', "Error reading dupes.");
   
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

   if (area->dupeCheck == off) return 1; // no dupeCheck return 1 "no dupe"

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
   str = getKludge(msg, "MSGID:");
   if (str != NULL) {
      entry->msgid   = malloc(strlen(str)+1-7); strcpy(entry->msgid, str+7);
      free(str);
   } else entry->msgid = NULL;

   if (!isDupe(*area, entry)) {
      // add to newDupes
      tree_add(&(newDupes->avlTree), &compareEntries, (char *) entry, &deleteEntry);
      return 1;
   }
   // it is a dupe do nothing but return 0
   else return 0;
}
