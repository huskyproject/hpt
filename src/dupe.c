#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <dupe.h>
#include <pkt.h>

#include <global.h>
#include <msgapi.h>

#include <compiler.h>
#include <stamp.h>
#include <progprot.h>

FILE *write;

char *createDupeFileName(s_area *area) {
   char *name;

   name = (char *) malloc(strlen(config->dupeHistoryDir)+strlen(area->areaName)+5);
   strcpy(name, config->dupeHistoryDir);
   strcat(name, area->areaName);
   strcat(name, ".dup");

   return name;
}

int compareEntries(const void *e1, const void *e2) {
   s_dupeEntry *a, *b;
   int rc;

   a = e1; b = e2;

   rc = strcmp(a->from, b->from);
   if (rc == 0) rc = strcmp(a->to, b->to);
   if (rc == 0) rc = strcmp(a->subject, b->subject);
   if (rc == 0) rc = strcmp(a->msgid, b->msgid);

   return rc;
}

int writeEntry(s_dupeEntry *entry) {
   fputc(strlen(entry->from), write); fputs(entry->from, write);
   fputc(strlen(entry->to), write); fputs(entry->to, write);
   fputc(strlen(entry->subject), write); fputs(entry->subject, write);
   fputc(strlen(entry->msgid), write); fputs(entry->msgid, write);
   
   return 0;
}
   
void deleteEntry(s_dupeEntry *entry) {
   free(entry->to);
   free(entry->from);
   free(entry->subject);
   free(entry->msgid);
   free(entry);
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
         tree_add(&(mem->tree), &compareEntries, entry, &deleteEntry);
      }
      
      free(packHeader);
   }

   free(fileHeader);
}

s_dupeMemory *readDupeFile(s_area *area) {
   FILE *f;
   char *fileName;
   s_dupeMemory *dupeMemory;
   
   dupeMemory = malloc(sizeof(s_dupeMemory));
   tree_init(&dupeMemory->tree);

   fileName = createDupeFileName(area);
   f = fopen(fileName, "rb");
   if (f != NULL) {
      // readFile
      doReading(f, dupeMemory);
      fclose(f);
   }
   free(fileName);

   return dupeMemory;
}

int appendToDupeFile(char *name, s_dupeMemory newDupeEntries) {
   FILE *f;
   UINT32 packs;
   s_dupePackHeader packHeader;
   

   f = fopen(name, "rb+");

   if (f == NULL) return 1;

   // seek for noOfPacks
   fseek(f, 8, SEEK_SET);
   // read noOfPacks
   fread(&packs, sizeof(UINT32), 1, f);
   // seek for noOfPacks
   fseek(f, 8, SEEK_SET);
   // write noOfPacks+1
   packs++;
   fwrite(&packs, sizeof(UINT32), 1, f);

   // add new packet to end of file
   fseek(f, 0, SEEK_END);
   packHeader.noOfEntries = tree_count(newDupeEntries.tree);
   packHeader.time_tSize  = sizeof(time_t);
   packHeader.packTime    = time(NULL);
   fwrite(&packHeader, sizeof(s_dupePackHeader), 1, f);

   // add entries
   write = f;
   tree_trav(newDupeEntries.tree, &writeEntry);
   write = NULL;
         
   fclose(f);

   return 0;
}

int createDupeFile(char *name, s_dupeMemory newDupeEntries) {
   FILE *f;
   s_dupeFileHeader fileHeader;
   s_dupePackHeader packHeader;

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
      packHeader.noOfEntries   = tree_count(newDupeEntries.tree);
      packHeader.time_tSize    = sizeof(time_t);
      packHeader.packTime      = time(NULL);
      fwrite(&packHeader, sizeof(s_dupePackHeader), 1, f);

      // write new Entries
      write = f;
      tree_trav(newDupeEntries.tree, &writeEntry);
      write = NULL;
      
      return 0;
   } else return 1;
}

int writeToDupeFile(s_area *area) {
   char *fileName;
   int  rc = 0;
   s_dupeMemory *newDupes = area->newDupes;

   if (newDupes != NULL) {

      if (tree_count(newDupes->tree) > 0) {

         fileName = createDupeFileName(area);

         if(fexist(fileName)) rc = appendToDupeFile(fileName, *newDupes);
         else rc = createDupeFile(fileName, *newDupes);

         free(fileName);
      }

   }

   return rc;
}

int isDupe(s_area area, s_dupeEntry *entry) {
   char first = 0, second = 0;

   return (first || second);
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
      tree_init(&newDupes->tree);
      area->newDupes = newDupes;
   }

   entry = malloc(sizeof(s_dupeEntry));

   entry->from    = malloc(strlen(msg.fromUserName)+1); strcpy(entry->from, msg.fromUserName);
   entry->to      = malloc(strlen(msg.toUserName)+1); strcpy(entry->to, msg.toUserName);
   entry->subject = malloc(strlen(msg.subjectLine)+1); strcpy(entry->subject, msg.subjectLine);
   str = getKludge(msg, "MSGID:");
   entry->msgid   = malloc(strlen(str)+1); strcpy(entry->msgid, str);

   if (!isDupe(*area, entry)) {
      // add to newDupes
      tree_add(&newDupes->tree, &compareEntries, entry, &deleteEntry);
      return 1;
   }
   // it is a dupe do nothing but return 0
   else return 0;
}