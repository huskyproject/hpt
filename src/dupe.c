#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <dupe.h>
#include <pkt.h>

#include <lhash.h>

#include <msgapi.h>

#include <compiler.h>
#include <stamp.h>
#include <progprot.h>

char *createDupeFileName(s_area *area) {
   char *name;

   name = (char *) malloc(strlen(area->fileName)+6);
   strcpy(name, area->fileName);
   
   if (area->msgbType == MSGTYPE_SDM) strcat(name, "dupes");
   else strcat(name, ".dup");

   return name;
}

void doReading(FILE *f, s_dupeMemory *mem) {
   // read Header
   s_dupeFileHeader *fileHeader;
   s_dupePackHeader *packHeader;
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
      
      mem->entries = realloc(mem->entries, (mem->noOfEntries + packHeader->noOfEntries) * packHeader->entrySize);
      // process all entries in a pack
      for (j = 0; j < packHeader->noOfEntries; i++) {
         // read the entry Struct
         fread(&(mem->entries[mem->noOfEntries + j]), packHeader->entrySize, 1, f);
         
         mem->noOfEntries++;
      }
      free(packHeader);
   }

   free(fileHeader);
}

int compareEntries(const void *e1, const void *e2) {
   const s_dupeEntry *a, *b;

   a = e1; b = e2;

   if (a->hash > b->hash) return 1;
   else if (a->hash == b->hash) return 0;
   else return -1;
}

s_dupeMemory *readDupeFile(s_area *area) {
   FILE *f;
   char *fileName;
   s_dupeMemory *dupeMemory;
   
   dupeMemory = malloc(sizeof(s_dupeMemory));
   dupeMemory->entries = NULL;
   dupeMemory->noOfEntries = 0;

   fileName = createDupeFileName(area);
   f = fopen(fileName, "rb");
   if (f != NULL) {
      // readFile
      doReading(f, dupeMemory);
      // sort entries for faster searching...
      qsort(&(dupeMemory->entries),dupeMemory->noOfEntries, sizeof(s_dupeEntry), &compareEntries);

      fclose(f);
   } else {
      // return "null"-struct
      dupeMemory->entrySize = sizeof(s_dupeEntry);
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
   packHeader.entrySize   = sizeof(s_dupeEntry);
   packHeader.noOfEntries = newDupeEntries.noOfEntries;
   packHeader.time_tSize  = sizeof(time_t);
   packHeader.packTime    = time(NULL);
   fwrite(&packHeader, sizeof(s_dupePackHeader), 1, f);

   // add entries
   fwrite(&(newDupeEntries.entries), newDupeEntries.entrySize, newDupeEntries.noOfEntries, f);
         
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
      packHeader.noOfEntries   = newDupeEntries.noOfEntries;
      packHeader.entrySize     = sizeof(s_dupeEntry);
      packHeader.time_tSize    = sizeof(time_t);
      packHeader.packTime      = time(NULL);
      fwrite(&packHeader, sizeof(s_dupePackHeader), 1, f);

      // write new Entries
      fwrite(newDupeEntries.entries, newDupeEntries.entrySize, newDupeEntries.noOfEntries, f);
      
      return 0;
   } else return 1;
}

int writeToDupeFile(s_area *area, s_dupeMemory newDupeEntries) {
   char *fileName;
   int  rc;

   fileName = createDupeFileName(area);

   if(fexist(fileName)) rc = appendToDupeFile(fileName,  newDupeEntries);
   else rc = createDupeFile(fileName, newDupeEntries);

   free(fileName);
   
   return rc;
}

UINT32 msgHash(s_message msg) {

   char   msgId[120];
   int    i = 0;
   char   *start;
   char   *hashstr;

   UINT32 hashCode;

   msgId[0] = 0;
   start = strstr(msg.text, "MSGID: ");
   if (start!=NULL)
      while(*start != '\r') {
         msgId[i] = *start;
         start++; i++;
         if (i > 118) break;
      }
   msgId[i] = 0;

   hashstr = malloc(strlen(msg.fromUserName) + strlen(msg.toUserName) + strlen(msg.subjectLine) + strlen(msgId) + 1);

   strcpy(hashstr, msg.fromUserName);
   strcat(hashstr, msg.toUserName);
   strcat(hashstr, msg.subjectLine);
   strcat(hashstr, msgId);

   hashCode = lh_strhash(hashstr);
   
   free(hashstr);

   return hashCode;
}

int binSearch(s_dupeMemory *mem, UINT32 hashCode, UINT32 left, UINT32 right) {
   UINT32 middle = (right - left) / 2;
   // test if middle is positiv
   if (hashCode == mem->entries[middle].hash) return 1;
   else if (left == right) return 0;
   // else recurse
   else if (hashCode < middle) return binSearch(mem, hashCode, left, middle-1);
   else return binSearch(mem, hashCode, middle+1, right);
}

int isDupe(s_area area, const s_message msg) {
   UINT32 hashCode = msgHash(msg);
   s_dupeMemory *mem = area.dupes, *newMem = area.newDupes;

   return ((binSearch(mem, hashCode, 0, mem->noOfEntries-1)==1) || (binSearch(newMem, hashCode, 0, newMem->noOfEntries-1)==1));;
}

int dupeDetection(s_area *area, const s_message msg) {
   s_dupeMemory *newDupes;
   
   // test if dupeDatabase is already read
   if (area->dupes == NULL) {
      //read Dupes
      readDupeFile(area);
   }
   // test if newDupes area already built up
   if (area->newDupes == NULL) {
      //make newDupes "NULL-struct"
      newDupes = malloc(sizeof(s_dupeMemory));
      newDupes->noOfEntries = 0;
      newDupes->entrySize = sizeof(s_dupeEntry);
      newDupes->entries = NULL;
      area->newDupes = newDupes;
   }
   if (!isDupe(*area, msg)) {
      // add to newDupes
      newDupes = area->newDupes;
      newDupes->noOfEntries++;
      newDupes->entries = realloc(newDupes->entries, newDupes->noOfEntries * sizeof(s_dupeEntry));
      newDupes->entries[newDupes->noOfEntries-1].hash = msgHash(msg);
      return 1;
   }
   // it is a dupe do nothing but return 0
   else return 0;
}