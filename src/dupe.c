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
   UINT16 headerSize, entrySize;
   UINT32 i, j;
   void *temp;    // buffer for storing the rest of the entry struct

   // read correct size
   fread(&headerSize, sizeof(UINT16), 1, f);

   // alloc memory and read struct
   fileHeader = malloc(headerSize);
   fread(fileHeader, headerSize, 1, f);

   // process all packs
   for (i = 0; i < fileHeader->noOfPacks; i++) {
      packHeader = malloc(fileHeader->dupePackHeaderSize);
      mem->entries = realloc(mem->entries, mem->noOfEntries * sizeof(s_dupeEntry));
      temp = malloc(entrySize - sizeof(s_dupeEntry));
      // process all entries in a pack
      for (j = 0; j < packHeader->noOfEntries; i++) {
         // read the part of the entry struct we know
         fread(&(mem->entries[mem->noOfEntries]), sizeof(s_dupeEntry), 1, f);
         // read rest
         fread(temp, entrySize-sizeof(s_dupeEntry), 1, f);
         
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
   
   dupeMemory = malloc(sizeof(s_dupeMemory));;
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
      while(*start != '\n') {
         msgId[i] = *start;
         start++; i++;
         if (i > 118) break;
      }
   msgId[119] = 0;

   hashstr = malloc(strlen(msg.fromUserName) + strlen(msg.toUserName) + strlen(msg.subjectLine) + strlen(msgId) + 1);

   strcpy(hashstr, msg.fromUserName);
   strcat(hashstr, msg.toUserName);
   strcat(hashstr, msg.subjectLine);
   strcat(hashstr, msgId);

   hashCode = lh_strhash(hashstr);
   
   free(hashstr);

   return hashCode;
   
}