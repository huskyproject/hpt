/*:ts=8*/
/*****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 * Copyright (C) 1997-1998
 *
 * Matthias Tichy
 *
 * Fido:     2:2433/1245 2:2433/1247 2:2432/601.29
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifndef  MSDOS
#include <fidoconfig.h>
#else
#include <fidoconf.h>
#endif

#include <dupe.h>
#include <version.h>
#include <global.h>

int processArea(s_area *echo) {
   time_t currentTime = time(NULL);
   char *dupeFileName = createDupeFileName(echo),
        *indexFileName = createDupeFileName(echo),
        *tmpFileName,
        *tmpIndexFileName;
   
   FILE             *dupeFile, *tmpFile, *tmpIndexFile;
   s_dupeFileHeader *dupeFileHeader;
   s_dupePackHeader *dupePackHeader;
   UINT16           headerSize;
   UINT32           oldindex, index, i, bufferSize, packs = 0;
   char             *buffer;
   struct stat      dupeStat;


   // create temporary Files
   tmpFileName = malloc(strlen(dupeFileName)+4+1);
   strcpy(tmpFileName, dupeFileName);
   strcat(tmpFileName, ".tmp");
   tmpIndexFileName = malloc(strlen(dupeFileName)+4+6+1);
   strcpy(tmpIndexFileName, dupeFileName);
   strcat(tmpIndexFileName, ".index.tmp");

   //rename index file
   indexFileName = realloc(indexFileName, strlen(indexFileName)+6+1);
   strcat(indexFileName, ".index");
   rename(indexFileName, tmpIndexFileName);

   // open renamed index file
   tmpIndexFile = fopen(tmpIndexFileName, "r");

   // open old dupe-file
   dupeFile     = fopen(dupeFileName, "r");
   if (dupeFile == NULL) return 1;  // if there is no dupeFile
      
   // open new dupe-file
   tmpFile      = fopen(tmpFileName, "w");

   // read dupeFileHeader
   fread(&headerSize, sizeof(UINT16), 1, dupeFile);
   dupeFileHeader = (s_dupeFileHeader *) malloc(headerSize);
   fseek(dupeFile, 0, SEEK_SET);
   fread(dupeFileHeader, headerSize, 1, dupeFile);
   
   // write dupeFileHeader to tmpFile
   fwrite(dupeFileHeader, headerSize, 1, tmpFile);

   // read first oldindex
   fread(&oldindex, sizeof(oldindex), 1, tmpIndexFile);

   dupePackHeader = (s_dupePackHeader *) malloc(dupeFileHeader->dupePackHeaderSize);
   
   // process the packs
   for (i = 0; i < dupeFileHeader->noOfPacks; i++) {

      fread(dupePackHeader, dupeFileHeader->dupePackHeaderSize, 1, dupeFile);
      if (feof(dupeFile)) break;

      // read the next oldindex
      if (fread(&oldindex, sizeof(oldindex), 1, tmpIndexFile) == 0) {
         // end of File -> take the size of the dupeFile as oldindex
         stat(dupeFileName, &dupeStat);
         oldindex = dupeStat.st_size;
      }

      bufferSize = oldindex - ftell(dupeFile);
      buffer = malloc(bufferSize);

      fread(buffer, bufferSize, 1, dupeFile);


      if ((currentTime - dupePackHeader->packTime) < (echo->dupeHistory * 24 * 60 * 60)) {
         // if pack is young enough

         // add index
         index = ftell(tmpFile);
         addIndex(echo, index);

         // copy it to tmpfile
         fwrite(dupePackHeader, dupeFileHeader->dupePackHeaderSize, 1, tmpFile);
         
         fwrite(buffer, bufferSize, 1, tmpFile);
         
         packs++;
      };

      free(buffer);
   }

   // patch dupeFileHeader
   dupeFileHeader->noOfPacks = packs;
   fseek(tmpFile, 0, SEEK_SET);
   fwrite(dupeFileHeader, headerSize, 1, tmpFile);

   // kill original files and rename tempFiles
   fclose(tmpFile);
   fclose(dupeFile);
   fclose(tmpIndexFile);
   
   remove(dupeFileName);
   remove(tmpIndexFileName);
   rename(tmpFileName, dupeFileName);

   free(dupeFileName);
   free(indexFileName);
   free(tmpFileName);

   free(dupePackHeader);
   free(dupeFileHeader);

   return 0;
}

int main() {
//   s_fidoconfig *config;
   UINT i;

   printf("purgeDupes v%d.%02d\n\n", VER_MAJOR, VER_MINOR);

   config = readConfig();

   if (config != NULL) {

      for (i = 0; i < config->echoAreaCount; i++)
         if (config->echoAreas[i].dupeCheck != off) {
            printf("%s\n", config->echoAreas[i].areaName);
            processArea(&(config->echoAreas[i]));
         }

      disposeConfig(config);
   } else printf("Config file could not found.\n");

   return 0;
}
