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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#include <pkt.h>

#include <global.h>

#include <smapi/compiler.h>
#include <smapi/unused.h>
#include <dupe.h>

#include <smapi/msgapi.h>
#include <smapi/stamp.h>
#include <smapi/progprot.h>

FILE *fDupe;

UINT32  DupeCountInHeader, maxTimeLifeDupesInArea;
unsigned long strcrc32(char *, unsigned long); 
s_dupeMemory *CommonDupes=NULL;


char *strtolower(char *string) {
  register int cont;
  int l;
  char *tmp;
    
  l=strlen(string);
  tmp=(char *) malloc (l+1);
  for (cont=0;cont<=l;cont++)
    tmp[cont]=(char)tolower(string[cont]);
  
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

  switch (config->typeDupeBase) {
     case hashDupes:
          strcat(name,".dph");
 	  break;
     case hashDupesWmsgid:
          strcat(name,".dpd");
 	  break;
     case textDupes:
          strcat(name,".dpt");
 	  break;
     case commonDupeBase:
 	  break;
  }

   return name;
}

int compareEntriesBlank(char *e1, char *e2) {
   int rc=1;
   unused(e1); unused(e2);
   return rc;
}


int compareEntries(char *p_e1, char *p_e2) {
   const s_textDupeEntry  *atxt,   *btxt;
   const s_hashDupeEntry  *ahash,  *bhash;
   const s_hashMDupeEntry *ahashM, *bhashM;
   int rc = 1;
   const void *e1 = (const void *)p_e1, *e2 = (const void *)p_e2;

   switch (config->typeDupeBase) {
      case hashDupes:
          ahash = e1; bhash = e2;
          if (ahash->CrcOfDupe == bhash->CrcOfDupe)
             rc=0;
          else
             rc=1;   
 	  break;
 
      case hashDupesWmsgid:
          ahashM = e1; bhashM = e2;
          if (ahashM->CrcOfDupe == bhashM->CrcOfDupe)
           rc = strcmp(ahashM->msgid, bhashM->msgid);
          else
           rc=1;   
 	  break;

      case textDupes:
          atxt = e1; btxt = e2;
          rc = strcmp(atxt->from, btxt->from);
          if (rc == 0) rc = strcmp(atxt->to, btxt->to);
          if (rc == 0) rc = strcmp(atxt->subject, btxt->subject);
          if (rc == 0) rc = strcmp(atxt->msgid, btxt->msgid);
 	  break;

      case commonDupeBase:
          ahash = e1; bhash = e2;
          if (ahash->CrcOfDupe == bhash->CrcOfDupe)
             rc=0;
          else
             rc=1;   
          break;
   }

   return rc;
}

int writeEntry(char *p_entry) {
   const s_textDupeEntry  *entxt;
   const s_hashDupeEntry  *enhash;
   const s_hashMDupeEntry *enhashM;
   UINT32 diff=0;
   time_t currtime;
   const void *entry = (const void *)p_entry;

   currtime = time(NULL);

   switch (config->typeDupeBase) {
      case hashDupes:
           enhash = entry;
           if ( (diff = currtime - enhash->TimeStampOfDupe) < maxTimeLifeDupesInArea) {
              fwrite(enhash, sizeof(s_hashDupeEntry), 1, fDupe);
              DupeCountInHeader++;   
           }
   	   break;

      case hashDupesWmsgid: 
           enhashM = entry;
           if ( (diff = currtime - enhashM->TimeStampOfDupe) < maxTimeLifeDupesInArea) {
              fwrite(enhashM, sizeof(time_t)+sizeof(UINT32), 1, fDupe);
              if ((enhashM->msgid != NULL)&&(0 < strlen(enhashM->msgid))) {
                 fputc(strlen(enhashM->msgid), fDupe);
                 fputs(enhashM->msgid, fDupe);
              }
              else fputc(0, fDupe);
              DupeCountInHeader++;   
           }
  	   break;

      case textDupes:
           entxt = entry;
           if ( (diff = currtime - entxt->TimeStampOfDupe) < maxTimeLifeDupesInArea) {
              fwrite(entxt, sizeof(time_t), 1, fDupe);
              if ((entxt->msgid != NULL)&&(0 < strlen(entxt->from))) {
                 fputc(strlen(entxt->from), fDupe); 
                 fputs(entxt->from, fDupe);
              }
              else fputc(0, fDupe);
              if ((entxt->msgid != NULL)&&(0 < strlen(entxt->to))) {
                 fputc(strlen(entxt->to), fDupe); 
                 fputs(entxt->to, fDupe);
              }
              else fputc(0, fDupe);
              if ((entxt->msgid != NULL)&&(0 < strlen(entxt->subject))) {
                 fputc(strlen(entxt->subject), fDupe); 
                 fputs(entxt->subject, fDupe);
              }
              else fputc(0, fDupe);
              if ((entxt->msgid != NULL)&&(0 < strlen(entxt->msgid))) {
                 fputc(strlen(entxt->msgid), fDupe);
                 fputs(entxt->msgid, fDupe);
              }
              else fputc(0, fDupe);
              DupeCountInHeader++;   
           }
 	   break;

      case commonDupeBase:
           enhash = entry;
           if ( (diff = currtime - enhash->TimeStampOfDupe) < maxTimeLifeDupesInArea) {
              fwrite(enhash, sizeof(s_hashDupeEntry), 1, fDupe);
              DupeCountInHeader++;   
           }
           break;
   }

   return 1;
}
 
int deleteEntry(char *entry) {
   const s_textDupeEntry  *entxt;
   const s_hashDupeEntry  *enhash;
   const s_hashMDupeEntry *enhashM;

   switch (config->typeDupeBase) {
      case hashDupes:
           enhash = (s_hashDupeEntry *)entry;
           free((s_hashDupeEntry*) enhash);
 	   break;

      case hashDupesWmsgid:
           enhashM = (s_hashMDupeEntry *)entry;
           free((s_hashMDupeEntry*)enhashM->msgid);
           free((s_hashMDupeEntry*)enhashM);
 	   break;

      case textDupes:
           entxt = (s_textDupeEntry *)entry;
           free((s_textDupeEntry*)entxt->to);
           free((s_textDupeEntry*)entxt->from);
           free((s_textDupeEntry*)entxt->subject);
           free((s_textDupeEntry*)entxt->msgid);
           free((s_textDupeEntry*)entxt);
 	   break;

      case commonDupeBase:
           enhash = (s_hashDupeEntry *)entry;
           free((s_hashDupeEntry*)enhash);
           break;
   }

   return 1;
}

void doReading(FILE *f, s_dupeMemory *mem) {
   s_textDupeEntry  *entxt;
   s_hashDupeEntry  *enhash;
   s_hashMDupeEntry *enhashM;
   UCHAR   length;
   UINT32 i;
   time_t timedupe;

   // read Number Of Dupes from dupefile
   fread(&DupeCountInHeader, sizeof(UINT32), 1, f);

   // process all dupes
   for (i = 0; i < DupeCountInHeader; i++) {
       if (feof(f)) break;

       switch (config->typeDupeBase) {
          case hashDupes:
               enhash = (s_hashDupeEntry*) malloc(sizeof(s_hashDupeEntry));
               fread(enhash, sizeof(s_hashDupeEntry), 1, f);
               tree_add(&(mem->avlTree), compareEntriesBlank, (char *) enhash, deleteEntry);
     	       break;

          case hashDupesWmsgid:
               enhashM = (s_hashMDupeEntry*) malloc(sizeof(s_hashMDupeEntry));
               fread(enhashM, sizeof(time_t)+sizeof(UINT32), 1, f);
               if ((length = (UCHAR)getc(f)) > 0) {  /* no EOF check :-( */
                  enhashM->msgid = malloc(length+1);
                  fread((UCHAR*)enhashM->msgid, length, 1, f);     
                  enhashM->msgid[length]='\0';
               } else enhashM->msgid = NULL;
               tree_add(&(mem->avlTree), compareEntriesBlank, (char *) enhashM, deleteEntry);
 	       break;

          case textDupes:
               entxt = (s_textDupeEntry*) malloc(sizeof(s_textDupeEntry));

               fread(&timedupe, sizeof(time_t), 1, f);     
               entxt->TimeStampOfDupe=timedupe;

               if ((length = (UCHAR)getc(f)) > 0) { /* no EOF check :-( */
                  entxt->from = malloc(length+1);
                  fread((UCHAR*)entxt->from, length, 1, f);     
                  entxt->from[length]='\0';
               } else entxt->from = NULL;
               if ((length = (UCHAR) getc(f)) > 0) { /* no EOF check :-( */
                  entxt->to = malloc(length+1);
                  fread((UCHAR*)entxt->to, length, 1, f);     
                  entxt->to[length]='\0';
               } else entxt->to = NULL;
               if ((length = (UCHAR)getc(f)) > 0) { /* no EOF check :-( */
                  entxt->subject = malloc(length+1);
                  fread((UCHAR*)entxt->subject, length, 1, f);     
                  entxt->subject[length]='\0';
	       } else entxt->subject = NULL;
               if ((length = (UCHAR)getc(f)) > 0) { /* no EOF check :-( */
                  entxt->msgid = malloc(length+1);
                  fread((UCHAR*)entxt->msgid, length, 1, f);     
                  entxt->msgid[length]='\0';
	       } else entxt->msgid = NULL;

               tree_add(&(mem->avlTree), compareEntriesBlank, (char *) entxt, deleteEntry);
 	       break;

          case commonDupeBase:
               enhash = (s_hashDupeEntry*) malloc(sizeof(s_hashDupeEntry));
               fread(enhash, sizeof(s_hashDupeEntry), 1, f);
               tree_add(&(mem->avlTree), compareEntriesBlank, (char *) enhash, deleteEntry);
               break;
       }
   

   }
}

s_dupeMemory *readDupeFile(s_area *area) {
   FILE *f;
   char *fileName;
   s_dupeMemory *dupeMemory;

   dupeMemory = malloc(sizeof(s_dupeMemory));
   tree_init(&(dupeMemory->avlTree));
 
   if (config->typeDupeBase!=commonDupeBase) {
      fileName = createDupeFileName(area);
      writeLogEntry(hpt_log, '2', "Reading dupes of %s.", area->areaName);
   }
   else {
      fileName = malloc(strlen(config->dupeHistoryDir)+15);
      strcpy(fileName, config->dupeHistoryDir);
      strcat(fileName, "hpt_base.dpa");
      writeLogEntry(hpt_log, '2', "Reading dupes from %s.", fileName);
   }

   f = fopen(fileName, "rb");
   if (f != NULL) {
      // readFile
      doReading(f, dupeMemory);
      fclose(f);
   } else writeLogEntry(hpt_log, '2', "Error reading dupes.");
   
   free(fileName);

   return dupeMemory;
}


int createDupeFile(s_area *area, char *name, s_dupeMemory DupeEntries) {
   FILE *f;

   f = fopen(name, "wb");
   if (f!= NULL) {
      
       if (config->typeDupeBase!=commonDupeBase)
          maxTimeLifeDupesInArea=area->dupeHistory*86400;    
       else
          maxTimeLifeDupesInArea=config->areasMaxDupeAge*86400;    

       DupeCountInHeader = 0;
       fwrite(&DupeCountInHeader, sizeof(UINT32), 1, f);    
       fDupe = f;
       tree_trav(&(DupeEntries.avlTree), writeEntry);
       fDupe = NULL;

       // writeDupeFileHeader
       if (DupeCountInHeader>0) {
          fseek(f, 0, SEEK_SET);
          fwrite(&DupeCountInHeader, sizeof(UINT32), 1, f);    
          fclose(f);
       // for 1 save commonDupeBase
       if (config->typeDupeBase==commonDupeBase)
          freeDupeMemory(area);
       }
       else {
          fclose(f);
          remove (name);
       }
     
       return 0;
   } else return 1;
}


int writeToDupeFile(s_area *area) {
   char *fileName;
   s_dupeMemory *dupes;
   int  rc = 0;          

   if (config->typeDupeBase!=commonDupeBase) {
      dupes = area->dupes;
      fileName = createDupeFileName(area);
   }
   else {
      dupes = CommonDupes;
      fileName = (char *) malloc(strlen(config->dupeHistoryDir)+15);
      strcpy(fileName, config->dupeHistoryDir);
      strcat(fileName, "hpt_base.dpa");
   }

   if (dupes != NULL) {
      if (tree_count(&(dupes->avlTree)) > 0) {
         rc = createDupeFile(area, fileName, *dupes);
      }
   }

   free(fileName);

   return rc;
}


void freeDupeMemory(s_area *area) {
   s_dupeMemory *dupes;
  
   if (config->typeDupeBase != commonDupeBase) 
      dupes = area -> dupes;
   else
      dupes = CommonDupes;

   if (dupes != NULL) {
      tree_mung(&(dupes -> avlTree), deleteEntry);
      if (config->typeDupeBase != commonDupeBase) {
         free(area -> dupes); area -> dupes = NULL;
      }
      else {
         free(CommonDupes); CommonDupes = NULL;
      }
   };
}


int dupeDetection(s_area *area, const s_message msg) {
   s_dupeMemory     *Dupes = area->dupes;
   s_textDupeEntry  *entxt;
   s_hashDupeEntry  *enhash;
   s_hashMDupeEntry *enhashM;
   char             *str, *str1;

   if (area->dupeCheck == dcOff) return 1; // no dupeCheck return 1 "no dupe"
   if ((str=getKludge(msg, "MSGID:"))==NULL) { 
      if (msg.text!=NULL) {
         str = malloc(25);                     // make pseudo MSGID from text!   
         sprintf (str, "MSGID: %08lx",strcrc32(msg.text, 0xFFFFFFFFL));
      }
      else {
         return 1;         // without msg.text - message is empty, no dupeCheck
      }
   }

   // test if dupeDatabase is already read
   if (config->typeDupeBase != commonDupeBase) {
      if (area->dupes == NULL) {
         Dupes = area->dupes = readDupeFile(area); //read Dupes
      }
   }
   else {
      if (CommonDupes == NULL)
         CommonDupes = readDupeFile(area); //read Dupes
   }

   switch (config->typeDupeBase) {
      case hashDupes:
           enhash = malloc(sizeof(s_hashDupeEntry));
           str1   = malloc(strlen(msg.fromUserName)+strlen(msg.toUserName)+strlen(msg.subjectLine)+strlen(str));
           strcpy(str1, msg.fromUserName);
           strcat(str1, msg.toUserName);
           strcat(str1, msg.subjectLine);
           strcat(str1, str+7);
           free(str);
           enhash->CrcOfDupe       = strcrc32(str1, 0xFFFFFFFFL);
           enhash->TimeStampOfDupe = time (NULL);
           free(str1);

           if (tree_srchall(&(Dupes->avlTree), compareEntries, (char *) enhash)) {
              // add to Dupes
              tree_add(&(Dupes->avlTree), compareEntriesBlank, (char *) enhash, deleteEntry);
              return 1;
           }
           // it is a dupe do nothing but return 0; and free dupe entry
           else {
           deleteEntry((char *)enhash);
           return 0;
           }
 	   break;

      case hashDupesWmsgid:
           enhashM = malloc(sizeof(s_hashMDupeEntry));
           str1    = malloc(strlen(msg.fromUserName)+strlen(msg.toUserName)+strlen(msg.subjectLine)+strlen(str));
           strcpy(str1, msg.fromUserName);
           strcat(str1, msg.toUserName);
           strcat(str1, msg.subjectLine);
           strcat(str1, str+7);
           enhashM->msgid = malloc(strlen(str)+1-7); 
           strcpy(enhashM->msgid, str+7);
           free(str);
           enhashM->CrcOfDupe       = strcrc32(str1, 0xFFFFFFFFL);
           enhashM->TimeStampOfDupe = time (NULL);
           free(str1);

           if (tree_srchall(&(Dupes->avlTree), compareEntries, (char *) enhashM)) {
              tree_add(&(Dupes->avlTree), compareEntriesBlank, (char *) enhashM, deleteEntry);
              return 1;
           }
           else {
              deleteEntry((char *)enhashM);
              return 0;
           }
 	   break;

      case textDupes: 
           entxt = malloc(sizeof(s_textDupeEntry));
           entxt->TimeStampOfDupe = time (NULL);
           
           entxt->from    = malloc(strlen(msg.fromUserName)+2); 
           if (0==strlen(msg.fromUserName)) strcpy(entxt->from," "); else strcpy(entxt->from, msg.fromUserName); 
           entxt->to      = malloc(strlen(msg.toUserName)+2); 
           if (0==strlen(msg.toUserName)) strcpy(entxt->to," "); else strcpy(entxt->to, msg.toUserName);
           entxt->subject = malloc(strlen(msg.subjectLine)+2); 
           if (0==strlen(msg.subjectLine)) strcpy(entxt->subject," "); else strcpy(entxt->subject, msg.subjectLine);
           entxt->msgid   = malloc(strlen(str)+2-7); strcpy(entxt->msgid, str+7);
           free(str);

           if (tree_srchall(&(Dupes->avlTree), compareEntries, (char *) entxt)) {
              tree_add(&(Dupes->avlTree), compareEntriesBlank, (char *) entxt, deleteEntry);
              return 1;
           }
           else {
              deleteEntry((char *)entxt);
              return 0;
           }
   	   break;
      
      case commonDupeBase:
           enhash = malloc(sizeof(s_hashDupeEntry));
           str1   = malloc(strlen(msg.fromUserName)+strlen(msg.toUserName)+strlen(msg.subjectLine)+strlen(area->areaName)+strlen(str)+10);
           strcpy(str1, area->areaName);
           strcat(str1, msg.fromUserName);
           strcat(str1, msg.toUserName);
           strcat(str1, msg.subjectLine);
           strcat(str1, str+7);
           free(str);
           enhash->CrcOfDupe       = strcrc32(str1, 0xFFFFFFFFL);
           enhash->TimeStampOfDupe = time (NULL);
           free(str1);

           if (tree_srchall(&(CommonDupes->avlTree), compareEntries, (char *) enhash)) {
              tree_add(&(CommonDupes->avlTree), compareEntriesBlank, (char *) enhash, deleteEntry);
              return 1;
           }
           else {
              deleteEntry((char *)enhash);
              return 0;
           }
           break;
   }

 return 0;
}

