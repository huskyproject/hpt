/*****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 * Copyright (C) 1997-2000
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
 *****************************************************************************
 * $Id$
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include <pkt.h>
#include <global.h>

#include <smapi/compiler.h>
#include <smapi/unused.h>
#include <dupe.h>

#include <smapi/msgapi.h>
#include <smapi/stamp.h>
#include <smapi/progprot.h>

#include <fidoconf/common.h>
#include <fidoconf/xstr.h>
#include <fidoconf/crc.h>

FILE *fDupe;

UINT32  DupeCountInHeader, maxTimeLifeDupesInArea;
s_dupeMemory *CommonDupes=NULL;


char *createDupeFileName(s_area *area) {
    char *name=NULL, *ptr, *retname=NULL;

/*     w_log(LL_FUNC,"dupe.c::createDupeFileName()"); */

    if (!area->DOSFile) {/*
	if (area->fileName) xstrcat(&name, (ptr = strrchr(area->fileName,PATH_DELIM))
				    ? ptr+1 : area->fileName);
	else*/ 
        name = makeMsgbFileName(config, area->areaName);
    } else {
	if (area->fileName) xstrcat(&name, (ptr = strrchr(area->fileName,PATH_DELIM))
				    ? ptr+1 : area->fileName);
/* 	else xstrcat(&name, "passthru"); */
	else xscatprintf(&name, "%X", strcrc32(area->areaName,0xFFFFFFFFUL) );
    }

    switch (config->typeDupeBase) {
    case hashDupes:
	xstrcat(&name,".dph");
	break;
    case hashDupesWmsgid:
	xstrcat(&name,".dpd");
	break;
    case textDupes:
	xstrcat(&name,".dpt");
	break;
    case commonDupeBase:
	break;
    }

    if (config->areasFileNameCase == eUpper)
	name = strUpper(name);
    else 
	name = strLower(name);

    xstrscat(&retname, config->dupeHistoryDir, name, NULL);
    nfree(name);

/*     w_log(LL_FUNC,"dupe.c::createDupeFileName() OK (return '%s')",retname); */
    return retname;
}
/*
int compareEntriesBlank(char *e1, char *e2) {
   int rc=1;
   unused(e1); unused(e2);
   return rc;
}
*/

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
              rc = 0;
          else if (ahash->CrcOfDupe > bhash->CrcOfDupe)
              rc = 1;  
          else
              rc = -1;
 	  break;
 
      case hashDupesWmsgid:
          ahashM = e1; bhashM = e2;
          if (ahashM->CrcOfDupe == bhashM->CrcOfDupe)
              rc = strcmp(ahashM->msgid, bhashM->msgid);
          else if (ahashM->CrcOfDupe > bhashM->CrcOfDupe)
              rc = 1;  
          else
              rc = -1;
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
          else if (ahash->CrcOfDupe > bhash->CrcOfDupe)
              rc = 1;  
          else
              rc = -1;
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
    s_textDupeEntry  *entxt;
    s_hashDupeEntry  *enhash;
    s_hashMDupeEntry *enhashM;
    
    switch (config->typeDupeBase) {
    case hashDupes:
        enhash = (s_hashDupeEntry *)entry;
        nfree(enhash);
        break;
        
    case hashDupesWmsgid:
        enhashM = (s_hashMDupeEntry *)entry;
        nfree(enhashM->msgid);
        nfree(enhashM);
        break;
        
    case textDupes:
        entxt = (s_textDupeEntry *)entry;
        nfree(entxt->to);
        nfree(entxt->from);
        nfree(entxt->subject);
        nfree(entxt->msgid);
        nfree(entxt);
        break;
        
    case commonDupeBase:
        enhash = (s_hashDupeEntry *)entry;
        nfree(enhash);
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

   /*  read Number Of Dupes from dupefile */
   fread(&DupeCountInHeader, sizeof(UINT32), 1, f);

   /*  process all dupes */
   for (i = 0; i < DupeCountInHeader; i++) {
       if (feof(f)) break;

       switch (config->typeDupeBase) {
          case hashDupes:
               enhash = (s_hashDupeEntry*) safe_malloc(sizeof(s_hashDupeEntry));
               fread(enhash, sizeof(s_hashDupeEntry), 1, f);
               tree_add(&(mem->avlTree), /*compareEntriesBlank*/ compareEntries, (char *) enhash, deleteEntry);
     	       break;

          case hashDupesWmsgid:
               enhashM = (s_hashMDupeEntry*) safe_malloc(sizeof(s_hashMDupeEntry));
               fread(enhashM, sizeof(time_t)+sizeof(UINT32), 1, f);
               if ((length = (UCHAR)getc(f)) > 0) {  /* no EOF check :-( */
                  enhashM->msgid = safe_malloc(length+1);
                  fread((UCHAR*)enhashM->msgid, length, 1, f);     
                  enhashM->msgid[length]='\0';
               } else enhashM->msgid = NULL;
               tree_add(&(mem->avlTree), /*compareEntriesBlank*/ compareEntries, (char *) enhashM, deleteEntry);
 	       break;

          case textDupes:
               entxt = (s_textDupeEntry*) safe_malloc(sizeof(s_textDupeEntry));

               fread(&timedupe, sizeof(time_t), 1, f);     
               entxt->TimeStampOfDupe=timedupe;

               if ((length = (UCHAR)getc(f)) > 0) { /* no EOF check :-( */
                  entxt->from = safe_malloc(length+1);
                  fread((UCHAR*)entxt->from, length, 1, f);     
                  entxt->from[length]='\0';
               } else entxt->from = NULL;
               if ((length = (UCHAR) getc(f)) > 0) { /* no EOF check :-( */
                  entxt->to = safe_malloc(length+1);
                  fread((UCHAR*)entxt->to, length, 1, f);     
                  entxt->to[length]='\0';
               } else entxt->to = NULL;
               if ((length = (UCHAR)getc(f)) > 0) { /* no EOF check :-( */
                  entxt->subject = safe_malloc(length+1);
                  fread((UCHAR*)entxt->subject, length, 1, f);     
                  entxt->subject[length]='\0';
	       } else entxt->subject = NULL;
               if ((length = (UCHAR)getc(f)) > 0) { /* no EOF check :-( */
                  entxt->msgid = safe_malloc(length+1);
                  fread((UCHAR*)entxt->msgid, length, 1, f);     
                  entxt->msgid[length]='\0';
	       } else entxt->msgid = NULL;

               tree_add(&(mem->avlTree), /*compareEntriesBlank*/ compareEntries, (char *) entxt, deleteEntry);
 	       break;

          case commonDupeBase:
               enhash = (s_hashDupeEntry*) safe_malloc(sizeof(s_hashDupeEntry));
               fread(enhash, sizeof(s_hashDupeEntry), 1, f);
               tree_add(&(mem->avlTree), /*compareEntriesBlank*/ compareEntries, (char *) enhash, deleteEntry);
               break;
       }
   

   }
}

s_dupeMemory *readDupeFile(s_area *area) {
   FILE *f;
   char *fileName=NULL;
   s_dupeMemory *dupeMemory;

   dupeMemory = safe_malloc(sizeof(s_dupeMemory));
   tree_init(&(dupeMemory->avlTree));
   
   if (config->typeDupeBase!=commonDupeBase) {
       fileName = createDupeFileName(area);
       w_log(LL_DUPE, "Reading dupes of %s", area->areaName);
   }
   else {
       xstrscat(&fileName, config->dupeHistoryDir, "hpt_base.dpa", NULL);
       w_log(LL_DUPE, "Reading dupes from %s", fileName);
   }

   f = fopen(fileName, "rb");
   if (f != NULL) { w_log(LL_FILE,"dupe.c:readDupeFile(): opened %s (\"rb\" mode)",fileName);
       /*  readFile */
       doReading(f, dupeMemory);
       fclose(f);
   } else {
       if (fexist(fileName)) w_log(LL_ERR, "Error reading dupe base: %s", fileName);
       else if( errno != ENOENT)
         w_log(LL_ERR, "Dupe base '%s' read error: %s", fileName, strerror(errno) );
   }

   nfree(fileName);

   return dupeMemory;
}


int createDupeFile(s_area *area, char *name, s_dupeMemory DupeEntries) {
   FILE *f;

/*    w_log(LL_SRCLINE,"dupe.c:%u:createDupeFile() name='%s'", __LINE__, name); */

   f = fopen(name, "wb");
   if (f!= NULL) {
       w_log(LL_FILE,"dupe.c:createDupeFile(): opened %s (\"wb\" mode)",name);
       if (config->typeDupeBase!=commonDupeBase)
          maxTimeLifeDupesInArea=area->dupeHistory*86400;    
       else
          maxTimeLifeDupesInArea=config->areasMaxDupeAge*86400;    

       DupeCountInHeader = 0;
       fwrite(&DupeCountInHeader, sizeof(UINT32), 1, f);    
       fDupe = f;
       tree_trav(&(DupeEntries.avlTree), writeEntry);
       fDupe = NULL;

       /*  writeDupeFileHeader */
       if (DupeCountInHeader>0) {
          fseek(f, 0, SEEK_SET);
          fwrite(&DupeCountInHeader, sizeof(UINT32), 1, f);    
          fclose(f);
       /*  for 1 save commonDupeBase */
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
   char *fileName=NULL;
   s_dupeMemory *dupes;
   int  rc = 0;          

   if (area->dupeCheck == dcOff) return rc;
   
   if (config->typeDupeBase!=commonDupeBase) {
      dupes = area->dupes;
      fileName = createDupeFileName(area);
   }
   else {
      dupes = CommonDupes;
      xstrscat(&fileName, config->dupeHistoryDir, "hpt_base.dpa", NULL);
   }

   if (dupes != NULL) {
      if (tree_count(&(dupes->avlTree)) > 0) {
         rc = createDupeFile(area, fileName, *dupes);
      }
   }

   nfree(fileName);

   return rc;
}


void freeDupeMemory(s_area *area) {
   s_dupeMemory *dupes;

   if (area->dupeCheck == dcOff) return;
  
   if (config->typeDupeBase != commonDupeBase) 
      dupes = area -> dupes;
   else
      dupes = CommonDupes;

   if (dupes != NULL) {
      tree_mung(&(dupes -> avlTree), deleteEntry);
      if (config->typeDupeBase != commonDupeBase) {
         nfree(area -> dupes);
      }
      else {
         nfree(CommonDupes);
      }
   };
}


int dupeDetection(s_area *area, const s_message msg) {
    s_dupeMemory     *Dupes = area->dupes;
    s_textDupeEntry  *entxt;
    s_hashDupeEntry  *enhash;
    s_hashMDupeEntry *enhashM;
    char             *str, *str1;
    int nRet = 0;

    w_log(LL_FUNC,"dupe.c::dupeDetection() begin");
    
    if (area->dupeCheck == dcOff) return 1; /*  no dupeCheck return 1 "no dupe" */
    if ((str=(char*)GetCtrlToken((byte*)msg.text, (byte*)"MSGID:"))==NULL) {
        if (msg.text) xscatprintf (&str, "MSGID: %08lx",strcrc32(msg.text, 0xFFFFFFFFL));
        else return 1; /*  without msg.text - message is empty, no dupeCheck */
    }
    
    /*  test if dupeDatabase is already read */
    if (config->typeDupeBase != commonDupeBase) {
        if (area->dupes == NULL) {
            Dupes = area->dupes = readDupeFile(area); /* read Dupes */
        }
    }
    else {
        if (CommonDupes == NULL)
            CommonDupes = readDupeFile(area); /* read Dupes */
    }
    
    switch (config->typeDupeBase) {
    case hashDupes:
        enhash = safe_malloc(sizeof(s_hashDupeEntry));
        str1   = safe_malloc(strlen(msg.fromUserName)+strlen(msg.toUserName)+strlen(msg.subjectLine)+strlen(str));
        strcpy(str1, msg.fromUserName);
        strcat(str1, msg.toUserName);
        strcat(str1, msg.subjectLine);
        strcat(str1, str+7);
        nfree(str);
        enhash->CrcOfDupe       = strcrc32(str1, 0xFFFFFFFFL);
        enhash->TimeStampOfDupe = time (NULL);
        nfree(str1);
        nRet = tree_add(&(Dupes->avlTree), compareEntries, (char *) enhash, deleteEntry);
        break;
        
    case hashDupesWmsgid:
        enhashM = safe_malloc(sizeof(s_hashMDupeEntry));
        str1    = safe_malloc(strlen(msg.fromUserName)+strlen(msg.toUserName)+strlen(msg.subjectLine)+strlen(str));
        strcpy(str1, msg.fromUserName);
        strcat(str1, msg.toUserName);
        strcat(str1, msg.subjectLine);
        strcat(str1, str+7);
        enhashM->msgid = safe_malloc(strlen(str)+1-7); 
        strcpy(enhashM->msgid, str+7);
        nfree(str);
        enhashM->CrcOfDupe       = strcrc32(str1, 0xFFFFFFFFL);
        enhashM->TimeStampOfDupe = time (NULL);
        nfree(str1);
        nRet = tree_add(&(Dupes->avlTree), compareEntries, (char *) enhashM, deleteEntry);
        break;
        
    case textDupes: 
        entxt = safe_malloc(sizeof(s_textDupeEntry));
        entxt->TimeStampOfDupe = time (NULL);
        
        entxt->from    = safe_malloc(strlen(msg.fromUserName)+2); 
        if (0==strlen(msg.fromUserName)) strcpy(entxt->from," "); else strcpy(entxt->from, msg.fromUserName); 
        entxt->to      = safe_malloc(strlen(msg.toUserName)+2); 
        if (0==strlen(msg.toUserName)) strcpy(entxt->to," "); else strcpy(entxt->to, msg.toUserName);
        entxt->subject = safe_malloc(strlen(msg.subjectLine)+2); 
        if (0==strlen(msg.subjectLine)) strcpy(entxt->subject," "); else strcpy(entxt->subject, msg.subjectLine);
        entxt->msgid   = safe_malloc(strlen(str)+2-7); strcpy(entxt->msgid, str+7);
        nfree(str);
        nRet = tree_add(&(Dupes->avlTree), compareEntries, (char *) entxt, deleteEntry);
        break;
        
    case commonDupeBase:
        enhash = safe_malloc(sizeof(s_hashDupeEntry));
        str1   = safe_malloc(strlen(msg.fromUserName)+strlen(msg.toUserName)+strlen(msg.subjectLine)+strlen(area->areaName)+strlen(str)+10);
        strcpy(str1, area->areaName);
        strcat(str1, msg.fromUserName);
        strcat(str1, msg.toUserName);
        strcat(str1, msg.subjectLine);
        strcat(str1, str+7);
        nfree(str);
        enhash->CrcOfDupe       = strcrc32(str1, 0xFFFFFFFFL);
        enhash->TimeStampOfDupe = time (NULL);
        nfree(str1);
        nRet = tree_add(&(CommonDupes->avlTree), compareEntries, (char *) enhash, deleteEntry);
        break;
    }
    w_log(LL_FUNC,"dupe.c::dupeDetection() end nRet = %d", nRet);
    return nRet;
}

