#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <config.h>
#include <common.h>

#include <compiler.h>

s_llist *makeNextNode(s_llist **list)
{
   s_llist *node;

   if (NULL == *list) {                        // end found
      node = (s_llist *) malloc(sizeof(s_llist));
      node->next = NULL;
      *list = node;
      return node;
   } else {                                   // not at end -> recurse
      return makeNextNode(&(*list)->next);
   } /* endif */
}

void insertConfigLine(s_config *conf, char *line)
{
   char     *start;
   s_llist  *list;

   stripLeadingChars(line, " ÿ\t");

   if (('\0' == line[0]) || (';' == line[0])) {  // empty lines and comments are a waste of space
      return;
   } /* endif */

   start = strtok(line, " ÿ\t");                 // save key
   list = makeNextNode(&conf->start);
   list->keyword = (char *) malloc(strlen(start)+1);
   strcpy(list->keyword, start);

   while ('\0' != *start++);                     // find entry
   stripLeadingChars(start, " ÿ\t");
   list->entry = (char *) malloc(strlen(start)+1); //save entry
   strcpy(list->entry, start);
}

s_config *openConfig(char *fileName)
{
   FILE     *config;
   s_config *temp;
   char     line[255];

   config = fopen(fileName, "r");

   if (NULL == config) {
      return NULL;
   } /* endif */

   temp = (s_config *) malloc(sizeof(s_config));
   temp->start = NULL;

   while (NULL != fgets(line, 255, config)) {
      line[strlen(line)-1] = '\0';              // kill \n
      insertConfigLine(temp, line);
   } /* endwhile */

   fclose(config);

   temp->next = temp->start;

   return temp;
}

char *findEntry(s_llist *llist, char *key, s_llist **next)
{
   if (NULL == llist) {
      return NULL;                              // end of list
   } else {
      if (0 == stricmp(key, llist->keyword)) {   // we have found it
         *next = llist->next;
         return llist->entry;
      } else {
         return findEntry(llist->next, key, next);    // else recurse
      } /* endif */
   } /* endif */
}

char *getConfigEntry(s_config *config, char *key, e_configSearch search)
{
   switch (search) {
   case FIRST:
        return findEntry(config->start, key, &(config->next));
      break;
   case NEXT:
        return findEntry(config->next, key, &(config->next));
      break;
   default:
     break;
   } /* endswitch */
   return NULL;         // make compiler happy
}

int getConfigEntryCount(s_config *config, char *key)
{
   int i = 0;
   s_llist *llist;


   llist = config->start;
   while (NULL != llist) {
      if (stricmp(llist->keyword,key) == 0 ) i++;
      llist = llist->next;
   }
   return i;
}

s_llist *freeNode(s_llist *list)
{
   if (NULL != list->next) {                    // there is another node hanging around
      return freeNode(list->next);              // kill it
   } else {
      free(list->keyword);
      free(list->entry);
      return NULL;
   } /* endif */
}

void freeConfig(s_config *config)
{
   if (NULL != config) {
      config->start = freeNode(config->start);
      free(config);
      config = NULL;
   } /* endif */
}
