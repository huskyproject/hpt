#ifndef CONFIG_H
#define CONFIG_H

struct llist {
   char *keyword;
   char *entry;
   struct llist *next;
};

typedef struct llist s_llist;


struct config {
//   char     *configFilename;
//   FILE     *configFile;
   s_llist  *start;             // this is the beginning of the linked list
   s_llist  *next;              // this is the node where searching will be started
                                // when using NEXT
};

typedef struct config s_config;

enum configSearch {FIRST, NEXT};

typedef enum configSearch e_configSearch;

s_config *openConfig(char *fileName);
/*DOC
  Input:  fileName is the name of the config to read in.
  Output: openConfig returns a pointer to an s_config struct
  FZ:     openConfig reads the configfile into an linkedlist.
          Empty lines and lines starting with ';' are discarded.
          The first word of the line ("xxxx xxx" is one word) ist the keyword,
          the rest of the line is saved as entry.
*/

char     *getConfigEntry(s_config *config, char *key, e_configSearch search);
/*DOC
  Input:  config is a pointer to the config struct to be searched.
          it is searched for the key.
          search defines how the search operates.
  Output: openConfig returns a string or NULL
  FZ:     if search == FIRST the first entry belonging to key will be returned.
          if search == NEXT  the next entry belonging to key will be returned.
          if no key is found NULL is returned.
*/

int      getConfigEntryCount(s_config *config, char *key);
/*DOC
  Input:  config is a pointer to the config struct to be searched.
          it is searched for the key.
  Output: openConfig returns a int
  FZ:     the number of entrys with the keyword key is returned.
*/

void     freeConfig(s_config *config);
/*DOC
  Input:  config is the config which should be freed.
  Output: ./.
  FZ:     all memory use by config will be freed.
*/

#endif
