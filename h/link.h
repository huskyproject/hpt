#ifndef LINK_H
#define LINK_H

struct link {
   s_addr hisAka;
   s_addr ourAka;
   char   pwd[9];   // 8 byte passwort + \0
   char   *pktFile;
};

typedef struct link s_link;

#endif
