#include <stdio.h>

#include <config.h>

int main()
{
   s_config *config;

   config = openConfig("aha.cfg");
   if (NULL == config) return 1;      // something bad has happened.

   printf("first Address: %s\n", getConfigEntry(config, "Address", FIRST));
   printf("next  Address: %s\n", getConfigEntry(config, "Address", NEXT));
   printf("int          : %s\n", getConfigEntry(config, "int", FIRST));
   printf("dummy        : %s\n", getConfigEntry(config, "dummy", FIRST));

   freeConfig(config);

   return 0;
}
