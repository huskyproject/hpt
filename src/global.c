#include <global.h>

s_log     *log;
s_config  *config;

const int VER_MAJOR = 0;
const int VER_MINOR = 19;
char      versionStr[10];

s_addr    *addr;
UINT      addrCount;

s_link    *links;
UINT      linkCount;

s_route   *routes;
UINT      routeCount;

char      *inboundDir;
char      *inboundDirSec;
char      *outboundDir;

s_area    netArea;
s_area    dupeArea;
s_area    badArea;

s_area    *echoAreas;
UINT      echoAreaCount;

char      *configFile = NULL;
int       cmToss = 0;
int       cmScan = 0;



