#ifndef GLOBAL_H
#define GLOBAL_H

#include <log.h>
#include <config.h>
//#include <common.h>
#include <area.h>
#include <link.h>
#include <route.h>


extern s_log     *log;
extern s_config  *config;

// variables for config statements

extern s_addr    *addr;         // array of addr
extern UINT      addrCount;     // number of addr read

extern s_link    *links;        // array of links
extern UINT      linkCount;     // number of stored links

extern s_route   *routes;
extern UINT      routeCount;

extern char      *inboundDir;
extern char      *inboundDirSec;
extern char      *outboundDir;

extern s_area    netArea;
extern s_area    dupeArea;
extern s_area    badArea;

extern s_area    *echoAreas;
extern UINT      echoAreaCount;

// variables for commandline statements

extern char      *configFile;
extern int       cmToss;
extern int       cmScan;

#endif
