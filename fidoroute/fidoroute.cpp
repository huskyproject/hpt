// $Id$
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#if defined (__TSC__)
# pragma call(inline_max => 150)
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#if defined (__TSC__)
# include <alloc.h>
# include <dir.h>
# define EOLCHR "\n"
#elif defined (__WATCOMC__)
# include <malloc.h>
# include <direct.h>
# include <io.h>

# define fnsplit _splitpath
# define fnmerge _makepath

# define EOLCHR "\n"

# if defined (__OS2__)
#  define _OS2 1
# endif
#elif defined(__GNUC__)
//  #include <malloc.h>
# include <sys/param.h>         // for MAXPATHLEN
# include <dirent.h>
# include <unistd.h>
# include <glob.h>

# define strnicmp(x,y,z) strncasecmp(x,y,z)
# define stricmp(x,y) strcasecmp(x,y)
# define itoa(i,a,base) (sprintf(a,"%i",i),a)

# define EOLCHR "\n"
# define link linkd

#elif defined (__MSVC__)
# define EOLCHR "\n"
# define MAXDRIVE  3
# define fnsplit _splitpath
# define fnmerge _makepath
#endif

#define VERSION   "1.35"
#define CREATED   "%c %s routing for %d:%d/%d. Created by Hubroute generator "VERSION""EOLCHR"%c %45s%c"EOLCHR""
#ifdef _TARGET
# if defined (__GNUC__)
#  define TARGET "GNU/" _TARGET
# else
#  define TARGET _TARGET
# endif
#else /*defined (__GNUC__) */
# if defined(_OS2) || defined (__OS2__)
#  define TARGET "OS/2"
# elif defined (__NT__)
#  define TARGET "Win32"
# elif defined (__GNUC__)
#  define TARGET "GNU/Unix"
# else
#  define TARGET "DOS"
# endif
#endif

#ifdef boolean
# undef boolean
#endif

typedef unsigned short ushort;
typedef unsigned long ulong;
typedef unsigned short boolean;

struct nodeaddr
{
  ushort z, n, f;
  nodeaddr( ushort zz = 0, ushort nn = 0, ushort ff = 0 ):z( zz ), n( nn ), f( ff )
  {
  };
  boolean operator==( nodeaddr & a )
  {
    return z == a.z && n == a.n && f == a.f;
  };
  void CleanUp( void )
  {
    z = n = f = 0;
  }
};

struct listitem
{
  ushort idx;                   // uplink index in file
  ushort is_uplink;             // is first in route.raw
  nodeaddr addr;
};

struct link
{
  ushort flavor;
  nodeaddr addr;
};

struct CfgValue
{
  const char *Name;
  void *Value;
  ushort Pass;
    boolean( *LoadVal ) ( char *in, void *out );
};

static const char *ErrNoMemory = EOLCHR "Unable to allocate memory.";
static const char *ErrOpenCfg = EOLCHR "Unable to open config file.";
static const char *ErrNoFile = "Unable to open file.";
static const char *ErrOpenTmp = EOLCHR "Unable to open temp file.";
static const char *ErrOpenDest = EOLCHR "Unable to open dest file.";
static const char *ErrUnknownRouteType = EOLCHR "Unsupported route type.";
static const char *ErrUnknownMinType = EOLCHR "Illegal value of \"Minimized\".";
static const char *ErrQuoteString = "Illegal quoted string.";
static const char *ErrMissMainAddr = EOLCHR "Missing or illegal main address.";
static const char *ErrMissRouteType = EOLCHR "Missing \"RouteType\" keyword.";
static const char *ErrMissMinType = EOLCHR "Missing \"Minimize\" keyword. YES Accepted.";
static const char *ErrNoReplEnd = EOLCHR "Missing \"RouteEnd\" in dest file.";
static const char *ErrNoReplBeg = EOLCHR "Missing \"RouteBegin\" in dest file.";
static const char *ErrBadNdlType = "Bad \"HubRoute\" definition.";
static const char *ErrMissDirect =
  EOLCHR "%s is routed via us, but missing in \"Link\" definitions." EOLCHR
  " \'DefaultFlavor\' assumed.";
static const char *ErrReroute = EOLCHR "Re-routing for %s.";
static const char *ErrLoop = EOLCHR "RouteLoop detected for %s. Try to route by default";
static const char *WarnNoMin = EOLCHR "Unable to minimize tree - out of memory";

#define Error(s)   fprintf(stderr,"%s" EOLCHR,s)
#define ErrorS(s,str)   fprintf(stderr,s,str)
#define ErrorL(s)  fprintf(stderr, "%s %d: %s" EOLCHR, CfgFile, CfgLine, s)

#define true     1
#define false    0

#define ItemNum(arr) (sizeof(arr)/sizeof(arr[0]))

#define	MAXNODES	5000
#define	MAXWILD		2000
#define	MAXLINKS	1000
#define	MAXAKAS		50
#define	BUFFLEN		30000
#define	PATHLEN		100
#define	WILDVALUE	0xFFFF
#define	DEADLOCK_DEPTH	10
int MAX_ROUTE_LEN = 64;

enum
{
  DIRECT_FLAVOR = 1, CRASH_FLAVOR = 2, HOLD_FLAVOR = 4,
  NORMAL_FLAVOR = 16, FILE_FLAVOR = 32, NOARC_FLAVOR = 64
};

static ushort DefaultFlavor = HOLD_FLAVOR;

#if defined (__WATCOMC__)
# define MAXPATH 256
# define MAXDRIVE  3
# define MAXDIR  256
# define MAXFILE NAME_MAX
# define MAXEXT  NAME_MAX
#elif defined (__GNUC__)  || (__MSVC__)
# ifdef MAXPATHLEN
#  define MAXPATH MAXPATHLEN
# else
#  define MAXPATH 512
# endif
# define MAXDIR  MAXPATH
# define MAXFILE MAXPATH
# define MAXEXT  MAXPATH
#endif

#if defined(__GNUC__)
static char TempFile[MAXPATH];

#else
static char TempFile[MAXPATH];
static char OutDrv[MAXDRIVE];
#endif

#if !defined (__GNUC__)
static char OutDir[MAXDIR];
static char OutName[MAXFILE];
static char OutExt[MAXEXT];
#endif

#define	SQUISH		1
#define	ITRACK		2
#define	TMAIL		3
#define	BPACK		4
#define	IMBINK		5
#define	XMAIL		6
#define	IFMAIL		7
#define	BIP		8
#define	UNIMAIL		9
#define	QECHO		10
#define	FIDOGATE	11
#define	FTRACK		12
#define	HUSKY		13
static ushort RouteMode = 0;
static ushort MinMode = 0;
static ushort KillTransit = 0;

#if defined (__GNUC__)
glob_t globbuf;
#endif

static char *Buff;
static char *Prefix;
static nodeaddr PrevNode;
static nodeaddr *MyNode = NULL;
static nodeaddr UpNode( 0, 0, 0 );      // t-mail routing only
static link *Link;
static listitem *Node;
static listitem *WildNode;      // Wildcards in nodelist
static ushort nNodes = 0, nLinks = 0, nAKAs = 0, nWilds = 0;
static ushort level;            // 0 - node, 1 - net, 2 - zone, 3 - world
static time_t currtime;
static char *CfgFile;
static ushort CfgLine;
static char WriteTo[PATHLEN];
static FILE *NewRoute;
static FILE *OldRoute;

#define	Spit(s)	{ fputs(s, NewRoute); fputs(EOLCHR, NewRoute); }
static char RouteBegin[100];
static char RouteEnd[100];
static boolean StarWild, AddPoint, DefaultFromMe, FullAddr, FillRoute, WithSlash, TmailAddFor;
static char CmntSym = '#';

static ushort InMemory( nodeaddr addr )
{
  for( ushort i = 0; i < nNodes; i++ )
    if( Node[i].addr == addr )
      return i;
  return 0xFFFF;
}

static boolean IsMyNode( nodeaddr addr )
{
  int i;
  for( i = 0; i < nAKAs; i++ )
    if( MyNode[i] == addr )
      return true;
  return false;
}

static boolean DirectLink( ushort Idx )
{
  int i;
  for( i = 0; i < nLinks; i++ )
    if( Link[i].addr == Node[Idx].addr )
      return true;
  return false;
}

static boolean DirectLink( nodeaddr n )
{
  int i;
  for( i = 0; i < nLinks; i++ )
    if( Link[i].addr == n )
      return true;
  return false;
}

inline void skipws( char **p )
{
  while( **p == ' ' || **p == '\t' || **p == '\r' )
    ( *p )++;
}

static ushort getnum( char **p )
{
  int i = 0;
  while( isdigit( **p ) )
    i = i * 10 + ( *( ( *p )++ ) - '0' );
  return ( ushort ) i;
}

static nodeaddr ScanNode( char **p )
{
  nodeaddr addr = PrevNode;
  ushort tmp, mode;

#define START 1
#define SCAN  2
#define DONE  3
  skipws( p );
  mode = START;
  while( mode != DONE )
  {
    switch ( mode )
    {
    case START:
      if( strnicmp( *p, "World", 5 ) == 0 )
      {
        addr.z = addr.n = addr.f = WILDVALUE;
        PrevNode = *MyNode;     // _Main_ aka
        *p += 5;
        return addr;
      }
    case SCAN:
      skipws( p );
      if( strnicmp( *p, "All", 3 ) == 0 )
      {
        tmp = WILDVALUE;
        *p += 3;
      }
      else if( **p == '*' )
      {
        tmp = WILDVALUE;
        *p += 1;
      }
      else
        tmp = getnum( p );
      switch ( **p )
      {
      case ':':
        addr.z = tmp;
        mode = SCAN;
        ( *p )++;
        break;
      case '/':
        addr.n = tmp;
        mode = SCAN;
        ( *p )++;
        break;
      default:
        addr.f = tmp;
        mode = DONE;
      }
    }
  }
  PrevNode = addr;

  // Skip unnesessary tail such as point address etc.
  while( **p != ' ' && **p != '\t' && **p != '\r' && **p != '\n' && **p != '\0' )
    ( *p )++;
  return addr;

#undef START
#undef SCAN
#undef DONE
}

static ushort WriteNode( nodeaddr Node, char *out, short addrtype )
{
  char tmp[10];
  ushort wildlevel = 0;
  if( Node.f == WILDVALUE )
    wildlevel++;
  if( Node.n == WILDVALUE )
    wildlevel++;
  if( Node.z == WILDVALUE )
    wildlevel++;
  if( wildlevel == level || addrtype == 1 )
  {
    const char *Wild = ( StarWild ) ? "*" : "All";
    strcat( out, " " );
    if( Node.z == WILDVALUE && Node.n == WILDVALUE && Node.n == WILDVALUE )
      strcat( out, StarWild ? "*:*/*" : "World" );
    else
    {
      if( addrtype || FullAddr || Node.z != PrevNode.z )
      {
        strcat( out, itoa( Node.z, tmp, 10 ) );
        strcat( out, ":" );
      }
      if( addrtype || FullAddr || Node.n != PrevNode.n || Node.f == WILDVALUE )
      {
        strcat( out, Node.n != WILDVALUE ? itoa( Node.n, tmp, 10 ) : Wild );
        if( !WithSlash )
          strcat( out, "/" );
      }
      if( WithSlash )
        strcat( out, "/" );
      strcat( out, Node.f != WILDVALUE ? itoa( Node.f, tmp, 10 ) : Wild );
    }
    if( AddPoint && !addrtype )
      strcat( out, ".*" );
    if( DefaultFromMe )
      PrevNode = *MyNode;       // Main aka
    else
      PrevNode = Node;
  }
  return ( ushort ) strlen( out );
}

static char *StrNode( nodeaddr Node )
{
  static char buff[40];
  boolean tmp = FullAddr;
  buff[0] = '\0';
  FullAddr = true;
  buff[WriteNode( Node, buff, 1 )] = '\0';
  FullAddr = tmp;
  return buff;
}

static ushort TestCmpQuality( nodeaddr & S, nodeaddr & D )
{
  ushort Q = 0;
  if( ( D.z != WILDVALUE && S.z != D.z ) ||
      ( D.n != WILDVALUE && S.n != D.n ) || ( D.f != WILDVALUE && S.f != D.f ) )
    return 0;                   // Not match

  if( D.z == WILDVALUE )
    Q++;
  else
    Q += 2;

  if( D.n == WILDVALUE )
    Q += 10;
  else
    Q += 20;

  if( D.f == WILDVALUE )
    Q += 100;
  else
    Q += 200;                   // Who cares... :)

  return Q;
}

static void FixWildcard( void )
{
  ushort i;
  for( i = 0; i < nNodes; i++ )
  {
    // Fix wildcard such as All:5020/All to All:All/All etc.
    if( Node[i].addr.z == WILDVALUE )
      Node[i].addr.n = WILDVALUE;
    if( Node[i].addr.n == WILDVALUE )
      Node[i].addr.f = WILDVALUE;
    ushort MaxQuality, MaxQualityIdx, cmp;
    MaxQuality = 0;

    // Try to route unrouted items to nearest wildcard
    if( Node[i].idx == WILDVALUE && !DirectLink( i ) )  // not routed
    {
      ushort j;
      for( j = 0; j < nNodes; j++ )
        if( Node[j].idx != WILDVALUE )  // is routed
          if( ( cmp = TestCmpQuality( Node[i].addr, Node[j].addr ) ) > MaxQuality )
          {
            MaxQuality = cmp;
            MaxQualityIdx = j;
          }
      if( MaxQuality > 0 )      // found correct match
      {
        boolean deadlock = false;
        ushort idx = MaxQualityIdx;

        // Try to recognize route-loop such as 2:5020/50 <= 2:5020/All
        for( j = 0; j < DEADLOCK_DEPTH && !deadlock; j++ )
          if( i == idx )        // We catch the same node
            deadlock = true;

          else if( idx != WILDVALUE )   // Catch unrouted
            idx = Node[idx].idx;

          else                  // idx == WILDVALUE - unrouted (may be direct)
            break;
        if( !deadlock )
          Node[i].idx = MaxQualityIdx;
      }
    }
  }

  // Fixup my downlinks if they are undefined as Direct links
  for( i = 0; i < nNodes; i++ ) // Look for my downlinks
  {
    if( Node[i].idx != WILDVALUE && IsMyNode( Node[Node[i].idx].addr ) && !DirectLink( i ) )
    {
      Link[nLinks].addr = Node[i].addr;
      Link[nLinks].flavor = DefaultFlavor;
      nLinks++;
      ErrorS( ErrMissDirect, StrNode( Node[i].addr ) );
    }
  }

  // Make the tree one-leveled
  for( i = 0; i < nNodes; i++ )
  {
    if( Node[i].idx != WILDVALUE )      // routed
    {
      nodeaddr Orig = Node[i].addr;
      while( !( Node[Node[i].idx].idx == WILDVALUE ||
                ( DirectLink( Node[i].idx ) && Node[Node[i].idx].addr.f != 0xFFFF ) ) )
      {
        Node[i].idx = Node[Node[i].idx].idx;
        if( Node[Node[i].idx].addr == Orig )    // Loop detected
        {
          ErrorS( ErrLoop, StrNode( Node[Node[i].idx].addr ) );
          Node[Node[i].idx].idx = WILDVALUE;
          break;
        }
      }
    }
  }
}

static boolean IsWild( nodeaddr n )
{
  return ( n.z == WILDVALUE || n.n == WILDVALUE || n.f == WILDVALUE ) ? true : false;
}

int CmpWild( void const *l1, void const *l2 )
{
  if( ( ( listitem * ) l1 )->addr.z > ( ( listitem * ) l2 )->addr.z )
    return 1;

  else if( ( ( listitem * ) l1 )->addr.z < ( ( listitem * ) l2 )->addr.z )
    return -1;

  else if( ( ( listitem * ) l1 )->addr.n > ( ( listitem * ) l2 )->addr.n )
    return 1;

  else if( ( ( listitem * ) l1 )->addr.n < ( ( listitem * ) l2 )->addr.n )
    return -1;

  else if( ( ( listitem * ) l1 )->addr.f > ( ( listitem * ) l2 )->addr.f )
    return 1;

  else if( ( ( listitem * ) l1 )->addr.f < ( ( listitem * ) l2 )->addr.f )
    return -1;

  else
    return 0;
}

static void RemoveUnnecessary( void )
{
  ushort i, j;

  // Remove double-routed nodes if it's up-wild routed by the same way
  if( MinMode )
  {
    WildNode = ( listitem * ) calloc( MAXWILD, sizeof( listitem ) );
    if( WildNode != NULL )
    {
      for( i = 0; i < nNodes; i++ )
        if( IsWild( Node[i].addr ) )
          WildNode[nWilds++] = Node[i];
      qsort( WildNode, nWilds, sizeof( listitem ), CmpWild );
      for( i = 0; i < nNodes; i++ )
      {
        if( Node[i].idx != WILDVALUE )  // routed
        {
          for( j = 0; j < nWilds; j++ )
          {
            if( !( Node[i].addr == WildNode[j].addr ) &&
                TestCmpQuality( Node[i].addr, WildNode[j].addr ) > 0 )
            {
              if( Node[i].idx == WildNode[j].idx && !DirectLink( i ) )
                Node[i].idx = 0xFFFE;
              break;
            }
          }
        }
      }
      free( WildNode );
    }
    else
      Error( WarnNoMin );
  }
}

static const char *GetFlavor( link * pLink, const char *Flav[] )
{
  if( pLink->flavor & CRASH_FLAVOR )
    return Flav[0];

  else if( pLink->flavor & DIRECT_FLAVOR )
    return Flav[1];

  else if( pLink->flavor & HOLD_FLAVOR )
    return Flav[2];

  else
    return Flav[3];
}

const char *SqFlavors[] = {
  "Crash ", "Direct", "Hold  ", "Normal"
};

static void MakeSqPrefix( link * pLink, char *out )
{
  strcpy( out, "Route " );
  strcat( out, GetFlavor( pLink, SqFlavors ) );
  if( pLink->flavor & FILE_FLAVOR )
    strcat( out, " file" );
  else
    strcat( out, "     " );

  if( pLink->flavor & NOARC_FLAVOR )
    strcat( out, " NoArc" );
  else
    strcat( out, "      " );

  WriteNode( pLink->addr, out, 1 );
  strcat( out, " " );
}

static void PutDirects( ushort mask, ushort pattern, const char *Pfix )
{
  int i;
  PrevNode = *MyNode;           // Main aka
  strcpy( Buff, Pfix );
  strcpy( Prefix, Pfix );
  for( i = 0; i < nLinks; i++ )
  {
    if( ( Link[i].flavor & mask ) == pattern )
      if( WriteNode( Link[i].addr, Buff, 0 ) >= MAX_ROUTE_LEN )
      {
        Spit( Buff );           // Spit out
        strcpy( Buff, Prefix );
        PrevNode = *MyNode;     // Main aka
      }
  }
  if( strcmp( Buff, Prefix ) != 0 )
    Spit( Buff );
}

static void PutDownLinksGeneric( ushort UpIdx, ushort type,
                                 ushort( *wrtnode ) ( nodeaddr, char *, ushort ) )
{
  ushort i;
  for( i = 0; i < nNodes; i++ )
  {
    if( Node[i].idx == UpIdx && !DirectLink( i ) && !IsMyNode( Node[i].addr ) &&
        ( ( UpIdx != WILDVALUE && Node[i].idx != i ) ||
          ( UpIdx == WILDVALUE && Node[i].is_uplink ) ) )
    {
      if( wrtnode( Node[i].addr, Buff, type ) >= MAX_ROUTE_LEN )
      {
        if( UpNode.z != 0 )
        {
          wrtnode( UpNode, Buff, 1 );
          PrevNode = *MyNode;
        }
        Spit( Buff );           // Spit out
        strcpy( Buff, Prefix );
        if( UpIdx != WILDVALUE && UpNode.z == 0 )
          PrevNode = Node[UpIdx].addr;
      }
      if( FillRoute )           // Prevents duplication in 'Unrouted'
        Node[i].idx = 0;
      else
        PutDownLinksGeneric( i, type, wrtnode );
    }
  }
}

static void PutDownLinks( ushort UpIdx, ushort type )
{
  ushort i;
  for( i = 0; i < nNodes; i++ )
  {
    if( Node[i].idx == UpIdx && !DirectLink( i ) && !IsMyNode( Node[i].addr ) &&
        ( ( UpIdx != WILDVALUE && Node[i].idx != i ) ||
          ( UpIdx == WILDVALUE && Node[i].is_uplink ) ) )
    {
      if( WriteNode( Node[i].addr, Buff, type ) >= MAX_ROUTE_LEN )
      {
        if( UpNode.z != 0 )
        {
          WriteNode( UpNode, Buff, 1 );
          PrevNode = *MyNode;
        }
        Spit( Buff );           // Spit out
        strcpy( Buff, Prefix );
        if( UpIdx != WILDVALUE && UpNode.z == 0 )
          PrevNode = Node[UpIdx].addr;
      }

      if( FillRoute )           // Prevents duplication in 'Unrouted'
        Node[i].idx = 0;
      else
        PutDownLinks( i, type );
    }
  }
}

static const char *RouteType[] = {
  "Nodes", "Nets", "Zones", "Default"
};

static void DirectsSQ( void )
{
  PutDirects( CRASH_FLAVOR | NOARC_FLAVOR, CRASH_FLAVOR, "Send Crash  " );
  PutDirects( DIRECT_FLAVOR | NOARC_FLAVOR, DIRECT_FLAVOR, "Send Direct " );
  PutDirects( HOLD_FLAVOR | NOARC_FLAVOR, HOLD_FLAVOR, "Send Hold   " );
  PutDirects( NORMAL_FLAVOR | NOARC_FLAVOR, NORMAL_FLAVOR, "Send Normal " );
  PutDirects( CRASH_FLAVOR | NOARC_FLAVOR, CRASH_FLAVOR | NOARC_FLAVOR, "Send Crash  NoArc " );
  PutDirects( DIRECT_FLAVOR | NOARC_FLAVOR, DIRECT_FLAVOR | NOARC_FLAVOR, "Send Direct NoArc " );
  PutDirects( HOLD_FLAVOR | NOARC_FLAVOR, HOLD_FLAVOR | NOARC_FLAVOR, "Send Hold   NoArc " );
  PutDirects( NORMAL_FLAVOR | NOARC_FLAVOR, NORMAL_FLAVOR | NOARC_FLAVOR, "Send Normal NoArc " );
}

static void PutRoutingSq( void )
{
  StarWild = false;
  AddPoint = false;
  DefaultFromMe = false;
  FullAddr = false;
  FillRoute = false;
  WithSlash = false;
  fprintf( NewRoute, CREATED, ';', "Squish", MyNode->z, MyNode->n, MyNode->f,
           ';', ctime( &currtime ), ';' );
  Spit( "; *** Direct links" EOLCHR ";" );
  DirectsSQ(  );
  Spit( ";" EOLCHR "; *** Route" EOLCHR ";" );
  for( level = 0; level < 4; level++ )
  {
    fprintf( NewRoute, "; *** %s" EOLCHR "", RouteType[level] );
    if( level )
      DirectsSQ(  );
    for( ushort i = 0; i < nLinks; i++ )
    {
      MakeSqPrefix( Link + i, Prefix );
      strcpy( Buff, Prefix );
      PutDownLinks( InMemory( Link[i].addr ), 0 );
      if( strcmp( Buff, Prefix ) != 0 )
        Spit( Buff );           // Spit short but significant line
    }
  }
}


// Make Routing for ITrack
const char *ItrFlavors[] = {
  "Crash", "Dir  ", "Hold ", "     "
};

static void PutRoutingItr( void )
{
  StarWild = true;
  AddPoint = true;
  DefaultFromMe = false;
  FullAddr = true;
  FillRoute = false;
  WithSlash = false;
  fprintf( NewRoute, CREATED, ';', "iTrack", MyNode->z, MyNode->n, MyNode->f,
           ';', ctime( &currtime ), ';' );
  for( level = 0; level < 4; level++ )
  {
    int i;
    fprintf( NewRoute, "; *** %s" EOLCHR "", RouteType[level] );
    for( i = 0; i < nLinks; i++ )
    {
      strcpy( Prefix, ( char * ) GetFlavor( Link + i, ItrFlavors ) );
      WriteNode( Link[i].addr, Prefix, 1 );
      strcat( Prefix, "  " );
      strcpy( Buff, Prefix );
      WriteNode( Link[i].addr, Buff, 0 );
      PutDownLinks( InMemory( Link[i].addr ), 0 );
      if( strcmp( Buff, Prefix ) != 0 ) // We added any downlinks
        Spit( Buff );           // Spit short but significant line
    }
  }
}


// 北  Make Routing for T-mail
static void DirectsTmail( void )
{
  AddPoint = true;
  PrevNode = *MyNode;           // Main AKA
  PutDirects( CRASH_FLAVOR, CRASH_FLAVOR, "Direct " );
  PutDirects( DIRECT_FLAVOR, DIRECT_FLAVOR, "Direct " );
  PutDirects( NORMAL_FLAVOR, NORMAL_FLAVOR, "Direct " );
  PutDirects( HOLD_FLAVOR, HOLD_FLAVOR, "Direct " );
  AddPoint = false;
  PutDirects( CRASH_FLAVOR, CRASH_FLAVOR, "Priority " );
  PutDirects( HOLD_FLAVOR, HOLD_FLAVOR, "Hold " );
}

static void PutRoutingTmail( void )
{
  StarWild = true;
  AddPoint = false;
  DefaultFromMe = true;
  FullAddr = false;
  FillRoute = false;
  WithSlash = true;
  fprintf( NewRoute, CREATED, ';', "T-mail", MyNode->z, MyNode->n, MyNode->f,
           ';', ctime( &currtime ), ';' );
  Spit( "; *** Direct links" );
  DirectsTmail(  );
  for( level = 0; level < 4; level++ )
  {
    fprintf( NewRoute, "; *** %s" EOLCHR "", RouteType[level] );
    if( level )
      DirectsTmail(  );
    int i;
    for( i = 0; i < nLinks; i++ )
    {
      if( TmailAddFor )
        strcpy( Prefix, "Mail-For  " );
      else
        strcpy( Prefix, "Mail  " );
      strcpy( Buff, Prefix );
      UpNode = Link[i].addr;
      PutDownLinks( InMemory( Link[i].addr ), 0 );
      if( strcmp( Buff, Prefix ) != 0 )
      {
        WriteNode( UpNode, Buff, 1 );
        Spit( Buff );           // Spit short but significant line
      }
      // 'Files'
      if( Link[i].flavor & FILE_FLAVOR )
      {
        if( TmailAddFor )
          strcpy( Prefix, "Files-For " );
        else
          strcpy( Prefix, "Files " );
        strcpy( Buff, Prefix );
        UpNode = Link[i].addr;
        PutDownLinks( InMemory( Link[i].addr ), 0 );
        if( strcmp( Buff, Prefix ) != 0 )
        {
          WriteNode( UpNode, Buff, 1 );
          Spit( Buff );         // Spit short but significant line
        }
      }
    }
  }
}


// 北  Make Routing for BPACK
static void DirectsBpack( void )
{
  PrevNode = *MyNode;
  PutDirects( CRASH_FLAVOR, CRASH_FLAVOR, "Direct crash  " );
  PutDirects( DIRECT_FLAVOR, DIRECT_FLAVOR, "Direct direct " );
  PutDirects( NORMAL_FLAVOR, NORMAL_FLAVOR, "Direct        " );
  PutDirects( HOLD_FLAVOR, HOLD_FLAVOR, "Direct hold   " );
  PutDirects( NOARC_FLAVOR, NOARC_FLAVOR, "NoArcSend     " );
}

static void PutRoutingBpack( void )
{
  StarWild = true;
  AddPoint = false;
  DefaultFromMe = false;
  FullAddr = true;
  FillRoute = false;
  WithSlash = false;
  fprintf( NewRoute, CREATED, ';', "BPack", MyNode->z, MyNode->n, MyNode->f,
           ';', ctime( &currtime ), ';' );
  Spit( "; *** Direct links" );
  DirectsBpack(  );
  for( level = 0; level < 4; level++ )
  {
    fprintf( NewRoute, "; *** %s" EOLCHR "", RouteType[level] );
    if( level )
      DirectsBpack(  );
    int i;
    for( i = 0; i < nLinks; i++ )
    {
      strcpy( Prefix, "Route " );
      strcat( Prefix, GetFlavor( Link + i, SqFlavors ) );
      WriteNode( Link[i].addr, Prefix, 1 );
      strcat( Prefix, " " );
      strcpy( Buff, Prefix );
      PutDownLinks( InMemory( Link[i].addr ), 0 );
      if( strcmp( Buff, Prefix ) != 0 )
        Spit( Buff );           // Spit short but significant line
    }
  }
}


// 北  Make Routing for IMBINK
static void PutRoutingImb( void )
{
  StarWild = true;
  AddPoint = true;
  DefaultFromMe = false;
  FullAddr = false;
  FillRoute = false;
  WithSlash = false;
  CmntSym = '#';
  fprintf( NewRoute, CREATED, '#', "Imbink", MyNode->z, MyNode->n, MyNode->f,
           '#', ctime( &currtime ), '#' );
  PutDirects( FILE_FLAVOR, FILE_FLAVOR, "FSENDTO " );
  PutDirects( NOARC_FLAVOR, 0, "Compress ZIP " );
  for( level = 0; level < 4; level++ )
  {
    fprintf( NewRoute, "# *** %s" EOLCHR "", RouteType[level] );
    int i;
    for( i = 0; i < nLinks; i++ )
    {
      strcpy( Prefix, "Static " );
      strcat( Prefix, GetFlavor( Link + i, SqFlavors ) );
      WriteNode( Link[i].addr, Prefix, 1 );
      strcat( Prefix, "  " );
      strcpy( Buff, Prefix );
      WriteNode( Link[i].addr, Buff, 0 );
      PutDownLinks( InMemory( Link[i].addr ), 0 );
      if( strcmp( Buff, Prefix ) != 0 )
        Spit( Buff );           // Spit short but significant line
    }
  }
}


// 北  Make Routing for XMAIL
static void PutRoutingXmail( void )
{
  StarWild = false;
  AddPoint = false;
  DefaultFromMe = false;
  FullAddr = true;
  FillRoute = false;
  WithSlash = false;
  CmntSym = ';';
  fprintf( NewRoute, CREATED, ';', "Xmail", MyNode->z, MyNode->n, MyNode->f,
           ';', ctime( &currtime ), ';' );
  fprintf( NewRoute, "; *** Directs" EOLCHR "" );
  level = 0;
  int i;
  for( i = 0; i < nLinks; i++ )
  {
    Buff[0] = 0;
    WriteNode( Link[i].addr, Buff, 0 );
    if( Buff[0] )
      Spit( Buff + 1 );
  }
  for( level = 0; level < 4; level++ )
  {
    fprintf( NewRoute, "; *** %s" EOLCHR "", RouteType[level] );
    ushort i;
    if( level )
    {
      for( i = 0; i < nLinks; i++ )
      {
        Buff[0] = 0;
        WriteNode( Link[i].addr, Buff, 0 );
        if( Buff[0] )
          Spit( Buff + 1 );
      }
    }
    for( i = 0; i < nNodes; i++ )
    {
      Buff[0] = 0;
      if( Node[i].idx != WILDVALUE && Node[i].idx != ( WILDVALUE - 1 ) && !DirectLink( i ) )
      {
        WriteNode( Node[i].addr, Buff, 0 );
        if( Buff[0] )
        {
          strcat( Buff, " VIA " );
          WriteNode( Node[Node[i].idx].addr, Buff, 1 );
          strcat( Buff, " /NC" );
          Spit( Buff + 1 );
        }
      }
    }
  }
}


// 北  Make Routing for ifmail
static const char *GetIfFlavor( link * pLink )
{
  if( pLink->flavor & CRASH_FLAVOR )
    return "c";

  else if( pLink->flavor & DIRECT_FLAVOR )
    return "n";

  else if( pLink->flavor & HOLD_FLAVOR )
    return "h";

  else
    return "n";
}

static char *AddInt( char *where, ushort value )
{
  itoa( value, where, 10 );
  return ( where + strlen( where ) );
}

static boolean WriteIfNode( nodeaddr Node, char *out, ushort wmode )
{
  char *p = out + strlen( out );
  ushort wildlevel = 0;
  if( Node.f == WILDVALUE )
    wildlevel++;
  if( Node.n == WILDVALUE )
    wildlevel++;
  if( Node.z == WILDVALUE )
    wildlevel++;
  if( wildlevel == level || wmode )
  {
    if( Node.f != WILDVALUE )
    {
      *p++ = 'f';
      p = AddInt( p, Node.f );
      *p = '.';
      *( ++p ) = '\0';
    }
    if( Node.n != WILDVALUE )
    {
      *p++ = 'n';
      p = AddInt( p, Node.n );
      *p = '.';
      *( ++p ) = '\0';
    }
    if( Node.z != WILDVALUE )
    {
      *p++ = 'z';
      p = AddInt( p, Node.z );
      *p++ = '.';
    }
    strcpy( p, "fidonet.org" );
    return true;
  }
  else
    return false;
}

static void PutRoutingIfmail( void )
{
  StarWild = false;
  AddPoint = false;
  DefaultFromMe = false;
  FullAddr = true;
  FillRoute = false;
  WithSlash = false;
  CmntSym = '#';
  fprintf( NewRoute, CREATED, '#', "sendmail", MyNode->z, MyNode->n,
           MyNode->f, '#', ctime( &currtime ), '#' );
  for( level = 0; level < 4; level++ )
  {
    fprintf( NewRoute, "# *** %s" EOLCHR "", RouteType[level] );
    ushort i;
    for( i = 0; i < nNodes; i++ )
    {
      Buff[0] = 0;
      if( Node[i].idx != WILDVALUE &&   // routed
          Node[i].idx != ( WILDVALUE - 1 ) &&   // not joined with wildcard
          ( Node[Node[i].idx].idx != WILDVALUE &&
            Node[Node[i].idx].idx != WILDVALUE - 1 ||
            DirectLink( Node[i].idx ) ) && !IsMyNode( Node[Node[i].idx].addr ) || DirectLink( i ) )
      {
        strcpy( Buff, "." );
        if( WriteIfNode( Node[i].addr, Buff, 0 ) )
        {
          listitem Dest;
          strcat( Buff, "\tifmail-" );
          Dest = DirectLink( i ) ? Node[i] : Node[Node[i].idx];
          int j;
          for( j = 0; j < nLinks; j++ )
            if( Link[j].addr == Dest.addr )
              strcat( Buff, GetIfFlavor( Link + j ) );
          strcat( Buff, ":" );
          WriteIfNode( Dest.addr, Buff, 1 );
          if( !level )
            Spit( Buff + 1 );
          Spit( Buff );
        }
      }
    }
  }
}


// 北  Make Routing for BiP
const char *BipFlavors[] = {
  "Crash", "Dir  ", "Hold ", "Norm "
};

static void PutRoutingBip( void )
{
  StarWild = true;
  AddPoint = true;
  DefaultFromMe = true;
  FullAddr = false;
  FillRoute = false;
  WithSlash = false;
  fprintf( NewRoute, CREATED, ';', "BiP", MyNode->z, MyNode->n, MyNode->f,
           ';', ctime( &currtime ), ';' );
  for( level = 3; level != 0xFFFF; level-- )
  {
    fprintf( NewRoute, "; *** %s" EOLCHR "", RouteType[level] );
    int i;
    for( i = 0; i < nLinks; i++ )
    {
      strcpy( Prefix, "Route" );
      strcat( Prefix, ( char * ) GetFlavor( Link + i, BipFlavors ) );
      WriteNode( Link[i].addr, Prefix, 1 );
      strcat( Prefix, "  " );
      strcpy( Buff, Prefix );
      WriteNode( Link[i].addr, Buff, 0 );
      PutDownLinks( InMemory( Link[i].addr ), 0 );
      if( strcmp( Buff, Prefix ) != 0 )
        Spit( Buff );           // Spit short but significant line
      if( Link[i].flavor & FILE_FLAVOR )
      {
        strcpy( Prefix, "File" );
        strcat( Prefix, GetFlavor( Link + i, BipFlavors ) );
        WriteNode( Link[i].addr, Prefix, 1 );
        strcat( Prefix, "  " );
        strcpy( Buff, Prefix );
        WriteNode( Link[i].addr, Buff, 0 );
        PutDownLinks( InMemory( Link[i].addr ), 0 );
        if( strcmp( Buff, Prefix ) != 0 )
          Spit( Buff );         // Spit short but significant line
      }
    }
  }
}


// 北  Make Routing for Unimail
static void PutRoutingUnimail( void )
{
  StarWild = true;
  AddPoint = true;
  DefaultFromMe = false;
  FullAddr = true;
  FillRoute = false;
  WithSlash = false;
  fprintf( NewRoute, CREATED, ';', "Unimail", MyNode->z, MyNode->n, MyNode->f,
           ';', ctime( &currtime ), ';' );
  Spit( ";" EOLCHR "; *** Route" EOLCHR ";" );
  for( level = 0; level < 4; level++ )
  {
    fprintf( NewRoute, "; *** %s" EOLCHR "", RouteType[level] );
    int i;
    for( i = 0; i < nLinks; i++ )
    {
      strcpy( Prefix, "Route" );
      strcat( Prefix, GetFlavor( Link + i, SqFlavors ) );
      WriteNode( Link[i].addr, Prefix, 1 );
      strcpy( Buff, Prefix );
      WriteNode( Link[i].addr, Buff, 0 );
      PutDownLinks( InMemory( Link[i].addr ), 0 );
      if( strcmp( Buff, Prefix ) != 0 )
        Spit( Buff );           // Spit short but significant line
    }
  }
}


// 北  Make Routing for QECHO
ushort WriteNodeQecho( nodeaddr Node, char *out, ushort addrtype )
{
  char tmp[20];
  ushort wildlevel = 0;
  if( Node.f == WILDVALUE )
    wildlevel++;
  if( Node.n == WILDVALUE )
    wildlevel++;
  if( Node.z == WILDVALUE )
    wildlevel++;
  if( wildlevel == level || addrtype == 1 )
  {
    if( wildlevel == 3 )
    {
      strcat( out, "1: 2: 3: 4: 5: 6: 7:" );
    }
    else
    {
      strcat( out, " " );
      strcat( out, itoa( Node.z, tmp, 10 ) );
      strcat( out, ":" );
      if( wildlevel < 2 )
      {
        strcat( out, itoa( Node.n, tmp, 10 ) );
      }
      if( wildlevel < 1 )
      {
        strcat( out, "/" );
        strcat( out, itoa( Node.f, tmp, 10 ) );
      }
    }
  }
  return ushort( strlen( out ) );
}

static void PutRoutingQecho( void )
{
  StarWild = false;
  AddPoint = false;
  DefaultFromMe = false;
  FullAddr = true;
  FillRoute = false;
  WithSlash = false;
  CmntSym = '#';
  MAX_ROUTE_LEN = 100;
  fprintf( NewRoute, CREATED, '#', "QECHO", MyNode->z, MyNode->n, MyNode->f,
           '#', ctime( &currtime ), '#' );
  Spit( "#" EOLCHR "# *** Route" EOLCHR "#" );
  for( level = 0; level < 3; level++ )
  {
    fprintf( NewRoute, "# *** %s" EOLCHR "", RouteType[level] );
    int i;
    for( i = 0; i < nLinks; i++ )
    {
      sprintf( Prefix, "RouteVia\t%d:%d/%d@fidonet" EOLCHR "RouteFor\t",
               Link[i].addr.z, Link[i].addr.n, Link[i].addr.f );
      strcpy( Buff, Prefix );
      if( level == 0 )
      {
        WriteNodeQecho( Link[i].addr, Buff, 1 );
      }
      PutDownLinksGeneric( InMemory( Link[i].addr ), 0, WriteNodeQecho );
      if( strcmp( Buff, Prefix ) != 0 )
      {
        Spit( Buff );           // Spit non-empty line
      }
    }
  }
}


// 北  Make Routing for Fidogate
const char *FidogateFlavors[] = {
  "crash ", "direct", "hold  ", "normal"
};

static void MakeFidogatePrefix( link * pLink, char *out )
{
  strcpy( out, "route " );
  strcat( out, ( char * ) GetFlavor( pLink, FidogateFlavors ) );

  if( pLink->flavor & FILE_FLAVOR )
    strcat( out, " file" );
  else
    strcat( out, "     " );

  if( pLink->flavor & NOARC_FLAVOR )
    strcat( out, " noarc" );
  else
    strcat( out, "      " );

  WriteNode( pLink->addr, out, 1 );
  strcat( out, " " );
}

static void DirectsFidogate( void )
{
  PutDirects( CRASH_FLAVOR, CRASH_FLAVOR, "send crash  " );
  PutDirects( DIRECT_FLAVOR, DIRECT_FLAVOR, "send direct " );
  PutDirects( HOLD_FLAVOR, HOLD_FLAVOR, "send hold   " );
  PutDirects( NORMAL_FLAVOR, NORMAL_FLAVOR, "send normal " );
}

static void PutRoutingFidogate( void )
{
  StarWild = false;
  AddPoint = false;
  DefaultFromMe = false;
  FullAddr = true;
  FillRoute = false;
  WithSlash = false;
  CmntSym = '#';
  fprintf( NewRoute, CREATED, CmntSym, "Fidogate", MyNode->z, MyNode->n,
           MyNode->f, '#', ctime( &currtime ), '#' );
  Spit( "# *** Direct links" EOLCHR "#" );
  DirectsFidogate(  );
  Spit( "#" EOLCHR "# *** Route" EOLCHR "#" );
  for( level = 0; level < 4; level++ )
  {
    fprintf( NewRoute, "# *** %s" EOLCHR "", RouteType[level] );
    if( level )
      DirectsFidogate(  );
    for( ushort i = 0; i < nLinks; i++ )
    {
      MakeFidogatePrefix( Link + i, Prefix );
      strcpy( Buff, Prefix );
      PutDownLinks( InMemory( Link[i].addr ), 0 );
      if( strcmp( Buff, Prefix ) != 0 )
        Spit( Buff );           // Spit short but significant line
    }
  }
}

// 北  Make Routing for FTRACK
static int counter = 0;
ushort WriteNodeFtrack( nodeaddr Node, char *out, ushort addrtype )
{
  static const char *prefix = "Mask: * * * ";
  static const char *postfix = " * *";
  ushort wildlevel = 0;
  if( Node.f == WILDVALUE )
    wildlevel++;
  if( Node.n == WILDVALUE )
    wildlevel++;
  if( Node.z == WILDVALUE )
    wildlevel++;
  if( wildlevel == level || addrtype == 1 )
  {
    counter++;
    strcpy( out, prefix );
    if( level == 3 )
      strcat( out, "*" );
    else
      WriteNode( Node, out + strlen( prefix ), addrtype );
    strcat( out, postfix );
  }
  else if( wildlevel == 1 && addrtype == 0 && level == 0 )
  {
    strcpy( out, prefix );
    WriteNode( Node, out + strlen( prefix ), 1 );
    strcat( out, postfix );
  }
  return ushort( strlen( out ) );
}

static void PutRoutingFtrack( void )
{
  StarWild = true;
  AddPoint = true;
  DefaultFromMe = true;
  FullAddr = true;
  FillRoute = false;
  WithSlash = true;
  CmntSym = '\\';
  Prefix[0] = CmntSym;
  Prefix[1] = 0;
  nodeaddr tmpNode;
  MAX_ROUTE_LEN = 10;
  fprintf( NewRoute, CREATED, CmntSym, "Ftrack", MyNode->z, MyNode->n,
           MyNode->f, CmntSym, ctime( &currtime ), CmntSym );
  for( level = 0; level < 4; level++ )
  {
    counter = 0;
    fprintf( NewRoute, "%c *** %s" EOLCHR "", CmntSym, RouteType[level] );
    int i;
    for( i = 0; i < nLinks; i++ )
    {
      counter = 0;
      Buff[0] = 0;
      if( level == 0 )
      {
        WriteNodeFtrack( Link[i].addr, Buff, 0 );
        Spit( Buff );
        counter++;
        Buff[0] = 0;
      }
      PutDownLinksGeneric( InMemory( Link[i].addr ), 0, WriteNodeFtrack );
      if( counter )
      {
        sprintf( Buff, "Action: Route %s", GetFlavor( Link + i, SqFlavors ) );
        AddPoint = false;
        tmpNode = Link[i].addr;
        if( DirectLink( tmpNode ) && MyNode->z == tmpNode.z && MyNode->n == tmpNode.n
            && tmpNode.f == WILDVALUE )
        {
          strcat( Buff, "%.0" );
        }
        else
        {
          WriteNode( Link[i].addr, Buff, 1 );
        }
        AddPoint = true;
        strcat( Buff, "\n\\" );
        Spit( Buff );
      }
    }
  }
}

const char *HuskyFlavors[] = {
  "crash", "direct", "hold", "normal"
};

// 北  Make Routing for HPT
static void PutRoutingHusky( void )
{
  StarWild = true;
  AddPoint = false;
  DefaultFromMe = false;
  FullAddr = true;
  FillRoute = false;
  WithSlash = false;
  CmntSym = '#';
  fprintf( NewRoute, CREATED, '#', "Husky", MyNode->z, MyNode->n, MyNode->f,
           '#', ctime( &currtime ), '#' );
  for( level = 0; level < 4; level++ )
  {
    fprintf( NewRoute, "# *** %s" EOLCHR "", RouteType[level] );
    int i;
    for( i = 0; i < nLinks; i++ )
    {
      strcpy( Prefix, "route " );
      strcat( Prefix, ( char * ) GetFlavor( Link + i, HuskyFlavors ) );
      WriteNode( Link[i].addr, Prefix, 1 );
      strcpy( Buff, Prefix );
      WriteNode( Link[i].addr, Buff, 0 );
      PutDownLinks( InMemory( Link[i].addr ), 0 );
      if( strcmp( Buff, Prefix ) != 0 )
        Spit( Buff );
    }
  }
}

//-----------------------------------------------------------------
static void PutUnRouted( void )
{
  FillRoute = true;
  FullAddr = true;
  fprintf( NewRoute,
           "%c" EOLCHR "%c !!! Undefined !!!" EOLCHR "%c ----------------"
           EOLCHR "", CmntSym, CmntSym, CmntSym );
  level = 0;
  Prefix[0] = CmntSym;
  Prefix[1] = 0;
  strcat( Prefix, " >>> " );
  strcpy( Buff, Prefix );
  PutDownLinks( WILDVALUE, 0 );
  if( strcmp( Buff, Prefix ) != 0 )
    Spit( Buff );               // Spit short but significant line
}


// 北  Config parser
static boolean LoadAddress( char *p, void * )
{
  MyNode[nAKAs++] = ScanNode( &p );
  return true;
}

static boolean GetRouteType( char *p, void * )
{
  if( strnicmp( p, "squish", 6 ) == 0 )
    RouteMode = SQUISH;

  else if( strnicmp( p, "itrack", 6 ) == 0 )
    RouteMode = ITRACK;

  else if( strnicmp( p, "tmail", 5 ) == 0 )
  {
    RouteMode = TMAIL;
    if( ( strnicmp( p, "tmailn", 6 ) == 0 ) )
      TmailAddFor = true;
    else
      TmailAddFor = false;
  }

  else if( strnicmp( p, "bpack", 5 ) == 0 )
    RouteMode = BPACK;

  else if( strnicmp( p, "imbink", 6 ) == 0 )
    RouteMode = IMBINK;

  else if( strnicmp( p, "xmail", 5 ) == 0 )
    RouteMode = XMAIL;

  else if( strnicmp( p, "ifmail", 6 ) == 0 )
    RouteMode = IFMAIL;

  else if( strnicmp( p, "bip", 3 ) == 0 )
    RouteMode = BIP;

  else if( strnicmp( p, "unimail", 7 ) == 0 )
    RouteMode = UNIMAIL;

  else if( strnicmp( p, "qecho", 5 ) == 0 )
    RouteMode = QECHO;

  else if( strnicmp( p, "fidogate", 8 ) == 0 )
    RouteMode = FIDOGATE;

  else if( strnicmp( p, "ftrack", 6 ) == 0 )
    RouteMode = FTRACK;

  else if( strnicmp( p, "husky", 5 ) == 0 )
    RouteMode = HUSKY;

  else
  {
    ErrorL( ErrUnknownRouteType );
    return false;
  }
  return true;
}

static boolean GetBoolean( char *p, void *target )
{
  if( strnicmp( p, "yes", 3 ) == 0 || strnicmp( p, "on", 2 ) == 0 || strnicmp( p, "1", 1 ) == 0 )
    *( ushort * ) target = 1;

  else if( strnicmp( p, "no", 2 ) == 0 || strnicmp( p, "off", 3 ) == 0
           || strnicmp( p, "0", 1 ) == 0 )
    *( ushort * ) target = 0;

  else
  {
    ErrorL( ErrUnknownMinType );
    return false;
  }
  return true;
}

static boolean GetFile( char *p, void *Name )
{
  char *p1 = ( char * ) Name;
  while( !isspace( *p ) )
    *( p1++ ) = *( p++ );
  *p1 = 0;
  return true;
}

static boolean GetQuotedString( char *p, void *str )
{
  char *p1 = ( char * ) str;
  if( *p == '\"' )
  {
    p++;
    while( *p != '\"' )
    {
      if( *p == '\n' || *p == '\0' )
      {
        ErrorL( ErrQuoteString );
        return false;
      }
      else
        *( p1++ ) = *( p++ );
    }
    *p1 = 0;
  }
  return true;
}

static boolean GetDestFile( char *p, void *Name )
{
  GetFile( p, Name );
  if( ( OldRoute = fopen( ( char * ) Name, "rt" ) ) == NULL )
  {
    Error( ErrOpenDest );
    return false;
  }

  if( TempFile[0] == '\0' )
  {
#if !defined(__GNUC__)
    fnsplit( ( char * ) Name, OutDrv, OutDir, OutName, OutExt );
    fnmerge( TempFile, OutDrv, OutDir, "MK$ROUTE", "$$$" );
#else
    strcpy( TempFile, ( char * ) Name );
    strcat( TempFile, ".$$$" );
#endif
  }

  if( ( NewRoute = fopen( TempFile, "wt" ) ) == NULL )
  {
//  Error(ErrOpenTmp);
    ErrorS( "Unable to open temp file \"%s\"", TempFile );
    return false;
  }
  boolean ReplaceArea = false;
  size_t beglen = strlen( RouteBegin );
  size_t endlen = strlen( RouteEnd );
  while( fgets( Buff, BUFFLEN - 1, OldRoute ) )
  {
    if( !ReplaceArea )
      fputs( Buff, NewRoute );
    if( strncmp( Buff, RouteBegin, beglen ) == 0 )
      ReplaceArea = true;
    if( ReplaceArea && ( strncmp( Buff, RouteEnd, endlen ) == 0 ) )
      return true;
  }
  Error( ReplaceArea ? ErrNoReplEnd : ErrNoReplBeg );
  fclose( OldRoute );
  fclose( NewRoute );
  unlink( TempFile );
  return false;
}

static boolean GetFlavor( char *p, void *mask )
{
  while( *p != '\n' && *p != '\0' && *p != ';' )
  {
    if( tolower( *p ) == 'd' )
      *( ushort * ) mask |= DIRECT_FLAVOR;

    else if( tolower( *p ) == 'c' )
      *( ushort * ) mask |= CRASH_FLAVOR;

    else if( tolower( *p ) == 'h' )
      *( ushort * ) mask |= HOLD_FLAVOR;

    else if( tolower( *p ) == 'n' )
      *( ushort * ) mask |= NORMAL_FLAVOR;

    else if( tolower( *p ) == 'f' )
      *( ushort * ) mask |= FILE_FLAVOR;

    else if( tolower( *p ) == 'a' )
      *( ushort * ) mask |= NOARC_FLAVOR;
    p++;
  }
  if( ( *( ushort * ) mask & ( DIRECT_FLAVOR | CRASH_FLAVOR | HOLD_FLAVOR ) ) == 0 )
    *( ushort * ) mask |= NORMAL_FLAVOR;
  return true;
}

static boolean GetLink( char *p, void * )
{
  memset( Link + nLinks, 0, sizeof( Link[0] ) );
  Link[nLinks].addr = ScanNode( &p );
  GetFlavor( p, &Link[nLinks].flavor );
  if( InMemory( Link[nLinks].addr ) == WILDVALUE )      // Not in Node[]
  {
    Node[nNodes].addr = Link[nLinks].addr;
    Node[nNodes++].idx = WILDVALUE;
  }
  nLinks++;
  return true;
}

static ushort StoreUplink( nodeaddr tmpNode )
{
  ushort Uplink = InMemory( tmpNode );
  if( Uplink == WILDVALUE )     // Not in memory yet
  {
    Uplink = nNodes;
    Node[nNodes].addr = tmpNode;
    Node[nNodes].is_uplink = true;
    Node[nNodes++].idx = WILDVALUE;
  }
  return Uplink;
}

static void StoreDownLink( ushort Uplink, nodeaddr tmpNode )
{
  if( !IsMyNode( tmpNode ) )
  {
    ushort Downlink = InMemory( tmpNode );
    if( !( Downlink == Uplink ) )
    {
      if( Downlink == WILDVALUE )       // New node
      {
        Downlink = nNodes;
        Node[nNodes].addr = tmpNode;
        Node[nNodes++].idx = Uplink;
      }
      else
      {
        if( Node[Downlink].idx != WILDVALUE &&  // Already routed
            Node[Downlink].idx != Uplink )      // differently
        {
          ErrorS( ErrReroute, StrNode( tmpNode ) );
        }
        Node[Downlink].idx = Uplink;
      }
      Node[Downlink].is_uplink = false;
    }
  }
}

static boolean GetRouteStr( char *p, void * )
{
  boolean ViaRoute;
  skipws( &p );
  if( !( *p == ';' || *p == '\n' || *p == '\0' ) )
  {
    PrevNode = *MyNode;         // Main AKA
    if( *p == '>' )             // 'via'-routing
    {
      p++;
      skipws( &p );
      ViaRoute = true;
    }
    else
      ViaRoute = false;
    nodeaddr tmpNode = ScanNode( &p );
    if( ViaRoute )
    {
      if( IsMyNode( tmpNode ) )
      {
        tmpNode = ScanNode( &p );       // skip myself
        StoreDownLink( StoreUplink( MyNode[0] ), tmpNode );
      }
      else if( KillTransit )
      {
        ScanNode( &p );         // skip transit node
      }
    }
    ushort Uplink = StoreUplink( tmpNode );
    while( *p != '\n' && *p != '\0' && *p != ';' )
    {
      tmpNode = ScanNode( &p );
      StoreDownLink( Uplink, tmpNode );
      skipws( &p );
    }
  }
  return true;
}

static boolean GetRouteFile( char *p, void * )
{
  char Name[100];
  GetFile( p, Name );
  FILE *nodes;
  if( ( nodes = fopen( Name, "rt" ) ) != NULL )
  {
    fprintf( stderr, "" EOLCHR "Scanning route file %s...", Name );
    while( fgets( Buff, BUFFLEN, nodes ) )
      GetRouteStr( Buff, NULL );
    fclose( nodes );
    return true;
  }
  else
  {
    ErrorL( ErrNoFile );
    return false;
  }
}

static boolean GetTrustStr( char *p, void * )
{
  if( !( *p == ';' || *p == '\n' || *p == '\0' ) )
  {
    PrevNode = *MyNode;         // Main AKA
    nodeaddr tmpNode = ScanNode( &p );  // scan network
    while( *p != '\n' && *p != '\0' && *p != ';' )
    {
      nodeaddr TrustedNode = ScanNode( &p );
      if( DirectLink( TrustedNode ) )
      {
        ushort idx = StoreUplink( TrustedNode );
        StoreDownLink( idx, tmpNode );
      }
      skipws( &p );
    }
  }
  return true;
}

static boolean GetTrustFile( char *p, void * )
{
  char Name[100];
  GetFile( p, Name );
  FILE *nodes;
  if( ( nodes = fopen( Name, "rt" ) ) != NULL )
  {
    fprintf( stderr, "" EOLCHR "Scanning route file %s...", Name );
    while( fgets( Buff, BUFFLEN, nodes ) )
      GetTrustStr( Buff, NULL );
    fclose( nodes );
    return true;
  }
  else
  {
    ErrorL( ErrNoFile );
    return false;
  }
}

const char *Dash = "-/|\\";
static ushort DashCnt = 0;

static void DrawDash( void )
{
  putc( Dash[DashCnt++], stderr );
  putc( '\b', stderr );
  DashCnt &= 3;
}

static boolean GetHubRoute( char *p, void * )
{
  char Name[100];
  FILE *ndl;
  strcpy( Name, strtok( p, " \t" ) );

#if !defined(__GNUC__)
  fnsplit( Name, OutDrv, OutDir, OutName, OutExt );
#endif

  if( strchr( Name, '?' ) || strchr( Name, '*' ) )
  {
    short maxext = ( -1 );

#if defined (__TSC__)
    short ext;
    int rc;
    ffblk ff;
    for( rc = findfirst( Name, &ff, 0 ); rc != ( -1 ); rc = findnext( &ff ) )
    {
      char bb[MAXFILE];
      strcpy( bb, ff.ff_name );
      *( strrchr( bb, '.' ) ) = '\0';
      char *p1 = bb;
      char *p2 = bb + strlen( bb ) + 1;
      ext = atoi( p2 );
      if( ext > maxext )
      {
        maxext = ext;
        strcpy( OutName, p1 );
        strcpy( OutExt, p2 );
      }
    }

#elif defined (__WATCOMC__)
    short ext;
    DIR *ff;
    if( ( ff = opendir( Name ) ) != 0 )
    {
      while( readdir( ff ) != NULL )
      {
        char bb[MAXFILE];
        strcpy( bb, ff->d_name );
        *( strrchr( bb, '.' ) ) = '\0';
        char *p1 = bb;
        char *p2 = bb + strlen( bb ) + 1;
        ext = ( short ) atoi( p2 );
        if( ext > maxext )
        {
          maxext = ext;
          strcpy( OutName, p1 );
          strcpy( OutExt, p2 );
        }
      }
      closedir( ff );
    }
#endif

#if defined (__GNUC__)
    if( !glob( Name, GLOB_ERR, NULL, &globbuf ) )
      maxext = 0;
#endif

    if( maxext > ( -1 ) )       // found!
#if !defined(__GNUC__)
      fnmerge( Name, OutDrv, OutDir, OutName, OutExt );
#else
    {
      strcpy( Name, globbuf.gl_pathv[globbuf.gl_pathc - 1] );
      globfree( &globbuf );
    }
#endif
    else
    {
      ErrorL( ErrNoFile );
      return false;
    }
  }
  if( ( ndl = fopen( Name, "rt" ) ) == NULL )
  {
    ErrorL( ErrNoFile );
    return false;
  }
  else
  {
    setvbuf( ndl, NULL, _IOFBF, 0x8000 );       // Max buffering for speed
    char *p1 = strtok( NULL, " \t" );   // possible ndl type
    if( strlen( p1 ) != 1 )
    {
      ErrorL( ErrBadNdlType );
      fclose( ndl );
      return false;
    }
    else
    {
      ushort level, found = 0, z, n, f, Uplink;
      switch ( toupper( *p1 ) )
      {
      case 'Z':
        level = 0;
        break;
      case 'R':
      case 'N':
        level = 1;
        found = 1;
        break;
      default:
        ErrorL( ErrBadNdlType );
        fclose( ndl );
        return false;
      }
      p1 = strtok( NULL, " \t" );
      if( p1 == NULL )
      {
        ErrorL( ErrBadNdlType );
        fclose( ndl );
        return false;
      }
      ushort mz = ( ushort ) atoi( p1 );
      p1 = strtok( NULL, " \t" );
      if( p1 == NULL )
      {
        ErrorL( ErrBadNdlType );
        fclose( ndl );
        return false;
      }
      ushort mn = ( ushort ) atoi( p1 );
      fprintf( stderr, "" EOLCHR "Scanning nodelist %s for %d:%d hubroute...", Name, mz, mn );
      ushort count = 0;
      ushort step = level ? 20 : 1000;
      while( fgets( Buff, BUFFLEN, ndl ) != NULL )
      {
        if( ++count > step )
        {
          DrawDash(  );
          count = 0;
        }
        if( Buff[0] != ';' )
        {
          if( level == 0 && strnicmp( Buff, "zone", 4 ) == 0 )
          {
            found = 0;
            if( ( z = ( ushort ) atoi( Buff + 5 ) ) == mz )
              found |= 0x01;
          }
          else if( ( found & 0x01 ) && strnicmp( Buff, "region", 6 ) == 0 )
          {
            found &= 0x01;
            if( ( n = ( ushort ) atoi( Buff + 7 ) ) == mn )
              found |= 0x02;
          }
          else if( ( found & 0x01 ) && strnicmp( Buff, "host", 4 ) == 0 )
          {
            found &= 0x01;
            if( ( n = ( ushort ) atoi( Buff + 5 ) ) == mn )
              found |= 0x02;
          }
          else if( ( found & 0x3 ) == 3 && strnicmp( Buff, "hub", 3 ) == 0 )
          {
            found &= 0x03;
            f = ( ushort ) atoi( Buff + 4 );
            found |= 0x04;
          }
          else if( ( found & 0x03 ) == 3 )
          {
            found |= 0x08;
            if( strnicmp( Buff, "pvt", 3 ) == 0 )
              f = ( ushort ) atoi( Buff + 4 );
            else if( ( strnicmp( Buff, "hold", 4 ) == 0 ) || ( strnicmp( Buff, "down", 4 ) == 0 ) )
              f = ( ushort ) atoi( Buff + 5 );
            else if( Buff[0] == ',' )
              f = ( ushort ) atoi( Buff + 1 );
            else
            {
              found &= 7;
              continue;
            }
          }
          if( found == 3 )      // host routing
            Uplink = StoreUplink( nodeaddr( level ? mz : z, n, 0 ) );
          else if( found == 7 ) // hub routing
            Uplink = StoreUplink( nodeaddr( level ? mz : z, n, f ) );
          else if( found >= 0x0B )      // node
            StoreDownLink( Uplink, nodeaddr( level ? mz : z, n, f ) );
        }
      }
    }
  }
  fclose( ndl );
  return true;
}


#define CFG_PASSES 6
static CfgValue CfgTab[] = {
  {"Address", NULL, 1, LoadAddress}
  ,
  {"Hubroute", NULL, 3, GetHubRoute}
  ,
  {"RouteFile", NULL, 3, GetRouteFile}
  ,
  {"TrustFile", NULL, 4, GetTrustFile}
  ,
  {"RouteType", &RouteMode, 1, GetRouteType}
  ,
  {"WriteTo", WriteTo, 2, GetDestFile}
  ,
  {"Minimize", &MinMode, 1, GetBoolean}
  ,
  {"KillTransit", &KillTransit, 1, GetBoolean}
  ,
  {"DefaultFlavor", &DefaultFlavor, 2, GetFlavor}
  ,
  {"DefaultRoute", NULL, 5, GetRouteStr}
  ,
  {"Link", NULL, 2, GetLink}
  ,
  {"RouteBegin", RouteBegin, 1, GetQuotedString}
  ,
  {"RouteEnd", RouteEnd, 1, GetQuotedString}
  ,
  {"TempFile", TempFile, 1, GetFile}
};

static boolean PassOK( ushort Pass )
{
  switch ( Pass )
  {
  case 0:
    break;
  case 1:
    // Existing main address
    if( MyNode->z == 0 || MyNode->n == 0 )
    {
      Error( ErrMissMainAddr );
      return false;
    }
    // Existing RouteType keyword
    if( !RouteMode )
    {
      Error( ErrMissRouteType );
      return false;
    }
    // Existing "Minimize"
    if( MinMode == 2 )
      Error( ErrMissMinType );
    break;
  case 2:
  case 3:
  case 4:
    break;
  case 5:
    fprintf( stderr, EOLCHR "Adjusting routing..." );
    FixWildcard(  );
    RemoveUnnecessary(  );
    break;
  }
  return true;
}

static boolean LoadConfig( void )
{
  FILE *cfg;
  boolean KeyWordFailed;
  if( ( cfg = fopen( CfgFile, "rt" ) ) != 0 )
  {
    char tmp[50];
    fprintf( stderr, "" EOLCHR "Scanning config file... " );
    ushort i;
    for( i = 0; i < CFG_PASSES; i++ )
    {
      CfgLine = 0;
      KeyWordFailed = false;
      while( fgets( Buff, BUFFLEN - 1, cfg ) )
      {
        CfgLine++;
        char *p = Buff;
        skipws( &p );
        if( *p == '#' || *p == ';' || *p == '\n' || *p == '\0' )
          continue;             // skip blank line or comment
        char *p1 = tmp;
        while( !isspace( *p ) )
          *( p1++ ) = *( p++ );
        *p1 = 0;
        unsigned int j;
        for( j = 0; j < ItemNum( CfgTab ); j++ )
        {
          if( CfgTab[j].Pass == i && stricmp( CfgTab[j].Name, tmp ) == 0 )
          {
            skipws( &p );
            KeyWordFailed |= !CfgTab[j].LoadVal( p, CfgTab[j].Value );
          }
        }
      }
      if( KeyWordFailed || !PassOK( i ) )
        return false;
      rewind( cfg );
    }
    return true;
  }
  else
    Error( ErrOpenCfg );
  return false;
}

int main( int argc, char **argv )
{
  char REVISION[] =  "$Revision$";
  REVISION[strlen(REVISION)-1]=0;
  if( strlen(REVISION) > 10 )
    strcpy(REVISION,REVISION+10);
  else
    REVISION[0]=0;
  fprintf( stderr,
           "Hubroute generator v." VERSION "(" TARGET ")%s%s" EOLCHR
           "Copyright (c) 1994-2003 Yuri Safronov 2:5020/204" EOLCHR
           "Copyright (c) 2009-2010 Husky Project development team" EOLCHR,
           REVISION[0]?"rev.":"", REVISION );
  if( argc > 1 )
  {
    if( !stricmp( argv[1], "--help" ) || !stricmp( argv[1], "-h" ) || !stricmp( argv[1], "/h" ) )
    {
      fprintf( stderr, "" EOLCHR "Usage: fidoroute [config.file]" EOLCHR "" );
      return 0;
    }
  }
  PrevNode.CleanUp(  );

  // Allocate buffers
  Buff = ( char * ) malloc( BUFFLEN );
  Prefix = ( char * ) malloc( 500 );
  Node = ( listitem * ) calloc( MAXNODES, sizeof( listitem ) );
  Link = ( link * ) calloc( MAXLINKS, sizeof( link ) );
  CfgFile = ( char * ) calloc( 1, PATHLEN );
  MyNode = ( nodeaddr * ) calloc( MAXAKAS, sizeof( nodeaddr ) );
  if( Buff == NULL || Prefix == NULL || Node == NULL || Link == NULL
      || CfgFile == NULL || MyNode == NULL )
  {
    Error( ErrNoMemory );
    return 2;
  }
  else
  {
    nNodes = 0;
    nLinks = 0;
    TempFile[0] = '\0';
    if( argc == 1 )
#if defined(__GNUC__)
      strcpy( CfgFile, "fidoroute.conf" );
#else
      strcpy( CfgFile, "fidoroute.cfg" );
#endif
    else
      strcpy( CfgFile, argv[1] );
    if( LoadConfig(  ) )
    {
      fprintf( stderr, "" EOLCHR "Writing routing... " );
      time( &currtime );
      switch ( RouteMode )
      {
      case SQUISH:
        PutRoutingSq(  );
        break;
      case ITRACK:
        PutRoutingItr(  );
        break;
      case TMAIL:
        PutRoutingTmail(  );
        break;
      case BPACK:
        PutRoutingBpack(  );
        break;
      case IMBINK:
        PutRoutingImb(  );
        break;
      case XMAIL:
        PutRoutingXmail(  );
        break;
      case IFMAIL:
        PutRoutingIfmail(  );
        break;
      case BIP:
        PutRoutingBip(  );
        break;
      case UNIMAIL:
        PutRoutingUnimail(  );
        break;
      case QECHO:
        PutRoutingQecho(  );
        break;
      case FIDOGATE:
        PutRoutingFidogate(  );
        break;
      case FTRACK:
        PutRoutingFtrack(  );
        break;
      case HUSKY:
        PutRoutingHusky(  );
        break;
      }
      PutUnRouted(  );
      Spit( RouteEnd );
      while( fgets( Buff, BUFFLEN - 1, OldRoute ) )
        fputs( Buff, NewRoute );
      fclose( OldRoute );
      fclose( NewRoute );
      unlink( WriteTo );
      rename( TempFile, WriteTo );
      fprintf( stderr, "" EOLCHR "Done - %d rules for %d links." EOLCHR "", nNodes, nLinks );
      return 0;
    }
    else
      return 1;
  }
}
