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
#ifndef _FCOMMON_H
#define _FCOMMON_H

#ifdef __NT__
#include <fidoconf/typesize.h>
#endif
#include <stdio.h>
#include <fidoconf/fidoconf.h>


enum prio {CRASH, HOLD, NORMAL, DIRECT, IMMEDIATE};
enum type {PKT, REQUEST, FLOFILE};
typedef enum prio e_prio;
typedef enum type e_type;

/* common functions */
void writeDupeFiles(void);

void exit_hpt(char *logstr, int print);
/*DOC
  exit to shell with errorlevel 1.
  print logstr to log file
  print logstr to stderr if print!=0
  closed log file, removed lockfile, disposed config
*/

e_prio cvtFlavour2Prio(e_flavour flavour);
/*DOC
  Input:  a fidoconfig flavour
  Output: a hpt prio
  FZ:     obvious
*/

void addAnotherPktFile(s_link *link, char *filename);
/*DOC
  Input:  a pointer to a link structure, a pointer to a filename
  FZ:     Adds the string pointed to by filename to the list off additional
          pktfiles for the specified link. No checks are performed. The
          string is duplicated internally.
*/
  
int   createTempPktFileName(s_link *link);
/*DOC
  Input:  a pointer to a link structure
  Output: 0 is returned if a filename and a packedfilename could be created.
          1 else
  FZ:     createTempPktFile tries to compose a new, not used pktfilename.
          It takes the least 24bit of the actual time. The last 2 Bytes
          area filled with a counter. So you can get up to 256 different files
          in a second and have the same timestamp only every 291 days.
          The pktFileName and the packFileName are stored in the link
          structure
*/

int    createDirectoryTree(const char *pathName);
/*DOC
  Input:  a pointer to a \0 terminated string
  Output: 0 if successfull, 1 else
  FZ:     pathName is a correct directory name
          createDirectoryTree creates the directory and all parental directories
          if they do not exist.
*/
  
int    createOutboundFileName(s_link *link, e_prio prio, e_type typ);
/*DOC
  Input:  link is the link whose OutboundFileName should be created.
          prio is some kind of CRASH, HOLD, NORMAL, DIRECT, IMMEDIATE
          typ is some kind of PKT, REQUEST, FLOFILE
  Output: a pointer to a char is returned.
  FZ:     1 is returned if link is busy
          0 else
          */

#if defined (__TURBOC__) || defined(__IBMC__) || defined(__WATCOMC__)
 int truncate(const char *fileName, long length);
 /*DOC
   Truncates the file at given position
 */
 int fTruncate( int fd, long length );
 /*DOC
   Truncates the file at given position
 */
#endif

#if (defined ( __WATCOMC__ ) || defined ( __MINGW32__ )) && defined ( __NT__ )
int __stdcall SetConsoleTitleA( const char* lpConsoleTitle );
#ifdef __MINGW32__
long __stdcall GetConsoleTitleA( const char*, long );
#endif
#endif

#if defined (__EMX__)
#include <io.h>
#endif

int  createLockFile(char *lockFile);
void *safe_malloc(size_t size);
void *safe_calloc(size_t nmemb, size_t size);
void *safe_realloc(void *ptr, size_t size);
char *safe_strdup(const char *src);

#endif
