/*:ts=8*/
/*****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 * Copyright (C) 1997-1998
 *
 * Matthias Tichy
 *
 * Fido:     2:2433/1245 2:2433/1247 2:2432/601.29
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
#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <typesize.h>

struct log {
// char *fileName;      // name of the file where the log will be stored.
   char *keysAllowed;   // only log-data with one of these keys will be stored
   char *appName;       // name of the application which has created this log entry
   FILE *logFile;       // in this logFile
   char open;           // is the log-file open?
};

typedef struct log s_log;

s_log *openLog(char *fileName, char *appN, char *keys);
/*DOC
  Input:  fileName is a valid name for a file.
          appN contains the name of the application.
          keys contains the list of keys which will go to log 
  Output: openLog returns a pointer to an s_log struct.
  FZ:     openLog fills the s_log struct, opens the logfile and returns the struct
*/

void closeLog(s_log *log);
/*DOC
  Input:  log is a pointer to a s_log
  Output: ./.
  FZ:     closes the logFile and frees all mem use by log.
*/

void writeLogEntry(s_log *log, char key, char *logString);
/*DOC
  Input:  log is a pointer to a s_log
          key is the key under which the log-entry will be stored
          logString is the logEntry
  Output: ./. 
  FZ:     if the key is in keysAllowed the logString will be written to the log.
*/

#endif
