/*****************************************************************************
 * HTICK --- FTN Ticker / Request Processor
 *****************************************************************************
 * Copyright (C) 1999 by
 *
 * Gabriel Plutzar
 *
 * Fido:     2:31/1
 * Internet: gabriel@hit.priv.at
 *
 * Vienna, Austria, Europe
 *
 * This file is part of HTICK, which is based on HPT by Matthias Tichy, 
 * 2:2432/605.14 2:2433/1245, mtt@tichy.de
 *
 * HTICK is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * HTICK is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with HTICK; see the file COPYING.  If not, write to the Free
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *****************************************************************************/

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <typesize.h>

struct log {
// char *fileName;       // name of the file where the log will be stored.
   char *keysAllowed;    // only log-data with one of these keys will be stored
   char *appName;        // name of the application which has created this log entry
   FILE *logFile;        // in this logFile
   char open;            // is the log-file open?
   char firstLinePrinted;// First line in Log File printed ?
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
