/*****************************************************************************
 * String utilities for HPT (FTN NetMail/EchoMail Tosser)
 *****************************************************************************
 * Copyright (C) 1997-2000
 *
 * Kolya Nesterov
 *
 * Fido:     2:463/567
 * Kiev, Ukraine
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
#ifndef _XSTR_H
#define _XSTR_H


char *xstralloc(char **s, size_t add);
/* 
 * Adds to variable "s" "add" bytes (allocates or reallocates it)
 */

char *xstrcat(char **s, char *add);
/*
 * Appends "add" to variable "s", reallocating it when it needs
 */

char *xstrscat(char **s, ...);
/*
 * Appends a list of strings to "s", reallocating it when it needs
 * list is terminated with NULL value
 */
	
int xscatprintf(char **s, const char *format, ...);
/* 
 * sprintf's "format" to the end of "s". Reallocates it when it needs
 */

#endif
