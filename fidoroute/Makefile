#!/usr/bin/make -f
# $Id$
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# To build normal binary run `make all`
# To build binary for debugging (using gdb) run `make debug`

CDEFS?=-D_TARGET=\"`uname -s`\"
DEBUGOPTS?=-Wall -ggdb
COPTS?=-s -O2
PREFIX?=/usr/local
MANDIR?=$(PREFIX)/man
MAN1DIR?=$(MANDIR)/man1/
MAN5DIR?=$(MANDIR)/man5/
BINDIR?=$(PREFIX)/bin/

all:
	g++ $(COPTS) $(CDEFS) -o fidoroute fidoroute.cpp

debug:
	g++ $(DEBUGOPTS) $(CDEFS) -o fidoroute fidoroute.cpp

install-man:
	if [ ! -d $(MAN1DIR) ]; install -d $(MAN1DIR); fi
	install fidoroute.1 $(MAN1DIR)
	if [ ! -d $(MAN5DIR) ]; install -d $(MAN5DIR); fi
	install fidoroute.5 $(MAN5DIR)

install-bin:
	if [ ! -d $(BINDIR) ]; install -d $(BINDIR); fi
	install fidoroute $(BINDIR)

install: install-bin install-man
