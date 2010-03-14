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
# To install normal binary and man pages run `make install`
# To install debug binary and man pages run `make install-debug install-man`

BINARIES=fidoroute
MAN1PAGES=fidoroute.1
MAN5PAGES=fidoroute.conf.5
DOCS=fidoroute.conf.ru.html
CDEFS?=-D_TARGET=\"`uname -s`\"
DEBUGOPTS?=-Wall -ggdb
COPTS?=-s -O2
PREFIX?=/usr/local
MANDIR?=$(PREFIX)/man
MAN1DIR?=$(MANDIR)/man1/
MAN5DIR?=$(MANDIR)/man5/
BINDIR?=$(PREFIX)/bin/
DOCDIR?=$(PREFIX)/share/doc/fidoroute/
MANPAGES=$(MAN1PAGES) $(MAN5PAGES)

all: $(BINARIES)
	g++ $(COPTS) $(CDEFS) -o fidoroute fidoroute.cpp

debug: $(BINARIES)
	g++ $(DEBUGOPTS) $(CDEFS) -o fidoroute fidoroute.cpp

doc: $(DOCS)

fidoroute.conf.ru.html:
	wget -k -O fidoroute.conf.ru.html 'http://sourceforge.net/apps/mediawiki/husky/index.php?title=%D0%A4%D0%B0%D0%B9%D0%BB_fidoroute.conf&printable=yes' || true

install-doc: doc
	if [ ! -d $(DOCDIR) ]; then install -d $(DOCDIR); fi
	install fidoroute.conf.ru.html $(DOCDIR)

install-man:
	if [ ! -d $(MAN1DIR) ]; then install -d $(MAN1DIR); fi
	install $(MAN1PAGES) $(MAN1DIR)
	if [ ! -d $(MAN5DIR) ]; then install -d $(MAN5DIR); fi
	install $(MAN5PAGES) $(MAN5DIR)

install-debug: debug
	if [ ! -d $(BINDIR) ]; then install -d $(BINDIR); fi
	install $(BINARIES) $(BINDIR)

install-bin: all
	if [ ! -d $(BINDIR) ]; then install -d $(BINDIR); fi
	install $(BINARIES) $(BINDIR)

install: install-bin install-man
