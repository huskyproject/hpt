# include Husky-Makefile-Config
include ../../huskymak.cfg

SRC_DIR = ../src/

PERL=0
include makeperl.inc

ifeq ($(DEBUG), 1)
  CFLAGS = -I../h -I$(INCDIR) $(DEBCFLAGS) $(WARNFLAGS) $(PERLFLAGS)
  LFLAGS = $(DEBLFLAGS)
else
  CFLAGS = -I../h -I$(INCDIR) $(OPTCFLAGS) $(WARNFLAGS) $(PERLFLAGS)
  LFLAGS = $(OPTLFLAGS)
endif

LIBS  = -L$(LIBDIR) -lfidoconf -lsmapi

CDEFS=-D$(OSTYPE) $(ADDCDEFS)

default: all

%$(OBJ): $(SRC_DIR)%.c
	$(CC) $(CFLAGS) $(CDEFS) $(SRC_DIR)$*.c

include makefile.inc

all: commonprogs

clean: commonclean

distclean: commondistclean

install: hpt$(EXE) pktinfo$(EXE) txt2pkt$(EXE) hptlink$(EXE) hpttree$(EXE)
ifeq ($(SHORTNAMES), 1)
	$(INSTALL) $(IMOPT) man/hpt.1 $(MANDIR)/man1
        $(INSTALL) $(IMOPT) man/hptlink.1 $(MANDIR)/man1
        $(INSTALL) $(IMOPT) man/hpttree.1 $(MANDIR)/man1
else
	gzip -c man/hpt.1 > hpt.1.gz
	gzip -c man/hptlink.1 > hptlink.1.gz
	gzip -c man/hpttree.1 > hpttree.1.gz
	-$(MKDIR) $(MKDIROPT) $(MANDIR)
	-$(MKDIR) $(MKDIROPT) $(MANDIR)/man1
	$(INSTALL) $(IMOPT) hpt.1.gz $(MANDIR)/man1
	$(INSTALL) $(IMOPT) hptlink.1.gz $(MANDIR)/man1
	$(INSTALL) $(IMOPT) hpttree.1.gz $(MANDIR)/man1
	$(RM) hpt.1.gz
	$(RM) hptlink.1.gz
	$(RM) hpttree.1.gz
endif
	$(INSTALL) $(IBOPT) hpt$(EXE) $(BINDIR)
	$(INSTALL) $(IBOPT) pktinfo$(EXE) $(BINDIR)
	$(INSTALL) $(IBOPT) txt2pkt$(EXE) $(BINDIR)
	$(INSTALL) $(IBOPT) hptlink$(EXE) $(BINDIR)
	$(INSTALL) $(IBOPT) hpttree$(EXE) $(BINDIR)


