# include Husky-Makefile-Config
include ../huskymak.cfg

SRC_DIR = src$(DIRSEP)

ifeq ($(DEBUG), 1)
  CFLAGS = -Ih -I$(INCDIR) $(DEBCFLAGS) $(WARNFLAGS)
  LFLAGS = $(DEBLFLAGS)
else
  CFLAGS = -Ih -I$(INCDIR) $(OPTCFLAGS) $(WARNFLAGS)
  LFLAGS = $(OPTLFLAGS)
endif

ifeq ($(SHORTNAME), 1)
  LIBS  = -L$(LIBDIR) -lfidoconf -lsmapi
else
  LIBS  = -L$(LIBDIR) -lfidoconfig -lsmapi
endif

ifeq ($(PERL), 1)
  CFLAGS += -DDO_PERL `perl -MExtUtils::Embed -e ccopts`
  PERLLIBS = `perl -MExtUtils::Embed -e ldopts`
  PERLOBJ = perl$(OBJ)
endif

CDEFS=-D$(OSTYPE) $(ADDCDEFS)

include makefile.inc

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

uninstall:
	-$(RM) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hpt.1
        -$(RM) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hptlink.1
        -$(RM) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hpttree.1
	-$(RM) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hpt.1.gz 
	-$(RM) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hptlink.1.gz
	-$(RM) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hpttree.1.gz
	-$(RM) $(BINDIR)$(DIRSEP)hpt$(EXE)
	-$(RM) $(BINDIR)$(DIRSEP)pktinfo$(EXE)
	-$(RM) $(BINDIR)$(DIRSEP)txt2pkt$(EXE)
	-$(RM) $(BINDIR)$(DIRSEP)hptlink$(EXE)
	-$(RM) $(BINDIR)$(DIRSEP)hpttree$(EXE)


