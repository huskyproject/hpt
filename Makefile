# include Husky-Makefile-Config
ifeq ($(DEBIAN), 1)
# Every Debian-Source-Paket has one included.
include /usr/share/husky/huskymak.cfg
else
include ../huskymak.cfg
endif

SRC_DIR = src$(DIRSEP)

ifeq ($(DEBUG), 1)
  CFLAGS = -Ih -I$(INCDIR) $(DEBCFLAGS) $(WARNFLAGS)
  LFLAGS = $(DEBLFLAGS)
else
  CFLAGS = -Ih -I$(INCDIR) $(OPTCFLAGS) $(WARNFLAGS)
  LFLAGS = $(OPTLFLAGS)
endif

ifeq ($(SHORTNAME), 1)
  LIBS=-L$(LIBDIR) -lfidoconf -lsmapi -lhusky
else
  LIBS=-L$(LIBDIR) -lfidoconfig -lsmapi -lhusky
endif

ifeq ($(USE_HPTZIP), 1)
  LIBS+= -lhptzip
  CFLAGS += -DUSE_HPTZIP
endif

ifeq ($(PERL), 1)
  CFLAGS += -DDO_PERL `perl -MExtUtils::Embed -e ccopts`
  PERLLIBS = `perl -MExtUtils::Embed -e ldopts`
  PERLOBJ = perl$(_OBJ)
endif

CDEFS=-D$(OSTYPE) $(ADDCDEFS)

default: all

include makefile.inc

hpt.1.gz: man/hpt.1
	gzip -c man/hpt.1 > hpt.1.gz

hptlink.1.gz: man/hptlink.1
	gzip -c man/hptlink.1 > hptlink.1.gz

hpttree.1.gz: man/hpttree.1
	gzip -c man/hpttree.1 > hpttree.1.gz

txt2pkt.1.gz: man/txt2pkt.1
	gzip -c man/txt2pkt.1 > txt2pkt.1.gz

ifeq ($(SHORTNAMES), 1)
all: commonall
else
all: commonall hpt.1.gz hptlink.1.gz hpttree.1.gz txt2pkt.1.gz
endif

ifeq ($(SHORTNAMES), 1)
install: hpt$(_EXE) pktinfo$(_EXE) txt2pkt$(_EXE) hptlink$(_EXE) hpttree$(_EXE)
	$(INSTALL) $(IMOPT) man/hpt.1 $(MANDIR)/man1
	$(INSTALL) $(IMOPT) man/hptlink.1 $(MANDIR)/man1
	$(INSTALL) $(IMOPT) man/hpttree.1 $(MANDIR)/man1
	$(INSTALL) $(IMOPT) man/txt2pkt.1 $(MANDIR)/man1
else
install: hpt$(_EXE) pktinfo$(_EXE) txt2pkt$(_EXE) hptlink$(_EXE) hpttree$(_EXE) hpt.1.gz hptlink.1.gz hpttree.1.gz txt2pkt.1.gz
	-$(MKDIR) $(MKDIROPT) $(MANDIR)
	-$(MKDIR) $(MKDIROPT) $(MANDIR)/man1
	$(INSTALL) $(IMOPT) hpt.1.gz $(MANDIR)/man1
	$(INSTALL) $(IMOPT) hptlink.1.gz $(MANDIR)/man1
	$(INSTALL) $(IMOPT) hpttree.1.gz $(MANDIR)/man1
	$(INSTALL) $(IMOPT) txt2pkt.1.gz $(MANDIR)/man1
endif
	$(INSTALL) $(IBOPT) hpt$(_EXE) $(BINDIR)
	$(INSTALL) $(IBOPT) pktinfo$(_EXE) $(BINDIR)
	$(INSTALL) $(IBOPT) txt2pkt$(_EXE) $(BINDIR)
	$(INSTALL) $(IBOPT) hptlink$(_EXE) $(BINDIR)
	$(INSTALL) $(IBOPT) hpttree$(_EXE) $(BINDIR)

uninstall:
	-$(RM) $(RMOPT) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hpt.1
	-$(RM) $(RMOPT) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hptlink.1
	-$(RM) $(RMOPT) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hpttree.1
	-$(RM) $(RMOPT) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hpt.1.gz 
	-$(RM) $(RMOPT) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hptlink.1.gz
	-$(RM) $(RMOPT) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hpttree.1.gz
	-$(RM) $(RMOPT) $(BINDIR)$(DIRSEP)hpt$(_EXE)
	-$(RM) $(RMOPT) $(BINDIR)$(DIRSEP)pktinfo$(_EXE)
	-$(RM) $(RMOPT) $(BINDIR)$(DIRSEP)txt2pkt$(_EXE)
	-$(RM) $(RMOPT) $(BINDIR)$(DIRSEP)hptlink$(_EXE)
	-$(RM) $(RMOPT) $(BINDIR)$(DIRSEP)hpttree$(_EXE)


