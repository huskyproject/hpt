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

LIBS  = -L$(LIBDIR) -lfidoconf -lsmapi -lhusky

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
install: hpt$(EXE) pktinfo$(EXE) txt2pkt$(EXE) hptlink$(EXE) hpttree$(EXE)
	$(INSTALL) $(IMOPT) man/hpt.1 $(MANDIR)/man1
	$(INSTALL) $(IMOPT) man/hptlink.1 $(MANDIR)/man1
	$(INSTALL) $(IMOPT) man/hpttree.1 $(MANDIR)/man1
	$(INSTALL) $(IMOPT) man/txt2pkt.1 $(MANDIR)/man1
else
install: hpt$(EXE) pktinfo$(EXE) txt2pkt$(EXE) hptlink$(EXE) hpttree$(EXE) hpt.1.gz hptlink.1.gz hpttree.1.gz txt2pkt.1.gz
	-$(MKDIR) $(MKDIROPT) $(MANDIR)
	-$(MKDIR) $(MKDIROPT) $(MANDIR)/man1
	$(INSTALL) $(IMOPT) hpt.1.gz $(MANDIR)/man1
	$(INSTALL) $(IMOPT) hptlink.1.gz $(MANDIR)/man1
	$(INSTALL) $(IMOPT) hpttree.1.gz $(MANDIR)/man1
	$(INSTALL) $(IMOPT) txt2pkt.1.gz $(MANDIR)/man1
endif
	$(INSTALL) $(IBOPT) hpt$(EXE) $(BINDIR)
	$(INSTALL) $(IBOPT) pktinfo$(EXE) $(BINDIR)
	$(INSTALL) $(IBOPT) txt2pkt$(EXE) $(BINDIR)
	$(INSTALL) $(IBOPT) hptlink$(EXE) $(BINDIR)
	$(INSTALL) $(IBOPT) hpttree$(EXE) $(BINDIR)

uninstall:
	-$(RM) $(RMOPT) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hpt.1
	-$(RM) $(RMOPT) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hptlink.1
	-$(RM) $(RMOPT) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hpttree.1
	-$(RM) $(RMOPT) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hpt.1.gz 
	-$(RM) $(RMOPT) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hptlink.1.gz
	-$(RM) $(RMOPT) $(MANDIR)$(DIRSEP)man1$(DIRSEP)hpttree.1.gz
	-$(RM) $(RMOPT) $(BINDIR)$(DIRSEP)hpt$(EXE)
	-$(RM) $(RMOPT) $(BINDIR)$(DIRSEP)pktinfo$(EXE)
	-$(RM) $(RMOPT) $(BINDIR)$(DIRSEP)txt2pkt$(EXE)
	-$(RM) $(RMOPT) $(BINDIR)$(DIRSEP)hptlink$(EXE)
	-$(RM) $(RMOPT) $(BINDIR)$(DIRSEP)hpttree$(EXE)


