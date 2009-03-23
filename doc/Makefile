ifeq ($(DEBIAN), 1)
# Every Debian-Source-Paket has one included.
include /usr/share/husky/huskymak.cfg
else ifdef RPM_BUILD_ROOT
# For RPM build is require all files in one directory branch
include ../huskymak.cfg
else
include ../../huskymak.cfg
endif

all: html info dvi

ifdef HTMLDIR
html: hpt.html
else
html:
	@echo
endif

ifdef DVIDIR
dvi: hpt.dvi
else
dvi:
	@echo
endif

ifdef INFODIR
info: hpt.info
else
info:
	@echo
endif

hpt.html: hpt.texi
	export LC_ALL=C; makeinfo --html --no-split hpt.texi

hpt.dvi: hpt.texi
	texi2dvi hpt.texi

hpt.info: hpt.texi
	makeinfo --no-split hpt.texi

clean:
	-$(RM) $(RMOPT) *~
	-$(RM) $(RMOPT) hpt.aux
	-$(RM) $(RMOPT) hpt.cp
	-$(RM) $(RMOPT) hpt.fn
	-$(RM) $(RMOPT) hpt.fns
	-$(RM) $(RMOPT) hpt.ky
	-$(RM) $(RMOPT) hpt.log
	-$(RM) $(RMOPT) hpt.pg
	-$(RM) $(RMOPT) hpt.toc
	-$(RM) $(RMOPT) hpt.tp
	-$(RM) $(RMOPT) hpt.vr

distclean: clean
	-$(RM) $(RMOPT) hpt.dvi
	-$(RM) $(RMOPT) hpt.info*
	-$(RM) $(RMOPT) hpt.inf
	-$(RM) $(RMOPT) hpt*html

install: info html dvi
	@echo .
ifdef INFODIR
	-$(MKDIR) $(MKDIROPT) $(DESTDIR)$(INFODIR)
	$(INSTALL) $(IMOPT) hpt.info $(DESTDIR)$(INFODIR)
	-install-info --info-dir=$(INFODIR)  $(DESTDIR)$(INFODIR)$(DIRSEP)hpt.info
endif
ifdef HTMLDIR
	-$(MKDIR) $(MKDIROPT) $(DESTDIR)$(HTMLDIR)
	$(INSTALL) $(IMOPT) hpt*html $(DESTDIR)$(HTMLDIR)
endif
ifdef DVIDIR
	-$(MKDIR) $(MKDIROPT) $(DESTDIR)$(DVIDIR)
	$(INSTALL)  hpt.dvi $(DESTDIR)$(DVIDIR)
endif
uninstall:
	-install-info --remove --info-dir=$(DESTDIR)$(INFODIR) $(DESTDIR)$(INFODIR)$(DIRSEP)hpt.info
	-$(RM) $(RMOPT) $(DESTDIR)$(INFODIR)$(DIRSEP)hpt.info
	-$(RM) $(RMOPT) $(DESTDIR)$(HTMLDIR)$(DIRSEP)hpt*html
	-$(RM) $(RMOPT) $(DESTDIR)$(DVIDIR)$(DIRSEP)hpt.dvi
