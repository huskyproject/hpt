ifeq ($(DEBIAN), 1)
# Every Debian-Source-Paket has one included.
include /usr/share/husky/huskymak.cfg
else ifdef RPM_BUILD_ROOT
# RPM build requires all files to be in the source directory
include ../huskymak.cfg
else
include ../../huskymak.cfg
endif

all: info html txt dvi pdf

ifdef INFODIR
info: hpt.info
else
info: ;
endif

ifdef HTMLDIR
html: hpt.html
else
html: ;
endif

ifdef TXTDIR
txt: hpt.txt
else
txt: ;
endif

ifdef DVIDIR
dvi: hpt.dvi
else
dvi: ;
endif

ifdef PDFDIR
pdf: hpt.pdf
else
pdf: ;
endif

hpt.info: hpt.texi
	-makeinfo --no-split hpt.texi

hpt.html: hpt.texi
	-LC_ALL=C makeinfo --html --no-split hpt.texi

hpt.txt: hpt.texi
	-LC_ALL=C makeinfo --plaintext --no-split hpt.texi -o hpt.txt

hpt.dvi: hpt.texi
	-texi2dvi hpt.texi

hpt.pdf: hpt.texi
	-LC_ALL=C makeinfo --pdf --no-split hpt.texi -o hpt.pdf

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
	-$(RM) $(RMOPT) hpt.info
	-$(RM) $(RMOPT) hpt.inf
	-$(RM) $(RMOPT) hpt.html
	-$(RM) $(RMOPT) hpt.txt
	-$(RM) $(RMOPT) hpt.pdf

install: info html txt dvi pdf
ifdef INFODIR
	-$(MKDIR) $(MKDIROPT) $(DESTDIR)$(INFODIR)
	$(INSTALL) $(IMOPT) hpt.info $(DESTDIR)$(INFODIR)
	-install-info --info-dir=$(INFODIR)  $(DESTDIR)$(INFODIR)$(DIRSEP)hpt.info
endif
ifdef HTMLDIR
	-$(MKDIR) $(MKDIROPT) $(DESTDIR)$(HTMLDIR)
	$(INSTALL) $(IMOPT)  hpt.html $(DESTDIR)$(HTMLDIR)
endif
ifdef TXTDIR
	-$(MKDIR) $(MKDIROPT) $(DESTDIR)$(TXTDIR)
	$(INSTALL) $(IMOPT)  hpt.txt $(DESTDIR)$(TXTDIR)
endif
ifdef DVIDIR
	-$(MKDIR) $(MKDIROPT) $(DESTDIR)$(DVIDIR)
	$(INSTALL) $(IMOPT)  hpt.dvi $(DESTDIR)$(DVIDIR)
endif
ifdef PDFDIR
	-$(MKDIR) $(MKDIROPT) $(DESTDIR)$(PDFDIR)
	$(INSTALL) $(IMOPT)  hpt.pdf $(DESTDIR)$(PDFDIR)
endif

uninstall:
	-install-info --remove --info-dir=$(DESTDIR)$(INFODIR) $(DESTDIR)$(INFODIR)$(DIRSEP)hpt.info
	-$(RM) $(RMOPT) $(DESTDIR)$(INFODIR)$(DIRSEP)hpt.info
	-$(RM) $(RMOPT) $(DESTDIR)$(HTMLDIR)$(DIRSEP)hpt.html
	-$(RMDIR) $(DESTDIR)$(HTMLDIR) >& /dev/null || true
	-$(RM) $(RMOPT) $(DESTDIR)$(TXTDIR)$(DIRSEP)hpt.txt
	-$(RMDIR) $(DESTDIR)$(TXTDIR) >& /dev/null || true
	-$(RM) $(RMOPT) $(DESTDIR)$(DVIDIR)$(DIRSEP)hpt.dvi
	-$(RMDIR) $(DESTDIR)$(DVIDIR) >& /dev/null || true
	-$(RM) $(RMOPT) $(DESTDIR)$(PDFDIR)$(DIRSEP)hpt.pdf
	-$(RMDIR) $(DESTDIR)$(PDFDIR) >& /dev/null || true
