include ../../huskymak.cfg

all: html info dvi

ifdef HTMLDIR
html: hpt_toc.html
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

hpt_toc.html: hpt.texi
	texi2html -split_node -number -menu hpt.texi

hpt.dvi: hpt.texi
	texi2dvi hpt.texi

hpt.info: hpt.texi
	makeinfo --no-split hpt.texi

clean:
	-$(RM) $(RMOPT) hpt.fns
	-$(RM) $(RMOPT) hpt.aux
	-$(RM) $(RMOPT) hpt.toc
	-$(RM) $(RMOPT) hpt.cp
	-$(RM) $(RMOPT) hpt.fn
	-$(RM) $(RMOPT) hpt.vr
	-$(RM) $(RMOPT) hpt.kr
	-$(RM) $(RMOPT) hpt.ke
	-$(RM) $(RMOPT) hpt.tp
	-$(RM) $(RMOPT) hpt.kes
	-$(RM) $(RMOPT) hpt.krs
	-$(RM) $(RMOPT) hpt.ky
	-$(RM) $(RMOPT) hpt.pg
	-$(RM) $(RMOPT) hpt.cps
	-$(RM) $(RMOPT) hpt.log
	-$(RM) $(RMOPT) hpt.fns
	-$(RM) $(RMOPT) *~

distclean: clean
	-$(RM) $(RMOPT) hpt.dvi
	-$(RM) $(RMOPT) hpt.inf
	-$(RM) $(RMOPT) hpt*html
	-$(RM) $(RMOPT) hpt.ps
	-$(RM) $(RMOPT) hpt.doc
	-$(RM) $(RMOPT) hpt.info*

install: info html dvi
	@echo .
ifdef INFODIR
	-$(MKDIR) $(MKDIROPT) $(INFODIR)
	$(INSTALL)  hpt.info $(INFODIR)
	-install-info --info-dir=$(INFODIR)  $(INFODIR)$(DIRSEP)hpt.info
endif
ifdef HTMLDIR
	-$(MKDIR) $(MKDIROPT) $(HTMLDIR)
	$(INSTALL)  hpt*html $(HTMLDIR)
endif

uninstall:
	-install-info --remove --info-dir=$(INFODIR) $(INFODIR)$(DIRSEP)hpt.info
	-$(RM) $(RMOPT) $(INFODIR)$(DIRSEP)hpt.info
	-$(RM) $(RMOPT) $(HTMLDIR)$(DIRSEP)hpt*html

