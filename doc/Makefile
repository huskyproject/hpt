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
	-$(RM) $(RMOPT) *~
	-$(RM) $(RMOPT) hpt*html
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

