# A makefile for hpt documentation
# hpt/doc/Makefile

.PHONY: hpt_info hpt_html hpt_txt hpt_dvi hpt_pdf \
        hpt_rmdir_DOC hpt_clean_DOC \
        hpt_install_info hpt_install_html hpt_install_txt \
        hpt_install_dvi hpt_install_pdf hpt_info_uninstall hpt_docs_uninstall

ifdef DOCDIR
    hpt_doc: hpt_info hpt_html hpt_txt hpt_dvi hpt_pdf ;
else
    hpt_doc: hpt_info ;
endif

ifdef INFODIR
    hpt_info: $(hpt_BUILDDIR)hpt.info$(_COMPR)
else
    hpt_info: ;
endif

ifeq ($(HTML), 1)
    hpt_html: $(hpt_BUILDDIR)hpt.html
else
    hpt_html: ;
endif

ifeq ($(TXT), 1)
    hpt_txt: $(hpt_BUILDDIR)hpt.txt
else
    hpt_txt: ;
endif

ifeq ($(DVI), 1)
    hpt_dvi: $(hpt_BUILDDIR)hpt.dvi
else
    hpt_dvi: ;
endif

ifeq ($(PDF), 1)
    hpt_pdf: $(hpt_BUILDDIR)hpt.pdf
else
    hpt_pdf: ;
endif

hpt_DOCDIR_BLD=$(hpt_BUILDDIR)doc$(DIRSEP)
hpt_TEXI=$(hpt_DOCDIR_BLD)hpt.texi

ifdef COMPRESS
$(hpt_BUILDDIR)hpt.info$(_COMPR): $(hpt_BUILDDIR)hpt.info
	$(COMPRESS) -c $? > $@
endif

$(hpt_BUILDDIR)hpt.info: $(hpt_TEXI)
	-$(MAKEINFO) $(MINOSPLIT) "$<" $(MIOUT) "$@"

$(hpt_BUILDDIR)hpt.html: $(hpt_TEXI)
	-LC_ALL=C $(MAKEINFO) $(MIHTML) $(MINOSPLIT) "$<" $(MIOUT) "$@"

$(hpt_BUILDDIR)hpt.txt: $(hpt_TEXI)
	-LC_ALL=C $(MAKEINFO) $(MIPTEXT) $(MINOSPLIT) "$<" $(MIOUT) "$@"

$(hpt_BUILDDIR)hpt.dvi: $(hpt_DOCDIR_BLD)hpt.dvi
	$(LN) $(LNHOPT) "$<" $(hpt_BUILDDIR)

$(hpt_DOCDIR_BLD)hpt.dvi: $(hpt_TEXI)
	-cd $(hpt_DOCDIR_BLD); LC_ALL=C $(TEXI2DVI) ../../../"$<"

$(hpt_BUILDDIR)hpt.pdf: $(hpt_DOCDIR_BLD)hpt.pdf
	$(LN) $(LNHOPT) "$<" $(hpt_BUILDDIR)

$(hpt_DOCDIR_BLD)hpt.pdf: $(hpt_TEXI)
	-cd $(hpt_DOCDIR_BLD); \
	LC_ALL=C $(MAKEINFO) $(MIPDF) $(MINOSPLIT) hpt.texi $(MIOUT) hpt.pdf

$(hpt_TEXI): $(hpt_DOCDIR)hpt.texi | $(hpt_DOCDIR_BLD)
	$(LN) $(LNHOPT) "$<" $(hpt_DOCDIR_BLD)

$(hpt_DOCDIR_BLD):
	[ -d "$(hpt_BUILDDIR)" ] || $(MKDIR) $(MKDIROPT) "$(hpt_BUILDDIR)"
	[ -d "$@" ] || $(MKDIR) $(MKDIROPT) "$@"


# Install
ifdef DOCDIR
# See "all_info_install" in the root Makefile
    hpt_doc_install: all_info_install hpt_install_html hpt_install_txt \
                 hpt_install_dvi hpt_install_pdf ;
else
    hpt_doc_install: all_info_install ;
endif

ifeq ($(HTML), 1)
    hpt_install_html: $(DOCDIR_DST)hpt.html ;

    $(DOCDIR_DST)hpt.html: $(hpt_BUILDDIR)hpt.html | $(DOCDIR_DST)
		$(INSTALL) $(IMOPT) "$<" "$|"; \
		$(TOUCH) "$@"
else
    hpt_install_html: ;
endif

ifeq ($(TXT), 1)
    hpt_install_txt: $(DOCDIR_DST)hpt.txt ;

    $(DOCDIR_DST)hpt.txt: $(hpt_BUILDDIR)hpt.txt | $(DOCDIR_DST)
		$(INSTALL) $(IMOPT) "$<" "$|"; \
		$(TOUCH) "$@"
else
    hpt_install_txt: ;
endif

ifeq ($(DVI), 1)
    hpt_install_dvi: $(DOCDIR_DST)hpt.dvi ;

    $(DOCDIR_DST)hpt.dvi: $(hpt_BUILDDIR)hpt.dvi | $(DOCDIR_DST)
		$(INSTALL) $(IMOPT) "$<" "$|"; \
		$(TOUCH) "$@"
else
    hpt_install_dvi: ;
endif

ifeq ($(PDF), 1)
    hpt_install_pdf: $(DOCDIR_DST)hpt.pdf ;

    $(DOCDIR_DST)hpt.pdf: $(hpt_BUILDDIR)hpt.pdf | $(DOCDIR_DST)
		$(INSTALL) $(IMOPT) "$<" "$|"; \
		$(TOUCH) "$@"
else
    hpt_install_pdf: ;
endif


# Clean
hpt_doc_clean: hpt_rmdir_DOC ;

hpt_rmdir_DOC: hpt_clean_DOC
	-[ -d "$(hpt_DOCDIR_BLD)" ] && $(RMDIR) $(hpt_DOCDIR_BLD) || true

hpt_clean_DOC:
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.fns
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.aux
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.toc
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.cp
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.fn
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.vr
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.kr
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.ke
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.tp
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.kes
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.krs
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.ky
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.pg
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.cps
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)*.log
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.texi
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.dvi
	-$(RM) $(RMOPT) $(hpt_DOCDIR_BLD)hpt.pdf

# Distclean
hpt_doc_distclean: hpt_doc_clean
	-$(RM) $(RMOPT) $(hpt_BUILDDIR)hpt*dvi
	-$(RM) $(RMOPT) $(hpt_BUILDDIR)hpt.inf
	-$(RM) $(RMOPT) $(hpt_BUILDDIR)hpt*html
	-$(RM) $(RMOPT) $(hpt_BUILDDIR)hpt.ps
	-$(RM) $(RMOPT) $(hpt_BUILDDIR)hpt.doc
	-$(RM) $(RMOPT) $(hpt_BUILDDIR)hpt*txt
	-$(RM) $(RMOPT) $(hpt_BUILDDIR)hpt.pdf
	-$(RM) $(RMOPT) $(hpt_BUILDDIR)hpt.info*


# Uninstall
ifdef DOCDIR
    hpt_doc_uninstall: hpt_info_uninstall hpt_docs_uninstall ;
else
    hpt_doc_uninstall: hpt_info_uninstall ;
endif

ifdef INFODIR
# See "all_info_uninstall" in the root Makefile
    hpt_info_uninstall: all_info_uninstall
		-$(RM) $(RMOPT) $(INFODIR_DST)hpt.info$(_COMPR)
else
    hpt_info_uninstall: ;
endif

hpt_docs_uninstall:
ifeq ($(HTML), 1)
	-$(RM) $(RMOPT) $(DOCDIR_DST)hpt.html
endif
ifeq ($(TXT), 1)
	-$(RM) $(RMOPT) $(DOCDIR_DST)hpt.txt
endif
ifeq ($(DVI), 1)
	-$(RM) $(RMOPT) $(DOCDIR_DST)hpt.dvi
endif
ifeq ($(PDF), 1)
	-$(RM) $(RMOPT) $(DOCDIR_DST)hpt.pdf
endif
