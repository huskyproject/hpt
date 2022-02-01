# hpt/Makefile
#
# This file is part of hpt, part of the Husky fidonet software project
# Use with GNU make v.3.82 or later
# Requires: husky enviroment
#

ifdef MAN1DIR
    hpt_MAN1PAGES := hpt.1
    ifeq ($(HPT_UTIL), 1)
        hpt_MAN1PAGES += hptlink.1 hpttree.1 pktinfo.1 txt2pkt.1
    endif

    hpt_MAN1BLD := $(foreach man,$(hpt_MAN1PAGES),$(hpt_BUILDDIR)$(man).gz)
    hpt_MAN1DST := $(foreach man,$(hpt_MAN1PAGES),$(DESTDIR)$(MAN1DIR)$(DIRSEP)$(man).gz)
endif

hpt_LIBS := $(areafix_TARGET_BLD) $(fidoconf_TARGET_BLD) \
            $(smapi_TARGET_BLD) $(huskylib_TARGET_BLD)

ifeq ($(PERL), 1)
    hpt_CFLAGS := -DDO_PERL $(shell perl -MExtUtils::Embed -e ccopts) $(CFLAGS)
    PERLLIBS := $(shell perl -MExtUtils::Embed -e ldopts)
    PERLOBJ := perl$(_OBJ)
else
    hpt_CFLAGS = $(CFLAGS)
endif

hpt_CDEFS := $(CDEFS) -I$(areafix_ROOTDIR) \
                      -I$(fidoconf_ROOTDIR) \
                      -I$(smapi_ROOTDIR) \
                      -I$(huskylib_ROOTDIR) \
                      -I$(hpt_ROOTDIR)$(hpt_H_DIR)

ifeq ($(USE_HPTZIP), 1)
    ifeq ($(DYNLIBS), 1)
        hpt_LIBZ = -lz
    else
        hpt_LIBZ = -Xlinker -l:libz.a
    endif
    hpt_LIBS += $(hptzip_TARGET_BLD)
    hpt_CFLAGS += -DUSE_HPTZIP
    hpt_CDEFS  += -I$(hptzip_ROOTDIR)
endif

hpt_ALL_SRC = $(wildcard $(hpt_SRCDIR)*.c)

hpt_ALL_OBJFILES = $(notdir $(hpt_ALL_SRC:.c=$(_OBJ)))

hpt_OBJFILES = carbon$(_OBJ) dupe$(_OBJ) fcommon$(_OBJ) global$(_OBJ) \
	hpt$(_OBJ) hptafix$(_OBJ) link$(_OBJ) $(PERLOBJ) pktread$(_OBJ) \
	pktwrite$(_OBJ) post$(_OBJ) scan$(_OBJ) scanarea$(_OBJ) seenby$(_OBJ) \
	toss$(_OBJ)

# Prepend directory
hpt_OBJS := $(addprefix $(hpt_OBJDIR),$(hpt_OBJFILES))
hpt_ALL_OBJS := $(addprefix $(hpt_OBJDIR), $(hpt_ALL_OBJFILES))

hpt_DEPS := $(hpt_ALL_OBJFILES)
ifdef O
    hpt_DEPS := $(hpt_DEPS:$(O)=)
endif
ifdef _OBJ
    hpt_DEPS := $(hpt_DEPS:$(_OBJ)=$(_DEP))
else
    hpt_DEPS := $(addsuffix $(_DEP),$(hpt_DEPS))
endif
hpt_DEPS := $(addprefix $(hpt_DEPDIR),$(hpt_DEPS))

ifneq ($(HPT_UTIL), 1)
    hpt_TARGET = hpt$(_EXE)
else
    hpt_utils    := hptlink hpttree pktinfo tpkt txt2pkt
    hpt_TARGET   := hpt$(_EXE) $(addsuffix $(_EXE), $(hpt_utils))

    hptlink_OBJS := $(hpt_OBJDIR)hptlink$(_OBJ)

    hpttree_OBJS := $(hpt_OBJDIR)hpttree$(_OBJ)

    pktinfo_OBJS := pktinfo$(_OBJ) dupe$(_OBJ) fcommon$(_OBJ) global$(_OBJ) \
                    pktread$(_OBJ)
    pktinfo_OBJS := $(addprefix $(hpt_OBJDIR), $(pktinfo_OBJS))

    tpkt_OBJS    := tpkt$(_OBJ) dupe$(_OBJ) fcommon$(_OBJ) global$(_OBJ) \
                    pktread$(_OBJ) pktwrite$(_OBJ)
    tpkt_OBJS    := $(addprefix $(hpt_OBJDIR), $(tpkt_OBJS))

    txt2pkt_OBJS := txt2pkt$(_OBJ) dupe$(_OBJ) fcommon$(_OBJ) global$(_OBJ) \
                    pktread$(_OBJ) pktwrite$(_OBJ)
    txt2pkt_OBJS := $(addprefix $(hpt_OBJDIR), $(txt2pkt_OBJS))
endif

hpt_TARGET_OBJ = $(addprefix $(hpt_OBJDIR), $(hpt_TARGET))
hpt_TARGET_BLD = $(addprefix $(hpt_BUILDDIR), $(hpt_TARGET))
hpt_TARGET_DST = $(addprefix $(BINDIR_DST), $(hpt_TARGET))


.PHONY: hpt_build hpt_install hpt_uninstall hpt_clean hpt_distclean hpt_depend \
        hpt_doc hpt_doc_install hpt_doc_uninstall hpt_doc_clean \
        hpt_doc_distclean hpt_clean_OBJ hpt_main_distclean hpt_rmdir_DEP hpt_rm_DEPS

hpt_build: $(hpt_TARGET_BLD) $(hpt_MAN1BLD) hpt_doc

ifneq ($(MAKECMDGOALS), depend)
    include $(hpt_DOCDIR)Makefile
ifneq ($(MAKECMDGOALS), distclean)
ifneq ($(MAKECMDGOALS), uninstall)
    include $(hpt_DEPS)
endif
endif
endif


# Build applications
$(hpt_BUILDDIR)hpt$(_EXE): $(hpt_OBJS) $(hpt_LIBS) | do_not_run_make_as_root
	$(CC) $(LFLAGS) $(EXENAMEFLAG) $@ $^ $(hpt_LIBZ) $(PERLLIBS)

ifeq ($(HPT_UTIL), 1)
    $(hpt_BUILDDIR)hptlink$(_EXE): $(hptlink_OBJS) $(hpt_LIBS) | do_not_run_make_as_root
		$(CC) $(LFLAGS) $(EXENAMEFLAG) $@ $^ $(hpt_LIBZ)

    $(hpt_BUILDDIR)hpttree$(_EXE): $(hpttree_OBJS) $(hpt_LIBS) | do_not_run_make_as_root
		$(CC) $(LFLAGS) $(EXENAMEFLAG) $@ $^ $(hpt_LIBZ)

    $(hpt_BUILDDIR)pktinfo$(_EXE): $(pktinfo_OBJS) $(hpt_LIBS) | do_not_run_make_as_root
		$(CC) $(LFLAGS) $(EXENAMEFLAG) $@ $^ $(hpt_LIBZ)

    $(hpt_BUILDDIR)tpkt$(_EXE): $(tpkt_OBJS) $(hpt_LIBS) | do_not_run_make_as_root
		$(CC) $(LFLAGS) $(EXENAMEFLAG) $@ $^ $(hpt_LIBZ)

    $(hpt_BUILDDIR)txt2pkt$(_EXE): $(txt2pkt_OBJS) $(hpt_LIBS) | do_not_run_make_as_root
		$(CC) $(LFLAGS) $(EXENAMEFLAG) $@ $^ $(hpt_LIBZ)
endif

# Compile .c files
$(hpt_ALL_OBJS): $(hpt_OBJDIR)%$(_OBJ): $(hpt_SRCDIR)%.c | $(hpt_OBJDIR)
	$(CC) $(hpt_CFLAGS) $(hpt_CDEFS) -o $(hpt_OBJDIR)$*$(_OBJ) $(hpt_SRCDIR)$*.c

$(hpt_OBJDIR): | $(hpt_BUILDDIR) do_not_run_make_as_root
	[ -d $@ ] || $(MKDIR) $(MKDIROPT) $@


# Build man pages
ifdef MAN1DIR
    $(hpt_MAN1BLD): $(hpt_BUILDDIR)%.gz: $(hpt_MANDIR)% | do_not_run_make_as_root
	gzip -c $(hpt_MANDIR)$* > $(hpt_BUILDDIR)$*.gz
else
    $(hpt_MAN1BLD): ;
endif


# Install
ifneq ($(MAKECMDGOALS), install)
    hpt_install: ;
else
    hpt_install: $(hpt_TARGET_DST) hpt_install_man hpt_doc_install ;
endif

$(hpt_TARGET_DST): $(BINDIR_DST)%: $(hpt_BUILDDIR)% | \
    $(DESTDIR)$(BINDIR)
	$(INSTALL) $(IBOPT) $(hpt_BUILDDIR)$* $(DESTDIR)$(BINDIR); \
	$(TOUCH) "$(BINDIR_DST)$*"

ifndef MAN1DIR
    hpt_install_man: ;
else
    hpt_install_man: $(hpt_MAN1DST)

    $(hpt_MAN1DST): $(DESTDIR)$(MAN1DIR)$(DIRSEP)%: $(hpt_BUILDDIR)% | \
        $(DESTDIR)$(MAN1DIR)
	$(INSTALL) $(IMOPT) $(hpt_BUILDDIR)$* $(DESTDIR)$(MAN1DIR); \
	$(TOUCH) "$(DESTDIR)$(MAN1DIR)$(DIRSEP)$*"
endif


# Clean
hpt_clean: hpt_clean_OBJ hpt_doc_clean
	-[ -d "$(hpt_OBJDIR)" ] && $(RMDIR) $(hpt_OBJDIR) || true

hpt_clean_OBJ:
	-$(RM) $(RMOPT) $(hpt_OBJDIR)*

# Distclean
hpt_distclean: hpt_doc_distclean hpt_main_distclean hpt_rmdir_DEP;
	-[ -d "$(hpt_BUILDDIR)" ] && $(RMDIR) $(hpt_BUILDDIR) || true

hpt_rmdir_DEP: hpt_rm_DEPS
	-[ -d "$(hpt_DEPDIR)" ] && $(RMDIR) $(hpt_DEPDIR) || true

hpt_rm_DEPS:
	-$(RM) $(RMOPT) $(hpt_DEPDIR)*

hpt_main_distclean: hpt_clean ;
	-$(RM) $(RMOPT) $(hpt_TARGET_BLD)
ifeq ($(OSTYPE), UNIX)
    ifdef MAN1DIR
		-$(RM) $(RMOPT) $(hpt_MAN1BLD)
    endif
endif


# Uninstall
hpt_uninstall: hpt_main_uninstall hpt_doc_uninstall

hpt_main_uninstall:
	-$(RM) $(RMOPT) $(hpt_TARGET_DST)
ifdef MAN1DIR
	-$(RM) $(RMOPT) $(hpt_MAN1DST)
endif


# Depend
ifeq ($(MAKECMDGOALS),depend)
hpt_depend: $(hpt_DEPS) ;

# Build a dependency makefile for every source file
$(hpt_DEPS): $(hpt_DEPDIR)%$(_DEP): $(hpt_SRCDIR)%.c | $(hpt_DEPDIR)
	@set -e; rm -f $@; \
	$(CC) -MM $(hpt_CFLAGS) $(hpt_CDEFS) $< > $@.$$$$; \
	sed 's,\($*\)$(__OBJ)[ :]*,$(hpt_OBJDIR)\1$(_OBJ) $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

$(hpt_DEPDIR): | $(hpt_BUILDDIR) do_not_run_depend_as_root
	[ -d $@ ] || $(MKDIR) $(MKDIROPT) $@
endif

$(hpt_BUILDDIR):
	[ -d $@ ] || $(MKDIR) $(MKDIROPT) $@
