# common rules for perl support (UNIX platforms)
ifeq (~$(PERL)~, ~1~)
PERLFLAGS = -DDO_PERL `perl -MExtUtils::Embed -e ccopts`
PERLLIBS = `perl -MExtUtils::Embed -e ldopts`
PERLOBJ = perl$(OBJ)
endif
