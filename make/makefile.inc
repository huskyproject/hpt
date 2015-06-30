# $Id$
#
# Common makefiles part (include-file) for hpt

# Use defines before including this file:
# _OBJ  object files suffix begins with point (".o", ".obj", ... )
# _LIB  library files suffix begins with point (".a", ".lib", ... )
# _DLL  dinamic linking library files suffix begins with point (".dll", ".so", ...)
# LIBPREFIX  library filename prefix ("lib", "", ...)
# LIBSUFFIX  library filename suffix (compiler ID, three characters, somewhere empty)
# DLLPREFIX  dynamic linking library prefix (usually empty)
# DLLSUFFIX  dynamic linking library suffix (compiler ID or empty)
# O, B, L, H prefixes to use with names of objects, binaries, libraries and headers respectively

# Module name
LIBNAME = hpt

# Version
VERMAJOR= 1
VERMINOR= 9
VERPATCH= 0
VERH    = $(VERMAJOR).$(VERMINOR)
VER     = $(VERH).$(VERPATCH)

# Sources directory
_SRC_DIR= ../src/
# Headers directory
H_DIR   = ../h/

# Programms name
PKTINFO = $(B)pktinfo$(_EXE)
TPKT    = $(B)tpkt$(_EXE)
TXT2PKT = $(B)txt2pkt$(_EXE)
HPTLINK = $(B)hptlink$(_EXE)
HPTTREE = $(B)hpttree$(_EXE)
HPT     = $(B)hpt$(_EXE)

# Header files
HEADERS = $(H)hptafix.h $(H)cvsdate.h $(H)dupe.h $(H)fcommon.h $(H)global.h \
          $(H)hpt.h $(H)hptperl.h $(H)link.h $(H)pkt.h $(H)post.h $(H)scan.h \
          $(H)scanarea.h $(H)seenby.h $(H)toss.h $(H)version.h

OBJS       =

# Object files: programs
PKTINFOOBJS= $(O)pktinfo$(_OBJ) $(O)dupe$(_OBJ) $(O)pktread$(_OBJ) $(O)fcommon$(_OBJ) \
             $(O)global$(_OBJ)
TPKTOBJS   = $(O)global$(_OBJ) $(O)tpkt$(_OBJ) $(O)fcommon$(_OBJ) $(O)pktread$(_OBJ) $(O)pktwrite$(_OBJ) \
             $(O)dupe$(_OBJ)
TXT2PKTOBJS= $(O)global$(_OBJ) $(O)txt2pkt$(_OBJ) $(O)pktwrite$(_OBJ) $(O)dupe$(_OBJ) $(O)pktread$(_OBJ) \
             $(O)fcommon$(_OBJ)
HPTLINKOBJS= $(O)global$(_OBJ) $(O)hptlink$(_OBJ)
HPTTREEOBJS= $(O)hpttree$(_OBJ)
HPTOBJS    = $(O)global$(_OBJ) $(O)hpt$(_OBJ) $(O)pktread$(_OBJ) $(O)pktwrite$(_OBJ) $(O)fcommon$(_OBJ) \
             $(O)toss$(_OBJ) $(O)scan$(_OBJ) \
             $(O)scanarea$(_OBJ) $(O)post$(_OBJ) $(O)hptafix$(_OBJ) $(O)dupe$(_OBJ) \
             $(O)seenby$(_OBJ) $(O)link$(_OBJ) $(O)carbon$(_OBJ) $(PERLOBJ)
PRGOBJS    = $(PKTINFOOBJS) $(TPKTOBJS) $(TXT2PKTOBJS) $(HPTLINKOBJS) $(HPTTREEOBJS) $(HPTOBJS)

# Binary files(s) to bild from sources
PROGRAMS  = $(PKTINFO) $(TPKT) $(TXT2PKT) $(HPTLINK) $(HPTTREE) $(HPT)

# List of libraries required to build binary file(s)
LIBS    =
