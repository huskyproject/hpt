# $Id$
#
# Common makefiles part (include-file) for hpt

# Use defines before including this file:
# _OBJ	object files suffix begins with point (".o", ".obj", ... )
# _LIB	library files suffix begins with point (".a", ".lib", ... )
# _DLL	dinamic linking library files suffix begins with point (".dll", ".so", ...)
# LIBPREFIX  library filename prefix ("lib", "", ...)
# LIBSUFFIX  library filename suffix (compiler ID, three characters, somewhere empty)
# DLLPREFIX  dinamic linking library prefix (usually empty)
# DLLSUFFIX  dinamic linking library suffix (compiler ID or empty)
# _SRC_DIR  sources dir

LIBNAME = hpt

# Version
VERMAJOR= 1
VERMINOR= 9
VERPATCH= 0
VERH	= $(VERMAJOR).$(VERMINOR)
VER	= $(VERH).$(VERPATCH)

# Programms name
PKTINFO	= pktinfo$(_EXE)
TPKT	= tpkt$(_EXE)
TXT2PKT	= txt2pkt$(_EXE)
HPTLINK = hptlink$(_EXE)
HPTTREE	= hpttree$(_EXE)
HPT	= hpt$(_EXE)

# Object files: programs
OBJS	   = 
PKTINFOOBJS= pktinfo$(_OBJ) dupe$(_OBJ)  pktread$(_OBJ) fcommon$(_OBJ) \
	     global$(_OBJ) 
TPKTOBJS   = tpkt$(_OBJ) fcommon$(_OBJ) pktread$(_OBJ) pktwrite$(_OBJ) \
	     global$(_OBJ) dupe$(_OBJ)
TXT2PKTOBJS= txt2pkt$(_OBJ) pktwrite$(_OBJ) dupe$(_OBJ) pktread$(_OBJ) \
	     fcommon$(_OBJ) global$(_OBJ)
HPTLINKOBJS= hptlink$(_OBJ) global$(_OBJ)
HPTTREEOBJS= hpttree$(_OBJ)
HPTOBJS    = hpt$(_OBJ) pktread$(_OBJ) pktwrite$(_OBJ) fcommon$(_OBJ) \
	     global$(_OBJ) toss$(_OBJ) scan$(_OBJ) \
	     scanarea$(_OBJ) post$(_OBJ) hptafix$(_OBJ) dupe$(_OBJ) \
	     seenby$(_OBJ) link$(_OBJ) carbon$(_OBJ) $(PERLOBJ)

# Header files
HEADERS	= hptafix.h cvsdate.h dupe.h fcommon.h global.h hpt.h hptperl.h \
	  link.h pkt.h post.h scan.h scanarea.h seenby.h toss.h \
	  version.h

# Sources directory
_SRC_DIR= ../src/

# Headers directory
H_DIR	= ../h/

# Binary files(s) to bild from sources
PROGRAMS  = $(PKTINFO) $(TPKT) $(TXT2PKT) $(HPTLINK) $(HPTTREE) $(HPT)

# List of libraries required to build binary file(s)
LIBS	=
