DEBUG   = 1

OBJS    = hpt.obj pktread.obj pktwrite.obj fcommon.obj log.obj global.obj toss.obj scan.obj scanarea.obj recode.obj seenby.obj dupe.obj areafix.obj tree.obj post.obj
SRC_DIR = ..\src
LIBS    = ..\..\smapi\smapiibo.lib ..\..\fidoconfig\fidoconfig.lib

!IF $(DEBUG) == 1
CFLAGS  = -c -I..\h;..\..\smapi;..\..\fidoconfig -Ss+ -q+ -Ti+ -Sp1 /DEBug /DOS2
LFLAGS  = -q+ /B"/NOl /DEbug"
!ELSE
CFLAGS  = -O+ -c -I..\h;..\..\smapi;..\..\fidoconfig -Ss+ -q+ -Sp1 /DOS2
LFLAGS  = -q+ /B"/NOL"
!ENDIF

all: $(OBJS) \
     pktinfo.exe \
     tlog.exe \
     hpt.exe

$(OBJS): $(SRC_DIR)\$*.c
  @echo compiling $*.c
  $(CC) $(CFLAGS) $(SRC_DIR)\$*.c

pktinfo.obj tlog.obj: $(SRC_DIR)\$*.c
  @echo compiling $*.c
  $(CC) $(CFLAGS) $(SRC_DIR)\$*.c

pktinfo.exe: pktinfo.obj pktread.obj
  @echo linking pktinfo
  $(CC) $(LFLAGS) pktinfo.obj pktread.obj global.obj log.obj $(LIBS)

tlog.exe: tlog.obj log.obj
  @echo linking tlog
  $(CC) $(LFLAGS) tlog.obj log.obj $(LIBS)

hpt.exe: $(OBJS)
  @echo linking hpt
  $(CC) $(LFLAGS) $(OBJS) $(LIBS)
