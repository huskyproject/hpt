DEBUG   = 1

OBJS    = hpt.obj pkt.obj common.obj log.obj config.obj global.obj toss.obj dir.obj patmat.obj
SRC_DIR = ..\src

!IF $(DEBUG) == 1
CFLAGS  = -c -I..\h;..\..\smapi -Ss+ -q+ -Ti+ -sa /DEBug /DOS_2
LFLAGS  = -q+ /B"/NOl /DEbug"
!ELSE
CFLAGS  = -O+ -c -I..\h;..\..\smapi -Ss+ -q+ -sa /DOS_2
LFLAGS  = -q+ /B"/NOL"
!ENDIF

all: $(OBJS) \
     pktinfo.exe \
     tlog.exe \
     tconfig.exe \
     hpt.exe

$(OBJS): $(SRC_DIR)\$*.c
  @echo compiling $*.c
  $(CC) $(CFLAGS) $(SRC_DIR)\$*.c

pktinfo.obj tlog.obj tconfig.obj: $(SRC_DIR)\$*.c
  @echo compiling $*.c
  $(CC) $(CFLAGS) $(SRC_DIR)\$*.c

pktinfo.exe: pktinfo.obj common.obj pkt.obj
  @echo linking pktinfo
  $(CC) $(LFLAGS) pktinfo.obj common.obj pkt.obj

tlog.exe: tlog.obj log.obj
  @echo linking tlog
  $(CC) $(LFLAGS) tlog.obj log.obj

tconfig.exe: tconfig.obj config.obj common.obj
  @echo linking tconfig
  $(CC) $(LFLAGS) tconfig.obj config.obj common.obj

hpt.exe: $(OBJS)
  @echo linking hpt
  $(CC) $(LFLAGS) $(OBJS) ..\..\smapi\smapiibo.lib
