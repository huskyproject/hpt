DEBUG   = 1
GNULIBC = 2
CC      = gcc 

OBJS    = hpt.o pktread.o pktwrite.o common.o log.o config.o global.o toss.o patmat.o scan.o scanarea.o seenby.o
SRC_DIR = ../src/

ifeq ($(GNULIBC),2)
  CADDFLAGS = -I/usr/lib/gcc-lib/i586-pc-linux-gnulibc2/2.8.0/include -b i586-pc-linux-gnulibc2
  LADDFLAGS = -b i586-pc-linux-gnulibc2
else
  CADDFLAGS =
  LADDFLAGS =
endif

ifeq ($(DEBUG), 1)
  CFLAGS  = -c -I../h -I../../smapi -Wall -g -s -DUNIX $(CADDFLAGS)
  LFLAGS  = $(LADDFLAGS)
else
  CFLAGS  = -c -I../h -I../../smapi -Wall -O2 -s -DUNIX $(CADDFLAGS)
  LFLAGS  = $(LADDFLAGS)
endif

all: $(OBJS) \
     pktinfo \
     tlog \
     tconfig \
     tpkt \
     hpt

%.o: $(SRC_DIR)%.c
	@echo compiling $*.c
	$(CC) $(CFLAGS) $(SRC_DIR)$*.c

pktinfo: pktinfo.o $(OBJS)
	@echo linking pktinfo
	$(CC) $(LFLAGS) -o pktinfo pktinfo.o pktread.o common.o global.o ../../smapi/smapilnx.a

tconfig: tconfig.o config.o common.o
	@echo linking tconfig
	$(CC) $(LFLAGS) -o tconfig tconfig.o config.o common.o global.o ../../smapi/smapilnx.a

tlog: tlog.o log.o
	@echo linking tlog
	$(CC) $(LFLAGS) -o tlog tlog.o log.o

tpkt: tpkt.o pktwrite.o common.o pktread.o
	@echo linking tpkt
	$(CC) $(LFLAGS) -o tpkt tpkt.o common.o pktread.o pktwrite.o global.o ../../smapi/smapilnx.a

hpt: $(OBJS)
	@echo linking hpt
	$(CC) $(LFLAGS) -o hpt $(OBJS) ../../smapi/smapilnx.a
