DEBUG   = 1
CC      = gcc 

OBJS    = hpt.o pktread.o pktwrite.o fcommon.o log.o global.o toss.o patmat.o scan.o scanarea.o seenby.o
SRC_DIR = ../src/

ifeq ($(DEBUG), 1)
  CFLAGS  = -c -I../h -I../../smapi -I../../fidoconfig -Wall -g -s -DUNIX
  LFLAGS  = 
else
  CFLAGS  = -c -I../h -I../../smapi -Wall -O2 -s -DUNIX $(CADDFLAGS)
  LFLAGS  =  
endif

all: $(OBJS) \
     pktinfo \
     tlog \
     tpkt \
     hpt

%.o: $(SRC_DIR)%.c
	@echo compiling $*.c
	$(CC) $(CFLAGS) $(SRC_DIR)$*.c

pktinfo: pktinfo.o $(OBJS)
	@echo linking pktinfo
	$(CC) $(LFLAGS) -o pktinfo pktinfo.o pktread.o fcommon.o global.o -lsmapilnx -lfidoconfig

tlog: tlog.o log.o
	@echo linking tlog
	$(CC) $(LFLAGS) -o tlog tlog.o log.o

tpkt: tpkt.o pktwrite.o fcommon.o pktread.o
	@echo linking tpkt
	$(CC) $(LFLAGS) -o tpkt tpkt.o fcommon.o pktread.o pktwrite.o global.o -lsmapilnx  -lfidoconfig

hpt: $(OBJS)
	@echo linking hpt
	$(CC) $(LFLAGS) -o hpt $(OBJS) -lsmapilnx -lfidoconfig
