DEBUG   = 1
CC      = gcc 
INSTDIR = /usr/local/bin
MANDIR  = /usr/local/man

OBJS    = hpt.o pktread.o pktwrite.o fcommon.o log.o global.o toss.o scan.o scanarea.o seenby.o dupe.o tree.o recode.o areafix.o
SRC_DIR = ../src/

ifeq ($(DEBUG), 1)
  CFLAGS  = -c -I../h -I../../smapi -I../../fidoconfig -Wall -ggdb -O3 -s -DUNIX
  LFLAGS  = 
else
  CFLAGS  = -c -I../h -I../../smapi -Wall -O2 -s -DUNIX
  LFLAGS  =  
endif

all: $(OBJS) \
     pktinfo \
     tlog \
     tpkt \
     hpt \
     purgeDupes 

%.o: $(SRC_DIR)%.c
	$(CC) $(CFLAGS) $(SRC_DIR)$*.c

pktinfo: pktinfo.o $(OBJS)
	$(CC) $(LFLAGS) -o pktinfo log.o recode.o pktinfo.o pktread.o fcommon.o global.o -lsmapilnx -lfidoconfig

tlog: tlog.o log.o
	$(CC) $(LFLAGS) -o tlog tlog.o log.o

tpkt: tpkt.o pktwrite.o fcommon.o pktread.o recode.o log.o global.o 
	$(CC) $(LFLAGS) -o tpkt log.o tpkt.o fcommon.o pktread.o recode.o pktwrite.o global.o -lsmapilnx  -lfidoconfig

hpt: $(OBJS)
	$(CC) $(LFLAGS) -o hpt $(OBJS) -lsmapilnx -lfidoconfig

purgeDupes: purgeDupes.o global.o dupe.o tree.o pktread.o log.o recode.o
	$(CC) $(LFLAGS) -o purgeDupes purgeDupes.o tree.o pktread.o recode.o dupe.o global.o log.o -lfidoconfig -lsmapilnx

clean:
	-rm -f *.o
	-rm *~

distclean: clean
	-rm tpkt pktinfo hpt purgeDupes tlog
	-rm *.1.gz
	-rm *.log

install:
	install -s hpt pktinfo purgeDupes $(INSTDIR)
	gzip -c hpt.1 > hpt.1.gz
	gzip -c purgeDupes.1 > purgeDupes.1.gz
	install hpt.1.gz purgeDupes.1.gz $(MANDIR)/man1
