HASHDUPE = 0
DEBUG    = 1
CC       = gcc 
INSTDIR  = /usr/local/bin
MANDIR   = /usr/local/man

OBJS    = hpt.o pktread.o pktwrite.o fcommon.o log.o global.o toss.o scan.o scanarea.o seenby.o crc.o dupe.o tree.o recode.o areafix.o post.o link.o strsep.o
SRC_DIR = ../src/

ifeq ($(HASHDUPE), 1)

ifeq ($(DEBUG), 1)
  CFLAGS  = -c -I../h -I../../fidoconfig -I../h -I../../smapi -Wall -ggdb -O3 -DUNIX -DHASHDUPE
  LFLAGS  =
else
  CFLAGS  = -c -I../h -I../../smapi -Wall -O3 -s -DUNIX -DHASHDUPE
  LFLAGS  =  
endif

else

ifeq ($(DEBUG), 1)
  CFLAGS  = -c -I../h -I../../fidoconfig -I../h -I../../smapi -Wall -ggdb -O6 -DUNIX
  LFLAGS  =
else
  CFLAGS  = -c -I../h -I../../smapi -Wall -O3 -s -DUNIX
  LFLAGS  =  
endif

endif

ifeq ($(HASHDUPE), 1)
all: $(OBJS) \
     pktinfo \
     tlog \
     tpkt \
     txt2pkt \
     hpt
else
all: $(OBJS) \
     pktinfo \
     tlog \
     tpkt \
     txt2pkt \
     hpt \
     purgeDupes 
endif

%.o: $(SRC_DIR)%.c
	$(CC) $(CFLAGS) $(SRC_DIR)$*.c

pktinfo: pktinfo.o $(OBJS)
	$(CC) $(LFLAGS) -o pktinfo log.o recode.o pktinfo.o pktread.o fcommon.o global.o -lsmapilnx -lfidoconfig

tlog: tlog.o log.o
	$(CC) $(LFLAGS) -o tlog tlog.o log.o

tpkt: tpkt.o pktwrite.o fcommon.o pktread.o recode.o log.o global.o 
	$(CC) $(LFLAGS) -o tpkt log.o tpkt.o fcommon.o pktread.o recode.o pktwrite.o global.o -lsmapilnx  -lfidoconfig

txt2pkt: txt2pkt.o pktwrite.o fcommon.o pktread.o recode.o log.o global.o 
	$(CC) $(LFLAGS) -o txt2pkt log.o txt2pkt.o fcommon.o pktread.o recode.o pktwrite.o global.o -lsmapilnx  -lfidoconfig

hpt: $(OBJS)
	$(CC) $(LFLAGS) -o hpt $(OBJS) -lsmapilnx -lfidoconfig 

ifeq ($(HASHDUPE), 0)
purgeDupes: purgeDupes.o global.o dupe.o tree.o pktread.o log.o recode.o
	$(CC) $(LFLAGS) -o purgeDupes purgeDupes.o tree.o pktread.o recode.o dupe.o global.o log.o -lfidoconfig -lsmapilnx
endif

clean:
	-rm -f *.o
	-rm *~
	-rm core

distclean: clean
ifeq ($(HASHDUPE), 0)
	-rm tpkt txt2pkt pktinfo hpt purgeDupes tlog
else
	-rm tpkt txt2pkt pktinfo hpt tlog
endif
	-rm *.1.gz
	-rm *.log

install:
	gzip -c hpt.1 > hpt.1.gz
ifeq ($(HASHDUPE), 0)
	install -s hpt pktinfo purgeDupes txt2pkt $(INSTDIR)
	gzip -c purgeDupes.1 > purgeDupes.1.gz
	install hpt.1.gz purgeDupes.1.gz $(MANDIR)/man1
else
	install -s hpt pktinfo txt2pkt $(INSTDIR)
	install hpt.1.gz $(MANDIR)/man1
endif
