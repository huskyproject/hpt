# for gcc, use this:
# CC    = gcc -Wall
# for xlc, use this:
CC      = cc
INSTDIR = $(HOME)/fido/bin
MANDIR  = $(HOME)/fido/man
LIBDIR  = $(HOME)/fido/lib

OBJS    = hpt.o pktread.o pktwrite.o fcommon.o log.o global.o toss.o scan.o scanarea.o seenby.o dupe.o tree.o recode.o areafix.o post.o strsep.o link.o
SRC_DIR = ../src/

CFLAGS     = -c -I../../fidoconfig -I../../smapi -I../h -O2 -s -DUNIX
LFLAGS     = -L$(LIBDIR)
FIDOCONFIG = -lfidoconfig
SMAPI      = -lsmapiunix


all: $(OBJS) \
     pktinfo \
     tlog \
     tpkt \
     hpt \
     purgeDupes 
#     install

%.o: $(SRC_DIR)%.c
	$(CC) $(CFLAGS) $(SRC_DIR)$*.c

pktinfo: pktinfo.o $(OBJS)
	$(CC) $(LFLAGS) -o pktinfo log.o pktinfo.o pktread.o fcommon.o global.o recode.o $(FIDOCONFIG) $(SMAPI)

tlog: tlog.o log.o
	$(CC) $(LFLAGS) -o tlog tlog.o log.o

tpkt: tpkt.o pktwrite.o log.o fcommon.o pktread.o recode.o
	$(CC) $(LFLAGS) -o tpkt tpkt.o fcommon.o pktread.o pktwrite.o global.o recode.o log.o $(FIDOCONFIG) $(SMAPI)

hpt: $(OBJS)
	$(CC) $(LFLAGS) -o hpt $(OBJS) $(FIDOCONFIG) $(SMAPI) 

purgeDupes: purgeDupes.o global.o dupe.o tree.o pktread.o log.o recode.o
	$(CC) $(LFLAGS) -o purgeDupes purgeDupes.o tree.o pktread.o dupe.o global.o log.o recode.o $(FIDOCONFIG) $(SMAPI)

clean:
	-rm -f *.o
	-rm *~

distclean: clean
	-rm purgeDupes hpt tpkt tlog pktinfo

install:
	cp  hpt pktinfo purgeDupes $(INSTDIR)
	cp  ../linux/hpt.1 $(MANDIR)/man1
	cp  ../linux/purgeDupes.1 $(MANDIR)/man1

