CC    = gcc -Wall
INSTDIR = /usr/local/bin
MANDIR  = /usr/local/man
LIBDIR  = /usr/local/lib

OBJS    = hpt.o pktread.o pktwrite.o fcommon.o log.o global.o toss.o scan.o scanarea.o seenby.o dupe.o tree.o recode.o areafix.o post.o link.o strsep.o crc.o
SRC_DIR = ../src/
CDIR = ../linux

CFLAGS     = -c -I ../../fidoconfig -I ../../smapi -I ../h -O2 -pipe -DUNIX
LFLAGS     = -L $(LIBDIR) -L ../../smapi -L ../../fidoconfig
FIDOCONFIG = -lfidoconfig
SMAPI      = -lsmapibsd

IOPT  = -c -m 644 -o bin -g bin
IBOPT = -s -c -m 755 -o bin -g bin

ALLBIN = pktinfo tlog tpkt hpt purgeDupes

all: $(ALLBIN)

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
	-rm -f *.o *.1.gz $(ALLBIN)
	-rm *~

install:
	install $(IBOPT) $(ALLBIN) $(INSTDIR)
	gzip -c $(CDIR)/hpt.1 > hpt.1.gz
	gzip -c $(CDIR)/purgeDupes.1 > purgeDupes.1.gz
	install $(IOPT) hpt.1.gz purgeDupes.1.gz $(MANDIR)/man1
