DEBUG   = 1
# for gcc, use this:
# CC    = gcc -Wall
# for xlc, use this:
CC      = cc -qcpluscmt
INSTDIR = /usr/local/bin
MANDIR  = /usr/local/man

OBJS    = hpt.o pktread.o pktwrite.o fcommon.o log.o global.o toss.o scan.o scanarea.o seenby.o dupe.o tree.o recode.o
SRC_DIR = ../src/

FIDOCONFIG = ../../fidoconfig/fidoconfig.a
SMAPI      = ../../smapi/libsmapiunix.a

ifeq ($(DEBUG), 1)
  CFLAGS  = -c -I../h -I../../smapi -I../../fidoconfig -g -O2 -s -DUNIX
  LFLAGS  = 
else
  CFLAGS  = -c -I../h -I../../smapi -O2 -s -DUNIX $(CADDFLAGS)
  LFLAGS  =  
endif

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
	$(CC) $(LFLAGS) -o pktinfo pktinfo.o pktread.o fcommon.o global.o recode.o $(FIDOCONFIG) $(SMAPI)

tlog: tlog.o log.o
	$(CC) $(LFLAGS) -o tlog tlog.o log.o

tpkt: tpkt.o pktwrite.o fcommon.o pktread.o recode.o
	$(CC) $(LFLAGS) -o tpkt tpkt.o fcommon.o pktread.o pktwrite.o global.o recode.o $(FIDOCONFIG) $(SMAPI)

hpt: $(OBJS)
	$(CC) $(LFLAGS) -o hpt $(OBJS) $(FIDOCONFIG) $(SMAPI) 

purgeDupes: purgeDupes.o global.o dupe.o tree.o pktread.o log.o recode.o
	$(CC) $(LFLAGS) -o purgeDupes purgeDupes.o tree.o pktread.o dupe.o global.o log.o recode.o $(FIDOCONFIG) $(SMAPI)

clean:
	-rm -f *.o
	-rm *~

install:
	install -s hpt pktinfo purgeDupes $(INSTDIR)
	gzip -c hpt.1 > hpt.1.gz
	gzip -c purgeDupes.1 > purgeDupes.1.gz
	install hpt.1.gz purgeDupes.1.gz $(MANDIR)/man1
