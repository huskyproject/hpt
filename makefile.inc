# you must  define at least the following variables if you want to
# include this file:
#OBJ    =.o
#RM     =rm
#DIRSEP =/
#CFLAGS =-I../h -I../.. -c
#LFLAGS =-s
#CDEFS  =-DUNIX
#CC     =gcc
EXENAMEFLAG=-o
#SRC_DIR=../src/
#LIBS   =-L$(LIBDIR) -lfidoconfig -lsmapi

OBJS	= $(PERLOBJ) fcommon$(_OBJ) hpt$(_OBJ) pktread$(_OBJ) \
	global$(_OBJ) toss$(_OBJ) scan$(_OBJ) scanarea$(_OBJ) seenby$(_OBJ) \
	dupe$(_OBJ) hptafix$(_OBJ) post$(_OBJ) \
	link$(_OBJ) pktwrite$(_OBJ) carbon$(_OBJ)

commonall: $(OBJS) \
     pktinfo$(_EXE) \
     tpkt$(_EXE) \
     txt2pkt$(_EXE) \
     hptlink$(_EXE) \
     hpttree$(_EXE) \
     hpt$(_EXE)

%$(_OBJ): $(SRC_DIR)%.c
	$(CC) $(CFLAGS) $(CDEFS) $(SRC_DIR)$*.c

pktinfo$(_EXE): pktinfo$(_OBJ) $(OBJS)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) pktinfo$(_EXE) pktinfo$(_OBJ) \
          pktread$(_OBJ) fcommon$(_OBJ) global$(_OBJ) dupe$(_OBJ) \
	  $(LIBS)

tpkt$(_EXE): tpkt$(_OBJ) pktwrite$(_OBJ) fcommon$(_OBJ) pktread$(_OBJ) \
              global$(_OBJ) 
	$(CC) $(LFLAGS) $(EXENAMEFLAG) tpkt$(_EXE) tpkt$(_OBJ) \
              fcommon$(_OBJ) pktread$(_OBJ) pktwrite$(_OBJ) global$(_OBJ) \
              dupe$(_OBJ) $(LIBS)

txt2pkt$(_EXE): txt2pkt$(_OBJ) pktwrite$(_OBJ) fcommon$(_OBJ) pktread$(_OBJ) \
               global$(_OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) txt2pkt$(_EXE) txt2pkt$(_OBJ) \
          fcommon$(_OBJ) pktread$(_OBJ) pktwrite$(_OBJ) \
          global$(_OBJ) dupe$(_OBJ) $(LIBS)

hptlink$(_EXE): hptlink$(_OBJ) global$(_OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) hptlink$(_EXE) hptlink$(_OBJ) $(LIBS) global$(_OBJ)

hpttree$(_EXE): hpttree$(_OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) hpttree$(_EXE) hpttree$(_OBJ) $(LIBS)

hpt$(_EXE): $(OBJS)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) hpt$(_EXE) $(OBJS) $(LIBS) $(PERLLIBS)

clean:
	-$(RM) $(RMOPT) *$(_OBJ)
	-$(RM) $(RMOPT) core

distclean: clean
	-$(RM) $(RMOPT) tpkt$(_EXE)
	-$(RM) $(RMOPT) txt2pkt$(_EXE)
	-$(RM) $(RMOPT) pktinfo$(_EXE)
	-$(RM) $(RMOPT) hpt$(_EXE)
	-$(RM) $(RMOPT) hptlink$(_EXE)
	-$(RM) $(RMOPT) hpttree$(_EXE)
	-$(RM) $(RMOPT) hpt.1.gz
	-$(RM) $(RMOPT) hptlink.1.gz
	-$(RM) $(RMOPT) hpttree.1.gz
	-$(RM) $(RMOPT) txt2pkt.1.gz

