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
	dupe$(_OBJ) query$(_OBJ) areafix$(_OBJ) post$(_OBJ) \
	link$(_OBJ) pktwrite$(_OBJ) carbon$(_OBJ) stat$(_OBJ)

commonall: $(OBJS) \
     pktinfo$(EXE) \
     tpkt$(EXE) \
     txt2pkt$(EXE) \
     hptlink$(EXE) \
     hpttree$(EXE) \
     hpt$(EXE)

%$(_OBJ): $(SRC_DIR)%.c
	$(CC) $(CFLAGS) $(CDEFS) $(SRC_DIR)$*.c

pktinfo$(EXE): pktinfo$(_OBJ) $(OBJS)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) pktinfo$(EXE) pktinfo$(_OBJ) \
          pktread$(_OBJ) fcommon$(_OBJ) global$(_OBJ) dupe$(_OBJ) \
	  $(LIBS)

tpkt$(EXE): tpkt$(_OBJ) pktwrite$(_OBJ) fcommon$(_OBJ) pktread$(_OBJ) \
              global$(_OBJ) 
	$(CC) $(LFLAGS) $(EXENAMEFLAG) tpkt$(EXE) tpkt$(_OBJ) \
              fcommon$(_OBJ) pktread$(_OBJ) pktwrite$(_OBJ) global$(_OBJ) \
              dupe$(_OBJ) $(LIBS)

txt2pkt$(EXE): txt2pkt$(_OBJ) pktwrite$(_OBJ) fcommon$(_OBJ) pktread$(_OBJ) \
               global$(_OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) txt2pkt$(EXE) txt2pkt$(_OBJ) \
          fcommon$(_OBJ) pktread$(_OBJ) pktwrite$(_OBJ) \
          global$(_OBJ) dupe$(_OBJ) $(LIBS)

hptlink$(EXE): hptlink$(_OBJ) global$(_OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) hptlink$(EXE) hptlink$(_OBJ) $(LIBS) global$(_OBJ)

hpttree$(EXE): hpttree$(_OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) hpttree$(EXE) hpttree$(_OBJ) $(LIBS)

hpt$(EXE): $(OBJS)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) hpt$(EXE) $(OBJS) $(LIBS) $(PERLLIBS)

clean:
	-$(RM) $(RMOPT) *$(_OBJ)
	-$(RM) $(RMOPT) core

distclean: clean
	-$(RM) $(RMOPT) tpkt$(EXE)
	-$(RM) $(RMOPT) txt2pkt$(EXE)
	-$(RM) $(RMOPT) pktinfo$(EXE)
	-$(RM) $(RMOPT) hpt$(EXE)
	-$(RM) $(RMOPT) hptlink$(EXE)
	-$(RM) $(RMOPT) hpttree$(EXE)
	-$(RM) $(RMOPT) hpt.1.gz
	-$(RM) $(RMOPT) hptlink.1.gz
	-$(RM) $(RMOPT) hpttree.1.gz
	-$(RM) $(RMOPT) txt2pkt.1.gz

