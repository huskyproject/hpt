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

OBJS    = fcommon$(OBJ) getfree$(OBJ) hpt$(OBJ) pktread$(OBJ) pktwrite$(OBJ) \
	  log$(OBJ) global$(OBJ) toss$(OBJ) scan$(OBJ) scanarea$(OBJ) \
	  seenby$(OBJ) crc$(OBJ) dupe$(OBJ) tree$(OBJ) recode$(OBJ) query$(OBJ) \
	  areafix$(OBJ) arealist$(OBJ) post$(OBJ) link$(OBJ) strsep$(OBJ) \
	  $(PERLOBJ)


commonall: $(OBJS) \
     pktinfo$(EXE) \
     tpkt$(EXE) \
     txt2pkt$(EXE) \
     hptlink$(EXE) \
     hpttree$(EXE) \
     hpt$(EXE)

%$(OBJ): $(SRC_DIR)%.c
	$(CC) $(CFLAGS) $(CDEFS) $(SRC_DIR)$*.c

pktinfo$(EXE): pktinfo$(OBJ) $(OBJS)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) pktinfo$(EXE) log$(OBJ) recode$(OBJ) pktinfo$(OBJ) \
          pktread$(OBJ) fcommon$(OBJ) global$(OBJ) dupe$(OBJ) tree$(OBJ) \
	  crc$(OBJ) $(LIBS)

tpkt$(EXE): tpkt$(OBJ) pktwrite$(OBJ) fcommon$(OBJ) pktread$(OBJ) \
              recode$(OBJ) log$(OBJ) global$(OBJ) 
	$(CC) $(LFLAGS) $(EXENAMEFLAG) tpkt$(EXE) log$(OBJ) tpkt$(OBJ) fcommon$(OBJ) \
              pktread$(OBJ) recode$(OBJ) pktwrite$(OBJ) global$(OBJ) \
              dupe$(OBJ) tree$(OBJ) crc$(OBJ) $(LIBS)

txt2pkt$(EXE): txt2pkt$(OBJ) pktwrite$(OBJ) fcommon$(OBJ) pktread$(OBJ) \
               recode$(OBJ) log$(OBJ) global$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) txt2pkt$(EXE) log$(OBJ) txt2pkt$(OBJ) \
          fcommon$(OBJ) pktread$(OBJ) recode$(OBJ) pktwrite$(OBJ) \
          global$(OBJ) dupe$(OBJ) tree$(OBJ) crc$(OBJ) $(LIBS)

hptlink$(EXE): hptlink$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) hptlink$(EXE) hptlink$(OBJ) $(LIBS)

hpttree$(EXE): hpttree$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) hpttree$(EXE) hpttree$(OBJ) $(LIBS)

hpt$(EXE): $(OBJS)
	$(CC) $(LFLAGS) $(EXENAMEFLAG) hpt$(EXE) $(OBJS) $(LIBS) $(PERLLIBS)

clean:
	-$(RM) *$(OBJ)
	-$(RM) *~
	-$(RM) core

distclean: clean
	-$(RM) tpkt$(EXE)
	-$(RM) txt2pkt$(EXE)
	-$(RM) pktinfo$(EXE)
	-$(RM) hpt$(EXE)
	-$(RM) hptlink$(EXE)
	-$(RM) hpttree$(EXE)
	-$(RM) hpt.1.gz
	-$(RM) hptlink.1.gz
	-$(RM) hpttree.1.gz

