# common rules for all platforms

VER = 0.2
VERH = 0

commonprogs: pktinfo$(EXE) tpkt$(EXE) txt2pkt$(EXE) hptlink$(EXE) hpttree$(EXE) hpt$(EXE) $(SYMBOLIC)
	$(NULL)

pktinfo$(EXE): pktinfo$(OBJ) pktread$(OBJ) fcommon$(OBJ) global$(OBJ) dupe$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG)pktinfo$(EXE) pktinfo$(OBJ) pktread$(OBJ) fcommon$(OBJ) global$(OBJ) dupe$(OBJ) $(LIBS)

tpkt$(EXE): tpkt$(OBJ) fcommon$(OBJ) pktread$(OBJ) pktwrite$(OBJ) global$(OBJ) dupe$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG)tpkt$(EXE) tpkt$(OBJ) fcommon$(OBJ) pktread$(OBJ) pktwrite$(OBJ) global$(OBJ) dupe$(OBJ) $(LIBS)

txt2pkt$(EXE): txt2pkt$(OBJ) fcommon$(OBJ) pktread$(OBJ) pktwrite$(OBJ) global$(OBJ) dupe$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG)txt2pkt$(EXE) txt2pkt$(OBJ) fcommon$(OBJ) pktread$(OBJ) pktwrite$(OBJ) global$(OBJ) dupe$(OBJ) $(LIBS)

hptlink$(EXE): hptlink$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG)hptlink$(EXE) hptlink$(OBJ) $(LIBS)

hpttree$(EXE): hpttree$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG)hpttree$(EXE) hpttree$(OBJ) $(LIBS)

hpt$(EXE): hpt$(OBJ) pktread$(OBJ) pktwrite$(OBJ) fcommon$(OBJ) global$(OBJ) query$(OBJ) toss$(OBJ) scan$(OBJ) scanarea$(OBJ) post$(OBJ) areafix$(OBJ) arealist$(OBJ) dupe$(OBJ) seenby$(OBJ) link$(OBJ) getfree$(OBJ) $(PERLOBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG)hpt$(EXE) hpt$(OBJ) pktread$(OBJ) pktwrite$(OBJ) fcommon$(OBJ) global$(OBJ) query$(OBJ) toss$(OBJ) scan$(OBJ) scanarea$(OBJ) post$(OBJ) areafix$(OBJ) arealist$(OBJ) dupe$(OBJ) seenby$(OBJ) link$(OBJ) getfree$(OBJ) $(PERLOBJ) $(LIBS) $(PERLLIBS)

commonclean: $(SYMBOLIC)
	-$(RM) *~
	-$(RM) *$(OBJ)
	-$(RM) core

commondistclean: clean $(SYMBOLIC)
	-$(RM) tpkt$(EXE)
	-$(RM) txt2pkt$(EXE)
	-$(RM) pktinfo$(EXE)
	-$(RM) hpt$(EXE)
	-$(RM) hptlink$(EXE)
	-$(RM) hpttree$(EXE)
