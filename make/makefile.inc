# common rules for all platforms

VER = 0.1
VERH = 0

OBJS = hpt$(OBJ) pktread$(OBJ) pktwrite$(OBJ) fcommon$(OBJ) log$(OBJ) global$(OBJ) toss$(OBJ) scan$(OBJ) scanarea$(OBJ) post$(OBJ) areafix$(OBJ) arealist$(OBJ) dupe$(OBJ) recode$(OBJ) tree$(OBJ) seenby$(OBJ) strsep$(OBJ) link$(OBJ) crc$(OBJ) pktinfo$(OBJ) txt2pkt$(OBJ) tpkt$(OBJ) hptlink$(OBJ) hpttree$(OBJ)

commonprogs: pktinfo$(EXE) tpkt$(EXE) txt2pkt$(EXE) hptlink$(EXE) hpttree$(EXE) hpt$(EXE)	 $(SYMBOLIC)
	$(NULL)

pktinfo$(EXE): log$(OBJ) recode$(OBJ) pktinfo$(OBJ) pktread$(OBJ) fcommon$(OBJ) global$(OBJ) dupe$(OBJ) tree$(OBJ) crc$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG)pktinfo$(EXE) log$(OBJ) recode$(OBJ) pktinfo$(OBJ) pktread$(OBJ) fcommon$(OBJ) global$(OBJ) dupe$(OBJ) tree$(OBJ) crc$(OBJ) $(LIBS)

tpkt$(EXE): log$(OBJ) tpkt$(OBJ) fcommon$(OBJ) pktread$(OBJ) recode$(OBJ) pktwrite$(OBJ) global$(OBJ) dupe$(OBJ) tree$(OBJ) crc$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG)tpkt$(EXE) log$(OBJ) tpkt$(OBJ) fcommon$(OBJ) pktread$(OBJ) recode$(OBJ) pktwrite$(OBJ) global$(OBJ) dupe$(OBJ) tree$(OBJ) crc$(OBJ) $(LIBS)

txt2pkt$(EXE): log$(OBJ) txt2pkt$(OBJ) fcommon$(OBJ) pktread$(OBJ) recode$(OBJ) pktwrite$(OBJ) global$(OBJ) dupe$(OBJ) tree$(OBJ) crc$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG)txt2pkt$(EXE) log$(OBJ) txt2pkt$(OBJ) fcommon$(OBJ) pktread$(OBJ) recode$(OBJ) pktwrite$(OBJ) global$(OBJ) dupe$(OBJ) tree$(OBJ) crc$(OBJ) $(LIBS)

hptlink$(EXE): hptlink$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG)hptlink$(EXE) hptlink$(OBJ) $(LIBS)

hpttree$(EXE): hpttree$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG)hpttree$(EXE) hpttree$(OBJ) $(LIBS)

hpt$(EXE): hpt$(OBJ) pktread$(OBJ) pktwrite$(OBJ) fcommon$(OBJ) log$(OBJ) global$(OBJ) toss$(OBJ) scan$(OBJ) scanarea$(OBJ) post$(OBJ) areafix$(OBJ) arealist$(OBJ) dupe$(OBJ) recode$(OBJ) tree$(OBJ) seenby$(OBJ) strsep$(OBJ) link$(OBJ) crc$(OBJ)
	$(CC) $(LFLAGS) $(EXENAMEFLAG)hpt$(EXE) hpt$(OBJ) pktread$(OBJ) pktwrite$(OBJ) fcommon$(OBJ) log$(OBJ) global$(OBJ) toss$(OBJ) scan$(OBJ) scanarea$(OBJ) post$(OBJ) areafix$(OBJ) arealist$(OBJ) dupe$(OBJ) recode$(OBJ) tree$(OBJ) seenby$(OBJ) strsep$(OBJ) link$(OBJ) crc$(OBJ) $(LIBS)

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
