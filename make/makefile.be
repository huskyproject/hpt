# Generic UNIX makefile
# this file requires GNU make

DEBUG=-s
# set to -g for debugging

PERL=0
include makeperl.inc

OBJ    =.o
RM     =rm
DIRSEP =/
CFLAGS =-I../h -I../.. -c  $(DEBUG) $(PERLFLAGS)
LFLAGS =$(DEBUG)
CDEFS  =-DUNIX
CC     =cc
EXENAMEFLAG=-o 
SRC_DIR=../src/
LIBS   =../../fidoconf/libfidoconfigbe.a ../../smapi/libsmapibe.a

default: all
%$(OBJ): $(SRC_DIR)%.c
	$(CC) $(CFLAGS) $(CDEFS) $(SRC_DIR)$*.c

    
include makefile.inc

all: commonprogs

clean: commonclean

distclean: commondistclean
