# Generic UNIX makefile
# this file requires GNU make
# no support for the husky build environment

DEBUG=-s
# set to -g for debugging

OBJ    =.o
RM     =rm
DIRSEP =/
CFLAGS =-I../h -I../.. -c  $(DEBUG)
LFLAGS =$(DEBUG)
CDEFS  =-DUNIX
CC     =cc
EXENAMEFLAG=-o 
SRC_DIR=../src/
LIBS   =../../fidoconf/libfidoconfigbe.a ../../smapi/libsmapibe.a

include ../makefile.inc



