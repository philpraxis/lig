#
#	Make the LISP Internet Grouper (lig)
#
#	
#
#	David Meyer
#	dmm@1-4-5.net
#	Wed Apr  8 13:36:24 2009
#
#	$Header: /home/dmm/lisp/lig/RCS/Makefile,v 1.8 2009/07/06 17:17:51 dmm Exp $
#


SRC      = lig.c send_map_request.c lib.c cksum.c print.c get_my_ip_addr.c
INC	 = lig.h lig-external.h
OBJ	 = $(SRC:%.c=%.o)
EXE      = lig

RCS      = RCS
MISC     = Makefile README 

CC	 = gcc
CFLAGS   = -g -DDEBUG=3
LDLIBS   = 
LDFLAGS  = 

${EXE}: ${OBJ} ${INC} Makefile
	$(CC) -o $@ ${OBJ} $(LDLIBS) $(LDFLAGS)

clean:
	/bin/rm -f ${OBJ} ${EXE} core a.out Make.log Make.err *~

