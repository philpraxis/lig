#
#	Make the LISP Internet Groper (lig)
#
#	By David Meyer <dmm@1-4-5.net>
#	Copyright 2009 David Meyer
#
#	David Meyer
#	dmm@1-4-5.net
#	Wed Apr  8 13:36:24 2009
#
#	This program is free software; you can redistribute it
#	and/or modify it under the terms of the GNU General
#	Public License as published by the Free Software
#	Foundation; either version 2 of the License, or (at your
#	option) any later version. 
#
#	This program is distributed in the hope that it will be
#	useful,  but WITHOUT ANY WARRANTY; without even the
#	implied warranty of MERCHANTABILITY or FITNESS FOR A
#	PARTICULAR PURPOSE.  See the GNU General Public License
#	for more details. 
#
#	You should have received a copy of the GNU General Public
#	License along with this program; if not, write to the
#	Free Software Foundation, Inc., 59 Temple Place - Suite
#	330, Boston, MA  02111-1307, USA. 
#
#	$Header: /home/dmm/lisp/lig/RCS/Makefile,v 1.11 2009/09/29 02:08:14 dmm Exp $
#

SRC      = lig.c send_map_request.c lib.c cksum.c print.c get_my_ip_addr.c
INC	 = lig.h lig-external.h
OBJ	 = $(SRC:%.c=%.o)
EXE      = lig
#
#	man pages
#
#	man is just a target so you can say 'make man'
MAN	 = man
MANSRC	 = lig.1
MANOUT	 = lig.man
#
#	misc junk
#
RCS      = RCS
MISC     = Makefile README 
#
#	compile/load options
#
CC	 = gcc
CFLAGS   = -Wall -Wno-implicit-function-declaration
LDLIBS   = 
LDFLAGS  = 
#
#
${EXE}: ${OBJ} ${INC} Makefile
	$(CC) -o $@ ${OBJ} $(LDLIBS) $(LDFLAGS)

${MAN}: ${MANSRC}
	groff -t -e -mandoc -Tascii ${MANSRC} | col -bx > ${MANOUT}

clean:
	/bin/rm -f ${OBJ} ${EXE} ${MANOUT} core a.out Make.log Make.err *~

