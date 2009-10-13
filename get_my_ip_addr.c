/*
 *	get_my_ip_addr.c
 *
 *	By David Meyer <dmm@1-4-5.net>
 *	Copyright 2009 David Meyer
 *
 *	Basically, loop through the interfaces
 *	and take the first non-loopback interface.
 *
 *	NB: doesn't work for IPv6
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Mon Jul  6 09:45:50 2009
 *
 *	This program is free software; you can redistribute it
 *	and/or modify it under the terms of the GNU General
 *	Public License as published by the Free Software
 *	Foundation; either version 2 of the License, or (at your
 *	option) any later version. 
 *
 *	This program is distributed in the hope that it will be
 *	useful,  but WITHOUT ANY WARRANTY; without even the
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A
 *	PARTICULAR PURPOSE.  See the GNU General Public License
 *	for more details. 
 *
 *	You should have received a copy of the GNU General Public
 *	License along with this program; if not, write to the
 *	Free Software Foundation, Inc., 59 Temple Place - Suite
 *	330, Boston, MA  02111-1307, USA. 
 *
 *	$Header: /home/dmm/lisp/lig/RCS/get_my_ip_addr.c,v 1.17 2009/10/13 15:54:08 dmm Exp $
 *
 */


#include	"lig.h"
#include	"lig-external.h"


/*
 *	usable_addr
 *
 *	Basically, don't use the a looback or EID as 
 *	a source address
 *
 */

unsigned int usable_addr(addr)
     char	*addr;
{
    if (disallow_eid)			/* don't allow an EID as the source in the innner IP header */
	return(strcmp(LOOPBACK,addr) && strncmp(V4EID,addr,V4EID_PREFIX_LEN));
    else
	return(strcmp(LOOPBACK,addr));
}

/*
 *	get_my_ip_addr
 *
 *	Get a usable IPv4 address for the source in the inner header in 
 *	the EMR we're about to send.
 *
 *	Probably not POSIX
 *
 */

void get_my_ip_addr(my_addr)
     struct     in_addr *my_addr;
{

    struct	ifaddrs		*ifaddr;
    struct	ifaddrs		*ifa;
    int				afi;

    if (getifaddrs(&ifaddr) == -1) {
	perror("getifaddrs");
	exit(BAD);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
	afi = ifa->ifa_addr->sa_family;
	if (afi == AF_INET) {
	    if (usable_addr(inet_ntoa(((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr))) {
		memcpy((void *) my_addr,
		       (void *) &((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr,
		       sizeof(struct in_addr));
		return;
	    }
	}
    }
    fprintf(stderr, "No usable source address\n");
    exit(BAD);
}


