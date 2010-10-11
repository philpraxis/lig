/*
 *	get_my_ip_addr.c
 *
 *	By David Meyer <dmm@1-4-5.net>
 *	Copyright 2009 David Meyer
 *
 *	Basically, loop through the interfaces
 *	and take the first non-loopback interface.
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Mon Jul  6 09:45:50 2009
 *
 *	IPv6 support added by Lorand Jakab <lj@icanhas.net>
 *	Mon Aug 23 15:26:51 2010 +0200
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
 *	$Header: /home/dmm/lisp/lig/RCS/get_my_ip_addr.c,v 1.18 2010/02/27 19:10:17 dmm Exp $
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
     struct sockaddr	*addr;
{
    char buf[NI_MAXHOST];
    int e;

    if ((e = getnameinfo(addr,SA_LEN(addr->sa_family),
		    buf,NI_MAXHOST,NULL,0,NI_NUMERICHOST)) != 0) {
	fprintf(stderr,"getnameinfo: %s\n",gai_strerror(e));
	exit(BAD);
    }

    if (disallow_eid)			/* don't allow an EID as the source in the innner IP header */
	return(strcmp(LOOPBACK,buf) && strcmp(LOOPBACK6,buf) &&
		strncmp(LINK_LOCAL,buf,LINK_LOCAL_LEN) &&
		strncmp(V4EID,buf,V4EID_PREFIX_LEN) &&
		strncmp(V6EID,buf,V6EID_PREFIX_LEN));
    else
	return(strcmp(LOOPBACK,buf) && strcmp(LOOPBACK6,buf) &&
		strncmp(LINK_LOCAL,buf,LINK_LOCAL_LEN));
}

/*
 *	get_my_ip_addr
 *
 *	Get a usable address for the source in the inner header in 
 *	the EMR we're about to send.
 *
 *	Probably not POSIX
 *
 */

int get_my_ip_addr(afi,my_addr)
     int		    afi;
     struct     sockaddr    *my_addr;
{

    struct	ifaddrs		*ifaddr;
    struct	ifaddrs		*ifa;

    if (getifaddrs(&ifaddr) == -1) {
	perror("getifaddrs");
	exit(BAD);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
	if (ifa->ifa_addr == NULL)
	    continue;
	if (ifa->ifa_addr->sa_family != afi )
	    continue;
	if (usable_addr(ifa->ifa_addr)) {
	    memcpy((void *) my_addr,ifa->ifa_addr,SA_LEN(afi));
	    freeifaddrs(ifaddr);
	    return 0;
	}
    }

    freeifaddrs(ifaddr);
    return -1;
}


