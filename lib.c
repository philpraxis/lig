/*
 *	lib.c
 *
 *	Various lig library routines
 *
 *	By David Meyer <dmm@1-4-5.net>
 *	Copyright 2009 David Meyer
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr 23 15:37:01 2009
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
 *	$Header: /home/dmm/lisp/lig/RCS/lib.c,v 1.41 2009/09/18 02:28:45 dmm Exp $
 *
 */


#include	"lig.h"
#include	"lig-external.h"


/*
 *	tvdiff(last,first) --
 *
 *	Return the difference of 2 timeval structs in ms. Assume
 *	last >= first or its 0.
 *
 */

long tvdiff(last,first)
	struct timeval *last; 
	struct timeval *first;
{

  long	diff;

  diff = ((last->tv_sec - first->tv_sec) * 1000) +
         ((last->tv_usec - first->tv_usec)/1000);

  return((diff > 0) ? diff : 0);
}

/*
 *	wait_for_response(s)
 *
 *	Wait for a response on socket s
 *
 */

wait_for_response(s,timeout)
  int s;
  int timeout;
{

    struct timeval tv;
    fd_set         readfds;

    tv.tv_sec  = 0;
    tv.tv_usec = timeout*1000;		/* timeout is in ms */

    FD_ZERO(&readfds);
    FD_SET(s,&readfds);

    if (select(s+1,&readfds,NULL,NULL,&tv) == -1) {
	perror("select");
	exit(BAD);
    } 
    if (FD_ISSET(s,&readfds)) 
	return(1);		    /* got something */
    else 
	return(0);		    /* else we timed out */
}

/*
 *	Retrieve a map-reply from socket r
 *
 *	Since we currently have to receive on a raw socket, peek the 
 *	packet and only read it if its actually a map-reply (i.e., has
 *	source 4342.
 *
 */

void get_map_reply(r,packet, from)
	int			r;
	uchar			*packet;
	struct sockaddr_in	*from;

{

    int fromlen = sizeof(struct sockaddr_in);

    memset((char *) from, 0, sizeof(*from));

    if (recvfrom(r,
		 packet,
		 MAX_IP_PACKET,
		 0,
		 (struct sockaddr *) from,
		 &fromlen) < 0) {
	perror("recvfrom");
	exit(BAD);
    }
 
    if (debug > 2)
	printf("Received packet from <%s:%d>\n",
	       inet_ntoa(from->sin_addr),
	       ntohs(from->sin_port));
}


/*
 *	build_nonce 
 *
 *	Build 64 bit nonce per draft-ietf-lisp-04.txt and RFC 4086. 
 *
 *	Use a simple algorithm (see below).
 *
 */

void build_nonce(nonce0,nonce1)
     unsigned int	*nonce0;
     unsigned int	*nonce1;
{
    *nonce0 = random()^random();
    *nonce1 = random()^time(NULL);
}


/*
 *	find_nonce --
 *
 *	Find the matching nonce, if any. Note that the
 *	nonce is two unsigned ints, so the two ints are
 *	at (2*i) and [(2*i)+1]
 *	
 *
 *	09/10/2009:	nonce increased to 64 bits
 */

find_nonce(map_reply, nonce, count)
  struct   map_reply_pkt *map_reply;
  unsigned int	         *nonce;
  int		          count;

{
    int i;

    for (i = 0; i <= count; i++) {
	if ((ntohl(map_reply->lisp_nonce0) == nonce[(2*i)]) &&
	    (ntohl(map_reply->lisp_nonce1) == nonce[(2*i)+1])) {
	    return(1);			/* good nonce */
	}
    }	  
    return(0);				/* nope...*/
}

