/*
 *	lig-lib.c
 *
 *	Various library routines
 * 
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr 23 15:37:01 2009
 *
 *	$Header: /home/dmm/lisp/lig/RCS/lib.c,v 1.32 2009/08/24 16:15:13 dmm Exp $
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
	u_char			*packet;
	struct sockaddr_in	*from;

{

    int fromlen = sizeof(struct sockaddr_in);

    memset((char *) &from, 0, sizeof(from));

    if (recvfrom(r,
		 packet,
		 MAX_IP_PACKET,
		 0,
		 (struct sockaddr *) from,
		 &fromlen) < 0) {
	perror("recvfrom");
	exit(BAD);
    }
 
    if (debug)
	printf("Received packet from <%s:%d>\n",
	       inet_ntoa(from->sin_addr),
	       ntohs(from->sin_port));
}

/*
 *	find the matching nonce, if any
 */

find_nonce(rnonce, nonce, count)
 unsigned int rnonce;
 unsigned int *nonce;
 int   count;

{
    int i;

    for (i = 0; i <= count; i++) {
	if (rnonce == nonce[i]) {
	    return(1);			/* good nonce */
	}
    }
    return(0);				/* nope...*/
}

