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
 *	$Header: /home/dmm/lisp/lig/RCS/lib.c,v 1.21 2009/07/06 17:17:21 dmm Exp $
 *
 */


#include	"lig.h"
#include	"lig-external.h"


/*
 *	Print a map_reply packet. The output format matches Dino's
 *	(to the extent possible).
 *
 *
 */

void print_map_reply(map_reply,requested_eid,mr_to,mr_from,elapsed_time,from)
    struct map_reply_pkt *map_reply;
    char *requested_eid;
    char *mr_to;
    char *mr_from;
    long elapsed_time;
    struct in_addr *from;
{

    struct lisp_map_reply_eidtype *eidtype;
    struct lisp_map_reply_loctype *loctype;
    struct in_addr		   *eid;
    struct in_addr		   *locator;
    char			   pw[8];
    int				   offset = 0;
    int				   record_count = 0;
    int				   locator_count = 0;
    int				   i;    
    int				   j;

    printf("Received map-reply from %s with rtt %2.5f sec\n",
	   mr_from, (double) elapsed_time/1000);
    printf("\nMapping entry for EID %s:\n", requested_eid);

    record_count = map_reply->record_count;

    /*
     *	loop through the Records
     */	

    for (i = 0; i < record_count; i++) {
	eidtype = (struct lisp_map_reply_eidtype *) &map_reply->data;
        locator_count = eidtype->loc_count;
	eid = (struct in_addr *) &eidtype->eid_prefix;
	printf("%s/%d,", inet_ntoa(*eid),eidtype->eid_mask_len);
	if (debug) 
	    printf(" via map-reply, record ttl: %d, %s, nonce: 0x%x\n", 
		   ntohl(eidtype->record_ttl), 
		   eidtype->auth_bit ? "auth" : "not auth", 
		   ntohl(map_reply->lisp_nonce));
	else
	    printf(" record ttl: %d\n", ntohl(eidtype->record_ttl)); 

        loctype = (struct lisp_map_reply_loctype *)
	    CO(eidtype->eid_prefix, sizeof(struct in_addr));
	
        printf("  %-18s%-10s%-10s\n","Locator","State","Priority/Weight");

	/*
         * loop through the Loc's (see lig.h)
         */

        for (j = 0; j < locator_count; j++) {
	    locator = (struct in_addr *) &loctype->locator;

            sprintf(pw, "%d/%d", loctype->priority, loctype->weight);
            printf("  %-18s%-10s%-10s\n",
		   inet_ntoa(*locator),
		   loctype->reach_bit ? "up" : "down",
	           pw);
	    /*
             * Find the next "Loc" in this Record
	     *
             *	obviously this needs fixed for IPv6 
             */

            offset = sizeof(struct lisp_map_reply_loctype) + sizeof(struct in_addr);
	    loctype = (struct lisp_map_reply_loctype *) CO(loctype, offset);

	}
    }
}


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
 */

unsigned int get_map_reply(r,packet)
     int    r;
     u_char  *packet;
{

    struct sockaddr_in	 from;
    int                  fromlen = sizeof(struct sockaddr_in);
    struct ip            *iph;
    struct udphdr        *udph;
    struct lisphdr       *lisph;
    struct map_reply_pkt *map_reply;


    memset(packet, 0, MAX_IP_PACKET);
    memset((char *) &from, 0, sizeof(from));

    from.sin_family      = AF_INET;
    from.sin_port        = htons(0);
    from.sin_addr.s_addr = INADDR_ANY;

    if (recvfrom(r,
		 packet,
		 MAX_IP_PACKET,
		 0,
		 (struct sockaddr *) &from,
		 &fromlen) < 0) {
	perror("recvfrom");
	exit(BAD);
    }

 
    /*
     *  LISP control packet ?
     */

    iph = (struct ip *) packet;
    udph      = (struct udphdr *) CO(iph, sizeof(struct ip)); 
    map_reply = (struct map_reply_pkt *) CO(udph, sizeof(struct udphdr));

#ifdef BSD
    if (ntohs(udph->uh_sport) != LISP_CONTROL_PORT) {
#else
    if (ntohs(udph->source) != LISP_CONTROL_PORT) {
#endif
	if (debug)
	    printf("Packet is not a Map-Reply. Source Port = %d\n",
#ifdef BSD
		   ntohs(udph->uh_sport));
#else
		   ntohs(udph->source));
#endif
	return(0);			/* not a map-reply */
    } else
	return(1);			/* is a map-reply */
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

