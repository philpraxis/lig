/* 
 *	lig.c --
 * 
 *	lig -- LISP Internet Grouper
 *
 *	By David Meyer <dmm@1-4-5.net>
 *	Copyright 2009 David Meyer
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr  9 09:44:57 2009
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
 *	$Header: /home/dmm/lisp/lig/RCS/lig.c,v 1.88 2009/10/07 21:15:08 dmm Exp $
 *
 */

#include	"lig.h"
#include	"lig-external.h"

/*
 *	globals
 */

int			s;			/* send socket */
int			r;			/* receive socket */
int			debug    = 0;
unsigned int		*nonce;
struct   sockaddr_in	map_resolver_addr;
uchar			packet[MAX_IP_PACKET];

/*
 *	use these to construct and parse packets
 */

struct ip		*iph;
struct udphdr		*udph;
struct lisphdr		*lisph;
struct map_reply_pkt	*map_reply;

int main(int argc, char *argv[])
{

    struct hostent	*hostent;
    struct timeval	before;
    struct timeval	after;
    struct protoent	*proto;
    struct sockaddr_in	 me;
    struct sockaddr_in	 from;
    struct in_addr	my_addr; 

    /*
     * Remember the requested eid and map resolver properties here 
     */

    char *eid		= NULL;
    char *src_ip_addr	= NULL;
    char *eid_name	= NULL;
    char *mr_name	= NULL;
    char *progname	= NULL;
    char *map_resolver	= getenv(DEFAULT_MAP_RESOLVER); /* check for env var */
    int  eid_addrtype	= 0;
    int  eid_length	= 0;
    int  mr_addrtype	= 0;
    int  mr_length	= 0;

    int i		= 0;		/* generic counter */
    unsigned int port	= 0;		/* if -p <port> specified, put it in here to find overflow */
    unsigned int iseed;			/* initial random number generator */
    unsigned int nonce0;
    unsigned int nonce1;   

    /*
     *	parse args
     */  

    int  opt           = 0;
    char *optstring    = "c:dm:p:t:s:v";
    int  count         = COUNT;
    int	 timeout       = MAP_REPLY_TIMEOUT;

    emr_inner_src_port = 0;		

    while ((opt = getopt (argc, argv, optstring)) != EOF) {
	switch (opt) {
	case 'c':
	    count = atoi(optarg);
	    if ((count < MIN_COUNT) || (count > MAX_COUNT)) {
		fprintf(stderr,
			"%s: Invalid number, specify count in the range (%u:%u)\n",
			argv[0], MIN_COUNT,MAX_COUNT);
		exit(BAD);
	    }
	    break;
	case 'd':
	    debug = 1;
	    break;
	case 'p':
	    if ((port = atoi(optarg)) > MAX_EPHEMERAL_PORT) {
		fprintf(stderr, "%s: Invalid port (%d)\n", argv[0], port);
		exit(BAD);
	    }
	    emr_inner_src_port = (ushort) port;
	    break;
	case 'm':
	    if ((map_resolver = strdup(optarg)) == NULL) {
		perror ("strdup(map_resolver)");
		exit(BAD);
	    }
	    break;
	case 's':
	    if ((src_ip_addr = strdup(optarg)) == NULL) {
		perror ("strdup(src_ip_addr)");
		exit(BAD);
	    }
	    break;
	case 't':
	    timeout = atoi(optarg);		/* seconds */
	    if ((timeout < MIN_MR_TIMEOUT) || (timeout > MAX_MR_TIMEOUT)) {
		fprintf(stderr,
			"%s: Invalid number, specify timeout in the range (%u:%u) seconds\n",
			argv[0], MIN_MR_TIMEOUT,MAX_MR_TIMEOUT);
		exit(BAD);
	    }
	    break;
	case 'v':
	    fprintf(stderr, VERSION, argv[0]);
	    exit (GOOD);
	default:
	    fprintf(stderr, USAGE, argv[0]);
	    exit (BAD);
	}
    }

    /* 
     *	save the program name somewhere
     */

    if ((progname  = strdup(argv[0])) == NULL) {
	perror ("strdup");
	exit(BAD);
    }

    argc -= optind;
    argv += optind;

    if (argc != 1) {
	fprintf(stderr, USAGE, progname);
	exit (BAD);
    }

    if ((eid = strdup(argv[0])) == NULL) {
	perror ("strdup(argv[0])");
	exit(BAD);
    }
	
    /* 
     *	The requested eid should be here
     */

    if ((eid_name = strdup(eid)) == NULL) {
	perror ("strdup(eid)");
	exit(BAD);
    }

    if (map_resolver == NULL) {
        fprintf(stderr,
		"%s not set and -m not specified\n",
		DEFAULT_MAP_RESOLVER);
	fprintf(stderr, USAGE, progname);
	exit(BAD);
    }

    if ((mr_name = strdup(map_resolver)) == NULL) {
	perror ("strdup(map_resolver)");
	exit(BAD);
    }

    /*
     * gethostbyname fails if eid is an IPv6 addresss (obviously)... 
     *
     */

    if ((hostent = gethostbyname(eid)) == NULL) {
	fprintf(stderr, "gethostbyname for %s failed (%s)\n",
		eid, hstrerror(h_errno));
	exit(BAD);
    }
	
    /*
     *  save the eid, eid_addrtype, and length. Should be 
     *  checking h_addrtype for AF_INET or AF_INET6...
     */

    eid_addrtype = hostent->h_addrtype;
    eid_length   = hostent->h_length;
    eid          = strdup(inet_ntoa(*((struct in_addr *)hostent->h_addr)));

    if ((hostent = gethostbyname(map_resolver)) == NULL) {
	fprintf(stderr, "gethostbyname for %s failed (%s)\n",
		map_resolver,
		hstrerror(h_errno));
	exit(BAD);
    }

    /*
     *  likewise for the map resolver
     */

    mr_addrtype  = hostent->h_addrtype;
    mr_length    = hostent->h_length;
    map_resolver = strdup(inet_ntoa(*((struct in_addr *)hostent->h_addr)));

    /*
     *	get an array of nonces of size 2*count
     *  (need 2*count as nonces are 64 bit as of 
     *	draft-ietf-lisp-04.txt)
     */

    if ((nonce = (unsigned int *) malloc(2*count*sizeof(unsigned int))) < 0) {
	perror ("malloc (nonce)");
	exit(BAD);
    }

    /*
     *	Get a couple of UDP sockets. Can't send and receive on the
     *	same socket since you encapsulate to the port LISP_DATA_PORT
     *	(4341) and receive on emr_inner_src_port (and source port
     *	LISP_CONTROL_PORT (4342)).
     *
     *	So send a encapsulated map-request (EMR) on socket s with dest
     *	UDP port LISP_DATA_PORT and receive map-replies on socket r on
     *	emr_inner_src_port (and source port LISP_CONTROL_PORT (4342)).
     *	
     */

    if ((proto = getprotobyname("UDP")) == NULL) {
	perror ("getprotobyname");
	exit(BAD);
    }

    if ((s = socket(AF_INET,SOCK_DGRAM,proto->p_proto)) < 0) {
	perror("SOCK_DGRAM (s)");
	exit(1);
    }

    if ((r = socket(AF_INET,SOCK_DGRAM,proto->p_proto)) < 0) {
	perror("SOCK_DGRAM (r)");
	exit(1);
    }

    if (src_ip_addr) 
	my_addr.s_addr = inet_addr(src_ip_addr); 
    else 
	get_my_ip_addr(&my_addr); 

    /* 
     *	Initialize the random number generator for the nonces
     */
     
    iseed = (unsigned int) time (NULL);
    srandom(iseed);

    /* 
     *	Set up to receive a map-reply.
     *
     *	Use this for the source port on the innner UDP header, and for
     *  the dest port when receiving a map-reply. Bind to this 
     *  port to the receive socket.
     *
     */

    memset(packet,       0, MAX_IP_PACKET);
    memset((char *) &me, 0, sizeof(me));

    /*
     * http://tools.ietf.org/html/draft-larsen-tsvwg-port-randomization-02.txt
     */

    if (!emr_inner_src_port)
	emr_inner_src_port = MIN_EPHEMERAL_PORT +
	    random() % (MAX_EPHEMERAL_PORT - MIN_EPHEMERAL_PORT);

    me.sin_port        = htons(emr_inner_src_port); 
    me.sin_family      = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;

    if (bind(r,(struct sockaddr *) &me, sizeof(me)) == -1) {
	perror("bind");
	exit(BAD);
    }

    /*
     *	loop until either we get a map-reply or we 
     *	try count times
     * 
     *  09/10/2009: nonce is now 64 bits, so we have 
     *              2*count unsigned ints in the nonce array.
     *
     */

    for (i = 0; i < count; i++) {

        build_nonce(&nonce0,&nonce1);
	nonce[2*i]     = nonce0;	/* save these for later (find_nonce) */
	nonce[(2*i)+1] = nonce1;

	if (debug)
	    printf("Send map-request to %s (%s) for %s (%s) ...\n",
		   mr_name,
		   map_resolver,
		   eid_name,
		   eid);
        else
	    printf("Send map-request to %s for %s ...\n", mr_name, eid_name);

	if (send_map_request(s,
			     nonce0,
			     nonce1,
			     &before,
			     eid,
			     map_resolver,
			     &my_addr)) {
	    perror("can't send map-request");
	    exit(BAD);
	}

        if (wait_for_response(r,timeout)) {	
	    if (gettimeofday(&after,NULL) == -1) {
		perror("gettimeofday");
		return(BAD);
	    }
	    get_map_reply(r, packet, &from);
	    map_reply = (struct map_reply_pkt *) packet;
	    if (map_reply->lisp_type != LISP_MAP_REPLY) {
		fprintf(stderr, "Packet not a Map Reply (0x%x)\n", map_reply->lisp_type);
		continue;			/* try again */
	    }

	    /*
             * Ok, its a map-reply, now check to see if we can find
	     * the nonce
             *
             */

	    if (find_nonce(map_reply,nonce, (i+1))) {
		print_map_reply(map_reply,
				eid,
				map_resolver,
				strdup(inet_ntoa(from.sin_addr)),
				tvdiff(&after,&before));
		exit(GOOD);
	    } else {	                    /* Otherwise assume its spoofed */
		printf("Spoofed map-reply: 0x%08x/0x%08x-0x%08x/0x%08x\n",
                       nonce0,
		       ntohl(map_reply->lisp_nonce0),
		       nonce1,
		       ntohl(map_reply->lisp_nonce1));
		continue;			/* try again if count left */
	    }

	}					/* timed out */
    }
    printf("*** No map-reply received ***\n");
}


