/* 
 *	lig.c --
 * 
 *	Main loop for lig
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr  9 09:44:57 2009
 *
 *	$Header: /home/dmm/lisp/lig/RCS/lig.c,v 1.66 2009/08/25 20:50:02 dmm Exp $
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
boolean			no_reply = TRUE;
unsigned int		*nonce;
struct   sockaddr_in	map_resolver_addr;
u_char			packet[MAX_IP_PACKET];

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

    char *eid          = NULL;
    char *map_resolver = NULL;
    char *src_ip_addr  = NULL;
    char *eid_name     = NULL;
    char *mr_name      = NULL;
    char *progname     = NULL;
    int  eid_addrtype  = 0;
    int  eid_length    = 0;
    int  mr_addrtype   = 0;
    int  mr_length     = 0;

    unsigned int iseed;			/* initial random number generator */
    int i;				/* generic counter */

    /*
     *	parse args
     */  

    int  opt           = 0;
    char *optstring    = "c:dm:p:t:s:";
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
	    emr_inner_src_port = atoi(optarg);
	    break;
	case 'm':
	    map_resolver = strdup(optarg);
	    break;
	case 's':
	    src_ip_addr = strdup(optarg);
	    break;
	case 't':
	    timeout = atoi(optarg);		/* seconds */
	    if ((timeout < MIN_MR_TIMEOUT) || (timeout > MAX_MR_TIMEOUT)) {
		fprintf(stderr,
			"%s: Invalid number, specify timeout in the range (%u:%u) seconds\n",
			argv[0], MIN_MR_TIMEOUT,MAX_MR_TIMEOUT);
		exit(BAD);
	    }
	    timeout = timeout*1000;		/* convert to ms */
	    break;
	default:
	    fprintf(stderr, USAGE, argv[0]);
	    exit (BAD);
	}
    }

    /*
     *	argv[0]:	lig
     *  argv[1]:	<eid>
     *  argv[2]:	-t
     *  argv[3]:	<mr>
     *
     * at least...
     *
     */

    /* 
     *	first, save the program name somewhere
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
	fprintf(stderr, "-m <map resolver> not specified\n");
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
		map_resolver, hstrerror(h_errno));
	exit(BAD);
    }

    /*
     *  likewise for the map resolver
     */

    mr_addrtype  = hostent->h_addrtype;
    mr_length    = hostent->h_length;
    map_resolver = strdup(inet_ntoa(*((struct in_addr *)hostent->h_addr)));

    /*
     *	get an array of nonces of size count
     */

    if ((nonce = (unsigned int *) malloc(count*sizeof(unsigned int))) < 0) {
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

    /*
     *	get my ip_address
     *
     *	Don't love get_my_ip_addr. It loops through
     *	the interfaces in a way that is probably not 
     *  POSIX compliant (SIOCGIFCONF), and looks for
     *	an IP address that isn't a looback (127.0.0.1)
     *  or an EID (153.16/16).
     *
     *	Also doesn't return IPv6 addresses.
     *
     */

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

    memset(packet,         0, MAX_IP_PACKET);
    memset((char *) &me,   0, sizeof(me));

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
     */

    for (i = 0; i < count; i++) {	
	nonce[i] = random();
	if (debug)
	    printf("Send map-request to %s (%s) for %s (%s) ...\n",
		   mr_name,
		   map_resolver,
		   eid_name,
		   eid);
        else
	    printf("Send map-request to %s for %s ...\n",
		   mr_name,
		   eid_name);
	if (send_map_request(s,
			     nonce[i],
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
		fprintf(stderr, "Packet not a Map Reply (0x%x)\n",
			map_reply->lisp_type);
		continue;			/* try again */
	    }

	    /*
             * Ok, its a map-reply, now check to see if we can find
	     * the nonce
             *
             */

	    if (find_nonce(ntohl(map_reply->lisp_nonce),nonce, i)) {
		print_map_reply(map_reply,
				eid,
				map_resolver,
				strdup(inet_ntoa(from.sin_addr)),
				tvdiff(&after,&before));
		exit(GOOD);
	    } else {	                    /* Otherwise assume its spoofed */
		printf("Apparently spoofed map-reply (0x%x)\n", nonce[i]);
                no_reply = FALSE;
		if (debug)
		    print_map_reply(map_reply,
				    eid,
				    map_resolver,
				    strdup(inet_ntoa(from.sin_addr)),
				    tvdiff(&after,&before));
		continue;			/* try again if count left */
	    }

	} 					/* we timed out */
    }
    if (no_reply)
	printf("*** No map-reply received ***\n");
}


