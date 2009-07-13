/* 
 *	lig.c --
 * 
 *	Main loop for lig
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr  9 09:44:57 2009
 *
 *	$Header: /home/dmm/lisp/lig/RCS/lig.c,v 1.41 2009/07/13 22:38:21 dmm Exp $
 *
 */

#include	"lig.h"
#include	"lig-external.h"

/*
 *	globals
 */

int			s;
int			r;
int			debug = 0;
boolean			no_reply = TRUE;
unsigned int		*nonce;
unsigned int		rnonce;
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

    /*
     * Remember the requested eid and map resolver properties here 
     */

    char *eid          = NULL;
    char *map_resolver = NULL;
    char *src_ip_addr  = NULL;
    char *eid_name     = NULL;
    char *mr_name      = NULL;
    int  eid_addrtype;
    int  eid_length;
    int  mr_addrtype;
    int  mr_length;

    unsigned int iseed;			/* initial random number generator */
    int i;

    /*
     *	parse args
     */  

    int  opt           = 0;
    char *optstring    = "c:dm:t:s:";
    int  count         = COUNT;
    int	 timeout       = MAP_REPLY_TIMEOUT;

    while ((opt = getopt (argc, argv, optstring)) != EOF)
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

    /*
     *	argv[0]:	lig
     *  argv[1]:	<eid>
     *  argv[2]:	-t
     *  argv[3]:	<mr>
     *
     * at least...
     *
     */

    if (argc < 4) {
	fprintf(stderr, USAGE, argv[0]);
	exit (BAD);
    }
	
    /* 
     *	The requested eid should be here
     */

    if ((eid = strdup(argv[optind])) == NULL) {
	perror ("strdup(argv[optind])");
	exit(BAD);
    }
    if ((eid_name = strdup(eid)) == NULL) {
	perror ("strdup(eid)");
	exit(BAD);
    }
    if (map_resolver == NULL) {
	fprintf(stderr, "-m <map resolver> not specified\n");
	fprintf(stderr, USAGE, argv[0]);
	exit(BAD);
    }
    if ((mr_name = strdup(map_resolver)) == NULL) {
	perror ("strdup(map_resolver)");
	exit(BAD);
    }


    /*
     * gethostbyname seems to fail if eid is 
     * an IPv6 addresss...
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
    eid = strdup(inet_ntoa(*((struct in_addr *)hostent->h_addr)));

    if ((hostent = gethostbyname(map_resolver)) == NULL) {
	fprintf(stderr, "gethostbyname for %s failed (%s)\n",
		map_resolver, hstrerror(h_errno));
	exit(BAD);
    }

    /*
     *  likewise for the map resolver
     */

    mr_addrtype = hostent->h_addrtype;
    mr_length   = hostent->h_length;
    map_resolver  = strdup(inet_ntoa(*((struct in_addr *)hostent->h_addr)));


    /*
     *	get an array of nonces of size count
     */

    if ((nonce = (unsigned int *) malloc(count*sizeof(unsigned int))) < 0) {
	perror ("malloc (nonce)");
	exit(BAD);
    }

    /*
     * get a UDP socket
     */

    if ((proto = getprotobyname("UDP")) == NULL) {
	perror ("getprotobyname");
	exit(BAD);
    }

    if ((s = socket(AF_INET,SOCK_DGRAM,proto->p_proto)) < 0) {
	perror("SOCK_DGRAM");
	exit(1);
    }

    /*
     *	For some reason I need to receive on a RAW socket
     *  (Linux anyway).
     */

    if ((r = socket(AF_INET,SOCK_RAW,proto->p_proto)) < 0) {
	perror("SOCK_RAW");
	exit(1);
    }

    /* 
     *	Dork around with privileges (SOCK_RAW and all)
     */

    if (setuid(getuid()) == -1) {
	perror("setuid");
	exit(BAD);
    }

    /* 
     *	Set up the relevant offsets in the packet. Really
     *  just want the map-reply.
     *
     */

    iph       = (struct ip *) packet;
    udph      = (struct udphdr *) CO(iph, sizeof(struct ip)); 
    map_reply = (struct map_reply_pkt *) CO(udph, sizeof(struct udphdr));

    /* 
     *	Initialize the random number generator for the nonces
     */
     
    iseed = (unsigned int) time (NULL);
    srandom(iseed);

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

	if (send_map_request(s, nonce[i], &before, eid, map_resolver, src_ip_addr)) {
	    perror("can't send map-request");
	    exit(BAD);
	}

        if (wait_for_response(r,timeout)) {	
	    if (gettimeofday(&after,NULL) == -1) {
		perror("gettimeofday");
		return(BAD);
	    }

	    if (!get_map_reply(r, packet))	/* get a packet */
		continue;			/* not a LISP control packet */

	    /*
             *	We have a packet that has UDP source port = 4342.
	     *	Assume it is a map-reply.
             *
             *	Now check the nonce
             *
	     */

	    if (find_nonce(ntohl(map_reply->lisp_nonce),nonce, i)) {
		print_map_reply(map_reply,
				eid,
				map_resolver,
				strdup(inet_ntoa(iph->ip_src)),
				tvdiff(&after,&before));
		exit(GOOD);
		no_reply = FALSE;
	    } else {	                       /* Otherwise assume its spoofed */
		printf("Apparently spoofed map-reply (0x%x)\n", nonce[i]);
		if (debug)
		    print_map_reply(map_reply,
				    eid,
				    map_resolver,
				    strdup(inet_ntoa(iph->ip_src)),
				    tvdiff(&after,&before));
		continue;			/* try again if count left */
	    }

	} 					/* we timed out */
    }
    if (no_reply)
	printf("*** No map-reply received ***\n");
}


