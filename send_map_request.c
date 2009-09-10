/*
 *	send_map_request.c
 *
 *
 *      Functions related to sending a map-request
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Tue Apr 14 14:48:13 2009
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
 *
 *	 $Header: /home/dmm/lisp/lig/RCS/send_map_request.c,v 1.45 2009/09/10 23:22:23 dmm Exp $ 
 *
 */

#include	"lig.h"
#include	"lig-external.h"

/*
 *	send_map_request --
 *
 *	Sends a IP/UDP encapsulated map-request for eid to map_server
 *
 *
 *	Here's the packet we need to build:
 *
 *                IP header (kernel does this on socket s)
 *                UDP header (DEST PORT = 4341, UDP socket/kernel does this)
 *       lisph -> LISP header
 *  packet,iph -> IP header (SRC = this host,  DEST = eid)
 *	  udph -> UDP (SRC PORT = ANY DEST PORT = 4342)
 * map_request -> struct map-request
 *
 *
 *	We'll open a UDP socket on dest port 4341, and 
 *	give it a "packet" that that looks like:
 *
 *       lisph -> Outer LISP header
 *  packet,iph -> IP header (SRC = this host,  DEST = eid)
 *	  udph -> UDP (DEST PORT = 4342)
 * map_request -> struct map-request
 *
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr 16 14:46:51 2009
 *
 *	$Header: /home/dmm/lisp/lig/RCS/send_map_request.c,v 1.45 2009/09/10 23:22:23 dmm Exp $
 *
 */

int send_map_request(s,nonce0,nonce1,before,eid,map_resolver,my_addr)
     int		s;
     unsigned int	nonce0;
     unsigned int	nonce1;
     struct timeval     *before;
     char		*eid;
     char		*map_resolver;
     struct in_addr	*my_addr; 
{

    u_char			packet[MAX_IP_PACKET];	
    struct sockaddr_in		mr;
    struct lisphdr		*lisph;
    struct ip			*iph;
    struct udphdr		*udph;
    struct map_request_pkt	*map_request;
    int				ip_len = 0;
    int				packet_len = 0;
    int				nbytes = 0;


    if (debug > 2)
	fprintf(stderr, "send_map_request (inner header): <%s:%d,%s:%d>\n",
		inet_ntoa(*my_addr),
		emr_inner_src_port,
		eid,
		LISP_CONTROL_PORT);

    /*
     *	make sure packet is clean
     */

    memset(packet, 0, MAX_IP_PACKET);

    /*
     *	Build the packet.
     *
     *	The packet has the following form:
     *
     *	 outer-ip-header		built by the kernel
     *	 udp-header (4341)		built by the kernel
     *	 outer lisp-header		struct lisphdr *lisph
     *	 inner-ip-header		struct ip      *iphdr
     *	 udp-header (4342)		struct udphdr  *udphdr
     *   lisp-header (map-request)	struct map_request_pkt *map_request
     */

    /*
     *	CO is a macro that makes sure the pointer 
     *  arithmetic is done correctly. Basically...
     *
     *   #define	CO(addr,len) (((char *) addr + len))
     *
     */

    lisph       = (struct lisphdr *)         packet;
    iph		= (struct ip *)              CO(lisph, sizeof(struct lisphdr));
    udph        = (struct udphdr *)          CO(iph,   sizeof(struct ip));
    map_request = (struct map_request_pkt *) CO(udph,  sizeof(struct udphdr));

    /*
     *  compute lengths of interest
     */

    ip_len      = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct map_request_pkt);
    packet_len  = ip_len + sizeof(struct lisphdr);

    /*
     *	Build the outer LISP header 
     */

    lisph->smr_bit             = 0;
    lisph->lisp_loc_reach_bits = 0;		/* no reachability info */
    lisph->lisp_nonce          = htonl(nonce0);

    /*
     *	Build inner IP header
     *
     *  packet,iph -> IP header (SRC = this host,  DEST = EID)
     *
     */

    iph->ip_hl  = 5;
    iph->ip_v   = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(ip_len);	/* ip + udp headers, + map_request */
    iph->ip_id  = htons(54321);		/* the value doesn't matter here */
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p   = IPPROTO_UDP;
    iph->ip_sum = 0;			/* compute checksum later */
    iph->ip_src.s_addr = my_addr->s_addr;
    iph->ip_dst.s_addr = inet_addr(eid); /* string from command line */

    /*
     *	Build UDP inner header
     *
     *   DEST Port is 4342 (LISP Control)
     */

#ifdef BSD
    udph->uh_sport = htons(emr_inner_src_port);
    udph->uh_dport = htons(LISP_CONTROL_PORT);
    udph->uh_ulen  = htons(sizeof(struct udphdr) + sizeof(struct map_request_pkt));
    udph->uh_sum   = 0;
#else
    udph->source = htons(emr_inner_src_port);
    udph->dest   = htons(LISP_CONTROL_PORT);
    udph->len    = htons(sizeof(struct udphdr) + sizeof(struct map_request_pkt));
    udph->check  = 0;
#endif
    /*
     * Build the Map-Request
     *
     * 6.1.2.  Map-Request Message Format
     *
     *

     *         0                   1                   2                   3
     *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *        |Type=1 |A|M|P|S|           Reserved            | Record Count  |
     *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *        |                             Nonce                             |
     *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *        |         Source-EID-AFI        |            ITR-AFI            |
     *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *        |                   Source EID Address  ...                     |
     *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *        |                Originating ITR RLOC Address ...               |
     *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *      / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
     *    Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *      \ |                       EID-prefix  ...                         |
     *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *        |                   Map-Reply Record  ...                       |
     *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *        |                     Mapping Protocol Data                     |
     *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */


    map_request->smr_bit                     = 0;
    map_request->rloc_probe                  = 0;
    map_request->map_data_present            = 0;
    map_request->auth_bit                    = 0;
    map_request->lisp_type                   = 1;	/* Map-Request */
    map_request->reserved                    = htons(0);
    map_request->record_count                = 1;
    map_request->lisp_nonce0                 = htonl(nonce0); 
    map_request->lisp_nonce1                 = htonl(nonce1); 
    map_request->source_eid_afi              = htons(LISP_AFI_IP);
    map_request->itr_afi                     = htons(LISP_AFI_IP);
    map_request->source_eid.s_addr           = inet_addr("0.0.0.0");
    map_request->originating_itr_rloc.s_addr = my_addr->s_addr; 
    map_request->reserved1                   = 0;
    map_request->eid_prefix.s_addr           = inet_addr(eid);
    map_request->eid_prefix_afi              = htons(LISP_AFI_IP);
    map_request->eid_mask_len		     = LISP_IP_MASK_LEN;

    iph->ip_sum = csum (packet, ip_len);	/* ok, compute checksum now */

#ifdef BSD
    udph->uh_sum  = 0;				/* still needs to be done */
#else
    udph->check   = 0;				/* still needs to be done */
#endif

#if (DEBUG > 4)
    print_lisp_header(lisph);
    print_ip_header(iph);
    print_udp_header(udph);
    print_map_request(map_request);
#endif


    /*
     *	Set up to talk to the map-resolver
     *
     *	Kernel puts on:
     *
     *	 IP  (SRC = my_addr, DEST = map_resolver)
     *   UDP (DEST PORT = 4341)
     *
     *	The UDP packet we build (packet) looks like:
     *
     *	 IP  (SRC = my_addr, DEST = eid)
     *	 UDP (DEST PORT = 4342)
     *	 map-request_pkt
     *
     */

    memset((char *) &mr, 0, sizeof(mr));

    mr.sin_family      = AF_INET;
    mr.sin_addr.s_addr = inet_addr(map_resolver);
    mr.sin_port        = htons(LISP_DATA_PORT);

    if (gettimeofday(before,NULL) == -1) {
	perror("gettimeofday");
	return(BAD);
    }

    if ((nbytes = sendto(s,
			 (const void *) packet,
			 packet_len,
			 0,
			 (struct sockaddr *)&mr,
			 sizeof(struct sockaddr))) < 0) {
	perror("sendto");
	exit(BAD);
    }

    if (nbytes != packet_len) {
	fprintf(stderr,
		"send_map_request: nbytes (%d) != packet_len(%d)\n",
		nbytes, packet_len);
	exit(BAD);
    }

    return(GOOD);
}


