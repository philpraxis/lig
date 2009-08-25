/*
 *	Various diagnostic print routines
 *
 *	08072009:
 *		make print_map_reply handle IPv6 RLOCs
 *
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr 23 15:34:18 2009
 *
 *
 *	$Header: /home/dmm/lisp/lig/RCS/print.c,v 1.19 2009/08/25 21:51:58 dmm Exp $
 *
 */

#include	"lig.h"
#include	"lig-external.h"

/*
 *	Print an LISP header
 *
 *
 */

void print_lisp_header(lisphdr) 
     struct lisphdr *lisphdr;
{
    printf("\nLISP Header\n");
    printf("=========\n");
    printf("lisphdr->lisp_loc_reach_bits\t= %d\n",  lisphdr->lisp_loc_reach_bits);
    printf("lisphdr->smr_bit\t\t= %d\n",   lisphdr->smr_bit);
    printf("lisphdr->nonce\t\t\t= 0x%x\n", ntohl(lisphdr->lisp_nonce));
}

/*
 *	Print an IP header
 *
 *
 */

void print_ip_header(iph) 
    struct ip	           *iph;
{
    printf("\nIP Header\n");
    printf("=========\n");
    printf("iph->ip_hl\t= %d\n",  iph->ip_hl);
    printf("iph->ip_v\t= %d\n",   iph->ip_v);
    printf("iph->ip_tos\t= %d\n", iph->ip_tos);
    printf("iph->ip_len\t= %d\n", ntohs(iph->ip_len));
    printf("iph->ip_id\t= %d\n",  ntohs(iph->ip_id));
    printf("iph->ip_off\t= %d\n", iph->ip_off);
    printf("iph->ip_ttl\t= %d\n", iph->ip_ttl);
    printf("iph->ip_p\t= %d\n",   iph->ip_p);
    printf("iph->sum\t= 0x%x\n",  iph->ip_sum);
    printf("iph->ip_src\t= %s\n", inet_ntoa(iph->ip_src));
    printf("iph->ip_dst\t= %s\n", inet_ntoa(iph->ip_dst));
}

/*
 *	Print an UDP header
 *
 *
 */

void print_udp_header(udph) 
    struct udphdr          *udph;
{
    printf("\nUDP Header\n");
    printf("==========\n");
#ifdef BSD
    printf("udph->uh_sport\t= %d\n", ntohs(udph->uh_sport));
    printf("udph->uh_dport\t= %d\n",   ntohs(udph->uh_dport));
    printf("udph->uh_ulen\t= %d\n",    ntohs(udph->uh_ulen));
    printf("udph->uh_sum\t= 0x%x\n",  udph->uh_sum);
#else
    printf("udph->source\t= %d\n", ntohs(udph->source));
    printf("udph->dest\t= %d\n",   ntohs(udph->dest));
    printf("udph->len\t= %d\n",    ntohs(udph->len));
    printf("udph->check\t= 0x%x\n",  udph->check);
#endif
}


/*
 *	print_negative_cache_entry
 *
 *	Prettily print a negative cache entry
 *
 */
void print_negative_cache_entry(action)
     int	action;
{
    printf("  Negative cache entry, action: ");
    switch (action) {
    case LISP_ACTION_NO_ACTION:
	printf("no-action\n");
	break;
    case LISP_ACTION_FORWARD:
	printf("forward-native\n");
	break;
    case LISP_ACTION_DROP:
	printf("drop\n");
	break;
    case LISP_ACTION_SEND_MAP_REQUEST:
	printf("send-map-request\n");
	break;
    default:
	printf("unknown-action (%d)\n", action);
	break;
    }		
}


/*
 *	set_afi_and_addr_offset
 *
 *	Set up the afi for inet_ntop and set
 *	the addr_offset to calculate location of 
 *	the next locator.
 *
 */

void set_afi_and_addr_offset(loc_afi,afi,addr_offset)
     ushort		loc_afi;
     int		*afi;
     unsigned int	*addr_offset;
{
    switch (loc_afi) {
    case LISP_AFI_IP:
	*afi = AF_INET;
	*addr_offset = sizeof(struct in_addr);
	break;
    case LISP_AFI_IPV6:
	*afi = AF_INET6;
	*addr_offset = sizeof(struct in6_addr);
	break;
    default:
	fprintf(stderr, "Unknown AFI (0x%x)\n", loc_afi);
	break;
    }
}


/*
 *	Print a map_reply packet. The output format matches Dino's
 *	(to the extent possible).
 *
 *
 */

void print_map_reply(map_reply,requested_eid,mr_to,mr_from,elapsed_time)
    struct map_reply_pkt *map_reply;
    char *requested_eid;
    char *mr_to;
    char *mr_from;
    long elapsed_time;
{
    char			   pw[8];
    char			   buf[256];
    struct in_addr		   *eid;
    struct lisp_map_reply_eidtype  *eidtype	   = NULL;
    struct lisp_map_reply_loctype  *loctype        = NULL; 
    const char			   *formatted_addr = NULL;
    unsigned int		   offset          = 0;
    unsigned int		   addr_offset     = 0;
    int				   record_count    = 0;
    int				   locator_count   = 0;
    int				   afi             = 0;
    int				   record          = 0;    
    int				   locator         = 0;

    printf("Received map-reply from %s with rtt %2.5f secs\n",
	   mr_from, (double) elapsed_time/1000);
    printf("\nMapping entry for EID %s:\n", requested_eid);

    record_count = map_reply->record_count;

    /*
     *	loop through the Records
     *
     *	Assumes the EID-prefix is v4
     *
     */	

    eidtype = (struct lisp_map_reply_eidtype *) &map_reply->data;

    /*
     *	loop through the records
     */

    for (record = 0; record < record_count; record++) {
        locator_count = eidtype->loc_count;
	eid           = (struct in_addr *) &eidtype->eid_prefix;

	printf("%s/%d,", inet_ntoa(*eid),eidtype->eid_mask_len);
	if (debug)
	    printf(" via map-reply, record ttl: %d, %s, nonce: 0x%x\n", 
		   ntohl(eidtype->record_ttl), 
		   eidtype->auth_bit ? "auth" : "not auth", 
		   ntohl(map_reply->lisp_nonce));
	else
	    printf(" via map-reply, record ttl: %d, %s\n", 
		   ntohl(eidtype->record_ttl), 
		   eidtype->auth_bit ? "auth" : "not auth"); 
	if (locator_count) {		/* have some locators */
	    loctype = (struct lisp_map_reply_loctype *)
		CO(eidtype->eid_prefix, sizeof(struct in_addr));

	    printf("  %-32s%-10s%-10s\n","Locator","State","Priority/Weight");

	    /*
	     * loop through the locators (per record)
	     */

	    for (locator = 0; locator < locator_count; locator++) {
                set_afi_and_addr_offset(ntohs(loctype->loc_afi),
					&afi,
					&addr_offset);

		if ((formatted_addr = inet_ntop(afi,
						&loctype->locator,
						buf,
						sizeof(buf))) == NULL) {
		    perror("inet_ntop");
		    exit(BAD);
		}

		sprintf(pw, "%d/%d", loctype->priority, loctype->weight);
		printf("  %-32s%-10s%-10s\n",
		       formatted_addr,
		       loctype->reach_bit ? "up" : "down",
		       pw);

		offset  = sizeof(struct lisp_map_reply_loctype) + addr_offset;
		loctype = (struct lisp_map_reply_loctype *) CO(loctype, offset);
	    }
	} else {		/* zero locators means negative map reply */
	    print_negative_cache_entry(eidtype->action);
	}

        /* this should be the next record */
	eidtype = (struct lisp_map_reply_eidtype *) loctype;
    }
}


/*
 *	Print a map_reqest packet
 *
 *
 */

void print_map_request(map_request)
    struct map_request_pkt *map_request;
{
    printf("\nMap-Request Packet\n");
    printf("==========================\n");

    printf("smr_bit\t\t\t= %d\n", map_request->smr_bit);
    printf("rloc_probet\t\t= %d\n", map_request->rloc_probe);
    printf("map_data_present\t= %d\n",map_request->map_data_present);
    printf("auth_bit\t\t= 0x%x\n", map_request->auth_bit);
    printf("lisp_type\t\t= %d\n",map_request->lisp_type);
    printf("lisp_nonce\t\t= 0x%x\n", ntohl(map_request->lisp_nonce)); 
    printf("reserved\t\t\t= %d\n",map_request->reserved);
    printf("reserved1\t\t= %d\n",map_request->reserved1);
    printf("record_count\t\t= %d\n",map_request->record_count);
    printf("source_eid_afi\t\t= %d\n",
	   ntohs(map_request->source_eid_afi));
    printf("itr_afi\t\t\t= %d\n", 
	   ntohs(map_request->itr_afi));
    printf("source_eid\t\t= %s\n",
           inet_ntoa(map_request->source_eid));
    printf("originating_itr_rloc\t= %s\n",
           inet_ntoa(map_request->originating_itr_rloc));
    printf("reserved1\t\t= %d\n",map_request->reserved1);
    printf("eid_prefix\t\t= %s\n",
	   inet_ntoa(map_request->eid_prefix));
    printf("eid_prefix_afi\t\t= %d\n",
	   ntohs(map_request->eid_prefix_afi));
    printf("eid_mask_len\t\t= %d\n",map_request->eid_mask_len);


}
