/*
 *	Various diagnostic print routines
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr 23 15:34:18 2009
 *
 *	$Header: /home/dmm/lisp/lig/RCS/print.c,v 1.7 2009/08/05 20:23:24 dmm Exp $
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
    struct in6_addr		   *locator6;
    char			   pw[8];
    char			   buf[256];
    int				   offset = 0;
    int				   record_count = 0;
    int				   locator_count = 0;
    int				   i;    
    int				   j;

    printf("Received map-reply from %s with rtt %2.5f secs\n",
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
	
	if (locator_count) {
	    printf("  %-20s%-10s%-10s\n","Locator","State","Priority/Weight");

	    /*
	     * loop through the Loc's (see lig.h)
             *
             *	all of this needs fixed for IPv6
	     */

	    for (j = 0; j < locator_count; j++) {
		switch (ntohs(loctype->loc_afi)) {
		case LISP_AFI_IP:
		    locator = (struct in_addr *) &loctype->locator;

		    sprintf(pw, "%d/%d", loctype->priority, loctype->weight);
		    printf("  %-20s%-10s%-10s\n",
			   inet_ntoa(*locator),
			   loctype->reach_bit ? "up" : "down",
			   pw);
		    offset = sizeof(struct lisp_map_reply_loctype) + sizeof(struct in_addr);
		    break;
		case LISP_AFI_IPV6:
		    sprintf(pw, "%d/%d", loctype->priority, loctype->weight);
	            printf("  %-20s%-10s%-10s\n",
			   "IPv6 not supported",
			   loctype->reach_bit ? "up" : "down", pw);
		    offset = sizeof(struct lisp_map_reply_loctype) + sizeof(struct in6_addr);
		    break;
		default:
		    fprintf(stderr, "Unknown Locator AFI (%d)\n",ntohs(loctype->loc_afi));
		    break;
		}
		loctype = (struct lisp_map_reply_loctype *) CO(loctype, offset);
	    }
	} else {
	    printf("  Negative cache entry, action: ");
	    switch (eidtype->action) {
	    case 0:
		printf("no-action\n");
		break;
	    case 1:
		printf("forward-native\n");
		break;
	    case 2:
		printf("drop\n");
		break;
	    case 3:
		printf("send-map-request\n");
		break;
	    default:
		printf("unknown-action (%d)\n", eidtype->action);
		break;
	    }		
	}

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
