/*
 *	Various diagnostic print routines
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr 23 15:34:18 2009
 *
 *	$Header: /home/dmm/lisp/lig/RCS/print.c,v 1.2 2009/04/28 17:08:22 dmm Exp $
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
 *	Print a map_reqest packet
 *
 *
 */

void print_map_request(map_request)
    struct map_request_pkt *map_request;
{
    printf("\nMap-Request Packet\n");
    printf("==========================\n");

    printf("lisp_loc_reach_bits\t= %d\n", map_request->lisp_loc_reach_bits);
    printf("smr_bit\t\t\t= %d\n", map_request->smr_bit);
    printf("lisp_nonce\t\t= 0x%x\n", ntohl(map_request->lisp_nonce)); 
    printf("lisp_type\t\t= %d\n",map_request->lisp_type);
    printf("auth_bit\t\t= 0x%x\n", map_request->auth_bit);
    printf("map_data_present\t= %d\n",map_request->map_data_present);
    printf("rsvd\t\t\t= %d\n",map_request->rsvd);
    printf("reserved0\t\t= %d\n",map_request->reserved0);
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
