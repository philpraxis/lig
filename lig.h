/*
 *	lig.h --
 *
 *	By David Meyer <dmm@1-4-5.net>
 *	Copyright 2009 David Meyer
 *
 *	Definitions for lig
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr 16 14:50:33 2009
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
 *	$Header: /home/dmm/lisp/lig/RCS/lig.h,v 1.61 2009/09/16 14:34:29 dmm Exp $
 *
 */


#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<errno.h>
#include	<ctype.h>
#include        <netdb.h>
#include	<strings.h>
#include	<sys/types.h>
#include	<sys/param.h>
#include	<sys/socket.h>
#include	<netinet/in_systm.h>
#include	<netinet/in.h>
#include	<netinet/udp.h>
#include	<netinet/ip.h>
#include	<netinet/ip6.h>
#include	<arpa/inet.h>
#include	<net/if.h>
#include	<sys/ioctl.h>

typedef enum			{FALSE,TRUE} boolean;
#define	uchar			u_char

#define GOOD			0
#define BAD			-1
#define	MAX_IP_PACKET		4096
#define	COUNT			3
#define MIN_COUNT		1
#define	MAX_COUNT		5
#define MAP_REPLY_TIMEOUT	2*1000	/* milliseconds */
#define	MIN_MR_TIMEOUT		1	/* seconds */
#define	MAX_MR_TIMEOUT		5	/* seconds */
#define	NINTERFACES		10
#define	LOOPBACK		"127.0.0.1"
#define	V4EID		        "153.16"
#define	V4EID_PREFIX_LEN        6	/* characters in "153.16" */
#define	MIN_EPHEMERAL_PORT	32768
#define	MAX_EPHEMERAL_PORT	65535

#define	USAGE	"usage: %s [-d] <eid> -m <map resolver> \
[-c <count>] [-p <port>] [-t <timeout>] [-v]\n"

/*
 *	VERSION 
 *
 *	XXYYZZ, where
 * 
 *	XX is the draft-ietf-lisp-XX.txt version
 *	YY is the draft-ietf-lisp-ms-YY.txt version
 *      ZZ is the lig version
 */

#define	VERSION "%s version 04.02.01\n"


/*
 *	CO --
 *
 *	Calculate Offset
 *
 *	Try not to make dumb mistakes with
 *	pointer arithmetic
 *
 */

#define	CO(addr,len) (((char *) addr + len))

/*
 * LISP Types
 */

#define	LISP_MAP_REQUEST	1
#define	LISP_MAP_REPLY		2
#define	LISP_MAP_REGISTER	3
#define	LISP_DATA_PORT		4341
#define	LISP_CONTROL_PORT	4342

/*
 *	Map Reply action codes
 */

#define LISP_ACTION_NO_ACTION		0
#define LISP_ACTION_FORWARD		1
#define LISP_ACTION_DROP		2
#define LISP_ACTION_SEND_MAP_REQUEST	3

/*
 *	#define AF_INET         2
 *	#define AF_INET6        10
 *
 */

#define LISP_AFI_IP		1
#define LISP_AFI_IPV6		2
#define	LISP_IP_MASK_LEN	32



/* 
 *	Map-Request Message Format 
 *    
 *         0                   1                   2                   3 
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *        |Type=1 |A|M|P|S|         Reserved              | Record Count  | 
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *        |                         Nonce . . .                           | 
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *        |                         . . . Nonce                           | 
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
 */ 


struct map_request_pkt {
#ifdef __LITTLE_ENDIAN
	uchar           smr_bit:1;
	uchar           rloc_probe:1;
	uchar           map_data_present:1;
	uchar           auth_bit:1;
	uchar           lisp_type:4;
#else
	uchar           lisp_type:4;
	uchar           auth_bit:1;
	uchar           map_data_present:1;
	uchar           rloc_probe:1;
	uchar           smr_bit:1;
#endif
	ushort          reserved;
	uchar           record_count;
	unsigned int    lisp_nonce0;
	unsigned int    lisp_nonce1;
	ushort          source_eid_afi;
	ushort          itr_afi;
	struct in_addr	source_eid;
	struct in_addr	originating_itr_rloc;
	uchar 		reserved1;
	uchar 		eid_mask_len;
	ushort		eid_prefix_afi;
	struct in_addr	eid_prefix;
} __attribute__ ((__packed__));


/* 
 * LISP data header. But also the fixed header for control packets. 
 * 
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *   L   |N|L|E|  rflags |                 Nonce                         | 
 *   I \ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *   S / |                       Locator Status Bits                     | 
 *   P   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 * 
 */ 


struct lisphdr { 
#ifdef __LITTLE_ENDIAN
    unsigned int lisp_loc_status_bits; 
    unsigned int lisp_data_nonce:24; 
    unsigned int rflags:5; 
    unsigned int e_bit:1; 
    unsigned int l_bit:1; 
    unsigned int n_bit:1; 
#else 
    unsigned int n_bit:1; 
    unsigned int l_bit:1; 
    unsigned int e_bit:1; 
    unsigned int rflags:5; 
    unsigned int lisp_data_nonce:24; 
    unsigned int lisp_loc_status_bits; 
#endif 
} __attribute__ ((__packed__));
 

/*/
struct lisphdr {
#ifdef __LITTLE_ENDIAN
    unsigned int          lisp_loc_reach_bits:31;
    unsigned int          smr_bit:1;
#else
    unsigned int          smr_bit:1;
    unsigned int          lisp_loc_reach_bits:31;
#endif
    unsigned int          lisp_nonce;
} __attribute__ ((__packed__));
*/




/* 
 *	Map-Reply Message Format 
 *
 *	Note: 64 bit nonce is concat(nonce0,nonce1)
 *
 *    
 *          0                   1                   2                   3 
 *          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 *         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *         |Type=2 |P|E|            Reserved               | Record Count  | 
 *         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *         |                         Nonce0                                | 
 *         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *         |                         Nonce1                                | 
 *  +----> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *  |      |                          Record  TTL                          | 
 *  |      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *  R      | Locator Count | EID mask-len  | ACT |A|M|     Reserved        | 
 *  e      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *  c      |           Reserved            |            EID-AFI            | 
 *  o      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *  r      |                          EID-prefix                           | 
 *  d      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *  |     /|    Priority   |    Weight     |  M Priority   |   M Weight    | 
 *  |    / +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *  |  Loc |           Unused Flags      |R|           Loc-AFI             |  
 *  |    \ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *  |     \|                             Locator                           | 
 *  +--->  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *         |                     Mapping Protocol Data                     | 
 *         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 */ 

struct map_reply_pkt {
#ifdef __LITTLE_ENDIAN
     int            rsvd:2;
     int            echo_nonce_capable:1;
     int            rloc_probe:1;
     int            lisp_type:4;
#else
     int            lisp_type:4;
     int            rloc_probe:1;
     int            echo_nonce_capable:1;
     int            rsvd:2;
#endif
     ushort         reserved;
     uchar          record_count;
     unsigned int   lisp_nonce0;
     unsigned int   lisp_nonce1;
     uchar          data[0];
}  __attribute__ ((__packed__));



struct lisp_map_reply_eidtype {
    unsigned int	record_ttl;
    uchar 		loc_count;
    uchar 		eid_mask_len;
#ifdef __LITTLE_ENDIAN
    int			reserved:3;
    int			mobility_bit:1;
    int			auth_bit:1;
    int			action:3;
#else
    int			action:3;
    int			auth_bit:1;
    int			mobility_bit:1;
    int			reserved:3;
#endif
    uchar 		reserved2;
    ushort		reserved3;
    ushort		eid_afi;
    uchar 		eid_prefix[0];         /* ITR-locator than EID-prefix */
} __attribute__ ((__packed__));

struct lisp_map_reply_loctype {
    uchar   priority;
    uchar   weight;
    uchar   mpriority;
    uchar   mweight;
    uchar   unused_flags1;
#ifdef __LITTLE_ENDIAN
    uchar   reach_bit:1;
    uchar   unused_flags2:7;
#else
    uchar   unused_flags2:7;
    uchar   reach_bit:1;
#endif
    ushort loc_afi;
    uchar   locator[0];
} __attribute__ ((__packed__));

/*
 *	a RLOC can be v4 or v6 (so far)
 */

struct lisp_addrtype {
    union {
        struct in_addr	ip;
        struct in6_addr ipv6;
    } address;
};


/*
 *  emr_inner_src_port --
 * 
 *  source port in the EMR's inner UDP header. Listen on
 *  this port in the returned map-reply (the source port on
 *  the map-reply is 4342).
 *
 */

ushort emr_inner_src_port;
