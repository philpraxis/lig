/* 
 *	cksum.c --
 * 
 *	By David Meyer <dmm@1-4-5.net>
 *	Copyright 2009 David Meyer
 *
 *	Compute the IP checksum for lig
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
 *	$Header: /home/dmm/lisp/lig/RCS/cksum.c,v 1.5 2009/10/12 23:43:15 dmm Exp $
 *
 */

#include	"lig.h"

ushort ip_checksum (unsigned short *buf, int nwords)
{
    unsigned long sum;

    for (sum = 0; nwords > 0; nwords--)
	sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}



/*    
 *
 *	Calculate the UDP checksum (calculated with the whole packet).
 *
 *	Parameters:
 *
 *	buff	-	pointer to the UDP header
 *	len	-	the UDP packet length.
 *	src	-	the IP source address (in network format).
 *	dest	-	the IP destination address (in network format).
 *
 *	Returns:
 *		The result of the checksum.
 */

uint16_t udp_checksum (buff,len,src,dest)
	const void	*buff;
	unsigned int	len;
	in_addr_t	src;
	in_addr_t	dest;
{

    const	uint16_t *buf	= buff;
    uint16_t	*ip_src		= (void *)&src;
    uint16_t	*ip_dst		= (void *)&dest;
    unsigned int length		= len;
    uint32_t	sum		= 0;

    while (len > 1) {
	sum += *buf++;
	if (sum & 0x80000000)
	    sum = (sum & 0xFFFF) + (sum >> 16);
	len -= 2;
    }
 
    /* Add the padding if the packet length is odd */

    if (len & 1)
	sum += *((uint8_t *)buf);
 
    /* Add the pseudo-header */

    sum += *(ip_src++);
    sum += *ip_src;
 
    sum += *(ip_dst++);
    sum += *ip_dst;
 
    sum += htons(IPPROTO_UDP);
    sum += htons(length);
 
    /* Add the carries */

    while (sum >> 16)
	sum = (sum & 0xFFFF) + (sum >> 16);
 
    /* Return the one's complement of sum */

    return ((uint16_t)(~sum));
}
