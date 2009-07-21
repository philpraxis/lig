/*
 *	get_my_ip_addr.c
 *
 *	Basically, loop through the interfaces
 *	and take the first non-loopback interface.
 *
 *	NB: doesn't work for IPv6
 *
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Mon Jul  6 09:45:50 2009
 *
 *	$Header: /home/dmm/lisp/lig.new/RCS/get_my_ip_addr.c,v 1.6 2009/07/17 16:25:09 dmm Exp $
 *
 */


#include	"lig.h"
#include	"lig-external.h"


void get_my_ip_addr(my_addr)
     struct     in_addr *my_addr;
{

    struct ifconf	conf;
    struct sockaddr_in 	*s_in;
    int			s, i, count;

    /*
     *  Open dummy socket
     */

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
	perror("error opening socket");
	exit(BAD);
    }

    memset(&conf, 0, sizeof(conf));
    conf.ifc_len = sizeof(struct ifreq) * NINTERFACES;

    if ((conf.ifc_buf = (char*) malloc(conf.ifc_len)) == NULL) {
	perror ("malloc (NINTERFACES)");
	exit(BAD);
    }
        
    if (ioctl(s, SIOCGIFCONF, &conf) == -1) {
	perror("failed to get device list");
	exit(BAD);
    }

    count = conf.ifc_len / sizeof(struct ifreq);

    for (i = 0; i < count; i++) {
	s_in = (struct sockaddr_in*) &conf.ifc_req[i].ifr_addr;
	if (strcmp(LOOPBACK,inet_ntoa(s_in->sin_addr))) {

#if (DEBUG > 3)
	    fprintf(stderr,
		    "get_my_ip_addr: using %s (%s)\n", 
		    inet_ntoa(s_in->sin_addr),
		    conf.ifc_req[i].ifr_name);
#endif

            memcpy((void *) my_addr, (void *) &(s_in->sin_addr),
		   sizeof(struct in_addr));
            free(conf.ifc_buf);
	    close(s);
	    return;
	}
    }
    fprintf(stderr, "No usable source address\n");
    exit(BAD);
}


/*
 *	don't like this...
 */

#ifdef notdef
/*
 *	get my own IP address
 *
 *	Fails if /etc/hosts has an entry like
 *
 *	127.0.0.1	<whatever your hostname is>
 *
 */

void get_my_ip_addr(my_addr) 
     struct     in_addr *my_addr;

{
    char                hostname[128] = "";
    struct hostent      *hostent = 0;
    struct in_addr      **hostptr;
    struct in_addr      *host;

    if ((gethostname(hostname, sizeof(hostname))) < 0) {
        perror("gethostname");
        exit(BAD);
    }

    if ((hostent = gethostbyname(hostname)) < 0) {
	perror("gethostbyname");
	exit(BAD);
    }
    hostptr = (struct in_addr **)hostent->h_addr_list;
    host = hostptr[0];
    memcpy((void *) my_addr, (void *) host, sizeof(struct in_addr));
}

#endif
