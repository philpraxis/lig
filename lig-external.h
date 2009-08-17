
/*
 *	lig-external.h
 *
 *	Any externals that everyone needs go here.
 *
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr  9 12:01:29 2009
 *
 *	$Header: /home/dmm/lisp/lig/RCS/lig-external.h,v 1.12 2009/08/17 21:55:54 dmm Exp $
 *
 */

extern	struct protoent *proto;
extern	int optind;
extern  int debug;
extern	ushort emr_inner_src_port;

extern void   *memcpy();
extern void   *memset();
extern char   *strdup();
extern size_t  strlen();

extern ushort       csum ();
extern void         get_my_ip_addr();
extern void	    get_map_reply();
extern long         tvdiff();
