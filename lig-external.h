
/*
 *	lig-external.h
 *
 *	By David Meyer <dmm@1-4-5.net>
 *	Copyright 2009 David Meyer
 *
 *	Any externals that everyone needs go here.
 *
 *	David Meyer
 *	dmm@1-4-5.net
 *	Thu Apr  9 12:01:29 2009
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *	$Header: /home/dmm/lisp/lig/RCS/lig-external.h,v 1.17 2009/10/07 18:55:57 dmm Exp dmm $
 *
 */

extern	struct protoent	*proto;
extern	int		optind;
extern  int		debug;
extern	ushort		emr_inner_src_port;

#if !defined(BSD)
extern void		*memcpy();
extern void		*memset();
extern char		*strdup();
#endif

extern ushort		csum ();
extern void		get_my_ip_addr();
extern long		tvdiff();
