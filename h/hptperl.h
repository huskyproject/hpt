/*****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 *
 * hpt perl hooks interface by val khokhlov, 2:550/180@fidonet
 *
 * This file is part of HPT.
 *
 * HPT is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * HPT is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with HPT; see the file COPYING.  If not, write to the Free
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *****************************************************************************/
/* $Id$ */

#ifndef _HPTPPERL_H
#define _HPTPPERL_H

#include <fidoconf/arealist.h>
#include <areafix/areafix.h>

#if defined(__NT__) && !defined(WIN32) /* WIN32 needed for perl-core include files */
#  define WIN32
#endif

#define SUB_FILTER              0x0001
#define SUB_PROCESS_PKT         0x0002
#define SUB_PKT_DONE            0x0004
#define SUB_AFTER_UNPACK        0x0008
#define SUB_BEFORE_PACK         0x0010
#define SUB_HPT_START           0x0020
#define SUB_HPT_EXIT            0x0040
#define SUB_ROUTE               0x0080
#define SUB_SCAN                0x0100
#define SUB_TOSSBAD             0x0200
#define SUB_ON_ECHOLIST         0x0400
#define SUB_ON_AFIXCMD          0x0800
#define SUB_ON_AFIXREQ			0x1000
#define SUB_PUTMSG				0x2000
#define SUB_EXPORT				0x4000
#define SUB_FILTER2             0x8000
#define SUB_ON_ROBOTMSG         0x10000

#define PERLFILE        "filter.pl"
#define PERLFILT        "filter"
#define PERLPKT         "process_pkt"
#define PERLPKTDONE     "pkt_done"
#define PERLAFTERUNP    "after_unpack"
#define PERLBEFOREPACK  "before_pack"
#define PERLSTART       "hpt_start"
#define PERLEXIT        "hpt_exit"
#define PERLROUTE       "route"
#define PERLSCAN        "scan"
#define PERLTOSSBAD     "tossbad"
#define PERLONECHOLIST  "on_echolist"
#define PERLONAFIXCMD   "on_afixcmd"
#define PERLONAFIXREQ	"on_afixreq"
#define PERLPUTMSG      "put_msg"
#define PERLEXPORT      "export"
#define PERLFILT2       "filter2"
#define PERLROBOTMSG    "on_robotmsg"

extern int skip_addvia;

void perl_invalidate(e_perlconftype confType);
void perl_setvars(void);

int perlscanmsg(char *area, s_message *msg);
s_route *perlroute(s_message *msg, s_route *route);
int perlfilter(s_message *msg, hs_addr pktOrigAddr, int secure);
int perlpkt(const char *fname, int secure);
void perlpktdone(const char *fname, int rc);
void perlafterunp(void);
void perlbeforepack(void);
int perltossbad(s_message *msg, char *area, hs_addr pktOrigAddr, char *reason);
int PerlStart(void);
void perldone(void);

int perl_echolist(char **report, s_listype type, ps_arealist al, char *aka);
int perl_afixcmd(char **report, int cmd, char *aka, char *line);
int perl_afixreq(s_message *msg, hs_addr pktOrigAddr);
int perl_putmsg(s_area *echo, s_message *msg);
int perl_export(s_area *echo, s_link *link, s_message *msg);
int perl_robotmsg(s_message *msg, char *type);

#endif
