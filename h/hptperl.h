/* $Id$ */

#ifndef _HPTPPERL_H
#define _HPTPPERL_H

#if defined(__NT__) && !defined(WIN32) /* WIN32 needed for perl-core include files */
#  define WIN32
#endif

#define PERLFILE        "filter.pl"
#define PERLFILT        "filter"
#define PERLPKT         "process_pkt"
#define PERLPKTDONE     "pkt_done"
#define PERLAFTERUNP    "after_unpack"
#define PERLBEFOREPACK  "before_pack"
#define PERLEXIT        "hpt_exit"
#define PERLROUTE       "route"
#define PERLSCAN        "scan"
#define PERLTOSSBAD     "tossbad"

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

#endif
