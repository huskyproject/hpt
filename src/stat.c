/* $Id$
 *****************************************************************************
 * HPT --- FTN NetMail/EchoMail Tosser
 *****************************************************************************
 * Copyright (C) 2002-2003
 *
 * Husky development team
 *
 * http://husky.sf.net
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
 *****************************************************************************
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/xstr.h>
#include <fidoconf/log.h>


#include "stat.h"

#define REV_MIN 1            /* min revision we can read */
#define REV_CUR 1            /* revision we write */
#define REV_MAX 1            /* max revision we can read */

/*#define STAT_ALONE*/         /* complie stat.c w/o hpt */
#define STAT_DEBUG

#ifdef STAT_ALONE
#  define msg(s) fprintf(stderr,      __FILE__ ":%u: %s %s", __LINE__, s)
#  define msg2(s,s2) fprintf(stderr,  __FILE__ ":%u: %s %s", __LINE__, s, s2)
#else
#  define msg(s) w_log(LL_ALERT,  __FILE__ ":%u: %s", __LINE__, s)
#  define msg2(s,s2) w_log(LL_ALERT,  __FILE__ ":%u: %s %s", __LINE__, s, s2)
#endif

/* internal address record */
typedef struct _st_addr {
    unsigned short zone, net, node, point;
} st_addr;

/* link stats data */
typedef struct _stat_link {
    st_addr addr;
    long in, out, dupe, bad;
    long inb, outb;
} stat_link;

/* links chain record */
typedef struct  _chain_link{
    stat_link link;
    struct _chain_link *next;
} chain_link;

/* echo stats internal record */
typedef struct _stat_echo { 
    struct _stat_echo *next;
    short              links;
    chain_link        *chain;
    short              tag_len;
    char              *tag;
} stat_echo;

/* prototypes */
int acmp(hs_addr *a1, st_addr *a2);
int acmp2(st_addr *a1, st_addr *a2);
int write_echo(FILE *F, stat_echo *e);
stat_echo *read_echo(FILE *F);
void free_echo(stat_echo *e);
void debug_out(stat_echo *e);

static stat_echo *statecho = NULL;  /* first echo in echoes chain */
static int do_stat = 1;                /* drop to 0 if critical error */

/* Compare addresses (fidoconfig hs_addr and local st_addr)
 */
int acmp(hs_addr *a1, st_addr *a2)
{
    if (a1->zone  != a2->zone)  return (a1->zone  < a2->zone)  ? -1 : 1;
    if (a1->net   != a2->net)   return (a1->net   < a2->net)   ? -1 : 1;
    if (a1->node  != a2->node)  return (a1->node  < a2->node)  ? -1 : 1;
    if (a1->point != a2->point) return (a1->point < a2->point) ? -1 : 1;
    return 0;
}

/* Compare addresses (two local st_addr)
 */
int acmp2(st_addr *a1, st_addr *a2)
{
    if (a1->zone  != a2->zone)  return (a1->zone  < a2->zone)  ? -1 : 1;
    if (a1->net   != a2->net)   return (a1->net   < a2->net)   ? -1 : 1;
    if (a1->node  != a2->node)  return (a1->node  < a2->node)  ? -1 : 1;
    if (a1->point != a2->point) return (a1->point < a2->point) ? -1 : 1;
    return 0;
}

void put_stat(s_area *echo, hs_addr *link, st_type type, long len)
{
    stat_echo *cur = statecho, *prev = NULL, *me=NULL;
    chain_link *curl, *prevl;
    int res;

    if(!echo || !link){ msg("Parameter is NULL"); return; }
    if (!do_stat) return;
    /* find pos and insert echo */
    while ( (res = (cur != NULL) ? sstricmp(echo->areaName, cur->tag) : -1) )
        if (res < 0) {
            me = calloc(1,sizeof(*me));
            if (me == NULL) { msg("Out of memory"); do_stat = 0; return; }
            
            if( (me->tag_len = sstrlen(echo->areaName)) )
                me->tag = strdup(echo->areaName);
            me->links = 0; me->chain = NULL;
            if (prev != NULL) prev->next = me; else statecho = me;
            me->next = cur; cur = me; break;
        }
        else { prev = cur; cur = cur->next; }
        /* find pos and insert link into chain */
        if (cur == NULL) return;
        curl = cur->chain; prevl = NULL;
        while ( (res = (curl != NULL) ? acmp(link, &(curl->link.addr)) : -1) ) {
            if (res < 0) {
                chain_link *me;
                me = calloc(1,sizeof(*me));
                if (me == NULL) { msg("Out of memory"); do_stat = 0; return; }
                
                cur->links++;
                me->link.addr.zone  = link->zone;
                me->link.addr.net   = link->net;
                me->link.addr.node  = link->node;
                me->link.addr.point = link->point;
                me->link.in = me->link.out = me->link.bad = me->link.dupe = 0;
                me->link.inb = me->link.outb = 0;
                if (prevl != NULL) prevl->next = me; else cur->chain = me;
                me->next = curl; curl = me; break;
            }
            else { prevl = curl; curl = curl->next; }
        }
        /* set values */
        if (curl == NULL) return;
        switch (type) {
        case stNORM: curl->link.in++; curl->link.inb += len; break;
        case stBAD:  curl->link.bad++; break;
        case stDUPE: curl->link.dupe++; break;
        case stOUT:  curl->link.out++; curl->link.outb += len; break;
        }
}

void upd_stat(char *file) 
{
    stat_echo *cur, *next;
    FILE *OLD = NULL, *NEW = NULL;
    char *oldf = NULL, *newf = NULL;
    struct {
        char vk[2]; 
        short rev;
        time_t t0;
        char xxx[8];
    } hdr = {"vk", REV_CUR, 0, {0,0,0,0,0,0,0,0}}, ohdr;
    
    if (!do_stat) { msg("stat was disabled"); return; }
    if (statecho == NULL) { 
#ifdef STAT_DEBUG
        msg("Nothing new to stat");
#endif
        return; 
    }
#ifdef STAT_DEBUG
    msg("Current statistic below");
    debug_out(NULL);
    msg("Cumulative statistic below");
#endif
    /* read old base: hpt.sta */
    oldf = file;
    OLD = fopen(oldf, "rb");
    if (OLD != NULL) {
        int rc = fread(&ohdr, sizeof(ohdr), 1, OLD); 
        if (rc < 1) {
#ifdef STAT_DEBUG
            msg2("Ignoring empty or corrupt stat base", oldf);
#endif
            fclose(OLD); OLD = NULL;
        }
        else if (ohdr.rev < REV_MIN || ohdr.rev > REV_MAX) {
            msg2("Incompatible stat base", oldf); fclose(OLD); 
            do_stat = 0; return;
        }
    }
    /* make new base: hpt.st$ */
    if ( (newf = sstrdup(oldf)) ) newf[strlen(newf)-1] = '$';
    else { msg("Out of memory"); if (OLD != NULL) fclose(OLD); return; }
    NEW = fopen(newf, "wb");
    if (NEW == NULL) {
        msg2("Can't create tmp-file", newf);
        if (OLD != NULL) fclose(OLD); 
        do_stat = 0; return; 
    }
    hdr.t0 = OLD ? ohdr.t0 : time(NULL);
    fwrite(&hdr, sizeof(hdr), 1, NEW);
    /* main loop */
    cur = statecho;
    while (do_stat && OLD && !feof(OLD)) {
        stat_echo *old/* = read_echo(OLD)*/;
        old = read_echo(OLD);
        if (!do_stat || old == NULL) break;
        /* write new echoes with lesser names */
        while ( cur && sstricmp(cur->tag, old->tag) < 0 ) {
            write_echo(NEW, cur);
            cur = cur->next;
        }
        /* update current echo */
        if ( cur && sstricmp(cur->tag, old->tag) == 0 ) {
            chain_link *prevl = NULL; 
            chain_link *newl  = cur->chain; 
            chain_link *oldl  = old->chain;
            while (oldl != NULL) {
                int res = newl ? acmp2(&(oldl->link.addr), &(newl->link.addr)) : -1;
                /* insert link before current */
                if (res < 0) {
                    chain_link *me = malloc(sizeof(*me));
                    if (me == NULL) { msg("Out of memory"); do_stat = 0; continue; }
                    
                    memcpy(&(me->link), &(oldl->link), sizeof(me->link));
                    if (prevl != NULL) prevl->next = me; else cur->chain = me;
                    me->next = newl;
                    cur->links++;
                    oldl = oldl->next;
                }
                /* combine links data into current */
                else if (res == 0) {
                    newl->link.in   += oldl->link.in;
                    newl->link.out  += oldl->link.out;
                    newl->link.dupe += oldl->link.dupe;
                    newl->link.bad  += oldl->link.bad;
                    newl->link.inb  += oldl->link.inb;
                    newl->link.outb += oldl->link.outb;
                    oldl = oldl->next;
                    prevl = newl; newl = newl->next;
                }
                /* to append link after current just advance to the next link */
                else if (newl != NULL) { prevl = newl; newl = newl->next; }
            }
            write_echo(NEW, cur);
            cur = cur->next;
        }
        /* keep old echo unchanged */
        else write_echo(NEW, old);
        free_echo(old);
    }
    /* write new echoes to the end of base */
    while (do_stat && cur != NULL) { write_echo(NEW, cur); cur = cur->next; }
    cur = statecho;
    while (cur != NULL) { next = cur->next; free_echo(cur); cur = next; }
    /* unlink old and rename new */
    fclose(NEW); if (OLD) fclose(OLD);
    if (do_stat) { remove(oldf); rename(newf, oldf); }
    else { remove(newf); msg("New stat base is not written"); }
}

int write_echo(FILE *F, stat_echo *e) 
{
    chain_link *cl;
    int tst;
    short real_links = 0;
    
    if (!e || !e->links) return 0;
#ifdef STAT_DEBUG
    debug_out(e);
#endif
    cl = e->chain; while (cl) { real_links++; cl = cl->next; }
/*    tst = fwrite(&(e->links), sizeof(e->links), 1, F); */
    tst = fwrite(&(real_links), sizeof(e->links), 1, F);
    tst += fwrite(&(e->tag_len), sizeof(e->tag_len), 1, F);
    tst += fwrite(e->tag, e->tag_len, 1, F);
    if (tst < 3) { msg("Write error"); do_stat = 0; return 0; }
    
    cl = e->chain;
    while (cl) {
        tst = fwrite(&(cl->link), sizeof(cl->link), 1, F);
        if (tst < 1) { msg("Write error"); do_stat = 0; return 0; }
        cl = cl->next;
    }
    return 1;
}

stat_echo *read_echo(FILE *F) 
{
    stat_echo *old;
    chain_link *l, *prev = NULL;
    short ol, ot;
    int i, tst;
    
    tst = fread(&ol, sizeof(ol), 1, F); if (tst < 1) return NULL;
    tst = fread(&ot, sizeof(ot), 1, F); if (tst < 1) return NULL;
    
    old = calloc( 1, sizeof (stat_echo) );
    if (old == NULL) { msg("Out of memory"); do_stat = 0; return NULL; }
    
    old->links = ol; 
    old->tag_len = ot; 
    old->chain = NULL;
    old->tag = calloc( 1, ot+1 );
    tst = fread(old->tag, ot, 1, F); 

    if (tst < 1) { msg("Read error"); free_echo(old); do_stat = 0; return NULL; }
    /* read links */
    for (i = 0; i < ol; i++) {
        l = malloc(sizeof(*l));
        if (l == NULL) { msg("Out of memory"); do_stat = 0; return NULL; }
        
        if (prev != NULL) prev->next = l; else old->chain = l;
        l->next = NULL;
        tst = fread(&(l->link), sizeof(l->link), 1, F);
        if (tst < 1) { msg("Read error"); free_echo(old); do_stat = 0; return NULL; }
        prev = l;
    }
    return old;
}

void free_echo(stat_echo *e) {
    chain_link *cur, *next;
    cur = e->chain;
    while (cur != NULL) { next = cur->next; nfree(cur); cur = next; }
    nfree(e->tag);
    nfree(e);
}

void debug_out(stat_echo *e) {
#ifdef STAT_DEBUG
    stat_echo *cur = e ? e : statecho;
    chain_link *curl;
    while (cur != NULL) {
        curl = cur->chain;
        while (curl != NULL) {
#ifdef STAT_ALONE
            fprintf(stderr, "%s, %d:%d/%d.%d: i=%d/o=%d/b=%d/d=%d ib=%d/ob=%d\n",
#else
                w_log(LL_DEBUGS, "%s, %d:%d/%d.%d: i=%d/o=%d/b=%d/d=%d ib=%d/ob=%d",
#endif
                cur->tag,
                curl->link.addr.zone, curl->link.addr.net, curl->link.addr.node, curl->link.addr.point,
                curl->link.in, curl->link.out, curl->link.bad, curl->link.dupe,
                curl->link.inb, curl->link.outb);
            curl = curl->next;
        }
        if (e) break;
        cur = cur->next;
    }
#endif
}
