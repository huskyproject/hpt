/*****************************************************************************
 * AreaFix for HPT (FTN NetMail/EchoMail Tosser)
 *****************************************************************************
 * Copyright (C) 2000
 *
 * Lev Serebryakov
 *
 * Fido:     2:5030/661
 * Internet: lev@serebryakov.spb.ru
 * St.Petersburg, Russia
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(__TURBOC__) && !(defined(_MSC_VER) && (_MSC_VER >= 1200))
#include <unistd.h>
#endif

#include <ctype.h>
#include <arealist.h>
#include <fidoconf/common.h>

#define LIST_PAGE_SIZE	256

ps_arealist newAreaList()
{
	ps_arealist al;

	if(NULL == (al = malloc(sizeof(s_arealist)))) return NULL;
	al->areas = NULL;
	al->count = 0;
	al->maxcount = LIST_PAGE_SIZE;
	if(NULL == (al->areas = malloc(al->maxcount*sizeof(s_arealistitem)))) { free(al); return NULL; }
	return al;
}

void freeAreaList(ps_arealist al)
{
	int i;
	if(al) {
		if(al->areas && al->maxcount) {
			for(i = 0; i < al->count; i++) {
				nfree(al->areas[i].tag);
				nfree(al->areas[i].desc);
			}
			nfree(al->areas);
		}
		nfree(al);
	}
	return;
}

int addAreaListItem(ps_arealist al, int active, char *tag, char *desc)
{
	ps_arealistitem areas;
	int l;

	if(al->count == al->maxcount) {
		if(NULL == (areas = realloc(al->areas,(al->maxcount+LIST_PAGE_SIZE)*sizeof(s_arealistitem)))) return 1;
		al->areas = areas;
		al->maxcount += LIST_PAGE_SIZE;
    }
    al->areas[al->count].active = active;
    al->areas[al->count].tag = strdup(tag);
    if(desc) {
    	l = strlen(desc);
    	al->areas[al->count].desc = safe_malloc(l+3);
    	if('"' == desc[0] && '"' == desc[l-1]) {
    		strcpy(al->areas[al->count].desc,desc);
    	} else {
    		al->areas[al->count].desc[0] = '"';
    		strcpy(&al->areas[al->count].desc[1],desc);
			al->areas[al->count].desc[l+1] = '"';
			al->areas[al->count].desc[l+2] = '\x00';
    	}
	}
    else al->areas[al->count].desc = NULL;
	al->count++;

	return 0;
}

static int compare_arealistitems(const void *a, const void *b) { return strcmp(((ps_arealistitem)a)->tag,((ps_arealistitem)b)->tag); }

void sortAreaList(ps_arealist al)
{
	if(al && al->count && al->areas)
		qsort(al->areas,al->count,sizeof(s_arealistitem),compare_arealistitems);
}

static char *addline(char *text, char *line, int *pos, int *tlen)
{
	int ll;

	if(!text) return NULL;
	if(!line) return text;

	ll = strlen(line);

	if(*pos+ll+1 > *tlen) {
		*tlen += 1024;
		if(NULL == (text = realloc(text,*tlen))) return NULL;
	}
	strcpy(&text[*pos],line);
	*pos += ll;
	return text;
}

static char *addchars(char *text, char c, int count, int *pos, int *tlen)
{
	int i;
	if(!text) return NULL;
	if(*pos+count+1 > *tlen) {
		*tlen += count+1024;
		if(NULL == (text = realloc(text,*tlen))) return NULL;
	}
	for(i = *pos; i < *pos+count; i++) text[i] = c;
    text[i] = '\x00';
    *pos += count;
	return text;
}

char *formatAreaList(ps_arealist al, int maxlen, char *activechars)
{
	char *text;
	char *p;
	int i;
	int clen,wlen;
	int tlen;
	int tpos = 0;

	if(!al || !al->count || !al->areas) return NULL;

	tlen = al->count * (maxlen+3);

	if(NULL == (text = malloc(tlen))) return NULL;
	text[tpos] = '\x00';
	
	for(i = 0; i < al->count; i++) {
		clen = 0;
		if(tpos >= tlen) {
			tlen += (maxlen+3) * 32;
			if(NULL == (text = realloc(text,tlen))) return NULL;
		}
		if(activechars) {
			text[tpos++] = activechars[al->areas[i].active];
			clen++;
		}
		text[tpos++] = ' ';
		clen++;
		text[tpos] = '\x00';

        if(NULL == (text = addline(text,al->areas[i].tag,&tpos,&tlen))) return NULL;

        /* Not add description */
        if(!al->areas[i].desc) {
			text[tpos++] = '\r';
			text[tpos] = '\x00';
        	continue;
		}

        clen += strlen(al->areas[i].tag);
        wlen = strlen(al->areas[i].desc);
        if(clen + 3 + wlen <= maxlen) {
			text[tpos++] = ' ';
			text[tpos] = '\x00';
	        if(NULL == (text = addchars(text,'.',maxlen-(clen+2+wlen),&tpos,&tlen))) return NULL;
			text[tpos++] = ' ';
			text[tpos] = '\x00';
	        if(NULL == (text = addline(text,al->areas[i].desc,&tpos,&tlen))) return NULL;
        } else {
        	p = strchr(al->areas[i].desc,' ');
        	if(p && (p - al->areas[i].desc) + clen + 3 <= maxlen) {
        		wlen = p - al->areas[i].desc;
				*p = '\x00';				

				text[tpos++] = ' ';
				text[tpos] = '\x00';
	    	    if(NULL == (text = addchars(text,'.',maxlen-(clen+2+wlen),&tpos,&tlen))) {
	        		*p = ' ';
	        		return NULL;
				}
				text[tpos++] = ' ';
				text[tpos] = '\x00';
	        	if(NULL == (text = addline(text,al->areas[i].desc,&tpos,&tlen))) {
	        		*p = ' ';
	        		return NULL;
				}
				wlen = strlen(p+1);
				text[tpos++] = '\r';
				text[tpos] = '\x00';
		        if(NULL == (text = addline(addchars(text,' ',maxlen-wlen,&tpos,&tlen),p+1,&tpos,&tlen))) {
					*p = ' ';
		        	return NULL;
				}
				*p = ' ';
        	} else {
				text[tpos++] = '\r';
				text[tpos] = '\x00';
		        if(NULL == (text = addline(addchars(text,' ',maxlen-wlen,&tpos,&tlen),al->areas[i].desc,&tpos,&tlen))) return NULL;
        	}
        }
		text[tpos++] = '\r';
		text[tpos] = '\x00';
	}
	return text;
}
