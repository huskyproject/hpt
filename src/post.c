/*****************************************************************************
 * Post for HPT (FTN NetMail/EchoMail Tosser)
 *****************************************************************************
 * Copyright (C) 1998-99
 *
 * Kolya Nesterov
 *
 * Fido:     2:463/7208.53
 * Kiev, Ukraine
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
 * $Id$
 */
/* Revision log:
   16.12.98 - first version, written at ~1:30, in the middle of doing
   calculation homework on Theoretical Electrics, you understood ;)
   18.12.98 - woops forgot copyright notice, minor fixes
   tearline generation added
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <huskylib/huskylib.h>

#ifdef HAS_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAS_SYS_SYSEXITS_H
#include <sys/sysexits.h>
#endif
#ifdef HAS_SYSEXITS_H
#include <sysexits.h>
#endif

#include <fidoconf/fidoconf.h>
#include <fidoconf/common.h>
#include <fidoconf/afixcmd.h>
#include <areafix/areafix.h>

#include <version.h>
#include <toss.h>
#include <post.h>
#include <global.h>
#include <version.h>
#include <hpt.h>
#include <scanarea.h>
#include <scan.h>
#include <hptafix.h>

#if (defined (__EMX__) || defined (__MINGW32__)) && defined (__NT__)
/* we can't include windows.h for several reasons ... */
#define CharToOem CharToOemA
#endif

#define MAX_LINELEN 45
#define LINPERSECTION 0x7FFFFFFFL

#define ENCODE_BYTE(b) (((b) == 0) ? 0x60 : ((b) + 0x20))

char uu_b[]   = "\"begin\" to last encoded line)\r";
char uu_m[]   = "first to last encoded line)\r";
char uu_e[]   = "first encoded line to \"end\")\r";
char uu_end[] = "end\r";
void print_help(void)
{
    fprintf(stdout, "\n   Post a message to area:\n");
    fprintf(stdout, "        hpt post [options] file\n\n");
    fprintf(stdout, "        options are:\n\n");
    fprintf(stdout, "        -nf \"name from\"\n");
    fprintf(stdout, "            message sender's name, if not defined post uses\n");
    fprintf(stdout, "            sysop name (see fidoconfig)\n\n");
    fprintf(stdout, "        -nt \"name to\"\n");
    fprintf(stdout, "            message receiver's name, if not defined post uses \"All\"\n\n");
    fprintf(stdout, "        -af \"address from\"\n");
    fprintf(stdout, "            message sender's address, if not defined post\n");
    fprintf(stdout, "            uses first system address (see fidoconfig)\n\n");
    fprintf(stdout, "        -at \"address to\"\n");
    fprintf(stdout, "            message receiver's address, *MUST BE PRESENT FOR NETMAIL*\n\n");
    fprintf(stdout, "         -s \"subject\"\n");
    fprintf(stdout, "            subject line, if not defined then assumed to be empty\n\n");
    fprintf(stdout, "         -e \"echo area\"\n");
    fprintf(stdout, "            area to post echomail message into, if not\n");
    fprintf(stdout, "            defined message is posted to netmail\n\n");
    fprintf(stdout, "         -z \"tearline\"\n");
    fprintf(stdout, "            tearline, if not defined then assumed to be\n");
    fprintf(stdout, "            no tearline at all. Use -z \"\" to post with empty tearline\n\n");
    fprintf(stdout, "         -o \"origin\"\n");
    fprintf(stdout, "            origin, if not defined then assumed to be name\n");
    fprintf(stdout, "            of station in config-file\n\n");
    fprintf(stdout, "         -f flag(s)\n");
    fprintf(stdout, "            flags to set to the posted msg. possible ones\n");
    fprintf(stdout, "            are: pvt, crash, read, sent, att, fwd, orphan,\n");
    fprintf(stdout, "            k/s, loc, hld, xx2, frq, rrq, cpt, arq, urq,\n");
    fprintf(stdout, "            kfs, tfs, dir, imm, cfm, npd;\n");
    fprintf(stdout,
            "            use it like this: pvt loc k/s OR pvt,loc,k/s OR \"pvt loc k/s\"\n\n");
    fprintf(stdout, "         -x export message to echo links\n\n");
    fprintf(stdout, "         -d erase input file after posting\n\n");
    fprintf(stdout, "         -u[size] uue-multipart posting\n");
    fprintf(stdout, "            size - number of lines per section (unlimited by default)\n\n");
    fprintf(stdout, "         -h get help\n\n");
    fprintf(stdout, "         file - text file to be posted or \"-\" for stdin\n\n");
    exit(EX_OK);
} /* print_help */

void init_libs(void)
{
    struct _minf m;

    if(config == NULL)
    {
        processConfig();
    }

    /* init areafix */
    if(!init_hptafix())
    {
        exit_hpt("Can't init Areafix library", 1);
    }

    if(initSMAPI == -1)
    {
        /*  init SMAPI */
        initSMAPI     = 0;
        m.req_version = 0;
        m.def_zone    = (UINT16)config->addr[0].zone;

        if(MsgOpenApi(&m) != 0)
        {
            exit_hpt("MsgApiOpen Error", 1);
        } /*endif */
    }
} /* init_libs */

struct post_parameters
{
    char *   name_from; /* should be freed */
    int      name_from_len;
    char *   name_to;   /* should be freed */
    int      name_to_len;
    char *   address_from;
    char *   address_to;
    char *   subject;   /* should be freed */
    int      subject_len;
    char *   area_name;
    char *   tearline;  /* should be freed */
    int      tearline_len;
    char *   origin;    /* should be freed */
    int      origin_len;
    long     attr;
    char *   flags;     /* should be freed */
    int      export_mail;
    int      erase_file;
    int      uue;
    int      sum_r;
    char *   file;
    char *   fname;     /* should be freed */
    int      file_size;
    s_area * area;
    char *   text_head; /* should be freed */
    char *   text_foot; /* should be freed */
    int      sections;
    char *   temp_file; /* should be freed */
    long *   sectioning; /* should be freed */
    int      perms;
};

void free_post_parameters(struct post_parameters * p)
{
    nfree(p->name_to);
    nfree(p->name_from);
    nfree(p->subject);
    nfree(p->tearline);
    nfree(p->origin);
    nfree(p->flags);
    nfree(p->fname);
    nfree(p->text_head);
    nfree(p->text_foot);
    nfree(p->temp_file);
    nfree(p->sectioning);
}

int strdup_convert(char ** dest, char * src)
{
    size_t len;

    assert(dest != NULL);

    if(src == NULL)
    {
        *dest = NULL;
        return 0;
    }

    len   = strlen(src);
    *dest = malloc(len + 1);

    if(*dest == NULL)
    {
        w_log(LL_CRIT, "out of memory");
        return -1;
    }

#ifdef __NT__
    CharToOem(src, *dest);
#else
    memcpy(*dest, src, len + 1);
#endif
    return (int)len;
} /* strdup_convert */

int parse_post_command(struct post_parameters * p,
                       unsigned int argc,
                       char ** argv,
                       unsigned int * n)
{
    char * cur_arg;

    for( ; *n < argc; (*n)++)
    {
        cur_arg = argv[*n];

        if(*cur_arg == '-' && cur_arg[1] != '\0')
        {
            switch(cur_arg[1])
            {
                case 'a': /*  address */

                    if(*n + 1 >= argc)
                    {
                        goto unknown_switch;
                    }

                    if(cur_arg[2] == 't' && cur_arg[3] == 0)
                    {
                        p->address_to = argv[++*n];
                    }
                    else if(cur_arg[2] == 'f' && cur_arg[3] == 0)
                    {
                        p->address_from = argv[++*n];
                    }
                    else
                    {
                        goto unknown_switch;
                    }

                    break;

                case 'n': /*  name */

                    if(*n + 1 >= argc)
                    {
                        goto unknown_switch;
                    }

                    if(cur_arg[2] == 't' && cur_arg[3] == 0)
                    {
                        if(-1 == (p->name_to_len = strdup_convert(&p->name_to, argv[++*n])))
                        {
                            goto low_mem;
                        }
                    }
                    else if(cur_arg[2] == 'f' && cur_arg[3] == 0)
                    {
                        if(-1 == (p->name_from_len = strdup_convert(&p->name_from, argv[++*n])))
                        {
                            goto low_mem;
                        }
                    }
                    else
                    {
                        goto unknown_switch;
                    }

                    break;

                case 'f': /*  flags */

                    if(cur_arg[2] != 0)
                    {
                        goto unknown_switch;
                    }

                    for(++*n; *n < argc; ++*n)
                    {
                        long attr = 0;
                        char * flags = NULL, * end = NULL;
                        int parsed;
                        parsed = parseAttrString(argv[*n], &flags, &attr, &end);

                        if(parsed <= 0 || *end != '\0')
                        {
                            nfree(flags);
                            break;
                        }

                        if(attr)
                        {
                            p->attr |= attr;
                        }

                        if(flags != NULL)
                        {
                            xstrscat(&p->flags, " ", flags, NULLP);
                            nfree(flags);
                        }
                    }
                    --*n;
                    break;

                case 'e': /*  echo name */

                    if(cur_arg[2] != 0 || *n + 1 >= argc)
                    {
                        goto unknown_switch;
                    }

                    p->area_name = argv[++*n];
                    break;

                case 's': /*  subject */

                    if(cur_arg[2] != 0 || *n + 1 >= argc)
                    {
                        goto unknown_switch;
                    }

                    if(-1 == (p->subject_len = strdup_convert(&p->subject, argv[++*n])))
                    {
                        goto low_mem;
                    }

                    break;

                case 'x': /*  export message */

                    if(cur_arg[2] != 0)
                    {
                        goto unknown_switch;
                    }

                    p->export_mail = 1;
                    break;

                case 'd': /*  erase input file after posting */

                    if(cur_arg[2] != 0)
                    {
                        goto unknown_switch;
                    }

                    p->erase_file = 1;
                    break;

                case 'u': /*  uue-multipart posting */
                    p->uue = atoi(cur_arg + 2); /* TODO: additional checks would be great */

                    if(p->uue < 1) /* zero or negative */
                    {
                        p->uue = LINPERSECTION;
                    }

                    break;

                case 'z': /*  tearline */

                    if(cur_arg[2] != 0 || *n + 1 >= argc)
                    {
                        goto unknown_switch;
                    }

                    if(-1 == (p->tearline_len = strdup_convert(&p->tearline, argv[++*n])))
                    {
                        goto low_mem;
                    }

                    break;

                case 'o': /*  origin */

                    if(cur_arg[2] != 0 || *n + 1 >= argc)
                    {
                        goto unknown_switch;
                    }

                    if(-1 == (p->origin_len = strdup_convert(&p->origin, argv[++(*n)])))
                    {
                        goto low_mem;
                    }

                    break;

                default:
                    goto unknown_switch;
            } /* switch */
        }
        else
        {
            break;
        }
    }

    /* We discovered first non-switch argument or end of command line */
    if(*n < argc)
    {
        p->file = argv[*n];
        ++*n;
    }
    else
    {
        w_log(LL_CRIT, "post: no filename is given");
        return 3;
    }

    return 0;

unknown_switch: w_log(LL_CRIT, "post: unknown or incomplete switch %s", cur_arg);
    return 1;

low_mem: w_log(LL_CRIT, "post: low memory");
    return 2;
} /* parse_post_command */

int sum_r_byte(UCHAR byte, int checksum)
{
    checksum  = (checksum >> 1) + ((checksum & 1) << 15); /* ror */
    checksum += byte;
    checksum &= 0xffff;
    return checksum;
}

int sum_r(UCHAR * buffer, int length, int checksum)
{
    int i;

    for(i = 0; i < length; ++i)
    {
        checksum = sum_r_byte(buffer[i], checksum);
    }
    return checksum;
}

/* in_line buffer size should be multiple of 3 zero-padded if needed */
/* out_line buffer should be ceiling(len/3)*4 + 1 + "\n" bytes long */
int uuencode_line(UCHAR * in_line, int len, UCHAR * out_line, int * sum_r_src, int * sum_r_enc)
{
    UCHAR * in_ptr = in_line, * out_ptr = out_line;
    int i;

    assert(in_line != NULL);
    assert(out_line != NULL);
    assert(len < 0x40);

    if(sum_r_src != NULL)
    {
        *sum_r_src = sum_r(in_line, len, *sum_r_src);
    }

    *out_ptr++ = ENCODE_BYTE((UCHAR)len);

    /* Encode the line */
    for(i = 0; i < len; i += 3, in_ptr += 3, out_ptr += 4)
    {
        /* Encode 3 bytes from the input buffer */
        out_ptr[0] = ENCODE_BYTE((in_ptr[0]) >> 2);
        out_ptr[1] = ENCODE_BYTE(((in_ptr[0] & 0x03) << 4) | ((in_ptr[1]) >> 4));
        out_ptr[2] = ENCODE_BYTE(((in_ptr[1] & 0x0F) << 2) | ((in_ptr[2]) >> 6));
        out_ptr[3] = ENCODE_BYTE(in_ptr[2] & 0x3F);
    }

    if(sum_r_enc != NULL)
    {
        *sum_r_enc = sum_r(out_line, (int)(out_ptr - out_line), *sum_r_enc);
        *sum_r_enc = sum_r_byte(0x0a, *sum_r_enc);
    }

    *out_ptr++ = '\r';
    return (int)(out_ptr - out_line);
} /* uuencode_line */

FILE * uuencode_file(FILE * input, struct post_parameters * p)
{
    unsigned int part = 0, max_sections = 16, sect_size = 0;
    int lines = 0, sum_r_sect = 0;
    size_t linelen, outlen;
    UCHAR inbuf[MAX_LINELEN];
    UCHAR outbuf[MAX_LINELEN / 3 * 4 + 1 + 1]; /* + \r + prefix */
    FILE * tmpfile    = NULL;
    char * begin_line = NULL;

    assert(MAX_LINELEN % 3 == 0);

    if((p->sectioning = malloc(sizeof(long) * max_sections)) == NULL)
    {
        return NULL;
    }

    xstrscat(&p->temp_file, config->tempOutbound, "hptucode.$$$", NULLP);
    tmpfile = fopen(p->temp_file, "wb");

    if(tmpfile == NULL)
    {
        w_log(LL_ERROR, "post: failed to open temp file %s: %s", p->temp_file, strerror(errno));
        return NULL;
    }

    p->sectioning[0] = 0;

    /* Write the 'begin' line, giving it a mode of 0600 */
    sect_size  = xscatprintf(&begin_line, "begin %03o %s\r", p->perms, p->fname);
    sum_r_sect = sum_r((UCHAR *)begin_line, sect_size - 1, sum_r_sect);
    sum_r_sect = sum_r_byte(0x0a, sum_r_sect);

    if(fwrite(begin_line, 1, sect_size, tmpfile) != sect_size) /* error */
    {
        nfree(begin_line);
        fclose(input);
        fclose(tmpfile);
        w_log(LL_ERROR, "post: temp file write error: %s", strerror(errno));
        return NULL;
    }

    nfree(begin_line);

    do
    {
        if(lines >= p->uue)
        {
            ++part;

            if(part + 1 >= max_sections) /* yes, alloc in advance for one element that will mark
                                            eof */
            {
                max_sections *= 2;
                p->sectioning = srealloc(p->sectioning, sizeof(long) * max_sections);
            }

            fprintf(tmpfile, "\rsum -r/size %d/%u section (from ", sum_r_sect, sect_size);

            if(part == 1)
            {
                fwrite(uu_b, sizeof(uu_b) - 1, 1, tmpfile);
            }
            else
            {
                fwrite(uu_m, sizeof(uu_m) - 1, 1, tmpfile);
            }

            p->sectioning[part] = (long)ftell(tmpfile);
            lines      = sect_size = 0;
            sum_r_sect = 0;
        }

        linelen       = fread(inbuf, 1, MAX_LINELEN, input);
        p->file_size += (int)linelen;
        outlen        = (size_t)uuencode_line(inbuf, (int)linelen, outbuf, &p->sum_r, &sum_r_sect);
        sect_size    += (unsigned int)outlen;

        if(fwrite(outbuf, 1, outlen, tmpfile) != outlen) /* error */
        {
            fclose(input);
            fclose(tmpfile);
            w_log(LL_ERROR, "post: temp file write error: %s", strerror(errno));
            return NULL;
        }

        ++lines;
    }
    while(linelen != 0);
    sect_size += (unsigned int)fwrite(uu_end, 1, sizeof(uu_end) - 1, tmpfile);
    sum_r_sect = sum_r((UCHAR *)uu_end, sizeof(uu_end) - 2, sum_r_sect);
    sum_r_sect = sum_r_byte(0x0a, sum_r_sect);
    fprintf(tmpfile, "\rsum -r/size %d/%u section (from ", sum_r_sect, sect_size);
    fwrite(uu_e, sizeof(uu_e) - 1, 1, tmpfile);
    fprintf(tmpfile, "sum -r/size %d/%d entire input file\r", p->sum_r, p->file_size);
    ++part;
    assert(part < max_sections);
    p->sectioning[part] = (long)ftell(tmpfile);
    p->sections         = part;
    p->sectioning       = srealloc(p->sectioning, sizeof(long) * (p->sections + 1));
    fclose(input);
    fclose(tmpfile);
    return fopen(p->temp_file, "rb");
} /* uuencode_file */

UINT uuencode2buf(struct post_parameters * p, char ** text, UINT msg_len, FILE * input, int part)
{
    int sum_r_sect = 0, sect_size = 0, lines = 0;
    UINT linelen, max_msg_len, outlen;
    UCHAR inbuf[MAX_LINELEN];

    if(part == 0)
    {
        msg_len   += sect_size = xscatprintf(text, "begin %03o %s\r", p->perms, p->fname);
        sum_r_sect = sum_r((UCHAR *)*text + msg_len - sect_size, sect_size - 1, sum_r_sect);
        sum_r_sect = sum_r_byte(0x0a, sum_r_sect);
    }

    assert(MAX_LINELEN % 3 == 0);
    max_msg_len = msg_len + (MAX_LINELEN / 3 * 4 + 1 + 1) * p->uue;
    *text       = srealloc(*text, max_msg_len + 1);

    do
    {
        linelen = (UINT)fread(inbuf, 1, MAX_LINELEN, input);
        assert(msg_len + (MAX_LINELEN / 3 * 4 + 1 + 1) <= max_msg_len);
        outlen =
            uuencode_line(inbuf, linelen, (UCHAR *)*text + msg_len, &p->sum_r, &sum_r_sect);
        msg_len   += outlen;
        sect_size += outlen;
        ++lines;
    }
    while(linelen != 0 && lines < p->uue);
    (*text)[msg_len] = '\0';

    if(linelen == 0)
    {
        xstrcat(text, uu_end);
        msg_len   += sizeof(uu_end) - 1;
        sect_size += sizeof(uu_end) - 1;
        sum_r_sect = sum_r((UCHAR *)uu_end, sizeof(uu_end) - 2, sum_r_sect);
        sum_r_sect = sum_r_byte(0x0a, sum_r_sect);
        msg_len   += xscatprintf(text,
                                 "\rsum -r/size %d/%u section (from %s",
                                 sum_r_sect,
                                 sect_size,
                                 uu_e);
        msg_len += xscatprintf(text,
                               "sum -r/size %d/%d entire input file\r",
                               p->sum_r,
                               p->file_size);
    }
    else
    {
        if(part == 0)
        {
            msg_len += xscatprintf(text,
                                   "\rsum -r/size %d/%u section (from %s",
                                   sum_r_sect,
                                   sect_size,
                                   uu_b);
        }
        else
        {
            msg_len += xscatprintf(text,
                                   "\rsum -r/size %d/%u section (from %s",
                                   sum_r_sect,
                                   sect_size,
                                   uu_m);
        }
    }

    return msg_len;
} /* uuencode2buf */

FILE * open_input_file(struct post_parameters * p)
{
    FILE * input = NULL;

    if(p->file == NULL)
    {
        return NULL;
    }

    if(p->file[0] == '-' && p->file[1] == 0)
    {
        if(p->uue)
        {
            w_log(LL_CRIT, "post: uuencoding of stdin is not implemented");
        }
        else
        {
            input = stdin;
        }
    }
    else if(fexist(p->file))
    {
        input = fopen(p->file, (p->uue) ? "rb" : "rt");

        if(input == NULL)
        {
            w_log(LL_ERROR, "post: failed to open input file %s: %s", p->file, strerror(errno));
        }
        else if(p->uue) /* Calculate number of sections */
        {
            long file_size, lines;
            p->perms = 0644;
#ifdef __UNIX__
            {
                struct stat st;

                if(fstat(fileno(input), &st) == 0)
                {
                    p->perms = st.st_mode & 0777;
                }
            }
#else

            if(patimat(p->file, "*.exe") || patimat(p->file, "*.com"))
            {
                p->perms = 0755;
            }

#endif

            file_size = fsize(p->file);

            if(file_size < 0)
            {
                /* no precalculation is possible for this file
                 * or on current platform, fallback to temp file */
                input = uuencode_file(input, p);
            }
            else
            {
                lines        = (file_size + MAX_LINELEN - 1) / MAX_LINELEN + 1; /* +1 for
                                                                                   zero-len line
                                                                                   */
                p->sections  = (lines + p->uue - 1) / p->uue;
                p->file_size = file_size;
            }
        }
    }
    else
    {
        w_log(LL_ERROR, "post: input file '%s' does not exist", p->file);
    }

    return input;
} /* open_input_file */

int process_parameters(struct post_parameters * p, s_message * msg)
{
    int result = 0;

    /* Copy given values or set defaults */
    if(p->name_to != NULL)
    {
        msg->toUserName = p->name_to;
        p->name_to      = NULL;
    }
    else
    {
        msg->toUserName = safe_strdup("All");
        p->name_to_len  = 3;
    }

    if(p->name_from != NULL)
    {
        msg->fromUserName = p->name_from;
        p->name_from      = NULL;
    }
    else
    {
        msg->fromUserName = safe_strdup(config->sysop);
        p->name_from_len  = (int)strlen(config->sysop);
    }

    if(p->subject != NULL)
    {
        msg->subjectLine = p->subject;
        p->subject       = NULL;
    }
    else
    {
        msg->subjectLine = safe_calloc(1, 1);
    }

    strdup_convert(&p->fname, GetFilenameFromPathname(p->file));

    /* Choose where to post */
    if(p->area_name != NULL)
    {
        p->area = getNetMailArea(config, p->area_name);

        if(p->area == NULL)
        {
            p->area = getArea(config, p->area_name);

            if(p->area == &(config->badArea))
            {
                w_log(LL_ERROR, "post: wrong area to post: %s", p->area_name);
                return 1;
            }
        }
        else   /* found NetmailArea */
        {
            msg->netMail = 1;
        }
    }
    else /* first netmail area is default */
    {
        msg->netMail = 1;
        p->area      = &(config->netMailAreas[0]);
    }

    /* Decide on addresses */
    assert(p->area != NULL);

    if(p->address_from != NULL)
    {
        /* set defaults */
        msg->origAddr.zone = config->addr[0].zone;
        msg->origAddr.net  = config->addr[0].net;
        result             = parseFtnAddrZ(p->address_from, &(msg->origAddr), FTNADDR_NODE, NULL);

        if(result & FTNADDR_ERROR)
        {
            w_log(LL_ERROR, "post: wrong 'from' address: %s", p->address_from);
            return 1;
        }
    }
    else
    {
        msg->origAddr = p->area->useAka[0];
    }

    if(msg->netMail == 1)
    {
        if(p->address_to)
        {
            /* set defaults */
            msg->destAddr.zone = msg->origAddr.zone;
            msg->destAddr.net  = msg->origAddr.net;
            result             = parseFtnAddrZ(p->address_to, &msg->destAddr, FTNADDR_NODE, NULL);

            if(result & FTNADDR_ERROR)
            {
                w_log(LL_ERROR, "post: wrong 'to' address: %s", p->address_to);
                return 1;
            }
        }
        else
        {
            w_log(LL_ERROR, "post: attempt to post netmail msg without specifying dest. address");
            return 1;
        }
    }

    /* Copy attributes */
    msg->attributes |= p->attr;

    /* Create header for message(s) text */
    /* createKludges shouldn't be called here since it generate MSGID */
    if((p->export_mail || !p->area->fileName) && !config->disableTID)
    {
        xscatprintf(&p->text_head, "\001TID: %s\r", versionStr);
    }

    if(p->flags)
    {
        xscatprintf(&p->text_head, "\001FLAGS%s\r", p->flags);
    }

    /* Create footer for message(s) text */
    xscatprintf(&p->text_foot, "\r");

    if(!msg->netMail || p->tearline)
    {
        if(p->tearline_len > (79 - 4))
        {
            p->tearline[79 - 4] = '\0';
        }

        /* tearline in config supposed to be of acceptable length */
        xscatprintf(&p->text_foot,
                    "--- %s\r",
                    (p->tearline) ? p->tearline : (config->tearline) ? config->tearline : "");
    }

    if(!msg->netMail || p->origin)
    {
        char * origAddr = aka2str(&msg->origAddr);
        int origLen     = 11 + 3 +     /* " * Origin: " + " ()" */
                          (int)strlen(origAddr);
        assert(origLen < 79);

        if(p->origin == NULL)
        {
            p->origin     = safe_strdup((config->origin) ? config->origin : config->name);

            /* use versionStr for the origin line if no Name or Origin has been set in the config file */
            if (p->origin == NULL)
            {
                p->origin = safe_strdup(versionStr);
            }

            p->origin_len = (int)strlen(p->origin);
        }

        if(origLen + p->origin_len > 79)
        {
            p->origin[79 - origLen] = '\0';
        }

        xscatprintf(&p->text_foot, " * Origin: %s (%s)\r", p->origin, aka2str(&msg->origAddr));
    }

    /*  recoding from internal to transport charSet */
    if(config->outtab != NULL)
    {
        recodeToTransportCharset((char *)msg->fromUserName);
        recodeToTransportCharset((char *)msg->toUserName);
        recodeToTransportCharset((char *)msg->subjectLine);
    }

    return 0;
} /* process_parameters */

void process_input_file(struct post_parameters * p, FILE * input, s_message * msg, int * part)
{
    size_t msg_len;

    msg_len = strlen(msg->text);

    if(p->uue)
    {
        msg_len += (size_t)xscatprintf(&msg->text,
                                       "\rsection %d of %d of file %s < %s >\r\r",
                                       *part + 1,
                                       p->sections,
                                       p->fname,
                                       versionStr);

        if(*part > 0)
        {
            msg->subjectLine[p->subject_len] = '\0';
        }

        xscatprintf(&msg->subjectLine, " [%d/%d]", *part + 1, p->sections);

        if(p->temp_file != NULL) /* Load uu-code from temp file */
        {
            size_t to_read, was_read;
            to_read            = (size_t)(p->sectioning[*part + 1] - p->sectioning[*part]);
            msg->text          = srealloc(msg->text, msg_len + to_read + 1);
            msg_len           += was_read = fread(msg->text + msg_len, 1, to_read, input);
            msg->text[msg_len] = '\0';

            if(was_read != to_read) /* error */
            {
                w_log(LL_ERROR, "post: temp file read error: %s", strerror(errno));
                /* Continue anyway */
            }
        }
        else /* Encode on the fly based on size prediction */
        {
            msg_len = (size_t)uuencode2buf(p, &msg->text, (UINT)msg_len, input, *part);
        }

        /* msg_len += xscatprintf(&msg->text,"section %d end\r", *part + 1); */
        ++*part;
    }
    else /* Ordinary text paste */
    {
        int c;
        size_t cursize = msg_len;

        for( ; msg_len < 4 * 1024 * 1024; ++msg_len) /* impose reasonable restriction on max_len
                                                        */
        {
            c = getc(input);

            /* FIXME: Maybe fread with file opened in text mode and replace \n->\r will do
               better? */
            if(c == EOF || c == 0)
            {
                break;
            }

            if(msg_len >= cursize)
            {
                msg->text = safe_realloc(msg->text, (cursize += TEXTBUFFERSIZE) + 1);
            }

            msg->text[msg_len] = (char)c;

            if('\r' == c)
            {
                --msg_len;
            }

            if('\n' == c)
            {
                msg->text[msg_len] = '\r';
            }
        }
        msg->text[msg_len] = 0; /* always ok because buffer's size is (cursize + 1) */

        if(input == stdin)
        {
            while(!feof(input))
            {
                getc(input);
            }
        }
    }
} /* process_input_file */

void do_posting(struct post_parameters * p, FILE * text, s_message * msg)
{
    int part = 0;

    w_log(LL_START, "Start posting...");

    do
    {
        msg->text = createKludges(config,
                                  (msg->netMail == 0) ? strUpper(p->area_name) : NULL,
                                  &msg->origAddr,
                                  &msg->destAddr,
                                  versionStr);
        xstrcat(&msg->text, p->text_head);
        process_input_file(p, text, msg, &part);

        if(msg->text[0] && msg->text[strlen(msg->text) - 1] != '\r')
        {
            xstrcat(&msg->text, p->text_foot);
        }
        else
        {
            xstrcat(&msg->text, p->text_foot + 1);
        }

        msg->textLength = (hINT32)strlen(msg->text);
        w_log(LL_POSTING,
              "Posting msg from %u:%u/%u.%u -> %s in area: %s with subject: %s",
              msg->origAddr.zone,
              msg->origAddr.net,
              msg->origAddr.node,
              msg->origAddr.point,
              msg->netMail ? aka2str(&msg->destAddr) : msg->toUserName,
              (p->area_name) ? p->area_name : p->area->areaName,
              msg->subjectLine);

        /*  recoding from internal to transport charSet */
        if(config->outtab != NULL)
        {
            recodeToTransportCharset((char *)msg->text);
        }

        if(!p->export_mail && p->area->fileName)
        {
            msg->recode &= ~(REC_HDR | REC_TXT); /*  msg in transport Charset */
            putMsgInArea(p->area, msg, 1, msg->attributes);
        }
        else
        {
            if(msg->netMail)
            {
                processNMMsg(msg, NULL, NULL, 0, MSGLOCAL);
            }
            else
            {
                processEMMsg(msg, *(p->area->useAka), 1, (MSGSCANNED | MSGSENT | MSGLOCAL));
            }
        }

        nfree(msg->text);
    }
    while(part < p->sections);

    if(p->export_mail)
    {
        closeOpenedPkt();
        tossTempOutbound(config->tempOutbound);
        writeDupeFiles();
    }

    if((config->echotosslog) && (!p->export_mail))
    {
        FILE * f = fopen(config->echotosslog, "a");

        if(f == NULL)
        {
            w_log(LL_ERROR, "Could not open or create EchoTossLogFile.");
        }
        else
        {
            fprintf(f, "%s\n", p->area->areaName);
            fclose(f);
        }
    }

    w_log(LL_STOP, "End posting");
} /* do_posting */

void post(int c, unsigned int * n, char * params[])
{
    struct post_parameters p =
    {
        0
    };
    FILE * text   = NULL;
    s_message msg = {{0}};
    time_t t      = time(NULL);
    struct tm * tm;

    if(params[*n] != NULL && params[*n][1] == 'h')
    {
        print_help(); /* exit */
    }

    if(parse_post_command(&p, c, params, n))
    {
        free_post_parameters(&p);
        print_help(); /* exit */
    }

    --*n;
    init_libs();

    if(process_parameters(&p, &msg))
    {
        free_post_parameters(&p);
        return;
    }

    if((text = open_input_file(&p)) == NULL)
    {
        free_post_parameters(&p);
        return;
    }

    /*  won't be set in the msgbase, because the mail is processed if it were received */
    tm = localtime(&t);
    fts_time((char *)msg.datetime, tm);
    /* actual read from file and write to messagebase/pkt */
    do_posting(&p, text, &msg);

    /* Cleanup */
    if(!(p.file[0] == '-' && p.file[1] == 0))
    {
        fclose(text);

        if(p.erase_file)
        {
            remove(p.file);
        }
    }

    if(p.temp_file)
    {
        remove(p.temp_file);
    }

    freeMsgBuffers(&msg);
    free_post_parameters(&p);
    /* deinit SMAPI */
    MsgCloseApi();
} /* post */
