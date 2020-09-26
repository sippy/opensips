/*
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */


#ifndef TRIM_H
#define TRIM_H

#ifdef HAVE_SIGIO_RT
#define __USE_GNU /* or else F_SETSIG won't be included */
#define _GNU_SOURCE /* define this as well */
#endif

#include "str.h"

/* whitespace */
static inline int
is_ws(unsigned char ch)
{
    const unsigned int mask = (1 << (' ' - 1)) | (1 << ('\r' - 1)) |
        (1 << ('\n' - 1)) | (1 << ('\t' - 1));
    ch--;
    return ch < ' ' && ((1 << ch) & mask);
}

/*
 * trim leading ws
 *
 * Input: (char *)
 */
#define trim_ws(p) while (*(p) && is_ws(*(p))) p++

/*
 * trim trailing ws
 *
 * Input: (char *)
 */
#define trim_trail_ws(p) while (*(p) && is_ws(*(p))) p--

/*
 * This switch-case statement is used in
 * trim_leading and trim_trailing. You can
 * define characters that should be skipped
 * here.
 */
#define TRIM_SWITCH(c) {if (!is_ws(c)) return;}

/*! \brief
 * Remove any leading whitechars, like spaces,
 * horizontal tabs, carriage returns and line
 * feeds
 *
 * WARNING: String descriptor structure will be
 *          modified ! Make a copy otherwise you
 *          might be unable to free _s->s for
 *          example !
 *
 */

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

struct rtpp_codeptr {
    const char *fname;
    int linen;
    const char *funcn;
};

#define HERETYPE const struct rtpp_codeptr *
#define HEREVAL  ({static const struct rtpp_codeptr _here = {.fname = __FILE__, .linen = __LINE__, .funcn = __func__}; &_here;})
#define HEREARG mlp
#define HERETYPEARG HERETYPE HEREARG

#define TRIM_REPORT(cptr) if ((cptr) != NULL) { \
        int outfd = open("/tmp/TRIM_REPORT.trace", O_CREAT | O_WRONLY | O_APPEND, 0644); \
        if (outfd >= 0) { \
                char *abuf = NULL; \
                int asplen = asprintf(&abuf, "%s(%s:%d)(\"%.*s\")\n", cptr->funcn, \
		    cptr->fname, cptr->linen, _s->len, _s->s); \
                if (asplen > 0 && abuf != NULL) { \
                        write(outfd, abuf, asplen); \
                } \
                if (abuf != NULL) \
                        free(abuf); \
                close(outfd); \
        } \
}

#define trim_leading(_s) _rly_trim_leading(_s, HEREVAL)

static inline void _rly_trim_leading(str* _s, HERETYPEARG)
{
	TRIM_REPORT(HEREARG);
	for(; _s->len > 0; _s->len--, _s->s++) {
		TRIM_SWITCH(*(_s->s));
	}
}


/*! \brief
 * Remove any trailing white char, like spaces,
 * horizontal tabs, carriage returns and line feeds
 *
 * WARNING: String descriptor structure will be
 *          modified ! Make a copy otherwise you
 *          might be unable to free _s->s for
 *          example !
 */
#define trim_trailing(_s) _rly_trim_trailing(_s, HEREVAL)

static inline void _rly_trim_trailing(str* _s, HERETYPEARG)
{
	TRIM_REPORT(HEREARG);
	for(; _s->len > 0; _s->len--) {
		TRIM_SWITCH(_s->s[_s->len - 1]);
	}
}


/*! \brief
 * Do trim_leading and trim_trailing
 *
 * WARNING: String structure will be modified !
 *          Make a copy otherwise you might be
 *          unable to free _s->s for example !
 */
#define trim(_s) _rly_trim(_s, HEREVAL)

static inline void _rly_trim(str* _s, HERETYPEARG)
{
	TRIM_REPORT(HEREARG);
	_rly_trim_leading(_s, NULL);
	_rly_trim_trailing(_s, NULL);
}


#endif /* TRIM_H */
