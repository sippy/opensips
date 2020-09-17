/*
 * Copyright (C) 2020 Maksym Sobolyev
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
 *
 */

#if !defined(_turbocompare_h)
#define _turbocompare_h

#define markbetween(x,m,n) \
  (((~(typeof(x))0/255*(127+(n))-((x)&~(typeof(x))0/255*127))&~(x)&(((x)&~(typeof(x))0/255*127)+~(typeof(x))0/255*(127-(m))))&~(typeof(x))0/255*128)
#define LCMASK(x) (markbetween(x, 'A' - 1, 'Z' + 1) >> 2)
#define TOLOWER_FUNC(itype) \
    static inline unsigned itype \
    turbo_tolower_##itype(const void *wp) \
    { \
        unsigned itype msk, wrd; \
        memcpy(&wrd, wp, sizeof(wrd)); \
        msk = LCMASK(wrd); \
        return (wrd | msk); \
    }

TOLOWER_FUNC(long);
TOLOWER_FUNC(int);
TOLOWER_FUNC(short);
TOLOWER_FUNC(char);

#define FASTCASECMP_LOOP(itype) \
    while (len >= sizeof(unsigned itype)) { \
        if (turbo_tolower_##itype(us1.itype##_p) != turbo_tolower_##itype(us2.itype##_p)) \
            return 1; \
        len -= sizeof(unsigned itype); \
        if (len == 0) \
            return 0; \
        us1.itype##_p++; \
        us2.itype##_p++; \
    }

static inline int
turbo_strncasecmp(const char *s1, const char *s2, unsigned int len)
{
    union {
        const char *char_p;
        const unsigned long *long_p;
        const unsigned int *int_p;
        const unsigned short *short_p;
    } us1, us2;
    us1.char_p = s1;
    us2.char_p = s2;
    FASTCASECMP_LOOP(long);
    FASTCASECMP_LOOP(int);
    FASTCASECMP_LOOP(short);
    FASTCASECMP_LOOP(char);
    return 0;
}

#endif
