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

/*
 * Markbetween() macro takes int-like type in x treats it as a sequence of bytes
 * and produces a value of the same type and lengh with bytes of original
 * value in the range m > bX < n replaced with 0x80 and the rest with 0x00, i.e.
 *
 * markbetween((uint64_t)0x0102030405060708, 0x03, 0x08) == (uint64_t)0x0000008080808000
 *
 * Obtained from Bit Twiddling Hacks By Sean Eron Anderson <seander@cs.stanford.edu>
 */
#define markbetween(x,m,n) \
  (((~(typeof(x))0/255*(127+(n))-((x)&~(typeof(x))0/255*127))&~(x)&(((x)&~(typeof(x))0/255*127)+~(typeof(x))0/255*(127-(m))))&~(typeof(x))0/255*128)

/*
 * TURBO_LCMASK() generates mask that can be ORed with original int-like
 * value x to produce lower-case version of the sequence of bytes contained
 * in x.
 */
#define TURBO_LCMASK(x) (markbetween(x, 'A' - 1, 'Z' + 1) >> 2)
#define TOLOWER_FUNC(itype) \
    static inline unsigned itype \
    turbo_tolower_##itype(const void *wp) \
    { \
        unsigned itype msk, wrd; \
        memcpy(&wrd, wp, sizeof(wrd)); \
        msk = TURBO_LCMASK(wrd); \
        return (wrd | msk); \
    }

TOLOWER_FUNC(long);
TOLOWER_FUNC(int);
TOLOWER_FUNC(short);
TOLOWER_FUNC(char);

#define FASTCASEBCMP_LOOP(itype) \
    while (len >= sizeof(unsigned itype)) { \
        if (turbo_tolower_##itype(us1.itype##_p) != turbo_tolower_##itype(us2.itype##_p)) \
            return 1; \
        len -= sizeof(unsigned itype); \
        if (len == 0) \
            return 0; \
        us1.itype##_p++; \
        us2.itype##_p++; \
    }

/*
 * The turbo_casebcmp() function compares ASCII byte strings s1 against s2,
 * ignoring case and returning zero if they are identical, non-zero otherwise.
 * Both strings are assumed to be len bytes long. Zero-length strings are always
 * identical. No special treatment for \0 is performed, the comparison will
 * continue if both strings are matching until len bytes are compared, i.e.
 * turbo_casebcmp("1234\05678", "1234\05679", 9) will return 1.
 */
static inline int
turbo_casebcmp(const char *s1, const char *s2, unsigned int len)
{
    union {
        const char *char_p;
        const unsigned long *long_p;
        const unsigned int *int_p;
        const unsigned short *short_p;
    } us1, us2;
    us1.char_p = s1;
    us2.char_p = s2;
    FASTCASEBCMP_LOOP(long);
    FASTCASEBCMP_LOOP(int);
    FASTCASEBCMP_LOOP(short);
    FASTCASEBCMP_LOOP(char);
    return 0;
}

#endif
