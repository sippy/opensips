/*
 * digest_auth library
 *
 * Copyright (C) 2011 VoIP Embedded Inc.
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
 * History:
 * --------
 *  2011-05-13  initial version (Ovidiu Sas)
 */

#ifndef _DIGEST_AUTH_H_
#define _DIGEST_AUTH_H_

#include "digest_auth_md5.h"
#include "digest_auth_sha256.h"
#include "digest_auth_sha512t256.h"

#define WWW_AUTH_CODE       401
#define WWW_AUTH_HDR        "WWW-Authenticate"
#define PROXY_AUTH_CODE     407
#define PROXY_AUTH_HDR      "Proxy-Authenticate"

/* First/Last supported algorithm */
#define FIRST_ALG_SPTD (ALG_UNSPEC)
#define LAST_ALG_SPTD  (ALG_SHA512_256SESS)

typedef union {
	HASH_MD5 MD5;
	HASH_SHA256 SHA256;
	HASH_SHA512t256 SHA512t256;
} HASH;

typedef union {
	HASHHEX_MD5 MD5;
	HASHHEX_SHA256 SHA256;
	HASHHEX_SHA512t256 SHA512t256;
	char _start[0];
} HASHHEX;

struct digest_auth_calc;

struct digest_auth_response {
	HASH RespHash;
	const struct digest_auth_calc *digest_calc;
};

struct digest_auth_credential {
        str realm;
        str user;
        str passwd;
};

static inline void cvt_hex(const char *bin, char *hex, int HASHLEN, int HASHHEXLEN)
{
        unsigned short i;
        unsigned char j;

        for (i = 0; i<HASHLEN; i++)
        {
                j = (bin[i] >> 4) & 0xf;
                if (j <= 9)
                {
                        hex[i * 2] = (j + '0');
                } else {
                        hex[i * 2] = (j + 'a' - 10);
                }

                j = bin[i] & 0xf;

                if (j <= 9)
                {
                        hex[i * 2 + 1] = (j + '0');
                } else {
                        hex[i * 2 + 1] = (j + 'a' - 10);
                }
        };

        hex[HASHHEXLEN] = '\0';
}

static inline int bcmp_hex(const char *bin, const char *hex, int HASHLEN)
{
        unsigned short i;
        unsigned char j;

        for (i = 0; i<HASHLEN; i++)
        {
                j = (bin[i] >> 4) & 0xf;
                if (j <= 9)
                {
                        if (hex[i * 2] != (j + '0'))
				return (1);
                } else {
                        if (hex[i * 2] != (j + 'a' - 10))
				return (1);
                }

                j = bin[i] & 0xf;

                if (j <= 9)
                {
                        if (hex[i * 2 + 1] != (j + '0'))
				return (1);
                } else {
                        if (hex[i * 2 + 1] != (j + 'a' - 10))
				return (1);
                }
        };

        return (0);
}

#endif
