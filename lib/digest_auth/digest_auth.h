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

#define WWW_AUTH_CODE       401
#define WWW_AUTH_HDR        "WWW-Authenticate"
#define PROXY_AUTH_CODE     407
#define PROXY_AUTH_HDR      "Proxy-Authenticate"

/* First/Last supported algorithm */
#define FIRST_ALG_SPTD (ALG_UNSPEC)
#define LAST_ALG_SPTD  (ALG_SHA256SESS)

typedef union {
	char MD5[HASHLEN_MD5];
	char SHA256[HASHLEN_SHA256];
} HASH;

typedef union {
	char MD5[HASHHEXLEN_MD5 + 1];
	char SHA256[HASHHEXLEN_SHA256 + 1];
	char _start[0];
} HASHHEX;

struct digest_auth_response {
	HASHHEX hhex;
	int hhex_len;
	const str *algorithm_val;
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

#endif
