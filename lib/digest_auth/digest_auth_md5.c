/*
 * Copyright (C) 2011 VoIP Embedded Inc.
 * Copyright (C) 2013 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * Registrant OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * Registrant OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <ctype.h>
#include <string.h>

#include "../../str.h"
#include "../../md5global.h"
#include "../../md5.h"
#include "../../parser/digest/digest_parser.h"

#include "digest_auth.h"
#include "digest_auth_calc.h"

#define ALGORITHM_VALUE_MD5_S     "MD5"
#define ALGORITHM_VALUE_MD5SESS_S "MD5-sess"

/*
 * calculate H(A1)
 */
static void _digest_calc_HA1(const struct digest_auth_credential *crd,
   const str* nonce, const str* cnonce, int issess, HASHHEX *sess_key)
{
	MD5_CTX Md5Ctx;
	HASH HA1;

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, crd->user.s, crd->user.len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, crd->realm.s, crd->realm.len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, crd->passwd.s, crd->passwd.len);
	MD5Final(HA1.MD5, &Md5Ctx);
	cvt_hex(HA1.MD5, sess_key->MD5, HASHLEN_MD5, HASHHEXLEN_MD5);

	if (issess != 0)
	{
		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, sess_key->MD5, HASHHEXLEN_MD5);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, nonce->s, nonce->len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, cnonce->s, cnonce->len);
		MD5Final(HA1.MD5, &Md5Ctx);
		cvt_hex(HA1.MD5, sess_key->MD5, HASHLEN_MD5, HASHHEXLEN_MD5);
	};

}

static void digest_calc_HA1(const struct digest_auth_credential *crd,
   const str* nonce, const str* cnonce, HASHHEX *sess_key)
{
	_digest_calc_HA1(crd, nonce, cnonce, 0, sess_key);
}

static void digest_calc_HA1_s(const struct digest_auth_credential *crd,
   const str* nonce, const str* cnonce, HASHHEX *sess_key)
{
	_digest_calc_HA1(crd, nonce, cnonce, 1, sess_key);
}


/*
 * calculate H(A2)
 */
static void digest_calc_HA2(const str *msg_body, const str *method,
    const str *uri, int auth_int, HASHHEX *HA2Hex)
{
	MD5_CTX Md5Ctx;
	HASH HA2;
	HASH HENTITY;
	HASHHEX HENTITYHex;

	if (auth_int) {
		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, msg_body->s, msg_body->len);
		MD5Final(HENTITY.MD5, &Md5Ctx);
		cvt_hex(HENTITY.MD5, HENTITYHex.MD5, HASHLEN_MD5, HASHHEXLEN_MD5);
	}

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, method->s, method->len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, uri->s, uri->len);

	if (auth_int)
	{
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, HENTITYHex.MD5, HASHHEXLEN_MD5);
	};

	MD5Final(HA2.MD5, &Md5Ctx);
	cvt_hex(HA2.MD5, HA2Hex->MD5, HASHLEN_MD5, HASHHEXLEN_MD5);
}



/*
 * calculate request-digest/response-digest as per HTTP Digest spec
 */
static void digest_calc_response(const HASHHEX *ha1, const HASHHEX *ha2,
    const str *nonce, const str *qop_val, const str* nc, const str* cnonce,
    struct digest_auth_response *response)
{
	MD5_CTX Md5Ctx;
	HASH RespHash;

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, ha1->MD5, HASHHEXLEN_MD5);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, nonce->s, nonce->len);
	MD5Update(&Md5Ctx, ":", 1);

	if (qop_val != NULL)
	{
		MD5Update(&Md5Ctx, nc->s, nc->len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, cnonce->s, cnonce->len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, qop_val->s, qop_val->len);
		MD5Update(&Md5Ctx, ":", 1);
	};
	MD5Update(&Md5Ctx, ha2->MD5, HASHHEXLEN_MD5);
	MD5Final(RespHash.MD5, &Md5Ctx);
	cvt_hex(RespHash.MD5, response->hhex.MD5, HASHLEN_MD5,
	    HASHHEXLEN_MD5);
	response->hhex_len = HASHHEXLEN_MD5;
}

const struct digest_auth_calc md5_digest_calc = {
	.HA1 = digest_calc_HA1,
	.HA2 = digest_calc_HA2,
	.response = &digest_calc_response,
	.algorithm_val = str_init(ALGORITHM_VALUE_MD5_S),
	.HASHLEN = HASHLEN_MD5,
	.HASHHEXLEN = HASHHEXLEN_MD5
};

const struct digest_auth_calc md5sess_digest_calc = {
	.HA1 = digest_calc_HA1_s,
	.HA2 = digest_calc_HA2,
	.response = &digest_calc_response,
	.algorithm_val = str_init(ALGORITHM_VALUE_MD5SESS_S),
	.HASHLEN = HASHLEN_MD5,
	.HASHHEXLEN = HASHHEXLEN_MD5
};
