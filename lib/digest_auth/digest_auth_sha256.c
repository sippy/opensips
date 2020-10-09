/*
 * Copyright (C) 2011 VoIP Embedded Inc.
 * Copyright (C) 2013 OpenSIPS Solutions
 * Copyright (C) 2020 Maksym Sobolyev
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

#include "openssl/sha.h"

#include "../../str.h"
#include "../../parser/digest/digest_parser.h"

#include "digest_auth.h"
#include "digest_auth_calc.h"

#define ALGORITHM_VALUE_SHA256_S     "SHA-256"
#define ALGORITHM_VALUE_SHA256SESS_S "SHA-256-sess"

/*
 * calculate H(A1)
 */
static void _digest_calc_HA1(const struct digest_auth_credential *crd,
    const str* nonce, const str* cnonce, int issess, HASHHEX *sess_key)
{
	SHA256_CTX Sha256Ctx;
	HASH HA1;

	SHA256_Init(&Sha256Ctx);
	SHA256_Update(&Sha256Ctx, crd->user.s, crd->user.len);
	SHA256_Update(&Sha256Ctx, ":", 1);
	SHA256_Update(&Sha256Ctx, crd->realm.s, crd->realm.len);
	SHA256_Update(&Sha256Ctx, ":", 1);
	SHA256_Update(&Sha256Ctx, crd->passwd.s, crd->passwd.len);
	SHA256_Final((unsigned char *)HA1.SHA256, &Sha256Ctx);
	cvt_hex(HA1.SHA256, sess_key->SHA256, HASHLEN_SHA256, HASHHEXLEN_SHA256);

	if (issess != 0)
	{
		SHA256_Init(&Sha256Ctx);
		SHA256_Update(&Sha256Ctx, sess_key->SHA256, HASHHEXLEN_SHA256);
		SHA256_Update(&Sha256Ctx, ":", 1);
		SHA256_Update(&Sha256Ctx, nonce->s, nonce->len);
		SHA256_Update(&Sha256Ctx, ":", 1);
		SHA256_Update(&Sha256Ctx, cnonce->s, cnonce->len);
		SHA256_Final((unsigned char *)HA1.SHA256, &Sha256Ctx);
		cvt_hex(HA1.SHA256, sess_key->SHA256, HASHLEN_SHA256, HASHHEXLEN_SHA256);
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
	SHA256_CTX Sha256Ctx;
	HASH HA2;
	HASH HENTITY;
	HASHHEX HENTITYHex;

	if (auth_int) {
		SHA256_Init(&Sha256Ctx);
		SHA256_Update(&Sha256Ctx, msg_body->s, msg_body->len);
		SHA256_Final((unsigned char *)HENTITY.SHA256, &Sha256Ctx);
		cvt_hex(HENTITY.SHA256, HENTITYHex.SHA256, HASHLEN_SHA256, HASHHEXLEN_SHA256);
	}

	SHA256_Init(&Sha256Ctx);
	SHA256_Update(&Sha256Ctx, method->s, method->len);
	SHA256_Update(&Sha256Ctx, ":", 1);
	SHA256_Update(&Sha256Ctx, uri->s, uri->len);

	if (auth_int)
	{
		SHA256_Update(&Sha256Ctx, ":", 1);
		SHA256_Update(&Sha256Ctx, HENTITYHex.SHA256, HASHHEXLEN_SHA256);
	};

	SHA256_Final((unsigned char *)HA2.SHA256, &Sha256Ctx);
	cvt_hex(HA2.SHA256, HA2Hex->SHA256, HASHLEN_SHA256, HASHHEXLEN_SHA256);
}

/*
 * calculate request-digest/response-digest as per HTTP Digest spec
 */
static void digest_calc_response(const HASHHEX *ha1, const HASHHEX *ha2,
    const str *nonce, const str *qop_val, const str* nc, const str* cnonce,
    struct digest_auth_response *response)
{
	SHA256_CTX Sha256Ctx;
	HASH RespHash;

	SHA256_Init(&Sha256Ctx);
	SHA256_Update(&Sha256Ctx, ha1->SHA256, HASHHEXLEN_SHA256);
	SHA256_Update(&Sha256Ctx, ":", 1);
	SHA256_Update(&Sha256Ctx, nonce->s, nonce->len);
	SHA256_Update(&Sha256Ctx, ":", 1);

	if (qop_val != NULL)
	{
		SHA256_Update(&Sha256Ctx, nc->s, nc->len);
		SHA256_Update(&Sha256Ctx, ":", 1);
		SHA256_Update(&Sha256Ctx, cnonce->s, cnonce->len);
		SHA256_Update(&Sha256Ctx, ":", 1);
		SHA256_Update(&Sha256Ctx, qop_val->s, qop_val->len);
		SHA256_Update(&Sha256Ctx, ":", 1);
	};
	SHA256_Update(&Sha256Ctx, ha2->SHA256, HASHHEXLEN_SHA256);
	SHA256_Final((unsigned char *)RespHash.SHA256, &Sha256Ctx);
	cvt_hex(RespHash.SHA256, response->hhex.SHA256, HASHLEN_SHA256,
	    HASHHEXLEN_SHA256);
	response->hhex_len = HASHHEXLEN_SHA256;
}

const struct digest_auth_calc sha256_digest_calc = {
	.HA1 = digest_calc_HA1,
	.HA2 = digest_calc_HA2,
	.response = &digest_calc_response,
	.algorithm_val = str_init(ALGORITHM_VALUE_SHA256_S),
	.HASHLEN = HASHLEN_SHA256,
	.HASHHEXLEN = HASHHEXLEN_SHA256
};

const struct digest_auth_calc sha256sess_digest_calc = {
	.HA1 = digest_calc_HA1_s,
	.HA2 = digest_calc_HA2,
	.response = &digest_calc_response,
	.algorithm_val = str_init(ALGORITHM_VALUE_SHA256SESS_S),
	.HASHLEN = HASHLEN_SHA256,
	.HASHHEXLEN = HASHHEXLEN_SHA256
};
