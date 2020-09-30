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

#include "uac_auth.h"
#include "uac_auth_calc.h"

#define ALGORITHM_VALUE_SHA256_S "SHA-256"

/*
 * calculate H(A1)
 */
static void uac_calc_HA1( struct uac_credential *crd,
		struct authenticate_body *auth,
		str* cnonce,
		HASHHEX *sess_key)
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

	if ( auth->algorithm == ALG_SHA256SESS )
	{
		SHA256_Init(&Sha256Ctx);
		SHA256_Update(&Sha256Ctx, HA1.SHA256, HASHLEN_SHA256);
		SHA256_Update(&Sha256Ctx, ":", 1);
		SHA256_Update(&Sha256Ctx, auth->nonce.s, auth->nonce.len);
		SHA256_Update(&Sha256Ctx, ":", 1);
		SHA256_Update(&Sha256Ctx, cnonce->s, cnonce->len);
		SHA256_Final((unsigned char *)HA1.SHA256, &Sha256Ctx);
	};

	cvt_hex(HA1.SHA256, sess_key->SHA256, HASHLEN_SHA256, HASHHEXLEN_SHA256);
}



/*
 * calculate H(A2)
 */
static void uac_calc_HA2(str *msg_body, str *method, str *uri,
		int auth_int, HASHHEX *HA2Hex)
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
static void uac_calc_response( HASHHEX *ha1, HASHHEX *ha2,
		struct authenticate_body *auth,
		str* nc, str* cnonce,
		struct auth_response *response)
{
	SHA256_CTX Sha256Ctx;
	HASH RespHash;

	SHA256_Init(&Sha256Ctx);
	SHA256_Update(&Sha256Ctx, ha1->SHA256, HASHHEXLEN_SHA256);
	SHA256_Update(&Sha256Ctx, ":", 1);
	SHA256_Update(&Sha256Ctx, auth->nonce.s, auth->nonce.len);
	SHA256_Update(&Sha256Ctx, ":", 1);

	if((auth->flags&QOP_AUTH) || (auth->flags&QOP_AUTH_INT))
	{
		SHA256_Update(&Sha256Ctx, nc->s, nc->len);
		SHA256_Update(&Sha256Ctx, ":", 1);
		SHA256_Update(&Sha256Ctx, cnonce->s, cnonce->len);
		SHA256_Update(&Sha256Ctx, ":", 1);
		if (!(auth->flags&QOP_AUTH))
			SHA256_Update(&Sha256Ctx, "auth-int", 8);
		else
			SHA256_Update(&Sha256Ctx, "auth", 4);
		SHA256_Update(&Sha256Ctx, ":", 1);
	};
	SHA256_Update(&Sha256Ctx, ha2->SHA256, HASHHEXLEN_SHA256);
	SHA256_Final((unsigned char *)RespHash.SHA256, &Sha256Ctx);
	cvt_hex(RespHash.SHA256, response->hhex.SHA256, HASHLEN_SHA256,
	    HASHHEXLEN_SHA256);
	response->hhex_len = HASHHEXLEN_SHA256;
}

const struct uac_auth_calc sha256_uac_calc = {
    .HA1 = uac_calc_HA1,
    .HA2 = uac_calc_HA2,
    .response = &uac_calc_response,
    .algorithm_val = str_init(ALGORITHM_VALUE_SHA256_S)
};
