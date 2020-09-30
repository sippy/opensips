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

#include "uac_auth.h"
#include "uac_auth_calc.h"

#define ALGORITHM_VALUE_MD5_S     "MD5"
#define ALGORITHM_VALUE_MD5SESS_S "MD5-sess"

/*
 * calculate H(A1)
 */
static void uac_calc_HA1( struct uac_credential *crd,
		struct authenticate_body *auth,
		str* cnonce,
		HASHHEX *sess_key)
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

	if ( auth->algorithm == ALG_MD5SESS )
	{
		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, HA1.MD5, HASHLEN_MD5);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, auth->nonce.s, auth->nonce.len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, cnonce->s, cnonce->len);
		MD5Final(HA1.MD5, &Md5Ctx);
	};

	cvt_hex(HA1.MD5, sess_key->MD5, HASHLEN_MD5, HASHHEXLEN_MD5);
}



/*
 * calculate H(A2)
 */
static void uac_calc_HA2(str *msg_body, str *method, str *uri,
		int auth_int, HASHHEX *HA2Hex)
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
static void uac_calc_response( HASHHEX *ha1, HASHHEX *ha2,
		struct authenticate_body *auth,
		str* nc, str* cnonce,
		struct auth_response *response)
{
	MD5_CTX Md5Ctx;
	HASH RespHash;

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, ha1->MD5, HASHHEXLEN_MD5);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, auth->nonce.s, auth->nonce.len);
	MD5Update(&Md5Ctx, ":", 1);

	if((auth->flags&QOP_AUTH) || (auth->flags&QOP_AUTH_INT))
	{
		MD5Update(&Md5Ctx, nc->s, nc->len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, cnonce->s, cnonce->len);
		MD5Update(&Md5Ctx, ":", 1);
		if (!(auth->flags&QOP_AUTH))
			MD5Update(&Md5Ctx, "auth-int", 8);
		else
			MD5Update(&Md5Ctx, "auth", 4);
		MD5Update(&Md5Ctx, ":", 1);
	};
	MD5Update(&Md5Ctx, ha2->MD5, HASHHEXLEN_MD5);
	MD5Final(RespHash.MD5, &Md5Ctx);
	cvt_hex(RespHash.MD5, response->hhex.MD5, HASHLEN_MD5,
	    HASHHEXLEN_MD5);
	response->hhex_len = HASHHEXLEN_MD5;
}

const struct uac_auth_calc md5_uac_calc = {
    .HA1 = uac_calc_HA1,
    .HA2 = uac_calc_HA2,
    .response = &uac_calc_response,
    .algorithm_val = str_init(ALGORITHM_VALUE_MD5_S)
};

const struct uac_auth_calc md5sess_uac_calc = {
    .HA1 = uac_calc_HA1,
    .HA2 = uac_calc_HA2,
    .response = &uac_calc_response,
    .algorithm_val = str_init(ALGORITHM_VALUE_MD5SESS_S)
};
