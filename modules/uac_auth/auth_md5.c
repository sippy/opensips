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

/*
 * calculate H(A1)
 */
static void uac_calc_HA1( struct uac_credential *crd,
		struct authenticate_body *auth,
		str* cnonce,
		HASHHEX sess_key)
{
	MD5_CTX Md5Ctx;
	HASH HA1;

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, crd->user.s, crd->user.len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, crd->realm.s, crd->realm.len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, crd->passwd.s, crd->passwd.len);
	MD5Final(HA1, &Md5Ctx);

	if ( auth->algorithm == ALG_MD5SESS )
	{
		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, HA1, HASHLEN);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, auth->nonce.s, auth->nonce.len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, cnonce->s, cnonce->len);
		MD5Final(HA1, &Md5Ctx);
	};

	cvt_hex(HA1, sess_key);
}



/*
 * calculate H(A2)
 */
static void uac_calc_HA2(str *msg_body, str *method, str *uri,
		int auth_int, HASHHEX HA2Hex)
{
	MD5_CTX Md5Ctx;
	HASH HA2;
	HASH HENTITY;
	HASHHEX HENTITYHex;

	if (auth_int) {
		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, msg_body->s, msg_body->len);
		MD5Final(HENTITY, &Md5Ctx);
		cvt_hex(HENTITY, HENTITYHex);
	}

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, method->s, method->len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, uri->s, uri->len);

	if (auth_int)
	{
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, HENTITYHex, HASHHEXLEN);
	};

	MD5Final(HA2, &Md5Ctx);
	cvt_hex(HA2, HA2Hex);
}



/*
 * calculate request-digest/response-digest as per HTTP Digest spec
 */
static void uac_calc_response( HASHHEX ha1, HASHHEX ha2,
		struct authenticate_body *auth,
		str* nc, str* cnonce,
		HASHHEX response)
{
	MD5_CTX Md5Ctx;
	HASH RespHash;

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, ha1, HASHHEXLEN);
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
	MD5Update(&Md5Ctx, ha2, HASHHEXLEN);
	MD5Final(RespHash, &Md5Ctx);
	cvt_hex(RespHash, response);
}

const struct uac_auth_calc md5_uac_calc = {
    .HA1 = uac_calc_HA1,
    .HA2 = uac_calc_HA2,
    .response = &uac_calc_response
};
