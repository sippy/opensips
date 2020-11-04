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
 */

#include <tap.h>

#include "../../../str.h"

#include "../../../parser/digest/digest_parser.h"
#include "../../../lib/digest_auth/digest_auth.h"
#include "../../../lib/digest_auth/dauth_calc.h"

static const struct digest_auth_credential creds = {
	.user = str_init("AliceJ"), .realm = str_init("foobar.com"),
	.passwd = str_init("foobar1234")
};

static const struct tts {
	const struct digest_auth_credential *dac;
	const str_const *nonce;
	const str_const *cnonce;
	const str_const *msg_body;
	const str_const *method;
	const str_const *ruri;
	const str_const *qop_str;
	const str_const *nc;
	alg_t alg;
	int tres;
	const str_const *response;
} tset[] = {
	{
	/* Case #0 */
		.dac = &creds, .alg = ALG_OTHER, .tres = -1
	}, {
	/* Case #1 */
		.dac = &creds, .alg = ALG_UNSPEC, .tres = 0,
		.nonce = &str_const_init("slkjfs0912ead9109-"),
		.cnonce = NULL,
		.msg_body = NULL,
		.method = &str_const_init("INVITE"),
		.ruri = &str_const_init("sip:alice@bloxi.com"),
		.qop_str = NULL,
		.nc = NULL,
		.response = &str_const_init("dfc09f89706de11138faf5825091e078")
	}, {
	/* Case #2 */
		.dac = &creds, .alg = ALG_MD5, .tres = 0,
		.nonce = &str_const_init("slkjfs0912ead9109-"),
		.cnonce = NULL,
		.msg_body = NULL,
		.method = &str_const_init("INVITE"),
		.ruri = &str_const_init("sip:alice@bloxi.com"),
		.qop_str = NULL,
		.nc = NULL,
		.response = &str_const_init("dfc09f89706de11138faf5825091e078")
	}, {
	/* Case #3 */
		.dac = &creds, .alg = ALG_MD5SESS, .tres = 0,
		.nonce = &str_const_init("eN+Idipfiju9XcP6U5iu9tJI0CNqiUrkTAUyr3JXYVM"),
		.cnonce = &str_const_init("27555a22"),
		.msg_body = NULL,
		.method = &str_const_init("INVITE"),
		.ruri = &str_const_init("sip:alice@bloxi.com"),
		.qop_str = &str_const_init("auth"),
		.nc = &str_const_init("00000001"),
		.response = &str_const_init("8083e2ae96c48962d31ea5f0f4c2e622")
	}, {
	/* Case #4 */
		.dac = &creds, .alg = ALG_SHA256, .tres = 0,
		.nonce = &str_const_init("eN+Idipfiju9XcP6U5iu9tJI0CNqiUrkTAUyr3JXYVM"),
		.cnonce = &str_const_init("27555a22"),
		.msg_body = &str_const_init("TEST BODY\r\n"),
		.method = &str_const_init("INVITE"),
		.ruri = &str_const_init("sip:alice@bloxi.com"),
		.qop_str = &str_const_init("auth-int"),
		.nc = &str_const_init("00000001"),
		.response = &str_const_init("4b9d33a782d2011ae33bd2fd28409bf873c39ac11175a2e695a553d821b0d5aa")
	}, {
	/* Case #5 */
		.dac = &creds, .alg = ALG_SHA256SESS, .tres = 0,
		.nonce = &str_const_init("eN+Idipfiju9XcP6U5iu9tJI0CNqiUrkTAUyr3JXYVM"),
		.cnonce = &str_const_init("27555a22"),
		.msg_body = &str_const_init("TEST BODY\r\n"),
		.method = &str_const_init("INVITE"),
		.ruri = &str_const_init("sip:alice@bloxi.com"),
		.qop_str = &str_const_init("auth-int"),
		.nc = &str_const_init("00000001"),
		.response = &str_const_init("7e923bfb6bf07c2d740f7285e1ccc2aee04709a18564e08854470defd929fea2")
	}, {
	/* Case #6 */
		.dac = &creds, .alg = ALG_SHA512_256SESS, .tres = 0,
		.nonce = &str_const_init("eN+Idipfiju9XcP6U5iu9tJI0CNqiUrkTAUyr3JXYVM"),
		.cnonce = &str_const_init("27555a22"),
		.msg_body = &str_const_init("TEST BODY\r\n"),
		.method = &str_const_init("INVITE"),
		.ruri = &str_const_init("sip:alice@bloxi.com"),
		.qop_str = &str_const_init("auth-int"),
		.nc = &str_const_init("00000001"),
		.response = &str_const_init("280f41df4b5fad93bf611b2ae4d0f0cf8362479534b0deae408e8524031ffa0d")
	}, {
		.dac = NULL, .tres = 0
	}
};

void test_digest_calc(void)
{
        int i, rval;
	const struct digest_auth_calc* dcalc;
	struct digest_auth_response resp;
	HASHHEX ha1, ha2;

        for (i = 0; tset[i].dac != NULL; i++) {
		if ((tset[i].alg == ALG_SHA512_256 || tset[i].alg == ALG_SHA512_256SESS)
		    && !digest_algorithm_available(tset[i].alg))
			continue;
		dcalc = get_digest_calc(tset[i].alg);
		if (tset[i].tres == -1) {
			ok(dcalc == NULL, "Case #%d: get_digest_calc(%d) == NULL", i,
			    tset[i].alg);
		} else {
			ok(dcalc != NULL, "Case #%d: get_digest_calc(%d) != NULL", i,
			    tset[i].alg);
		}
		if (dcalc == NULL)
			continue;
		rval = dcalc->HA1(tset[i].dac, &ha1);
		ok(rval == 0, "Case #%d: HA1()", i);
		if (dcalc->HA1sess != NULL) {
			rval = dcalc->HA1sess(tset[i].nonce, tset[i].cnonce, &ha1);
			ok(rval == 0, "Case #%d: HA1sess()", i);
		}
		rval = dcalc->HA2(tset[i].msg_body, tset[i].method, tset[i].ruri,
		    tset[i].msg_body != NULL, &ha2);
		ok(rval == 0, "Case #%d: HA2()", i);
		rval = dcalc->response(&ha1, &ha2, tset[i].nonce, tset[i].qop_str,
		    tset[i].nc, tset[i].cnonce, &resp);
		ok(rval == 0, "Case #%d: response()", i);
		char tmpb[dcalc->HASHHEXLEN];
		dcalc->response_hash_fill(&resp, tmpb, sizeof(tmpb));
		rval = bcmp(tset[i].response->s, tmpb, sizeof(tmpb));
		ok(rval == 0, "Case #%d: response_hash_fill()", i);
		rval = dcalc->response_hash_bcmp(&resp, tset[i].response);
		ok(rval == 0, "Case #%d: response_hash_bcmp()", i);
        }
}
