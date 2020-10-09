/*
 * Digest Authentication Module
 *
 * Copyright (C) 2001-2003 FhG Fokus
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

#include <string.h>
#include "../../dprint.h"
#include "../../parser/digest/digest.h"
#include "../../sr_module.h"
#include "../../str.h"
#include "../../ut.h"
#include "auth_mod.h"
#include "nonce.h"
#include "common.h"
#include "api.h"
#include "rpid.h"
#include "index.h"
#include "../../lib/digest_auth/digest_auth_calc.h"
#include "../../lib/dassert.h"


/*
 * if realm determined from request, look if there are some
 * modification rules
 */
void strip_realm(str* _realm)
{
	/* no param defined -- return */
	if (!realm_prefix.len) return;

	/* prefix longer than realm -- return */
	if (realm_prefix.len > _realm->len) return;

	/* match ? -- if so, shorten realm -*/
	if (memcmp(realm_prefix.s, _realm->s, realm_prefix.len) == 0) {
		_realm->s += realm_prefix.len;
		_realm->len -= realm_prefix.len;
	}
	return;
}


/*
 * Find credentials with given realm in a SIP message header
 */
static inline int find_credentials(struct sip_msg* _m, str* _realm,
								hdr_types_t _hftype, struct hdr_field** _h)
{
	struct hdr_field** hook, *ptr, *prev;
	hdr_flags_t hdr_flags;
	int res;
	str* r;

	/*
	 * Determine if we should use WWW-Authorization or
	 * Proxy-Authorization header fields, this parameter
	 * is set in www_authorize and proxy_authorize
	 */
	switch(_hftype) {
	case HDR_AUTHORIZATION_T:
		hook = &(_m->authorization);
		hdr_flags=HDR_AUTHORIZATION_F;
		break;
	case HDR_PROXYAUTH_T:
		hook = &(_m->proxy_auth);
		hdr_flags=HDR_PROXYAUTH_F;
		break;
	default:
		hook = &(_m->authorization);
		hdr_flags=HDR_T2F(_hftype);
		break;
	}

	/*
	 * If the credentials haven't been parsed yet, do it now
	 */
	if (*hook == 0) {
		/* No credentials parsed yet */
		if (parse_headers(_m, hdr_flags, 0) == -1) {
			LM_ERR("failed to parse headers\n");
			return -1;
		}
	}

	ptr = *hook;

	/*
	 * Iterate through the credentials in the message and
	 * find credentials with given realm
	 */
	while(ptr) {
		res = parse_credentials(ptr);
		if (res < 0) {
			LM_ERR("failed to parse credentials\n");
			return (res == -1) ? -2 : -3;
		} else if (res == 0) {
			auth_body_t *abp = (auth_body_t *)(ptr->parsed);
			dig_cred_t *dcp = &(abp->digest);
			r = &(abp->digest.realm);
			if (r->len == _realm->len && dcp->alg.alg_parsed <= LAST_ALG_SPTD) {
				if (!strncasecmp(_realm->s, r->s, r->len)) {
					*_h = ptr;
					return 0;
				}
			}
		}

		prev = ptr;
		if (parse_headers(_m, hdr_flags, 1) == -1) {
			LM_ERR("failed to parse headers\n");
			return -4;
		} else {
			if (prev != _m->last_header) {
				if (_m->last_header->type == _hftype) ptr = _m->last_header;
				else break;
			} else break;
		}
	}

	/*
	 * Credentials with given realm not found
	 */

    return 1;
}


/*
 * Purpose of this function is to find credentials with given realm,
 * do sanity check, validate credential correctness and determine if
 * we should really authenticate (there must be no authentication for
 * ACK and CANCEL
 */
auth_result_t pre_auth(struct sip_msg* _m, str* _realm, hdr_types_t _hftype,
													struct hdr_field** _h)
{
	int ret, ecode;
	auth_body_t* c;
	struct sip_uri *uri;
	const str *emsg;

	/* ACK and CANCEL must be always authorized, there is
	 * no way how to challenge ACK and CANCEL cannot be
	 * challenged because it must have the same CSeq as
	 * the request to be canceled
	 */

	if ((_m->REQ_METHOD == METHOD_ACK) ||  (_m->REQ_METHOD == METHOD_CANCEL))
		return AUTHORIZED;

	if (_realm->len == 0) {
		if (get_realm(_m, _hftype, &uri) < 0) {
			LM_ERR("failed to extract realm\n");
			emsg = &str_init(MESSAGE_400);
			ecode = 400;
			goto ereply;
		}

		*_realm = uri->host;
		strip_realm(_realm);
	}

	/* Try to find credentials with corresponding realm
	 * in the message, parse them and return pointer to
	 * parsed structure
	 */
	ret = find_credentials(_m, _realm, _hftype, _h);
	if (ret < 0) {
		LM_ERR("failed to find credentials\n");
		if (ret == -2) {
			emsg = &str_init(MESSAGE_500);
			ecode = 500;
		} else {
			emsg = &str_init(MESSAGE_400);
			ecode = 400;
		}
		goto ereply;
	} else if (ret > 0) {
		LM_DBG("credentials with given realm not found\n");
		return NO_CREDENTIALS;
	}

	/* Pointer to the parsed credentials */
	c = (auth_body_t*)((*_h)->parsed);

	/* Check credentials correctness here */
	if (check_dig_cred(&(c->digest)) != E_DIG_OK) {
		LM_DBG("received credentials are not filled properly\n");
		emsg = &str_init(MESSAGE_400);
		ecode = 400;
		goto ereply;
	}

	if (mark_authorized_cred(_m, *_h) < 0) {
		LM_ERR("failed to mark parsed credentials\n");
		emsg = &str_init(MESSAGE_400);
		ecode = 500;
		goto ereply;
	}

	if (is_nonce_stale(&c->digest.nonce)) {
		LM_DBG("stale nonce value received\n");
		c->stale = 1;
		return STALE_NONCE;
	}

	if (check_nonce(&c->digest.nonce, &secret) != 0) {
		LM_DBG("invalid nonce value received\n");
		c->stale = 1;
		return STALE_NONCE;
	}

	return DO_AUTHORIZATION;
ereply:
	if (send_resp(_m, ecode, emsg, 0, 0) == -1) {
		LM_ERR("failed to send %d reply\n", ecode);
	}
	return ERROR;
}


/*
 * Purpose of this function is to do post authentication steps like
 * marking authorized credentials and so on.
 */
auth_result_t post_auth(struct sip_msg* _m, struct hdr_field* _h)
{
	auth_body_t* c;
	int index;

	c = (auth_body_t*)((_h)->parsed);

	if ((_m->REQ_METHOD == METHOD_ACK) ||
		(_m->REQ_METHOD == METHOD_CANCEL))
		return AUTHORIZED;

	if(!disable_nonce_check) {
		/* Verify if it is the first time this nonce is received */
		index= get_nonce_index(&c->digest.nonce);
		if(index== -1) {
			LM_ERR("failed to extract nonce index\n");
			return ERROR;
		}
		LM_DBG("nonce index= %d\n", index);

		if(!is_nonce_index_valid(index)) {
			LM_DBG("nonce index not valid\n");
			c->stale = 1;
			return STALE_NONCE;
		}
	}

	return AUTHORIZED;

}

int check_response(const dig_cred_t* _cred, const str* _method,
    const str *_msg_body, const HASHHEX* _ha1)
{
	HASHHEX ha2;
	struct digest_auth_response resp;
	const struct digest_auth_calc *digest_calc;

	digest_calc = get_digest_calc(_cred->alg.alg_parsed);
	DASSERT(digest_calc != NULL);

	/*
	 * First, we have to verify that the response received has
	 * the same length as responses created by us
	 */
	if (_cred->response.len != digest_calc->HASHHEXLEN) {
		LM_DBG("receive response len != %d\n", digest_calc->HASHHEXLEN);
		return 1;
	}

	/*
	 * Now, calculate our response from parameters received
	 * from the user agent
	 */
	digest_calc->HA2(_msg_body, _method, &(_cred->uri),
	    _cred->qop.qop_parsed == QOP_AUTHINT_D, &ha2);
	digest_calc->response(_ha1, &ha2, &(_cred->nonce), &(_cred->qop.qop_str),
	    &(_cred->nc), &(_cred->cnonce), &resp);

	LM_DBG("our result = \'%s\'\n", resp.hhex._start);

	/*
	 * And simply compare the strings, the user is
	 * authorized if they match
	 */
	if (!memcmp(resp.hhex._start, _cred->response.s, digest_calc->HASHHEXLEN)) {
		LM_DBG("authorization is OK\n");
		return 0;
	} else {
		LM_DBG("authorization failed\n");
		return 2;
	}
}

static void auth_calc_HA1(alg_t alg, const str* username, const str* realm,
    const str* password, const str* nonce, const str* cnonce, HASHHEX *sess_key)
{
	const struct digest_auth_calc *digest_calc;
	struct digest_auth_credential creds = {.realm = *realm,
	    .user = *username, .passwd = *password};

	digest_calc = get_digest_calc(alg);
	DASSERT(digest_calc != NULL);
	digest_calc->HA1(&creds, nonce, cnonce, sess_key);
}

int bind_auth(auth_api_t* api)
{
	if (!api) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	api->pre_auth = pre_auth;
	api->post_auth = post_auth;
	api->calc_HA1 = auth_calc_HA1;
	api->check_response = check_response;

	get_rpid_avp( &api->rpid_avp, &api->rpid_avp_type );

	return 0;
}
