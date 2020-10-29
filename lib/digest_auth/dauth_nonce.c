/*
 * Nonce related functions
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


#include <assert.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "../../md5global.h"
#include "../../md5.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../timer.h"

#include "dauth_nonce.h"

#define RAND_SECRET_LEN 32
/*
 * Length of nonce string in bytes
 */
#define NONCE_LEN (16+32)

struct nonce_context_priv {
	struct nonce_context pub;
	char* sec_rand;
	EVP_CIPHER_CTX *ectx, *dctx;
};

/*
 * Convert an integer to its hex representation,
 * destination array must be at least 8 bytes long,
 * this string is NOT zero terminated
 */
static inline void integer2hex(char* _d, int _s)
{
	int i;
	unsigned char j;
	char* s;

	_s = htonl(_s);
	s = (char*)&_s;

	for (i = 0; i < 4; i++) {

		j = (s[i] >> 4) & 0xf;
		if (j <= 9) {
			_d[i * 2] = (j + '0');
		} else {
			_d[i * 2] = (j + 'a' - 10);
		}

		j = s[i] & 0xf;
		if (j <= 9) {
			_d[i * 2 + 1] = (j + '0');
		} else {
		       _d[i * 2 + 1] = (j + 'a' - 10);
		}
	}
}


/*
 * Convert hex string to integer
 */
static inline int hex2integer(const char* _s)
{
	unsigned int i, res = 0;

	for(i = 0; i < 8; i++) {
		res *= 16;
		if ((_s[i] >= '0') && (_s[i] <= '9')) {
			res += _s[i] - '0';
		} else if ((_s[i] >= 'a') && (_s[i] <= 'f')) {
			res += _s[i] - 'a' + 10;
		} else if ((_s[i] >= 'A') && (_s[i] <= 'F')) {
			res += _s[i] - 'A' + 10;
		} else return 0;
	}

	return res;
}


/*
 * Calculate nonce value
 * Nonce value consists of the expires time (in seconds since 1.1 1970)
 * and a secret phrase
 */
void calc_nonce(const struct nonce_context *pub, char* _nonce,
    const struct nonce_params *npp)
{
	MD5_CTX ctx;
	unsigned char bin[16];
	unsigned int offset = 8;

	MD5Init(&ctx);


	integer2hex(_nonce, npp->expires);

	if(!pub->disable_nonce_check) {
		integer2hex(_nonce + 8, npp->index);
		offset = 16;
	}

    MD5Update(&ctx, _nonce, offset);

	MD5Update(&ctx, pub->secret.s, pub->secret.len);
	MD5Final(bin, &ctx);
	string2hex(bin, 16, _nonce + offset);
	_nonce[offset + 32] = '\0';
}

/*
 * Get nonce index
 */
int get_nonce_index(const str_const * _n)
{
    return hex2integer(_n->s + 8);
}


/*
 * Get expiry time from nonce string
 */
time_t get_nonce_expires(const str_const* _n)
{
	return (time_t)hex2integer(_n->s);
}


/*
 * Check, if the nonce received from client is
 * correct
 */
int check_nonce(const struct nonce_context *pub, const str_const * _nonce)
{
	char non[NONCE_LEN + 1];
	struct nonce_params np = {.index = 0};

	if (_nonce->s == 0) {
		return -1;  /* Invalid nonce */
	}

	if (_nonce->len != pub->nonce_len) {
		return 1; /* Lengths must be equal */
	}

	np.expires = get_nonce_expires(_nonce);
    if(!pub->disable_nonce_check)
		np.index = get_nonce_index(_nonce);

    calc_nonce(pub, non, &np);


	LM_DBG("comparing [%.*s] and [%.*s]\n",
			_nonce->len, ZSW(_nonce->s), pub->nonce_len, non);
    if (!memcmp(non, _nonce->s, _nonce->len)) {
		return 0;
	}
	return 2;
}


/*
 * Check if a nonce is stale
 */
int is_nonce_stale(const str_const * _n)
{
	if (!_n->s) return 0;

	if (get_nonce_expires(_n) < time(0)) {
		return 1;
	} else {
		return 0;
	}
}

int generate_random_secret(struct nonce_context *pub)
{
	struct nonce_context_priv *self = (typeof(self))pub;
	int rc;

	self->sec_rand = (char*)pkg_malloc(RAND_SECRET_LEN);
	if (!self->sec_rand) {
		LM_ERR("no pkg memory left\n");
		goto e0;
	}

	/* the generator is seeded from the core */
	rc = RAND_bytes((unsigned char *)self->sec_rand, RAND_SECRET_LEN);
	if(rc != 1) {
		LM_ERR("RAND_bytes() failed, error = %lu\n", ERR_get_error());
		goto e1;
	}

	pub->secret.s = self->sec_rand;
	pub->secret.len = RAND_SECRET_LEN;

	/*LM_DBG("Generated secret: '%.*s'\n", pub->secret.len, pub->secret.s); */

	return 0;
e1:
	pkg_free(self->sec_rand);
	self->sec_rand = NULL;
e0:
	return (-1);
}

int dauth_noncer_init(struct nonce_context *pub)
{
	struct nonce_context_priv *self = (typeof(self))pub;
	const unsigned char *key, *iv;

	if (pub->disable_nonce_check)
		return 0;
	key = (unsigned char *)pub->secret.s;
	iv = (unsigned char *)(pub->secret.s + RAND_SECRET_LEN / 2);
	if (EVP_EncryptInit_ex(self->ectx, EVP_aes_128_ecb(), NULL, key, iv) != 1) {
		LM_ERR("EVP_EncryptInit_ex() failed\n");
		goto e0;
	}
	assert(EVP_CIPHER_CTX_key_length(self->ectx) == RAND_SECRET_LEN / 2);
	LM_ERR("EVP_CIPHER_CTX_iv_length(self->ectx) = %d\n", EVP_CIPHER_CTX_iv_length(self->ectx));
	assert(EVP_CIPHER_CTX_iv_length(self->ectx) == RAND_SECRET_LEN / 2);
	if (EVP_DecryptInit_ex(self->dctx, EVP_aes_128_ecb(), NULL,  key, iv) != 1) {
		LM_ERR("EVP_DecryptInit_ex() failed\n");
		goto e0;
	}

	return 0;
e0:
	return (-1);
}

#if defined(CLOCK_REALTIME_PRECISE)
#define MYCLOCK_REALTIME CLOCK_REALTIME_PRECISE
#else
#define MYCLOCK_REALTIME CLOCK_REALTIME
#endif
#if defined(CLOCK_MONOTONIC_PRECISE)
#define MYCLOCK_MONOTONIC CLOCK_MONOTONIC_PRECISE
#else
#define MYCLOCK_MONOTONIC CLOCK_MONOTONIC
#endif


void dauth_noncer_reseed(void)
{
	struct {
		pid_t pid;
		struct timespec rtime;
		struct timespec mtime;
        } seed;

	seed.pid = getpid();
	clock_gettime(MYCLOCK_REALTIME, &seed.rtime);
	clock_gettime(MYCLOCK_MONOTONIC, &seed.mtime);

	RAND_add(&seed, sizeof(seed), (double)sizeof(seed) * 0.1);
}

struct nonce_context *dauth_noncer_new(int disable_nonce_check)
{
	struct nonce_context_priv *self;

	static_assert(offsetof(typeof(*self), pub) == 0,
	    "offsetof(struct nonce_context_priv, pub) == 0");

	self = pkg_malloc(sizeof(*self));
	if (self == NULL) {
		LM_ERR("no pkg memory left\n");
		goto e0;
	}
	memset(self, 0, sizeof(*self));
	if (!disable_nonce_check) {
		self->ectx = EVP_CIPHER_CTX_new();
		if (self->ectx == NULL) {
			LM_ERR("EVP_CIPHER_CTX_new failed\n");
			goto e1;
		}
		self->dctx = EVP_CIPHER_CTX_new();
		if (self->dctx == NULL) {
			LM_ERR("EVP_CIPHER_CTX_new failed\n");
			goto e2;
		}
	}
	self->pub.disable_nonce_check = disable_nonce_check;
	self->pub.nonce_len = (!disable_nonce_check) ? NONCE_LEN : NONCE_LEN - 8;
	return &(self->pub);
e2:
	if (!disable_nonce_check) EVP_CIPHER_CTX_free(self->ectx);
e1:
	pkg_free(self);
e0:
	return NULL;
}

void dauth_noncer_dtor(struct nonce_context *pub)
{
	struct nonce_context_priv *self = (typeof(self))pub;

	if (self->sec_rand != NULL)
		pkg_free(self->sec_rand);
	if (self->dctx != NULL)
		EVP_CIPHER_CTX_free(self->dctx);
	if (self->ectx != NULL)
		EVP_CIPHER_CTX_free(self->ectx);
	pkg_free(self);
}
