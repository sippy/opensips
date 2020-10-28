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


#ifndef NONCE_H
#define NONCE_H

#include "../../str.h"
#include <time.h>

struct nonce_context {
        str_const secret;
        char* sec_rand;
        int disable_nonce_check;
        int nonce_len;
};

struct nonce_params {
	time_t expires;
	int index;
};

/*
 * Calculate nonce value
 */
void calc_nonce(const struct nonce_context *ncp, char* _nonce,
    const struct nonce_params *npp);


/*
 * Check nonce value received from UA
 */
int check_nonce(const struct nonce_context *ncp, const str_const * _nonce);


/*
 * Get expiry time from nonce string
 */
time_t get_nonce_expires(const str_const * _nonce);

/*
 * Get index from nonce string
 */
int get_nonce_index(const str_const * _nonce);

/*
 * Check if the nonce is stale
 */
int is_nonce_stale(const str_const * _nonce);

struct nonce_context *dauth_nonce_context_new(int disable_nonce_check);
void dauth_nonce_context_dtor(struct nonce_context *);
int generate_random_secret(struct nonce_context *ncp);

#endif /* NONCE_H */
