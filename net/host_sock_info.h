/*
 * Copyright (C) 2023 Sippy Software, Inc.
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

#pragma once

#include <stddef.h>

#include "../resolve.h"

struct host_sock_info{
        union sockaddr_union su;
        struct {
                str_const hoststr;
                char hostname[MAX_DNS_NAME];
        } _;
};

static inline int hostent2hu( struct host_sock_info *hu,
                                                                struct hostent* he,
                                                                unsigned int idx,
                                                                unsigned short   port )
{
        union sockaddr_union* su = &hu->su;
        size_t nlen = strlen(he->h_name);

        if (nlen >= sizeof(hu->_.hostname)) {
                LM_CRIT("Hostname is too long: \"%s\"", he->h_name);
                return -1;
        }

        int r = hostent2su(su, he, idx, port);

        if (r == 0) {
                memcpy(hu->_.hostname, he->h_name, nlen);
                hu->_.hostname[nlen] = 0;
                hu->_.hoststr.s = hu->_.hostname;
                hu->_.hoststr.len = nlen;
        }
        return r;
}

static inline void hu_dup(const struct host_sock_info *hu_s, struct host_sock_info *hu_d)
{
        if (hu_s->_.hoststr.len > 0) {
                memcpy(hu_d, hu_s, sizeof(*hu_d));
                hu_d->_.hoststr.s = hu_d->_.hostname;
        } else {
                memcpy(hu_d, hu_s, sizeof(*hu_d) - offsetof(struct host_sock_info, _));
                hu_d->_.hoststr = (str_const){0};
        }
}

static inline const str_const hu_gethost(const struct host_sock_info *hu)
{

        if (hu == NULL || hu->_.hoststr.len == 0)
                return str_const_init("");
        return hu->_.hoststr;
}
