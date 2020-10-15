/*
 * digest_auth library
 *
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

#include "../../parser/parse_authenticate.h"

#include "digest_auth.h"

int digest_algorithm_check(const struct authenticate_body *auth)
{
        switch (auth->algorithm) {
        case ALG_UNSPEC:
        case ALG_MD5:
        case ALG_MD5SESS:
        case ALG_SHA256:
        case ALG_SHA256SESS:
#if defined(SHA_512_256_ENABLE)
        case ALG_SHA512_256:
        case ALG_SHA512_256SESS:
#endif
		return (1);

	default:
		break;
        }
        return (0);
}
