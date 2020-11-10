/*
 * Copyright (C) 2003-2008 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include "rtppm_try_connect.h"

int try_connect(int s, const struct sockaddr *name, socklen_t namelen, int timeout)
{
	int oflags, nflags, cres, pres;
	struct pollfd pfd;

	oflags = fcntl(s, F_GETFL);
	if (oflags < 0)
		return -1;
	nflags = fcntl(s, F_SETFL, oflags | O_NONBLOCK);
	if (nflags < 0)
		return -1;

	cres = connect(s, name, namelen);
	if (cres < 0 && errno != EINPROGRESS)
		goto out;
	if (cres == 0)
		goto out;
	pfd.fd = s;
	pfd.events = POLLOUT;
	pres = poll(&pfd, 1, timeout);
	if (pres <= 0) {
		cres = -1;
	} else {
		cres = 0;
	}
out:
	fcntl(s, F_SETFL, oflags);
	return cres;
}
