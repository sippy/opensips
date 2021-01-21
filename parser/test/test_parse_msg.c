/*
 * Copyright (C) 2020 - Maksym Sobolyev <sobomax@sippysoft.com>
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

#include <stdlib.h>
#include <string.h>

#include <tap.h>

#include "../../mem/mem.h"
#include "../../str.h"
#include "../../parser/msg_parser.h"

#include "test_parse_msg.h"

struct sip_msg *test_parse_msg(const str *tmsg)
{
    static struct sip_msg msg;

    memset(&msg, '\0', sizeof(msg));
    /* fill in msg */
    msg.buf = tmsg->s;
    msg.len = tmsg->len;
    msg.ruri_q = Q_UNSPECIFIED;

    if (parse_msg(msg.buf, msg.len, &msg) != 0) {
        LM_ERR("Unable to parse msg:\n\%.*s\\n", tmsg->len, tmsg->s);
        ok(0, "parse_msg()");
        goto e1;
    }
    ok(1, "parse_msg()");
    return &msg;

e1:
    free_sip_msg(&msg);
    return NULL;
}
