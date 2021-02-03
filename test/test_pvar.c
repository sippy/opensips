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

#include <tap.h>

#include "../str.h"
#include "../ut.h"
#include "../mem/mem.h"
#include "../pvar.h"

#include "test_pvar.h"

void test_pvar(struct sip_msg *tmsg, const struct pvar_tts *tset)
{
   pv_spec_p nsp = NULL;
   char *p;
   char buf[256];
   int i;

   nsp = (pv_spec_p)pkg_malloc(sizeof(pv_spec_t));
   if (nsp == NULL) {
       ok(0, "pkg_malloc(%d)", (int)sizeof(pv_spec_t));
       goto e0;
   }

   for (i = 0; tset[i].vname.s != NULL; i++) {
       memset(nsp, '\0', sizeof(pv_spec_t));
       p = pv_parse_spec((str *)&tset[i].vname, nsp);
       ok(p != NULL, "pv_parse_spec(\"%.*s\", %p)", tset[i].vname.len, tset[i].vname.s, nsp);
       if (p == NULL)
           continue;
       int sll = *log_level;
       *log_level = L_DBG;
       pv_spec_dbg(nsp);
       *log_level = sll;
       str res = {.s = buf, .len = sizeof(buf)};
       ok(pv_print_spec(tmsg, nsp, buf, &res.len) == 0, "pv_print_spec(\"%.*s\") == 0",
         tset[i].vname.len, tset[i].vname.s);
       ok(str_match(&res, &tset[i].rval), "pv_print_spec(\"%.*s\") -> \"%s\" == \"%.*s\"",
         tset[i].vname.len, tset[i].vname.s, buf, tset[i].rval.len, tset[i].rval.s);
   }
   pv_spec_free(nsp);
   return;
e0:
   return;
}
