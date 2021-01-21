/*
 * Entry point for including and running OpenSIPS unit tests (core + modules)
 *
 * Copyright (C) 2018-2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <assert.h>

#include <tap.h>

#include "../str.h"
#include "../cachedb/test/test_backends.h"
#include "../lib/test/test_csv.h"
#include "../parser/test/test_parser.h"
#include "../mem/test/test_malloc.h"

#include "../lib/list.h"
#include "../globals.h"
#include "../context.h"
#include "../dprint.h"
#include "../sr_module.h"
#include "../sr_module_deps.h"

#if !defined(UNIT_TESTS)
#define UNIT_TESTS
#define ENABLE_MAIN
#endif

#include "test_pvar.h"
#include "unit_tests.h"

void init_unit_tests(void)
{
	if (!strcmp(testing_module, "core")) {
		set_mpath("modules/");
		solve_module_dependencies(modules);
		//init_cachedb_tests();
		//init_malloc_tests();
	}

	ensure_global_context();
}

static const str sip_msg = str_init(
    "SIP/2.0 100 Trying\r\n"
    "Via: SIP/2.0/UDP 127.0.0.1:5061;received=127.0.0.1;rport=5061;branch=z9hG4bK02a524d19149e70db415ad24199cae6b\r\n"
    "From: \"Alice Smith\" <sip:alice_3_ipv4@127.0.0.1>;tag=JZ8sHU.`'u.HOVzs01Xpk`w*4M!*Msr%\r\n"
    "To: <sip:bob_3@127.0.0.1>\r\n"
    "Call-ID: i%lu5JEz[9[1?Kfd6%.Oq]d%U_}MlFl.@'SPnm3PI9oPVdJC~\r\n"
    "CSeq: 200 INVITE\r\n"
    "Server: OpenSIPS (3.2.0-dev (x86_64/linux))\r\n"
    "Content-Length: 100500\r\n\r\n"
);
static const struct pvar_tts pvar_tset[] = {
    {.vname = str_init("$ci"), .rval = str_init("i%lu5JEz[9[1?Kfd6%.Oq]d%U_}MlFl.@'SPnm3PI9oPVdJC~")},
    {.vname = str_init("$cl"), .rval = str_init("100500")},
    {.vname = str_init("$cs"), .rval = str_init("200")},
    {.vname = str_init("$fd"), .rval = str_init("127.0.0.1")},
    {.vname = str_init("$fn"), .rval = str_init("\"Alice Smith\"")},
    {.vname = str_init("$ft"), .rval = str_init("JZ8sHU.`'u.HOVzs01Xpk`w*4M!*Msr%")},
    {.vname = str_init("$fu"), .rval = str_init("sip:alice_3_ipv4@127.0.0.1")},
    {.vname = STR_NULL, .rval = STR_NULL}
};

int run_unit_tests(void)
{
	char *error;
	void *mod_handle;
	mod_tests_f mod_tests;

	/* core tests */
	if (!strcmp(testing_module, "core")) {
		//test_cachedb_backends();
		//test_malloc();
		test_lib_csv();
		struct sip_msg *m = test_parser(&sip_msg);
		assert(m != NULL);
		test_pvar(m, pvar_tset);

	/* module tests */
	} else {
		mod_handle = get_mod_handle(testing_module);
		if (!mod_handle) {
			LM_ERR("module not loaded / not found: '%s'\n", testing_module);
			return -1;
		}

		mod_tests = (mod_tests_f)dlsym(mod_handle, DLSYM_PREFIX "mod_tests");
		if ((error = (char *)dlerror())) {
			LM_ERR("failed to locate 'mod_tests' in '%s': %s\n",
			       testing_module, error);
			return -1;
		}

		mod_tests();
	}

	done_testing();
}

#if defined(ENABLE_MAIN)
int main(void)
{

	testing_module = "core";
	if (init_pkg_mallocs() == -1) {
		LM_ERR("init_pkg_mallocs() failed\n");
		return -1;
	}
	if (init_shm_mallocs() == -1) {
		LM_ERR("init_shm_mallocs() failed\n");
		return -1;
	}
	if (init_stats_collector() < 0) {
		LM_ERR("init_stats_collector() failed\n");
		return -1;
	}
	return run_unit_tests();
}
#endif
