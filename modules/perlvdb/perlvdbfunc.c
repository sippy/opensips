/* 
 * $Id: perlvdbfunc.c 816 2007-02-13 18:33:22Z bastian $
 *
 * Perl virtual database module interface
 *
 * Copyright (C) 2007 Collax GmbH
 *                    (Bastian Friedrich <bastian.friedrich@collax.com>)
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <string.h>
#include <ctype.h>
#include <stdio.h>

#include "perlvdb.h"
#include "perlvdbfunc.h"

/*
 * Simple conversion IV -> int
 * including decreasing ref cnt
 */

inline long IV2int(SV *in) {
	int ret = -1;

	if (SvOK(in)) {
		if (SvIOK(in)) {
			ret = SvIV(in);
		}
		SvREFCNT_dec(in);
	}

	return ret;
}

/*
 * Returns the class part of the URI
 */
char *parseurl(const char* url) {
	char *cn;

	cn = strchr(url, ':') + 1;
	if (strlen(cn) > 0)
		return cn;
	else
		return NULL;
}


SV *newvdbobj(const char* cn) {
	SV* obj;
	SV *class;

	class = newSVpv(cn, 0);

	obj = perlvdb_perlmethod(class, PERL_CONSTRUCTOR_NAME,
			NULL, NULL, NULL, NULL);

	return obj;
}

SV *getobj(db_con_t *con) {
	return ((SV*)CON_TAIL(con));
}

/*
 * Checks whether the passed SV is a valid VDB object:
 * - not null
 * - not undef
 * - an object
 * - derived from OpenSER::VDB
 */
int checkobj(SV* obj) {
	if (obj != NULL) {
		if (obj != &PL_sv_undef) {
			if (sv_isobject(obj)) {
				if (sv_derived_from(obj, PERL_VDB_BASECLASS)) {
					return 1;
				}
			}
		}
	}

	return 0;
}

/*
 * Initialize database module
 * No function should be called before this
 */
db_con_t* perlvdb_db_init(const char* url) {
	db_con_t* res;

	char *cn;
	SV *obj = NULL;
	
	int consize = sizeof(db_con_t) + sizeof(SV);
	
	if (!url) {
		LOG(L_ERR, "perlvdb_db_init: Invalid parameter value\n");
		return NULL;
	}

	cn = parseurl(url);
	if (!cn) {
		LOG(L_ERR, "perlvdb_db_init: Invalid perl vdb url.\n");
		return NULL;
	}

	obj = newvdbobj(cn);
	if (!checkobj(obj)) {
		LOG(L_ERR, "perlvdb_db_init: Could not initialize module."
				" Not inheriting from %s?\n",
				PERL_VDB_BASECLASS);
		return NULL;
	}

	res = pkg_malloc(consize);
	if (!res) {
		LOG(L_ERR, "perlvdb_db_init: No memory left\n");
		return NULL;
	}
	memset(res, 0, consize);
	CON_TAIL(res) = (unsigned int)obj;

	return res;
}


/*
 * Store name of table that will be used by
 * subsequent database functions
 */
int perlvdb_use_table(db_con_t* h, const char* t) {
	SV *ret;
	
	if (!h || !t) {
		LOG(L_ERR, "perlvdb_use_table: Invalid parameter value\n");
		return -1;
	}

	ret = perlvdb_perlmethod(getobj(h), PERL_VDB_USETABLEMETHOD,
			sv_2mortal(newSVpv(t, 0)), NULL, NULL, NULL);

	return IV2int(ret);
}


void perlvdb_db_close(db_con_t* h) {
	if (!h) {
		LOG(L_ERR, "db_close: Invalid parameter value\n");
		return;
	}

	pkg_free(h);
}


/*
 * Insert a row into specified table
 * h: structure representing database connection
 * k: key names
 * v: values of the keys
 * n: number of key=value pairs
 */
int perlvdb_db_insertreplace(db_con_t* h, db_key_t* k, db_val_t* v,
		int n, char *insertreplace) {
	AV *arr;
	SV *arrref;
	SV *ret;

	arr = pairs2perlarray(k, v, n);
	arrref = newRV_noinc((SV*)arr);
	ret = perlvdb_perlmethod(getobj(h), insertreplace,
			arrref, NULL, NULL, NULL);

	av_undef(arr);

	return IV2int(ret);
}

int perlvdb_db_insert(db_con_t* h, db_key_t* k, db_val_t* v, int n) {
	return perlvdb_db_insertreplace(h, k, v, n, PERL_VDB_INSERTMETHOD);
}

/*
 * Just like insert, but replace the row if it exists
 */
int perlvdb_db_replace(db_con_t* h, db_key_t* k, db_val_t* v, int n) {
	return perlvdb_db_insertreplace(h, k, v, n, PERL_VDB_REPLACEMETHOD);
}

/*
 * Delete a row from the specified table
 * h: structure representing database connection
 * k: key names
 * o: operators
 * v: values of the keys that must match
 * n: number of key=value pairs
 */
int perlvdb_db_delete(db_con_t* h, db_key_t* k, db_op_t* o, db_val_t* v,
		int n) {
	AV *arr;
	SV *arrref;
	SV *ret;

	arr = conds2perlarray(k, o, v, n);
	arrref = newRV_noinc((SV*)arr);
	ret = perlvdb_perlmethod(getobj(h), PERL_VDB_DELETEMETHOD,
			arrref, NULL, NULL, NULL);

	av_undef(arr);

	return IV2int(ret);
}


/*
 * Update some rows in the specified table
 * _h: structure representing database connection
 * _k: key names
 * _o: operators
 * _v: values of the keys that must match
 * _uk: updated columns
 * _uv: updated values of the columns
 * _n: number of key=value pairs
 * _un: number of columns to update
 */
int perlvdb_db_update(db_con_t* h, db_key_t* k, db_op_t* o, db_val_t* v,
	      db_key_t* uk, db_val_t* uv, int n, int un) {

	AV *condarr;
	AV *updatearr;

	SV *condarrref;
	SV *updatearrref;

	SV *ret;

	condarr = conds2perlarray(k, o, v, n);
	updatearr = pairs2perlarray(uk, uv, un);

	condarrref = newRV_noinc((SV*)condarr);
	updatearrref = newRV_noinc((SV*)updatearr);
	
	ret = perlvdb_perlmethod(getobj(h), PERL_VDB_UPDATEMETHOD,
			condarrref, updatearrref, NULL, NULL);

	av_undef(condarr);
	av_undef(updatearr);

	return IV2int(ret);
}


/*
 * Query table for specified rows
 * h: structure representing database connection
 * k: key names
 * op: operators
 * v: values of the keys that must match
 * c: column names to return
 * n: number of key=values pairs to compare
 * nc: number of columns to return
 * o: order by the specified column
 */
int perlvdb_db_query(db_con_t* h, db_key_t* k, db_op_t* op, db_val_t* v,
			db_key_t* c, int n, int nc,
			db_key_t o, db_res_t** r) {


	AV *condarr;
	AV *retkeysarr;
	SV *order;

	SV *condarrref;
	SV *retkeysref;

	SV *resultset;

	int retval = 0;

	/* Create parameter set */
	condarr = conds2perlarray(k, op, v, n);
	retkeysarr = keys2perlarray(c, nc);

	if (o) order = newSVpv(o, 0);
	else order = &PL_sv_undef;


	condarrref = newRV_noinc((SV*)condarr);
	retkeysref = newRV_noinc((SV*)retkeysarr);

	/* Call perl method */
	resultset = perlvdb_perlmethod(getobj(h), PERL_VDB_QUERYMETHOD,
			condarrref, retkeysref, order, NULL);

	av_undef(condarr);
	av_undef(retkeysarr);

	/* Transform perl result set to OpenSER result set */
	if (!resultset) {
		/* No results. */
		LOG(L_ERR, "perlvdb:perlvdb_db_query: "
				"Error in perl result set.\n");
		retval = -1;
	} else {
		if (sv_isa(resultset, "OpenSER::VDB::Result")) {
			retval = perlresult2dbres(resultset, r);
		/* Nested refs are decreased/deleted inside the routine */
			SvREFCNT_dec(resultset);
		} else {
			LOG(L_ERR, "Invalid result set retrieved from"
					" perl call.\n");
			retval = -1;
		}
	}

	return retval;
}


/*
 * Release a result set from memory
 */
int perlvdb_db_free_result(db_con_t* _h, db_res_t* _r) {
	int i;

	if (_r) {
		for (i = 0; i < _r->n; i++) {
			if (_r->rows[i].values)
				pkg_free(_r->rows[i].values);
		}

		if (_r->col.types)
			pkg_free(_r->col.types);
		if (_r->col.names)
			pkg_free(_r->col.names);
		if (_r->rows)
			pkg_free(_r->rows);
		pkg_free(_r);
	}
	return 0;
}
