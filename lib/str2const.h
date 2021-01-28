/*
 * Copyright (C) 2020 Sippy Software, Inc.
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
 *
 */

#ifndef __LIB_STR2CONST_H__
#define __LIB_STR2CONST_H__

#if defined(HAVE_GENERICS)
#define map_find(map, _s) _Generic(*(_s), \
	str:_map_find, \
	str_const:_map_find_C \
    )(map, _s)

#define map_get(map, _s) _Generic(*(_s), \
	str:_map_get, \
	str_const:_map_get_C \
    )(map, _s)

#define map_put(map, _s, _p) _Generic(*(_s), \
	str:_map_put, \
	str_const:_map_put_C \
    )(map, _s, _p)

#define str2const(_sp) ( \
    _Generic((_sp), str *: _s2c, const str *: _cs2cc)(_sp) \
)

#define escape_user(sin, sout) ( \
    _Generic(*(sin), str: _escape_userSS, str_const: _escape_user)(sin, sout) \
)

#define unescape_user(sin, sout) ( \
    _Generic(*(sin), str: _unescape_userSS, str_const: _unescape_user)(sin, sout) \
)

#define escape_param(sin, sout) ( \
    _Generic(*(sin), str: _escape_paramSS, str_const: _escape_param)(sin, sout) \
)

#define unescape_param(sin, sout) ( \
    _Generic(*(sin), str: _unescape_paramSS, str_const: _unescape_param)(sin, sout) \
)

#define parse_avp_spec(name, avp_name) _Generic(*(name), \
	str:_parse_avp_spec, \
	str_const:_parse_avp_specC \
    )(name, avp_name)

#define get_avp_id(name) _Generic(*(name), \
	str:_get_avp_idS, \
	str_const:_get_avp_id \
    )(name)

#define str_match(_a, _b) _Generic(*(_a), \
	str: _Generic(*(_b), \
	    str: _str_matchSS, \
	    str_const: _str_matchSC), \
	str_const: _Generic(*(_b), \
	    str: _str_matchCS, \
	    str_const: _str_matchCC) \
    )(_a, _b)

#define str_casematch(_a, _b) _Generic(*(_a), \
	str: _Generic(*(_b), \
	    str: _str_casematchSS, \
	    str_const: _str_casematchSC), \
	str_const: _Generic(*(_b), \
	    str: _str_casematchCS, \
	    str_const: _str_casematchCC) \
    )(_a, _b)

#define str_strcmp(_a, _b) _Generic(*(_a), \
        str: _Generic(*(_b), \
            str: _str_strcmpSS, \
            str_const: _str_strcmpSC), \
        str_const: _Generic(*(_b), \
            str: _str_strcmpCS, \
            str_const: _str_strcmpCC) \
    )(_a, _b)

#define evi_param_add_int(p_list, p_name, p_int) _Generic(*(p_name), \
        str:_evi_param_addS, \
        str_const:evi_param_add \
    )(p_list, p_name, p_int, EVI_INT_VAL)

#define evi_param_add_str(p_list, p_name, p_str) _Generic(*(p_name), \
        str:_evi_param_addS, \
        default:evi_param_add \
    )(p_list, p_name, p_str, EVI_STR_VAL)

#define evi_param_create(list, name) _Generic(*(name), \
	str:_evi_param_createS, \
	str_const:_evi_param_create \
    )(list, name)

#define get_uri_param_val(uri, param, val) _Generic(*(val), \
	str:_get_uri_param_valS, \
	str_const:_get_uri_param_val \
    )(uri, param, val)

#define bin_push_str(packet, info) _Generic(*(info), \
	str:_bin_push_str, \
	default:_bin_push_strC \
    )(packet, info)
#else /* !HAVE_GENERICS */
#define str2const(_sp) ((str_const *)(void *)(_sp))
#define map_find(map, _s) _map_find_C(map, str2const(_s))
#define map_get(map, _s) _map_get_C(map, str2const(_s))
#define map_put(map, _s, _p) _map_put_C(map, str2const(_s), _p)
#define escape_user(sin, sout) _escape_user(str2const(sin), sout)
#define unescape_user(sin, sout) _unescape_user(str2const(sin), sout)
#define escape_param(sin, sout) _escape_param(str2const(sin), sout)
#define unescape_param(sin, sout) _unescape_param(str2const(sin), sout)
#define parse_avp_spec(name, avp_name) _parse_avp_specC(str2const(name), avp_name)
#define get_avp_id(name) _get_avp_id(str2const(name))
#define str_match(_a, _b) _str_matchCC(str2const(_a), str2const(_b))
#define str_casematch(_a, _b) _str_casematchCC(str2const(_a), str2const(_b))
#define str_strcmp(_a, _b) _str_strcmpCC(str2const(_a), str2const(_b))
#define evi_param_add_int(p_list, p_name, p_int) evi_param_add(p_list, str2const(p_name), p_int, EVI_INT_VAL)
#define evi_param_add_str(p_list, p_name, p_str) evi_param_add(p_list, str2const(p_name), p_str, EVI_STR_VAL)
#define evi_param_create(list, name) _evi_param_create(list, str2const(name))
#define get_uri_param_val(uri, param, val) _get_uri_param_val(uri, param, str2const(val))
#define bin_push_str(packet, info) _bin_push_strC(packet, str2const(info))
#endif /* HAVE_GENERICS */

#endif /* __LIB_STR2CONST_H__ */
