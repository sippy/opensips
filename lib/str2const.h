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
#else /* !HAVE_GENERICS */
#define str2const(_sp) ((str_const *)(void *)(_sp))
#define escape_user(sin, sout) _escape_user(str2const(sin), sout)
#define unescape_user(sin, sout) _unescape_user(str2const(sin), sout)
#define escape_param(sin, sout) _escape_param(str2const(sin), sout)
#define unescape_param(sin, sout) _unescape_param(str2const(sin), sout)
#define str_strcmp(_a, _b) _str_strcmpCC(str2const(_a), str2const(_b))
#define evi_param_add_int(p_list, p_name, p_int) evi_param_add(p_list, str2const(p_name), p_int, EVI_INT_VAL)
#define evi_param_add_str(p_list, p_name, p_str) evi_param_add(p_list, str2const(p_name), p_str, EVI_STR_VAL)
#define evi_param_create(list, name) _evi_param_create(list, str2const(name))
#endif /* HAVE_GENERICS */

#endif /* __LIB_STR2CONST_H__ */
