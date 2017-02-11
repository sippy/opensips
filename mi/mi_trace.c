/*
 * Copyright (C) 2016 - OpenSIPS Foundation
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * History:
 * -------
 *  2016-09-19  first version (Ionut Ionita)
 */
#include "../ut.h"

#include "mi_trace.h"

#define TRACE_API_MODULE "proto_hep"
#define MI_ID_S "mi"
#define MI_TRACE_BUF_SIZE (1 << 10)

#define MAX_RPL_CHARS (1 << 7)
#define CORR_BUF_SIZE 64

/* CORR - magic for internally generated correltion id */
#define CORR_MAGIC "\x43\x4F\x52\x52"

trace_proto_t* mi_trace_api=NULL;
int mi_message_id;

static char* correlation_name = "correlation_id";
str correlation_value;
int correlation_id=-1, correlation_vendor=-1;


static char trace_buf[MI_TRACE_BUF_SIZE];


void try_load_trace_api(void)
{
	/* already loaded */
	if ( mi_trace_api )
		return;

	mi_trace_api = pkg_malloc(sizeof(trace_proto_t));
	if (mi_trace_api == NULL)
		return;

	memset(mi_trace_api, 0, sizeof(trace_proto_t));
	if (trace_prot_bind(TRACE_API_MODULE, mi_trace_api) < 0) {
		LM_DBG("No tracing module used!\n");
		return;
	}

	mi_message_id = mi_trace_api->get_message_id(MI_ID_S);
}

#define CHECK_OVERFLOW(_len)								\
	do {													\
		if ( _len >= MI_TRACE_BUF_SIZE ) {					\
			LM_ERR("not enough room in command buffer!\n"); \
			return 0;										\
		}													\
	} while (0);

char* build_mi_trace_request( str* cmd, struct mi_root* mi_req, str* backend)
{
	int len, new;
	struct mi_node* node;

	if ( !cmd || !backend )
		return 0;

	len = snprintf( trace_buf, MI_TRACE_BUF_SIZE,
			"(%.*s) %.*s\n",
			backend->len, backend->s,
			cmd->len, cmd->s);

	CHECK_OVERFLOW(len);

	if ( mi_req ) {
		node = mi_req->node.kids;

		while ( node ) {
			/* FIXME should we also put the name here? */
			new = snprintf( trace_buf+len, MI_TRACE_BUF_SIZE - len,
					"%.*s ", node->value.len, node->value.s);

			len += new;
			CHECK_OVERFLOW(len);

			node = node->next;
		}
	}


	return trace_buf;
}

char* build_mi_trace_reply( int code, str* reason, str* rpl_msg )
{
	int len, new;

	if ( !reason )
		return 0;

	len = snprintf( trace_buf, MI_TRACE_BUF_SIZE,
			"(%d:%.*s)\n",
			code, reason->len, reason->s);
	CHECK_OVERFLOW(len);

	if ( rpl_msg ) {
		new = snprintf( trace_buf+len, MI_TRACE_BUF_SIZE,
				"%.*s...\n",
				rpl_msg->len > MAX_RPL_CHARS ? MAX_RPL_CHARS : rpl_msg->len,
				rpl_msg->s);
		len += new;

		CHECK_OVERFLOW(len);
	}

	return trace_buf;
}

char* generate_correlation_id(int* len)
{
	static char corr_buf[CORR_BUF_SIZE];

	if ( !len )
		return 0;

	*len = snprintf(corr_buf, CORR_BUF_SIZE, "%s%d", CORR_MAGIC, rand());
	if ( *len >= CORR_BUF_SIZE ) {
		LM_ERR("not enough space in correlation buffer!\n");
		return 0;
	}

	return corr_buf;
}


int trace_mi_message(union sockaddr_union* src, union sockaddr_union* dst,
		str* body, str* correlation_value, trace_dest trace_dst)
{
	/* FIXME is this the case for all mi impelementations?? */
	const int proto = IPPROTO_TCP;
	union sockaddr_union tmp, *to_su, *from_su;

	trace_message message;

	if (mi_trace_api->create_trace_message == NULL ||
			mi_trace_api->send_message == NULL) {
		LM_DBG("trace api not loaded!\n");
		return 0;
	}


	if (src == NULL || dst == NULL) {
		tmp.sin.sin_addr.s_addr = TRACE_INADDR_LOOPBACK;
		tmp.sin.sin_port = 0;
		tmp.sin.sin_family = AF_INET;
	}

	/* FIXME src and/or dst port might be in htons form */
	if (src)
		from_su = src;
	else
		from_su = &tmp;

	if (dst)
		to_su = dst;
	else
		to_su = &tmp;

	message = mi_trace_api->create_trace_message(from_su, to_su,
			proto, body, mi_message_id, trace_dst);
	if (message == NULL) {
		LM_ERR("failed to create trace message!\n");
		return -1;
	}

	if ( correlation_value ) {
		if ( correlation_id < 0 || correlation_vendor < 0 ) {
			if ( load_correlation_id() < 0 ) {
				LM_ERR("can't load correlation id!\n");
				return -1;
			}
		}

		if ( mi_trace_api->add_trace_data( message, correlation_value->s,
				correlation_value->len, TRACE_TYPE_STR,
					correlation_id, correlation_vendor) < 0 ) {
			LM_ERR("can't set the correlation id!\n");
			return -1;
		}
	}

	if (mi_trace_api->send_message(message, trace_dst, 0) < 0) {
		LM_ERR("failed to send trace message!\n");
		return -1;
	}

	mi_trace_api->free_message(message);

	return 0;
}

int load_correlation_id(void)
{
	/* already looked for them */
	if (correlation_id > 0 && correlation_vendor > 0)
		return 0;

	return mi_trace_api->get_data_id(correlation_name, &correlation_vendor, &correlation_id);
}



static int mi_mods_no=0;

static int is_id_valid(int id)
{
	/* FIXME is this valid? */
	if ( id >= 8 * sizeof( *(((struct mi_cmd *)0)->trace_mask) ) ||
			id < 0 )
		return 0;

	return 1;
}

/**
 * returns an id that should internally be stored by each module implementing
 * the mi interface
 */
int register_mi_trace_mod(void)
{
	if ( !is_id_valid(mi_mods_no) ) {
		LM_BUG("can't register any more mods; change trace mask data type"
				" from struct mi_cmd!\n");
		return -1;
	}

	return mi_mods_no++;
}

/**
 *
 * initialise mask to 0 or 1 depending on list type
 * if whitelist all mi cmds will be initially set to 0
 * if blacklist all mi cmds will be initially set to 1
 *
 */
int init_mod_trace_cmds(int id, int white)
{
	int idx, len;
	struct mi_cmd* mi_cmds;

	if ( !is_id_valid(id) ) {
		LM_BUG("Invalid module id!\n");
		return -1;
	}

	get_mi_cmds(&mi_cmds, &len);

	for ( idx = 0; idx < len; idx++) {
		if (white) {
			*mi_cmds[idx].trace_mask &= ~(1 << id);
		} else {
			*mi_cmds[idx].trace_mask |= (1 << id);
		}
	}

	return 0;
}

/**
 *
 * block an mi command having its name
 *
 */
int block_mi_cmd_trace(int id, char* name, int len)
{
	struct mi_cmd* cmd;

	if ( !is_id_valid(id) ) {
		LM_BUG("Invalid module id!\n");
		return -1;
	}

	if ( !(cmd = lookup_mi_cmd(name, len)) ) {
		LM_ERR("command (%.*s) not found!\n", len, name);
		return -1;
	}

	*cmd->trace_mask &= ~(1 << id);

	return 0;
}

/**
 *
 * allow an mi command having its name
 *
 */
int allow_mi_cmd_trace(int id, char* name, int len)
{
	struct mi_cmd* cmd;

	if ( !is_id_valid(id) ) {
		LM_BUG("Invalid module id!\n");
		return -1;
	}

	if ( !(cmd = lookup_mi_cmd(name, len)) ) {
		LM_ERR("command (%.*s) not found!\n", len, name);
		return -1;
	}

	*cmd->trace_mask |= (1 << id);

	return 0;
}

unsigned char is_mi_cmd_traced(int id, struct mi_cmd* cmd)
{
	return (1 << id) & *cmd->trace_mask;
}

/**
 *
 * all mi modules that trace their commands must use this functions to parse
 * their blacklist
 *
 */
int parse_mi_cmd_bwlist(int id, char* bw_string, int len)
{

	char* tok_end;

	str token, list;

	int white;

	static const char type_delim = ':';
	static const char list_delim = ',';

	struct mi_cmd* cmd;

	if ( bw_string == NULL || len == 0 ) {
		LM_ERR("empty mi command list!\n");
		return -1;
	}

	tok_end = q_memchr(bw_string, type_delim, len);
	if ( !tok_end ) {
		LM_ERR("missing list type: either blacklist( b ) or whitelist ( w )!\n");
		return -1;
	}

	token.s = bw_string;
	token.len = tok_end - bw_string;
	str_trim_spaces_lr(token);

	if ( token.len != 1 ) {
		goto invalid_list;
	} else if ( token.s[0] == 'w' || token.s[0] == 'W' ) {
		white = 1;
	} else if ( token.s[0] == 'b' || token.s[0] == 'B' ) {
		white = 0;
	} else {
		goto invalid_list;
	}

	if ( init_mod_trace_cmds(id, white) < 0 ) {
		LM_ERR("failed to initialise trace mask for mi commands!\n");
		return -1;
	}

	if ( (tok_end - bw_string) >= len || tok_end + 1 == 0) {
		LM_ERR("no command in list!\n");
		return -1;
	}

	list.s = tok_end + 1;
	list.len = len - ((tok_end + 1) - bw_string);


	while ( list.s != NULL && list.len > 0 ) {
		tok_end = q_memchr( list.s, list_delim, list.len );
		if ( tok_end ) {
			token.s = list.s;
			token.len = tok_end - list.s;

			list.s = tok_end + 1;
			list.len -= token.len + 1;
		} else {
			token = list;
			list.s = NULL;
			list.len = 0;
		}

		str_trim_spaces_lr( token );

		cmd = lookup_mi_cmd( token.s, token.len );
		if ( cmd == NULL ) {
			LM_ERR("can't find mi command [%.*s]!\n", token.len, token.s);
			return -1;
		}

		if ( !cmd->trace_mask ) {
			LM_ERR("command <%.*s> doesn't have it's trace mask allocated!\n",
					token.len, token.s);
			continue;
		}

		if ( white ) {
			*cmd->trace_mask |= ( 1 << id );
		} else {
			*cmd->trace_mask &= ~( 1 << id );
		}
	}

	return 0;

invalid_list:
	LM_ERR("Invalid list type <%.*s>! Either b (blacklist) or w (whitelist)!\n",
			token.len, token.s);
	return -1;
}


