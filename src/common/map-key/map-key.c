/*
 * Copyright (C) 2021 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <stdlib.h>
#include <inttypes.h>

#include <common/dynamic-array.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/payload.h>
#include <common/payload-view.h>

#include <lttng/map-key.h>
#include <lttng/map-key-internal.h>

#define TOKEN_VAR_EVENT_NAME "EVENT_NAME"
#define TOKEN_VAR_PROVIDER_NAME "PROVIDER_NAME"

static
void destroy_map_key_token(void *ptr)
{
	struct lttng_map_key_token *token = (struct lttng_map_key_token *) ptr;
	switch (token->type) {
	case LTTNG_MAP_KEY_TOKEN_TYPE_STRING:
	{
		struct lttng_map_key_token_string *token_string =
				(struct lttng_map_key_token_string *) token;
		free(token_string->string);
		break;
	}
	case LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE:
		break;
	default:
		abort();
	}

	free(token);
}

struct lttng_map_key *lttng_map_key_create(void)
{
	 struct lttng_map_key *key = NULL;

	 key = zmalloc(sizeof(*key));
	 if (!key) {
	 	 return NULL;
	 }

	urcu_ref_init(&key->ref);
	lttng_dynamic_pointer_array_init(&key->tokens,
			destroy_map_key_token);

	return key;
}

ssize_t lttng_map_key_create_from_payload(struct lttng_payload_view *src_view,
		struct lttng_map_key **out_key)
{
	ssize_t ret, consumed_len;
	uint32_t i;
	const struct lttng_map_key_comm *comm;
	struct lttng_map_key *key;

	if (!src_view || !out_key) {
		ret = -1;
		goto end;
	}

	key = lttng_map_key_create();
	if (!key) {
		ret = -1;
		goto end;
	}

	comm = (typeof(comm)) src_view->buffer.data;
	consumed_len = sizeof(*comm);

	assert(comm->token_count > 0);

	for (i = 0; i < comm->token_count; i++) {
		enum lttng_map_key_status key_status;
		const struct lttng_map_key_token_comm *token_comm;
		struct lttng_payload_view child_view =
				lttng_payload_view_from_view(src_view, consumed_len,
						src_view->buffer.size - consumed_len);
		if (!lttng_payload_view_is_valid(&child_view)) {
			ret = -1;
			goto end;
		}

		token_comm = (const struct lttng_map_key_token_comm *) child_view.buffer.data;

		switch (token_comm->type) {
		case LTTNG_MAP_KEY_TOKEN_TYPE_STRING:
		{
			const char *str_val;
			const struct lttng_map_key_token_string_comm *comm;

			comm = (typeof(comm)) token_comm;
			str_val = (const char *) &comm->payload;

			if (!lttng_buffer_view_contains_string(&child_view.buffer,
					str_val, comm->string_len)) {
				ret = -1;
				goto end;
			}

			key_status = lttng_map_key_append_token_string(key, str_val);
			if (key_status != LTTNG_MAP_KEY_STATUS_OK) {
				ret = -1;
				goto end;
			}

			consumed_len += sizeof(*comm) + comm->string_len;

			break;
		}
		case LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE:
		{
			const struct lttng_map_key_token_variable_comm *comm;

			comm = (typeof(comm)) token_comm;
			key_status = lttng_map_key_append_token_variable(key,
					comm->var_type);
			if (key_status != LTTNG_MAP_KEY_STATUS_OK) {
				ret = -1;
				goto end;
			}

			consumed_len += sizeof(*comm);
			break;
		}
		default:
			abort();
		}
	}

	*out_key = key;
	ret = consumed_len;
end:
	return ret;
}

int lttng_map_key_serialize(const struct lttng_map_key *key,
		struct lttng_payload *payload)
{
	int ret;
	uint32_t i, nb_tokens;
	enum lttng_map_key_status key_status;
	struct lttng_map_key_comm comm = {0};

	DBG("Serializing map key");

	key_status = lttng_map_key_get_token_count(key, &nb_tokens);
	if (key_status != LTTNG_MAP_KEY_STATUS_OK) {
		ret = -1;
		goto end;
	}

	if (nb_tokens == 0) {
		ERR("Map key token number is zero");
	 	ret = -1;
		goto end;
	}

	DBG("Serializing map key token count: %" PRIu32, nb_tokens);
	comm.token_count = nb_tokens;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &comm,
			sizeof(comm));
	if (ret) {
		goto end;
	}

	for (i = 0; i < nb_tokens; i++) {
		uint8_t token_type;
		const struct lttng_map_key_token *token =
				lttng_map_key_get_token_at_index(key, i);
		DBG("Serializing map key token's type: %d", token->type);

		token_type = (uint8_t) token->type;

		switch (token->type) {
		case LTTNG_MAP_KEY_TOKEN_TYPE_STRING:
		{
			struct lttng_map_key_token_string *str_token =
					(struct lttng_map_key_token_string *) token;
			struct lttng_map_key_token_string_comm comm = {0};
			uint32_t len = strlen(str_token->string) + 1;

			DBG("Serializing a string type key token");
			comm.parent_type = token_type;
			comm.string_len = len;

			/* Serialize the length, include the null character */
			DBG("Serializing map key token string length (include null character):"
				"%" PRIu32, len);
			ret = lttng_dynamic_buffer_append(&payload->buffer,
				&comm, sizeof(comm));
			if (ret) {
				goto end;
			}

			/* Serialize the string */
			DBG("Serializing map key token string's value: \"%s\"",
					str_token->string);
			ret = lttng_dynamic_buffer_append(&payload->buffer,
					str_token->string, len);
			if (ret) {
				goto end;
			}

			break;
		}
		case LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE:
		{
			struct lttng_map_key_token_variable *var_token =
					(struct lttng_map_key_token_variable *) token;
			struct lttng_map_key_token_variable_comm comm = {0};

			DBG("Serializing a variable type key token");

			comm.parent_type = token_type;
			comm.var_type = var_token->type;

			ret = lttng_dynamic_buffer_append(&payload->buffer,
					&comm, sizeof(comm));
			if (ret) {
				goto end;
			}

			break;
		}
		default:
			abort();
		}
	}

end:
	return ret;
}

static inline
bool token_variable_type_is_valid(enum lttng_map_key_token_variable_type var_type)
{
	switch (var_type) {
	case LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_EVENT_NAME:
	case LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_PROVIDER_NAME:
		return true;
	default:
		return false;
	}
}

static bool lttng_map_key_token_variable_is_equal(
		const struct lttng_map_key_token *_a,
		const struct lttng_map_key_token *_b)
{
	struct lttng_map_key_token_variable *a, *b;
	assert(_a->type == LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE);
	assert(_b->type == LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE);

	a = container_of(_a, struct lttng_map_key_token_variable, parent);
	b = container_of(_b, struct lttng_map_key_token_variable, parent);

	return lttng_map_key_token_variable_get_type(a) ==
			lttng_map_key_token_variable_get_type(b);
}

enum lttng_map_key_status lttng_map_key_append_token_variable(
		struct lttng_map_key *key,
		enum lttng_map_key_token_variable_type var_type)
{
	int ret;
	enum lttng_map_key_status status;
	struct lttng_map_key_token_variable *token = NULL;

	if (!token_variable_type_is_valid(var_type)) {
		ERR("Invalid token variable type");
		status = LTTNG_MAP_KEY_STATUS_INVALID;
		goto end;
	}

	token = zmalloc(sizeof(*token));
	if (!token) {
		status = LTTNG_MAP_KEY_STATUS_ERROR;
		goto end;
	}

	token->parent.type = LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE;
	token->parent.equal = lttng_map_key_token_variable_is_equal;
	token->type = var_type;

	ret = lttng_dynamic_pointer_array_add_pointer(
			&key->tokens, token);
	if (ret) {
		status = LTTNG_MAP_KEY_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_MAP_KEY_STATUS_OK;

end:
	return status;
}

static bool lttng_map_key_token_string_is_equal(
		const struct lttng_map_key_token *_a,
		const struct lttng_map_key_token *_b)
{
	struct lttng_map_key_token_string *a, *b;
	const char *a_string, *b_string;

	assert(_a->type == LTTNG_MAP_KEY_TOKEN_TYPE_STRING);
	assert(_b->type == LTTNG_MAP_KEY_TOKEN_TYPE_STRING);

	a = container_of(_a, struct lttng_map_key_token_string, parent);
	b = container_of(_b, struct lttng_map_key_token_string, parent);

	a_string = lttng_map_key_token_string_get_string(a);
	b_string = lttng_map_key_token_string_get_string(b);

	return !strcmp(a_string, b_string);
}

enum lttng_map_key_status lttng_map_key_append_token_string(
		struct lttng_map_key *key, const char *string)
{
	int ret;
	enum lttng_map_key_status status;
	struct lttng_map_key_token_string *token = NULL;


	token = zmalloc(sizeof(*token));
	if (!token) {
		status = LTTNG_MAP_KEY_STATUS_ERROR;
		goto end;
	}

	token->parent.type = LTTNG_MAP_KEY_TOKEN_TYPE_STRING;
	token->parent.equal = lttng_map_key_token_string_is_equal;
	token->string = strdup(string);
	if (!token->string) {
		status = LTTNG_MAP_KEY_STATUS_ERROR;
		goto end;
	}

	ret = lttng_dynamic_pointer_array_add_pointer(
			&key->tokens, token);
	if (ret) {
		status = LTTNG_MAP_KEY_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_MAP_KEY_STATUS_OK;
end:
	return status;
}

enum lttng_map_key_status lttng_map_key_get_token_count(
		const struct lttng_map_key *key, unsigned int *count)
{
	enum lttng_map_key_status status;
	if (!key || !count) {
		status = LTTNG_MAP_KEY_STATUS_INVALID;
		goto end;

	}

	*count = lttng_dynamic_pointer_array_get_count(
			&key->tokens);

	status = LTTNG_MAP_KEY_STATUS_OK;
end:
	return status;
}

const struct lttng_map_key_token *
lttng_map_key_get_token_at_index(const struct lttng_map_key *key,
		unsigned int index)
{
	const struct lttng_map_key_token *token = NULL;
	enum lttng_map_key_status status;
	unsigned int count;

	if (!key) {
		goto end;
	}

	status = lttng_map_key_get_token_count(key, &count);
	if (status != LTTNG_MAP_KEY_STATUS_OK) {
		goto end;
	}

	if (index >= count) {
		goto end;
	}

	token = lttng_dynamic_pointer_array_get_pointer(&key->tokens,
			index);

end:
	return token;
}

enum lttng_map_key_token_variable_type lttng_map_key_token_variable_get_type(
		const struct lttng_map_key_token_variable *token)
{
	assert(token->parent.type == LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE);

	return token->type;
}

const char *lttng_map_key_token_string_get_string(
		const struct lttng_map_key_token_string *token)
{
	assert(token->parent.type == LTTNG_MAP_KEY_TOKEN_TYPE_STRING);

	return token->string;
}

void lttng_map_key_destroy(struct lttng_map_key *key)
{
	lttng_map_key_put(key);
}

LTTNG_HIDDEN
struct lttng_map_key *lttng_map_key_parse_from_string(const char *_key_str)
{
	struct lttng_map_key *key = NULL;
	enum lttng_map_key_status status;
	char *key_str = NULL, *curr_pos;

	key = lttng_map_key_create();
	if (!key) {
		goto end;
	}

	key_str = strdup(_key_str);

	curr_pos = key_str;

	curr_pos = strtok(curr_pos, "$}");
	while (curr_pos) {
		if (curr_pos[0] == '{') {
			if (strncmp(&curr_pos[1], TOKEN_VAR_EVENT_NAME, strlen(TOKEN_VAR_EVENT_NAME)) == 0) {
				status = lttng_map_key_append_token_variable(key,
						LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_EVENT_NAME);
				if (status != LTTNG_MAP_KEY_STATUS_OK) {
					goto error;
				}
			} else if (strncmp(&curr_pos[1], TOKEN_VAR_PROVIDER_NAME, strlen(TOKEN_VAR_PROVIDER_NAME)) == 0) {
				status = lttng_map_key_append_token_variable(key,
						LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_PROVIDER_NAME);
				if (status != LTTNG_MAP_KEY_STATUS_OK) {
					goto error;
				}
			} else {
				goto error;
			}
		} else {
			status = lttng_map_key_append_token_string(key, curr_pos);
			if (status != LTTNG_MAP_KEY_STATUS_OK) {
				goto error;
			}
		}
		curr_pos = strtok(NULL, "$}");
	}
	goto end;

error:
	lttng_map_key_destroy(key);
	key = NULL;
end:
	free(key_str);

	return key;
}

LTTNG_HIDDEN
bool lttng_map_key_is_equal(
		const struct lttng_map_key *a, const struct lttng_map_key *b)
{
	bool is_equal = false;
	enum lttng_map_key_status status;
	unsigned int a_count, b_count, i;

	if (!!a != !!b) {
		goto end;
	}

	if (a == NULL && b == NULL) {
		is_equal = true;
		goto end;
	}

	if (a == b) {
		is_equal = true;
		goto end;
	}

	status = lttng_map_key_get_token_count(a, &a_count);
	assert(status == LTTNG_MAP_KEY_STATUS_OK);
	status = lttng_map_key_get_token_count(b, &b_count);
	assert(status == LTTNG_MAP_KEY_STATUS_OK);

	if (a_count != b_count) {
		goto end;
	}

	for (i = 0; i < a_count; i++) {
		const struct lttng_map_key_token *token_a = NULL, *token_b = NULL;

		token_a = lttng_map_key_get_token_at_index(a, i);
		token_b = lttng_map_key_get_token_at_index(b, i);

		/* JORAJ TODO: is order important for the map key token? */
		if(token_a->type != token_b->type) {
			goto end;
		}

		if(!token_a->equal(token_a, token_b)) {
			goto end;
		}
	}

	is_equal = true;

end:
	return is_equal;


}

static void map_key_destroy_ref(struct urcu_ref *ref)
{
	struct lttng_map_key *key = container_of(ref, struct lttng_map_key, ref);

	lttng_dynamic_pointer_array_reset(&key->tokens);
	free(key);
}

LTTNG_HIDDEN
void lttng_map_key_get(struct lttng_map_key *key)
{
	urcu_ref_get(&key->ref);
}

LTTNG_HIDDEN
void lttng_map_key_put(struct lttng_map_key *key)
{
	if (!key) {
		return;
	}

	urcu_ref_put(&key->ref, map_key_destroy_ref);
}
