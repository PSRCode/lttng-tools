/*
 * Copyright (C) 2021 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#ifndef LTTNG_MAP_KEY_INTERNAL_H
#define LTTNG_MAP_KEY_INTERNAL_H

#include <common/dynamic-array.h>
#include <common/macros.h>
#include <stdbool.h>
#include <urcu/ref.h>

#include <lttng/map-key.h>

struct lttng_payload;
struct lttng_payload_view;
struct lttng_map_key_token;

typedef bool (*map_key_token_equal_cb)(const struct lttng_map_key_token *a,
		const struct lttng_map_key_token *b);

enum lttng_map_key_token_type {
	LTTNG_MAP_KEY_TOKEN_TYPE_STRING,
	LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE,
};

struct lttng_map_key_token {
	enum lttng_map_key_token_type type;
	map_key_token_equal_cb equal;
};

struct lttng_map_key_token_comm {
	uint8_t type;
};

struct lttng_map_key_token_string {
	struct lttng_map_key_token parent;
	char *string;
};

struct lttng_map_key_token_string_comm {
	uint8_t parent_type;

	/* Includes null terminator. */
	uint32_t string_len;

	char payload[];
};

struct lttng_map_key_token_variable {
	struct lttng_map_key_token parent;
	enum lttng_map_key_token_variable_type type;
};

struct lttng_map_key_token_variable_comm {
	uint8_t parent_type;
	uint8_t var_type;
};

struct lttng_map_key {
	/* Reference counting is only exposed to internal users*/
	struct urcu_ref ref;
	/* Array of `struct lttng_map_key_token` */
	struct lttng_dynamic_pointer_array tokens;
};

struct lttng_map_key_comm {
	uint32_t token_count;
	/* Array of `struct lttng_map_key_token` */
	char payload[];
};

LTTNG_HIDDEN
void lttng_map_key_get(struct lttng_map_key *key);

LTTNG_HIDDEN
void lttng_map_key_put(struct lttng_map_key *key);

LTTNG_HIDDEN
ssize_t lttng_map_key_create_from_payload(struct lttng_payload_view *view,
		struct lttng_map_key **key);

LTTNG_HIDDEN
int lttng_map_key_serialize(const struct lttng_map_key *key,
		struct lttng_payload *payload);

LTTNG_HIDDEN
enum lttng_map_key_status lttng_map_key_get_token_count(
		const struct lttng_map_key *key, unsigned int *count);

LTTNG_HIDDEN
const struct lttng_map_key_token *lttng_map_key_get_token_at_index(
		const struct lttng_map_key *key, unsigned int index);

LTTNG_HIDDEN
enum lttng_map_key_token_variable_type lttng_map_key_token_variable_get_type(
		const struct lttng_map_key_token_variable *token);

LTTNG_HIDDEN
const char *lttng_map_key_token_string_get_string(
		const struct lttng_map_key_token_string *token);

LTTNG_HIDDEN
bool lttng_map_key_is_equal(
		const struct lttng_map_key *a, const struct lttng_map_key *b);

LTTNG_HIDDEN
void lttng_map_key_get(struct lttng_map_key *key);

LTTNG_HIDDEN
void lttng_map_key_put(struct lttng_map_key *key);

LTTNG_HIDDEN
struct lttng_map_key *lttng_map_key_parse_from_string(const char *key_str);

#endif /* LTTNG_MAP_KEY_INTERNAL_H */
