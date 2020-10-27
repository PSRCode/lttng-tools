/*
 * Copyright (C) 2021 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_KEY_H
#define LTTNG_MAP_KEY_H

struct lttng_map_key;

enum lttng_map_key_status {
	LTTNG_MAP_KEY_STATUS_ERROR = -2,
	LTTNG_MAP_KEY_STATUS_INVALID = -1,
	LTTNG_MAP_KEY_STATUS_OK = 0,
};

enum lttng_map_key_token_variable_type {
	LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_EVENT_NAME,
	LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_PROVIDER_NAME,
};

struct lttng_map_key *lttng_map_key_create(void);

enum lttng_map_key_status lttng_map_key_append_token_variable(
		struct lttng_map_key *key,
		enum lttng_map_key_token_variable_type var_type);

enum lttng_map_key_status lttng_map_key_append_token_string(
		struct lttng_map_key *key, const char *string);

void lttng_map_key_destroy(struct lttng_map_key *key);

#endif /* LTTNG_MAP_KEY_H */
