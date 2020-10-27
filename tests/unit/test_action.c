/*
 * test_action.c
 *
 * Unit tests for the action API.
 *
 * Copyright (C) 2021 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <tap/tap.h>

#include <lttng/action/action.h>
#include <lttng/action/action-internal.h>
#include <lttng/action/incr-value.h>
#include <lttng/action/incr-value-internal.h>

#include <lttng/map-key-internal.h>

#include <common/dynamic-buffer.h>
#include <common/buffer-view.h>
#include <common/payload.h>

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

#define NUM_TESTS 14

static
void test_action_incr_value(void)
{
	int ret;
	struct lttng_action *action = NULL;
	struct lttng_action *action_from_buffer = NULL;
	const char *map_name = "my_map_name";
	const char *session_name = "my_session_name";
	const char *first_part_key = "first_part_🥇_";
	const char *second_part_key = "_🥈_second_part";
	struct lttng_map_key *key = NULL;
	enum lttng_action_status action_status;
	enum lttng_map_key_status key_status;
	struct lttng_payload buffer;
	const struct lttng_map_key *key_from_buffer;
	const struct lttng_map_key_token *token;

	lttng_payload_init(&buffer);

	/* Test key creation */
	key = lttng_map_key_create();
	ok(key, "Key created");

	key_status = lttng_map_key_append_token_string(key, first_part_key);
	ok(key_status == LTTNG_MAP_KEY_STATUS_OK, "Key append first string");

	key_status = lttng_map_key_append_token_variable(key, LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_EVENT_NAME);
	ok(key_status == LTTNG_MAP_KEY_STATUS_OK, "Key append event name variable");

	key_status = lttng_map_key_append_token_string(key, second_part_key);
	ok(key_status == LTTNG_MAP_KEY_STATUS_OK, "Key append second string");

	/*Test incr value action creation */
	action = lttng_action_incr_value_create();
	ok(action, "Incr-value action created");

	action_status = lttng_action_incr_value_set_session_name(action, session_name);
	ok(action_status == LTTNG_ACTION_STATUS_OK, "incr-value set session name");

	action_status = lttng_action_incr_value_set_map_name(action, map_name);
	ok(action_status == LTTNG_ACTION_STATUS_OK, "incr-value set map name");

	action_status = lttng_action_incr_value_set_key(action, key);
	ok(action_status == LTTNG_ACTION_STATUS_OK, "incr-value set key");

	/* Test incr value action serialization */
	ret = lttng_action_serialize(action, &buffer);
	ok(ret == 0, "Incr value action serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(&buffer, 0, -1);

		(void) lttng_action_create_from_payload(
				&view, &action_from_buffer);
	}
	ok(action_from_buffer, "Incr value action created from payload is non-null");

	action_status = lttng_action_incr_value_get_key(action, &key_from_buffer);
	ok(key_from_buffer, "Retrived key from incr value action");

	token = lttng_map_key_get_token_at_index(key_from_buffer, 0);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_STRING, "First key token is a string");

	token = lttng_map_key_get_token_at_index(key_from_buffer, 1);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE, "Second key token is a variable");

	token = lttng_map_key_get_token_at_index(key_from_buffer, 2);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_STRING, "Third key token is a string");

	lttng_payload_reset(&buffer);

	lttng_action_destroy(action);
	lttng_action_destroy(action_from_buffer);
	lttng_map_key_destroy(key);
}

int main(int argc, const char *argv[])
{
	plan_tests(NUM_TESTS);
	test_action_incr_value();
	return exit_status();
}
