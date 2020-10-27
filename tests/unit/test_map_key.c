/*
 * test_map_key.c
 *
 * Unit tests for the map-key API.
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

#include <lttng/map-key-internal.h>

#define NUM_TESTS 38

const char *key_str1 = "simple_string";
const char *key_str2 = "${EVENT_NAME}";
const char *key_str3 = "foo_${EVENT_NAME}";
const char *key_str4 = "foo_${EVENT_NAME}_bar";
const char *key_str5 = "${EVENT_NAME}_bar_${EVENT_NAME}";
const char *key_str6 = "foo_${NON_EXISTING_VAR}";
const char *key_str7 = "foo_${}";
const char *key_str8 = "foo_${PROVIDER_NAME}";

static
void test_map_key(void)
{
	struct lttng_map_key *key;
	enum lttng_map_key_status status;
	const struct lttng_map_key_token *token;
	const struct lttng_map_key_token_variable *var_token;
	unsigned int count;

	key = lttng_map_key_parse_from_string(key_str6);
	ok(!key, "Failed to create key from \"%s\" as expected", key_str6);

	key = lttng_map_key_parse_from_string(key_str7);
	ok(!key, "Failed to create key from \"%s\" as expected", key_str7);

	key = lttng_map_key_parse_from_string(key_str1);
	ok(key, "Created key from \"%s\"", key_str1);
	status = lttng_map_key_get_token_count(key, &count);
	ok(status == LTTNG_MAP_KEY_STATUS_OK, "Got count for key_str1");
	ok(count == 1, "Got correct token count for key_str1");
	token = lttng_map_key_get_token_at_index(key, 0);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_STRING, "First token of string type");
	lttng_map_key_destroy(key);

	key = lttng_map_key_parse_from_string(key_str2);
	ok(key, "Created key from \"%s\"", key_str2);
	status = lttng_map_key_get_token_count(key, &count);
	ok(status == LTTNG_MAP_KEY_STATUS_OK, "Got count for key_str2");
	ok(count == 1, "Got correct token count for key_str2");
	token = lttng_map_key_get_token_at_index(key, 0);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE, "First token of variable type");
	var_token = (typeof(var_token)) token;
	ok(var_token->type == LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_EVENT_NAME, "EVENT_NAME variable type");
	lttng_map_key_destroy(key);

	key = lttng_map_key_parse_from_string(key_str3);
	ok(key, "Created key from \"%s\"", key_str3);
	status = lttng_map_key_get_token_count(key, &count);
	ok(status == LTTNG_MAP_KEY_STATUS_OK, "Got count for key_str3");
	ok(count == 2, "Got correct token count for key_str3");
	token = lttng_map_key_get_token_at_index(key, 0);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_STRING, "First token of string type");
	token = lttng_map_key_get_token_at_index(key, 1);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE, "Second token of variable type");
	var_token = (typeof(var_token)) token;
	ok(var_token->type == LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_EVENT_NAME, "EVENT_NAME variable type");
	lttng_map_key_destroy(key);

	key = lttng_map_key_parse_from_string(key_str4);
	ok(key, "Created key from \"%s\"", key_str4);
	status = lttng_map_key_get_token_count(key, &count);
	ok(status == LTTNG_MAP_KEY_STATUS_OK, "Got count for key_str4");
	ok(count == 3, "Got correct token count for key_str4");
	token = lttng_map_key_get_token_at_index(key, 0);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_STRING, "First token of string type");
	token = lttng_map_key_get_token_at_index(key, 1);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE, "Second token of variable type");
	var_token = (typeof(var_token)) token;
	ok(var_token->type == LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_EVENT_NAME, "EVENT_NAME variable type");
	token = lttng_map_key_get_token_at_index(key, 2);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_STRING, "Third token of string type");
	lttng_map_key_destroy(key);

	key = lttng_map_key_parse_from_string(key_str5);
	ok(key, "Created key from \"%s\"", key_str5);
	status = lttng_map_key_get_token_count(key, &count);
	ok(status == LTTNG_MAP_KEY_STATUS_OK, "Got count for key_str5");
	ok(count == 3, "Got correct token count for key_str5");
	token = lttng_map_key_get_token_at_index(key, 0);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE, "First token of variable type");
	var_token = (typeof(var_token)) token;
	ok(var_token->type == LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_EVENT_NAME, "EVENT_NAME variable type");
	token = lttng_map_key_get_token_at_index(key, 1);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_STRING, "Second token of string type");
	token = lttng_map_key_get_token_at_index(key, 2);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE, "Third token of variable type");
	var_token = (typeof(var_token)) token;
	ok(var_token->type == LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_EVENT_NAME, "EVENT_NAME variable type");
	lttng_map_key_destroy(key);

	key = lttng_map_key_parse_from_string(key_str8);
	ok(key, "Created key from \"%s\"", key_str8);
	status = lttng_map_key_get_token_count(key, &count);
	ok(status == LTTNG_MAP_KEY_STATUS_OK, "Got count for key_str8");
	ok(count == 2, "Got correct token count for key_str8");
	token = lttng_map_key_get_token_at_index(key, 0);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_STRING, "First token of string type");
	token = lttng_map_key_get_token_at_index(key, 1);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE, "Second token of variable type");
	var_token = (typeof(var_token)) token;
	ok(var_token->type == LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_PROVIDER_NAME, "PROVIDER_NAME variable type");
	lttng_map_key_destroy(key);
}

int main(int argc, const char *argv[])
{
	plan_tests(NUM_TESTS);
	test_map_key();
	return exit_status();
}
