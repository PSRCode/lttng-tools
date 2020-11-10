/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <math.h>

#include <common/dynamic-array.h>
#include <lttng/domain.h>
#include <lttng/lttng-error.h>
#include <lttng/map/map.h>
#include <lttng/map/map-internal.h>

#include "../command.h"

#include "common/argpar/argpar.h"

enum {
	OPT_HELP,
	OPT_SESSION,
	OPT_LIST_OPTIONS,
	OPT_USERSPACE,
	OPT_KERNEL,
};

static const
struct argpar_opt_descr view_map_options[] = {
	{ OPT_HELP, 'h', "help", false },
	{ OPT_SESSION, 's', "session", true },
	{ OPT_LIST_OPTIONS, '\0', "list-options", false },
	/* Domains */
	{ OPT_USERSPACE, 'u', "userspace", false },
	{ OPT_KERNEL, 'k', "kernel", false },
	ARGPAR_OPT_DESCR_SENTINEL,
};

static
bool assign_domain_type(enum lttng_domain_type *dest,
		enum lttng_domain_type src)
{
	bool ret;

	if (*dest == LTTNG_DOMAIN_NONE || *dest == src) {
		*dest = src;
		ret = true;
	} else {
		ERR("Multiple domains specified.");
		ret = false;
	}

	return ret;
}

static
bool assign_string(char **dest, const char *src, const char *opt_name)
{
	bool ret;

	if (*dest) {
		ERR("Duplicate %s given.", opt_name);
		goto error;
	}

	*dest = strdup(src);
	if (!*dest) {
		ERR("Failed to allocate %s string.", opt_name);
		goto error;
	}

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

static
int compare_key_value_by_key(const void *a, const void *b)
{
	const struct lttng_map_key_value_pair *kv_a =
			*((const struct lttng_map_key_value_pair **) a);
	const struct lttng_map_key_value_pair *kv_b =
			*((const struct lttng_map_key_value_pair **) b);
	const char *key_a, *key_b;
	enum lttng_map_status map_status;

	map_status = lttng_map_key_value_pair_get_key(kv_a, &key_a);
	assert(map_status == LTTNG_MAP_STATUS_OK);

	map_status = lttng_map_key_value_pair_get_key(kv_b, &key_b);
	assert(map_status == LTTNG_MAP_STATUS_OK);

	return strcmp(key_a, key_b);
}

static
void print_one_map_key_value_pair(const struct lttng_map_key_value_pair *kv_pair,
		size_t key_len, size_t val_len)
{
	const char *key = NULL;
	uint64_t value;
	enum lttng_map_status status;

	status = lttng_map_key_value_pair_get_key(kv_pair, &key);
	if (status != LTTNG_MAP_STATUS_OK) {
		ERR("Failed to get key-value pair's key.");
		goto end;
	}

	status = lttng_map_key_value_pair_get_value(kv_pair, &value);
	if (status != LTTNG_MAP_STATUS_OK) {
		ERR("Failed to get value-value pair's value.");
		goto end;
	}

	MSG("| %*s | %*"PRIu64" |", (int) -key_len, key, (int) val_len, value);

end:
	return;
}

static
void print_line(size_t key_len, size_t val_len)
{
	int i;

	_MSG("+");
	for (i = 0; i < (int) key_len; i++) {
		_MSG("-");
	}
	_MSG("+");
	for (i = 0; i < (int) val_len + 2; i++) {
		_MSG("-");
	}
	MSG("+");
}

static
size_t number_of_digit(uint64_t val)
{
	size_t ret;

	if (val == 0) {
		ret = 1;
	} else {
		/*
		 * SOURCE:
		 * https://stackoverflow.com/questions/1068849/how-do-i-determine-the-number-of-digits-of-an-integer-in-c
		 * If the log10() call becomes to expensive, we could use a
		 * recursive approach to count the digits.
		 */
		ret = floor(log10(val)) + 1;
	}

	return ret;
}

static
enum lttng_error_code print_one_map(struct lttng_handle *handle,
		const char *map_name)
{
	enum lttng_error_code ret;
	enum lttng_map_status map_status;
	struct lttng_map_key_value_pair_list *kv_pair_list = NULL;
	size_t longest_key_len = 0, longest_val_len = 0;
	unsigned int i, key_value_pair_count;
	struct lttng_dynamic_pointer_array sorted_kv_pair_list;

	lttng_dynamic_pointer_array_init(&sorted_kv_pair_list, NULL);

	/* Fetch the key value pair_list from the sessiond */
	ret = lttng_list_map_key_value_pairs(handle, map_name, &kv_pair_list);
	if (ret != LTTNG_OK) {
		ERR("Error listing map key value pair_list: %s.",
				lttng_strerror(-ret));
		goto error;
	}

	map_status = lttng_map_key_value_pair_list_get_count(kv_pair_list,
			&key_value_pair_count);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Failed to get key-value pair count.");
		goto error;
	}

	for (i = 0; i < key_value_pair_count; i++) {
		const char *cur_key;
		uint64_t cur_val;
		const struct lttng_map_key_value_pair *pair =
				lttng_map_key_value_pair_list_get_at_index(
						kv_pair_list, i);

		/* Add all key value pairs to the sorting array. */
		lttng_dynamic_pointer_array_add_pointer(&sorted_kv_pair_list,
				(void *) pair);

		/* Keep track of the longest key. */
		lttng_map_key_value_pair_get_key(pair, &cur_key);
		longest_key_len = max(longest_key_len, strlen(cur_key));

		/* Keep track of the longest value. */
		lttng_map_key_value_pair_get_value(pair, &cur_val);
		longest_val_len = max(longest_val_len, number_of_digit(cur_val));
	}

	qsort(sorted_kv_pair_list.array.buffer.data,
			lttng_dynamic_pointer_array_get_count(&sorted_kv_pair_list),
			sizeof(struct lttng_map_key_value_pair *),
			compare_key_value_by_key);

	MSG("Session: '%s', map: '%s':", handle->session_name, map_name);

	if (key_value_pair_count == 0) {
		MSG("    No value in the map");
		ret = LTTNG_OK;
		goto end;
	} else {
		for (i = 0; i < key_value_pair_count; i++) {
			print_line(longest_key_len, longest_val_len);

			print_one_map_key_value_pair(
				lttng_dynamic_pointer_array_get_pointer(&sorted_kv_pair_list, i),
				longest_key_len, longest_val_len);
		}

		print_line(longest_key_len, longest_val_len);
	}

	ret = LTTNG_OK;
	goto end;

error:
	ret = LTTNG_ERR_MAP_VALUES_LIST_FAIL;
end:
	lttng_map_key_value_pair_list_destroy(kv_pair_list);
	lttng_dynamic_pointer_array_reset(&sorted_kv_pair_list);

	return ret;
}

static
int view_map(struct lttng_handle *handle, const char *desired_map_name)
{
	enum lttng_error_code ret;
	struct lttng_map_list *map_list = NULL;
	enum lttng_map_status map_status;
	bool desired_map_found = false;
	unsigned int i, map_count;

	DBG("Listing map(s) (%s)", desired_map_name ? : "<all>");
	/*
	 * Query the sessiond for a list of all the maps that match the
	 * provided map name and domain (if any).
	 */
	ret = lttng_list_maps(handle, &map_list);
	if (ret != LTTNG_OK) {
		ERR("Error getting map list");
		goto end;
	}

	map_status = lttng_map_list_get_count(map_list, &map_count);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Error getting map list element count");
		ret = -1;
		goto end;
	}

	for (i = 0; i < map_count; i++) {
		const struct lttng_map *map = NULL;
		const char *map_name = NULL;
		map = lttng_map_list_get_at_index(map_list, i);
		if (!map) {
			ERR("Error getting map from list: index = %u", i);
			goto end;
		}

		map_status = lttng_map_get_name(map, &map_name);
		if (map_status != LTTNG_MAP_STATUS_OK) {
			ERR("Error getting map name");
			ret = -1;
			goto end;
		}

		if (desired_map_name != NULL) {
			if (strncmp(map_name, desired_map_name, NAME_MAX) == 0) {
				desired_map_found = true;
				ret = print_one_map(handle, map_name);
				if (ret != LTTNG_OK) {
					ret = -1;
					goto end;
				}
			}
		}
	}

	if (desired_map_name && !desired_map_found) {
		ret = LTTNG_ERR_MAP_NOT_FOUND;
		ERR("map %s: %s (session %s)", desired_map_name,
			lttng_strerror(-ret), handle->session_name);
		goto end;
	}

end:
	lttng_map_list_destroy(map_list);
	return ret;
}

int cmd_view_map(int argc, const char **argv)
{
	struct argpar_parse_ret argpar_parse_ret = { 0 };
	enum lttng_domain_type domain_type = LTTNG_DOMAIN_NONE;
	const char *opt_map_name = NULL;;
	char *opt_session_name = NULL, *session_name = NULL;
	struct lttng_domain domain;
	struct lttng_domain *domains = NULL;
	struct lttng_handle *handle;

	int ret, i;

	memset(&domain, 0, sizeof(domain));

	argpar_parse_ret = argpar_parse(argc - 1, argv + 1,
		view_map_options, true);
	if (!argpar_parse_ret.items) {
		ERR("%s", argpar_parse_ret.error);
		goto error;
	}

	for (i = 0; i < argpar_parse_ret.items->n_items; i++) {
		struct argpar_item *item = argpar_parse_ret.items->items[i];

		if (item->type == ARGPAR_ITEM_TYPE_OPT) {
			struct argpar_item_opt *item_opt =
				(struct argpar_item_opt *) item;

			switch (item_opt->descr->id) {
			case OPT_HELP:
				SHOW_HELP();
				ret = CMD_SUCCESS;
				goto end;
			case OPT_SESSION:
				if (!assign_string(&opt_session_name, item_opt->arg,
						"-s/--session")) {
					goto error;
				}
				break;
			case OPT_LIST_OPTIONS:
				list_cmd_options_argpar(stdout,
					view_map_options);
				ret = CMD_SUCCESS;
				goto end;
			case OPT_USERSPACE:
				if (!assign_domain_type(&domain_type, LTTNG_DOMAIN_UST)) {
					goto error;
				}
				break;

			case OPT_KERNEL:
				if (!assign_domain_type(&domain_type, LTTNG_DOMAIN_KERNEL)) {
					goto error;
				}
				break;

			default:
				abort();
			}

		} else {
			struct argpar_item_non_opt *item_non_opt =
				(struct argpar_item_non_opt *) item;

			if (opt_map_name) {
				ERR("Unexpected argument: %s", item_non_opt->arg);
				goto error;
			}
			opt_map_name = item_non_opt->arg;
		}
	}

	if (!opt_map_name) {
		ERR("Map name must be provided");
		goto error;
	}

	if (!opt_session_name) {
		DBG("No session name provided, print maps of the default session");
		session_name = get_session_name();
		if (session_name == NULL) {
			goto error;
		}
	} else {
		session_name = opt_session_name;
	}

	domain.type = domain_type;
	handle = lttng_create_handle(session_name, &domain);
	if (handle == NULL) {
		ret = CMD_FATAL;
		goto end;
	}

	if (domain.type != LTTNG_DOMAIN_NONE) {
		/* Print maps of the given domain. */
		ret = view_map(handle, opt_map_name);
		if (ret != LTTNG_OK) {
			goto error;
		}
	} else {
		int i, nb_domain;

		/* We want all domain(s) */
		nb_domain = lttng_list_domains(session_name, &domains);
		if (nb_domain < 0) {
			ret = CMD_ERROR;
			ERR("%s", lttng_strerror(nb_domain));
			goto end;
		}

		for (i = 0; i < nb_domain; i++) {
			/* Clean handle before creating a new one */
			if (handle) {
				lttng_destroy_handle(handle);
			}

			handle = lttng_create_handle(session_name, &domains[i]);
			if (handle == NULL) {
				ret = CMD_FATAL;
				goto end;
			}

			ret = view_map(handle, opt_map_name);
			if (ret != LTTNG_OK) {
				goto error;
			}
		}
	}

	ret = CMD_SUCCESS;
	goto end;
error:
	ret = CMD_ERROR;

end:
	if (!opt_session_name && session_name) {
		free(session_name);
	}

	argpar_parse_ret_fini(&argpar_parse_ret);
	return ret;
}
