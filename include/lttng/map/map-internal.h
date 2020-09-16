/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_INTERNAL_H
#define LTTNG_MAP_INTERNAL_H

#include <common/macros.h>
#include <common/optional.h>
#include <common/payload.h>
#include <common/payload-view.h>
#include <urcu/ref.h>

#include "map.h"

struct lttng_payload;
struct lttng_payload_view;

struct lttng_map {
	/* Reference counting is only exposed to internal users. */
	struct urcu_ref ref;

	char *name;
	LTTNG_OPTIONAL(bool) is_enabled;
	LTTNG_OPTIONAL(pid_t) pid;
	LTTNG_OPTIONAL(uid_t) uid;
	enum lttng_map_bitness bitness;
	enum lttng_map_boundary_policy boundary_policy;
	enum lttng_domain_type domain;
	enum lttng_buffer_type buffer_type;
	unsigned int dimension_count;
	uint64_t *dimension_sizes;
};

struct lttng_map_list {
	struct lttng_dynamic_pointer_array array;
};

struct lttng_map_key_value_pair {
	char *key;
	uint64_t value;
};

struct lttng_map_key_value_pair_list {
	struct lttng_dynamic_pointer_array array;
};

struct lttng_map_comm {
	uint32_t name_length /* Includes '\0' */;
	uint32_t length;
	uint8_t is_enabled;
	uint64_t pid;
	uint64_t uid;
	uint8_t bitness;
	uint8_t boundary_policy;
	uint8_t domain;
	uint8_t buffer_type;
	uint64_t dimension_count;

	/* length excludes its own length. */
	/* A name and dimension sizes follow. */
	char payload[];
} LTTNG_PACKED;

struct lttng_map_list_comm {
	uint32_t count;
	/* Count * lttng_map_comm structure */
	char payload[];
} LTTNG_PACKED;

struct lttng_map_key_value_pair_comm {
	uint32_t key_length /* Includes '\0' */;
	uint64_t value;
} LTTNG_PACKED;

struct lttng_map_key_value_pair_list_comm {
	uint32_t count;
	/* Count * lttng_map_key_value_pair_comm structure */
	char payload[];
} LTTNG_PACKED;

LTTNG_HIDDEN
ssize_t lttng_map_create_from_payload(struct lttng_payload_view *view,
		struct lttng_map **map);

LTTNG_HIDDEN
int lttng_map_serialize(const struct lttng_map *map,
		struct lttng_payload *payload);

LTTNG_HIDDEN
void lttng_map_get(struct lttng_map *map);

LTTNG_HIDDEN
void lttng_map_put(struct lttng_map *map);

LTTNG_HIDDEN
void lttng_map_set_is_enabled(struct lttng_map *map, bool enabled);

LTTNG_HIDDEN
void lttng_map_set_pid(struct lttng_map *map, pid_t pid);

LTTNG_HIDDEN
void lttng_map_set_uid(struct lttng_map *map, uid_t uid);

/*
 * Allocate a new list of maps.
 * The returned object must be freed via lttng_map_list_destroy.
 */
LTTNG_HIDDEN
struct lttng_map_list *lttng_map_list_create(void);

/*
 * Add a map to the maps set.
 *
 * A reference to the added map is acquired on behalf of the map set
 * on success.
 */
LTTNG_HIDDEN
enum lttng_map_status lttng_map_list_add(struct lttng_map_list *map_list,
		struct lttng_map *map);

LTTNG_HIDDEN
ssize_t lttng_map_list_create_from_payload(struct lttng_payload_view *view,
		struct lttng_map_list **map_list);

/*
 * Serialize a map list to an lttng_payload object.
 * Return LTTNG_OK on success, negative lttng error code on error.
 */
LTTNG_HIDDEN
int lttng_map_list_serialize(const struct lttng_map_list *map_list,
		struct lttng_payload *payload);

LTTNG_HIDDEN
struct lttng_map_key_value_pair *lttng_map_key_value_pair_create(
		const char *key, uint64_t value);

LTTNG_HIDDEN
ssize_t lttng_map_key_value_pair_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_map_key_value_pair **key_value);

LTTNG_HIDDEN
int lttng_map_key_value_pair_serialize(
		const struct lttng_map_key_value_pair *key_value,
		struct lttng_payload *payload);

LTTNG_HIDDEN
void lttng_map_key_value_pair_destroy(
		struct lttng_map_key_value_pair *key_value);

LTTNG_HIDDEN
struct lttng_map_key_value_pair_list *lttng_map_key_value_pair_list_create(void);

LTTNG_HIDDEN
enum lttng_map_status lttng_map_key_value_pair_list_append_key_value(
		struct lttng_map_key_value_pair_list *key_values,
		struct lttng_map_key_value_pair *key_value);

LTTNG_HIDDEN
ssize_t lttng_map_key_value_pair_list_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_map_key_value_pair_list **key_values);

LTTNG_HIDDEN
int lttng_map_key_value_pair_list_serialize(
		const struct lttng_map_key_value_pair_list *key_values,
		struct lttng_payload *payload);

#endif /* LTTNG_MAP_INTERNAL_H */
