/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_H
#define LTTNG_MAP_H

#include <stddef.h>

#include <lttng/domain.h>
#include <lttng/handle.h>

struct lttng_map;
struct lttng_map_list;

struct lttng_map_key_value_pair;
/* A list of key value pair_list. */
struct lttng_map_key_value_pair_list;

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_map_status {
	LTTNG_MAP_STATUS_OK = 0,
	LTTNG_MAP_STATUS_ERROR = -1,
	LTTNG_MAP_STATUS_INVALID = -2,
	LTTNG_MAP_STATUS_UNSET = -3,
};

enum lttng_map_bitness {
	LTTNG_MAP_BITNESS_32BITS = 32,
	LTTNG_MAP_BITNESS_64BITS = 64,
};

enum lttng_map_boundary_policy {
	LTTNG_MAP_BOUNDARY_POLICY_OVERFLOW,
};

/*
 *
 * Return LTTNG_MAP_STATUS_OK on success, LTTNG_MAP_STATUS_INVALID if invalid
 * parameters are passed.
 */
extern enum lttng_map_status lttng_map_create(const char *name,
		unsigned int dimension_count,
		uint64_t *dimension_sizes,
		enum lttng_domain_type domain,
		enum lttng_buffer_type buffer_type,
		enum lttng_map_bitness bitness,
		enum lttng_map_boundary_policy boundary_policy,
		struct lttng_map **map);

extern enum lttng_map_status lttng_map_get_name(
		const struct lttng_map *map, const char **name);

extern enum lttng_map_status lttng_map_set_name(
		struct lttng_map *map, const char *name);

/*
 * Get the number of dimensions.
 *
 */
extern unsigned int lttng_map_get_dimension_count(
		const struct lttng_map *map);

/*
 * Get the number of elements for the provided dimension.
 *
 * Return LTTNG_MAP_STATUS_OK on success, LTTNG_MAP_STATUS_INVALID if invalid
 * parameters are passed.
 *
 */
extern enum lttng_map_status lttng_map_get_dimension_length(
		const struct lttng_map *map, unsigned int dimension,
		uint64_t *dimension_length);

extern int lttng_map_get_is_enabled(const struct lttng_map *map);

extern pid_t lttng_map_get_pid(const struct lttng_map *map);

extern uid_t lttng_map_get_uid(const struct lttng_map *map);

extern enum lttng_map_bitness lttng_map_get_bitness(
		const struct lttng_map *map);

extern enum lttng_domain_type lttng_map_get_domain(
		const struct lttng_map *map);

extern enum lttng_buffer_type lttng_map_get_buffer_type(
		const struct lttng_map *map);

extern enum lttng_map_boundary_policy lttng_map_get_boundary_policy(
		const struct lttng_map *map);

extern void lttng_map_destroy(struct lttng_map *map);

extern enum lttng_error_code lttng_add_map(struct lttng_handle *handle,
		struct lttng_map *map);

extern enum lttng_error_code lttng_enable_map(struct lttng_handle *handle,
		const char *map_name);

extern enum lttng_error_code lttng_disable_map(struct lttng_handle *handle,
		const char *map_name);

/*
 * Get a map from the list at a given index.
 *
 * Note that the map list maintains the ownership of the returned map.
 * It must not be destroyed by the user, nor should a reference to it be held
 * beyond the lifetime of the map list.
 *
 * Returns a map, or NULL on error.
 */
extern const struct lttng_map *lttng_map_list_get_at_index(
		const struct lttng_map_list *map_list, unsigned int index);

/*
 * Get the number of map in a map list.
 */

extern enum lttng_map_status lttng_map_list_get_count(
		const struct lttng_map_list *map_list, unsigned int *count);

/*
 * Destroy a map list.
 */
extern void lttng_map_list_destroy(struct lttng_map_list *map_list);

/*
 * Get the key of a key-value.
 *
 * The caller does not assume the ownership of the returned key.
 * The key shall only be used for the duration of the key-value's lifetime.
 *
 * Returns LTTNG_MAP_STATUS_OK and a pointer to the key-value's key on success,
 * LTTNG_MAP_STATUS_INVALID if an invalid parameter is passed, or
 */
extern enum lttng_map_status lttng_map_key_value_pair_get_key(
		const struct lttng_map_key_value_pair *kv_pair, const char **key);

/*
 * Get the value of a key-value.
 *
 * The caller does not assume the ownership of the returned value.
 * The value shall only be used for the duration of the key-value's lifetime.
 *
 * Returns LTTNG_MAP_STATUS_OK and a pointer to the key-value's value on success,
 * LTTNG_MAP_STATUS_INVALID if an invalid parameter is passed.
 */
extern enum lttng_map_status lttng_map_key_value_pair_get_value(
		const struct lttng_map_key_value_pair *kv_pair, uint64_t *value);

/*
 * List all key-value pairs for the given session and map.
 *
 * On success, a newly-allocated key-value list is returned.
 *
 * The key-value list must be destroyed by the caller (see
 * lttng_map_key_value_pair_list_destroy()).
 *
 * Returns LTTNG_OK on success, else a suitable LTTng error code.
 */
extern enum lttng_error_code lttng_list_map_key_value_pairs(
		struct lttng_handle *handle, const char *map_name,
		struct lttng_map_key_value_pair_list **kv_pair_list);

/*
 * Get a key-value from the list at a given index.
 *
 * Note that the key value list maintains the ownership of the returned key
 * value.
 * It must not be destroyed by the user, nor should a reference to it be held
 * beyond the lifetime of the key value list.
 *
 * Returns a key-value, or NULL on error.
 */
extern const struct lttng_map_key_value_pair *lttng_map_key_value_pair_list_get_at_index(
		const struct lttng_map_key_value_pair_list *kv_pair_list,
		unsigned int index);

/*
 * Get the number of key value pair in a key-value list.
 *
 * Return LTTNG_MAP_STATUS_OK on success,
 * LTTNG_MAP_STATUS_INVALID when invalid parameters are passed.
 */
extern enum lttng_map_status lttng_map_key_value_pair_list_get_count(
		const struct lttng_map_key_value_pair_list *kv_pair_list,
		unsigned int *count);

/*
 * Destroy a map_key_value set.
 */
extern void lttng_map_key_value_pair_list_destroy(
		struct lttng_map_key_value_pair_list *kv_pair_list);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_H */
