/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "lttng/map/map.h"
#include "lttng/domain.h"
#include <assert.h>
#include <string.h>

#include <common/error.h>
#include <common/macros.h>
#include <common/optional.h>
#include <common/payload.h>

#include <lttng/map/map-internal.h>

enum lttng_map_status lttng_map_set_name(struct lttng_map *map,
		const char *name)
{
	char *name_copy = NULL;
	enum lttng_map_status status;

	if (!map || !name || strlen(name) == 0) {
		status = LTTNG_MAP_STATUS_INVALID;
		goto end;
	}

	name_copy = strdup(name);
	if (!name_copy) {
		status = LTTNG_MAP_STATUS_ERROR;
		goto end;
	}

	free(map->name);

	map->name = name_copy;
	name_copy = NULL;

	status = LTTNG_MAP_STATUS_OK;
end:
	return status;
}

enum lttng_map_status lttng_map_get_name(const struct lttng_map *map,
		const char **name)
{
	enum lttng_map_status status;

	if (!map || !name) {
		status = LTTNG_MAP_STATUS_INVALID;
		goto end;
	}

	if (!map->name) {
		status = LTTNG_MAP_STATUS_UNSET;
	}

	*name = map->name;
	status = LTTNG_MAP_STATUS_OK;
end:
	return status;
}

enum lttng_map_status lttng_map_create(const char *name,
		unsigned int dimension_count,
		uint64_t *dimension_sizes,
		enum lttng_domain_type domain,
		enum lttng_buffer_type buffer_type,
		enum lttng_map_bitness bitness,
		enum lttng_map_boundary_policy boundary_policy,
		struct lttng_map **map_out)
{
	enum lttng_map_status status;
	struct lttng_map *map;

	if (dimension_count != 1) {
		status = LTTNG_MAP_STATUS_INVALID;
		goto end;
	}

	map = zmalloc(sizeof(struct lttng_map));
	if (!map) {
		status = LTTNG_MAP_STATUS_ERROR;
		goto end;
	}

	if (name) {
		status = lttng_map_set_name(map, name);
		if (status != LTTNG_MAP_STATUS_OK) {
			goto free_map;
		}
	} else {
		map->name = NULL;
	}

	map->dimension_count = dimension_count;
	map->dimension_sizes = zmalloc(
			sizeof(*map->dimension_sizes) * dimension_count);
	if (!map->dimension_sizes) {
		status = LTTNG_MAP_STATUS_ERROR;
		goto free_name;
	}

	memcpy(map->dimension_sizes, dimension_sizes,
			sizeof(*map->dimension_sizes) * dimension_count);

	map->domain = domain;
	map->buffer_type = buffer_type;
	map->bitness = bitness;
	map->boundary_policy = boundary_policy;

	urcu_ref_init(&map->ref);

	*map_out = map;

	status = LTTNG_MAP_STATUS_OK;

	goto end;
free_name:
	free(map->name);
free_map:
	free(map);
end:
	return status;
}

unsigned int lttng_map_get_dimension_count(
		const struct lttng_map *map)
{
	return map->dimension_count;
}

enum lttng_map_status lttng_map_get_dimension_length(
		const struct lttng_map *map, unsigned int dimension,
		uint64_t *dimension_length)
{
	enum lttng_map_status status;

	if (dimension >= map->dimension_count) {
		status = LTTNG_MAP_STATUS_INVALID;
		goto end;
	}

	*dimension_length = map->dimension_sizes[dimension];

	status = LTTNG_MAP_STATUS_OK;
end:
	return status;
}

enum lttng_map_bitness lttng_map_get_bitness(
		const struct lttng_map *map)
{
	return map->bitness;
}

enum lttng_domain_type lttng_map_get_domain(
		const struct lttng_map *map)
{
	return map->domain;
}

enum lttng_buffer_type lttng_map_get_buffer_type(
		const struct lttng_map *map)
{
	return map->buffer_type;
}

enum lttng_map_boundary_policy lttng_map_get_boundary_policy(
		const struct lttng_map *map)
{
	return map->boundary_policy;
}

LTTNG_HIDDEN
int lttng_map_serialize(const struct lttng_map *map,
		struct lttng_payload *payload)
{
	int ret;
	size_t header_offset, size_before_payload, size_name;
	struct lttng_map_comm map_comm = {};
	struct lttng_map_comm *header;

	if (map->name != NULL) {
		size_name = strlen(map->name) + 1;
	} else {
		size_name = 0;
	}

	map_comm.name_length = size_name;
	map_comm.is_enabled = LTTNG_OPTIONAL_GET(map->is_enabled);
	map_comm.bitness = map->bitness;
	map_comm.domain = map->domain;
	map_comm.buffer_type = map->buffer_type;
	map_comm.boundary_policy = map->boundary_policy;
	map_comm.dimension_count = map->dimension_count;

	switch (map->buffer_type) {
	case LTTNG_BUFFER_PER_PID:
		map_comm.pid = LTTNG_OPTIONAL_GET(map->pid);
		map_comm.uid = 0;
		break;
	case LTTNG_BUFFER_PER_UID:
		map_comm.uid = LTTNG_OPTIONAL_GET(map->uid);
		map_comm.pid = 0;
		break;
	default:
		abort();
	}

	header_offset = payload->buffer.size;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &map_comm,
			sizeof(map_comm));
	if (ret) {
		goto end;
	}

	size_before_payload = payload->buffer.size;

	/* map name */
	ret = lttng_dynamic_buffer_append(
			&payload->buffer, map->name, size_name);
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, map->dimension_sizes,
			sizeof(*map->dimension_sizes) * map->dimension_count);
	if (ret) {
		goto end;
	}

	/* Update payload size. */
	header = (typeof(header)) (payload->buffer.data + header_offset);
	header->length = payload->buffer.size - size_before_payload;

end:
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_map_create_from_payload(
		struct lttng_payload_view *src_view,
		struct lttng_map **map)
{
	ssize_t ret, offset = 0;
	const struct lttng_map_comm *map_comm;
	enum lttng_map_status status;
	unsigned int dimension_count;
	uint64_t *dimension_sizes = NULL;
	const char *name = NULL;
	enum lttng_domain_type domain;
	enum lttng_buffer_type buffer_type;
	enum lttng_map_bitness bitness;
	enum lttng_map_boundary_policy boundary_policy;

	if (!src_view || !map) {
		ret = -1;
		goto end;
	}

	map_comm = (typeof(map_comm)) src_view->buffer.data;
	offset += sizeof(*map_comm);

	domain = map_comm->domain;
	buffer_type = map_comm->buffer_type;
	bitness = map_comm->bitness;
	boundary_policy = map_comm->boundary_policy;
	dimension_count = map_comm->dimension_count;

	if (map_comm->name_length != 0) {
		struct lttng_payload_view name_view =
				lttng_payload_view_from_view(
						src_view, offset,
						map_comm->name_length);

		name = name_view.buffer.data;
		if (!lttng_buffer_view_contains_string(&name_view.buffer,
					name, map_comm->name_length)){
			ret = -1;
			goto end;
		}
		offset += map_comm->name_length;
	}

	size_t map_dim_sizes_len = sizeof(*(*map)->dimension_sizes) * dimension_count;

	struct lttng_payload_view dimension_sizes_view =
			lttng_payload_view_from_view(src_view, offset,
				map_dim_sizes_len);

	dimension_sizes = zmalloc(map_dim_sizes_len);
	if (!dimension_sizes) {
		ret = -1;
		goto end;
	}

	memcpy(dimension_sizes, dimension_sizes_view.buffer.data,
			map_dim_sizes_len);

	offset += map_dim_sizes_len;

	status = lttng_map_create(name, dimension_count,
			dimension_sizes, domain, buffer_type, bitness,
			boundary_policy, map);
	if (status != LTTNG_MAP_STATUS_OK) {
		ret = -1;
		goto end;
	}

	switch (buffer_type) {
	case LTTNG_BUFFER_PER_PID:
		lttng_map_set_pid(*map, map_comm->pid);
		break;
	case LTTNG_BUFFER_PER_UID:
		lttng_map_set_uid(*map, map_comm->uid);
		break;
	default:
		abort();
	}

	lttng_map_set_is_enabled(*map, map_comm->is_enabled);

	ret = offset;

end:
	free(dimension_sizes);
	return ret;
}

LTTNG_HIDDEN
void lttng_map_set_is_enabled(struct lttng_map *map, bool enabled)
{
	assert(map);

	LTTNG_OPTIONAL_SET(&map->is_enabled, enabled);
}

int lttng_map_get_is_enabled(const struct lttng_map *map)
{
	assert(map);
	return (int) LTTNG_OPTIONAL_GET(map->is_enabled);
}

LTTNG_HIDDEN
void lttng_map_set_pid(struct lttng_map *map, pid_t pid)
{
	assert(map);
	assert(map->buffer_type == LTTNG_BUFFER_PER_PID);

	LTTNG_OPTIONAL_SET(&map->pid, pid);
}

pid_t lttng_map_get_pid(const struct lttng_map *map)
{
	assert(map);

	return LTTNG_OPTIONAL_GET(map->pid);
}

LTTNG_HIDDEN
void lttng_map_set_uid(struct lttng_map *map, uid_t uid)
{
	assert(map);
	assert(map->buffer_type == LTTNG_BUFFER_PER_UID);

	LTTNG_OPTIONAL_SET(&map->uid, uid);
}

uid_t lttng_map_get_uid(const struct lttng_map *map)
{
	assert(map);

	return LTTNG_OPTIONAL_GET(map->uid);
}

LTTNG_HIDDEN
void lttng_map_get(struct lttng_map *map)
{
	urcu_ref_get(&map->ref);
}

static void map_destroy_ref(struct urcu_ref *ref)
{
	struct lttng_map *map = container_of(ref, struct lttng_map, ref);

	free(map->dimension_sizes);
	free(map->name);
	free(map);

}

LTTNG_HIDDEN
void lttng_map_put(struct lttng_map *map)
{
	if (!map) {
		return;
	}

	urcu_ref_put(&map->ref , map_destroy_ref);
}


void lttng_map_destroy(struct lttng_map *map)
{
	lttng_map_put(map);
}

static void delete_map_array_element(void *ptr)
{
	struct lttng_map *map = ptr;

	lttng_map_put(map);
}

LTTNG_HIDDEN
struct lttng_map_list *lttng_map_list_create(void)
{
	struct lttng_map_list *map_list = NULL;

	map_list = zmalloc(sizeof(*map_list));
	if (!map_list) {
		goto end;
	}

	lttng_dynamic_pointer_array_init(&map_list->array,
			delete_map_array_element);

end:
	return map_list;
}

LTTNG_HIDDEN
enum lttng_map_status lttng_map_list_add(struct lttng_map_list *map_list,
		struct lttng_map *map)
{
	enum lttng_map_status status;
	int ret;

	assert(map_list);
	assert(map);

	lttng_map_get(map);

	ret = lttng_dynamic_pointer_array_add_pointer(&map_list->array, map);
	if (ret) {
		lttng_map_put(map);
		status = LTTNG_MAP_STATUS_ERROR;
		goto end;
	}
	status = LTTNG_MAP_STATUS_OK;
end:
	return status;

}

LTTNG_HIDDEN
ssize_t lttng_map_list_create_from_payload(struct lttng_payload_view *src_view,
		struct lttng_map_list **map_list)
{
	unsigned int i;
	ssize_t ret, offset = 0;
	const struct lttng_map_list_comm *map_list_comm;
	struct lttng_map_list *local_map_list = NULL;

	map_list_comm = (typeof(map_list_comm)) src_view->buffer.data;
	offset += sizeof(*map_list_comm);

	local_map_list = lttng_map_list_create();
	if (!local_map_list) {
		ret = -1;
		goto end;
	}

	for (i = 0; i < map_list_comm->count; i++) {
		struct lttng_map *map = NULL;
		struct lttng_payload_view map_view =
				lttng_payload_view_from_view(src_view, offset, -1);
		ssize_t map_size;

		map_size = lttng_map_create_from_payload(&map_view, &map);
		if (map_size < 0) {
			ret = map_size;
			goto end;
		}

		/* Transfer ownership of the map to the collection. */
		ret = lttng_map_list_add(local_map_list, map);
		lttng_map_put(map);
		if (ret < 0) {
			ret = -1;
			goto end;
		}

		offset += map_size;
	}

	/* Pass ownership to caller. */
	*map_list = local_map_list;
	local_map_list = NULL;

	ret = offset;
end:
	lttng_map_list_destroy(local_map_list);
	return ret;
}

LTTNG_HIDDEN
int lttng_map_list_serialize(const struct lttng_map_list *map_list,
		struct lttng_payload *payload)
{
	int ret;
	unsigned int i, count;
	enum lttng_map_status status;
	struct lttng_map_list_comm map_list_comm = {};

	status = lttng_map_list_get_count(map_list, &count);
	if (status != LTTNG_MAP_STATUS_OK) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	map_list_comm.count = count;
	ret = lttng_dynamic_buffer_append(&payload->buffer, &map_list_comm,
			sizeof(map_list_comm));
	if (ret) {
		goto end;
	}
	for (i = 0; i < count; i++) {
		const struct lttng_map *map =
				lttng_map_list_get_at_index(map_list, i);

		assert(map);

		ret = lttng_map_serialize(map, payload);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

const struct lttng_map *lttng_map_list_get_at_index(
		const struct lttng_map_list *map_list, unsigned int index)
{
	struct lttng_map *map = NULL;

	assert(map_list);
	if (index >= lttng_dynamic_pointer_array_get_count(&map_list->array)) {
		goto end;
	}

	map = (struct lttng_map *)
			lttng_dynamic_pointer_array_get_pointer(
					&map_list->array, index);
end:
	return map;
}

enum lttng_map_status lttng_map_list_get_count(
		const struct lttng_map_list *map_list, unsigned int *count)
{
	enum lttng_map_status status = LTTNG_MAP_STATUS_OK;

	if (!map_list || !count) {
		status = LTTNG_MAP_STATUS_INVALID;
		goto end;
	}

	*count = lttng_dynamic_pointer_array_get_count(&map_list->array);
	status = LTTNG_MAP_STATUS_OK;
end:
	return status;
}

void lttng_map_list_destroy(struct lttng_map_list *map_list)
{
	if (!map_list) {
		return;
	}

	lttng_dynamic_pointer_array_reset(&map_list->array);
	free(map_list);
}

struct lttng_map_key_value_pair *lttng_map_key_value_pair_create(const char *key,
		uint64_t value)
{
	struct lttng_map_key_value_pair *key_value;

	key_value = zmalloc(sizeof(struct lttng_map_key_value_pair));
	if (!key_value) {
		goto end;
	}

	key_value->key = strdup(key);
	if (!key_value->key) {
		free(key_value);
		key_value = NULL;
		goto end;
	}
	key_value->value = value;

end:
	return key_value;
}

enum lttng_map_status lttng_map_key_value_pair_get_key(
		const struct lttng_map_key_value_pair *key_value,
		const char **key)
{
	assert(key_value);
	assert(key_value->key);

	*key = key_value->key;
	return LTTNG_MAP_STATUS_OK;
}

enum lttng_map_status lttng_map_key_value_pair_get_value(
		const struct lttng_map_key_value_pair *key_value,
		uint64_t *value)
{
	assert(key_value);
	*value = key_value->value;
	return LTTNG_MAP_STATUS_OK;
}

LTTNG_HIDDEN
ssize_t lttng_map_key_value_pair_create_from_payload(
		struct lttng_payload_view *src_view,
		struct lttng_map_key_value_pair **key_value)
{
	const struct lttng_map_key_value_pair_comm *kv_pair_comm;
	struct lttng_map_key_value_pair *kv_pair;
	ssize_t ret, offset = 0;
	const char *key;
	uint64_t value;

	if (!src_view || !key_value) {
		ret = -1;
		goto end;
	}

	kv_pair_comm = (typeof(kv_pair_comm)) src_view->buffer.data;
	offset += sizeof(*kv_pair_comm);

	if (kv_pair_comm->key_length == 0) {
		ret = -1;
		goto end;
	}

	value = kv_pair_comm->value;

	struct lttng_payload_view key_view =
		lttng_payload_view_from_view(src_view, offset,
			kv_pair_comm->key_length);
	key = key_view.buffer.data;
	if (!lttng_buffer_view_contains_string(&key_view.buffer,
			key, kv_pair_comm->key_length)) {
		ret = -1;
		goto end;
	}

	offset += kv_pair_comm->key_length;

	kv_pair = lttng_map_key_value_pair_create(key, value);
	if (!kv_pair) {
		ret = -1;
		goto end;
	}

	*key_value = kv_pair;

	ret = offset;

end:
	return ret;
}

LTTNG_HIDDEN
int lttng_map_key_value_pair_serialize(
		const struct lttng_map_key_value_pair *key_value,
		struct lttng_payload *payload)
{
	int ret;
	size_t key_len;
	struct lttng_map_key_value_pair_comm kv_pair_comm = {0};

	assert(key_value);
	assert(key_value->key);

	key_len = strlen(key_value->key) + 1;

	kv_pair_comm.key_length = key_len;
	kv_pair_comm.value = key_value->value;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &kv_pair_comm,
			sizeof(kv_pair_comm));
	if (ret) {
		goto end;
	}

	/* Append key.*/
	ret = lttng_dynamic_buffer_append(
			&payload->buffer, key_value->key, key_len);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

void lttng_map_key_value_pair_destroy(struct lttng_map_key_value_pair *key_value)
{
	if (!key_value) {
		return;
	}

	free(key_value->key);
	free(key_value);
}

static void delete_map_key_value_pair_array_element(void *ptr)
{
	struct lttng_map_key_value_pair *key_value = ptr;
	lttng_map_key_value_pair_destroy(key_value);
}

LTTNG_HIDDEN
struct lttng_map_key_value_pair_list *lttng_map_key_value_pair_list_create(void)
{
	struct lttng_map_key_value_pair_list *map_key_values = NULL;

	map_key_values = zmalloc(sizeof(*map_key_values));
	if (!map_key_values) {
		goto end;
	}

	lttng_dynamic_pointer_array_init(&map_key_values->array,
			delete_map_key_value_pair_array_element);

end:
	return map_key_values;
}

LTTNG_HIDDEN
enum lttng_map_status lttng_map_key_value_pair_list_append_key_value(
		struct lttng_map_key_value_pair_list *kv_pair_list,
		struct lttng_map_key_value_pair *key_value)
{
	int ret;
	enum lttng_map_status status;

	assert(kv_pair_list);
	assert(key_value);

	ret = lttng_dynamic_pointer_array_add_pointer(&kv_pair_list->array,
			key_value);
	if (ret) {
		status = LTTNG_MAP_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_MAP_STATUS_OK;

end:
	return status;
}

const struct lttng_map_key_value_pair *lttng_map_key_value_pair_list_get_at_index(
		const struct lttng_map_key_value_pair_list *kv_pair_list,
		unsigned int index)
{
	struct lttng_map_key_value_pair *key_value = NULL;

	assert(kv_pair_list);
	if (index >= lttng_dynamic_pointer_array_get_count(&kv_pair_list->array)) {
		goto end;
	}

	key_value = (struct lttng_map_key_value_pair *)
			lttng_dynamic_pointer_array_get_pointer(
					&kv_pair_list->array, index);
end:
	return key_value;
}

enum lttng_map_status lttng_map_key_value_pair_list_get_count(
		const struct lttng_map_key_value_pair_list *kv_pair_list,
		unsigned int *count)
{
	enum lttng_map_status status;

	if (!kv_pair_list || !count) {
		status = LTTNG_MAP_STATUS_INVALID;;
		goto end;
	}

	*count = lttng_dynamic_pointer_array_get_count(&kv_pair_list->array);

	status = LTTNG_MAP_STATUS_OK;
end:
	return status;
}

void lttng_map_key_value_pair_list_destroy(struct lttng_map_key_value_pair_list *kv_pair_list)
{
	if (!kv_pair_list) {
		return;
	}

	lttng_dynamic_pointer_array_reset(&kv_pair_list->array);
	free(kv_pair_list);
}

int lttng_map_key_value_pair_list_serialize(const struct lttng_map_key_value_pair_list *kv_pair_list,
		struct lttng_payload *payload)
{
	int ret;
	unsigned int i, count;
	enum lttng_map_status status;
	struct lttng_map_key_value_pair_list_comm kv_pair_list_comm = {};

	status = lttng_map_key_value_pair_list_get_count(kv_pair_list, &count);
	if (status != LTTNG_MAP_STATUS_OK) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	kv_pair_list_comm.count = count;
	ret = lttng_dynamic_buffer_append(&payload->buffer, &kv_pair_list_comm,
			sizeof(kv_pair_list_comm));
	if (ret) {
		goto end;
	}
	for (i = 0; i < count; i++) {
		const struct lttng_map_key_value_pair *kv_pair =
				lttng_map_key_value_pair_list_get_at_index(kv_pair_list, i);

		assert(kv_pair);

		ret = lttng_map_key_value_pair_serialize(kv_pair, payload);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_map_key_value_pair_list_create_from_payload(
		struct lttng_payload_view *src_view,
		struct lttng_map_key_value_pair_list **kv_pair_list)
{
	ssize_t ret, offset = 0;
	unsigned int i;
	const struct lttng_map_key_value_pair_list_comm *kv_pair_list_comm;
	struct lttng_map_key_value_pair_list *local_key_values = NULL;

	kv_pair_list_comm = (typeof(kv_pair_list_comm)) src_view->buffer.data;
	offset += sizeof(*kv_pair_list_comm);

	local_key_values = lttng_map_key_value_pair_list_create();
	if (!local_key_values) {
		ret = -1;
		goto end;
	}

	for (i = 0; i < kv_pair_list_comm->count; i++) {
		struct lttng_map_key_value_pair *kv_pair = NULL;
		struct lttng_payload_view kv_view =
				lttng_payload_view_from_view(src_view, offset, -1);
		ssize_t kv_size;

		kv_size = lttng_map_key_value_pair_create_from_payload(
				&kv_view, &kv_pair);
		if (kv_size < 0) {
			ret = kv_size;
			goto end;
		}

		/* Transfer ownership of the key-value to the collection. */
		ret = lttng_map_key_value_pair_list_append_key_value(local_key_values,
				kv_pair);
		if (ret < 0) {
			ret = -1;
			goto end;
		}

		offset += kv_size;
	}

	/* Pass ownership to caller. */
	*kv_pair_list = local_key_values;
	local_key_values = NULL;

	ret = offset;
end:
	lttng_map_key_value_pair_list_destroy(local_key_values);
	return ret;
}
