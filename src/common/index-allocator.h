/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _COMMON_INDEX_ALLOCATOR_H
#define _COMMON_INDEX_ALLOCATOR_H

#include <inttypes.h>

struct lttng_index_allocator;

enum lttng_index_allocator_status {
	LTTNG_INDEX_ALLOCATOR_STATUS_OK,
	LTTNG_INDEX_ALLOCATOR_STATUS_EMPTY,
	LTTNG_INDEX_ALLOCATOR_STATUS_ERROR,
};

struct lttng_index_allocator *lttng_index_allocator_create(
		uint64_t index_count);

uint64_t lttng_index_allocator_get_index_count(
	struct lttng_index_allocator *allocator);

enum lttng_index_allocator_status lttng_index_allocator_alloc(
		struct lttng_index_allocator *allocator,
		uint64_t *index);

enum lttng_index_allocator_status lttng_index_allocator_release(
		struct lttng_index_allocator *allocator, uint64_t index);

void lttng_index_allocator_destroy(struct lttng_index_allocator *allocator);

#endif /* _COMMON_INDEX_ALLOCATOR_H */
