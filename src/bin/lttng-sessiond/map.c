/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/kernel-ctl/kernel-ctl.h>
#include <lttng/map/map.h>
#include <lttng/map/map-internal.h>

#include "trace-kernel.h"
#include "trace-ust.h"

#include "map.h"

int map_kernel_add(struct ltt_kernel_session *ksession,
		struct lttng_map *map)
{
	int ret = 0;
	struct ltt_kernel_map *kernel_map;
	enum lttng_map_status map_status;
	const char *map_name;

	assert(lttng_map_get_domain(map) == LTTNG_DOMAIN_KERNEL);

	map_status = lttng_map_get_name(map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Can't get map name");
		ret = -1;
		goto error;
	}

	kernel_map = trace_kernel_get_map_by_name(map_name, ksession);
	if (kernel_map) {
		DBG("Kernel map named \"%s\" already present", map_name);
		ret = -1;
		goto error;
	}

	kernel_map = trace_kernel_create_map(map);
	assert(kernel_map);

	ret = kernctl_create_session_counter(ksession->fd,
			&kernel_map->counter_conf);
	if (ret < 0) {
		PERROR("ioctl kernel create session counter");
		goto error;
	}

	kernel_map->fd = ret;

	/* Prevent fd duplication after execlp() */
	ret = fcntl(kernel_map->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session counter fd");
		goto error;
	}

	kernel_map->map = map;
	cds_list_add(&kernel_map->list, &ksession->map_list.head);
	ksession->map_count++;

	DBG("Kernel session counter created (fd: %d)", kernel_map->fd);

	ret = kernctl_enable(kernel_map->fd);
	if (ret < 0) {
		PERROR("Enable kernel map");
	}

error:
	return ret;
}

int map_kernel_remove(struct ltt_kernel_session *ksession, const char *map_name)
{
	int ret = 0;
	struct ltt_kernel_map *kernel_map = NULL;

	kernel_map = trace_kernel_get_map_by_name(map_name, ksession);
	if (!kernel_map) {
		ERR("Can't find kernel map by name");
		ret = -1;
		goto end;
	}

	cds_list_del(&kernel_map->list);
	ksession->map_count--;

	trace_kernel_destroy_map(kernel_map);

end:
	return ret;
}

int map_ust_add(struct ltt_ust_session *usession, struct lttng_map *map)
{
	int ret = 0;
	struct ltt_ust_map *umap;
	enum lttng_map_status map_status;
	const char *map_name;
	enum lttng_buffer_type buffer_type;

	assert(lttng_map_get_domain(map) == LTTNG_DOMAIN_UST);

	map_status = lttng_map_get_name(map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Can't get map name");
		ret = -1;
		goto error;
	}

	buffer_type = lttng_map_get_buffer_type(map);

	umap = trace_ust_create_map(map);
	assert(umap);

	umap->enabled = 1;
	umap->id = trace_ust_get_next_chan_id(usession);
	umap->map = map;
	lttng_map_get(map);

	DBG2("Map %s is being created for UST with buffer type %d and id %" PRIu64,
			umap->name, buffer_type, umap->id);

	rcu_read_lock();

	/* Adding the map to the map hash table. */
	lttng_ht_add_unique_str(usession->domain_global.maps, &umap->node);

	rcu_read_unlock();

	DBG2("Map %s created successfully", umap->name);
error:
	return ret;
}

int map_ust_remove(struct ltt_ust_session *usession, const char *map_name)
{
	struct ltt_ust_map *umap;
	struct lttng_ht_iter iter;

	rcu_read_lock();
	umap = trace_ust_find_map_by_name(usession->domain_global.maps, map_name);
	if (umap) {
		iter.iter.node = &umap->node.node;
		lttng_ht_del(usession->domain_global.maps, &iter);

		trace_ust_destroy_map(umap);
	}

	rcu_read_unlock();
	return 0;
}
