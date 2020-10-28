/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */


#include "lttng/domain.h"
#include <common/kernel-ctl/kernel-ctl.h>
#include <lttng/map/map.h>
#include <lttng/map/map-internal.h>

#include "lttng-sessiond.h"
#include "lttng-ust-error.h"
#include "notification-thread-commands.h"
#include "trace-kernel.h"
#include "trace-ust.h"

#include "map.h"

int map_kernel_add(struct ltt_kernel_session *ksession,
		struct lttng_map *map)
{
	int ret = 0;
	struct ltt_kernel_map *kmap;
	enum lttng_map_status map_status;
	const char *map_name;

	assert(lttng_map_get_domain(map) == LTTNG_DOMAIN_KERNEL);

	map_status = lttng_map_get_name(map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Can't get map name");
		ret = -1;
		goto error;
	}

	kmap = trace_kernel_get_map_by_name(map_name, ksession);
	if (kmap) {
		DBG("Kernel map named \"%s\" already present", map_name);
		ret = -1;
		goto error;
	}

	kmap = trace_kernel_create_map(map);
	assert(kmap);

	ret = kernctl_create_session_counter(ksession->fd,
			&kmap->counter_conf);
	if (ret < 0) {
		PERROR("ioctl kernel create session counter");
		goto error;
	}

	kmap->fd = ret;

	/* Prevent fd duplication after execlp() */
	ret = fcntl(kmap->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session counter fd");
		goto error;
	}

	kmap->map = map;
	cds_list_add(&kmap->list, &ksession->map_list.head);
	ksession->map_count++;

	DBG("Kernel session counter created (fd: %d)", kmap->fd);

	ret = kernctl_enable(kmap->fd);
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

	lttng_map_set_is_enabled(umap->map, true);

	//FIXME: frdeso: dummy uid and pid values
	switch (lttng_map_get_buffer_type(umap->map)) {
	case LTTNG_BUFFER_PER_UID:
		lttng_map_set_uid(umap->map, 123456789);
		break;
	case LTTNG_BUFFER_PER_PID:
		lttng_map_set_pid(umap->map, 987654321);
		break;
	default:
		abort();
	}

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

/*
 * Enable UST map for session and domain.
 */
int map_ust_enable(struct ltt_ust_session *usess,
		struct ltt_ust_map *umap)
{
	int ret = LTTNG_OK;

	assert(usess);
	assert(umap);

	/* If already enabled, everything is OK */
	if (umap->enabled) {
		DBG3("Map %s already enabled. Skipping", umap->name);
		ret = LTTNG_ERR_UST_MAP_EXIST;
		goto end;
	} else {
		umap->enabled = 1;
		lttng_map_set_is_enabled(umap->map, true);
		DBG2("Map %s enabled successfully", umap->name);
	}

	if (!usess->active) {
		/*
		 * The map will be activated against the apps
		 * when the session is started as part of the
		 * application map "synchronize" operation.
		 */
		goto end;
	}

	DBG2("Map %s being enabled in UST domain", umap->name);

	/*
	 * Enable map for UST global domain on all applications. Ignore return
	 * value here since whatever error we got, it means that the map was
	 * not created on one or many registered applications and we can not report
	 * this to the user yet. However, at this stage, the map was
	 * successfully created on the session daemon side so the enable-map
	 * command is a success.
	 */
	(void) ust_app_enable_map_glb(usess, umap);


end:
	return ret;
}

int map_ust_disable(struct ltt_ust_session *usess,
		struct ltt_ust_map *umap)
{
	int ret = LTTNG_OK;

	assert(usess);
	assert(umap);

	/* Already disabled */
	if (umap->enabled == 0) {
		DBG2("Map UST %s already disabled", umap->name);
		ret = LTTNG_ERR_UST_MAP_EXIST;
		goto end;
	}

	umap->enabled = 0;
	lttng_map_set_is_enabled(umap->map, false);

	/*
	 * If session is inactive we don't notify the tracer right away. We
	 * wait for the next synchronization.
	 */
	if (!usess->active) {
		goto end;
	}

	DBG2("Map %s being disabled in UST global domain", umap->name);

	/* Disable map for global domain */
	ret = ust_app_disable_map_glb(usess, umap);
	if (ret < 0 && ret != -LTTNG_UST_ERR_EXIST) {
		ret = LTTNG_ERR_UST_MAP_DISABLE_FAIL;
		goto error;
	}


	DBG2("Map %s disabled successfully", umap->name);

	return LTTNG_OK;

end:
error:
	return ret;
}

int map_ust_remove(struct ltt_ust_session *usession, const char *map_name)
{
	struct ltt_ust_map *umap;
	struct lttng_ht_iter iter;

	assert(usession);

	rcu_read_lock();
	umap = trace_ust_find_map_by_name(usession->domain_global.maps, map_name);


	rcu_read_unlock();
	return 0;
}
