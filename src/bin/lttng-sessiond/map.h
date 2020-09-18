/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */
#ifndef _LTT_MAP_H
#define _LTT_MAP_H

#include <lttng/map/map.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include "trace-kernel.h"
#include "trace-ust.h"

int map_kernel_add(struct ltt_kernel_session *ksession,
		struct lttng_map *map);
int map_kernel_remove(struct ltt_kernel_session *ksession,
		const char *map_name);

int map_ust_add(struct ltt_ust_session *usession,
		struct lttng_map *map);
int map_ust_remove(struct ltt_ust_session *usession,
		const char *map_name);

#endif /* _LTT_MAP_H */
