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

int map_kernel_add(struct ltt_kernel_session *ksession,
		struct lttng_map *map);

#endif /* _LTT_MAP_H */
