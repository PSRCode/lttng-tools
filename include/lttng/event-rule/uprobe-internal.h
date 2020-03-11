/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_UPROBE_INTERNAL_H
#define LTTNG_EVENT_RULE_UPROBE_INTERNAL_H

#include <common/buffer-view.h>
#include <common/macros.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/uprobe.h>

struct lttng_event_rule_uprobe {
	struct lttng_event_rule parent;
	char *name;
	struct lttng_userspace_probe_location *location;
};

struct lttng_event_rule_uprobe_comm {
	uint32_t name_len;
	uint32_t location_len;
	/*name, location object */
	char payload[];
} LTTNG_PACKED;

LTTNG_HIDDEN
ssize_t lttng_event_rule_uprobe_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_event_rule **rule);

LTTNG_HIDDEN
struct lttng_userspace_probe_location *
lttng_event_rule_uprobe_get_location_no_const(
		const struct lttng_event_rule *rule);

#endif /* LTTNG_EVENT_RULE_UPROBE_INTERNAL_H */
