/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_KPROBE_INTERNAL_H
#define LTTNG_EVENT_RULE_KPROBE_INTERNAL_H

#include <common/buffer-view.h>
#include <common/macros.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/kprobe.h>

struct lttng_event_rule_kprobe {
	struct lttng_event_rule parent;
	char *name;
	struct {
		uint64_t address;
		uint64_t offset;
		char *symbol_name;
		bool set;
	} probe;
};

struct lttng_event_rule_kprobe_comm {
	uint32_t name_len;
	uint32_t probe_symbol_name_len;
	uint64_t probe_address;
	uint64_t probe_offset;
	/* name, source symbol_name */
	char payload[];
} LTTNG_PACKED;

LTTNG_HIDDEN
ssize_t lttng_event_rule_kprobe_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_event_rule **rule);

LTTNG_HIDDEN
uint64_t lttng_event_rule_kprobe_get_address(
		const struct lttng_event_rule *rule);

LTTNG_HIDDEN
uint64_t lttng_event_rule_kprobe_get_offset(
		const struct lttng_event_rule *rule);

LTTNG_HIDDEN
const char *lttng_event_rule_kprobe_get_symbol_name(
		const struct lttng_event_rule *rule);

#endif /* LTTNG_EVENT_RULE_KPROBE_INTERNAL_H */
