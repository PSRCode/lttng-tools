/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_SYSCALL_INTERNAL_H
#define LTTNG_EVENT_RULE_SYSCALL_INTERNAL_H

#include <common/buffer-view.h>
#include <common/macros.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/syscall.h>

struct lttng_event_rule_syscall {
	struct lttng_event_rule parent;
	char *pattern;
	char *filter_expression;

	/* internal use only */
	struct {
		char *filter;
		struct lttng_bytecode *bytecode;
	} internal_filter;
};

struct lttng_event_rule_syscall_comm {
	uint32_t pattern_len;
	uint32_t filter_expression_len;
	/* pattern, filter expression */
	char payload[];
} LTTNG_PACKED;

LTTNG_HIDDEN
ssize_t lttng_event_rule_syscall_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_event_rule **rule);

#endif /* LTTNG_EVENT_RULE_SYSCALL_INTERNAL_H */
