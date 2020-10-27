/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_INCR_VALUE_INTERNAL_H
#define LTTNG_ACTION_INCR_VALUE_INTERNAL_H

#include <common/macros.h>

struct lttng_action;
struct lttng_payload_view;

/*
 * Create a "incr-value" action from a payload view.
 *
 * On success, return the number of bytes consumed from `view`, and the created
 * action in `*action`. On failure, return -1.
 */
LTTNG_HIDDEN
extern ssize_t lttng_action_incr_value_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_action **action);

#endif /* LTTNG_ACTION_INCR_VALUE_INTERNAL_H */
