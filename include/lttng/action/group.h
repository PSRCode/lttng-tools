/*
 * Copyright (C) 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_GROUP_H
#define LTTNG_ACTION_GROUP_H

struct lttng_action;
struct lttng_action_group;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create a newly allocated action group object.
 *
 * Returns a new action group on success, NULL on failure. This action group
 * must be destroyed using lttng_action_group_destroy().
 */
extern struct lttng_action *lttng_action_group_create(void);

/*
 * Add an action to an lttng_action object of type LTTNG_ACTION_GROUP.
 *
 * The group takes ownership of the action.
 */
extern enum lttng_action_status lttng_action_group_add_action(
		struct lttng_action *group, struct lttng_action *action);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_GROUP_H */
