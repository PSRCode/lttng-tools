/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_INCR_VALUE_H
#define LTTNG_ACTION_INCR_VALUE_H

#include <lttng/action/action.h>
#include <lttng/map-key.h>

struct lttng_action;
struct lttng_map_key;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create a newly allocated incr-value action object.
 *
 * Returns a new action on success, NULL on failure. This action must be
 * destroyed using lttng_action_destroy().
 */
extern struct lttng_action *lttng_action_incr_value_create(void);

/*
 * Set the session name of an lttng_action object of type
 * LTTNG_ACTION_TYPE_INCREMENT_VALUE.
 */
extern enum lttng_action_status lttng_action_incr_value_set_session_name(
		struct lttng_action *action, const char *session_name);

/*
 * Get the session name of an lttng_action object of type
 * LTTNG_ACTION_TYPE_INCREMENT_VALUE.
 */
extern enum lttng_action_status lttng_action_incr_value_get_session_name(
		const struct lttng_action *action, const char **session_name);

/*
 * Set the map name of an lttng_action object of type
 * LTTNG_ACTION_TYPE_INCREMENT_VALUE.
 */
extern enum lttng_action_status lttng_action_incr_value_set_map_name(
		struct lttng_action *action, const char *map_name);

/*
 * Get the map name of an lttng_action object of type
 * LTTNG_ACTION_TYPE_INCREMENT_VALUE.
 */
extern enum lttng_action_status lttng_action_incr_value_get_map_name(
		const struct lttng_action *action, const char **map_name);

/*
 * Set key allocation policy for an lttng_action object type
 * LTTNG_ACTION_TYPE_INCREMENT_VALUE.
 *
 * The caller retains ownership of the passed lttng_map_key.
 */
extern enum lttng_action_status
lttng_action_incr_value_set_key(struct lttng_action *action,
		struct lttng_map_key *key);

/*
 * Get key allocation policy for an lttng_action object type
 * LTTNG_ACTION_TYPE_INCREMENT_VALUE.
 */
extern enum lttng_action_status
lttng_action_incr_value_get_key(const struct lttng_action *action,
		const struct lttng_map_key **key);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_INCR_VALUE_H */
