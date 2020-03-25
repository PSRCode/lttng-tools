/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_TRACKER_H
#define LTTNG_TRACKER_H

#include <lttng/constant.h>
#include <lttng/session.h>

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_tracker_type {
	LTTNG_TRACKER_PID = 0,
	LTTNG_TRACKER_VPID = 1,
	LTTNG_TRACKER_UID = 2,
	LTTNG_TRACKER_GID = 3,
	LTTNG_TRACKER_VUID = 4,
	LTTNG_TRACKER_VGID = 5,
};

enum lttng_tracker_id_type {
	LTTNG_ID_UNKNOWN = -1,
	LTTNG_ID_ALL = 0,
	LTTNG_ID_VALUE = 1,
	LTTNG_ID_STRING = 2,
};

enum lttng_tracker_id_status {
	/* Invalid tracker id parameter. */
	LTTNG_TRACKER_ID_STATUS_INVALID = -1,
	LTTNG_TRACKER_ID_STATUS_OK = 0,
	/* Tracker id parameter is unset. */
	LTTNG_TRACKER_ID_STATUS_UNSET = 1,
};

/*
 * A tracker id.
 */
struct lttng_tracker_id;

/*
 * A collection of tracker id.
 */
struct lttng_tracker_ids;

/*
 * Create a tracker id for the passed tracker type.
 * Users must set the tracker id using the matching API call.
 *
 * On success, the caller is responsible for calling lttng_tracker_id_destroy.
 * On error, return NULL.
 */
extern struct lttng_tracker_id *lttng_tracker_id_create(void);

/*
 * Configure the tracker id using the numerical representation of the resource
 * to be tracked/untracked.
 *
 * If the tracker id was already configured, calling this function will replace
 * the previous configuration and free memory as necessary.
 *
 * Returns LTTNG_TRACKER_ID_STATUS_OK on success,
 * LTTNG_TRACKER_ID_STATUS_INVALID is the passed parameter is invalid.
 */
extern enum lttng_tracker_id_status lttng_tracker_id_set_value(
		struct lttng_tracker_id *id, int value);

/*
 * Configure the tracker id using the string representation of the resource to
 * be tracked/untracked.
 *
 * If the tracker id was already configured, calling this function will replace
 * the previous configuration and free memory as necessary.
 *
 * Returns LTTNG_TRACKER_ID_STATUS_OK on success,
 * LTTNG_TRACKER_ID_STATUS_INVALID if the passed parameter is invalid.
 */
extern enum lttng_tracker_id_status lttng_tracker_id_set_string(
		struct lttng_tracker_id *id, const char *value);

/*
 * Configure the tracker id to track/untrack all resources for the tracker type.
 *
 * If the tracker id was already configured, calling this function will replace
 * the previous configuration and free memory as necessary.
 *
 * Returns LTTNG_TRACKER_ID_STATUS_OK on success,
 * LTTNG_TRACKER_ID_STATUS_INVALID if the passed parameter is invalid.
 */
extern enum lttng_tracker_id_status lttng_tracker_id_set_all(
		struct lttng_tracker_id *id);

/*
 * Destroy a tracker id.
 */
extern void lttng_tracker_id_destroy(struct lttng_tracker_id *id);

/*
 * Get the type of a tracker id.
 */
extern enum lttng_tracker_id_type lttng_tracker_id_get_type(
		const struct lttng_tracker_id *id);

/*
 * Get the value of a tracker id.
 *
 * Returns LTTNG_TRACKER_ID_OK on success,
 * LTTNG_TRACKER_ID_STATUS_INVALID when the tracker is not of type
 * LTTNG_ID_VALUE,
 * LTTNG_TRACKER_ID_STATUS_UNSET when the tracker is not set.
 */
extern enum lttng_tracker_id_status lttng_tracker_id_get_value(
		const struct lttng_tracker_id *id, int *value);

/*
 * Get the string representation of the tracker id.
 *
 * Returns LTTNG_TRACKER_ID_OK on success,
 * LTTNG_TRACKER_ID_STATUS_INVALID when the tracker is not of type
 * LTTNG_ID_STRING,
 * LTTNG_TRACKER_ID_STATUS_UNSET when the tracker is not set.
 */
extern enum lttng_tracker_id_status lttng_tracker_id_get_string(
		const struct lttng_tracker_id *id, const char **value);

/*
 * Add ID to session tracker.
 *
 * tracker_type is the type of tracker.
 * id is the lttng_tracker_type to track.
 *
 * Returns 0 on success else a negative LTTng error code.
 */
extern int lttng_track_id(struct lttng_handle *handle,
		enum lttng_tracker_type tracker_type,
		const struct lttng_tracker_id *id);

/*
 * Remove ID from session tracker.
 *
 * tracker_type is the type of tracker.
 * id is the lttng_tracker_type to untrack.
 * Returns 0 on success else a negative LTTng error code.
 */
extern int lttng_untrack_id(struct lttng_handle *handle,
		enum lttng_tracker_type tracker_type,
		const struct lttng_tracker_id *id);

/*
 * List IDs of a tracker.
 *
 * On success, ids is allocated.
 * The ids collection must be freed by the caller with lttng_destroy_ids().
 *
 * Returns 0 on success, else a negative LTTng error code.
 */
extern int lttng_list_tracker_ids(struct lttng_handle *handle,
		enum lttng_tracker_type tracker_type,
		struct lttng_tracker_ids **ids);

/*
 * Backward compatibility.
 * Add PID to session tracker.
 *
 * A pid argument >= 0 adds the PID to the session tracker.
 * A pid argument of -1 means "track all PIDs".
 *
 * Returns 0 on success else a negative LTTng error code.
 */
extern int lttng_track_pid(struct lttng_handle *handle, int pid);

/*
 * Backward compatibility.
 * Remove PID from session tracker.
 *
 * A pid argument >= 0 removes the PID from the session tracker.
 * A pid argument of -1 means "untrack all PIDs".
 *
 * Returns 0 on success else a negative LTTng error code.
 */
extern int lttng_untrack_pid(struct lttng_handle *handle, int pid);

/*
 * Backward compatibility
 * List PIDs in the tracker.
 *
 * enabled is set to whether the PID tracker is enabled.
 * pids is set to an allocated array of PIDs currently tracked. On
 * success, pids must be freed by the caller.
 * nr_pids is set to the number of entries contained by the pids array.
 *
 * Returns 0 on success, else a negative LTTng error code.
 */
extern int lttng_list_tracker_pids(struct lttng_handle *handle,
		int *enabled,
		int32_t **pids,
		size_t *nr_pids);

/*
 * Get a tracker id from the list at a given index.
 *
 * Note that the list maintains the ownership of the returned tracker id.
 * It must not be destroyed by the user, nor should it be held beyond the
 * lifetime of the tracker id list.
 *
 * Returns a tracker id, or NULL on error.
 */
extern const struct lttng_tracker_id *lttng_tracker_ids_get_at_index(
		const struct lttng_tracker_ids *ids, unsigned int index);

/*
 * Get the number of tracker id in a tracker id list.
 *
 * Return LTTNG_TRACKER_ID_STATUS on sucess,
 * LTTNG_TRACKER_ID_STATUS_INVALID when passed invalid parameters.
 */
extern enum lttng_tracker_id_status lttng_tracker_ids_get_count(
		const struct lttng_tracker_ids *ids, unsigned int *count);

/*
 * Destroy a tracker id list.
 */
extern void lttng_tracker_ids_destroy(struct lttng_tracker_ids *ids);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_TRACKER_H */
