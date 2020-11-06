/*
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_LOG_LEVEL_RULE_H
#define LTTNG_LOG_LEVEL_RULE_H

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_log_level_rule;

enum lttng_log_level_rule_type {
	LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN = -1,
	LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY = 0,
	LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS = 1,
};

enum lttng_log_level_rule_status {
	LTTNG_LOG_LEVEL_RULE_STATUS_OK = 0,
	LTTNG_LOG_LEVEL_RULE_STATUS_ERROR = -1,
	LTTNG_LOG_LEVEL_RULE_STATUS_INVALID = -3,
};

/*
 * Get the type of a log level rule.
 *
 * Returns the type of a log level rule on success,
 * LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN on error.
 */
extern enum lttng_log_level_rule_type lttng_log_level_rule_get_type(
		const struct lttng_log_level_rule *rule);

/*
 * Create a newly allocated log level rule where a log level must match exactly
 * the rule to be considered.
 *
 * Returns a new log level rule on success, NULL on failure. This log level rule must be
 * destroyed using lttng_log_level_rule_destroy().
 */
extern struct lttng_log_level_rule *lttng_log_level_rule_exactly_create(
		int level);

/*
 * Get the level property of a log level exactly rule.
 *
 * Returns LTTNG_LOG_LEVEL_RULE_STATUS and set the passed level pointer value
 * on success, LTTNG_LOG_LEVEL_RULE_STATUS if an invalid
 * parameter is passed.
 */
extern enum lttng_log_level_rule_status lttng_log_level_rule_exactly_get_level(
		const struct lttng_log_level_rule *rule, int *level);

/*
 * Create a newly allocated log level rule where a log level must be at least as
 * severe as the rule to be considered.
 *
 * Returns a new log level rule on success, NULL on failure. This log level rule
 * must be destroyed using lttng_log_level_rule_destroy().
 */
extern struct lttng_log_level_rule *
lttng_log_level_rule_at_least_as_severe_as_create(int level);

/*
 * Get the level property of a log level at least as severe rule.
 *
 * Returns LTTNG_LOG_LEVEL_RULE_STATUS and set the passed level pointer value
 * on success, LTTNG_LOG_LEVEL_RULE_STATUS if an invalid
 * parameter is passed.
 */
extern enum lttng_log_level_rule_status
lttng_log_level_rule_at_least_as_severe_as_get_level(
		const struct lttng_log_level_rule *rule, int *level);

/*
 * Destroy (release) a log level rule object.
 */
extern void lttng_log_level_rule_destroy(struct lttng_log_level_rule *log_level_rule);


#ifdef __cplusplus
}
#endif

#endif /* LTTNG_LOG_LEVEL_RULE_H */
