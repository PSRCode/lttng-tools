/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/action/action-internal.h>
#include <lttng/action/notify-internal.h>
#include <common/macros.h>
#include <assert.h>

static
void lttng_action_notify_destroy(struct lttng_action *action)
{
	free(action);
}

static
int lttng_action_notify_serialize(struct lttng_action *action,
		struct lttng_payload *payload)
{
	return 0;
}

static
bool lttng_action_notify_is_equal(const struct lttng_action *a,
		const struct lttng_action *b)
{
	/* There is no discriminant between notify actions. */
	return true;
}

struct lttng_action *lttng_action_notify_create(void)
{
	struct lttng_action_notify *notify;

	notify = zmalloc(sizeof(struct lttng_action_notify));
	if (!notify) {
		goto end;
	}

	lttng_action_init(&notify->parent, LTTNG_ACTION_TYPE_NOTIFY, NULL,
			lttng_action_notify_serialize,
			lttng_action_notify_is_equal,
			lttng_action_notify_destroy);
end:
	return &notify->parent;
}

ssize_t lttng_action_notify_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_action **action)
{
	ssize_t consumed_length;

	*action = lttng_action_notify_create();
	if (!*action) {
		consumed_length = -1;
		goto end;
	}

	consumed_length = 0;
end:
	return consumed_length;
}
