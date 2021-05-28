/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/mi-lttng.h>
#include <lttng/condition/condition-internal.h>
#include <lttng/condition/session-rotation-internal.h>
#include <lttng/location-internal.h>
#include <stdbool.h>

static
bool lttng_condition_session_rotation_validate(
		const struct lttng_condition *condition);
static
int lttng_condition_session_rotation_serialize(
		const struct lttng_condition *condition,
		struct lttng_payload *payload);
static
bool lttng_condition_session_rotation_is_equal(const struct lttng_condition *_a,
		const struct lttng_condition *_b);
static
void lttng_condition_session_rotation_destroy(
		struct lttng_condition *condition);

static enum lttng_error_code lttng_condition_session_rotation_mi(
		const struct lttng_condition *condition,
		struct mi_writer *writer);

static const
struct lttng_condition rotation_condition_template = {
	/* .type omitted; shall be set on creation. */
	.validate = lttng_condition_session_rotation_validate,
	.serialize = lttng_condition_session_rotation_serialize,
	.equal = lttng_condition_session_rotation_is_equal,
	.destroy = lttng_condition_session_rotation_destroy,
	.mi = lttng_condition_session_rotation_mi,
};

static
int lttng_evaluation_session_rotation_serialize(
		const struct lttng_evaluation *evaluation,
		struct lttng_payload *payload);
static
void lttng_evaluation_session_rotation_destroy(
		struct lttng_evaluation *evaluation);

static const
struct lttng_evaluation rotation_evaluation_template = {
	/* .type omitted; shall be set on creation. */
	.serialize = lttng_evaluation_session_rotation_serialize,
	.destroy = lttng_evaluation_session_rotation_destroy,
};

static
bool is_rotation_condition(const struct lttng_condition *condition)
{
	enum lttng_condition_type type = lttng_condition_get_type(condition);

	return type == LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING ||
			type == LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED;
}

static
bool is_rotation_evaluation(const struct lttng_evaluation *evaluation)
{
	enum lttng_condition_type type = lttng_evaluation_get_type(evaluation);

	return type == LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING ||
			type == LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED;
}

static
bool lttng_condition_session_rotation_validate(
		const struct lttng_condition *condition)
{
	bool valid = false;
	struct lttng_condition_session_rotation *rotation;

	if (!condition) {
		goto end;
	}

	rotation = container_of(condition,
			struct lttng_condition_session_rotation, parent);
	if (!rotation->session_name) {
		ERR("Invalid session rotation condition: a target session name must be set.");
		goto end;
	}

	valid = true;
end:
	return valid;
}

static
int lttng_condition_session_rotation_serialize(
		const struct lttng_condition *condition,
		struct lttng_payload *payload)
{
	int ret;
	size_t session_name_len;
	struct lttng_condition_session_rotation *rotation;
	struct lttng_condition_session_rotation_comm rotation_comm;

	if (!condition || !is_rotation_condition(condition)) {
		ret = -1;
		goto end;
	}

	DBG("Serializing session rotation condition");
	rotation = container_of(condition, struct lttng_condition_session_rotation,
			parent);

	session_name_len = strlen(rotation->session_name) + 1;
	if (session_name_len > LTTNG_NAME_MAX) {
		ret = -1;
		goto end;
	}

	rotation_comm.session_name_len = session_name_len;
	ret = lttng_dynamic_buffer_append(&payload->buffer, &rotation_comm,
			sizeof(rotation_comm));
	if (ret) {
		goto end;
	}
	ret = lttng_dynamic_buffer_append(&payload->buffer,
			rotation->session_name, session_name_len);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

static
bool lttng_condition_session_rotation_is_equal(const struct lttng_condition *_a,
		const struct lttng_condition *_b)
{
	bool is_equal = false;
	struct lttng_condition_session_rotation *a, *b;

	a = container_of(_a, struct lttng_condition_session_rotation, parent);
	b = container_of(_b, struct lttng_condition_session_rotation, parent);

	/* Both session names must be set or both must be unset. */
	if ((a->session_name && !b->session_name) ||
			(!a->session_name && b->session_name)) {
		WARN("Comparing session rotation conditions with uninitialized session names.");
		goto end;
	}

	if (a->session_name && b->session_name &&
			strcmp(a->session_name, b->session_name)) {
		goto end;
	}

	is_equal = true;
end:
	return is_equal;
}

static
void lttng_condition_session_rotation_destroy(
		struct lttng_condition *condition)
{
	struct lttng_condition_session_rotation *rotation;

	rotation = container_of(condition,
			struct lttng_condition_session_rotation, parent);

	free(rotation->session_name);
	free(rotation);
}

static
struct lttng_condition *lttng_condition_session_rotation_create(
		enum lttng_condition_type type)
{
	struct lttng_condition_session_rotation *condition;

	condition = zmalloc(sizeof(struct lttng_condition_session_rotation));
	if (!condition) {
		return NULL;
	}

	memcpy(&condition->parent, &rotation_condition_template,
			sizeof(condition->parent));
	lttng_condition_init(&condition->parent, type);
	return &condition->parent;
}

struct lttng_condition *lttng_condition_session_rotation_ongoing_create(void)
{
	return lttng_condition_session_rotation_create(
			LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING);
}

struct lttng_condition *lttng_condition_session_rotation_completed_create(void)
{
	return lttng_condition_session_rotation_create(
			LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED);
}

static
ssize_t init_condition_from_payload(struct lttng_condition *condition,
		struct lttng_payload_view *src_view)
{
	ssize_t ret, condition_size;
	enum lttng_condition_status status;
	const char *session_name;
	struct lttng_buffer_view name_view;
	const struct lttng_condition_session_rotation_comm *condition_comm;
	struct lttng_payload_view condition_comm_view =
			lttng_payload_view_from_view(
					src_view, 0, sizeof(*condition_comm));

	if (!lttng_payload_view_is_valid(&condition_comm_view)) {
		ERR("Failed to initialize from malformed condition buffer: buffer too short to contain header");
		ret = -1;
		goto end;
	}

	condition_comm = (typeof(condition_comm)) src_view->buffer.data;
	name_view = lttng_buffer_view_from_view(&src_view->buffer,
						sizeof(*condition_comm), condition_comm->session_name_len);

	if (!lttng_buffer_view_is_valid(&name_view)) {
		ERR("Failed to initialize from malformed condition buffer: buffer too short to contain session name");
		ret = -1;
		goto end;
	}

	if (condition_comm->session_name_len > LTTNG_NAME_MAX) {
		ERR("Failed to initialize from malformed condition buffer: name exceeds LTTNG_MAX_NAME");
		ret = -1;
		goto end;
	}

	session_name = name_view.data;
	if (*(session_name + condition_comm->session_name_len - 1) != '\0') {
		ERR("Malformed session name encountered in condition buffer");
		ret = -1;
		goto end;
	}

	status = lttng_condition_session_rotation_set_session_name(condition,
			session_name);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to set buffer consumed session name");
		ret = -1;
		goto end;
	}

	if (!lttng_condition_validate(condition)) {
		ret = -1;
		goto end;
	}

	condition_size = sizeof(*condition_comm) +
			(ssize_t) condition_comm->session_name_len;
	ret = condition_size;
end:
	return ret;
}

static
ssize_t lttng_condition_session_rotation_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_condition **_condition,
		enum lttng_condition_type type)
{
	ssize_t ret;
	struct lttng_condition *condition = NULL;

	switch (type) {
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
		condition = lttng_condition_session_rotation_ongoing_create();
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		condition = lttng_condition_session_rotation_completed_create();
		break;
	default:
		ret = -1;
		goto error;
	}

	if (!_condition || !condition) {
		ret = -1;
		goto error;
	}

	ret = init_condition_from_payload(condition, view);
	if (ret < 0) {
		goto error;
	}

	*_condition = condition;
	return ret;
error:
	lttng_condition_destroy(condition);
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_condition_session_rotation_ongoing_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_condition **condition)
{
	return lttng_condition_session_rotation_create_from_payload(view,
			condition,
			LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING);
}

LTTNG_HIDDEN
ssize_t lttng_condition_session_rotation_completed_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_condition **condition)
{
	return lttng_condition_session_rotation_create_from_payload(view,
			condition,
			LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED);
}

static
struct lttng_evaluation *lttng_evaluation_session_rotation_create(
		enum lttng_condition_type type, uint64_t id,
		struct lttng_trace_archive_location *location)
{
	struct lttng_evaluation_session_rotation *evaluation;

	evaluation = zmalloc(sizeof(struct lttng_evaluation_session_rotation));
	if (!evaluation) {
		return NULL;
	}

	memcpy(&evaluation->parent, &rotation_evaluation_template,
			sizeof(evaluation->parent));
	lttng_evaluation_init(&evaluation->parent, type);
	evaluation->id = id;
	evaluation->location = location;
	return &evaluation->parent;
}

static
ssize_t create_evaluation_from_payload(
		enum lttng_condition_type type,
		struct lttng_payload_view *view,
		struct lttng_evaluation **_evaluation)
{
	ssize_t ret, size;
	struct lttng_evaluation *evaluation = NULL;
	struct lttng_trace_archive_location *location = NULL;
	const struct lttng_evaluation_session_rotation_comm *comm;
	struct lttng_payload_view comm_view = lttng_payload_view_from_view(
			view, 0, sizeof(*comm));

	if (!lttng_payload_view_is_valid(&comm_view)) {
		goto error;
	}

	comm = (typeof(comm)) comm_view.buffer.data;
	size = sizeof(*comm);
	if (comm->has_location) {
		const struct lttng_buffer_view location_view =
				lttng_buffer_view_from_view(
						&view->buffer, sizeof(*comm), -1);

		if (!lttng_buffer_view_is_valid(&location_view)) {
			goto error;
		}

		ret = lttng_trace_archive_location_create_from_buffer(
				&location_view, &location);
		if (ret < 0) {
			goto error;
		}
		size += ret;
	}

	evaluation = lttng_evaluation_session_rotation_create(type, comm->id,
			location);
	if (!evaluation) {
		goto error;
	}

	ret = size;
	*_evaluation = evaluation;
	return ret;
error:
	lttng_trace_archive_location_destroy(location);
	evaluation = NULL;
	return -1;
}

static
ssize_t lttng_evaluation_session_rotation_create_from_payload(
		enum lttng_condition_type type,
		struct lttng_payload_view *view,
		struct lttng_evaluation **_evaluation)
{
	ssize_t ret;
	struct lttng_evaluation *evaluation = NULL;

	if (!_evaluation) {
		ret = -1;
		goto error;
	}

	ret = create_evaluation_from_payload(type, view, &evaluation);
	if (ret < 0) {
		goto error;
	}

	*_evaluation = evaluation;
	return ret;
error:
	lttng_evaluation_destroy(evaluation);
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_evaluation_session_rotation_ongoing_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_evaluation **evaluation)
{
	return lttng_evaluation_session_rotation_create_from_payload(
			LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING,
			view, evaluation);
}

LTTNG_HIDDEN
ssize_t lttng_evaluation_session_rotation_completed_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_evaluation **evaluation)
{
	return lttng_evaluation_session_rotation_create_from_payload(
			LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED,
			view, evaluation);
}

LTTNG_HIDDEN
struct lttng_evaluation *lttng_evaluation_session_rotation_ongoing_create(
		uint64_t id)
{
	return lttng_evaluation_session_rotation_create(
			LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING, id,
			NULL);
}

LTTNG_HIDDEN
struct lttng_evaluation *lttng_evaluation_session_rotation_completed_create(
		uint64_t id, struct lttng_trace_archive_location *location)
{
	return lttng_evaluation_session_rotation_create(
			LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED, id,
			location);
}

enum lttng_condition_status
lttng_condition_session_rotation_get_session_name(
		const struct lttng_condition *condition,
		const char **session_name)
{
	struct lttng_condition_session_rotation *rotation;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !is_rotation_condition(condition) || !session_name) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	rotation = container_of(condition, struct lttng_condition_session_rotation,
			parent);
	if (!rotation->session_name) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}
	*session_name = rotation->session_name;
end:
	return status;
}

enum lttng_condition_status
lttng_condition_session_rotation_set_session_name(
		struct lttng_condition *condition, const char *session_name)
{
	char *session_name_copy;
	struct lttng_condition_session_rotation *rotation;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !is_rotation_condition(condition) ||
			!session_name || strlen(session_name) == 0) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	rotation = container_of(condition,
			struct lttng_condition_session_rotation, parent);
	session_name_copy = strdup(session_name);
	if (!session_name_copy) {
		status = LTTNG_CONDITION_STATUS_ERROR;
		goto end;
	}

	free(rotation->session_name);
	rotation->session_name = session_name_copy;
end:
	return status;
}

static
int lttng_evaluation_session_rotation_serialize(
		const struct lttng_evaluation *evaluation,
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_evaluation_session_rotation *rotation;
	struct lttng_evaluation_session_rotation_comm comm = { 0 };

	rotation = container_of(evaluation,
			struct lttng_evaluation_session_rotation, parent);
	comm.id = rotation->id;
	comm.has_location = !!rotation->location;
	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &comm, sizeof(comm));
	if (ret) {
		goto end;
	}
	if (!rotation->location) {
		goto end;
	}
	ret = lttng_trace_archive_location_serialize(rotation->location,
			&payload->buffer);
end:
	return ret;
}

static
void lttng_evaluation_session_rotation_destroy(
		struct lttng_evaluation *evaluation)
{
	struct lttng_evaluation_session_rotation *rotation;

	rotation = container_of(evaluation,
			struct lttng_evaluation_session_rotation, parent);
	lttng_trace_archive_location_destroy(rotation->location);
	free(rotation);
}

enum lttng_evaluation_status
lttng_evaluation_session_rotation_get_id(
		const struct lttng_evaluation *evaluation, uint64_t *id)
{
	const struct lttng_evaluation_session_rotation *rotation;
	enum lttng_evaluation_status status = LTTNG_EVALUATION_STATUS_OK;

	if (!evaluation || !id || !is_rotation_evaluation(evaluation)) {
		status = LTTNG_EVALUATION_STATUS_INVALID;
		goto end;
	}

	rotation = container_of(evaluation,
			struct lttng_evaluation_session_rotation, parent);
	*id = rotation->id;
end:
	return status;
}

enum lttng_evaluation_status
lttng_evaluation_session_rotation_completed_get_location(
		const struct lttng_evaluation *evaluation,
		const struct lttng_trace_archive_location **location)
{
	const struct lttng_evaluation_session_rotation *rotation;
	enum lttng_evaluation_status status = LTTNG_EVALUATION_STATUS_OK;

	if (!evaluation || !location ||
			evaluation->type != LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED) {
		status = LTTNG_EVALUATION_STATUS_INVALID;
		goto end;
	}

	rotation = container_of(evaluation,
			struct lttng_evaluation_session_rotation, parent);
	*location = rotation->location;
end:
	return status;
}

static
enum lttng_error_code lttng_condition_session_rotation_mi(const struct lttng_condition *condition, struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_condition_status status;
	const char *session_name = NULL;

	assert(condition);
	assert(writer);
	assert(is_rotation_condition(condition));

	status = lttng_condition_session_rotation_get_session_name(condition, &session_name);
	assert(status == LTTNG_CONDITION_STATUS_OK);
	assert(session_name);

	/* Open condition_session_rotation. */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_condition_session_rotation);
	if (ret) {
		goto mi_error;
	}

	/* Session name. */
	ret = mi_lttng_writer_write_element_string(writer, mi_lttng_element_session_name, session_name);
	if (ret) {
		goto mi_error;
	}

	/* Close condition_session_rotation. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	return ret_code;
}
