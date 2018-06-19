/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/common.h>
#include <common/defaults.h>
#include <common/utils.h>

#include "lttng-relayd.h"
#include "utils.h"

#define DATETIME_STRING_SIZE 16

static char *get_filesystem_per_session(const char *path)
{
	int ret;
	int session_name_size;
	char *local_copy = NULL;
	char *session_name = NULL;
	char *datetime = NULL;
	char *hostname_ptr;
	char *session_name_with_datetime_ptr;
	char *leftover_ptr;
	char *filepath_per_session = NULL;

	/*
	 * All of this handling is HIGLY dependant on how the pathname are
	 * transmitted to the lttng-relayd. This consider that the following
	 * form is respected: <host-name>/<session-datetime>/<rest of path>.
	 */

	/* Get a local copy for strtok */
	local_copy = strdup(path);
	if (!local_copy) {
		ERR("strdup of local copy failed");
		goto error;
	}

	/*
	 * The use of strtok with "/" as delimiter is valid since we refuse "/"
	 * in session name and '/' is not a valid hostname character based on
	 * RFC-952 [1], RFC-921 [2] and refined in RFC-1123 [2].
	 * [1] https://tools.ietf.org/html/rfc952
	 * [2] https://tools.ietf.org/html/rfc921
	 * [3] https://tools.ietf.org/html/rfc1123#page-13
	 */

	/* Get the hostname and session_name with datetime appended */
	hostname_ptr = strtok_r(local_copy, "/", &leftover_ptr);
	if (!hostname_ptr) {
		ERR("hostname token not found");
		goto error;
	}

	session_name_with_datetime_ptr = strtok_r(NULL, "/", &leftover_ptr);
	if (!session_name_with_datetime_ptr) {
		ERR("Session name token not found");
		goto error;
	}

	/* Separate the session name and datetime. Use */
	session_name_size = strlen(session_name_with_datetime_ptr);

	session_name = malloc(session_name_size + 1);
	session_name[session_name_size] = '\0';

	/*
	 * Remove the datetime and the leading "-" using the defined sized for
	 * the datetime/ */
	session_name = strndup(session_name_with_datetime_ptr, session_name_size - DATETIME_STRING_SIZE);
	if (!session_name) {
		ERR("strdup of session name failed");
		goto error;
	}

	datetime = strndup(&session_name_with_datetime_ptr[session_name_size - DATETIME_STRING_SIZE + 1], DATETIME_STRING_SIZE);
	if (!datetime) {
		ERR("strdup of datetime failed");
		goto error;
	}

	ret = asprintf(&filepath_per_session, "%s/%s-%s/%s", session_name, hostname_ptr, datetime, leftover_ptr);
	if (ret < 0) {
		filepath_per_session = NULL;
		goto error;
	}

error:
	free(local_copy);
	free(session_name);
	free(datetime);
	return filepath_per_session;
}

static char *create_output_path_auto(const char *path_name)
{
	int ret;
	char *traces_path = NULL;
	char *alloc_path = NULL;
	char *default_path;

	default_path = utils_get_home_dir();
	if (default_path == NULL) {
		ERR("Home path not found.\n \
				Please specify an output path using -o, --output PATH");
		goto exit;
	}
	alloc_path = strdup(default_path);
	if (alloc_path == NULL) {
		PERROR("Path allocation");
		goto exit;
	}
	ret = asprintf(&traces_path, "%s/" DEFAULT_TRACE_DIR_NAME
			"/%s", alloc_path, path_name);
	if (ret < 0) {
		PERROR("asprintf trace dir name");
		goto exit;
	}
exit:
	free(alloc_path);
	return traces_path;
}

static char *create_output_path_noauto(const char *path_name)
{
	int ret;
	char *traces_path = NULL;
	char *full_path;

	full_path = utils_expand_path(opt_output_path);
	if (!full_path) {
		goto exit;
	}

	ret = asprintf(&traces_path, "%s/%s", full_path, path_name);
	if (ret < 0) {
		PERROR("asprintf trace dir name");
		goto exit;
	}
exit:
	free(full_path);
	return traces_path;
}

/*
 * Create the output trace directory path name string.
 *
 * Return the allocated string containing the path name or else NULL.
 */
char *create_output_path(const char *path_name)
{
	char *real_path = NULL;
	char *return_path = NULL;
	assert(path_name);

	if (opt_group_output_by_session) {
		real_path = get_filesystem_per_session(path_name);
	} else if (opt_group_output_by_host) {
		real_path = strdup(path_name);
	} else {
		ERR("Configuration error");
		assert(0);
	}

	if (!real_path) {
		goto error;
	}

	if (opt_output_path == NULL) {
		return_path = create_output_path_auto(real_path);
	} else {
		return_path = create_output_path_noauto(real_path);
	}
error:
	free(real_path);
	return return_path;
}
