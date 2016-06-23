/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <ctype.h>

#include <src/common/sessiond-comm/sessiond-comm.h>
#include <common/compat/string.h>

/* Mi dependancy */
#include <common/mi-lttng.h>

#include "../command.h"

#if (LTTNG_SYMBOL_NAME_LEN == 256)
#define LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API	"255"
#endif

static char *opt_event_list;
static int opt_event_type;
static char *opt_loglevel;
static int opt_loglevel_type;
static int opt_kernel;
static char *opt_session_name;
static int opt_domain;
static int opt_enable_all;
static char *opt_probe;
static char *opt_function;
static char *opt_channel_name;
static char *opt_filter;
static char *opt_exclude;
static char *opt_template_path;

enum {
	OPT_HELP = 1,
	OPT_TRACEPOINT,
	OPT_PROBE,
	OPT_FUNCTION,
	OPT_SYSCALL,
	OPT_LOGLEVEL,
	OPT_LOGLEVEL_ONLY,
	OPT_LIST_OPTIONS,
	OPT_FILTER,
	OPT_EXCLUDE,
};

static struct lttng_handle *handle;
static struct mi_writer *writer;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"all",            'a', POPT_ARG_VAL, &opt_enable_all, 1, 0, 0},
	{"channel",        'c', POPT_ARG_STRING, &opt_channel_name, 0, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_domain, LTTNG_DOMAIN_KERNEL, 0, 0},
	{"userspace",      'u', POPT_ARG_VAL, &opt_domain, LTTNG_DOMAIN_UST, 0, 0},
	{"jul",            'j', POPT_ARG_VAL, &opt_domain, LTTNG_DOMAIN_JUL, 0, 0},
	{"log4j",          'l', POPT_ARG_VAL, &opt_domain, LTTNG_DOMAIN_LOG4J, 0, 0},
	{"python",         'p', POPT_ARG_VAL, &opt_domain, LTTNG_DOMAIN_PYTHON, 0, 0},
	{"tracepoint",     0,   POPT_ARG_NONE, 0, OPT_TRACEPOINT, 0, 0},
	{"probe",          0,   POPT_ARG_STRING, &opt_probe, OPT_PROBE, 0, 0},
	{"function",       0,   POPT_ARG_STRING, &opt_function, OPT_FUNCTION, 0, 0},
	{"syscall",        0,   POPT_ARG_NONE, 0, OPT_SYSCALL, 0, 0},
	{"loglevel",       0,     POPT_ARG_STRING, 0, OPT_LOGLEVEL, 0, 0},
	{"loglevel-only",  0,     POPT_ARG_STRING, 0, OPT_LOGLEVEL_ONLY, 0, 0},
	{"filter",         'f', POPT_ARG_STRING, &opt_filter, OPT_FILTER, 0, 0},
	{"exclude",        'x', POPT_ARG_STRING, &opt_exclude, OPT_EXCLUDE, 0, 0},
	/* No op */
	{"session",        's', POPT_ARG_NONE, 0, 0, 0, 0},
	{"template-path",  't', POPT_ARG_NONE, 0, 0, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

static struct poptOption global_long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"template-path",  't', POPT_ARG_STRING, &opt_template_path, 0, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};
/*
 * Parse probe options.
 */
static int parse_probe_opts(struct lttng_event *ev, char *opt)
{
	int ret = CMD_SUCCESS;
	int match;
	char s_hex[19];
#define S_HEX_LEN_SCANF_IS_A_BROKEN_API "18"	/* 18 is (19 - 1) (\0 is extra) */
	char name[LTTNG_SYMBOL_NAME_LEN];

	if (opt == NULL) {
		ret = CMD_ERROR;
		goto end;
	}

	/* Check for symbol+offset */
	match = sscanf(opt, "%" LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API
			"[^'+']+%" S_HEX_LEN_SCANF_IS_A_BROKEN_API "s", name, s_hex);
	if (match == 2) {
		strncpy(ev->attr.probe.symbol_name, name, LTTNG_SYMBOL_NAME_LEN);
		ev->attr.probe.symbol_name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		DBG("probe symbol %s", ev->attr.probe.symbol_name);
		if (*s_hex == '\0') {
			ERR("Invalid probe offset %s", s_hex);
			ret = CMD_ERROR;
			goto end;
		}
		ev->attr.probe.offset = strtoul(s_hex, NULL, 0);
		DBG("probe offset %" PRIu64, ev->attr.probe.offset);
		ev->attr.probe.addr = 0;
		goto end;
	}

	/* Check for symbol */
	if (isalpha(name[0])) {
		match = sscanf(opt, "%" LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API "s",
			name);
		if (match == 1) {
			strncpy(ev->attr.probe.symbol_name, name, LTTNG_SYMBOL_NAME_LEN);
			ev->attr.probe.symbol_name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
			DBG("probe symbol %s", ev->attr.probe.symbol_name);
			ev->attr.probe.offset = 0;
			DBG("probe offset %" PRIu64, ev->attr.probe.offset);
			ev->attr.probe.addr = 0;
			goto end;
		}
	}

	/* Check for address */
	match = sscanf(opt, "%" S_HEX_LEN_SCANF_IS_A_BROKEN_API "s", s_hex);
	if (match > 0) {
		if (*s_hex == '\0') {
			ERR("Invalid probe address %s", s_hex);
			ret = CMD_ERROR;
			goto end;
		}
		ev->attr.probe.addr = strtoul(s_hex, NULL, 0);
		DBG("probe addr %" PRIu64, ev->attr.probe.addr);
		ev->attr.probe.offset = 0;
		memset(ev->attr.probe.symbol_name, 0, LTTNG_SYMBOL_NAME_LEN);
		goto end;
	}

	/* No match */
	ret = CMD_ERROR;

end:
	return ret;
}

/*
 * Maps LOG4j loglevel from string to value
 */
static int loglevel_log4j_str_to_value(const char *inputstr)
{
	int i = 0;
	char str[LTTNG_SYMBOL_NAME_LEN];

	if (!inputstr || strlen(inputstr) == 0) {
		return -1;
	}

	/*
	 * Loop up to LTTNG_SYMBOL_NAME_LEN minus one because the NULL bytes is
	 * added at the end of the loop so a the upper bound we avoid the overflow.
	 */
	while (i < (LTTNG_SYMBOL_NAME_LEN - 1) && inputstr[i] != '\0') {
		str[i] = toupper(inputstr[i]);
		i++;
	}
	str[i] = '\0';

	if (!strcmp(str, "LOG4J_OFF") || !strcmp(str, "OFF")) {
		return LTTNG_LOGLEVEL_LOG4J_OFF;
	} else if (!strcmp(str, "LOG4J_FATAL") || !strcmp(str, "FATAL")) {
		return LTTNG_LOGLEVEL_LOG4J_FATAL;
	} else if (!strcmp(str, "LOG4J_ERROR") || !strcmp(str, "ERROR")) {
		return LTTNG_LOGLEVEL_LOG4J_ERROR;
	} else if (!strcmp(str, "LOG4J_WARN") || !strcmp(str, "WARN")) {
		return LTTNG_LOGLEVEL_LOG4J_WARN;
	} else if (!strcmp(str, "LOG4J_INFO") || !strcmp(str, "INFO")) {
		return LTTNG_LOGLEVEL_LOG4J_INFO;
	} else if (!strcmp(str, "LOG4J_DEBUG") || !strcmp(str, "DEBUG")) {
		return LTTNG_LOGLEVEL_LOG4J_DEBUG;
	} else if (!strcmp(str, "LOG4J_TRACE") || !strcmp(str, "TRACE")) {
		return LTTNG_LOGLEVEL_LOG4J_TRACE;
	} else if (!strcmp(str, "LOG4J_ALL") || !strcmp(str, "ALL")) {
		return LTTNG_LOGLEVEL_LOG4J_ALL;
	} else {
		return -1;
	}
}

/*
 * Maps JUL loglevel from string to value
 */
static int loglevel_jul_str_to_value(const char *inputstr)
{
	int i = 0;
	char str[LTTNG_SYMBOL_NAME_LEN];

	if (!inputstr || strlen(inputstr) == 0) {
		return -1;
	}

	/*
	 * Loop up to LTTNG_SYMBOL_NAME_LEN minus one because the NULL bytes is
	 * added at the end of the loop so a the upper bound we avoid the overflow.
	 */
	while (i < (LTTNG_SYMBOL_NAME_LEN - 1) && inputstr[i] != '\0') {
		str[i] = toupper(inputstr[i]);
		i++;
	}
	str[i] = '\0';

	if (!strcmp(str, "JUL_OFF") || !strcmp(str, "OFF")) {
		return LTTNG_LOGLEVEL_JUL_OFF;
	} else if (!strcmp(str, "JUL_SEVERE") || !strcmp(str, "SEVERE")) {
		return LTTNG_LOGLEVEL_JUL_SEVERE;
	} else if (!strcmp(str, "JUL_WARNING") || !strcmp(str, "WARNING")) {
		return LTTNG_LOGLEVEL_JUL_WARNING;
	} else if (!strcmp(str, "JUL_INFO") || !strcmp(str, "INFO")) {
		return LTTNG_LOGLEVEL_JUL_INFO;
	} else if (!strcmp(str, "JUL_CONFIG") || !strcmp(str, "CONFIG")) {
		return LTTNG_LOGLEVEL_JUL_CONFIG;
	} else if (!strcmp(str, "JUL_FINE") || !strcmp(str, "FINE")) {
		return LTTNG_LOGLEVEL_JUL_FINE;
	} else if (!strcmp(str, "JUL_FINER") || !strcmp(str, "FINER")) {
		return LTTNG_LOGLEVEL_JUL_FINER;
	} else if (!strcmp(str, "JUL_FINEST") || !strcmp(str, "FINEST")) {
		return LTTNG_LOGLEVEL_JUL_FINEST;
	} else if (!strcmp(str, "JUL_ALL") || !strcmp(str, "ALL")) {
		return LTTNG_LOGLEVEL_JUL_ALL;
	} else {
		return -1;
	}
}

/*
 * Maps Python loglevel from string to value
 */
static int loglevel_python_str_to_value(const char *inputstr)
{
	int i = 0;
	char str[LTTNG_SYMBOL_NAME_LEN];

	if (!inputstr || strlen(inputstr) == 0) {
		return -1;
	}

	/*
	 * Loop up to LTTNG_SYMBOL_NAME_LEN minus one because the NULL bytes is
	 * added at the end of the loop so a the upper bound we avoid the overflow.
	 */
	while (i < (LTTNG_SYMBOL_NAME_LEN - 1) && inputstr[i] != '\0') {
		str[i] = toupper(inputstr[i]);
		i++;
	}
	str[i] = '\0';

	if (!strcmp(str, "PYTHON_CRITICAL") || !strcmp(str, "CRITICAL")) {
		return LTTNG_LOGLEVEL_PYTHON_CRITICAL;
	} else if (!strcmp(str, "PYTHON_ERROR") || !strcmp(str, "ERROR")) {
		return LTTNG_LOGLEVEL_PYTHON_ERROR;
	} else if (!strcmp(str, "PYTHON_WARNING") || !strcmp(str, "WARNING")) {
		return LTTNG_LOGLEVEL_PYTHON_WARNING;
	} else if (!strcmp(str, "PYTHON_INFO") || !strcmp(str, "INFO")) {
		return LTTNG_LOGLEVEL_PYTHON_INFO;
	} else if (!strcmp(str, "PYTNON_DEBUG") || !strcmp(str, "DEBUG")) {
		return LTTNG_LOGLEVEL_PYTHON_DEBUG;
	} else if (!strcmp(str, "PYTHON_NOTSET") || !strcmp(str, "NOTSET")) {
		return LTTNG_LOGLEVEL_PYTHON_NOTSET;
	} else {
		return -1;
	}
}

/*
 * Maps loglevel from string to value
 */
static
int loglevel_ust_str_to_value(const char *inputstr)
{
	int i = 0;
	char str[LTTNG_SYMBOL_NAME_LEN];

	if (!inputstr || strlen(inputstr) == 0) {
		return -1;
	}

	/*
	 * Loop up to LTTNG_SYMBOL_NAME_LEN minus one because the NULL bytes is
	 * added at the end of the loop so a the upper bound we avoid the overflow.
	 */
	while (i < (LTTNG_SYMBOL_NAME_LEN - 1) && inputstr[i] != '\0') {
		str[i] = toupper(inputstr[i]);
		i++;
	}
	str[i] = '\0';
	if (!strcmp(str, "TRACE_EMERG") || !strcmp(str, "EMERG")) {
		return LTTNG_LOGLEVEL_EMERG;
	} else if (!strcmp(str, "TRACE_ALERT") || !strcmp(str, "ALERT")) {
		return LTTNG_LOGLEVEL_ALERT;
	} else if (!strcmp(str, "TRACE_CRIT") || !strcmp(str, "CRIT")) {
		return LTTNG_LOGLEVEL_CRIT;
	} else if (!strcmp(str, "TRACE_ERR") || !strcmp(str, "ERR")) {
		return LTTNG_LOGLEVEL_ERR;
	} else if (!strcmp(str, "TRACE_WARNING") || !strcmp(str, "WARNING")) {
		return LTTNG_LOGLEVEL_WARNING;
	} else if (!strcmp(str, "TRACE_NOTICE") || !strcmp(str, "NOTICE")) {
		return LTTNG_LOGLEVEL_NOTICE;
	} else if (!strcmp(str, "TRACE_INFO") || !strcmp(str, "INFO")) {
		return LTTNG_LOGLEVEL_INFO;
	} else if (!strcmp(str, "TRACE_DEBUG_SYSTEM") || !strcmp(str, "DEBUG_SYSTEM") || !strcmp(str, "SYSTEM")) {
		return LTTNG_LOGLEVEL_DEBUG_SYSTEM;
	} else if (!strcmp(str, "TRACE_DEBUG_PROGRAM") || !strcmp(str, "DEBUG_PROGRAM") || !strcmp(str, "PROGRAM")) {
		return LTTNG_LOGLEVEL_DEBUG_PROGRAM;
	} else if (!strcmp(str, "TRACE_DEBUG_PROCESS") || !strcmp(str, "DEBUG_PROCESS") || !strcmp(str, "PROCESS")) {
		return LTTNG_LOGLEVEL_DEBUG_PROCESS;
	} else if (!strcmp(str, "TRACE_DEBUG_MODULE") || !strcmp(str, "DEBUG_MODULE") || !strcmp(str, "MODULE")) {
		return LTTNG_LOGLEVEL_DEBUG_MODULE;
	} else if (!strcmp(str, "TRACE_DEBUG_UNIT") || !strcmp(str, "DEBUG_UNIT") || !strcmp(str, "UNIT")) {
		return LTTNG_LOGLEVEL_DEBUG_UNIT;
	} else if (!strcmp(str, "TRACE_DEBUG_FUNCTION") || !strcmp(str, "DEBUG_FUNCTION") || !strcmp(str, "FUNCTION")) {
		return LTTNG_LOGLEVEL_DEBUG_FUNCTION;
	} else if (!strcmp(str, "TRACE_DEBUG_LINE") || !strcmp(str, "DEBUG_LINE") || !strcmp(str, "LINE")) {
		return LTTNG_LOGLEVEL_DEBUG_LINE;
	} else if (!strcmp(str, "TRACE_DEBUG") || !strcmp(str, "DEBUG")) {
		return LTTNG_LOGLEVEL_DEBUG;
	} else {
		return -1;
	}
}

/*
 * Map a userspace agent loglevel to it's value based on the domain type.
 *
 * Assert when loglevel is NULL and domain type is LTTNG_DOMAIN_NONE ||
 * LTTNG_DOMAIN_KERNEL.
 *
 * return -1 on invalid loglevel.
 */
static int loglevel_str_to_value(const char* loglevel, enum lttng_domain_type type)
{
	int ret = -1;
	switch (type) {
		case LTTNG_DOMAIN_UST:
			ret = loglevel_ust_str_to_value(loglevel);
			break;
		case LTTNG_DOMAIN_JUL:
			ret = loglevel_jul_str_to_value(loglevel);
			break;
		case LTTNG_DOMAIN_LOG4J:
			ret = loglevel_log4j_str_to_value(loglevel);
			break;
		case LTTNG_DOMAIN_PYTHON:
			ret = loglevel_python_str_to_value(loglevel);
			break;
		default:
			assert(0);
	}

	return ret;
}

static
const char *print_channel_name(const char *name)
{
	return name ? : DEFAULT_CHANNEL_NAME;
}

static
const char *print_raw_channel_name(const char *name)
{
	return name ? : "<default>";
}

/*
 * Mi print exlcusion list
 */
static
int mi_print_exclusion(int count, char **names)
{
	int i, ret;

	assert(writer);

	if (count == 0) {
		ret = 0;
		goto end;
	}
	ret = mi_lttng_writer_open_element(writer, config_element_exclusions);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		ret = mi_lttng_writer_write_element_string(writer,
				config_element_exclusion, names[i]);
		if (ret) {
			goto end;
		}
	}

	/* Close exclusions element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

/*
 * Return allocated string for pretty-printing exclusion names.
 */
static
char *print_exclusions(int count, char **names)
{
	int length = 0;
	int i;
	const char *preamble = " excluding ";
	char *ret;

	if (count == 0) {
		return strdup("");
	}

	/* calculate total required length */
	for (i = 0; i < count; i++) {
		length += strlen(names[i]) + 1;
	}

	/* add length of preamble + one for NUL - one for last (missing) comma */
	length += strlen(preamble);
	ret = zmalloc(length);
	if (!ret) {
		return NULL;
	}
	strncpy(ret, preamble, length);
	for (i = 0; i < count; i++) {
		strcat(ret, names[i]);
		if (i != count - 1) {
			strcat(ret, ",");
		}
	}

	return ret;
}

/*
 * Return an allocated string for pretty printing of exclusion of an event from
 * a config_element.
 *
 * e.g: test,test1,test2
 */
static
char *print_exclusions_config(const struct config_element *event)
{
	const char *path = "/event/exclusions/exclusion";
	struct config_element **element_array = NULL;
	int element_array_size = 0;
	char **exclusion_str_array = NULL;
	char *return_string = NULL;
	int length = 0;

	config_element_get_element_array(event, path, &element_array, &element_array_size);
	if (element_array_size == 0) {
		return_string = strdup("");
		goto end;
	}

	exclusion_str_array = calloc(element_array_size, sizeof(char *));
	if (!exclusion_str_array) {
		ERR("calloc exclusion string array");
		return_string = NULL;
		goto end;
	}

	/* Fetch data and get full length */
	for (int i = 0; i < element_array_size; i++) {
		exclusion_str_array[i] = config_element_get_element_value(element_array[i], "/exclusion");
		if (!exclusion_str_array[i]) {
			ERR("Fecthing exlusion %d of event config element", i);
			continue;
		}
		length += strlen(exclusion_str_array[i]) + 1;
	}

	return_string = zmalloc(length);
	if (!return_string) {
		return_string = NULL;
		goto end;
	}

	/* Construct string */
	for (int i = 0; i < element_array_size; i++) {
		if (!exclusion_str_array[i]) {
			continue;
		}

		strcat(return_string, exclusion_str_array[i]);
		if (i != element_array_size - 1) {
			strcat(return_string, ",");
		}
	}

end:
	config_element_free_array(element_array, element_array_size);
	if (exclusion_str_array) {
		for (int i = 0; i < element_array_size; i++) {
			free(exclusion_str_array[i]);
		}
	}
	free(exclusion_str_array);

	return return_string;
}

/*
 * Compare list of exclusions against an event name.
 * Return a list of legal exclusion names.
 * Produce an error or a warning about others (depending on the situation)
 */
static
int check_exclusion_subsets(const char *event_name,
		const char *exclusions,
		int *exclusion_count_ptr,
		char ***exclusion_list_ptr)
{
	const char *excluder_ptr;
	const char *event_ptr;
	const char *next_excluder;
	int excluder_length;
	int exclusion_count = 0;
	char **exclusion_list = NULL;
	int ret = CMD_SUCCESS;

	if (event_name[strlen(event_name) - 1] != '*') {
		ERR("Event %s: Excluders can only be used with wildcarded events", event_name);
		goto error;
	}

	next_excluder = exclusions;
	while (*next_excluder != 0) {
		event_ptr = event_name;
		excluder_ptr = next_excluder;
		excluder_length = strcspn(next_excluder, ",");

		/* Scan both the excluder and the event letter by letter */
		while (1) {
			char e, x;

			e = *event_ptr;
			x = *excluder_ptr;

			if (x == '*') {
				/* Event is a subset of the excluder */
				ERR("Event %s: %.*s excludes all events from %s",
						event_name,
						excluder_length,
						next_excluder,
						event_name);
				goto error;
			}
			if (e == '*') {
				char *string;
				char **new_exclusion_list;

				/* Excluder is a proper subset of event */
				string = lttng_strndup(next_excluder, excluder_length);
				if (!string) {
					PERROR("lttng_strndup error");
					goto error;
				}
				new_exclusion_list = realloc(exclusion_list,
					sizeof(char *) * (exclusion_count + 1));
				if (!new_exclusion_list) {
					PERROR("realloc");
					free(string);
					goto error;
				}
				exclusion_list = new_exclusion_list;
				exclusion_count++;
				exclusion_list[exclusion_count - 1] = string;
				break;
			}
			if (x != e) {
				/* Excluder and event sets have no common elements */
				WARN("Event %s: %.*s does not exclude any events from %s",
						event_name,
						excluder_length,
						next_excluder,
						event_name);
				break;
			}
			excluder_ptr++;
			event_ptr++;
		}
		/* next excluder */
		next_excluder += excluder_length;
		if (*next_excluder == ',') {
			next_excluder++;
		}
	}
	goto end;
error:
	while (exclusion_count--) {
		free(exclusion_list[exclusion_count]);
	}
	if (exclusion_list != NULL) {
		free(exclusion_list);
	}
	exclusion_list = NULL;
	exclusion_count = 0;
	ret = CMD_ERROR;
end:
	*exclusion_count_ptr = exclusion_count;
	*exclusion_list_ptr = exclusion_list;
	return ret;
}

static void warn_on_truncated_exclusion_names(char **exclusion_list,
	int exclusion_count, int *warn)
{
	size_t i = 0;

	for (i = 0; i < exclusion_count; ++i) {
		const char *name = exclusion_list[i];
		size_t len = strlen(name);

		if (len >= LTTNG_SYMBOL_NAME_LEN) {
			WARN("Event exclusion \"%s\" will be truncated",
				name);
			*warn = 1;
		}
	}
}

struct domain_configuration {
	int enable_all;
	int event_type;
	char *event_list;
	char *loglevel;
	int loglevel_type;
	enum lttng_domain_type domain_type;
	char *probe;
	char *function;
	char *channel_name;
	char *filter;
	char *exclude;
};

/*
 * Enabling event using the lttng API.
 * Note: in case of error only the last error code will be return.
 */
static int enable_events(char *session_name, struct domain_configuration *config)
{
	int ret = CMD_SUCCESS, command_ret = CMD_SUCCESS;
	int error_holder = CMD_SUCCESS, warn = 0, error = 0, success = 1;
	char *event_name, *channel_name = NULL;
	struct lttng_event ev;
	struct lttng_domain dom;
	int exclusion_count = 0;
	char **exclusion_list = NULL;

	int config_enable_all;
	int config_event_type;
	char *config_event_list;
	char *config_loglevel;
	int config_loglevel_type;
	enum lttng_domain_type config_domain_type;
	char *config_probe;
	char *config_function;
	char *config_channel_name;
	char *config_filter;
	char *config_exclude;

	assert(config);

	memset(&ev, 0, sizeof(ev));
	memset(&dom, 0, sizeof(dom));

	config_enable_all = config->enable_all;
	config_event_type = config->event_type;
	config_event_list = config->event_list;
	config_loglevel = config->loglevel;
	config_loglevel_type = config->loglevel_type;
	config_domain_type = config->domain_type;
	config_probe = config->probe;
	config_function = config->function;
	config_channel_name = config->channel_name;
	config_filter = config->filter;
	config_exclude = config->exclude;


	/* Create lttng domain */
	dom.type = config_domain_type;
	switch (config_domain_type) {
	case LTTNG_DOMAIN_KERNEL:
		dom.buf_type = LTTNG_BUFFER_GLOBAL;
		break;
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_PYTHON:
		dom.buf_type = LTTNG_BUFFER_PER_UID;
		break;
	case LTTNG_DOMAIN_NONE:
	default:
		assert(0);
	}



	channel_name = config_channel_name;

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	/* Prepare Mi */
	if (lttng_opt_mi) {
		/* Open a domain element */
		ret = mi_lttng_writer_open_element(writer, config_element_domain);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}

		/* Specify the domain type */
		ret = mi_lttng_writer_write_element_string(writer,
				config_element_type,
				mi_lttng_domaintype_string(config_domain_type));
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}

		/* Open a events element */
		ret = mi_lttng_writer_open_element(writer, config_element_events);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	if (config_enable_all) {
		/* Default setup for enable all */
		if (config_domain_type == LTTNG_DOMAIN_KERNEL) {
			ev.type = config_event_type;
			strcpy(ev.name, "*");
			/* kernel loglevels not implemented */
			ev.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;
		} else {
			ev.type = LTTNG_EVENT_TRACEPOINT;
			strcpy(ev.name, "*");
			ev.loglevel_type = config_loglevel_type;
			if (config_loglevel) {
				ev.loglevel = loglevel_str_to_value(config_loglevel, config_domain_type);
				if (ev.loglevel == -1) {
					ERR("Unknown loglevel %s", config_loglevel);
					ret = -LTTNG_ERR_INVALID;
					goto error;
				}
			} else {
				assert(config_domain_type != LTTNG_DOMAIN_NONE || config_domain_type != LTTNG_DOMAIN_KERNEL);
				switch (config_domain_type) {
				case LTTNG_DOMAIN_UST:
					ev.loglevel = -1;
					break;
				case LTTNG_DOMAIN_JUL:
					ev.loglevel = LTTNG_LOGLEVEL_JUL_ALL;
					break;
				case LTTNG_DOMAIN_LOG4J:
					ev.loglevel = LTTNG_LOGLEVEL_LOG4J_ALL;
					break;
				case LTTNG_DOMAIN_PYTHON:
					ev.loglevel = LTTNG_LOGLEVEL_PYTHON_DEBUG;
					break;
				default:
					assert(0);
				}
			}
		}

		if (config_exclude) {
			ret = check_exclusion_subsets("*", config_exclude,
					&exclusion_count, &exclusion_list);
			if (ret == CMD_ERROR) {
				goto error;
			}
			ev.exclusion = 1;

			warn_on_truncated_exclusion_names(exclusion_list,
				exclusion_count, &warn);
		}
		if (!config_filter) {
			ret = lttng_enable_event_with_exclusions(handle,
					&ev, channel_name,
					NULL,
					exclusion_count, exclusion_list);
			if (ret < 0) {
				switch (-ret) {
				case LTTNG_ERR_KERN_EVENT_EXIST:
					WARN("Kernel events already enabled (channel %s, session %s)",
							print_channel_name(channel_name), session_name);
					warn = 1;
					break;
				case LTTNG_ERR_TRACE_ALREADY_STARTED:
				{
					const char *msg = "The command tried to enable an event in a new domain for a session that has already been started once.";
					ERR("Events: %s (domain %s, channel %s, session %s)",
							msg,
							get_domain_str(dom.type),
							print_channel_name(channel_name),
							session_name);
					error = 1;
					break;
				}
				default:
					ERR("Events: %s (domain %s, channel %s, session %s)",
							lttng_strerror(ret),
							get_domain_str(dom.type),
							ret == -LTTNG_ERR_NEED_CHANNEL_NAME
								? print_raw_channel_name(channel_name)
								: print_channel_name(channel_name),
							session_name);
					error = 1;
					break;
				}
				goto end;
			}

			switch (config_event_type) {
			case LTTNG_EVENT_TRACEPOINT:
				if (config_loglevel && dom.type != LTTNG_DOMAIN_KERNEL) {
					char *exclusion_string = print_exclusions(exclusion_count, exclusion_list);

					if (!exclusion_string) {
						PERROR("Cannot allocate exclusion_string");
						error = 1;
						goto end;
					}
					MSG("All %s tracepoints%s are enabled in channel %s for loglevel %s",
							get_domain_str(dom.type),
							exclusion_string,
							print_channel_name(channel_name),
							config_loglevel);
					free(exclusion_string);
				} else {
					char *exclusion_string = print_exclusions(exclusion_count, exclusion_list);

					if (!exclusion_string) {
						PERROR("Cannot allocate exclusion_string");
						error = 1;
						goto end;
					}
					MSG("All %s tracepoints%s are enabled in channel %s",
							get_domain_str(dom.type),
							exclusion_string,
							print_channel_name(channel_name));
					free(exclusion_string);
				}
				break;
			case LTTNG_EVENT_SYSCALL:
				if (opt_kernel) {
					MSG("All %s system calls are enabled in channel %s",
							get_domain_str(dom.type),
							print_channel_name(channel_name));
				}
				break;
			case LTTNG_EVENT_ALL:
				if (config_loglevel && dom.type != LTTNG_DOMAIN_KERNEL) {
					char *exclusion_string = print_exclusions(exclusion_count, exclusion_list);

					if (!exclusion_string) {
						PERROR("Cannot allocate exclusion_string");
						error = 1;
						goto end;
					}
					MSG("All %s events%s are enabled in channel %s for loglevel %s",
							get_domain_str(dom.type),
							exclusion_string,
							print_channel_name(channel_name),
							config_loglevel);
					free(exclusion_string);
				} else {
					char *exclusion_string = print_exclusions(exclusion_count, exclusion_list);

					if (!exclusion_string) {
						PERROR("Cannot allocate exclusion_string");
						error = 1;
						goto end;
					}
					MSG("All %s events%s are enabled in channel %s",
							get_domain_str(dom.type),
							exclusion_string,
							print_channel_name(channel_name));
					free(exclusion_string);
				}
				break;
			default:
				/*
				 * We should not be here since lttng_enable_event should have
				 * failed on the event type.
				 */
				goto error;
			}
		}

		if (config_filter) {
			command_ret = lttng_enable_event_with_exclusions(handle, &ev, channel_name,
						config_filter, exclusion_count, exclusion_list);
			if (command_ret < 0) {
				switch (-command_ret) {
				case LTTNG_ERR_FILTER_EXIST:
					WARN("Filter on all events is already enabled"
							" (domain %s, channel %s, session %s)",
						get_domain_str(dom.type),
						print_channel_name(channel_name), session_name);
					warn = 1;
					break;
				case LTTNG_ERR_TRACE_ALREADY_STARTED:
				{
					const char *msg = "The command tried to enable an event in a new domain for a session that has already been started once.";
					ERR("All events: %s (domain %s, channel %s, session %s, filter \'%s\')",
							msg,
							get_domain_str(dom.type),
							print_channel_name(channel_name),
							session_name, config_filter);
					error = 1;
					break;
				}
				default:
					ERR("All events: %s (domain %s, channel %s, session %s, filter \'%s\')",
							lttng_strerror(command_ret),
							get_domain_str(dom.type),
							command_ret == -LTTNG_ERR_NEED_CHANNEL_NAME
								? print_raw_channel_name(channel_name)
								: print_channel_name(channel_name),
							session_name, config_filter);
					error = 1;
					break;
				}
				error_holder = command_ret;
			} else {
				ev.filter = 1;
				MSG("Filter '%s' successfully set", config_filter);
			}
		}

		if (lttng_opt_mi) {
			/* The wildcard * is used for kernel and ust domain to
			 * represent ALL. We copy * in event name to force the wildcard use
			 * for kernel domain
			 *
			 * Note: this is strictly for semantic and printing while in
			 * machine interface mode.
			 */
			strcpy(ev.name, "*");

			/* If we reach here the events are enabled */
			if (!error && !warn) {
				ev.enabled = 1;
			} else {
				ev.enabled = 0;
				success = 0;
			}
			ret = mi_lttng_event(writer, &ev, 1, handle->domain.type);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}

			/* print exclusion */
			ret = mi_print_exclusion(exclusion_count, exclusion_list);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}

			/* Success ? */
			ret = mi_lttng_writer_write_element_bool(writer,
					mi_lttng_element_command_success, success);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}

			/* Close event element */
			ret = mi_lttng_writer_close_element(writer);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}
		}

		goto end;
	}

	/* Strip event list */
	event_name = strtok(config_event_list, ",");
	while (event_name != NULL) {
		/* Copy name and type of the event */
		strncpy(ev.name, event_name, LTTNG_SYMBOL_NAME_LEN);
		ev.name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		ev.type = config_event_type;

		/* Kernel tracer action */
		switch (config_domain_type) {
		case LTTNG_DOMAIN_KERNEL:
			DBG("Enabling kernel event %s for channel %s",
					event_name,
					print_channel_name(channel_name));

			switch (config_event_type) {
			case LTTNG_EVENT_ALL:	/* Enable tracepoints and syscalls */
				/* If event name differs from *, select tracepoint. */
				if (strcmp(ev.name, "*")) {
					ev.type = LTTNG_EVENT_TRACEPOINT;
				}
				break;
			case LTTNG_EVENT_TRACEPOINT:
				break;
			case LTTNG_EVENT_PROBE:
				ret = parse_probe_opts(&ev, config_probe);
				if (ret) {
					ERR("Unable to parse probe options");
					ret = 0;
					goto error;
				}
				break;
			case LTTNG_EVENT_FUNCTION:
				ret = parse_probe_opts(&ev, config_function);
				if (ret) {
					ERR("Unable to parse function probe options");
					ret = 0;
					goto error;
				}
				break;
			case LTTNG_EVENT_SYSCALL:
				ev.type = LTTNG_EVENT_SYSCALL;
				break;
			default:
				ret = CMD_UNDEFINED;
				goto error;
			}

			/* kernel loglevels not implemented */
			ev.loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;
			break;
		case LTTNG_DOMAIN_UST:
			/* User-space tracer action */
			DBG("Enabling UST event %s for channel %s, loglevel %s", event_name,
					print_channel_name(channel_name), config_loglevel ? : "<all>");

			switch (config_event_type) {
			case LTTNG_EVENT_ALL:	/* Default behavior is tracepoint */
				/* Fall-through */
			case LTTNG_EVENT_TRACEPOINT:
				/* Copy name and type of the event */
				ev.type = LTTNG_EVENT_TRACEPOINT;
				strncpy(ev.name, event_name, LTTNG_SYMBOL_NAME_LEN);
				ev.name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
				break;
			case LTTNG_EVENT_PROBE:
			case LTTNG_EVENT_FUNCTION:
			case LTTNG_EVENT_SYSCALL:
			default:
				ERR("Event type not available for user-space tracing");
				ret = CMD_UNSUPPORTED;
				goto error;
			}

			if (config_exclude) {
				ev.exclusion = 1;
				if (config_event_type != LTTNG_EVENT_ALL && config_event_type != LTTNG_EVENT_TRACEPOINT) {
					ERR("Exclusion option can only be used with tracepoint events");
					ret = CMD_ERROR;
					goto error;
				}
				/* Free previously allocated items */
				if (exclusion_list != NULL) {
					while (exclusion_count--) {
						free(exclusion_list[exclusion_count]);
					}
					free(exclusion_list);
					exclusion_list = NULL;
				}
				/* Check for proper subsets */
				ret = check_exclusion_subsets(event_name, config_exclude,
						&exclusion_count, &exclusion_list);
				if (ret == CMD_ERROR) {
					goto error;
				}

				warn_on_truncated_exclusion_names(
					exclusion_list, exclusion_count, &warn);
			}

			ev.loglevel_type = config_loglevel_type;
			if (config_loglevel) {
				ev.loglevel = loglevel_ust_str_to_value(config_loglevel);
				if (ev.loglevel == -1) {
					ERR("Unknown loglevel %s", config_loglevel);
					ret = -LTTNG_ERR_INVALID;
					goto error;
				}
			} else {
				ev.loglevel = -1;
			}
			break;
		case LTTNG_DOMAIN_JUL:
		case LTTNG_DOMAIN_LOG4J:
		case LTTNG_DOMAIN_PYTHON:
			if (config_event_type != LTTNG_EVENT_ALL &&
					config_event_type != LTTNG_EVENT_TRACEPOINT) {
				ERR("Event type not supported for domain.");
				ret = CMD_UNSUPPORTED;
				goto error;
			}

			ev.loglevel_type = config_loglevel_type;
			if (config_loglevel) {
				ev.loglevel = loglevel_str_to_value(config_loglevel, config_domain_type);
				if (ev.loglevel == -1) {
					ERR("Unknown loglevel %s", config_loglevel);
					ret = -LTTNG_ERR_INVALID;
					goto error;
				}
			} else {
				switch (config_domain_type) {
				case LTTNG_DOMAIN_JUL:
					ev.loglevel = LTTNG_LOGLEVEL_JUL_ALL;
					break;
				case LTTNG_DOMAIN_LOG4J:
					ev.loglevel = LTTNG_LOGLEVEL_LOG4J_ALL;
					break;
				case LTTNG_DOMAIN_PYTHON:
					ev.loglevel = LTTNG_LOGLEVEL_PYTHON_DEBUG;
					break;
				default:
					assert(0);
					break;
				}
			}
			ev.type = LTTNG_EVENT_TRACEPOINT;
			strncpy(ev.name, event_name, LTTNG_SYMBOL_NAME_LEN);
			ev.name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
			break;
		default:
			assert(0);
		}

		if (!config_filter) {
			char *exclusion_string;

			command_ret = lttng_enable_event_with_exclusions(handle,
					&ev, channel_name,
					NULL, exclusion_count, exclusion_list);
			exclusion_string = print_exclusions(exclusion_count, exclusion_list);
			if (!exclusion_string) {
				PERROR("Cannot allocate exclusion_string");
				error = 1;
				goto end;
			}
			if (command_ret < 0) {
				/* Turn ret to positive value to handle the positive error code */
				switch (-command_ret) {
				case LTTNG_ERR_KERN_EVENT_EXIST:
					WARN("Kernel event %s%s already enabled (channel %s, session %s)",
							event_name,
							exclusion_string,
							print_channel_name(channel_name), session_name);
					warn = 1;
					break;
				case LTTNG_ERR_TRACE_ALREADY_STARTED:
				{
					const char *msg = "The command tried to enable an event in a new domain for a session that has already been started once.";
					ERR("Event %s%s: %s (domain %s,channel %s, session %s)", event_name,
							exclusion_string,
							msg,
							get_domain_str(dom.type),
							print_channel_name(channel_name),
							session_name);
					error = 1;
					break;
				}
				default:
					ERR("Event %s%s: %s (domain %s, channel %s, session %s)", event_name,
							exclusion_string,
							lttng_strerror(command_ret),
							get_domain_str(dom.type),
							command_ret == -LTTNG_ERR_NEED_CHANNEL_NAME
								? print_raw_channel_name(channel_name)
								: print_channel_name(channel_name),
							session_name);
					error = 1;
					break;
				}
				error_holder = command_ret;
			} else {
				switch (dom.type) {
				case LTTNG_DOMAIN_KERNEL:
				case LTTNG_DOMAIN_UST:
					MSG("%s event %s%s created in channel %s",
						get_domain_str(dom.type),
						event_name,
						exclusion_string,
						print_channel_name(channel_name));
					break;
				case LTTNG_DOMAIN_JUL:
				case LTTNG_DOMAIN_LOG4J:
				case LTTNG_DOMAIN_PYTHON:
					/*
					 * Don't print the default channel
					 * name for agent domains.
					 */
					MSG("%s event %s%s enabled",
						get_domain_str(dom.type),
						event_name,
						exclusion_string);
					break;
				default:
					assert(0);
				}
			}
			free(exclusion_string);
		}

		if (config_filter) {
			char *exclusion_string;

			/* Filter present */
			ev.filter = 1;

			command_ret = lttng_enable_event_with_exclusions(handle, &ev, channel_name,
					config_filter, exclusion_count, exclusion_list);
			exclusion_string = print_exclusions(exclusion_count, exclusion_list);
			if (!exclusion_string) {
				PERROR("Cannot allocate exclusion_string");
				error = 1;
				goto end;
			}
			if (command_ret < 0) {
				switch (-command_ret) {
				case LTTNG_ERR_FILTER_EXIST:
					WARN("Filter on event %s%s is already enabled"
							" (domain %s, channel %s, session %s)",
						event_name,
						exclusion_string,
						get_domain_str(dom.type),
						print_channel_name(channel_name), session_name);
					warn = 1;
					break;
				case LTTNG_ERR_TRACE_ALREADY_STARTED:
				{
					const char *msg = "The command tried to enable an event in a new domain for a session that has already been started once.";
					ERR("Event %s%s: %s (domain %s, channel %s, session %s, filter \'%s\')", ev.name,
							exclusion_string,
							msg,
							get_domain_str(dom.type),
							print_channel_name(channel_name),
							session_name, config_filter);
					error = 1;
					break;
				}
				default:
					ERR("Event %s%s: %s (domain %s, channel %s, session %s, filter \'%s\')", ev.name,
							exclusion_string,
							lttng_strerror(command_ret),
							get_domain_str(dom.type),
							command_ret == -LTTNG_ERR_NEED_CHANNEL_NAME
								? print_raw_channel_name(channel_name)
								: print_channel_name(channel_name),
							session_name, config_filter);
					error = 1;
					break;
				}
				error_holder = command_ret;

			} else {
				MSG("Event %s%s: Filter '%s' for domain %s successfully set",
						event_name, exclusion_string,
						config_filter,
						get_domain_str(dom.type));
			}
			free(exclusion_string);
		}

		if (lttng_opt_mi) {
			if (command_ret) {
				success = 0;
				ev.enabled = 0;
			} else {
				ev.enabled = 1;
			}

			ret = mi_lttng_event(writer, &ev, 1, handle->domain.type);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}

			/* print exclusion */
			ret = mi_print_exclusion(exclusion_count, exclusion_list);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}

			/* Success ? */
			ret = mi_lttng_writer_write_element_bool(writer,
					mi_lttng_element_command_success, success);
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}

			/* Close event element */
			ret = mi_lttng_writer_close_element(writer);
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}
		}

		/* Next event */
		event_name = strtok(NULL, ",");
		/* Reset warn, error and success */
		success = 1;
	}

end:
	/* Close Mi */
	if (lttng_opt_mi) {
		/* Close events and domain element */
		ret = mi_lttng_close_multi_element(writer, 2);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}
error:
	if (warn) {
		ret = CMD_WARNING;
	}
	if (error) {
		ret = CMD_ERROR;
	}
	lttng_destroy_handle(handle);

	if (exclusion_list != NULL) {
		while (exclusion_count--) {
			free(exclusion_list[exclusion_count]);
		}
		free(exclusion_list);
	}

	/* Overwrite ret with error_holder if there was an actual error with
	 * enabling an event.
	 */
	ret = error_holder ? error_holder : ret;

	return ret;
}

struct exclusions_tuple {
	char **exclusion_list;
	int exclusion_count;
};

static int enable_event_template_per_domain(const struct config_document *document,
		const char* session_name,
		const struct domain_configuration *config)
{
	int ret = 0;
	int warn = 0;
	int error = 0;
	int printed_bytes = 0;
	char *query = NULL;
	struct config_element **element_array = NULL;
	int element_array_size = 0;
	struct config_element *config_loglevel_type = NULL;
	struct config_element *config_loglevel = NULL;
	struct config_element *config_filter = NULL;
	struct exclusions_tuple *event_exclusion_array = NULL;

	assert(document);
	assert(config);


	printed_bytes = asprintf(&query, "//sessions/session/domains/domain[./type = '%s']/channels/channel/events/event[./enabled = 'true']", config_get_domain_str(config->domain_type));
	if (printed_bytes <= 0) {
		ERR("Asprintf template events query");
		ret = -1;
		goto end;
	}

	config_document_get_element_array(document, query, &element_array, &element_array_size);
	if (!element_array) {
		/* No event */
		goto end;
	}

	/*
	 * Handle log_level
	 * Only userspace domain accept loglevel.
	 *
	 * config-> loglevel is only set when the user pass --logleve/
	 * --loglevel-only on the command line so use it as a way to
	 *  know if a loglevel override is necessary
	 */
	if (config->domain_type != LTTNG_DOMAIN_KERNEL && config->loglevel) {
		char *loglevel_value_str = NULL;
		int loglevel_value = -1;

		loglevel_value = loglevel_str_to_value(config->loglevel, config->domain_type);
		if (loglevel_value == -1) {
			ERR("Unknown loglevel %s", config->loglevel);
			ret = 1;
			goto end;
		}

		printed_bytes = asprintf(&loglevel_value_str, "%d", loglevel_value);
		if (printed_bytes <= 0 ) {
			ERR("Asprintf loglevel");
			ret = 1;
			goto end;
		}

		config_loglevel = config_element_create(config_element_loglevel, loglevel_value_str);
		free(loglevel_value_str);
		if (!config_loglevel) {
			ERR("Loglevel config creation failed");
			ret = 1;
			goto end;
		}

		config_loglevel_type = config_element_create(config_element_loglevel_type, config_get_loglevel_type_string(config->loglevel_type));
		if (!config_loglevel_type) {
			ERR("Loglevel type config creattion failed");
			ret = 1;
			goto end;
		}
	}

	/* Handle the filter */
	if (config->filter) {
		config_filter = config_element_create(config_element_filter, config->filter);
		if (!config_filter) {
			ERR("Filter config creattion failed");
			ret = 1;
			goto end;
		}
	}

	/*
	 * Handle exclusion on a per event base
	 * For now only userspace domains can have exclusions.
	 */
	event_exclusion_array = calloc(element_array_size, sizeof(struct exclusions_tuple));
	if (!event_exclusion_array) {
		ERR("Calloc exclusion list array");
		ret = 1;
		goto end;
	}


	if (config->domain_type != LTTNG_DOMAIN_KERNEL && config->exclude) {
		for (int i = 0; i < element_array_size; i++) {
			struct config_element *cur_event = element_array[i];
			char ***exclusion_list = &(event_exclusion_array[i].exclusion_list);
			int *exclusion_count = &(event_exclusion_array[i].exclusion_count);
			char *event_type_str = NULL;
			int event_type;
			char *event_name = NULL;

			*exclusion_list = NULL;
			*exclusion_count = 0;

			/* Get event name */
			event_name = config_element_get_element_value(cur_event, "/event/name");
			if (!event_name) {
				ERR("Reading event name from config element");
				continue;
			}
			event_type_str = config_element_get_element_value(cur_event, "/event/type");
			if (!event_type_str) {
				ERR("Reading event type from config element");
				free(event_name);
				continue;
			}

			event_type = config_get_event_type(event_type_str);
			if (event_type != LTTNG_EVENT_ALL && event_type != LTTNG_EVENT_TRACEPOINT) {
				const char *msg = "Exclusions do not apply to this event";
				WARN("Event %s: %s exclusions: %s (domain %s, channel %s, session %s)",
						event_name, msg, config->exclude,
						get_domain_str(config->domain_type),
						print_channel_name(config->channel_name),
						session_name);
				free(event_type_str);
				free(event_name);
				goto end;
			}

			/* Check for proper subsets */
			ret = check_exclusion_subsets(event_name, config->exclude,
					exclusion_count, exclusion_list);

			warn_on_truncated_exclusion_names(
					*exclusion_list, *exclusion_count, &warn);
			free(event_type_str);
			free(event_name);
		}
	}

	/*
	 * Create valid events config_element and try to enable them one by one
	 */
	for (int i = 0; i < element_array_size; i++) {
		const char *sub_msg = NULL;
		bool success = false;
		bool warn = false;

		struct config_element *cur_event = element_array[i];
		struct config_element *success_element = NULL;
		char *msg = NULL;
		char *exclusions_string = NULL;
		char *filter_string = NULL;
		char *event_name = NULL;

		event_name = config_element_get_element_value(cur_event, "/event/name");
		if (!event_name) {
			sub_msg = "event name not present abort event creation ";
			event_name = strdup("<Error fetching event name>");
			goto enable_event_continue;
		}

		/* Add the loglevel */
		if (config_loglevel && config_loglevel_type) {
			config_element_add_or_replace_child(cur_event, config_loglevel);
			config_element_add_or_replace_child(cur_event, config_loglevel_type);
		}
		if (config_filter) {
			config_element_add_or_replace_child(cur_event, config_filter);
		}

		if (event_exclusion_array[i].exclusion_list) {
			char **exclusion_list = event_exclusion_array[i].exclusion_list;
			const int exclusion_count = event_exclusion_array[i].exclusion_count;
			struct config_element *config_exclusions = NULL;
			struct config_element *exclusion = NULL;

			config_exclusions = config_element_create(config_element_exclusions, NULL);
			if (!config_exclusions) {
				sub_msg = "Exclusions config element ration failed abort event creation";
				goto enable_event_continue;
			}

			for (int j = 0; j < exclusion_count; j++) {
				exclusion = config_element_create(config_element_exclusion, exclusion_list[j]);
				if (!exclusion) {
					sub_msg = "Exclusion config element creation failed abort event creation";
					config_element_free(config_exclusions);
					goto enable_event_continue;
				}
				ret = config_element_add_child(config_exclusions, exclusion);
				if (ret) {
					sub_msg = "Exclusion config element child addition failed abort event creation";
					config_element_free(config_exclusions);
					config_element_free(exclusion);
					goto enable_event_continue;
				}

				config_element_free(exclusion);
			}

			ret = config_element_add_or_replace_child(cur_event, config_exclusions);
			if (ret) {
				sub_msg = "Exclusions config element child addition failed abort event creation";
				config_element_free(config_exclusions);
				goto enable_event_continue;
			}
			config_element_free(config_exclusions);
		}


		ret = config_process_event_element(cur_event, session_name, config->domain_type, config->channel_name);
		if (!ret) {
			success = true;
			sub_msg = "created";

			/* Mi element insertion */
			success_element = config_element_create(mi_lttng_element_command_success, "true");
			if (success_element) {
				ret = config_element_add_or_replace_child(cur_event, success_element);
				if (ret) {
					error = 1;
				}
			} else {
				error = 1;
			}

		} else {
			success = false;
			if (ret < 0) {
				sub_msg = lttng_strerror(ret);
				if (-ret == LTTNG_ERR_UST_EVENT_ENABLED || -ret == LTTNG_ERR_KERN_EVENT_EXIST) {
					/*This is not an error */
					warn = true;
				}
			} else {
				sub_msg = "creation failed";
			}

			/* Mi related insertion */
			success_element = config_element_create(mi_lttng_element_command_success, "false");
			if (success_element) {
				ret = config_element_add_or_replace_child(cur_event, success_element);
				if (ret) {
					error = 1;
				}
			} else {
				error = 1;
			}
		}

enable_event_continue:

		/* Get exclusions string for printing */
		exclusions_string = print_exclusions_config(cur_event);
		filter_string = config_element_get_element_value(cur_event, "/event/filter");


		/* Domain is already present inside the error or msg */
		printed_bytes = asprintf(&msg,"%s%sEvent %s: %s (exclusions: [%s] filter: [%s] session %s, channel %s)",
				success ? get_domain_str(config->domain_type): "",
				success ? " " : "",
				event_name,
				sub_msg,
				/*
				 * TODO: print actual exclusion of loaded event
				 */
				exclusions_string ? : "",
				/*
				 * TODO: print actual exclusion of loaded event
				 */
				filter_string ? : "",
				session_name,
				print_channel_name(config->channel_name));

		if (printed_bytes > 0 && success) {
			MSG("%s", msg);
		} else if (printed_bytes > 0 && warn) {
			WARN("%s", msg);
			/* At least one event failed */
			error = 1;
		} else if (printed_bytes > 0) {
			ERR("%s", msg);
		} else {
			ERR("Asprintf enable event message");
			/* At least one event failed */
			error = 1;
		}
		config_element_free(success_element);
		free(exclusions_string);
		free(event_name);
		free(filter_string);
		free(msg);
		continue;
	}

	/* Prepare Mi */
	if (lttng_opt_mi) {
		/* Open a domain element */
		ret = mi_lttng_writer_open_element(writer, config_element_domain);
		if (ret) {
			ret = 1;
			goto end;
		}

		/* Specify the domain type */
		ret = mi_lttng_writer_write_element_string(writer,
				config_element_type,
				mi_lttng_domaintype_string(config->domain_type));
		if (ret) {
			ret = 1;
			goto end;
		}

		/* Open a events element */
		ret = mi_lttng_writer_open_element(writer, config_element_events);
		if (ret) {
			ret = 1;
			goto end;
		}

		for (int i = 0; i < element_array_size; i++) {
			ret = mi_lttng_writer_write_config_element(writer,
					element_array[i]);
			if (ret) {
				ret = 1;
				goto end;
			}
		}

		ret = mi_lttng_close_multi_element(writer, 2);
		if (ret) {
			ret = 1;
			goto end;
		}
	}


end:
	/* Free exclusion allocated items */
	if (event_exclusion_array != NULL) {
		for (int i = 0; i < element_array_size; i++) {
			char **exclusion_list = event_exclusion_array[i].exclusion_list;
			int exclusion_count = event_exclusion_array[i].exclusion_count;
			if (exclusion_list != NULL) {
				while (exclusion_count--) {
					free(exclusion_list[exclusion_count]);
				}
			}
			free(exclusion_list);
			exclusion_list = NULL;
		}
		free(event_exclusion_array);
	}
	config_element_free_array(element_array, element_array_size);
	config_element_free(config_loglevel);
	config_element_free(config_loglevel_type);
	config_element_free(config_filter);
	free(query);
	if (error) {
		ret = 1;
	}
	return ret;
}


static int enable_event_from_template(const struct config_document *document,
		const char* session_name,
		const struct domain_configuration *kernel_config,
		const struct domain_configuration *ust_config,
		const struct domain_configuration *jul_config,
		const struct domain_configuration *log4j_config,
		const struct domain_configuration *python_config)
{
	int ret = 0;
	int error = 0;

	ret = enable_event_template_per_domain(document, session_name, kernel_config);
	if (ret) {
		error = ret;
	}
	ret = enable_event_template_per_domain(document, session_name, ust_config);
	if (ret) {
		error = ret;
	}
	ret = enable_event_template_per_domain(document, session_name, jul_config);
	if (ret) {
		error = ret;
	}
	ret = enable_event_template_per_domain(document, session_name, log4j_config);
	if (ret) {
		error = ret;
	}
	ret = enable_event_template_per_domain(document, session_name, python_config);
	if (ret) {
		error = ret;
	}

	return error;
}

/*
 * Add event to trace session
 */

struct args_tuple {
	int argv_index_start;
	int argv_index_end;
};


static struct domain_configuration *initialize_domain_configuration(enum lttng_domain_type type)
{

	struct domain_configuration *config = malloc(sizeof(struct domain_configuration));

	if (!config) {
		goto end;
	}

	switch(type) {
	case LTTNG_DOMAIN_KERNEL:
		config->domain_type = LTTNG_DOMAIN_KERNEL;
		break;
	case LTTNG_DOMAIN_UST:
		config->domain_type = LTTNG_DOMAIN_UST;
		break;
	case LTTNG_DOMAIN_JUL:
		config->domain_type = LTTNG_DOMAIN_JUL;
		break;
	case LTTNG_DOMAIN_LOG4J:
		config->domain_type = LTTNG_DOMAIN_LOG4J;
		break;
	case LTTNG_DOMAIN_PYTHON:
		config->domain_type = LTTNG_DOMAIN_PYTHON;
		break;
	case LTTNG_DOMAIN_NONE:
	default:
		free(config);
		config=NULL;
		goto end;
	};

	config->event_type = LTTNG_EVENT_ALL ;
	config->enable_all = 0;
	config->loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;
	config->loglevel = NULL;
	config->probe = NULL;
	config->function = NULL;
	config->channel_name = NULL;
	config->filter = NULL;
	config->exclude = NULL;
	config->event_list = NULL;
end:
	return config;
}

int cmd_enable_events(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
	static poptContext pc;
	char *session_name = NULL;
	int event_type = -1;
	int i;
	int args_tuple_count = 0;
	int arg_state_looking_for_end = 0;
	struct args_tuple *args_tuple_list = NULL;
	struct domain_configuration *tmp_config = NULL;

	struct config_document *template = NULL;

	struct domain_configuration *jul_config = NULL;
	struct domain_configuration *kernel_config = NULL;
	struct domain_configuration *log4j_config = NULL;
	struct domain_configuration *python_config = NULL;
	struct domain_configuration *ust_config = NULL;

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		/* Open command element */
		ret = mi_lttng_writer_command_open(writer,
				mi_lttng_element_command_enable_event);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer,
				mi_lttng_element_command_output);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open the domains element */
		ret = mi_lttng_domains_open(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

	}

	/* Parse global arguments */
	pc = poptGetContext(NULL, argc, argv, global_long_options, 0);
	poptReadDefaultConfig(pc, 0);


	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			break;
		}
	}

	/* Dispose the global arguments context */
	poptFreeContext(pc);
	pc = NULL;

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			command_ret = CMD_ERROR;
			success = 0;
			goto mi_closing;
		}
	} else {
		session_name = opt_session_name;
	}

	/* Find the number of domain based on the passed arguments */
	for (i = 1; i < argc ; i++) {

		if (strcmp("-u", argv[i]) && strcmp("--userspace", argv[i]) &&
			strcmp("-j", argv[i]) && strcmp("--jul", argv[i]) &&
			strcmp("-l", argv[i]) && strcmp("--log4j", argv[i]) &&
			strcmp("-p", argv[i]) && strcmp("--python", argv[i]) &&
			strcmp("-k", argv[i]) && strcmp("--kernel", argv[i])) {
			continue;
		}


		struct args_tuple *tmp_pointer =  NULL;
		args_tuple_count++;
		tmp_pointer = realloc(args_tuple_list, sizeof(struct args_tuple) * args_tuple_count);
		if (!tmp_pointer) {
			ERR("Realoc of args tuple failed");
			ret = CMD_ERROR;
			goto end;
		}
		args_tuple_list = tmp_pointer;

		if (!arg_state_looking_for_end) {
			if (args_tuple_count -1 < 0) {
				ERR("Args parsing illegal state");
				ret = CMD_ERROR;
				goto end;
			}
			args_tuple_list[args_tuple_count-1].argv_index_start = i;
			arg_state_looking_for_end = 1;
		} else {
			if (args_tuple_count - 2 < 0 || args_tuple_count -1 < 0) {
				ERR("Args parsing illegal state");
				ret = CMD_ERROR;
				goto end;
			}

			/* Close the previous tuple */
			args_tuple_list[args_tuple_count-2].argv_index_end = i - 1;

			/* Start the new tuple */
			args_tuple_list[args_tuple_count-1].argv_index_start = i;
		}
	}

	if (args_tuple_count == 0 && !opt_template_path) {
		ret = print_missing_or_multiple_domains(0);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
		goto end;
	} else if (args_tuple_count > 0) {
		/* Close the last tuple */
		args_tuple_list[args_tuple_count-1].argv_index_end = i - 1;

		if (args_tuple_count == 1) {
			/* Preserve the old way with a domain flag that can be anywhere */
			args_tuple_list[0].argv_index_start = 1;
		}
	}

	for (i = 0; i < args_tuple_count; i++) {
		struct args_tuple *tuple = &args_tuple_list[i];
		int cur_argc = tuple->argv_index_end - tuple-> argv_index_start + 1;
		const char **cur_argv = &argv[tuple->argv_index_start];

		/* Default options */

		/* Domain */
		opt_domain = LTTNG_DOMAIN_NONE;

		/* Event options */
		opt_enable_all = 0;
		opt_event_type = LTTNG_EVENT_ALL;
		opt_loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;
		opt_event_list = NULL;
		opt_loglevel = NULL;
		opt_probe = NULL;
		opt_function = NULL;
		opt_channel_name = NULL;
		opt_filter = NULL;
		opt_exclude = NULL;

		pc = poptGetContext(NULL, cur_argc, cur_argv, long_options, POPT_CONTEXT_KEEP_FIRST);
		poptReadDefaultConfig(pc, 0);

		/* Default event type */
		opt_event_type = LTTNG_EVENT_ALL;

		while ((opt = poptGetNextOpt(pc)) != -1) {
			switch (opt) {
			case OPT_HELP:
				SHOW_HELP();
				goto end;
			case OPT_TRACEPOINT:
				opt_event_type = LTTNG_EVENT_TRACEPOINT;
				break;
			case OPT_PROBE:
				opt_event_type = LTTNG_EVENT_PROBE;
				break;
			case OPT_FUNCTION:
				opt_event_type = LTTNG_EVENT_FUNCTION;
				break;
			case OPT_SYSCALL:
				opt_event_type = LTTNG_EVENT_SYSCALL;
				break;
			case OPT_LOGLEVEL:
				opt_loglevel_type = LTTNG_EVENT_LOGLEVEL_RANGE;
				opt_loglevel = poptGetOptArg(pc);
				break;
			case OPT_LOGLEVEL_ONLY:
				opt_loglevel_type = LTTNG_EVENT_LOGLEVEL_SINGLE;
				opt_loglevel = poptGetOptArg(pc);
				break;
			case OPT_LIST_OPTIONS:
				list_cmd_options(stdout, long_options);
				goto end;
			case OPT_FILTER:
				break;
			case OPT_EXCLUDE:
				break;
			default:
				ret = CMD_UNDEFINED;
				goto end;
			}

			/* Validate event type. Multiple event type are not supported. */
			if (event_type == -1) {
				event_type = opt_event_type;
			} else {
				if (event_type != opt_event_type) {
					ERR("Multiple event type not supported.");
					ret = CMD_ERROR;
					goto end;
				}
			}
		}

		tmp_config = initialize_domain_configuration(opt_domain);

		opt_event_list = (char*) poptGetArg(pc);
		if (opt_event_list == NULL && opt_enable_all == 0 && !opt_template_path) {
			ERR("Missing event name(s).\n");
			ret = CMD_ERROR;
			goto end;
		}

		/* Option check */
		if (opt_domain == LTTNG_DOMAIN_KERNEL) {
			if (opt_loglevel) {
				WARN("Kernel loglevels are not supported.");
			}
		}

		if (opt_exclude) {
			switch (opt_domain) {
			case LTTNG_DOMAIN_KERNEL:
			case LTTNG_DOMAIN_JUL:
			case LTTNG_DOMAIN_LOG4J:
			case LTTNG_DOMAIN_PYTHON:
				ERR("Event name exclusions are not yet implemented for %s events",
					get_domain_str(opt_domain));
				ret = CMD_ERROR;
				goto end;
			case LTTNG_DOMAIN_UST:
				/* Exclusions supported */
				break;
			default:
				assert(0);
			}
		}

		if (opt_template_path) {
			if (event_type != LTTNG_EVENT_ALL) {
				WARN("Type options for events while using a template have no effect (--function,--probe,--syscall,--tracepoint).");
			}
			if (opt_enable_all) {
				WARN("The all (-a) shortcut for enabling all events while using a template have no effect.");
			}
		}

		tmp_config->event_type = event_type ;
		tmp_config->enable_all = opt_enable_all;
		tmp_config->loglevel_type = opt_loglevel_type;
		tmp_config->loglevel = opt_loglevel;
		tmp_config->probe = opt_probe;
		tmp_config->function = opt_function;
		tmp_config->channel_name = opt_channel_name;
		tmp_config->filter = opt_filter;
		tmp_config->exclude = opt_exclude;
		tmp_config->event_list = opt_event_list;


		switch(opt_domain) {
		case LTTNG_DOMAIN_KERNEL:
			if (kernel_config) {
				ERR("Only one -k option is permitted per command");
				ret = CMD_ERROR;
				goto end;
			}
			kernel_config = tmp_config;
			break;
		case LTTNG_DOMAIN_UST:
			if (ust_config) {
				ERR("Only one -u option is permitted per command");
				ret = CMD_ERROR;
				goto end;
			}
			ust_config = tmp_config;
			break;
		case LTTNG_DOMAIN_JUL:
			if (jul_config) {
				ERR("Only one -j option is permitted per command");
				ret = CMD_ERROR;
				goto end;
			}
			jul_config = tmp_config;
			break;
		case LTTNG_DOMAIN_LOG4J:
			if (log4j_config) {
				ERR("Only one -l option is permitted per command");
				ret = CMD_ERROR;
				goto end;
			}
			log4j_config = tmp_config;
			break;
		case LTTNG_DOMAIN_PYTHON:
			if (python_config) {
				ERR("Only one -p option is permitted per command");
				ret = CMD_ERROR;
				goto end;
			}
			python_config = tmp_config;
			break;
		case LTTNG_DOMAIN_NONE:
		default:
			ret = CMD_ERROR;
			goto end;
		}

		tmp_config = NULL;

		poptFreeContext(pc);
		pc = NULL;
	}


	if (opt_template_path) {
		/* validate template */
		template = config_document_get(opt_template_path, 0);
		if (!template) {
			ERR("Could not load the template");
			ret = CMD_ERROR;
			goto end;
		}
		/* TODO: validate the xml */
		/* Only one session, only one channel per domain */
		if (!kernel_config) {
			kernel_config = initialize_domain_configuration(LTTNG_DOMAIN_KERNEL);
			if (!kernel_config) {
				ERR("Default initialization for kernel domain configuration");
				ret = CMD_ERROR;
				goto end;
			}
		}

		if (!ust_config) {
			ust_config = initialize_domain_configuration(LTTNG_DOMAIN_UST);
			if (!ust_config) {
				ERR("Default initialization for ust domain configuration");
				ret = CMD_ERROR;
				goto end;
			}
		}

		if (!jul_config) {
			jul_config = initialize_domain_configuration(LTTNG_DOMAIN_JUL);
			if (!jul_config) {
				ERR("Default initialization for jul domain configuration");
				ret = CMD_ERROR;
				goto end;
			}
		}

		if (!log4j_config) {
			log4j_config = initialize_domain_configuration(LTTNG_DOMAIN_LOG4J);
			if (!log4j_config) {
				ERR("Default initialization for log4j domain configuration");
				ret = CMD_ERROR;
				goto end;
			}
		}

		if (!python_config) {
			python_config = initialize_domain_configuration(LTTNG_DOMAIN_PYTHON);
			if (!python_config) {
				ERR("Default initialization for python domain configuration");
				ret = CMD_ERROR;
				goto end;
			}
		}

		command_ret = enable_event_from_template(template, session_name, kernel_config, ust_config,
				jul_config, log4j_config, python_config);

		goto end;
	}

	if (kernel_config) {
		command_ret = enable_events(session_name, kernel_config);
		if (command_ret) {
			success = 0;
		}
	}

	if (ust_config) {
		command_ret = enable_events(session_name, ust_config);
		if (command_ret) {
			success = 0;
		}
	}

	if (jul_config) {
		command_ret = enable_events(session_name, jul_config);
		if (command_ret) {
			success = 0;
		}
	}

	if (log4j_config) {
		command_ret = enable_events(session_name, log4j_config);
		if (command_ret) {
			success = 0;
		}
	}

	if (python_config) {
		command_ret = enable_events(session_name, python_config);
		if (command_ret) {
			success = 0;
		}
	}

mi_closing:
	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close domains and output element */
		ret = mi_lttng_close_multi_element(writer, 2);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		ret = mi_lttng_writer_write_element_bool(writer,
				mi_lttng_element_command_success, success);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Command element close */
		ret = mi_lttng_writer_command_close(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

end:
	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		ret = ret ? ret : LTTNG_ERR_MI_IO_FAIL;
	}

	if (opt_session_name == NULL) {
		free(session_name);
	}

	/* Overwrite ret if an error occurred in enable_events */
	ret = command_ret ? command_ret : ret;

	config_document_free(template);
	free(args_tuple_list);
	free(tmp_config);
	free(jul_config);
	free(kernel_config);
	free(log4j_config);
	free(python_config);
	free(ust_config);
	poptFreeContext(pc);
	return ret;
}
