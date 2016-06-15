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
	{"session",        's', POPT_ARG_NONE, 0, 0, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

static struct poptOption global_long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/* Represent an event to be enabled */
struct internal_event {
	char *session_name;
	char *channel_name;
	enum lttng_domain_type domain_type;
	struct lttng_event *event;
	int exclusion_list_size;
	char **exclusion_list;
	char *filter_expression;
};

/* Represent the a set of configuration for a given domain */
struct domain_configuration {
	enum lttng_domain_type domain_type;

	enum lttng_event_type event_type;
	int enable_all;
	char *event_list;

	char *loglevel;
	int loglevel_type;

	char *probe;
	char *function;
	char *channel_name;
	char *filter;
	char *exclude;
};

/* Represent a subset of the command line */
struct args_tuple {
	int argv_index_start;
	int argv_index_end;
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
int loglevel_str_to_value(const char *inputstr)
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

static void free_internal_event_list(struct internal_event *event_list,
		const unsigned int size)
 {
       if (size == 0 && event_list) {
	       assert(0);
       }

       if (size == 0) {
	       goto end;
       }

       for (int i = 0; i < size ; i++) {
	       free(event_list[i].event);
	       free(event_list[i].filter_expression);
	       free(event_list[i].session_name);
	       free(event_list[i].channel_name);

               if (event_list[i].exclusion_list) {
                       unsigned int count = event_list[i].exclusion_list_size;
                       for (int j = 0; j < count; j++) {
                               free(event_list->exclusion_list[j]);
                       }
               }
               free(event_list[i].exclusion_list);
       }
end:
       free(event_list);
}


/*
 * Responsible for user output and mi output per event.
 */
static int generate_output_per_event(struct internal_event *internal_event,
		int command_ret)
{
	int ret = CMD_SUCCESS;
	char *exclusion_string = NULL;
	char *session_name;
	char *channel_name;
	char *filter_expression;
	enum lttng_domain_type domain_type;
	struct lttng_event *ev;
	int success;

	char *empty_string = "";

	assert(internal_event);
	assert(internal_event->session_name);
	assert(domain_type = internal_event->domain_type);
	assert(internal_event->event);
	assert(internal_event->event->name);

	session_name =  internal_event->session_name;
	channel_name = internal_event->channel_name;
	domain_type = internal_event->domain_type;
	ev = internal_event->event;

	if (internal_event->filter_expression) {
		filter_expression = internal_event->filter_expression;
	} else {
		filter_expression = empty_string;
	}

	if (command_ret < 0) {
		success = 0;
	} else {
		success = 1;
	}

	exclusion_string = print_exclusions(internal_event->exclusion_list_size,
			internal_event->exclusion_list);

	if (!exclusion_string) {
		PERROR("Cannot allocate exclusion_string");
		ret = CMD_ERROR;
		goto error;
	}

	if (command_ret < 0) {
		switch (-command_ret) {
		case LTTNG_ERR_FILTER_EXIST:
			WARN("Filter on event %s%s is already enabled"
					" (domain %s, channel %s, session %s)",
				ev->name,
				exclusion_string,
				get_domain_str(domain_type),
				print_channel_name(channel_name), session_name);
			break;
		case LTTNG_ERR_TRACE_ALREADY_STARTED:
		{
			const char *msg = "The command tried to enable an event in a new domain for a session that has already been started once.";
			ERR("Event %s%s: %s (domain %s, channel %s, session %s, filter \'%s\')", ev->name,
					exclusion_string,
					msg,
					get_domain_str(domain_type),
					print_channel_name(channel_name),
					session_name, filter_expression);
			break;
		}
		case LTTNG_ERR_KERN_EVENT_EXIST:
			WARN("Kernel event %s%s already enabled (channel %s, session %s)",
					ev->name,
					exclusion_string,
					print_channel_name(channel_name), session_name);
			break;
		default:
			ERR("Event %s%s: %s (domain %s, channel %s, session %s, filter \'%s\')",
					ev->name,
					exclusion_string,
					lttng_strerror(command_ret),
					get_domain_str(domain_type),
					command_ret == -LTTNG_ERR_NEED_CHANNEL_NAME
						? print_raw_channel_name(channel_name)
						: print_channel_name(channel_name),
					session_name, filter_expression);
			break;
		}
	} else {
		if (internal_event->filter_expression) {
			MSG("Event %s%s: Filter '%s' for domain %s successfully set",
					ev->name, exclusion_string,
					filter_expression,
					get_domain_str(domain_type));
		} else {
			MSG("%s event %s%s created in channel %s",
					get_domain_str(domain_type),
					ev->name,
					exclusion_string,
					print_channel_name(channel_name));
		}
	}


	if (lttng_opt_mi) {
		ret = mi_lttng_event(writer, ev, 1, domain_type);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}

		/* print exclusion */
		ret = mi_print_exclusion(internal_event->exclusion_list_size,
				internal_event->exclusion_list);
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
error:
	free(exclusion_string);
	return ret;
}

/*
 * Enabling event using the lttng API.
 * Note: in case of error only the last error code will be return.
 */
static int enable_events(char *session_name, struct domain_configuration *config)
{
	int ret = CMD_SUCCESS, command_ret = CMD_SUCCESS;
	int error_holder = CMD_SUCCESS, warn = 0, error = 0, success = 1;
	char *event_name, *channel_name = NULL;
	struct lttng_domain dom;
	int exclusion_count = 0;
	char **exclusion_list = NULL;
	struct lttng_handle *handle;

	struct internal_event *internal_event_list = NULL;
	unsigned int internal_event_list_size = 0;

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

	if (config_domain_type == LTTNG_DOMAIN_KERNEL) {
		if (config_loglevel) {
			WARN("Kernel loglevels are not supported.");
		}
	}

	/* Create lttng domain and handle */
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

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	if (config_exclude) {
		switch (dom.type) {
		case LTTNG_DOMAIN_KERNEL:
		case LTTNG_DOMAIN_JUL:
		case LTTNG_DOMAIN_LOG4J:
		case LTTNG_DOMAIN_PYTHON:
			ERR("Event name exclusions are not yet implemented for %s events",
					get_domain_str(dom.type));
			ret = CMD_ERROR;
			goto error;
		case LTTNG_DOMAIN_UST:
			/* Exclusions supported */
			break;
		default:
			assert(0);
		}
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

	channel_name = config_channel_name;

	/* TODO: move enabling of all event to its own function */
	if (config_enable_all) {
		struct lttng_event ev;
		memset(&ev, 0, sizeof(ev));
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
				assert(config_domain_type != LTTNG_DOMAIN_NONE || config_domain_type != LTTNG_DOMAIN_KERNEL);
				switch (config_domain_type) {
				case LTTNG_DOMAIN_UST:
					ev.loglevel = loglevel_str_to_value(config_loglevel);
					break;
				case LTTNG_DOMAIN_JUL:
					ev.loglevel = loglevel_jul_str_to_value(config_loglevel);
					break;
				case LTTNG_DOMAIN_LOG4J:
					ev.loglevel = loglevel_log4j_str_to_value(config_loglevel);
					break;
				case LTTNG_DOMAIN_PYTHON:
					ev.loglevel = loglevel_python_str_to_value(config_loglevel);
					break;
				default:
					assert(0);
				}

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

	/* Count the number of events */
	if (!config_event_list) {
		/* Nothing to do */
		goto end;
	}

	char *tmp = config_event_list;

	/* There will be at last 1 event */
	internal_event_list_size = 1;
	while ((tmp = strchr(tmp, ',')) != NULL) {
		internal_event_list_size++;
		tmp++;
	}

	/* Initialize array of event */
	internal_event_list = calloc(internal_event_list_size, sizeof(struct internal_event));
	for (int i = 0; i < internal_event_list_size; i++) {
		        internal_event_list[i].event = zmalloc(sizeof(struct lttng_event));
			if (!internal_event_list[i].event) {
				ERR("Error initializing events array");
				ret = CMD_ERROR;
				goto error;
			}

			/* Set minimal internal event information */
			internal_event_list[i].session_name = strdup(session_name);
			if (!internal_event_list[i].session_name) {
				ERR("Session name duplication failed");
				ret = CMD_ERROR;
				goto error;
			}


			if (config_channel_name) {
				internal_event_list[i].channel_name = strdup(config_channel_name);
			}
			internal_event_list[i].domain_type = config_domain_type;
			internal_event_list[i].filter_expression = NULL;
	}

	/* Strip command line event list */
	for (int i = 0; i < internal_event_list_size; i++) {
		/* Copy name and type of the event */
		struct lttng_event *ev = internal_event_list[i].event;
		struct internal_event *int_event = &internal_event_list[i];

		if (i == 0) {
			event_name = strtok(config_event_list, ",");
		} else {
			event_name = strtok(NULL, ",");
		}
		strncpy(ev->name, event_name, LTTNG_SYMBOL_NAME_LEN);
		ev->name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		ev->type = config_event_type;

		/* Kernel tracer action */
		switch (config_domain_type) {
		case LTTNG_DOMAIN_KERNEL:
			DBG("Enabling kernel event %s for channel %s",
					event_name,
					print_channel_name(channel_name));

			/* Set the event type */
			switch (config_event_type) {
			case LTTNG_EVENT_ALL:	/* Enable tracepoints and syscalls */
				/* If event name differs from *, select tracepoint. */
				if (strcmp(ev->name, "*")) {
					ev->type = LTTNG_EVENT_TRACEPOINT;
				}
				break;
			case LTTNG_EVENT_TRACEPOINT:
				break;
			case LTTNG_EVENT_PROBE:
				ret = parse_probe_opts(ev, config_probe);
				if (ret) {
					ERR("Unable to parse probe options");
					ret = 0;
					goto error;
				}
				break;
			case LTTNG_EVENT_FUNCTION:
				ret = parse_probe_opts(ev, config_function);
				if (ret) {
					ERR("Unable to parse function probe options");
					ret = 0;
					goto error;
				}
				break;
			case LTTNG_EVENT_SYSCALL:
				ev->type = LTTNG_EVENT_SYSCALL;
				break;
			default:
				ret = CMD_UNDEFINED;
				goto error;
			}

			/* kernel loglevels not implemented */
			ev->loglevel_type = LTTNG_EVENT_LOGLEVEL_ALL;
			break;
		case LTTNG_DOMAIN_UST:
			/* User-space tracer action */
			DBG("Enabling UST event %s for channel %s, loglevel %s", ev->name,
					print_channel_name(int_event->channel_name), config_loglevel ? : "<all>");


			/* Set the event type */
			switch (config_event_type) {
			case LTTNG_EVENT_ALL:	/* Default behavior is tracepoint */
				/* Fall-through */
			case LTTNG_EVENT_TRACEPOINT:
				ev->type = LTTNG_EVENT_TRACEPOINT;
				break;
			case LTTNG_EVENT_PROBE:
			case LTTNG_EVENT_FUNCTION:
			case LTTNG_EVENT_SYSCALL:
			default:
				ERR("Event type not available for user-space tracing");
				ret = CMD_UNSUPPORTED;
				goto error;
			}

			/* Set the exclusion */
			if (config_exclude) {
				ev->exclusion = 1;
				if (ev->type != LTTNG_EVENT_ALL && ev->type != LTTNG_EVENT_TRACEPOINT) {
					ERR("Exclusion option can only be used with tracepoint events");
					ret = CMD_ERROR;
					goto error;
				}
				/* Check for proper subsets */
				ret = check_exclusion_subsets(ev->name, config_exclude,
						&int_event->exclusion_list_size, &int_event->exclusion_list);
				if (ret == CMD_ERROR) {
					goto error;
				}

				warn_on_truncated_exclusion_names(
					int_event->exclusion_list,
					int_event->exclusion_list_size, &warn);

			}

			/* Set the log level type */
			ev->loglevel_type = config_loglevel_type;

			/* Set the loglevel */
			if (config_loglevel) {
				ev->loglevel = loglevel_str_to_value(config_loglevel);
				if (ev->loglevel == -1) {
					ERR("Unknown loglevel %s", config_loglevel);
					ret = -LTTNG_ERR_INVALID;
					goto error;
				}
			} else {
				ev->loglevel = -1;
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
			/* Defaut the type */
			ev->type = LTTNG_EVENT_TRACEPOINT;

			/* Set the loglevel type */
			ev->loglevel_type = config_loglevel_type;

			/* Set the loglevel */
			if (config_loglevel) {
				switch (config_domain_type) {
				case LTTNG_DOMAIN_JUL:
					ev->loglevel = loglevel_jul_str_to_value(config_loglevel);
					break;
				case LTTNG_DOMAIN_LOG4J:
					ev->loglevel = loglevel_log4j_str_to_value(config_loglevel);
					break;
				case LTTNG_DOMAIN_PYTHON:
					ev->loglevel = loglevel_python_str_to_value(config_loglevel);
					break;
				default:
					assert(0);
					break;
				}

				if (ev->loglevel == -1) {
					ERR("Unknown loglevel %s", config_loglevel);
					ret = -LTTNG_ERR_INVALID;
					goto error;
				}
			} else {
				switch (config_domain_type) {
				case LTTNG_DOMAIN_JUL:
					ev->loglevel = LTTNG_LOGLEVEL_JUL_ALL;
					break;
				case LTTNG_DOMAIN_LOG4J:
					ev->loglevel = LTTNG_LOGLEVEL_LOG4J_ALL;
					break;
				case LTTNG_DOMAIN_PYTHON:
					ev->loglevel = LTTNG_LOGLEVEL_PYTHON_DEBUG;
					break;
				default:
					assert(0);
					break;
				}
			}
			break;
		default:
			assert(0);
		}

		/* Set the filter */
		if (config_filter) {
			ev->filter = 1;
			int_event->filter_expression = config_filter;
			if (!int_event->filter_expression) {
				ERR("Duplication of filter string");
				ret = CMD_ERROR;
				goto error;
			}
		}

	}

	/* Enable the vents */
	for (int i = 0; i < internal_event_list_size; i++) {
		command_ret = lttng_enable_event_with_exclusions(handle,
				internal_event_list[i].event,
				internal_event_list[i].channel_name,
				internal_event_list[i].filter_expression,
				internal_event_list[i].exclusion_list_size,
				internal_event_list[i].exclusion_list);

		if (command_ret < 0 ) {
			error_holder = command_ret;
			switch (-command_ret){
			case LTTNG_ERR_FILTER_EXIST:
				warn = 1;
				break;
			case LTTNG_ERR_TRACE_ALREADY_STARTED:
				error = 1;
				break;
			case LTTNG_ERR_KERN_EVENT_EXIST:
				warn = 1;
				break;
			default:
				error = 1;
				break;
			}
			internal_event_list[i].event->enabled = 0;
		} else {
			internal_event_list[i].event->enabled = 1;
		}

		ret = generate_output_per_event(&internal_event_list[i], command_ret);
		if (ret != CMD_SUCCESS) {
			goto error;
		}
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

	free_internal_event_list(internal_event_list, internal_event_list_size);

	/* Overwrite ret with error_holder if there was an actual error with
	 * enabling an event.
	 */
	ret = error_holder ? error_holder : ret;

	return ret;
}

/*
 * Add event to trace session
 */



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
	int i;
	int args_tuple_count = 0;
	int arg_state_looking_for_end = 0;
	struct args_tuple *args_tuple_list = NULL;
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

	if (args_tuple_count <= 0) {
		ret = print_missing_or_multiple_domains(0);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
		goto end;
	}

	/* Close the last tuple */
	args_tuple_list[args_tuple_count-1].argv_index_end = i - 1;

	if (args_tuple_count == 1) {
		/* Preserve the old way with a domain flag that can be anywhere */
		args_tuple_list[0].argv_index_start = 1;
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

		struct domain_configuration *tmp_config = initialize_domain_configuration(opt_domain);

		opt_event_list = (char*) poptGetArg(pc);
		if (opt_event_list == NULL && opt_enable_all == 0) {
			ERR("Missing event name(s).\n");
			ret = CMD_ERROR;
			goto end;
		}


		tmp_config->event_type = opt_event_type ;
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

	free(args_tuple_list);
	free(jul_config);
	free(kernel_config);
	free(log4j_config);
	free(python_config);
	free(ust_config);
	poptFreeContext(pc);
	return ret;
}
