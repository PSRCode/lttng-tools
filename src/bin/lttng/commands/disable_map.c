/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <stdio.h>

#include <lttng/map/map.h>

#include "common/argpar/argpar.h"

#include "../command.h"
#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-disable-map.1.h>
;
#endif

enum {
	OPT_HELP,
	OPT_KERNEL,
	OPT_SESSION,
	OPT_USERSPACE,
};

static const
struct argpar_opt_descr disable_map_options[] = {
	{ OPT_HELP, 'h', "help", false },
	{ OPT_SESSION, 's', "session", true },
	{ OPT_USERSPACE, 'u', "userspace", false },
	{ OPT_KERNEL, 'k', "kernel", false },
	ARGPAR_OPT_DESCR_SENTINEL,
};

static
bool assign_string(char **dest, const char *src, const char *opt_name)
{
	bool ret;

	if (*dest) {
		ERR("Duplicate %s given.", opt_name);
		goto error;
	}

	*dest = strdup(src);
	if (!*dest) {
		ERR("Failed to allocate %s string.", opt_name);
		goto error;
	}

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

int cmd_disable_map(int argc, const char **argv)
{
	int ret, i;
	struct argpar_parse_ret argpar_parse_ret = { 0 };
	const char *opt_map_name = NULL;
	enum lttng_error_code error_code_ret;
	bool opt_userspace = false, opt_kernel = false;
	char *opt_session_name = NULL, *session_name = NULL;
	struct lttng_domain dom = {0};
	struct lttng_handle *handle;

	argpar_parse_ret = argpar_parse(argc - 1, argv + 1,
		disable_map_options, true);
	if (!argpar_parse_ret.items) {
		ERR("%s", argpar_parse_ret.error);
		goto error;
	}

	for (i = 0; i < argpar_parse_ret.items->n_items; i++) {
		struct argpar_item *item = argpar_parse_ret.items->items[i];

		if (item->type == ARGPAR_ITEM_TYPE_OPT) {
			struct argpar_item_opt *item_opt =
				(struct argpar_item_opt *) item;

			switch (item_opt->descr->id) {
			case OPT_HELP:
				SHOW_HELP();
				ret = 0;
				goto end;
			case OPT_SESSION:
				if (!assign_string(&opt_session_name, item_opt->arg,
						"-s/--session")) {
					goto error;
				}
				break;
			case OPT_USERSPACE:
				opt_userspace = true;
				break;
			case OPT_KERNEL:
				opt_kernel = true;
				break;
			default:
				abort();
			}

		} else {
			struct argpar_item_non_opt *item_non_opt =
				(struct argpar_item_non_opt *) item;

			if (opt_map_name) {
				ERR("Unexpected argument: %s", item_non_opt->arg);
				goto error;
			}

			opt_map_name = item_non_opt->arg;
		}
	}

	if (!opt_map_name) {
		ERR("Missing `name` argument.");
		goto error;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			goto error;
		}
	} else {
		session_name = opt_session_name;
	}

	/* Check that one and only one domain option was provided. */
	ret = print_missing_or_multiple_domains(
			opt_kernel + opt_userspace, false);
	if (ret) {
		goto error;
	}

	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
		dom.buf_type = LTTNG_BUFFER_GLOBAL;
	} else {
		dom.type=LTTNG_DOMAIN_UST;
		dom.buf_type = LTTNG_BUFFER_PER_UID;
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	error_code_ret = lttng_disable_map(handle, opt_map_name);
	if (error_code_ret != LTTNG_OK) {
		ERR("Error disabling map \"%s\"", opt_map_name);
		goto error;
	}

	MSG("Disabled map `%s`.", opt_map_name);

	ret = 0;
	goto end;

error:
	ret = 1;

end:
	argpar_parse_ret_fini(&argpar_parse_ret);

	return ret;
}
