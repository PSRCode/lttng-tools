/*
 * Copyright (C) 2017 - Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <sys/types.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <limits.h>

#include <common/compat/getenv.h>
#include <common/time.h>
#include <common/defaults.h>

#include "tcp_keep_alive.h"

#define SOLARIS_IDLE_TIME_MIN_S 10
#define SOLARIS_IDLE_TIME_MAX_S 864000 /* 10 days */

/* Per-platform definition of TCP socket option */
#ifdef __sun__
#define COMPAT_TCP_KEEPIDLE TCP_KEEPALIVE_THRESHOLD
#define COMPAT_SOL_TCP IPPROTO_TCP /* Solaris does not support SOL_TCP */
#else
#define COMPAT_TCP_KEEPIDLE TCP_KEEPIDLE
#define COMPAT_SOL_TCP SOL_TCP
#endif /* __sun__ */

struct tcp_keep_alive_support {
	/* TCP keep-alive is supported by this platform. */
	bool supported;
	/* Overriding idle-time per socket is supported by this
	 * platform.
	 */
	bool idle_time_supported;
	/* Overriding probe interval per socket is supported by this
	 * platform.
	 */
	bool probe_interval_supported;
	/* Configuring max probe count per socket is supported by this
	 * platform.
	 */
	bool max_probe_count_supported;
};

struct tcp_keep_alive_config {
	bool initialized;
	/* Maps to the environment variable defined
	 * by LTTNG_RELAYD_TCP_KEEPALIVE_ENV
	 */
	bool enabled;
	/* Maps to the environment variable defined
	 * by LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV
	 */
	int idle_time_print;
	/* Platform dependant value for idle_time */
	int idle_time;
	/* Maps to the environment variable defined
	 * by LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBE_INTERVAL_ENV
	 */
	int probe_interval;
	/* Maps to the environment variable defined
	 * by LTTNG_RELAYD_TCP_KEEP_ALIVE_MAX_PROBE_COUNT_ENV
	 */
	int max_probe_count;
};

static struct tcp_keep_alive_config config = {
	.initialized = false,
	.enabled = false,
	.idle_time_print = 0,
	.idle_time = 0,
	.probe_interval = 0,
	.max_probe_count = 0
};

static struct tcp_keep_alive_support support = {
	.supported = false,
	.idle_time_supported = false,
	.probe_interval_supported = false,
	.max_probe_count_supported = false
};


static
bool long_to_int_overflowing(long value){
	if (value > INT_MAX) {
		return true;
	}
	return false;
}

/*
 * Common parser for string to positive int conversion where the value must be
 * in range [0, INT_MAX].
 * Returns -1 on invalid value.
 */
static
int tcp_keep_alive_string_to_pos_int_parser(const char *env_var, const char *value)
{
	int ret;
	long tmp;
	char *endptr = NULL;

	errno = 0;
	tmp = strtol(value, &endptr, 0);
	if (errno != 0) {
		ERR("%s cannot be parsed.", env_var);
		PERROR("Errno for previous parsing failure.");
		ret = -1;
		goto end;
	}

	if (endptr == value || *endptr != '\0') {
	    ERR("%s is not a valid number.", env_var);
	    ret = -1;
	    goto end;
	}

	if (tmp < 0) {
		ERR("%s must be greater or equal to 0.", env_var);
		ret = -1;
		goto end;
	}
	if (long_to_int_overflowing(tmp)){
		ERR("%s is too big. Maximum value is %d.", env_var, INT_MAX);
		ret = -1;
		goto end;
	}

	ret = (int) tmp;
end:
	return ret;

}

/*
 * Per-platform implementation of tcp_keep_alive_idle_time_parser.
 * Returns -1 on invalid value.
 */
#ifdef __sun__
static int tcp_keep_alive_idle_time_parser(const char *value)
{
	int ret;
	int tmp;
	unsigned int tmp_ms;

	/* Parse base value in seconds. */
	tmp = tcp_keep_alive_string_to_pos_int_parser(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV, value);

	/*
	 * Additional constraints for Solaris.
	 * Minimum 10s , maximum 10 days. Defined by
	 * https://docs.oracle.com/cd/E23824_01/html/821-1475/tcp-7p.html#REFMAN7tcp-7p
	 */
	if (tmp != 0 && (tmp < SOLARIS_IDLE_TIME_MIN_S || tmp > SOLARIS_IDLE_TIME_MAX_S)) {
		ERR("%s must be comprised between %d and %d inclusively on Solaris.",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV,
				SOLARIS_IDLE_TIME_MIN_S,
				SOLARIS_IDLE_TIME_MAX_S);
		ret = -1;
		goto end;
	}

	/* On Solaris idle time is given in milliseconds. */
	tmp_ms = (unsigned int) tmp * MSEC_PER_SEC;
	if ((tmp != 0 && (tmp_ms / (unsigned int) tmp) != MSEC_PER_SEC ) || tmp_ms > INT_MAX){
		/* Overflow */
		int max_possible_value = INT_MAX / MSEC_PER_SEC;
		ERR("%s is too big. Maximum value is %d.",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV,
				max_possible_value);
		ret = -1;
		goto end;
	}

	/* tmp_ms is > 0 and <= INT_MAX. Cast is safe */
	ret = (int) tmp_ms;
end:
	return ret;
}
#else
static int tcp_keep_alive_idle_time_parser(const char *value)
{
	return tcp_keep_alive_string_to_pos_int_parser(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV, value);
}
#endif /* __sun__ */

/* Per-platform support of tcp_keep_alive functionality. */
#ifdef __sun__
static
void tcp_keep_alive_init_support(struct tcp_keep_alive_support *support)
{
	support->supported = true;
#ifdef TCP_KEEPALIVE_THRESHOLD
	support->idle_time_supported = true;
#else
	support->idle_time_supported = false;;
#endif /* TCP_KEEPALIVE_THRESHOLD */

	/* Sun does not support either tcp_keepalive_probes or
	 * tcp_keepalive_intvl. Inferring a value for
	 * TCP_KEEPALIVE_ABORT_THRESHOLD doing
	 * tcp_keepalive_probes * tcp_keepalive_intvl could yield a good
	 * alternative but Solaris does not detail the algorithm used (constant
	 * time retry like linux or something fancier). Ignore those
	 * setting on Solaris for now.
	 */
	support->probe_interval_supported = false;
	support->max_probe_count_supported = false;
}
#else
static
void tcp_keep_alive_init_support(struct tcp_keep_alive_support *support)
{
	support->supported = true;
	support->idle_time_supported = true;
	support->probe_interval_supported = true;
	support->max_probe_count_supported = true;
}
#endif /* (__sun__) */


/* Retrieve settings from env vars and check/warn if supported by platform. */
static
int tcp_keep_alive_init_config(struct tcp_keep_alive_support *support, struct tcp_keep_alive_config *config)
{
	int ret;
	const char *value;

	config->initialized = true;

	value = lttng_secure_getenv(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_ENV);
	if (value && !support->supported) {
		WARN("Using per-socket TCP Keep-alive mechanism is not supported by this platform. Ignoring the %s environment variable.",
			DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_ENV);
		config->enabled = false;
	} else if (value && !strcmp(value, "1")) {
		config->enabled = true;
	} else {
		config->enabled = false;
	}

	/* Get value for tcp_keepalive_time in seconds*/
	value = lttng_secure_getenv(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV);
	if (value && !support->idle_time_supported) {
		WARN("Overriding the TCP keep-alive idle time threshold per-socket is not supported by this platform. Ignoring the %s environment variable.",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV);
	} else if (value) {
		int idle_time_platform;
		int idle_time_seconds;;
		idle_time_platform = tcp_keep_alive_idle_time_parser(value);
		if (idle_time_platform < 0) {
			ret = 1;
			goto error;
		}

		idle_time_seconds = tcp_keep_alive_string_to_pos_int_parser(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV, value);
		if (idle_time_seconds < 0) {
			ERR("tcp_keep_alive_string_to_pos_int_parser is a subset of tcp_keep_alive_idle_time_parser. Should never fails.");
			abort();
		}
		config->idle_time = idle_time_platform;
		config->idle_time_print = idle_time_seconds;
	}

	/* Get value for tcp_keepalive_intvl in seconds */
	value = lttng_secure_getenv(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBE_INTERVAL_ENV);
	if (value && !support->probe_interval_supported) {
		WARN("Overriding the TCP keep-alive probe interval time per-socket is not supported by this platform. Ignoring the %s environment variable.",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBE_INTERVAL_ENV);
	} else if (value) {
		int probe_interval;
		probe_interval = tcp_keep_alive_string_to_pos_int_parser(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBE_INTERVAL_ENV, value);
		if (probe_interval < 0) {
			ret = 1;
			goto error;
		}
		config->probe_interval = probe_interval;
	}

	/* Get value for tcp_keepalive_probes */
	value = lttng_secure_getenv(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_MAX_PROBE_COUNT_ENV);
	if (value && !support->max_probe_count_supported) {
		WARN("Overriding the TCP keep-alive maximum probe count per-socket is not supported by this platform. Ignoring the %s environment variable.",
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_MAX_PROBE_COUNT_ENV);
	} else if (value) {
		int max_probe_count;
		max_probe_count = tcp_keep_alive_string_to_pos_int_parser(
				DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_MAX_PROBE_COUNT_ENV,
				value);
		if (max_probe_count < 0) {
			ret = 1;
			goto error;
		}
		config->max_probe_count = max_probe_count;
	}

	if (config->enabled) {
		DBG(DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_ENV " enabled");
	}
	if (config->idle_time > 0) {
		DBG("Overriding %s to %d",
			DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV,
			config->idle_time_print);
	}
	if (config->probe_interval > 0) {
		DBG("Overriding %s to %d",
			DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBE_INTERVAL_ENV,
			config->probe_interval);
	}
	if (config->max_probe_count > 0) {
		DBG("Overriding %s to %d",
			DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_MAX_PROBE_COUNT_ENV,
			config->max_probe_count);
	}
	ret = 0;

error:
	return ret;
}

int tcp_keep_alive_init(void)
{
	tcp_keep_alive_init_support(&support);
	return tcp_keep_alive_init_config(&support, &config);
}

/*
 * Set the socket options regarding tcp_keepalive.
 */
int socket_apply_keep_alive_config(int socket_fd)
{
	int ret;
	int val = 1;

	if (!config.initialized) {
		ERR("TCP keep-alive configuration is not initialized.");
		abort();
	}

	/* TCP keep-alive */
	if (!support.supported || !config.enabled ) {
		ret = 0;
		goto end;
	}

	ret = setsockopt(socket_fd, COMPAT_SOL_TCP, SO_KEEPALIVE, &val,
			sizeof(val));
	if (ret < 0) {
		PERROR("setsockopt so_keepalive");
		goto end;
	}

	/* TCP keep-alive idle time */
	if (support.idle_time_supported && config.idle_time > 0) {
		ret = setsockopt(socket_fd, COMPAT_SOL_TCP, COMPAT_TCP_KEEPIDLE, &config.idle_time,
				sizeof(config.idle_time));
		if (ret < 0) {
			PERROR("setsockopt TCP_KEEPIDLE");
			goto end;
		}
	}
	/* TCP keep-alive probe interval */
	if (support.probe_interval_supported && config.probe_interval > 0) {
		ret = setsockopt(socket_fd, COMPAT_SOL_TCP, TCP_KEEPINTVL, &config.probe_interval,
				sizeof(config.probe_interval));
		if (ret < 0) {
			PERROR("setsockopt TCP_KEEPINTVL");
			goto end;
		}
	}

	/* TCP keep-alive max probe count */
	if (support.max_probe_count_supported && config.max_probe_count > 0) {
		ret = setsockopt(socket_fd, COMPAT_SOL_TCP, TCP_KEEPCNT, &config.max_probe_count,
				sizeof(config.max_probe_count));
		if (ret < 0) {
			PERROR("setsockopt TCP_KEEPCNT");
			goto end;
		}
	}
end:
	return ret;
}
