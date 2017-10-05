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

#include <common/compat/getenv.h>
#include <common/time.h>

#include "tcp_keep_alive.h"

#define LTTNG_RELAYD_TCP_KEEP_ALIVE_ENABLE_ENV "LTTNG_RELAYD_TCP_KEEP_ALIVE_ENABLE"
#define LTTNG_RELAYD_TCP_KEEP_ALIVE_TIME_ENV "LTTNG_RELAYD_TCP_KEEP_ALIVE_TIME"
#define LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBES_ENV "LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBES"
#define LTTNG_RELAYD_TCP_KEEP_ALIVE_INTVL_ENV "LTTNG_RELAYD_TCP_KEEP_ALIVE_INTVL"

#ifdef __sun__
#define COMPAT_TCP_KEEPIDLE TCP_KEEPALIVE_THRESHOLD
#define SOL_TCP IPPROTO_TCP /* Solaris does not support SOL_TCP */
#else
#define COMPAT_TCP_KEEPIDLE TCP_KEEPIDLE
#endif /* __sun__ */

static bool tcp_keepalive_enabled = false;
static int tcp_keepalive_time = -1;
static int tcp_keepalive_intvl = -1;
static int tcp_keepalive_probes = -1;

#ifdef __sun__
static bool tcp_keepalive_time_valid(int value)
{
	bool ret;
	if (value < -1) {
		ret = false;
		goto end;
	}
	if (value == -1) {
		/* Let the system manage the parameter */
		ret = true;
		goto end;
	}
#ifdef TCP_KEEPALIVE_THRESHOLD
	/*
	 * Minimum 10s , maximum 10 days. Defined by
	 * https://docs.oracle.com/cd/E23824_01/html/821-1475/tcp-7p.html#REFMAN7tcp-7p
	 */
	if (value < 10 || value > 864000) {
		ret = false;
		goto end;
	}
	ret = true;
#else
	WARN("Solaris 10 does not support local override of the TCP_KEEP_ALIVE_THRESHOLD. " LTTNG_RELAYD_TCP_KEEP_ALIVE_TIME_ENV);
	ret = false;
	goto end;
#endif /* TCP_KEEPALIVE_THRESHOLD */
end:
	return ret;
}
#else
static bool tcp_keepalive_time_valid(int value)
{
	return value >= -1;
}
#endif /* __sun__ */

int tcp_keepalive_get_settings(void)
{
	int ret;
	const char *value;

	value = lttng_secure_getenv(LTTNG_RELAYD_TCP_KEEP_ALIVE_ENABLE_ENV);
	if (value && !strcmp(value, "1")) {
		tcp_keepalive_enabled = true;
	} else {
		tcp_keepalive_enabled = false;
		ret = 0;
		goto disabled;
	}

	/* Get value for tcp_keepalive_time in seconds*/
	value = lttng_secure_getenv(LTTNG_RELAYD_TCP_KEEP_ALIVE_TIME_ENV);
	if (value) {
		int tmp;
		errno = 0;
		tmp = (int) strtol(value, NULL, 0);
		if (errno != 0) {
			PERROR("TCP_KEEP_ALIVE time parse");
			ret = 1;
			goto error;
		}

		if (!tcp_keepalive_time_valid(tmp)) {
			ERR("TCP_KEEP_ALIVE time invalid value");
			ret = 1;
			goto error;
		}
#ifdef __sun__
		/*
		 * Under solaris this value is expressed in
		 * milliseconds. Fits in a int.
		 */
		if (tmp != -1) {
			tmp = tmp * MSEC_PER_SEC;
		}
#endif /* ifdef __sun__ */
		tcp_keepalive_time = tmp;
	}


	/* Get value for tcp_keepalive_intvl in seconds */
	value = lttng_secure_getenv(LTTNG_RELAYD_TCP_KEEP_ALIVE_INTVL_ENV);
	if (value) {
		int tmp;
		errno = 0;
		tmp = (int) strtol(value, NULL, 0);
		if (errno != 0 || tmp < -1) {
			PERROR("TCP_KEEP_ALIVE interval parse");
			ret = 1;
			goto error;
		} else {
			if (tmp >= 0) {
#ifdef __sun__
				WARN("Solaris does not support local override of tcp_keepalive_intvl. " LTTNG_RELAYD_TCP_KEEP_ALIVE_INTVL_ENV);
				ret = 1;
				goto error;
#else
				tcp_keepalive_intvl = tmp;
#endif /* __sun__ */
			}
		}
	}

	/* Get value for tcp_keepalive_probes */
	value = lttng_secure_getenv(LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBES_ENV);
	if (value) {
		int tmp;
		errno = 0;
		tmp = (int) strtol(value, NULL, 0);
		if (errno != 0 || tmp < -1) {
			PERROR("TCP_KEEP_ALIVE probes parse");
			ret = 1;
			goto error;
		} else {
			if (tmp >= 0) {
#ifdef __sun__
				WARN("Solaris does not support local override of tcp_keepalive_probes. " LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBES_ENV);
				ret = 1;
				goto error;
#else
				tcp_keepalive_probes = tmp;
#endif /* __sun__ */
			}
		}
	}

	DBG("TCP_KEEP_ALIVE enabled");
	if (tcp_keepalive_time > -1) {
		DBG("Overwrite tcp_keepalive_time to %d", tcp_keepalive_time);
	}
	if (tcp_keepalive_intvl > -1) {
		DBG("Overwrite tcp_keepalive_intvl to %d", tcp_keepalive_intvl);
	}
	if (tcp_keepalive_probes > -1) {
		DBG("Overwrite tcp_keepalive_time to %d", tcp_keepalive_probes);
	}
	ret = 0;

error:
disabled:
	return ret;
}

/*
 * Set the socket options regarding tcp_keepalive.
 */
int tcp_keepalive_setsockopt(int fd)
{
	int ret;
	int val = 1;

	if (!tcp_keepalive_enabled) {
		ret = 0;
		goto end;
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val,
			sizeof(val));
	if (ret < 0) {
		PERROR("setsockopt so_keepalive");
		goto end;
	}

#if !defined(__sun__) || (defined(__sun__) && defined(TCP_KEEPALIVE_THRESHOLD))
	if (tcp_keepalive_time > -1) {
		ret = setsockopt(fd, SOL_TCP, COMPAT_TCP_KEEPIDLE, &tcp_keepalive_time,
				sizeof(tcp_keepalive_time));
		if (ret < 0) {
			PERROR("setsockopt TCP_KEEPIDLE");
			goto end;
		}
	}
#endif /* ! defined(__sun__) || (defined(__sun__) && defined(TCP_KEEPALIVE_THRESHOLD)) */

	/* Sun does not support either tcp_keepalive_probes or
	 * tcp_keepalive_intvl. Inferring a value for
	 * TCP_KEEPALIVE_ABORT_THRESHOLD doing
	 * tcp_keepalive_probes * tcp_keepalive_intvl could yield a good
	 * alternative but Solaris does not detail the algorithm used (constant
	 * time retry like linux or somthing fancier). So simply ignore those
	 * setting on solaris for now.
	 */
#ifndef __sun__
	if (tcp_keepalive_intvl > -1) {
		ret = setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &tcp_keepalive_intvl,
				sizeof(tcp_keepalive_intvl));
		if (ret < 0) {
			PERROR("setsockopt TCP_KEEPINTVL");
			goto end;
		}
	}

	if (tcp_keepalive_probes > -1) {
		ret = setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &tcp_keepalive_probes,
				sizeof(tcp_keepalive_probes));
		if (ret < 0) {
			PERROR("setsockopt TCP_KEEPCNT");
			goto end;
		}
	}
#endif /* __sun__ */
end:
	return ret;
}
