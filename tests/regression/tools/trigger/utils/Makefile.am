# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(srcdir) -I$(top_srcdir)/tests/utils
LIBLTTNG_CTL=$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

noinst_PROGRAMS = notification-client
notification_client_SOURCES = notification-client.c
notification_client_LDADD = $(UST_LIBS) $(DL_LIBS) $(LIBLTTNG_CTL) \
		$(top_builddir)/tests/utils/libtestutils.la
