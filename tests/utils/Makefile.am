SUBDIRS = tap testapp

EXTRA_DIST = utils.sh test_utils.py babelstats.pl
dist_noinst_SCRIPTS = utils.sh test_utils.py babelstats.pl java_env.sh.tmpl

# Default prefix from lttng-ust autoconf
DEFAULT_LIBRARY_PATH="/usr/local/lib:/usr/lib"

if USER_DEFINED_LTTNG_UST_PREFIX
UST_LIB_PATH = "$(UST_PREFIX)/lib"
else
UST_LIB_PATH = "${DEFAULT_LIBRARY_PATH}"
endif

JAVA_ENV_MESSAGE="Generated on "

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi
	@cp $(srcdir)/java_env.sh.tmpl $(builddir)/java_env.sh
	@sed -i "s|%SED_REPLACE_NOTE|"$(JAVA_ENV_MESSAGE)"`date`|" ./java_env.sh
	@sed -i 's|%SED_REPLACE_CLASSPATH|'$(JAVA_CLASSPATH)"|" $(builddir)/java_env.sh
	@sed -i 's|%SED_REPLACE_LIBRARY_PATH|'$(UST_LIB_PATH)"|" $(builddir)/java_env.sh

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
	@rm $(builddir)/java_env.sh
