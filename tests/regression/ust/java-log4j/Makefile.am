noinst_SCRIPTS = test_java_log4j JTestLTTng.java
EXTRA_DIST = test_java_log4j JTestLTTng.java

JAVAROOT=.

# Note: JAVACFLAGS is generated on autoconf and reused implicitly here to
# compile JTestLTTng with the good -classpath compiler option.
dist_noinst_JAVA = JTestLTTng.java

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	rm -f *.class
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi

