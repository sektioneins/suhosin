# The PHP build has no header dependency tracking: after a header changes, make only rebuilds
# the .c files that changed too. Objects built against an old php_suhosin.h then read the module
# globals at the wrong offsets. Every object depends on every header of the extension here, so
# that a header change rebuilds all of them. SUHOSIN_OBJECTS comes from config.m4.
SUHOSIN_HEADERS = \
	$(srcdir)/php_suhosin.h \
	$(srcdir)/suhosin_rfc1867.h \
	$(srcdir)/sha256.h \
	$(srcdir)/pledge.h \
	$(srcdir)/suhosin_logo.h \
	$(srcdir)/mbregex.h

$(SUHOSIN_OBJECTS): $(SUHOSIN_HEADERS)
