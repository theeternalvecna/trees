AM_CPPFLAGS = -I$(top_srcdir)/src -I$(builddir) $(LIBDOVECOT_INCLUDE)

lib_LTLIBRARIES = lib18_scrambler_plugin.la

lib18_scrambler_plugin_la_SOURCES = \
	scrambler-common.c  \
	scrambler-common.h  \
	scrambler-istream.c \
	scrambler-istream.h \
	scrambler-ostream.c \
	scrambler-ostream.h \
	scrambler-plugin.c  \
	scrambler-plugin.h

lib18_scrambler_plugin_la_LDFLAGS = \
	-shared -rdynamic -avoid-version -module
