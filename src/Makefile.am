AM_CPPFLAGS = -I$(top_srcdir)/src -I$(builddir) $(LIBDOVECOT_INCLUDE)

lib_LTLIBRARIES = lib18_trees_plugin.la

libdir = $(moduledir)

lib18_trees_plugin_la_SOURCES = \
	trees-common.c  \
	trees-common.h  \
	trees-istream.c \
	trees-istream.h \
	trees-ostream.c \
	trees-ostream.h \
	trees-plugin.c  \
	trees-plugin.h

lib18_trees_plugin_la_LDFLAGS = \
	-shared -rdynamic -avoid-version -module
