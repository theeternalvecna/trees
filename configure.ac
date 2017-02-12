AC_PREREQ([2.64])
AC_INIT([trees],[1.0.0],[https://0xacab.org/riseuplabs/trees/issues],
        [trees-plugin],[https://0xacab.org/riseuplabs/trees.git])

AC_CONFIG_HEADERS([trees-config.h])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET
AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip tar-pax])
AM_MAINTAINER_MODE([enable])

# Enable silent rules if available (Introduced in AM 1.11)
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for C compiler
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PROG_CC
AC_PROG_CC_STDC

LT_INIT

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for standard C headers.
AC_HEADER_STDC

# Make sure we have libsodium
AC_CHECK_LIB([sodium], [sodium_init], [],
	[AC_MSG_ERROR([Cannot find libsodium. Use LDFLAGS=-Ldir to specify its location.])]
)
AC_CHECK_HEADERS([sodium.h])

# Make sure we have dovecot develpment headers are available. We need to make
# this trick so the m4 macro look in /usr/include and not /usr/local/include.
# Better solution is welcome!
orig_prefix=$prefix
prefix="/usr"
DC_DOVECOT
DC_DOVECOT_MODULEDIR
prefix=$orig_prefix
LIBDOVECOT_INCLUDE="$LIBDOVECOT_INCLUDE"
AC_SUBST(LIBDOVECOT_INCLUDE)

CFLAGS="$CFLAGS $DOVECOT_CFLAGS"

CFLAGS="$CFLAGS -Wall -Werror -fno-strict-aliasing -W -Wmissing-prototypes"
CFLAGS="$CFLAGS -W -Wfloat-equal -Wundef -Wpointer-arith"
CFLAGS="$CFLAGS -Wstrict-prototypes -Wwrite-strings"
CFLAGS="$CFLAGS -Wredundant-decls -Wchar-subscripts -Wcomment"
CFLAGS="$CFLAGS -Wnested-externs -Wbad-function-cast -Wswitch-enum"
CFLAGS="$CFLAGS -Waggregate-return -Wpacked -Wunused"
CFLAGS="$CFLAGS -Wunused-parameter "
CFLAGS="$CFLAGS -Wpointer-arith -Wchar-subscripts -Wformat=2"
CFLAGS="$CFLAGS -Wbad-function-cast -Wstrict-aliasing=2"
CFLAGS="$CFLAGS -Wl,-z,relro,-z,now -fPIC -fstack-check -D_FORTIFY_SOURCE=2"

AC_CONFIG_FILES([
	Makefile
  src/Makefile
])

AC_OUTPUT
