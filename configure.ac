AC_INIT([shopify], [0.0], [prabowo@darapsa.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AM_PROG_AR
LT_INIT
PKG_CHECK_MODULES([DEPS], [libmicrohttpd libgcrypt libpcre2-8 libcurl json-c])
AC_CHECK_HEADERS([fcntl.h])
AC_C_INLINE
AC_CHECK_FUNCS([strrchr])
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_TYPE_SIZE_T
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile shopify.pc])
AC_OUTPUT
