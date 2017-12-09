#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
#AC_CONFIG_SRCDIR([include/evco.h])
#AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

# Checks for libraries.
# FIXME: Replace `main' with a function in `-levent':
AC_CHECK_LIB([event], [main])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([socket])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 tests/Makefile])

#debug options support
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],[debug program(default is no)])],
    [CFLAGS="${CFLAGS} -DDEBUG -g"],
    [CFLAGS="-O2"])

AC_OUTPUT
