#
# $Id: configure.ac,v 79df6e8e7b5d 2010/06/23 14:52:39 Hirochika $
#
# Copyright (c) 2010 Scyphus Solutions Co.,Ltd. All rights reserved.
# Authors:
#      Hirochika Asai  <asai@scyphus.co.jp>
#

AC_PREREQ(2.59)
AC_INIT([anacap], [current], [bug@scyphus.co.jp])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE
AC_SUBST(SUBDIRS)
AC_SUBST(CFLAGS)

# arguments
AC_ARG_ENABLE(debug,
  [  --enable-debug    Turn on debugging [default no]],
  [case "${enableval}" in
    yes) debug=yes; AC_MSG_RESULT(Checking for debug... yes); AC_DEFINE(DEBUG, 1, debugging option) ;;
    no)  debug=no;;
    *) AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
  esac],[debug=no])
AM_CONDITIONAL(DEBUG, test x$debug = xtrue)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_LIBTOOL

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
#AC_CHECK_FUNCS([])
AC_FUNC_MALLOC

AC_CONFIG_FILES([Makefile include/Makefile lib/Makefile])
AC_OUTPUT
