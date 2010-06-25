#
# $Id: configure.ac,v 1a6039a88c34 2010/06/25 07:46:23 Hirochika $
#
# Copyright (c) 2010 Scyphus Solutions Co. Ltd. All rights reserved.
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
#AC_PROG_RANLIB

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h fcntl.h sys/time.h])
AC_HEADER_TIME

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_STRUCT_TM
AC_TYPE_INT32_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
#AC_CHECK_FUNCS([])
AC_FUNC_MALLOC
AC_FUNC_MMAP

AC_CONFIG_FILES([Makefile include/Makefile lib/Makefile])
AC_OUTPUT
