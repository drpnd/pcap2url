#
# $Id: Makefile.am,v 1a6039a88c34 2010/06/25 07:46:23 Hirochika $
#
# Copyright (c) 2010 Scyphus Solutions Co. Ltd. All rights reserved.
# Authors:
#      Hirochika Asai  <asai@scyphus.co.jp>
#

INCLUDES = -I$(top_srcdir)/include

SUBDIRS = include lib .

bin_PROGRAMS = anacap
anacap_SOURCES = main.c
anacap_LDFLAGS = -lz -static $(top_builddir)/lib/libanacap.la

EXTRA_DIST = LICENSE
CLEANFILES = *~
