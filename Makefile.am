#
# $Id: Makefile.am,v c3f47cbdba35 2010/07/26 14:21:11 Hirochika $
#
# Copyright (c) 2010 Scyphus Solutions Co. Ltd. All rights reserved.
# Authors:
#      Hirochika Asai  <asai@scyphus.co.jp>
#

INCLUDES = -I$(top_srcdir)/include

SUBDIRS = include lib .

bin_PROGRAMS = anacap
anacap_SOURCES = main.c
anacap_DEPENDENCIES = $(top_builddir)/lib/libanacap.la
anacap_LDFLAGS = -lz -static $(top_builddir)/lib/libanacap.la

EXTRA_DIST = LICENSE
CLEANFILES = *~
