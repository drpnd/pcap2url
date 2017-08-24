#
# Copyright (c) 2010,2017 Hirochika Asai <asai@jar.jp>
# All rights reserved.
#

INCLUDES = -I$(top_srcdir)/include

SUBDIRS = include lib .

bin_PROGRAMS = pcap2url
pcap2url_SOURCES = main.c
pcap2url_DEPENDENCIES = $(top_builddir)/lib/libanacap.la
pcap2url_LDFLAGS = -lz -static $(top_builddir)/lib/libanacap.la

EXTRA_DIST = LICENSE
CLEANFILES = *~
