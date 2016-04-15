#
#  VPNConnect -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2010 OpenVPN.Technologies, Inc. <sale@vpnconnect.net>
 #  Copyright (C) 2016 XNXSoft <dnfsec@gmail.com>
#  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
#

include $(top_srcdir)/build/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST = \
	vpnconnectserv.vcxproj \
	vpnconnectserv.vcxproj.filters

AM_CPPFLAGS = \
	-I$(top_srcdir)/include -I$(top_srcdir)/src/vpnconnect

if WIN32
sbin_PROGRAMS = vpnconnectserv
vpnconnectserv_CFLAGS = \
	-municode -D_UNICODE \
	-UNTDDI_VERSION -U_WIN32_WINNT \
	-D_WIN32_WINNT=_WIN32_WINNT_VISTA
vpnconnectserv_LDADD = -ladvapi32 -luserenv -liphlpapi -lfwpuclnt -lrpcrt4 -lshlwapi -lnetapi32 -lws2_32
endif

vpnconnectserv_SOURCES = \
        common.c \
	automatic.c \
	interactive.c \
	service.c service.h \
	validate.c validate.h \
	$(top_srcdir)/src/vpnconnect/block_dns.c $(top_srcdir)/src/vpnconnect/block_dns.h \
	vpnconnectserv_resources.rc
