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

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

CLEANFILES = vpnconnect.8.html

dist_doc_DATA = \
	management-notes.txt

dist_noinst_DATA = \
	README.plugins

if WIN32
dist_noinst_DATA += vpnconnect.8
nodist_html_DATA = vpnconnect.8.html
vpnconnect.8.html: $(srcdir)/vpnconnect.8
	$(MAN2HTML) < $(srcdir)/vpnconnect.8 > vpnconnect.8.html
else
dist_man_MANS = vpnconnect.8
endif

