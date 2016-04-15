/*
 *  VPNConnect -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN.Technologies, Inc. <sale@vpnconnect.net>
 *  Copyright (C) 2016 XNXSoft <dnfsec@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef VPNCONNECT_PKCS11_H
#define VPNCONNECT_PKCS11_H

#if defined(ENABLE_PKCS11)

#include "ssl_common.h"

bool
pkcs11_initialize (
	const bool fProtectedAuthentication,
	const int nPINCachePeriod
);

void
pkcs11_terminate ();

bool
pkcs11_addProvider (
	const char * const provider,
	const bool fProtectedAuthentication,
	const unsigned private_mode,
	const bool fCertIsPrivate
);

int
pkcs11_logout();

int
pkcs11_management_id_count ();

bool
pkcs11_management_id_get (
	const int index,
	char ** id,
	char **base64
);

int
tls_ctx_use_pkcs11 (
	struct tls_root_ctx * const ssl_ctx,
	bool pkcs11_id_management,
	const char * const pkcs11_id
);

void
show_pkcs11_ids (
	const char * const provider,
	bool cert_private
);

#endif			/* ENABLE_PKCS11 */

#endif			/* VPNCONNECT_PKCS11H_H */
