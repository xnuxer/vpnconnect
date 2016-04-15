/*
 *  VPNConnect -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2012 VPNConnect.Technologies, Inc. <sale@vpnconnect.net>
 *  Copyright (C) 2016 XNXSoft <dnfsec@gmail.com>
 *  Copyright (C) 2013      Gert Doering <gert@greenie.muc.de>
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

#ifndef VPNCONNECT_COMP_LZ4_H
#define VPNCONNECT_COMP_LZ4_H

#if defined(ENABLE_LZ4)

#include "buffer.h"

extern const struct compress_alg lz4_alg;
extern const struct compress_alg lz4v2_alg;

struct lz4_workspace
{
  int dummy;
};

#endif /* ENABLE_LZ4 */
#endif
