/*
 *  VPNConnect -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2009 VPNConnect.Technologies, Inc. <sale@vpnconnect.net>
 *  Copyright (C) 2016 XNXSoft <dnfsec@gmail.com>
 *  Copyright (C) 2010 David Sommerseth <dazo@users.sourceforge.net>
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

/*
 * This plugin is similar to simple.c, except it also logs extra information
 * to stdout for every plugin method called by VPNConnect.  The only difference
 * between this (log_v3.c) and log.c is that this module uses the v3 plug-in
 * API.
 *
 * See the README file for build instructions.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ENABLE_CRYPTO

#include "vpnconnect-plugin.h"

/*
 * Our context, where we keep our state.
 */
struct plugin_context {
  const char *username;
  const char *password;
};

/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 */
static const char *
get_env (const char *name, const char *envp[])
{
  if (envp)
    {
      int i;
      const int namelen = strlen (name);
      for (i = 0; envp[i]; ++i)
	{
	  if (!strncmp (envp[i], name, namelen))
	    {
	      const char *cp = envp[i] + namelen;
	      if (*cp == '=')
		return cp + 1;
	    }
	}
    }
  return NULL;
}

VPNCONNECT_EXPORT int
vpnconnect_plugin_open_v3 (const int v3structver,
                        struct vpnconnect_plugin_args_open_in const *args,
                        struct vpnconnect_plugin_args_open_return *ret)
{
  struct plugin_context *context = NULL;

  /* Check that we are API compatible */
  if( v3structver != VPNCONNECT_PLUGINv3_STRUCTVER ) {
    printf("log_v3: ** ERROR ** Incompatible plug-in interface between this plug-in and VPNConnect.n");
    return VPNCONNECT_PLUGIN_FUNC_ERROR;
  }

  if( args->ssl_api != SSLAPI_OPENSSL ) {
    printf("This plug-in can only be used against VPNConnect.with OpenSSL\n");
    return VPNCONNECT_PLUGIN_FUNC_ERROR;
  }

  /* Print some version information about the VPNConnect.process using this plug-in */
  printf("log_v3: VPNConnect.%s  (Major: %i, Minor: %i, Patch: %s)\n",
         args->ovpn_version, args->ovpn_version_major,
         args->ovpn_version_minor, args->ovpn_version_patch);

  /*  Which callbacks to intercept.  */
  ret->type_mask =
    VPNCONNECT_PLUGIN_MASK (VPNCONNECT_PLUGIN_UP) |
    VPNCONNECT_PLUGIN_MASK (VPNCONNECT_PLUGIN_DOWN) |
    VPNCONNECT_PLUGIN_MASK (VPNCONNECT_PLUGIN_ROUTE_UP) |
    VPNCONNECT_PLUGIN_MASK (VPNCONNECT_PLUGIN_IPCHANGE) |
    VPNCONNECT_PLUGIN_MASK (VPNCONNECT_PLUGIN_TLS_VERIFY) |
    VPNCONNECT_PLUGIN_MASK (VPNCONNECT_PLUGIN_AUTH_USER_PASS_VERIFY) |
    VPNCONNECT_PLUGIN_MASK (VPNCONNECT_PLUGIN_CLIENT_CONNECT_V2) |
    VPNCONNECT_PLUGIN_MASK (VPNCONNECT_PLUGIN_CLIENT_DISCONNECT) |
    VPNCONNECT_PLUGIN_MASK (VPNCONNECT_PLUGIN_LEARN_ADDRESS) |
    VPNCONNECT_PLUGIN_MASK (VPNCONNECT_PLUGIN_TLS_FINAL);


  /* Allocate our context */
  context = (struct plugin_context *) calloc (1, sizeof (struct plugin_context));

  /* Set the username/password we will require. */
  context->username = "foo";
  context->password = "bar";

  /* Point the global context handle to our newly created context */
  ret->handle = (void *) context;

  return VPNCONNECT_PLUGIN_FUNC_SUCCESS;
}

void
show (const int type, const char *argv[], const char *envp[])
{
  size_t i;
  switch (type)
    {
    case VPNCONNECT_PLUGIN_UP:
      printf ("VPNCONNECT_PLUGIN_UP\n");
      break;
    case VPNCONNECT_PLUGIN_DOWN:
      printf ("VPNCONNECT_PLUGIN_DOWN\n");
      break;
    case VPNCONNECT_PLUGIN_ROUTE_UP:
      printf ("VPNCONNECT_PLUGIN_ROUTE_UP\n");
      break;
    case VPNCONNECT_PLUGIN_IPCHANGE:
      printf ("VPNCONNECT_PLUGIN_IPCHANGE\n");
      break;
    case VPNCONNECT_PLUGIN_TLS_VERIFY:
      printf ("VPNCONNECT_PLUGIN_TLS_VERIFY\n");
      break;
    case VPNCONNECT_PLUGIN_AUTH_USER_PASS_VERIFY:
      printf ("VPNCONNECT_PLUGIN_AUTH_USER_PASS_VERIFY\n");
      break;
    case VPNCONNECT_PLUGIN_CLIENT_CONNECT_V2:
      printf ("VPNCONNECT_PLUGIN_CLIENT_CONNECT_V2\n");
      break;
    case VPNCONNECT_PLUGIN_CLIENT_DISCONNECT:
      printf ("VPNCONNECT_PLUGIN_CLIENT_DISCONNECT\n");
      break;
    case VPNCONNECT_PLUGIN_LEARN_ADDRESS:
      printf ("VPNCONNECT_PLUGIN_LEARN_ADDRESS\n");
      break;
    case VPNCONNECT_PLUGIN_TLS_FINAL:
      printf ("VPNCONNECT_PLUGIN_TLS_FINAL\n");
      break;
    default:
      printf ("VPNCONNECT_PLUGIN_?\n");
      break;
    }

  printf ("ARGV\n");
  for (i = 0; argv[i] != NULL; ++i)
    printf ("%d '%s'\n", (int)i, argv[i]);

  printf ("ENVP\n");
  for (i = 0; envp[i] != NULL; ++i)
    printf ("%d '%s'\n", (int)i, envp[i]);
}

static void
x509_print_info (X509 *x509crt)
{
  int i, n;
  int fn_nid;
  ASN1_OBJECT *fn;
  ASN1_STRING *val;
  X509_NAME *x509_name;
  X509_NAME_ENTRY *ent;
  const char *objbuf;
  unsigned char *buf;

  x509_name = X509_get_subject_name (x509crt);
  n = X509_NAME_entry_count (x509_name);
  for (i = 0; i < n; ++i)
    {
      ent = X509_NAME_get_entry (x509_name, i);
      if (!ent)
	continue;
      fn = X509_NAME_ENTRY_get_object (ent);
      if (!fn)
	continue;
      val = X509_NAME_ENTRY_get_data (ent);
      if (!val)
	continue;
      fn_nid = OBJ_obj2nid (fn);
      if (fn_nid == NID_undef)
	continue;
      objbuf = OBJ_nid2sn (fn_nid);
      if (!objbuf)
	continue;
      buf = (unsigned char *)1; /* bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround */
      if (ASN1_STRING_to_UTF8 (&buf, val) <= 0)
	continue;

      printf("X509 %s: %s\n", objbuf, (char *)buf);
      OPENSSL_free (buf);
    }
}



VPNCONNECT_EXPORT int
vpnconnect_plugin_func_v3 (const int version,
                        struct vpnconnect_plugin_args_func_in const *args,
                        struct vpnconnect_plugin_args_func_return *retptr)
{
  struct plugin_context *context = (struct plugin_context *) args->handle;

  printf("\nvpnconnect_plugin_func_v3() :::::>> ");
  show (args->type, args->argv, args->envp);

  /* Dump some X509 information if we're in the TLS_VERIFY phase */
  if ((args->type == VPNCONNECT_PLUGIN_TLS_VERIFY) && args->current_cert ) {
    printf("---- X509 Subject information ----\n");
    printf("Certificate depth: %i\n", args->current_cert_depth);
    x509_print_info(args->current_cert);
    printf("----------------------------------\n");
  }

  /* check entered username/password against what we require */
  if (args->type == VPNCONNECT_PLUGIN_AUTH_USER_PASS_VERIFY)
    {
      /* get username/password from envp string array */
      const char *username = get_env ("username", args->envp);
      const char *password = get_env ("password", args->envp);

      if (username && !strcmp (username, context->username)
	  && password && !strcmp (password, context->password))
	return VPNCONNECT_PLUGIN_FUNC_SUCCESS;
      else
	return VPNCONNECT_PLUGIN_FUNC_ERROR;
    }
  else
    return VPNCONNECT_PLUGIN_FUNC_SUCCESS;
}

VPNCONNECT_EXPORT void
vpnconnect_plugin_close_v1 (vpnconnect_plugin_handle_t handle)
{
  struct plugin_context *context = (struct plugin_context *) handle;
  free (context);
}
