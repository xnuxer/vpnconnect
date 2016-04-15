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

/*
 * This plugin is similar to simple.c, except it also logs extra information
 * to stdout for every plugin method called by VPNConnect.
 *
 * See the README file for build instructions.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

VPNCONNECT_EXPORT vpnconnect_plugin_handle_t
vpnconnect_plugin_open_v1 (unsigned int *type_mask, const char *argv[], const char *envp[])
{
  struct plugin_context *context;

  /*
   * Allocate our context
   */
  context = (struct plugin_context *) calloc (1, sizeof (struct plugin_context));

  /*
   * Set the username/password we will require.
   */
  context->username = "foo";
  context->password = "bar";

  /*
   * Which callbacks to intercept.
   */
  *type_mask =
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

  return (vpnconnect_plugin_handle_t) context;
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

VPNCONNECT_EXPORT int
vpnconnect_plugin_func_v1 (vpnconnect_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
  struct plugin_context *context = (struct plugin_context *) handle;

  show (type, argv, envp);

  /* check entered username/password against what we require */
  if (type == VPNCONNECT_PLUGIN_AUTH_USER_PASS_VERIFY)
    {
      /* get username/password from envp string array */
      const char *username = get_env ("username", envp);
      const char *password = get_env ("password", envp);

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
