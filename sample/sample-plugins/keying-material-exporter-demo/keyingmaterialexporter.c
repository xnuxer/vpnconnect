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
 * This file implements a Sample (HTTP) SSO VPNConnect.plugin module
 *
 * See the README file for build instructions.
 */

#define ENABLE_CRYPTO

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "vpnconnect-plugin.h"

#ifndef MAXPATH
#define MAXPATH 1024
#endif

#define ovpn_err(fmt, ...) \
  plugin->log(PLOG_ERR,   "SSO", fmt , ## __VA_ARGS__)
#define ovpn_dbg(fmt, ...) \
  plugin->log(PLOG_DEBUG, "SSO", fmt , ## __VA_ARGS__)
#define ovpn_note(fmt, ...) \
  plugin->log(PLOG_NOTE,  "SSO", fmt , ## __VA_ARGS__)

enum endpoint { CLIENT = 1, SERVER = 2 };

struct plugin {
  plugin_log_t log;
  enum endpoint type;
  int mask;
};

struct session {
  char user[48];
  char key [48];
};

/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 */

static const char *
get_env(const char *name, const char *envp[])
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
vpnconnect_plugin_open_v3 (const int version,
                        struct vpnconnect_plugin_args_open_in const *args,
                        struct vpnconnect_plugin_args_open_return *rv)
{
  struct plugin *plugin = calloc (1, sizeof(*plugin));

  plugin->type = get_env ("remote_1", args->envp) ? CLIENT : SERVER;
  plugin->log  = args->callbacks->plugin_log;

  plugin->mask  = VPNCONNECT_PLUGIN_MASK(VPNCONNECT_PLUGIN_TLS_FINAL);
  plugin->mask |= VPNCONNECT_PLUGIN_MASK(VPNCONNECT_PLUGIN_TLS_VERIFY);

  ovpn_note("vpn endpoint type=%s",plugin->type == CLIENT ? "client":"server");

  rv->type_mask = plugin->mask;
  rv->handle = (void *)plugin;

  return VPNCONNECT_PLUGIN_FUNC_SUCCESS;
}

static void
session_user_set(struct session *sess, X509 *x509)
{
  int fn_nid;
  ASN1_OBJECT *fn;
  ASN1_STRING *val;
  X509_NAME *x509_name;
  X509_NAME_ENTRY *ent;
  const char *objbuf;

  x509_name = X509_get_subject_name (x509);
  int i, n = X509_NAME_entry_count (x509_name);
  for (i = 0; i < n; ++i)
    {
      if (!(ent = X509_NAME_get_entry (x509_name, i)))
        continue;
      if (!(fn = X509_NAME_ENTRY_get_object (ent)))
        continue;
      if (!(val = X509_NAME_ENTRY_get_data (ent)))
        continue;
      if ((fn_nid = OBJ_obj2nid (fn)) == NID_undef)
        continue;
      if (!(objbuf = OBJ_nid2sn (fn_nid)))
        continue;
      /* bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround */
      unsigned char *buf = (unsigned char *)1;
      if (ASN1_STRING_to_UTF8 (&buf, val) <= 0)
        continue;

      if (!strncasecmp(objbuf, "CN", 2))
        snprintf(sess->user, sizeof(sess->user) - 1, (char *)buf);

      OPENSSL_free (buf);
    }
}

static int
tls_verify(struct vpnconnect_plugin_args_func_in const *args)
{
  struct plugin *plugin = (struct plugin  *)args->handle;
  struct session *sess  = (struct session *)args->per_client_context;

  /* we store cert subject for the server end point only */
  if (plugin->type != SERVER)
    return VPNCONNECT_PLUGIN_FUNC_SUCCESS;

  if (!args->current_cert) {
    ovpn_err("this example plugin requires client certificate");
    return VPNCONNECT_PLUGIN_FUNC_ERROR;
  }

  session_user_set(sess, args->current_cert);

  return VPNCONNECT_PLUGIN_FUNC_SUCCESS;
}

static void
file_store(char *file, char *content)
{
  FILE *f;
  if (!(f = fopen(file, "w+")))
    return;

  fprintf(f, "%s", content);
  fclose(f);
}

static void
server_store(struct vpnconnect_plugin_args_func_in const *args)
{
  struct plugin *plugin = (struct plugin  *)args->handle;
  struct session *sess  = (struct session *)args->per_client_context;

  char file[MAXPATH];
  snprintf(file, sizeof(file) - 1, "/tmp/vpnconnect_sso_%s", sess->key);
  ovpn_note("app session file: %s", file);
  file_store(file, sess->user);
}

static void
client_store(struct vpnconnect_plugin_args_func_in const *args)
{
  struct plugin *plugin = (struct plugin  *)args->handle;
  struct session *sess  = (struct session *)args->per_client_context;

  char *file = "/tmp/vpnconnect_sso_user";
  ovpn_note("app session file: %s", file);
  file_store(file, sess->key);
}

static int
tls_final(struct vpnconnect_plugin_args_func_in const *args,
          struct vpnconnect_plugin_args_func_return *rv)
{
  struct plugin *plugin = (struct plugin  *)args->handle;
  struct session *sess  = (struct session *)args->per_client_context;

  const char *key;
  if (!(key = get_env ("exported_keying_material", args->envp)))
    return VPNCONNECT_PLUGIN_FUNC_ERROR;

  snprintf(sess->key, sizeof(sess->key) - 1, "%s", key);
  ovpn_note("app session key:  %s", sess->key);

  switch (plugin->type) {
  case SERVER:
    server_store(args);
    break;
  case CLIENT:
    client_store(args);
    return VPNCONNECT_PLUGIN_FUNC_SUCCESS;
  }

  ovpn_note("app session user: %s", sess->user);
  return VPNCONNECT_PLUGIN_FUNC_SUCCESS;
}

VPNCONNECT_EXPORT int
vpnconnect_plugin_func_v3 (const int version,
                        struct vpnconnect_plugin_args_func_in const *args,
                        struct vpnconnect_plugin_args_func_return *rv)
{
  switch(args->type) {
  case VPNCONNECT_PLUGIN_TLS_VERIFY:
    return tls_verify(args);
  case VPNCONNECT_PLUGIN_TLS_FINAL:
    return tls_final(args, rv);
  }
  return VPNCONNECT_PLUGIN_FUNC_SUCCESS;
}

VPNCONNECT_EXPORT void *
vpnconnect_plugin_client_constructor_v1(vpnconnect_plugin_handle_t handle)
{
  struct plugin *plugin = (struct plugin *)handle;
  struct session *sess  = calloc (1, sizeof(*sess));

  ovpn_note("app session created");

  return (void *)sess;
}

VPNCONNECT_EXPORT void
vpnconnect_plugin_client_destructor_v1(vpnconnect_plugin_handle_t handle, void *ctx)
{
  struct plugin *plugin = (struct plugin *)handle;
  struct session *sess  = (struct session *)ctx;

  ovpn_note("app session key: %s", sess->key);
  ovpn_note("app session destroyed");

  free (sess);
}

VPNCONNECT_EXPORT void
vpnconnect_plugin_close_v1 (vpnconnect_plugin_handle_t handle)
{
  struct plugin *plugin = (struct plugin *)handle;
  free (plugin);
}
