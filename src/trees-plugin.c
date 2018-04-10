/*
 * Copyright (c) 2014-2015 - The scrambler-plugin authors.
 *                    2017 - David Goulet <dgoulet@riseup.net>
 *
 * On 30.4.2015 - or earlier on notice - the scrambler-plugin authors will
 * make this source code available under the terms of the GNU Affero General
 * Public License version 3.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdio.h>

#include <dovecot/lib.h>
#include <dovecot/array.h>
#include <dovecot/buffer.h>
#include <dovecot/hash.h>
#include <dovecot/istream.h>
#include <dovecot/ostream.h>
#include <dovecot/ostream-private.h>
#include <dovecot/str.h>
#include <dovecot/safe-mkstemp.h>
#include <dovecot/mail-user.h>
#include <dovecot/mail-storage-private.h>
#include <dovecot/index-storage.h>
#include <dovecot/index-mail.h>
#include <dovecot/strescape.h>

#include <sodium.h>

#include "trees-plugin.h"
#include "trees-common.h"
#include "trees-ostream.h"
#include "trees-istream.h"

#define TREES_CONTEXT(obj) \
  MODULE_CONTEXT(obj, trees_storage_module)
#define TREES_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, trees_mail_module)
#define TREES_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, trees_user_module)

struct trees_user {
  /* Dovecot module context. */
  union mail_user_module_context module_ctx;

  /* Is this user has enabled this plugin? */
  int enabled;
  /* Version */
  uint32_t version;

  /* User public key. */
  unsigned int public_key_set : 1;
  unsigned char public_key[crypto_box_PUBLICKEYBYTES];

  /* Indicate if the private key has been set. With inbound mail, the plugin
   * doesn't have access to the private key thus can be empty. */
  unsigned int private_key_set : 1;
  unsigned char private_key[crypto_box_SECRETKEYBYTES];
};

const char *trees_plugin_version = DOVECOT_ABI_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(trees_storage_module,
                                  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(trees_mail_module,
                                  &mail_module_register);
static MODULE_CONTEXT_DEFINE_INIT(trees_user_module,
                                  &mail_user_module_register);

static const char *
trees_get_string_setting(struct mail_user *user, const char *name)
{
  return mail_user_plugin_getenv(user, name);
}

static unsigned long long int
trees_get_ullong_setting(struct mail_user *user, const char *name)
{
  const char *value = trees_get_string_setting(user, name);
  if (value == NULL) {
    return ULLONG_MAX;
  }
  return strtoull(value, NULL, 10);
}

static int
trees_get_integer_setting(struct mail_user *user, const char *name)
{
  const char *value = trees_get_string_setting(user, name);
  if (value == NULL) {
    return -1;
  }
  return atoi(value);
}

static int
trees_get_user_hexdata(struct mail_user *user, const char *param,
                       unsigned char *out, size_t out_len)
{
  const char *hex_str;

  hex_str = trees_get_string_setting(user, param);
  if (hex_str == NULL) {
    goto error;
  }
  if (sodium_hex2bin(out, out_len, hex_str, strlen(hex_str),
                     NULL, NULL, NULL)) {
    user->error = p_strdup_printf(user->pool,
                                  "Unable to convert %s for user %s.", param,
                                  user->username);
    i_error("[trees] Failing to hex2bin for %s", param);
    goto error;
  }

  /* Success! */
  return 0;
error:
  return -1;
}

static int
trees_get_private_key(struct mail_user *user,
                      struct trees_user *suser)
{
  int have_salt; int pwhash_alg;
  unsigned long long opslimit, memlimit;
  unsigned char pw_salt[crypto_pwhash_SALTBYTES];
  unsigned char sk_nonce[crypto_secretbox_NONCEBYTES];
  /* This is the key to unlock the secretbox. */
  unsigned char sk[crypto_secretbox_KEYBYTES];
  /* Encrypted secretbox that we need to open which is the size of a crypto
   * sealed box and the MAC data. */
  unsigned char secretbox[crypto_secretbox_MACBYTES +
                          crypto_box_SECRETKEYBYTES];
  const char *password;

	/* We check if we have direct access to the secretbox key which will make us
	 * bypass the entire pwhash process. If to, we go directly to open the
	 * secretbox. This is used for SSO or secret key caching mechanism. */
  if (trees_get_user_hexdata(user, "trees_secretbox_key",
                             sk, sizeof(sk)) == 0) {
    goto secretbox;
  }

  /* Get the user password that we'll use to . */
  password = trees_get_string_setting(user, "trees_password");

  /* No password means that we are receiving email and have no access to the
   * user private data so stop now. */
  if (password == NULL) {
    goto end;
  }

  /* Get the opslimit and memlimit. */
  opslimit = trees_get_ullong_setting(user, "trees_pwhash_opslimit");
  if (opslimit == ULLONG_MAX) {
    i_error("[trees] Bad pwhash_opslimit value.");
    goto error;
  }
  memlimit = trees_get_ullong_setting(user, "trees_pwhash_memlimit");
  if (memlimit == ULLONG_MAX) {
    i_error("[trees] Bad pwhash_memlimit value.");
    goto error;
  }

  /* Get the trees user salt. It's possible that it's not available. */
  have_salt = trees_get_user_hexdata(user, "trees_pwhash_salt",
                                         pw_salt, sizeof(pw_salt));
  if (have_salt == -1) {
    i_error("[trees] Unable to get the pwhash_salt.");
    goto end;
  }

	/* Get the pwhash value from database and then map it. After this, the
	 * pwhash_alg should be used with libsodium API. */
	pwhash_alg = trees_get_integer_setting(user, "trees_pwhash_algo");
	pwhash_alg = trees_pluging_pwhash_map(pwhash_alg);
	if (pwhash_alg == -1) {
		i_error("[trees] Unknown pwhash algorithm value: %d.", pwhash_alg);
		goto error;
	}

  /* Derive key from password to open the secretbox containing the private
   * key of the user. */
  if (crypto_pwhash(sk, sizeof(sk),
                    password, strlen(password), pw_salt,
                    opslimit, (size_t) memlimit,
                    pwhash_alg) < 0) {
    user->error = p_strdup_printf(user->pool,
                                  "Unable to derive private key for user %s.",
                                  user->username);
    i_error("[trees] pwhash failed for %s", user->username);
    goto error;
  }

secretbox:

  /* Get the secretbox data. */
  if (trees_get_user_hexdata(user, "trees_locked_secretbox",
                                 secretbox, sizeof(secretbox))) {
    i_error("[trees] Unable to get locked_secretbox");
    goto error;
  }

  /* Get the nonce. */
  if (trees_get_user_hexdata(user, "trees_sk_nonce",
                             sk_nonce, sizeof(sk_nonce))) {
    user->error = p_strdup_printf(user->pool,
                                  "Unable to find nonce value for user %s.",
                                  user->username);
    i_error("[trees] Unable to get sk_nonce.");
    goto error;
  }

  if (crypto_secretbox_open_easy(suser->private_key, secretbox,
                                 sizeof(secretbox), sk_nonce, sk) < 0) {
    i_error("[trees] Unable to open secretbox.");
    goto error;
  }
  /* Got the private key! */
  suser->private_key_set = 1;

end:
  return 0;
error:
  sodium_memzero(sk, sizeof(sk));
  return -1;
}

static void
trees_mail_user_created(struct mail_user *user)
{
  int version;
  struct mail_user_vfuncs *v = user->vlast;
  struct trees_user *suser;

  suser = p_new(user->pool, struct trees_user, 1);
  memset(suser, 0, sizeof(*suser));

  suser->module_ctx.super = *v;
  user->vlast = &suser->module_ctx.super;

  /* Does this user should use the trees or not? */
  suser->enabled = trees_get_integer_setting(user, "trees_enabled");
  if (suser->enabled == -1 || suser->enabled == 0) {
    /* Not present means disabled. Stop right now because we won't use
     * anything of this plugin for the user. */
    suser->enabled = 0;
    goto end;
  }

  /* Get plugin version that the user is configured for. */
  version = trees_get_integer_setting(user, "trees_version");
  if (version < MIN_VERSION || version > MAX_VERSION) {
    i_error("[trees] Bad version value.");
    goto end;
  }
  suser->version = (uint32_t) version;

  /* Getting user public key. Without it, we can't do much so error if we
   * can't find it. */
  if (trees_get_user_hexdata(user, "trees_public_key",
                                 suser->public_key,
                                 sizeof(suser->public_key))) {
    i_error("[trees] Unable to find public_key");
    goto end;
  }
  suser->public_key_set = 1;

  /* If there are no password available or missing the salt, we'll consider
   * that we don't have access to private key thus it could be an inbound
   * email. If we are successful at getting the private key, this flag will
   * be set to 1. */
  suser->private_key_set = 0;
  if (trees_get_private_key(user, suser) < 0) {
    goto end;
  }

end:
  MODULE_CONTEXT_SET(user, trees_user_module, suser);
}

static int
trees_mail_save_begin(struct mail_save_context *context,
                      struct istream *input)
{
  struct mailbox *box = context->transaction->box;
  union mailbox_module_context *mbox = TREES_CONTEXT(box);
  struct trees_user *suser = TREES_USER_CONTEXT(box->storage->user);
  struct ostream *output;

  if (mbox->super.save_begin(context, input) < 0) {
    return -1;
  }

  if (!suser->enabled) {
    goto end;
  }

  if (!suser->public_key_set) {
    /* No public key for a user that have the plugin enabled is not good. */
    i_error("[trees] User public key not found. Skipping.");
    goto end;
  }

  // TODO: find a better solution for this. this currently works, because
  // there is only one other ostream (zlib) in the setup. the trees should
  // be added to the other end of the ostream chain, not to the
  // beginning (the usual way).
  if (context->data.output->real_stream->parent == NULL) {
    output = trees_ostream_create(context->data.output,
                                      suser->public_key, suser->version);
    o_stream_unref(&context->data.output);
    context->data.output = output;
  } else {
    output = trees_ostream_create(context->data.output->real_stream->parent,
                                      suser->public_key, suser->version);
    o_stream_unref(&context->data.output->real_stream->parent);
    context->data.output->real_stream->parent = output;
  }

end:
  return 0;
}

static void
trees_mailbox_allocated(struct mailbox *box)
{
  struct mailbox_vfuncs *v = box->vlast;
  union mailbox_module_context *mbox;
  enum mail_storage_class_flags class_flags = box->storage->class_flags;

  mbox = p_new(box->pool, union mailbox_module_context, 1);
  mbox->super = *v;
  box->vlast = &mbox->super;

  MODULE_CONTEXT_SET_SELF(box, trees_storage_module, mbox);

  if ((class_flags & MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS) == 0) {
    v->save_begin = trees_mail_save_begin;
  }
}

static int
trees_istream_opened(struct mail *_mail, struct istream **stream)
{
  unsigned char *private_key = NULL;
  struct mail_private *mail = (struct mail_private *)_mail;
  struct mail_user *user = _mail->box->storage->user;
  struct trees_user *suser = TREES_USER_CONTEXT(user);
  union mail_module_context *mmail = TREES_MAIL_CONTEXT(mail);
  struct istream *input;

  input = *stream;
  if (suser->private_key_set) {
    private_key = suser->private_key;
  }
  *stream = trees_istream_create(input, suser->public_key,
                                     private_key);
  i_stream_unref(&input);

  return mmail->super.istream_opened(_mail, stream);
}

static void
trees_mail_allocated(struct mail *_mail)
{
  struct mail_private *mail = (struct mail_private *)_mail;
  struct mail_vfuncs *v = mail->vlast;
  union mail_module_context *mmail;

  mmail = p_new(mail->pool, union mail_module_context, 1);
  mmail->super = *v;
  mail->vlast = &mmail->super;

  v->istream_opened = trees_istream_opened;

  MODULE_CONTEXT_SET_SELF(mail, trees_mail_module, mmail);
}

static struct mail_storage_hooks trees_mail_storage_hooks = {
  .mail_user_created = trees_mail_user_created,
  .mailbox_allocated = trees_mailbox_allocated,
  .mail_allocated = trees_mail_allocated
};

void
trees_plugin_init(struct module *module)
{
  if (trees_initialize() < 0) {
    /* Don't hook anything has we weren't able to initialize ourself. */
    return;
  }
  mail_storage_hooks_add(module, &trees_mail_storage_hooks);
}

void
trees_plugin_deinit(void)
{
  mail_storage_hooks_remove(&trees_mail_storage_hooks);
}
