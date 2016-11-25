/*
 * Copyright (c) 2014-2015 The scrambler-plugin authors. All rights reserved.
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

#include "scrambler-plugin.h"
#include "scrambler-common.h"
#include "scrambler-ostream.h"
#include "scrambler-istream.h"

// After buffer grows larger than this, create a temporary file to /tmp where to read the mail.
#define MAIL_MAX_MEMORY_BUFFER (1024 * 128)

#define SCRAMBLER_CONTEXT(obj) \
  MODULE_CONTEXT(obj, scrambler_storage_module)
#define SCRAMBLER_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, scrambler_mail_module)
#define SCRAMBLER_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, scrambler_user_module)

struct scrambler_user {
  /* Dovecot module context. */
  union mail_user_module_context module_ctx;
  /* Is this user has enabled this plugin? */
  unsigned int enabled : 1;
  /* User keypair. */
  unsigned char public_key[crypto_box_PUBLICKEYBYTES];
  /* Indicate if the private key has been set. With inbound mail, the plugin
   * doesn't have access to the private key thus being empy. */
  unsigned int private_key_set : 1;
  unsigned char private_key[crypto_box_SECRETKEYBYTES];
};

const char *scrambler_plugin_version = DOVECOT_ABI_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(scrambler_storage_module, &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(scrambler_mail_module, &mail_module_register);
static MODULE_CONTEXT_DEFINE_INIT(scrambler_user_module, &mail_user_module_register);

static const char *
scrambler_get_string_setting(struct mail_user *user, const char *name)
{
  return mail_user_plugin_getenv(user, name);
}

static unsigned long long int
scrambler_get_ullong_setting(struct mail_user *user, const char *name)
{
  const char *value = scrambler_get_string_setting(user, name);
  if (value == NULL) {
    return ULLONG_MAX;
  }
  return strtoull(value, NULL, 10);
}

static int
scrambler_get_integer_setting(struct mail_user *user, const char *name)
{
  const char *value = scrambler_get_string_setting(user, name);
  if (value == NULL) {
    return -1;
  }
  return atoi(value);
}

static int
scrambler_get_user_hexdata(struct mail_user *user, const char *param,
                           unsigned char *out, size_t out_len)
{
  const char *hex_str;

  hex_str = scrambler_get_string_setting(user, param);
  if (hex_str == NULL) {
    goto error;
  }
  if (sodium_hex2bin(out, out_len, hex_str, strlen(hex_str),
                     NULL, NULL, NULL)) {
    user->error = p_strdup_printf(user->pool,
                                  "Unable to convert %s for user %s.", param,
                                  user->username);
    goto error;
  }
  i_debug("[Hex value] %s", hex_str);

  /* Success! */
  return 0;
error:
  return -1;
}

static int
scrambler_get_private_key(struct mail_user *user,
                          struct scrambler_user *suser)
{
  int have_salt, password_fd;
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

  /* Get the user password that we'll use to . */
  password = scrambler_get_string_setting(user, "scrambler_password");
  password_fd = scrambler_get_integer_setting(user, "scrambler_password_fd");
  if (password == NULL && password_fd >= 0) {
    password = scrambler_read_line_fd(user->pool, password_fd);
  }

  /* No password means that we are receiving email and have no access to the
   * user private data so stop now. */
  if (password == NULL) {
    i_debug("No password!");
    goto end;
  }

  i_debug("Password: %s", password);

  /* Get the nonce. */
  if (scrambler_get_user_hexdata(user, "scrambler_sk_nonce",
                                 sk_nonce, sizeof(sk_nonce))) {
    user->error = p_strdup_printf(user->pool,
                                  "Unable to find nonce value for user %s.",
                                  user->username);
    i_debug("Bad nonce");
    goto error;
  }
  i_debug("Got nonce");

  /* Get the opslimit and memlimit. */
  opslimit = scrambler_get_ullong_setting(user, "scrambler_pwhash_opslimit");
  if (opslimit == ULLONG_MAX) {
    i_debug("Bad opslimit");
    goto error;
  }
  i_debug("OPLimit: %llu", opslimit);
  memlimit = scrambler_get_ullong_setting(user, "scrambler_pwhash_memlimit");
  if (memlimit == ULLONG_MAX) {
    i_debug("Bad memlimit");
    goto error;
  }
  i_debug("MemLimit: %llu", memlimit);

  /* Get the scrambler user salt. It's possible that it's not available. */
  have_salt = !!scrambler_get_user_hexdata(user, "scrambler_pwhash_salt",
                                           pw_salt, sizeof(pw_salt));
  if (!have_salt || password == NULL) {
    i_debug("No salt!");
    goto end;
  }
  i_debug("Got Salt");

  /* Derive key from password to open the secretbox containing the private
   * key of the user. */
  if (crypto_pwhash(sk, sizeof(sk),
                    password, strlen(password), pw_salt,
                    opslimit, (size_t) memlimit,
                    crypto_pwhash_ALG_DEFAULT) < 0) {
    user->error = p_strdup_printf(user->pool,
                                  "Unable to derive private key for user %s.",
                                  user->username);
    i_debug("Hashing failed");
    goto error;
  }
  i_debug("Hashing succeeded");

  if (scrambler_get_user_hexdata(user, "scrambler_locked_secretbox",
                                 secretbox, sizeof(secretbox))) {
    i_debug("Unable to get secretbox from dovecot");
    goto error;
  }
  i_debug("Got Secretbox");

  if (crypto_secretbox_open_easy(suser->private_key, secretbox,
                                 sizeof(secretbox), sk_nonce, sk) < 0) {
    i_debug("Secretbox opening failed");
    goto error;
  }
  i_debug("Secretbox opened");
  /* Got the private key! */
  suser->private_key_set = 1;

end:
  return 0;
error:
  sodium_memzero(sk, sizeof(sk));
  return -1;
}

static void
scrambler_mail_user_created(struct mail_user *user)
{
  struct mail_user_vfuncs *v = user->vlast;
  struct scrambler_user *suser;

  suser = p_new(user->pool, struct scrambler_user, 1);
  memset(suser, 0, sizeof(*suser));

  suser->module_ctx.super = *v;
  user->vlast = &suser->module_ctx.super;

  /* Does this user should use the scrambler or not? */
  suser->enabled = scrambler_get_integer_setting(user, "scrambler_enabled");
  if (suser->enabled == -1) {
    /* Not present means disabled. Stop right now because we won't use
     * anything of this plugin for the user. */
    suser->enabled = 0;
    goto end;
  }

  /* Getting user public key. Without it, we can't do much so error if we
   * can't find it. */
  if (scrambler_get_user_hexdata(user, "scrambler_public_key",
                                 suser->public_key,
                                 sizeof(suser->public_key))) {
    user->error = p_strdup_printf(user->pool,
                                  "Unable to find public key for user %s.",
                                  user->username);
    goto end;
  }

  /* If there are no password available or missing the salt, we'll consider
   * that we don't have access to private key thus it could be an inbound
   * email. If we are successful at getting the private key, this flag will
   * be set to 1. */
  suser->private_key_set = 0;
  if (scrambler_get_private_key(user, suser) < 0) {
    user->error = p_strdup_printf(user->pool,
                                  "Error getting private key for user %s.",
                                  user->username);
    goto end;
  }

end:
  MODULE_CONTEXT_SET(user, scrambler_user_module, suser);
}

static int
scrambler_mail_save_begin(struct mail_save_context *context,
                          struct istream *input)
{
  struct mailbox *box = context->transaction->box;
  union mailbox_module_context *mbox = SCRAMBLER_CONTEXT(box);
  struct scrambler_user *suser = SCRAMBLER_USER_CONTEXT(box->storage->user);
  struct ostream *output;

  if (mbox->super.save_begin(context, input) < 0) {
    return -1;
  }

  if (!suser->enabled) {
    i_debug("scrambler write plain mail");
    goto end;

  }

  // TODO: find a better solution for this. this currently works, because
  // there is only one other ostream (zlib) in the setup. the scrambler should
  // be added to the other end of the ostream chain, not to the
  // beginning (the usual way).
  if (context->data.output->real_stream->parent == NULL) {
    output = scrambler_ostream_create(context->data.output,
                                      suser->public_key);
    o_stream_unref(&context->data.output);
    context->data.output = output;
  } else {
    output = scrambler_ostream_create(context->data.output->real_stream->parent,
                                      suser->public_key);
    o_stream_unref(&context->data.output->real_stream->parent);
    context->data.output->real_stream->parent = output;
  }
  i_debug("scrambler write encrypted mail");

end:
  return 0;
}

static void
scrambler_mailbox_allocated(struct mailbox *box)
{
  struct mailbox_vfuncs *v = box->vlast;
  union mailbox_module_context *mbox;
  enum mail_storage_class_flags class_flags = box->storage->class_flags;

  mbox = p_new(box->pool, union mailbox_module_context, 1);
  mbox->super = *v;
  box->vlast = &mbox->super;

  MODULE_CONTEXT_SET_SELF(box, scrambler_storage_module, mbox);

  if ((class_flags & MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS) == 0) {
    v->save_begin = scrambler_mail_save_begin;
  }
}

static int
scrambler_istream_opened(struct mail *_mail, struct istream **stream)
{
  struct mail_private *mail = (struct mail_private *)_mail;
  struct mail_user *user = _mail->box->storage->user;
  struct scrambler_user *suser = SCRAMBLER_USER_CONTEXT(user);
  union mail_module_context *mmail = SCRAMBLER_MAIL_CONTEXT(mail);
  struct istream *input;

  input = *stream;
  assert(suser->private_key_set);
  *stream = scrambler_istream_create(input, suser->public_key,
                                     suser->private_key);
  i_stream_unref(&input);

  int result = mmail->super.istream_opened(_mail, stream);

  return result;
}

static void
scrambler_mail_allocated(struct mail *_mail)
{
  struct mail_private *mail = (struct mail_private *)_mail;
  struct mail_vfuncs *v = mail->vlast;
  union mail_module_context *mmail;

  mmail = p_new(mail->pool, union mail_module_context, 1);
  mmail->super = *v;
  mail->vlast = &mmail->super;

  v->istream_opened = scrambler_istream_opened;

  MODULE_CONTEXT_SET_SELF(mail, scrambler_mail_module, mmail);
}

static struct mail_storage_hooks scrambler_mail_storage_hooks = {
  .mail_user_created = scrambler_mail_user_created,
  .mailbox_allocated = scrambler_mailbox_allocated,
  .mail_allocated = scrambler_mail_allocated
};

void
scrambler_plugin_init(struct module *module)
{
  if (scrambler_initialize() < 0) {
    /* Don't hook anything has we weren't able to initialize ourself. */
    return;
  }
  mail_storage_hooks_add(module, &scrambler_mail_storage_hooks);
}

void
scrambler_plugin_deinit(void)
{
  mail_storage_hooks_remove(&scrambler_mail_storage_hooks);
}
