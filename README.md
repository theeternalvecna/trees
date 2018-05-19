TREES - A NaCL-based Dovecot encryption plugin
=======================================================

This plugin adds individually encrypted mail storage to the Dovecot IMAP
server.

This plugin is inspired by Posteo's
[scrambler](https://github.com/posteo/scrambler-plugin)
which uses OpenSSL and RSA keypairs. TREES works in a
similar way, but uses the Sodium crypto library (based on NaCL).

How it works:

1. On IMAP log in, the user's cleartext password is passed to the plugin.

2. The plugin creates an argon2 digest from the password.

3. This password digest is used as a symmetric secret to decrypt a libsodium
   secretbox.

4. Inside the secretbox is stored a Curve25519 private key.

5. The Curve25519 private key is used to decrypt each individual message, using
   lidsodium sealed boxes.

6. New mail is encrypted as it arrives using the Curve25519 public key.

Requirements
-------------------------------------

* dovecot source (`apt install dovecot-dev`)

* libsodium (must be >= 1.0.9, which is when argon2 hashing was added)
  libraries and header files: `apt install -t jessie-backports libsodium18
  libsodium-dev`

* libsodium authentication plugin for dovecot: not required, but there is
  little benefit from hashing passwords using argon2 if dovecot authentication
  relies on a weaker digest algorithm.
  https://github.com/LuckyFellow/dovecot-libsodium-plugin.git

Installation
-------------------------------------

* Run `autogen.sh` and then
  `./configure --with-moduledir=/usr/lib/dovecot/modules`.

* Type `make` to compile the plugin.

* Type `make install` to install the plugin to `/usr/lib/dovecot/modules/`

* Enable the plugin. For example, add `mail_plugins = expire quota trees`
  to `/etc/dovecot/conf.d/10-mail.conf`

See below for how to configure the plugin.

Database
-------------------------------------

In order to run, the plugin needs the following configuration values (via the
dovecot environment).

* `trees_password` The plain user password. It's used to unlock the
  `trees_locked_secretbox` in order to get access to the private key.

* `trees_enabled` Can be either the integer `1` or `0`.

* `trees_public_key` The public Curve25519 key of the user (hex string).

* `trees_locked_secretbox` contains the Curve25519 private key of a user
  which is locked using the argon2 digest of the user's password (hex string).

* `trees_sk_nonce` 24 byte random nonce for `locked_secretbox` (hex string).

* `trees_pwhash_opslimit` argon2 CPU usage parameter (3..10 int).

* `trees_pwhash_memlimit` argon2 memory usage parameter (must be in range
  8192 bytes to 4 TB, expressed in bytes).

* `trees_pwhash_salt` 16 byte random argon2 salt (hex string).

An example database scheme for this might be:

    CREATE TABLE `storage_keys` (
      `id` int(11) NOT NULL AUTO_INCREMENT,
      `enabled` tinyint(4) DEFAULT '1',
      `version` tinyint(4) DEFAULT '1',
      `public_key` text,
      `pwhash_algo` tinyint(4) DEFAULT '1',
      `pwhash_opslimit` int(11) DEFAULT NULL,
      `pwhash_memlimit` int(11) DEFAULT NULL,
      `pwhash_salt` varchar(255) DEFAULT NULL,
      `sk_nonce` varchar(255) DEFAULT NULL,
      `locked_secretbox` text,
      `user_id` int(11) DEFAULT NULL,
      PRIMARY KEY (`id`)
    ) ENGINE=InnoDB AUTO_INCREMENT DEFAULT

NOTE: the database MUST NOT store the argon2 digest, since this value is the
secret key that unlocks `locked_secretbox`. This is very different than how
password hashing for authentication works, where the digest and parameters are
stored.
pwhash_algo is 0 for libsodium <= 1.0.14 and 1 for libsodium >= 1.0.15

Dovecot Configuration
-------------------------------------

* passdb MUST be enabled.

* prefetch MUST be enabled.

* zlib compression must be disabled (might be compatible, need further
  testing).

* indexes should be disabled (otherwise, headers of incoming email are cached in
  cleartext).

* `default_pass_scheme = ARGON2` recommended (Note: this will use the crypt-
  style argon2 digest string for authentication, which is a very different
  format than is used by TREES. It is out of TREES's scope how to set up
  Argon2 authentication with Dovecot).

SQL Configuration
-------------------------------------

`/etc/dovecot/conf.d/auth-sql.conf.ext`

    passdb {
      driver = sql
      args = /etc/dovecot/dovecot-sql.conf
    }

    userdb {
      driver = prefetch
    }

    userdb {
      driver = sql
      args = /etc/dovecot/dovecot-sql.conf
    }

Here is a dovecot SQL query configuration that will work with the sample
`storage_keys` table.

`/etc/dovecot/dovecot-sql.conf`:

    ##
    ## PASSWORD QUERY
    ##
    ## because prefetch is enabled, the userdb_x entries will be used to populate
    ## user object.
    ##

    password_query = SELECT \
      mailboxes.username                        AS username, \
      mailboxes.domain                          AS domain, \
      mailboxes.password                        AS password, \
      8                                         AS userdb_uid, \
      8                                         AS userdb_gid, \
      CONCAT('/maildir/', mailboxes.maildir)    AS userdb_home, \
      REPLACE('%w', '%%', '%%%%')               AS userdb_trees_password, \
      storage_keys.enabled                      AS userdb_trees_enabled, \
      storage_keys.version                      AS userdb_trees_version, \
      storage_keys.public_key                   AS userdb_trees_public_key, \
      storage_keys.locked_secretbox             AS userdb_trees_locked_secretbox, \
      storage_keys.sk_nonce                     AS userdb_trees_sk_nonce, \
      storage_keys.pwhash_algo                  AS userdb_trees_pwhash_algo, \
      storage_keys.pwhash_opslimit              AS userdb_trees_pwhash_opslimit, \
      storage_keys.pwhash_memlimit              AS userdb_trees_pwhash_memlimit, \
      storage_keys.pwhash_salt                  AS userdb_trees_pwhash_salt \
      FROM mailboxes \
      LEFT OUTER JOIN storage_keys ON mailboxes.user_id = storage_keys.user_id \
      WHERE mailboxes.username = '%n' AND mailboxes.domain = '%d' \
      AND mailboxes.is_active = 1

    ##
    ## USER QUERY
    ##
    ## user_query is used to return the location of the mailbox and check the quota
    ## because we have prefetch enabled, this query is only used for LDA.
    ##

    user_query = SELECT \
      8                                         AS uid, \
      8                                         AS gid, \
      CONCAT('/maildir/', mailboxes.maildir)    AS home, \
      storage_keys.enabled                      AS trees_enabled, \
      storage_keys.version                      AS userdb_trees_version, \
      storage_keys.public_key                   AS trees_public_key, \
      CONCAT('*:bytes=', mailboxes.quota)       AS quota_rule \
      FROM mailboxes \
      LEFT OUTER JOIN storage_keys ON mailboxes.user_id = storage_keys.user_id \
      WHERE mailboxes.username = '%n' AND mailboxes.domain = '%d' \
      AND mailboxes.is_active = 1

The odd line `REPLACE('%w', '%%', '%%%%')` is needed to pass the cleartext
password to TREES, and allow `%` as a valid password character.

Argon2 Parameters
----------------------------------------------

There are three recommended levels for the Argon2 parameters, Interactive,
Moderate, and Sensitive. In the case of TREES, setting the parameters at
Moderate or Sensitive will make checking email very slow.

Interactive: For interactive, online operations, that need to be fast, a
reasonable minimum is:

* opslimit: 4
* memlimit: 2 ** 25 (32mb)

Moderate: This requires 128 Mb of dedicated RAM, and takes about 0.7 seconds on
a 2.8 Ghz Core i7 CPU.

* opslimit: 6
* memlimit: 2 ** 27 (128mb)

Sensitive: For highly sensitive data and non-interactive operations, consider
these values. With these parameters, deriving a key takes about 3.5 seconds on
a 2.8 Ghz Core i7 CPU and requires 512 Mb of dedicated RAM. Not practical for
IMAP!

* opslimit: 8
* memlimit: 2 ** 29 (512mb)

TODOs
----------------------------------------------

* Document how to migrate unencrypted mailboxes
* Fix tests
