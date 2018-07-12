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

#ifndef TREES_PLUGIN_H
#define TREES_PLUGIN_H

/* Map pwhash libsodium hash values internally so we can match them to the
 * database field pwhash_algo. We do this because we don't want to rely on
 * libsodium ABI for which they happily remove things. */
static inline int
trees_pluging_pwhash_map(int value)
{
	switch (value) {
	case 0:
		/* argon2i, libsodium <= 1.0.14. */
		return crypto_pwhash_ALG_ARGON2I13;
#ifdef crypto_pwhash_ALG_ARGON2ID13
	case 1:
		/* argon2id, libsodium >= 1.0.15 */
		return crypto_pwhash_ALG_ARGON2ID13;
#endif
	default:
		return -1;
	}
}

void trees_plugin_init(struct module *module);
void trees_plugin_deinit(void);

#endif /* TREES_PLUGIN_H */
