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

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <dovecot/lib.h>
#include <dovecot/base64.h>
#include <dovecot/buffer.h>
#include <dovecot/str.h>

#include <sodium.h>

#include "trees-common.h"

const unsigned char trees_header[] = { 0xee, 0xff, 0xcc };

int
trees_initialize(void)
{
  if (sodium_init() < 0) {
    i_info("trees plugin libsodium failed to initialized.");
    return -1;
  }
  i_debug("trees plugin initialized");
  return 0;
}

#ifdef DEBUG_STREAMS

void
i_debug_hex(const char *prefix, const unsigned char *data, size_t size)
{
  T_BEGIN {
    string_t *output = t_str_new(1024);
    str_append(output, prefix);
    str_append(output, ": ");
    for (size_t index = 0; index < size; index++) {
      if (index > 0)
        str_append(output, " ");

      str_printfa(output, "%02x", data[index]);
    }
    i_debug("%s", str_c(output));
  } T_END;
}

#else /* DEBUG_STREAMS */

void
i_debug_hex(const char *prefix, const unsigned char *data, size_t size)
{
  (void) prefix;
  (void) data;
  (void) size;
  return;
}

#endif /* DEBUG_STREAMS */
