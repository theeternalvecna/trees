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

#ifndef TREES_COMMON_H
#define TREES_COMMON_H

#include <sodium.h>

#define VERSION_ONE 1
/* Earliest and latest version this plugin supports. */
#define MIN_VERSION VERSION_ONE
#define MAX_VERSION VERSION_ONE

#define MAGIC_SIZE (sizeof(trees_header))
#define VERSION_SIZE (sizeof(uint32_t))
#define HEADER_SIZE (MAGIC_SIZE + VERSION_SIZE)

/* Aligns with the docevot default buffer size. */
#define CHUNK_SIZE 8192
#define ENCRYPTED_CHUNK_SIZE (crypto_box_SEALBYTES + CHUNK_SIZE)
#define MAXIMAL_PASSWORD_LENGTH 256
#define MAX_ISTREAM_BUFFER_SIZE (ENCRYPTED_CHUNK_SIZE * 2)

#define MIN(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

#define MAX(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

extern const unsigned char trees_header[3];

int trees_initialize(void);

const char *trees_read_line_fd(pool_t pool, int file_descriptor);

void i_debug_hex(const char *prefix, const unsigned char *data, size_t size);

#endif /* TREES_COMMON_H */
