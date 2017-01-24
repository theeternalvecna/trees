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
#include <arpa/inet.h>
#include <string.h>

#include <dovecot/lib.h>
#include <dovecot/ostream.h>
#include <dovecot/ostream-private.h>

#include <sodium.h>

#include "scrambler-common.h"
#include "scrambler-ostream.h"


struct scrambler_ostream {
  struct ostream_private ostream;

  uint32_t version;
  const unsigned char *public_key;

  unsigned char chunk_buffer[CHUNK_SIZE];
  unsigned int chunk_buffer_size;

  unsigned int flushed : 1;

#ifdef DEBUG_STREAMS
  unsigned int in_byte_count;
  unsigned int out_byte_count;
#endif
};

static ssize_t
scrambler_ostream_send_header(struct scrambler_ostream *sstream)
{
  char header[HEADER_SIZE];
  uint32_t version_to_host;

  /* First set the header magic number. */
  memcpy(header, scrambler_header, MAGIC_SIZE);
  /* Then, put in the version. */
  version_to_host = htonl(sstream->version);
  memcpy(header + MAGIC_SIZE, &version_to_host, VERSION_SIZE);

  /* The header here consists of a magic number. */
  ssize_t ret = o_stream_send(sstream->ostream.parent, header,
                              sizeof(header));
#ifdef DEBUG_STREAMS
  sstream->out_byte_count += sizeof(header);
#endif
  return ret;
}

static ssize_t
scrambler_ostream_send_chunk(struct scrambler_ostream *sstream,
                             const unsigned char *chunk, size_t chunk_size)
{
  int ret;
  /* Extra protection here against overflow. Maybe too agressive! */
  assert(chunk_size < (SIZE_MAX - crypto_box_SEALBYTES));
  size_t ciphertext_len = crypto_box_SEALBYTES + chunk_size;
  unsigned char ciphertext[ciphertext_len];

  sodium_memzero(ciphertext, sizeof(ciphertext));
  ret = crypto_box_seal(ciphertext, chunk, chunk_size,
                        sstream->public_key);
  if (ret < 0) {
    sstream->ostream.ostream.stream_errno = EACCES;
    return ret;
  }
  o_stream_send(sstream->ostream.parent, ciphertext, ciphertext_len);

#ifdef DEBUG_STREAMS
  sstream->out_byte_count += ciphertext_len;
#endif

  /* Return the size of the plaintext so dovecot gets the right size for the
   * istream after decryption. */
  return chunk_size;
}

static ssize_t
scrambler_ostream_sendv(struct ostream_private *stream,
                        const struct const_iovec *iov, unsigned int iov_count)
{
  size_t chunk_size;
  ssize_t result = 0, encrypt_result = 0;
  const unsigned char *source, *source_end;
  struct scrambler_ostream *sstream = (struct scrambler_ostream *) stream;

  for (unsigned int index = 0; index < iov_count; index++) {
    source = iov[index].iov_base;
    source_end = (unsigned char *)iov[index].iov_base + iov[index].iov_len;

    while (source < source_end) {
      chunk_size = MIN(CHUNK_SIZE, source_end - source);

      if (sstream->chunk_buffer_size > 0 || chunk_size < CHUNK_SIZE) {
        chunk_size = MIN(chunk_size, CHUNK_SIZE - sstream->chunk_buffer_size);
        memcpy(sstream->chunk_buffer + sstream->chunk_buffer_size, source,
               chunk_size);
        sstream->chunk_buffer_size += chunk_size;

        if (sstream->chunk_buffer_size == CHUNK_SIZE) {
          encrypt_result = scrambler_ostream_send_chunk(sstream,
                                                        sstream->chunk_buffer,
                                                        CHUNK_SIZE);
          if (encrypt_result < 0) {
            return encrypt_result;
          }
          sstream->chunk_buffer_size = 0;
        }
      } else {
        encrypt_result = scrambler_ostream_send_chunk(sstream, source,
                                                      CHUNK_SIZE);
        if (encrypt_result < 0) {
          return encrypt_result;
        }
        chunk_size = encrypt_result;
      }

      source += chunk_size;
      result += chunk_size;
    }
  }

  stream->ostream.offset += result;

#ifdef DEBUG_STREAMS
  sstream->in_byte_count += result;
  i_debug("[scrambler] ostream send (%ld)", result);
#endif

  return result;
}

static int
scrambler_ostream_flush(struct ostream_private *stream)
{
  ssize_t result = 0;
  struct scrambler_ostream *sstream = (struct scrambler_ostream *) stream;

  if (sstream->flushed) {
    goto end;
  }

  result = scrambler_ostream_send_chunk(sstream, sstream->chunk_buffer,
                                        sstream->chunk_buffer_size);
  if (result < 0) {
    i_error("[scrambler] Error sending last chunk on close");
    goto end;
  }
  sstream->chunk_buffer_size = 0;
  sstream->ostream.ostream.offset += result;

  result = o_stream_flush(stream->parent);
  if (result < 0) {
    o_stream_copy_error_from_parent(stream);
    goto end;
  }
  sstream->flushed = 1;

end:
#ifdef DEBUG_STREAMS
  i_debug("[scrambler] ostream flush (%ld)", result);
#endif
  return result;
}

static void
scrambler_ostream_close(struct iostream_private *stream,
                        bool close_parent)
{
  struct scrambler_ostream *sstream = (struct scrambler_ostream *) stream;

#ifdef DEBUG_STREAMS
  i_debug("[scrambler] ostream close - %u bytes in / %u bytes out / "
          "%u bytes overhead", sstream->in_byte_count,
          sstream->out_byte_count,
          sstream->out_byte_count - sstream->in_byte_count);
#endif

  if (close_parent) {
    o_stream_close(sstream->ostream.parent);
  }
}

struct ostream *
scrambler_ostream_create(struct ostream *output,
                         const unsigned char *public_key,
                         uint32_t version)
{
  struct scrambler_ostream *sstream = i_new(struct scrambler_ostream, 1);
  struct ostream *result;

  sstream->public_key = public_key;
  sstream->version = version;

  sstream->chunk_buffer_size = 0;
  sstream->flushed = 0;

  sstream->ostream.iostream.close = scrambler_ostream_close;
  sstream->ostream.sendv = scrambler_ostream_sendv;
  sstream->ostream.flush = scrambler_ostream_flush;

#ifdef DEBUG_STREAMS
  sstream->in_byte_count = 0;
  sstream->out_byte_count = 0;
#endif

  result = o_stream_create(&sstream->ostream, output,
                           o_stream_get_fd(output));
  if (scrambler_ostream_send_header(sstream) < 0) {
    i_error("[scrambler] Unable to create ostream");
    return NULL;
  }

  return result;
}
