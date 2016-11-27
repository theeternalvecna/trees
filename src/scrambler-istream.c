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

#include <dovecot/lib.h>
#include <dovecot/istream.h>
#include <dovecot/istream-private.h>

#include "scrambler-common.h"
#include "scrambler-istream.h"

enum scrambler_istream_mode {
  ISTREAM_MODE_DETECT  = 1,
  ISTREAM_MODE_DECRYPT = 2,
  ISTREAM_MODE_PLAIN   = 3,
};

struct scrambler_istream {
  struct istream_private istream;

  enum scrambler_istream_mode mode;

  const unsigned char *public_key;
  unsigned char *private_key;

  unsigned int chunk_index;
  bool last_chunk_read;

#ifdef DEBUG_STREAMS
  unsigned int in_byte_count;
  unsigned int out_byte_count;
#endif
};

static ssize_t
scrambler_istream_read_parent(struct scrambler_istream *sstream,
                              size_t minimal_read_size,
                              size_t minimal_alloc_size)
{
  struct istream_private *stream = &sstream->istream;
  size_t size;
  ssize_t result;

  size = i_stream_get_data_size(stream->parent);
  while (minimal_read_size != 0 && size < minimal_read_size) {
    result = i_stream_read(stream->parent);
    size = i_stream_get_data_size(stream->parent);

    if (result > 0 && stream->parent->eof) {
      break;
    }

    if (result <= 0 && (result != -2 || stream->skip == 0)) {
      stream->istream.stream_errno = stream->parent->stream_errno;
      stream->istream.eof = stream->parent->eof;
      return result;
    }
  }

  i_stream_alloc(stream, MAX(minimal_alloc_size, size));
  return size;
}

static ssize_t
scrambler_istream_read_detect_magic(struct scrambler_istream *sstream,
                                    const unsigned char *source)
{
  /* Check for the scrambler header and if so we have an encrypted email that
   * we'll try to decrypt. */
  if (memcmp(scrambler_header, source, sizeof(scrambler_header))) {
#ifdef DEBUG_STREAMS
    i_debug("istream read encrypted mail");
#endif
    sstream->mode = ISTREAM_MODE_DECRYPT;
    if (sstream->private_key == NULL) {
      i_error("tried to decrypt a mail without the private key");
      sstream->istream.istream.stream_errno = EACCES;
      sstream->istream.istream.eof = TRUE;
      return -1;
    }
  } else {
#ifdef DEBUG_STREAMS
    i_debug("istream read plain mail");
#endif
    sstream->mode = ISTREAM_MODE_PLAIN;
  }
  return 0;
}

static ssize_t
scrambler_istream_read_detect(struct scrambler_istream *sstream)
{
  struct istream_private *stream = &sstream->istream;
  const unsigned char *source;
  ssize_t result;
  size_t source_size;

  i_stream_set_max_buffer_size(sstream->istream.parent,
                               MAX_ISTREAM_BUFFER_SIZE);

  result = scrambler_istream_read_parent(sstream, MAGIC_SIZE, 0);
  if (result <= 0) {
    goto end;
  }
  source = i_stream_get_data(stream->parent, &source_size);
  result = scrambler_istream_read_detect_magic(sstream, source);
  if (result < 0) {
    goto end;
  }
#ifdef DEBUG_STREAMS
  sstream->in_byte_count += result;
#endif

  i_stream_skip(stream->parent, result);
end:
  return result;
}

static ssize_t
scrambler_istream_read_decrypt_chunk(struct scrambler_istream *sstream,
                                     unsigned char *destination,
                                     const unsigned char *source)
{
#ifdef DEBUG_STREAMS
  sstream->in_byte_count += ENCRYPTED_CHUNK_SIZE;
#endif
  i_debug_hex("[decrypt] scrambler source", destination,
              ENCRYPTED_CHUNK_SIZE);
  ssize_t ret = crypto_box_seal_open(destination, source,
                                     ENCRYPTED_CHUNK_SIZE,
                                     sstream->public_key,
                                     sstream->private_key);
  if (ret > 0) {
    i_debug_hex("[decrypt] scrambler destination", destination,
                ret);
  } else {
    i_debug("[decrypt] scrambler failed with %d", (int) ret);
  }
  sstream->chunk_index++;
  return ret;
}

static ssize_t
scrambler_istream_read_decrypt(struct scrambler_istream *sstream)
{
  struct istream_private *stream = &sstream->istream;
  const unsigned char *parent_data, *source, *source_end;
  unsigned char *destination, *destination_end;
  ssize_t result;
  size_t source_size;

  result = scrambler_istream_read_parent(sstream, ENCRYPTED_CHUNK_SIZE,
                                         CHUNK_SIZE + stream->pos);
  if (result <= 0 && result != -1) {
    return result;
  }

  parent_data = i_stream_get_data(stream->parent, &source_size);
  source = parent_data;
  source_end = source + source_size;
  destination = stream->w_buffer + stream->pos;
  destination_end = stream->w_buffer + stream->buffer_size;

  while ( (source_end - source) >= ENCRYPTED_CHUNK_SIZE ) {
    if (destination_end - destination < CHUNK_SIZE) {
      i_error("output buffer too small");
      sstream->istream.istream.stream_errno = EIO;
      sstream->istream.istream.eof = TRUE;
      return -1;
    }

    result = scrambler_istream_read_decrypt_chunk(sstream, destination,
                                                  source);
    if (result < 0) {
      return result;
    }
  }

  if (stream->parent->eof) {
    if (sstream->last_chunk_read) {
      stream->istream.stream_errno = stream->parent->stream_errno;
      stream->istream.eof = stream->parent->eof;
      return -1;
    } else {
      stream->istream.stream_errno = 0;
      stream->istream.eof = FALSE;

      if (destination_end - destination < CHUNK_SIZE) {
        i_error("output buffer too small (for final chunk)");
        sstream->istream.istream.stream_errno = EIO;
        sstream->istream.istream.eof = TRUE;
        return -1;
      }

      result = scrambler_istream_read_decrypt_chunk(sstream, destination, source);
      if (result < 0) {
        stream->istream.stream_errno = EIO;
        return result;
      }

      sstream->last_chunk_read = TRUE;
    }
  }

  i_stream_skip(stream->parent, source - parent_data);

  result = (destination - stream->w_buffer) - stream->pos;
  stream->pos = destination - stream->w_buffer;

  if (result == 0) {
    stream->istream.stream_errno = stream->parent->stream_errno;
    stream->istream.eof = stream->parent->eof;
    return -1;
  }

#ifdef DEBUG_STREAMS
  sstream->out_byte_count += result;
  i_debug("scrambler istream read (%d)", (int)result);
#endif

  return result;
}

static ssize_t
scrambler_istream_read_plain(struct scrambler_istream *sstream)
{
  size_t source_size, copy_size;
  ssize_t result;
  const unsigned char *source;
  struct istream_private *stream = &sstream->istream;

  result = scrambler_istream_read_parent(sstream, 1, 0);
  if (result <= 0) {
    return result;
  }

  source = i_stream_get_data(stream->parent, &source_size);
  copy_size = MIN(source_size, stream->buffer_size - stream->pos);
  memcpy(stream->w_buffer + stream->pos, source, copy_size);

  i_stream_skip(stream->parent, copy_size);
  stream->pos += copy_size;

#ifdef DEBUG_STREAMS
  sstream->in_byte_count += copy_size;
  sstream->out_byte_count += copy_size;
#endif

  return copy_size;
}

static ssize_t
scrambler_istream_read(struct istream_private *stream)
{
  int ret;
  struct scrambler_istream *sstream = (struct scrambler_istream *) stream;

  if (sstream->mode == ISTREAM_MODE_DETECT) {
    ret = scrambler_istream_read_detect(sstream);
    if (ret < 0) {
      return ret;
    }
  }

  /* We've now detected the mode, process it. */
  switch (sstream->mode) {
  case ISTREAM_MODE_DECRYPT:
    return scrambler_istream_read_decrypt(sstream);
  case ISTREAM_MODE_PLAIN:
    return scrambler_istream_read_plain(sstream);
  default:
    /* Should not happened in theory! */
    return -1;
  }
}

static void
scrambler_istream_seek(struct istream_private *stream, uoff_t v_offset,
                       bool mark)
{
  struct scrambler_istream *sstream = (struct scrambler_istream *) stream;

#ifdef DEBUG_STREAMS
  i_debug("scrambler istream seek %d / %d / %d",
          (int)stream->istream.v_offset, (int)v_offset, (int)mark);
#endif

  if (v_offset < stream->istream.v_offset) {
    // seeking backwards - go back to beginning and seek forward from there.
    sstream->mode = ISTREAM_MODE_DETECT;

    sstream->chunk_index = 0;
    sstream->last_chunk_read = 0;
#ifdef DEBUG_STREAMS
    sstream->in_byte_count = 0;
    sstream->out_byte_count = 0;
#endif

    stream->parent_expected_offset = stream->parent_start_offset;
    stream->skip = stream->pos = 0;
    stream->istream.v_offset = 0;

    i_stream_seek(stream->parent, 0);
  }
  i_stream_default_seek_nonseekable(stream, v_offset, mark);
}

static int
scrambler_istream_stat(struct istream_private *stream, bool exact)
{
  const struct stat *stat;
  if (i_stream_stat(stream->parent, exact, &stat) < 0) {
    return -1;
  }
  stream->statbuf = *stat;
  return 0;
}

static void
scrambler_istream_close(struct iostream_private *stream, bool close_parent)
{
  struct scrambler_istream *sstream = (struct scrambler_istream *)stream;

  /* Wipe private key material. */
  sodium_memzero(sstream->private_key, crypto_box_SECRETKEYBYTES);

#ifdef DEBUG_STREAMS
  i_debug("scrambler istream close - %u bytes in / %u bytes out / "
          "%u bytes overhead", sstream->in_byte_count,
          sstream->out_byte_count,
          sstream->in_byte_count - sstream->out_byte_count);
#endif

  if (close_parent) {
    i_stream_close(sstream->istream.parent);
  }
}

struct istream *
scrambler_istream_create(struct istream *input,
                         const unsigned char *public_key,
                         unsigned char *private_key)
{
  struct scrambler_istream *sstream = i_new(struct scrambler_istream, 1);

#ifdef DEBUG_STREAMS
  i_debug("scrambler istream create");
#endif

  sstream->mode = ISTREAM_MODE_DETECT;

  sstream->public_key = public_key;
  sstream->private_key = private_key;

  sstream->chunk_index = 0;
  sstream->last_chunk_read = 0;
#ifdef DEBUG_STREAMS
  sstream->in_byte_count = 0;
  sstream->out_byte_count = 0;
#endif

  sstream->istream.iostream.close = scrambler_istream_close;
  sstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
  sstream->istream.read = scrambler_istream_read;
  sstream->istream.seek = scrambler_istream_seek;
  sstream->istream.stat = scrambler_istream_stat;

  sstream->istream.istream.readable_fd = FALSE;
  sstream->istream.istream.blocking = input->blocking;
  sstream->istream.istream.seekable = input->seekable;

  return i_stream_create(&sstream->istream, input, i_stream_get_fd(input));
}
