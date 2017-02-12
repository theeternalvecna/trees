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
#include <arpa/inet.h>
#include <inttypes.h>

#include <dovecot/lib.h>
#include <dovecot/istream.h>
#include <dovecot/istream-private.h>

#include "trees-common.h"
#include "trees-istream.h"

enum trees_istream_mode {
  ISTREAM_MODE_DETECT  = 1,
  ISTREAM_MODE_DECRYPT = 2,
  ISTREAM_MODE_PLAIN   = 3,
};

struct trees_istream {
  struct istream_private istream;

  enum trees_istream_mode mode;

  uint32_t version;

  const unsigned char *public_key;
  unsigned char *private_key;

  unsigned int last_chunk_read : 1;

#ifdef DEBUG_STREAMS
  unsigned int in_byte_count;
  unsigned int out_byte_count;
#endif
};

static ssize_t
trees_istream_read_parent(struct trees_istream *sstream,
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
trees_istream_read_detect_header(struct trees_istream *sstream,
                                 const unsigned char *source)
{
  ssize_t ret;

  /* Check for the trees header and if so we have an encrypted email that
   * we'll try to decrypt. */
  if (!memcmp(trees_header, source, MAGIC_SIZE)) {
    /* Yay we have an encrypted mail! Let's get the version of the plugin it
     * was encrypted for. */
    uint32_t version_to_network;
    memcpy(&version_to_network, source + MAGIC_SIZE,
           sizeof(version_to_network));
    sstream->version = ntohl(version_to_network);
    sstream->mode = ISTREAM_MODE_DECRYPT;
    if (sstream->private_key == NULL) {
      i_error("[trees] No private key for decryption.");
      sstream->istream.istream.stream_errno = EACCES;
      sstream->istream.istream.eof = TRUE;
      ret = -1;
      goto end;
    }
    if (sstream->version < MIN_VERSION ||
        sstream->version > MAX_VERSION) {
      i_error("[trees] Unknown version %" PRIu32 ". Supporting %d to %d",
              sstream->version, MIN_VERSION, MAX_VERSION);
      sstream->istream.istream.stream_errno = EACCES;
      sstream->istream.istream.eof = TRUE;
      ret = -1;
      goto end;
    }
    /* Returning size of header so we can skip it for decryption. */
    ret = HEADER_SIZE;
  } else {
    sstream->mode = ISTREAM_MODE_PLAIN;
    ret = 0;
  }

end:
  return ret;
}

static ssize_t
trees_istream_read_detect(struct trees_istream *sstream)
{
  struct istream_private *stream = &sstream->istream;
  const unsigned char *source;
  ssize_t result;
  size_t source_size;

  i_stream_set_max_buffer_size(sstream->istream.parent,
                               MAX_ISTREAM_BUFFER_SIZE);

  result = trees_istream_read_parent(sstream, MAGIC_SIZE, 0);
  if (result <= 0) {
    /* Make sure we return an error here. */
    result = -1;
    goto end;
  }
  source = i_stream_get_data(stream->parent, &source_size);
  result = trees_istream_read_detect_header(sstream, source);
  if (result < 0) {
    goto end;
  }

  /* Skip the magic if any is detected. For plain email, the result is 0
   * else the size of the header. */
  i_stream_skip(stream->parent, result);

#ifdef DEBUG_STREAMS
  sstream->in_byte_count += result;
#endif

end:
  return result;
}

static ssize_t
trees_istream_read_decrypt_chunk(struct trees_istream *sstream,
                                 unsigned char *destination,
                                 const unsigned char *source,
                                 size_t source_size)
{
#ifdef DEBUG_STREAMS
  sstream->in_byte_count += source_size;
  i_debug("[trees] Decrypt chunk source size: %lu", source_size);
#endif

  /* Note that we skip the header in the source for decryption. */
  ssize_t ret = crypto_box_seal_open(destination, source,
                                     source_size,
                                     sstream->public_key,
                                     sstream->private_key);
  if (ret != 0) {
    i_error("[trees] Box seal open failed with %ld", ret);
    ret = -1;
  } else {
    /* We just decrypted that amount of bytes. */
    ret = source_size - crypto_box_SEALBYTES;
  }
  return ret;
}

static ssize_t
trees_istream_read_decrypt(struct trees_istream *sstream)
{
  struct istream_private *stream = &sstream->istream;
  const unsigned char *parent_data, *source, *source_end;
  unsigned char *destination, *destination_end;
  ssize_t result;
  size_t source_size;

  result = trees_istream_read_parent(sstream, ENCRYPTED_CHUNK_SIZE,
                                         CHUNK_SIZE + stream->pos);
  if (result <= 0 && result != -1) {
    return result;
  }

  parent_data = i_stream_get_data(stream->parent, &source_size);
  source = parent_data;
  source_end = source + source_size;
  destination = stream->w_buffer + stream->pos;
  destination_end = stream->w_buffer + stream->buffer_size;

  while ((source_end - source) >= ENCRYPTED_CHUNK_SIZE) {
    if (destination_end - destination < CHUNK_SIZE) {
      i_error("[trees] Decrypting to a destination too small. "
              "Expected %ld but remaining %ld. Stopping.",
              destination_end - destination,
              source_end - source);
      sstream->istream.istream.stream_errno = EIO;
      sstream->istream.istream.eof = TRUE;
      return -1;
    }

    /* Decrypt a chunk of our ENCRYPTED_CHUNK_SIZE as we know that we are
     * expecting at least that amount. */
    result = trees_istream_read_decrypt_chunk(sstream, destination,
                                                  source,
                                                  ENCRYPTED_CHUNK_SIZE);
    if (result < 0) {
      stream->istream.stream_errno = EIO;
      return result;
    }
    /* Move the buffers forward with the amount of bytes we just decrypted.
     * The destination buffer moves forward with how much we decrypted. */
    source += ENCRYPTED_CHUNK_SIZE;
    destination += result;
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
        i_error("[trees] At EOF, decrypting to a destination too small. "
                "Expected %ld but remaining %ld",
                destination_end - destination,
                source_end - source);
        sstream->istream.istream.stream_errno = EIO;
        sstream->istream.istream.eof = TRUE;
        return -1;
      }

      result = trees_istream_read_decrypt_chunk(sstream, destination,
                                                    source,
                                                    source_end - source);
      if (result < 0) {
        stream->istream.stream_errno = EIO;
        return result;
      }
      /* Move source and destination forward. */
      source += (source_end - source);
      destination += result;

      sstream->last_chunk_read = 1;
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
  i_debug("[trees] Read decrypt %ld bytes", result);
#endif

  return result;
}

static ssize_t
trees_istream_read_plain(struct trees_istream *sstream)
{
  size_t source_size, copy_size;
  ssize_t result;
  const unsigned char *source;
  struct istream_private *stream = &sstream->istream;

  result = trees_istream_read_parent(sstream, 1, 0);
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
trees_istream_read(struct istream_private *stream)
{
  int ret;
  struct trees_istream *sstream = (struct trees_istream *) stream;

  if (sstream->mode == ISTREAM_MODE_DETECT) {
    ret = trees_istream_read_detect(sstream);
    if (ret < 0) {
      return ret;
    }
  }

  /* We've now detected the mode, process it. */
  switch (sstream->mode) {
  case ISTREAM_MODE_DECRYPT:
    return trees_istream_read_decrypt(sstream);
  case ISTREAM_MODE_PLAIN:
    return trees_istream_read_plain(sstream);
  case ISTREAM_MODE_DETECT:
    /* Something went terribly wrong. */
    assert(0);
  default:
    /* Should not happened in theory! */
    return -1;
  }
}

static void
trees_istream_seek(struct istream_private *stream, uoff_t v_offset,
                   bool mark)
{
  struct trees_istream *sstream = (struct trees_istream *) stream;

#ifdef DEBUG_STREAMS
  i_debug("[trees] istream seek %d / %d / %d",
          (int)stream->istream.v_offset, (int)v_offset, (int)mark);
#endif

  if (v_offset < stream->istream.v_offset) {
    /* Seeking backwards. Go back to beginning and seek forward. */
    sstream->mode = ISTREAM_MODE_DETECT;

    sstream->last_chunk_read = 0;

    stream->parent_expected_offset = stream->parent_start_offset;
    stream->skip = stream->pos = 0;
    stream->istream.v_offset = 0;
#ifdef DEBUG_STREAMS
    sstream->in_byte_count = 0;
    sstream->out_byte_count = 0;
#endif

    i_stream_seek(stream->parent, 0);
  }
  i_stream_default_seek_nonseekable(stream, v_offset, mark);
}

static int
trees_istream_stat(struct istream_private *stream, bool exact)
{
  const struct stat *stat;
  if (i_stream_stat(stream->parent, exact, &stat) < 0) {
    return -1;
  }
  stream->statbuf = *stat;
  return 0;
}

static void
trees_istream_close(struct iostream_private *stream, bool close_parent)
{
  struct trees_istream *sstream = (struct trees_istream *) stream;

#ifdef DEBUG_STREAMS
  i_debug("[trees] istream close - %u bytes in / %u bytes out / "
          "%u bytes overhead", sstream->in_byte_count,
          sstream->out_byte_count,
          sstream->in_byte_count - sstream->out_byte_count);
#endif

  if (close_parent) {
    i_stream_close(sstream->istream.parent);
  }
}

struct istream *
trees_istream_create(struct istream *input,
                     const unsigned char *public_key,
                     unsigned char *private_key)
{
  struct trees_istream *sstream = i_new(struct trees_istream, 1);

  sstream->mode = ISTREAM_MODE_DETECT;

  sstream->public_key = public_key;
  sstream->private_key = private_key;

  sstream->last_chunk_read = 0;

  sstream->istream.iostream.close = trees_istream_close;
  sstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
  sstream->istream.read = trees_istream_read;
  sstream->istream.seek = trees_istream_seek;
  sstream->istream.stat = trees_istream_stat;

  sstream->istream.istream.readable_fd = FALSE;
  sstream->istream.istream.blocking = input->blocking;
  sstream->istream.istream.seekable = input->seekable;

#ifdef DEBUG_STREAMS
  sstream->in_byte_count = 0;
  sstream->out_byte_count = 0;
#endif

  return i_stream_create(&sstream->istream, input, i_stream_get_fd(input));
}
