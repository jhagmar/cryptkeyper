/* Cryptkeyper is
 *
 *     Copyright (C) 2013 Jonas Hagmar (jonas.hagmar@gmail.com)
 *
 * This file is part of cryptkeyper.
 *
 * Cryptkeyper is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * Cryptkeyper is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cryptkeyper. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef STREAM_H
#define STREAM_H

#include <stdio.h>

// forward declaration of stream context
typedef struct cx9r_stream cx9r_stream_t;

// stream read function pointer typedef
typedef size_t(*cx9r_sread_t)(void *ptr, size_t size, size_t nmemb, cx9r_stream_t *stream);
// stream end of file function pointer typedef
typedef int(*cx9r_seof_t)(cx9r_stream_t *stream);
// stream error function pointer typedef
typedef int(*cx9r_serror_t)(cx9r_stream_t *stream);
// stream close function pointer typedef
typedef int(*cx9r_sclose_t)(cx9r_stream_t *stream);

// stream context
struct cx9r_stream
{
  cx9r_sread_t sread;
  cx9r_seof_t seof;
  cx9r_serror_t serror;
  cx9r_sclose_t sclose;
  void *data;
};

// stream read
size_t cx9r_sread(void *ptr, size_t size, size_t nmemb, cx9r_stream_t *stream);
// stream end of file
int cx9r_seof(cx9r_stream_t *stream);
// stream error
int cx9r_serror(cx9r_stream_t *stream);
// stream close
int cx9r_sclose(cx9r_stream_t *stream);

// buffered file stream
cx9r_stream_t *cx9r_buf_file_sopen(FILE *file);
// AES256 CBC encrypted stream
cx9r_stream_t *cx9r_aes256_cbc_sopen(cx9r_stream_t *stream, void *key, void* iv);

#endif

