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

#include "stream.h"
#include "util.h"
#include <stdlib.h>
#include <stdint.h>

#define BUF_FILE_BUF_LENGTH (1 << 16)
#define MIN(x,y) ((x < y) ? x : y)

// stream read
size_t cx9r_sread(void *ptr, size_t size, size_t nmemb, cx9r_stream_t *stream) {
	return stream->sread(ptr, size, nmemb, stream);
}

// stream end of file
int cx9r_seof(cx9r_stream_t *stream) {
	return stream->seof(stream);
}

// stream error
int cx9r_serror(cx9r_stream_t *stream) {
	return stream->serror(stream);
}

// stream close
int cx9r_sclose(cx9r_stream_t *stream) {
	return stream->sclose(stream);
}

// extended context for buffered file stream
typedef struct {
	FILE *file;
	uint8_t buffer[BUF_FILE_BUF_LENGTH];
	size_t total;
	size_t pos;
} buf_file_data_t;

// read from buffered file stream
static size_t buf_file_sread(void *ptr, size_t size, size_t nmemb,
		cx9r_stream_t *stream) {
	buf_file_data_t *data;
	FILE *file;
	size_t total;
	size_t pos;
	size_t n;
	uint8_t *out;

	data = (buf_file_data_t*) stream->data;
	out = (uint8_t*) ptr;
	file = data->file;
	total = size * nmemb;
	pos = 0;

	while (pos < total) {
		if (data->pos == data->total) {
			data->pos = 0;
			if ((data->total = fread(data->buffer, 1, BUF_FILE_BUF_LENGTH, file))
					== 0) {
				break;
			}
		}

		n = MIN(data->total - data->pos, total - pos);

		memcpy(out + pos, data->buffer + data->pos, n);
		pos += n;
		data->pos += n;
	}

	return pos / size;
}

// buffered file stream end of file
static int buf_file_seof(cx9r_stream_t *stream) {
	buf_file_data_t *data;
	FILE *file;

	data = (buf_file_data_t*) stream->data;
	file = data->file;

	return (feof(file) && (data->pos == data->total));
}

// buffered file stream error
static int buf_file_serror(cx9r_stream_t *stream) {
	buf_file_data_t *data;
	FILE *file;

	data = (buf_file_data_t*) stream->data;
	file = data->file;

	return ferror(file);
}

// buffered file stream close
static int buf_file_sclose(cx9r_stream_t *stream) {
	buf_file_data_t *data;
	FILE *file;

	data = (buf_file_data_t*) stream->data;
	file = data->file;

	free(data);
	free(stream);
	return fclose(file);
}

// open buffered file stream
cx9r_stream_t *cx9r_buf_file_sopen(FILE *file) {
	cx9r_stream_t *stream;
	buf_file_data_t *data;

	CHECK(((stream = malloc(sizeof(cx9r_stream_t))) != NULL),
			stream, stream,	cx9r_buf_file_sopen_return);

	CHECK(((stream->data = data = malloc(sizeof(buf_file_data_t))) != NULL),
			data, data, cx9r_buf_file_sopen_dealloc_stream);

	data->file = file;
	data->total = 0;
	data->pos = 0;

	stream->sread = buf_file_sread;
	stream->seof = buf_file_seof;
	stream->serror = buf_file_serror;
	stream->sclose = buf_file_sclose;

	goto cx9r_buf_file_sopen_return;

cx9r_buf_file_sopen_dealloc_stream:

	free(stream);
	stream = NULL;

cx9r_buf_file_sopen_return:

	return stream;
}
