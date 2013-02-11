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
#include "aes256.h"
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
} file_data_t;

// read from buffered file stream
static size_t file_sread(void *ptr, size_t size, size_t nmemb,
		cx9r_stream_t *stream) {
	file_data_t *data;
	FILE *file;

	data = (file_data_t*) stream->data;
	file = data->file;

	return fread(ptr, size, nmemb, file);
}

// buffered file stream end of file
static int file_seof(cx9r_stream_t *stream) {
	file_data_t *data;
	FILE *file;

	data = (file_data_t*) stream->data;
	file = data->file;

	return feof(file);
}

// buffered file stream error
static int file_serror(cx9r_stream_t *stream) {
	file_data_t *data;
	FILE *file;

	data = (file_data_t*) stream->data;
	file = data->file;

	return ferror(file);
}

// buffered file stream close
static int file_sclose(cx9r_stream_t *stream) {
	file_data_t *data;
	FILE *file;

	data = (file_data_t*) stream->data;
	file = data->file;

	free(data);
	free(stream);
	return fclose(file);
}

cx9r_stream_t *cx9r_file_sopen(FILE *file) {
	cx9r_stream_t *stream;
	file_data_t *data;

	CHEQ(((stream = malloc(sizeof(cx9r_stream_t))) != NULL),
			bail);

	CHEQ(((stream->data = data = malloc(sizeof(file_data_t))) != NULL),
			dealloc_stream);

	data->file = file;

	stream->sread = file_sread;
	stream->seof = file_seof;
	stream->serror = file_serror;
	stream->sclose = file_sclose;

	goto bail;

dealloc_stream:

	free(stream);
	stream = NULL;

bail:

	return stream;
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

	CHEQ(((stream = malloc(sizeof(cx9r_stream_t))) != NULL),
			cx9r_buf_file_sopen_return);

	CHEQ(((stream->data = data = malloc(sizeof(buf_file_data_t))) != NULL),
			cx9r_buf_file_sopen_dealloc_stream);

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

#define AES256_CBC_NOM_BUF_LENGTH (1 << 16)
#define AES256_CBC_BUF_LENGTH (AES256_CBC_NOM_BUF_LENGTH - AES256_CBC_NOM_BUF_LENGTH%CX9R_AES256_BLOCK_LENGTH)

// extended context for AES256 CBC stream
typedef struct {
	cx9r_stream_t *in;
	cx9r_aes256_cbc_ctx *ctx;
	uint8_t buf[AES256_CBC_BUF_LENGTH];
	size_t total;
	size_t pos;
	int error;
	int eof;
	int unpadded; // whether or not the PKCS7 unpadding has been performed
} aes256_cbc_data_t;

static void aes256_cbc_fill_buf(aes256_cbc_data_t *data) {
	cx9r_stream_t *in;
	size_t bytes_to_read;
	size_t bytes_read;
	uint8_t pad_length;
	size_t i;

	if (data->unpadded) {
		return;
	}

	in = data->in;
	bytes_to_read = AES256_CBC_BUF_LENGTH - data->total;

	bytes_read = cx9r_sread(data->buf + data->total, 1, bytes_to_read, data->in);

	// stream must be an even multiple of the AES block length
	if (((data->total + bytes_read) % CX9R_AES256_BLOCK_LENGTH) != 0) {
		data->error = 1;
		return;
	}

	if (bytes_read > 0) {
		cx9r_aes256_cbc_decrypt(data->ctx, data->buf + data->total, bytes_read);
		data->total += bytes_read;
	}

	// check if we have read the last block
	if ((bytes_read != bytes_to_read) && (data->total > 0)) {
		// get padding length
		pad_length = data->buf[data->total - 1];
		if (pad_length > CX9R_AES256_BLOCK_LENGTH) {
			data->error = 1;
			return;
		}
		// check padding
		for (i = 0; i < pad_length; i++) {
			if (data->buf[data->total - i - 1] != pad_length) {
				data->error = 1;
				return;
			}
		}
		// unpad data
		data->total -= pad_length;
		data->unpadded = 1;
	}
}

// read from AES256 CBC stream
static size_t aes256_cbc_sread(void *ptr, size_t size, size_t nmemb,
		cx9r_stream_t *stream) {
	aes256_cbc_data_t *data;
	cx9r_stream_t *in;
	size_t total;
	size_t pos;
	size_t n;
	uint8_t *out;

	data = (aes256_cbc_data_t*) stream->data;
	out = (uint8_t*) ptr;
	in = data->in;
	total = size * nmemb;
	pos = 0;

	while (pos < total) {
		if (data->pos == data->total) {
			data->eof = 1;
			break;
		}

		if ((data->pos == (AES256_CBC_BUF_LENGTH - CX9R_AES256_BLOCK_LENGTH))
				&& !data->unpadded) {
			n = data->total - data->pos;
			memcpy(data->buf, data->buf + data->pos, n);
			data->pos = 0;
			data->total = n;
			aes256_cbc_fill_buf(data);
		}

		n = MIN(data->total - data->pos, total - pos);
		n = MIN(AES256_CBC_BUF_LENGTH - CX9R_AES256_BLOCK_LENGTH - data->pos, n);

		memcpy(out + pos, data->buf + data->pos, n);
		pos += n;
		data->pos += n;
	}

	return pos / size;
}

// AES256 CBC stream end of file
static int aes256_cbc_seof(cx9r_stream_t *stream) {
	aes256_cbc_data_t *data;
	cx9r_stream_t *in;

	data = (aes256_cbc_data_t*) stream->data;
	in = data->in;

	return data->eof;
}

// AES256 CBC stream error
static int aes256_cbc_serror(cx9r_stream_t *stream) {
	aes256_cbc_data_t *data;
	cx9r_stream_t *in;

	data = (aes256_cbc_data_t*) stream->data;
	in = data->in;

	return (cx9r_serror(in) || data->error);
}

// buffered file stream close
static int aes256_cbc_sclose(cx9r_stream_t *stream) {
	aes256_cbc_data_t *data;
	cx9r_aes256_cbc_ctx *ctx;
	cx9r_stream_t *in;

	data = (aes256_cbc_data_t*) stream->data;
	in = data->in;
	ctx = data->ctx;

	cx9r_aes256_cbc_close(ctx);
	free(ctx);
	free(data);
	free(stream);
	return cx9r_sclose(in);

}

// open AES CBC encrypted stream
cx9r_stream_t *cx9r_aes256_cbc_sopen(cx9r_stream_t *in, void *key, void* iv) {
	cx9r_stream_t *stream;
	aes256_cbc_data_t *data;
	cx9r_aes256_cbc_ctx *ctx;

	CHEQ(((stream = malloc(sizeof(cx9r_stream_t))) != NULL),
			bail);

	CHEQ(((stream->data = data = malloc(sizeof(aes256_cbc_data_t))) != NULL),
			cleanup_stream);

	CHEQ(((data->ctx = ctx = malloc(sizeof(cx9r_aes256_cbc_ctx))) != NULL),
			cleanup_data);

	CHEQ((cx9r_aes256_cbc_init(ctx, key, iv) == CX9R_OK), cleanup_ctx);

	data->in = in;
	data->ctx = ctx;
	data->total = 0;
	data->pos = 0;
	data->error = 0;
	data->eof = 0;
	data->unpadded = 0;

	stream->sread = aes256_cbc_sread;
	stream->seof = aes256_cbc_seof;
	stream->serror = aes256_cbc_serror;
	stream->sclose = aes256_cbc_sclose;

	aes256_cbc_fill_buf(data);

	goto bail;

cleanup_ctx:

	free(ctx);

cleanup_data:

	free(data);

cleanup_stream:

	free(stream);
	stream = NULL;

bail:
	return stream;
}
