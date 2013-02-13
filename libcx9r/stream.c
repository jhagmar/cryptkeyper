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
#include "sha256.h"
#include "util.h"
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

#define BUF_FILE_BUF_LENGTH (1 << 16)
#define MIN(x,y) ((x < y) ? x : y)

// stream read
size_t cx9r_sread(void *ptr, size_t size, size_t nmemb, cx9r_stream_t *stream) {
	if (cx9r_seof(stream) || cx9r_serror(stream)) {
		return 0;
	}
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

// read from file stream
static size_t file_sread(void *ptr, size_t size, size_t nmemb,
		cx9r_stream_t *stream) {
	file_data_t *data;
	FILE *file;

	data = (file_data_t*) stream->data;
	file = data->file;

	return fread(ptr, size, nmemb, file);
}

// file stream end of file
static int file_seof(cx9r_stream_t *stream) {
	file_data_t *data;
	FILE *file;

	data = (file_data_t*) stream->data;
	file = data->file;

	return feof(file);
}

// file stream error
static int file_serror(cx9r_stream_t *stream) {
	file_data_t *data;
	FILE *file;

	data = (file_data_t*) stream->data;
	file = data->file;

	return ferror(file);
}

// file stream close
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

// extended context for KeePass hashed stream
typedef struct {
	cx9r_stream_t *in;
	uint8_t *buf;
	size_t total;
	size_t pos;
	uint32_t buf_index;
	int eof;
	int error;
} hash_data_t;

// read from hashed stream
static size_t hash_sread(void *ptr, size_t size, size_t nmemb,
		cx9r_stream_t *stream) {
	hash_data_t *data;
	size_t total;
	size_t pos;
	size_t n;
	uint8_t *out;
	uint8_t raw_buf_index[sizeof(uint32_t)];
	uint8_t raw_buf_length[sizeof(int32_t)];
	int32_t buf_length;
	uint8_t read_hash[CX9R_SHA256_HASH_LENGTH];
	uint8_t comp_hash[CX9R_SHA256_HASH_LENGTH];
	size_t i;

	data = (hash_data_t*) stream->data;
	out = (uint8_t*) ptr;
	total = size * nmemb;
	pos = 0;

	while (pos < total) {
		if (data->pos == data->total) {
			if (cx9r_sread(raw_buf_index, 1, sizeof(uint32_t), data->in) != sizeof(uint32_t)) {
				data->error = 1;
				break;
			}
			if (cx9r_lsb_to_uint32(raw_buf_index) != data->buf_index) {
				data->error = 1;
				break;
			}
			data->buf_index++;
			if (cx9r_sread(read_hash, 1, CX9R_SHA256_HASH_LENGTH, data->in) != CX9R_SHA256_HASH_LENGTH) {
				data->error = 1;
				break;
			}
			if (cx9r_sread(raw_buf_length, 1, sizeof(int32_t), data->in) != sizeof(int32_t)) {
				data->error = 1;
				break;
			}
			buf_length = cx9r_lsb_to_int32(raw_buf_length);
			if (buf_length < 0) {
				data->error = 1;
				break;
			}
			if (buf_length == 0) {
				for (i = 0; i < CX9R_SHA256_HASH_LENGTH; i++) {
					if (read_hash[i] != 0) {
						data->error = 1;
						break;
					}
				}
				data->eof = 1;
				break;
			}
			if (data->buf != NULL) {
				free(data->buf);
				data->buf = NULL;
			}
			if ((data->buf = malloc(buf_length)) == NULL) {
				data->error = 1;
				break;
			}
			if (cx9r_sread(data->buf, 1, buf_length, data->in) != buf_length) {
				data->error = 1;
				free(data->buf);
				data->buf = NULL;
				break;
			}
			cx9r_sha256_hash_buffer(comp_hash, data->buf, buf_length);
			if (memcmp(comp_hash, read_hash, CX9R_SHA256_HASH_LENGTH) != 0) {
				data->error = 1;
				free(data->buf);
				data->buf = NULL;
				break;
			}
			data->pos = 0;
			data->total = buf_length;
		}

		n = MIN(data->total - data->pos, total - pos);

		memcpy(out + pos, data->buf + data->pos, n);
		pos += n;
		data->pos += n;
	}

bail:

	return pos / size;
}

// hashed stream end of file
static int hash_seof(cx9r_stream_t *stream) {
	hash_data_t *data;
	cx9r_stream_t *in;

	data = (hash_data_t*) stream->data;
	in = data->in;

	return (data->eof && (data->pos == data->total));
}

// hashed stream error
static int hash_serror(cx9r_stream_t *stream) {
	hash_data_t *data;
	cx9r_stream_t *in;

	data = (hash_data_t*) stream->data;
	in = data->in;

	return (cx9r_serror(in) || data->error);
}

// hashed stream close
static int hash_sclose(cx9r_stream_t *stream) {
	hash_data_t *data;
	cx9r_stream_t *in;

	data = (hash_data_t*) stream->data;
	in = data->in;

	if (data->buf != NULL) {
		free(data->buf);
	}
	free(data);
	free(stream);
	return cx9r_sclose(in);
}

// open KeePass hashed stream
cx9r_stream_t *cx9r_hash_sopen(cx9r_stream_t *in) {
	cx9r_stream_t *stream;
	hash_data_t *data;

	CHEQ(((stream = malloc(sizeof(cx9r_stream_t))) != NULL), bail);

	CHEQ(((stream->data = data = malloc(sizeof(hash_data_t))) != NULL),
			cleanup_stream);

	data->in = in;
	data->total = 0;
	data->pos = 0;
	data->error = 0;
	data->buf_index = 0;
	data->eof = 0;
	data->buf = NULL;

	stream->sread = hash_sread;
	stream->seof = hash_seof;
	stream->serror = hash_serror;
	stream->sclose = hash_sclose;

	goto bail;

cleanup_stream:

	free(stream);
	stream = NULL;

bail:
	return stream;
}

#define CHUNK 16384

//int inf(FILE *source, FILE *dest)
//{
//    int ret;
//    unsigned have;
//    z_stream strm;
//    unsigned char in[CHUNK];
//    unsigned char out[CHUNK];
//
//    /* allocate inflate state */
//    strm.zalloc = Z_NULL;
//    strm.zfree = Z_NULL;
//    strm.opaque = Z_NULL;
//    strm.avail_in = 0;
//    strm.next_in = Z_NULL;
//    ret = inflateInit(&strm);
//    if (ret != Z_OK)
//        return ret;
//
//    /* decompress until deflate stream ends or end of file */
//    do {
//        strm.avail_in = fread(in, 1, CHUNK, source);
//        if (ferror(source)) {
//            (void)inflateEnd(&strm);
//            return Z_ERRNO;
//        }
//        if (strm.avail_in == 0)
//            break;
//        strm.next_in = in;
//
//        /* run inflate() on input until output buffer not full */
//        do {
//            strm.avail_out = CHUNK;
//            strm.next_out = out;
//            ret = inflate(&strm, Z_NO_FLUSH);
//            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
//            switch (ret) {
//            case Z_NEED_DICT:
//                ret = Z_DATA_ERROR;     /* and fall through */
//            case Z_DATA_ERROR:
//            case Z_MEM_ERROR:
//                (void)inflateEnd(&strm);
//                return ret;
//            }
//            have = CHUNK - strm.avail_out;
//            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
//                (void)inflateEnd(&strm);
//                return Z_ERRNO;
//            }
//        } while (strm.avail_out == 0);
//
//        /* done when inflate() says it's done */
//    } while (ret != Z_STREAM_END);
//
//    /* clean up and return */
//    (void)inflateEnd(&strm);
//    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
//}

// buffer size recommendation on zlib home page for efficient
// operation is 2^18 bytes
#define GZIP_BUF_LENGTH (1 << 18)

// extended context for gzip stream
typedef struct {
	cx9r_stream_t *in;
	z_stream zstrm;
	uint8_t buf[GZIP_BUF_LENGTH];
	int error;
	int eof;
} gzip_data_t;

// read from gzip stream
static size_t gzip_sread(void *ptr, size_t size, size_t nmemb,
		cx9r_stream_t *stream) {
	gzip_data_t *data;
	cx9r_stream_t *in;
	z_stream *zstrm;
	size_t total;
	size_t n;
	uint8_t *out;
	int ret;

	data = (gzip_data_t*) stream->data;
	zstrm = &data->zstrm;
	out = (uint8_t*) ptr;
	in = data->in;
	total = zstrm->avail_out = size * nmemb;
	zstrm->next_out = out;

	while (zstrm->avail_out != 0) {
		if (zstrm->avail_in == 0) {
			n = cx9r_sread(data->buf, 1, GZIP_BUF_LENGTH, in);
			if (n == 0) {
				data->eof = 1;
				break;
			}
			zstrm->next_in = data->buf;
			zstrm->avail_in = n;
		}

		ret = inflate(zstrm, Z_NO_FLUSH);
		if ((ret == Z_NEED_DICT)
				|| (ret == Z_STREAM_ERROR)
				|| (ret == Z_DATA_ERROR)
				|| (ret == Z_MEM_ERROR)) {
			data->error = 1;
			break;
		}
		if (ret == Z_STREAM_END) {
			data->eof = 1;
		}
	}

	return (total - zstrm->avail_out) / size;
}

// gzip stream end of file
static int gzip_seof(cx9r_stream_t *stream) {
	gzip_data_t *data;
	cx9r_stream_t *in;

	data = (gzip_data_t*) stream->data;
	in = data->in;

	return data->eof;
}

// gzip stream error
static int gzip_serror(cx9r_stream_t *stream) {
	gzip_data_t *data;
	cx9r_stream_t *in;

	data = (gzip_data_t*) stream->data;
	in = data->in;

	return (cx9r_serror(in) || data->error);
}

// gzip stream close
static int gzip_sclose(cx9r_stream_t *stream) {
	gzip_data_t *data;
	cx9r_stream_t *in;

	data = (gzip_data_t*) stream->data;
	in = data->in;

	inflateEnd(&data->zstrm);
	free(data);
	free(stream);
	return cx9r_sclose(in);
}

#define GZIP_WINDOW_BITS (15 + 16) // largest window size, only gzip decompression

// open gzip encrypted stream
cx9r_stream_t *cx9r_gzip_sopen(cx9r_stream_t *in) {
	cx9r_stream_t *stream;
	gzip_data_t *data;
	z_stream *zstrm;

	CHEQ(((stream = malloc(sizeof(cx9r_stream_t))) != NULL),
			bail);

	CHEQ(((stream->data = data = malloc(sizeof(gzip_data_t))) != NULL),
			cleanup_stream);

	data->in = in;
	data->eof = 0;
	data->error = 0;
	zstrm = &data->zstrm;
	zstrm->zalloc = Z_NULL;
	zstrm->zfree = Z_NULL;
	zstrm->opaque = Z_NULL;
	zstrm->avail_in = 0;
	zstrm->next_in = Z_NULL;
	CHEQ((inflateInit2(zstrm, GZIP_WINDOW_BITS) == Z_OK), cleanup_data);

	stream->sread = gzip_sread;
	stream->seof = gzip_seof;
	stream->serror = gzip_serror;
	stream->sclose = gzip_sclose;

	goto bail;

cleanup_data:

	free(data);

cleanup_stream:

	free(stream);
	stream = NULL;

bail:
	return stream;
}

