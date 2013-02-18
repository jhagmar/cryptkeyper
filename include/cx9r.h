#ifndef CX9R_H
#define CX9R_H

#include <stdio.h>

#define CX9R_OK 0
#define CX9R_BAD_MAGIC 1		// incorrect magic bytes
#define CX9R_UNSUPPORTED_VERSION 2	// unsupported file version
#define CX9R_FILE_READ_ERR 3		// error while reading file
#define CX9R_MEM_ALLOC_ERR 4		// memory allocation error
#define CX9R_UNKNOWN_CIPHER 5		// unknown cipher algorithm
#define CX9R_UNKNOWN_COMPRESSION 6	// unknown compression algorithm
#define CX9R_WRONG_MASTER_SEED_LENGTH 7 // wrong length of master seed
// wrong length of # of transformation rounds field
#define CX9R_WRONG_N_TRANSFORM_ROUNDS_LENGTH 8
#define CX9R_WRONG_IV_LENGTH 9		// wrong length of IV
// wrong length of stream start bytes
#define CX9R_WRONG_STREAM_START_BYTES_LENGTH 10
// wrong length of inner random stream id
#define CX9R_WRONG_INNER_RANDOM_STREAM_ID_LENGTH 11
#define CX9R_BAD_HEADER_FIELD_ID 12	// bad header field id
#define CX9R_INIT_FAILURE 13            // initalization failed
#define CX9R_SHA256_FAILURE 14			// sha256 computation failed
#define CX9R_AES256_FAILURE 15			// aes256 operation failed
#define CX9R_KEY_VERIFICATION_FAILED 16 // failed to verify key
#define CX9R_STREAM_OPEN_ERR 17			// error opening stream

typedef int cx9r_err;			// return code
typedef void * cx9r_ctx;		// context

cx9r_err cx9r_init();
cx9r_err cx9r_kdbx_read(FILE *f, char *passphrase);

#endif
