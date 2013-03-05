#ifndef CX9R_H
#define CX9R_H

#include <stdio.h>

enum cx9r_err_enum {
	CX9R_OK,
	CX9R_BAD_MAGIC,				// incorrect magic bytes
	CX9R_UNSUPPORTED_VERSION,	// unsupported file version
	CX9R_FILE_READ_ERR,			// error while reading file
	CX9R_MEM_ALLOC_ERR,			// memory allocation error
	CX9R_UNKNOWN_CIPHER,		// unknown cipher algorithm
	CX9R_UNKNOWN_COMPRESSION,	// unknown compression algorithm
	CX9R_WRONG_MASTER_SEED_LENGTH, // wrong length of master seed
	// wrong length of # of transformation rounds field
	CX9R_WRONG_N_TRANSFORM_ROUNDS_LENGTH,
	CX9R_WRONG_IV_LENGTH,		// wrong length of IV
	// wrong length of stream start bytes
	CX9R_WRONG_STREAM_START_BYTES_LENGTH,
	// wrong length of inner random stream id
	CX9R_WRONG_INNER_RANDOM_STREAM_ID_LENGTH,
	CX9R_BAD_HEADER_FIELD_ID,	// bad header field id
	CX9R_INIT_FAILURE,          // initalization failed
	CX9R_SHA256_FAILURE,		// sha256 computation failed
	CX9R_AES256_FAILURE,		// aes256 operation failed
	CX9R_KEY_VERIFICATION_FAILED, // failed to verify key
	CX9R_STREAM_OPEN_ERR,		// error opening stream
	CX9R_PARSE_ERR				// parsing error
};

typedef enum cx9r_err_enum cx9r_err;	// return code
typedef void * cx9r_ctx;		// context

cx9r_err cx9r_init();
cx9r_err cx9r_kdbx_read(FILE *f, char *passphrase);

#endif
