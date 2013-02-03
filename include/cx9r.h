#ifndef CRYPTKEYPER_H
#define CRYPTKEYPER_H

#include <stdio.h>

#define CKPR_OK 0
#define CKPR_BAD_MAGIC 1		// incorrect magic bytes
#define CKPR_UNSUPPORTED_VERSION 2	// unsupported file version
#define CKPR_FILE_READ_ERR 3		// error while reading file
#define CKPR_MEM_ALLOC_ERR 4		// memory allocation error
#define CKPR_UNKNOWN_CIPHER 5		// unknown cipher algorithm
#define CKPR_UNKNOWN_COMPRESSION 6	// unknown compression algorithm
#define CKPR_WRONG_MASTER_SEED_LENGTH 7 // wrong length of master seed
// wrong length of # of transformation rounds field
#define CKPR_WRONG_N_TRANSFORM_ROUNDS_LENGTH 8
#define CKPR_WRONG_IV_LENGTH 9		// wrong length of IV
// wrong length of stream start bytes
#define CKPR_WRONG_STREAM_START_BYTES_LENGTH 10
// wrong length of inner random stream id
#define CKPR_WRONG_INNER_RANDOM_STREAM_ID_LENGTH 11
#define CKPR_BAD_HEADER_FIELD_ID 12	// bad header field id
#define CKPR_INIT_FAILURE 13            // initalization failed

typedef int ckpr_err;			// return code
typedef void * ckpr_ctx;		// context

ckpr_err ckpr_init();
ckpr_err ckpr_kdbx_read(FILE *f, char *passphrase);

#endif
