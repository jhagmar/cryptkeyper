// This a wrapper for libraries containing SHA256 implementations.
// Currently only libgcrypt supported.
#ifndef CKPR_SHA256_H
#define CKPR_SHA256_H

#include "../config.h"

#define SHA256_HASH_LENGTH 32

#ifdef GCRYPT_WITH_SHA256
#   include <gcrypt.h>
    typedef gcry_md_hd_t sha256_ctx;
#else
#error No libgcrypt support for sha256
#endif

#include <stdint.h>

void sha256_init(sha256_ctx *ctx);
void sha256_process(sha256_ctx *ctx, uint8_t *buffer, size_t length);
void sha256_close(sha256_ctx *ctx, uint8_t *hash);
void sha256_hash_buffer(uint8_t *hash, uint8_t *buffer, size_t length);

#endif

