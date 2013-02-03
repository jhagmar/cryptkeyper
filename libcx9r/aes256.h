// This a wrapper for libraries containing AES256 implementations.
// Currently only libgcrypt supported.
#ifndef CKPR_AES256_H
#define CKPR_AES256_H

#include "../config.h"

#define AES256_KEY_LENGTH 32
#define AES256_BLOCK_LENGTH 16

#ifdef GCRYPT_WITH_AES
#   include <gcrypt.h>
    typedef gcry_cipher_hd_t aes256_ecb_ctx;
    typedef gcry_cipher_hd_t aes256_cbc_ctx;
#else
#error No libgcrypt support for aes256
#endif

#include <stdint.h>

void aes256_ecb_init(aes256_ecb_ctx *ctx, uint8_t *key);
void aes256_ecb_encrypt(aes256_ecb_ctx *ctx, uint8_t *block);
void aes256_ecb_close(aes256_ecb_ctx *ctx);

void aes256_cbc_init(aes256_ecb_ctx *ctx, uint8_t *key, uint8_t *iv);
void aes256_cbc_decrypt(aes256_ecb_ctx *ctx, uint8_t *buffer, size_t length);
void aes256_cbc_close(aes256_ecb_ctx *ctx);


#endif

