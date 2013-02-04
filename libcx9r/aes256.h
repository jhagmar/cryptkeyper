/* Cryptkeyper is
 *
 *     Copyright (C) 2013 Jonas Hagmar (jonas.hagmar@gmail.com)
 *
 * This file is part of Cryptkeyper.
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
 * along with Cryptkeyper. If not, see <http://www.gnu.org/licenses/>.
 */

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

