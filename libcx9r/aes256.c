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

#include "aes256.h"

void aes256_ecb_init(aes256_ecb_ctx *ctx, uint8_t *key)
{
  gcry_cipher_open(ctx, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
  gcry_cipher_setkey(*ctx, key, AES256_KEY_LENGTH);
}

void aes256_ecb_encrypt(aes256_ecb_ctx *ctx, uint8_t *block)
{
  gcry_cipher_encrypt(*ctx, block, AES256_BLOCK_LENGTH, NULL, 0);
}

void aes256_ecb_close(aes256_ecb_ctx *ctx)
{
  gcry_cipher_close(*ctx);
}

void aes256_cbc_init(aes256_cbc_ctx *ctx, uint8_t *key, uint8_t *iv)
{
  gcry_cipher_open(ctx, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
  gcry_cipher_setkey(*ctx, key, AES256_KEY_LENGTH);
  gcry_cipher_setiv(*ctx, iv, AES256_BLOCK_LENGTH);
}

void aes256_cbc_decrypt(aes256_ecb_ctx *ctx, uint8_t *buffer, size_t length)
{
  gcry_cipher_decrypt(*ctx, buffer, length, NULL, 0);
}

void aes256_cbc_close(aes256_cbc_ctx *ctx)
{
  gcry_cipher_close(*ctx);
}
