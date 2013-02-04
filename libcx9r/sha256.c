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

#include "sha256.h"
#include <string.h>

void sha256_init(sha256_ctx *ctx)
{
  gcry_md_open(ctx, GCRY_MD_SHA256, 0);
}

void sha256_process(sha256_ctx *ctx, uint8_t *buffer, size_t length)
{
  gcry_md_write(*ctx, buffer, length);
}

void sha256_close(sha256_ctx *ctx, uint8_t *hash)
{
  memcpy(hash, gcry_md_read(*ctx, GCRY_MD_SHA256), SHA256_HASH_LENGTH);
  gcry_md_close(*ctx);
}

void sha256_hash_buffer(uint8_t *hash, uint8_t *buffer, size_t length)
{
  gcry_md_hash_buffer(GCRY_MD_SHA256, hash, buffer, length);
}
