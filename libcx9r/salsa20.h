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

#ifndef CX9R_SALSA20_H
#define CX9R_SALSA20_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#else
#error No stdint.h available
#endif

#define CX9R_SALSA20_STATE_LENGTH_8 64
#define CX9R_SALSA20_STATE_LENGTH_32 (CX9R_SALSA20_STATE_LENGTH_8/4)

typedef struct {
	uint32_t state[CX9R_SALSA20_STATE_LENGTH_32];
	uint8_t output[CX9R_SALSA20_STATE_LENGTH_8];
	uint8_t pos;
} cx9r_salsa20_ctx;

void cx9r_salsa20_128_init(cx9r_salsa20_ctx *ctx, const uint8_t *key,
		const uint8_t *iv);
void cx9r_salsa20_256_init(cx9r_salsa20_ctx *ctx, const uint8_t *key,
		const uint8_t *iv);
void cx9r_salsa20_encrypt(cx9r_salsa20_ctx *ctx,const uint8_t *input,
		uint8_t *output,uint32_t length);
void cx9r_salsa20_decrypt(cx9r_salsa20_ctx *ctx, const uint8_t *input,
		uint8_t *output, uint32_t length);
void cx9r_salsa20_keystream(cx9r_salsa20_ctx *ctx, uint8_t *output, uint32_t length);

#endif
