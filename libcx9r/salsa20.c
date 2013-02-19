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

/*
 * Based on:
salsa20-ref.c version 20051118
D. J. Bernstein
Public domain.
*/

#include <config.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#else
#error No stdint.h available
#endif
#include "salsa20.h"

#define ROTL(v,n) ((v << n) | (v >> (32 - n)))

#define F(n1, n2, n3, n) x[n1] ^= ROTL( (x[n2] + x[n3]), n )

#define QUARTERROUND(n0, n1, n2, n3) { \
	F(n1, n0, n3, 7);	\
	F(n2, n1, n0, 9);	\
	F(n3, n2, n1, 13);	\
	F(n0, n3, n2, 18);  \
}

#define COLUMNROUND {				\
	QUARTERROUND( 0,  4,  8, 12);	\
	QUARTERROUND( 5,  9, 13,  1);	\
	QUARTERROUND(10, 14,  2,  6);	\
	QUARTERROUND(15,  3,  7, 11);	\
}

#define ROWROUND {				\
	QUARTERROUND( 0,  1,  2,  3);	\
	QUARTERROUND( 5,  6,  7,  4);	\
	QUARTERROUND(10, 11,  8,  9);	\
	QUARTERROUND(15, 12, 13, 14);	\
}

#define DOUBLEROUND {			\
	COLUMNROUND;				\
	ROWROUND;					\
}

#define U32TO8_LITTLE(out, in) { \
	(out)[0] = (uint8_t)in; \
	(out)[1] = (uint8_t)(in >> 8); \
	(out)[2] = (uint8_t)(in >> 16); \
	(out)[3] = (uint8_t)(in >> 24); \
}

#define U8TO32_LITTLE(in) (in)[0] | ((in)[1] << 8) | ((in)[2] << 16) | ((in)[3] << 24);

static void salsa20_wordtobyte(uint8_t output[64], uint32_t const input[16])
{
  uint32_t x[16];
  int i;

  for (i = 0;i < 16;++i) x[i] = input[i];

  DOUBLEROUND;
  DOUBLEROUND;
  DOUBLEROUND;
  DOUBLEROUND;
  DOUBLEROUND;
  DOUBLEROUND;
  DOUBLEROUND;
  DOUBLEROUND;
  DOUBLEROUND;
  DOUBLEROUND;

  for (i = 0;i < 16;++i) x[i] += input[i];
  for (i = 0;i < 16;++i) U32TO8_LITTLE(output + 4 * i,x[i]);
}

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void cx9r_salsa20_init(cx9r_salsa20_ctx *x, const uint8_t *key,
		uint32_t n_key_bits, const uint8_t *iv)
{
  const char *constants;

  x->input[1] = U8TO32_LITTLE(key + 0);
  x->input[2] = U8TO32_LITTLE(key + 4);
  x->input[3] = U8TO32_LITTLE(key + 8);
  x->input[4] = U8TO32_LITTLE(key + 12);
  if (n_key_bits == 256) { /* recommended */
    key += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  x->input[11] = U8TO32_LITTLE(key + 0);
  x->input[12] = U8TO32_LITTLE(key + 4);
  x->input[13] = U8TO32_LITTLE(key + 8);
  x->input[14] = U8TO32_LITTLE(key + 12);
  x->input[0] = U8TO32_LITTLE(constants + 0);
  x->input[5] = U8TO32_LITTLE(constants + 4);
  x->input[10] = U8TO32_LITTLE(constants + 8);
  x->input[15] = U8TO32_LITTLE(constants + 12);
  x->input[6] = U8TO32_LITTLE(iv + 0);
  x->input[7] = U8TO32_LITTLE(iv + 4);
  x->input[8] = 0;
  x->input[9] = 0;
}

void cx9r_salsa20_encrypt(cx9r_salsa20_ctx *x,const uint8_t *input,
		uint8_t *output,uint32_t length)
{
  uint8_t buffer[64];
  int i;

  if (!length) return;
  for (;;) {
    salsa20_wordtobyte(buffer,x->input);
    x->input[8]++;
    if (!x->input[8]) {
      x->input[9]++;
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }
    if (length <= 64) {
      for (i = 0;i < length;++i) output[i] = input[i] ^ buffer[i];
      return;
    }
    for (i = 0;i < 64;++i) output[i] = input[i] ^ buffer[i];
    length -= 64;
    output += 64;
    input += 64;
  }
}

void cx9r_salsa20_decrypt(cx9r_salsa20_ctx *ctx, const uint8_t *input,
		uint8_t *output, uint32_t length)
{
	cx9r_salsa20_encrypt(ctx, input, output, length);
}

void cx9r_salsa20_keystream(cx9r_salsa20_ctx *ctx, uint8_t *output, uint32_t length)
{
  uint32_t i;
  for (i = 0; i < length; ++i) output[i] = 0;
  cx9r_salsa20_encrypt(ctx, output, output, length);
}
