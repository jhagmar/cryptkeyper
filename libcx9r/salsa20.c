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

#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#error No config.h available
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#else
#error No stdint.h available
#endif
#include "salsa20.h"

#if ((BYTEORDER != 1234) && (BYTEORDER != 4321))
#error Endianness unknown. Define BYTEORDER to 1234 or 4321.
#endif

#define TOGGLE_ENDIAN(out, t, in) {	\
	((uint8_t *)&t)[3] = ((uint8_t *)&in)[0];	\
	((uint8_t *)&t)[2] = ((uint8_t *)&in)[1];	\
	((uint8_t *)&t)[1] = ((uint8_t *)&in)[2];	\
	((uint8_t *)&t)[0] = ((uint8_t *)&in)[3];	\
	out = t;									\
}

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
  uint32_t in[16];
  uint32_t *out = (uint32_t*)output;
  uint32_t t;
  int i;

  x[0] = in[0] = input[0];
  x[1] = in[1] = input[1];
  x[2] = in[2] = input[2];
  x[3] = in[3] = input[3];
  x[4] = in[4] = input[4];
  x[5] = in[5] = input[5];
  x[6] = in[6] = input[6];
  x[7] = in[7] = input[7];
  x[8] = in[8] = input[8];
  x[9] = in[9] = input[9];
  x[10] = in[10] = input[10];
  x[11] = in[11] = input[11];
  x[12] = in[12] = input[12];
  x[13] = in[13] = input[13];
  x[14] = in[14] = input[14];
  x[15] = in[15] = input[15];

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

  x[0] += in[0];
  x[1] += in[1];
  x[2] += in[2];
  x[3] += in[3];
  x[4] += in[4];
  x[5] += in[5];
  x[6] += in[6];
  x[7] += in[7];
  x[8] += in[8];
  x[9] += in[9];
  x[10] += in[10];
  x[11] += in[11];
  x[12] += in[12];
  x[13] += in[13];
  x[14] += in[14];
  x[15] += in[15];

#if (BYTEORDER == 1234)
  out[0] = x[0];
    out[1] = x[1];
    out[2] = x[2];
    out[3] = x[3];
    out[4] = x[4];
    out[5] = x[5];
    out[6] = x[6];
    out[7] = x[7];
    out[8] = x[8];
    out[9] = x[9];
    out[10] = x[10];
    out[11] = x[11];
    out[12] = x[12];
    out[13] = x[13];
    out[14] = x[14];
    out[15] = x[15];
#else
  TOGGLE_ENDIAN(out[0], t, x[0]);
  TOGGLE_ENDIAN(out[1], t, x[1]);
  TOGGLE_ENDIAN(out[2], t, x[2]);
  TOGGLE_ENDIAN(out[3], t, x[3]);
  TOGGLE_ENDIAN(out[4], t, x[4]);
  TOGGLE_ENDIAN(out[5], t, x[5]);
  TOGGLE_ENDIAN(out[6], t, x[6]);
  TOGGLE_ENDIAN(out[7], t, x[7]);
  TOGGLE_ENDIAN(out[8], t, x[8]);
  TOGGLE_ENDIAN(out[9], t, x[9]);
  TOGGLE_ENDIAN(out[10], t, x[10]);
  TOGGLE_ENDIAN(out[11], t, x[11]);
  TOGGLE_ENDIAN(out[12], t, x[12]);
  TOGGLE_ENDIAN(out[13], t, x[13]);
  TOGGLE_ENDIAN(out[14], t, x[14]);
  TOGGLE_ENDIAN(out[15], t, x[15]);
#endif
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
