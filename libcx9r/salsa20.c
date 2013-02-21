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

#define MIN(x,y) ((x) < (y)) ? (x) : (y)

//#define U32TO8_LITTLE(out, in) { \
//	(out)[0] = (uint8_t)in; \
//	(out)[1] = (uint8_t)(in >> 8); \
//	(out)[2] = (uint8_t)(in >> 16); \
//	(out)[3] = (uint8_t)(in >> 24); \
//}

#if (BYTEORDER == 4321)
#define U8TO32_LITTLE(in) (in)[0] | ((in)[1] << 8) | ((in)[2] << 16) | ((in)[3] << 24);
#else
#define U8TO32_LITTLE(in) *((uint32_t*)(in))
#endif

static void salsa20_generate_output(cx9r_salsa20_ctx *ctx) {

	uint32_t *state;
	uint32_t x[16];
	uint32_t in[16];
	uint32_t *out = (uint32_t*) ctx->output;
#if (BYTEORDER == 4321)
	uint32_t t;
#endif

	state = ctx->state;

	x[0] = in[0] = state[0];
	x[1] = in[1] = state[1];
	x[2] = in[2] = state[2];
	x[3] = in[3] = state[3];
	x[4] = in[4] = state[4];
	x[5] = in[5] = state[5];
	x[6] = in[6] = state[6];
	x[7] = in[7] = state[7];
	x[8] = in[8] = state[8];
	x[9] = in[9] = state[9];
	x[10] = in[10] = state[10];
	x[11] = in[11] = state[11];
	x[12] = in[12] = state[12];
	x[13] = in[13] = state[13];
	x[14] = in[14] = state[14];
	x[15] = in[15] = state[15];

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

#if (BYTEORDER == 4321)
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
#else
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
#endif

	ctx->pos = 0;
	ctx->state[8]++;
	if (!ctx->state[8]) {
		ctx->state[9]++;
		/* stopping at 2^70 bytes per nonce is user's responsibility */
	}
}

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

static void salsa20_init(cx9r_salsa20_ctx *ctx, const uint8_t *key,
		uint32_t n_key_bits, const uint8_t *iv)
{
  const char *constants;

  ctx->state[1] = U8TO32_LITTLE(key + 0);
  ctx->state[2] = U8TO32_LITTLE(key + 4);
  ctx->state[3] = U8TO32_LITTLE(key + 8);
  ctx->state[4] = U8TO32_LITTLE(key + 12);
  if (n_key_bits == 256) { /* recommended */
    key += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  ctx->state[11] = U8TO32_LITTLE(key + 0);
  ctx->state[12] = U8TO32_LITTLE(key + 4);
  ctx->state[13] = U8TO32_LITTLE(key + 8);
  ctx->state[14] = U8TO32_LITTLE(key + 12);
  ctx->state[0] = U8TO32_LITTLE(constants + 0);
  ctx->state[5] = U8TO32_LITTLE(constants + 4);
  ctx->state[10] = U8TO32_LITTLE(constants + 8);
  ctx->state[15] = U8TO32_LITTLE(constants + 12);
  ctx->state[6] = U8TO32_LITTLE(iv + 0);
  ctx->state[7] = U8TO32_LITTLE(iv + 4);
  ctx->state[8] = 0;
  ctx->state[9] = 0;
  ctx->pos = CX9R_SALSA20_STATE_LENGTH_8;
}

void cx9r_salsa20_128_init(cx9r_salsa20_ctx *ctx, const uint8_t *key,
		const uint8_t *iv) {
	salsa20_init(ctx, key, 128, iv);
}

void cx9r_salsa20_256_init(cx9r_salsa20_ctx *ctx, const uint8_t *key,
		const uint8_t *iv) {
	salsa20_init(ctx, key, 256, iv);
}

void cx9r_salsa20_encrypt(cx9r_salsa20_ctx *ctx,const uint8_t *input,
		uint8_t *output,uint32_t length)
{
	uint32_t i;
	uint32_t n;
	uint8_t *keystream;

	while (length) {

		if (ctx->pos == CX9R_SALSA20_STATE_LENGTH_8) {
			salsa20_generate_output(ctx);
		}

		n = MIN(CX9R_SALSA20_STATE_LENGTH_8 - ctx->pos, length);

		keystream = ctx->output + ctx->pos;

		for (i = 0; i < n; i++) {
			output[i] = input[i] ^ keystream[i];
		}

		length -= n;
		output += n;
		input += n;
		ctx->pos += n;
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
