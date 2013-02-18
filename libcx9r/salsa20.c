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

#define ROTL(v,n) ((v << n) | (v >> (32 - n)))

#define F(r1, r2, r3, n) r1 ^= ROTL32( (r2 + r3), n )

#define QUARTERROUND(n1, n2, n3, n4) {  \
	F(x[n1], x[n4], x[n3], 7); 	\
	F(x[n2], x[n1], x[n4], 9);	\
	F(x[n3], x[n2], x[n1], 13);	\
	F(x[n4], x[n3], x[n2], 18);  \
}

#define U32TO8_LITTLE(out, in) { \
	(out)[0] = (uint8_t)in; \
	(out)[1] = (uint8_t)(in >> 8); \
	(out)[2] = (uint8_t)(in >> 16); \
	(out)[3] = (uint8_t)(in >> 24); \
}

#define U8TO32_LITTLE(in) (in)[0] | ((in)[1] << 8) | ((in)[2] << 16) | ((in)[3] << 24);

typedef struct {
	uint32_t input[16];
} ECRYPT_ctx;

static void salsa20_wordtobyte(uint8_t output[64], uint32_t const input[16])
{
  uint32_t x[16];
  int i;

  for (i = 0;i < 16;++i) x[i] = input[i];
  for (i = 20;i > 0;i -= 2) {
	  QUARTERROUND( 4,  8, 12,  0);
	  QUARTERROUND( 9, 13,  1,  5);
	  QUARTERROUND(14,  2,  6, 10);
	  QUARTERROUND( 3,  7, 11, 15);
	  QUARTERROUND( 1,  2,  3,  0);
	  QUARTERROUND( 6,  7,  4,  5);
	  QUARTERROUND(11,  8,  9, 10);
	  QUARTERROUND(12, 13, 14, 15);
  }
  for (i = 0;i < 16;++i) x[i] += input[i];
  for (i = 0;i < 16;++i) U32TO8_LITTLE(output + 4 * i,x[i]);
}

void ECRYPT_init(void)
{
  return;
}

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void ECRYPT_keysetup(ECRYPT_ctx *x,const uint8_t *k,uint32_t kbits,uint32_t ivbits)
{
  const char *constants;

  x->input[1] = U8TO32_LITTLE(k + 0);
  x->input[2] = U8TO32_LITTLE(k + 4);
  x->input[3] = U8TO32_LITTLE(k + 8);
  x->input[4] = U8TO32_LITTLE(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  x->input[11] = U8TO32_LITTLE(k + 0);
  x->input[12] = U8TO32_LITTLE(k + 4);
  x->input[13] = U8TO32_LITTLE(k + 8);
  x->input[14] = U8TO32_LITTLE(k + 12);
  x->input[0] = U8TO32_LITTLE(constants + 0);
  x->input[5] = U8TO32_LITTLE(constants + 4);
  x->input[10] = U8TO32_LITTLE(constants + 8);
  x->input[15] = U8TO32_LITTLE(constants + 12);
}

void ECRYPT_ivsetup(ECRYPT_ctx *x,const uint8_t *iv)
{
  x->input[6] = U8TO32_LITTLE(iv + 0);
  x->input[7] = U8TO32_LITTLE(iv + 4);
  x->input[8] = 0;
  x->input[9] = 0;
}

void ECRYPT_encrypt_bytes(ECRYPT_ctx *x,const uint8_t *m,uint8_t *c,uint32_t bytes)
{
  uint8_t output[64];
  int i;

  if (!bytes) return;
  for (;;) {
    salsa20_wordtobyte(output,x->input);
    x->input[8]++;
    if (!x->input[8]) {
      x->input[9]++;
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }
    if (bytes <= 64) {
      for (i = 0;i < bytes;++i) c[i] = m[i] ^ output[i];
      return;
    }
    for (i = 0;i < 64;++i) c[i] = m[i] ^ output[i];
    bytes -= 64;
    c += 64;
    m += 64;
  }
}

void ECRYPT_decrypt_bytes(ECRYPT_ctx *x,const uint8_t *c,uint8_t *m,uint32_t bytes)
{
  ECRYPT_encrypt_bytes(x,c,m,bytes);
}

void ECRYPT_keystream_bytes(ECRYPT_ctx *x,uint8_t *stream,uint32_t bytes)
{
  uint32_t i;
  for (i = 0;i < bytes;++i) stream[i] = 0;
  ECRYPT_encrypt_bytes(x,stream,stream,bytes);
}
