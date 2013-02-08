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

#include <gcrypt.h>
#include <stdio.h>
#include <stdint.h>

#define DATA_LENGTH 64
#define DATA2_LENGTH  20
#define HASH_LENGTH 32
#define SEED_LENGTH 32

void check(gcry_error_t err)
{
  printf("%s\n", gcry_strerror(err));
}

void dbg(void *b, int len)
{
  int i;

  for (i = 0; i < len; i++)
  {
    printf("%x ", ((uint8_t *)b)[i]);
  }
  printf("\n");
}

void transform_key(uint8_t *key, uint8_t const *seed, int rounds)
{
  gcry_cipher_hd_t h;
  uint8_t const iv[16] = 
  {
    0,0,0,0,0,0,0,0
  };
  int i;

  check( gcry_cipher_open(&h, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0) );
  check( gcry_cipher_setkey(h, seed, 32) );
  check( gcry_cipher_setiv(h, iv, 16) );
  dbg(key, 32);
  for (i = 0; i < rounds; i++)
  {
    check( gcry_cipher_encrypt(h, key, 16, NULL, 0) );
    check( gcry_cipher_encrypt(h, &key[16], 16, NULL, 0) );
    dbg(key, 32);
  }
  gcry_cipher_close(h);
}

int main(int argc, char *argv[])
{
  int ok = 1;
  int i;

  uint8_t const data[DATA_LENGTH] =
  {
    0xd3,0x0f,0xd9,0xba,0xf3,0xf5,0x27,0xa0,
    0x3d,0x19,0xbc,0xca,0xf7,0xb7,0xa9,0x14,
    0xc2,0x3f,0x97,0xfe,0x60,0x7b,0xd5,0x98,
    0x8a,0xc2,0xe3,0x90,0xf7,0xf3,0xb8,0x7c,
    0xa1,0x05,0x16,0xf2,0x33,0xda,0x98,0x19,
    0x7e,0xc3,0x2d,0x59,0x71,0x14,0x1d,0x3a,
    0x40,0xad,0x08,0xb8,0x47,0x42,0x71,0xf4,
    0x40,0xf3,0x8c,0xe8,0x8c,0x7e,0xbc,0x13
  };

  uint8_t const expected[HASH_LENGTH] =
  {
    0x17,0xab,0xf6,0xa5,0x0f,0xb5,0x78,0xb4,
    0xa1,0xf4,0x86,0xe7,0xb5,0xbc,0xb0,0x51,
    0x6d,0x97,0x35,0xfb,0xf7,0xc8,0x5e,0xed,
    0x0c,0xfb,0x1e,0x83,0x0b,0xb2,0x50,0x54
  };

  uint8_t const data2[DATA2_LENGTH] = "qwertyuiopqwertyuiop";

  uint8_t const expected2[HASH_LENGTH] =
  {
    0xd6,0xae,0x0d,0xfd,0xbe,0x1c,0x4f,0xb6,
    0xae,0x18,0xdb,0x44,0xde,0x29,0x2b,0xde,
    0x57,0x7d,0x49,0x80,0xa4,0x9a,0x2e,0x00,
    0x60,0x4e,0x55,0x10,0x4e,0xf8,0xfd,0x7e
  };

  uint8_t const seed[SEED_LENGTH] =
  {
    0x6c,0x2e,0xc1,0x09,0x46,0xdd,0x0b,0xfe,
    0x1b,0xe3,0x57,0xb1,0x2a,0x18,0xa1,0xcd,
    0xba,0xd5,0x6e,0x53,0x35,0xd5,0x5a,0xba,
    0x15,0x53,0x62,0x3b,0xc4,0x4a,0xee,0x69
  };

  uint8_t const master_seed[SEED_LENGTH] =
  {
    0xd3,0x0f,0xd9,0xba,0xf3,0xf5,0x27,0xa0,
    0x3d,0x19,0xbc,0xca,0xf7,0xb7,0xa9,0x14,
    0xc2,0x3f,0x97,0xfe,0x60,0x7b,0xd5,0x98,
    0x8a,0xc2,0xe3,0x90,0xf7,0xf3,0xb8,0x7c
  };

  uint8_t const final_key[HASH_LENGTH] =
  {
    0x17,0xab,0xf6,0xa5,0x0f,0xb5,0x78,0xb4,
    0xa1,0xf4,0x86,0xe7,0xb5,0xbc,0xb0,0x51,
    0x6d,0x97,0x35,0xfb,0xf7,0xc8,0x5e,0xed,
    0x0c,0xfb,0x1e,0x83,0x0b,0xb2,0x50,0x54
  };

  

  uint8_t hash[HASH_LENGTH];
  gcry_md_hd_t sha256h;
  
  FILE *f;

  if (!gcry_check_version ("1.2.0"))
  {
    fputs("libgcrypt version mismatch\n", stderr);
    exit (2);
  }

  gcry_md_hash_buffer(GCRY_MD_SHA256, hash, data, DATA_LENGTH);

  for (i = 0; i < HASH_LENGTH; i++)
  {
    ok &= (hash[i] == expected[i]);
  }

  if (ok)
  {
    printf("ok\n");
  }


  gcry_md_hash_buffer(GCRY_MD_SHA256, hash, data2, DATA2_LENGTH);
  gcry_md_hash_buffer(GCRY_MD_SHA256, hash, hash, HASH_LENGTH);

  for (i = 0; i < HASH_LENGTH; i++)
  {
    ok &= (hash[i] == expected2[i]);
  }

  if (ok)
  {
    printf("ok\n");
  }

  transform_key(hash, seed, 10);

  dbg(hash, HASH_LENGTH);

  gcry_md_hash_buffer(GCRY_MD_SHA256, hash, hash, HASH_LENGTH);

  gcry_md_open(&sha256h, GCRY_MD_SHA256, 0);
  gcry_md_write(sha256h, master_seed, SEED_LENGTH);
  gcry_md_write(sha256h, hash, HASH_LENGTH);

  for (i = 0; i < HASH_LENGTH; i++)
  {
    ok &= (gcry_md_read(sha256h, GCRY_MD_SHA256)[i] == final_key[i]);
  }

  gcry_md_close(sha256h);

  if (ok)
  {
    printf("ok!\n");
  }

  // read and check file

  // magic

  f = fopen("kpdb1.kdbx", "r");
  if (f == NULL) return 1;

  if (fclose(f) != 0)
  {
    return 3;
  }

  printf("ok!!\n");

  return 0;
}
