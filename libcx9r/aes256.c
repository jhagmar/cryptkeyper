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
