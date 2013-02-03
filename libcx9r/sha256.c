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
