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
#include "util.h"

cx9r_err cx9r_aes256_ecb_init(cx9r_aes256_ecb_ctx *ctx, uint8_t *key) {
	if (gcry_cipher_open(ctx, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0)
			!= GPG_ERR_NO_ERROR)
		goto bail;

	if (gcry_cipher_setkey(*ctx, key, CX9R_AES256_KEY_LENGTH)
			!= GPG_ERR_NO_ERROR)
		goto cleanup;

	return CX9R_OK;

	cleanup: gcry_cipher_close(*ctx);

	bail: return CX9R_AES256_FAILURE;
}

cx9r_err cx9r_aes256_ecb_encrypt_block(cx9r_aes256_ecb_ctx *ctx, uint8_t *block) {
	if (gcry_cipher_encrypt(*ctx, block, CX9R_AES256_BLOCK_LENGTH, NULL, 0)
			== GPG_ERR_NO_ERROR) {
		return CX9R_OK;
	} else {
		return CX9R_AES256_FAILURE;
	}
}

cx9r_err cx9r_aes256_ecb_close(cx9r_aes256_ecb_ctx *ctx) {
	gcry_cipher_close(*ctx);
	return CX9R_OK;
}

cx9r_err cx9r_aes256_cbc_init(cx9r_aes256_cbc_ctx *ctx, uint8_t *key,
		uint8_t *iv) {
	if (gcry_cipher_open(ctx, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0)
			!= GPG_ERR_NO_ERROR)
		goto bail;

	if (gcry_cipher_setkey(*ctx, key, CX9R_AES256_KEY_LENGTH)
			!= GPG_ERR_NO_ERROR)
		goto cleanup;

	if (gcry_cipher_setiv(*ctx, iv, CX9R_AES256_BLOCK_LENGTH)
			!= GPG_ERR_NO_ERROR)
		goto cleanup;

	return CX9R_OK;

	cleanup: gcry_cipher_close(*ctx);

	bail: return CX9R_AES256_FAILURE;
}

cx9r_err cx9r_aes256_cbc_decrypt(cx9r_aes256_ecb_ctx *ctx, uint8_t *buffer,
		size_t length) {
	if (gcry_cipher_decrypt(*ctx, buffer, length, NULL, 0)
			== GPG_ERR_NO_ERROR) {
		return CX9R_OK;
	} else {
		return CX9R_AES256_FAILURE;
	}
}

cx9r_err cx9r_aes256_cbc_close(cx9r_aes256_cbc_ctx *ctx) {
	gcry_cipher_close(*ctx);
	return CX9R_OK;
}
