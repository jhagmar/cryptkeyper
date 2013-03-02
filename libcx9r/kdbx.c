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

#include <cx9r.h>
#include <stream.h>
#include "sha256.h"
#include "aes256.h"
#include "base64.h"
#include "salsa20.h"
#include "key_tree.h"
#include "util.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_EXPAT
#include <expat.h>
#else
#error libexpat is required to build kdbx.c
#endif

// length of various kdbx file elements
#define KDBX_MAGIC_LENGTH 8	// length of magic bytes
#define KDBX_VERSION_LENGTH 4	// length of file version bytes
#define KDBX_CIPHER_ID_LENGTH 16	// cipher ID length
#define KDBX_COMPRESSION_LENGTH	4	// compression field length
#define KDBX_MASTER_SEED_LENGTH	32	// master
#define KDBX_N_TRANSFORM_ROUNDS_LENGTH 8	// # of transform rounds length
#define KDBX_IV_LENGTH 16 // cipher iv length
#define KDBX_STREAM_START_BYTES_LENGTH 32	// length of start bytes
// length of inner random stream id
#define KDBX_INNER_RANDOM_STREAM_ID_LENGTH 4

// IDs of header fields
#define ID_EOH 0			// end of header
#define ID_COMMENT 1			// comment
#define ID_CIPHER 2			// cipher ID
#define ID_COMPRESSION 3		// compression flags
#define ID_MASTER_SEED 4		// master seed
#define ID_TRANSFORM_SEED 5		// key transformation seed
#define ID_N_TRANSFORM_ROUNDS 6		// number of key transformation rounds
#define ID_IV 7				// encryption IV
#define ID_PROTECTED_STREAM_KEY 8	// protected stream key
#define ID_STREAM_START_BYTES 9		// stream start bytes
#define ID_INNER_RANDOM_STREAM_ID 10	// inner random stream ID

#define COMPRESSION_NONE 0	// no compression
#define COMPRESSION_GZIP 1	// gzip compression

// free a block of allocated memory and reset the pointer
#define DEALLOC(x) do {if (x != NULL) {free(x); x = NULL;}} while(0)

// context implementation
typedef struct {
	uint32_t compression;
	uint8_t *master_seed;
	uint8_t *transform_seed;
	uint64_t n_transform_rounds;
	uint8_t *iv;
	uint16_t protected_stream_key_length;
	uint8_t *protected_stream_key;
	uint8_t *stream_start_bytes;
	uint32_t inner_random_stream_id;
	uint8_t *key;
} ckpr_ctx_impl;

// cipher ID for aes-cbc with pkcs7 padding (standard cipher)
static const uint8_t aes_cbc_pkcs7_cipher_id[KDBX_CIPHER_ID_LENGTH] = { 0x31,
		0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a,
		0xfc, 0x5a, 0xff };

// convert an lsb byte array to uint64
static uint64_t lsb_to_uint64(uint8_t *b) {
	return (uint64_t) b[0] | (uint64_t) b[1] << 8 | (uint64_t) b[2] << 16
			| (uint64_t) b[3] << 24 | (uint64_t) b[4] << 32
			| (uint64_t) b[5] << 40 | (uint64_t) b[6] << 48
			| (uint64_t) b[7] << 56;
}

// read verify the kdbx magic bytes from a file
static cx9r_err kdbx_read_magic(cx9r_stream_t *stream) {
	uint8_t const kdbx_magic[KDBX_MAGIC_LENGTH] = { 0x03, 0xd9, 0xa2, 0x9a,
			0x67, 0xfb, 0x4b, 0xb5 };

	uint8_t magic[KDBX_MAGIC_LENGTH];

	// default return value
	cx9r_err err = CX9R_OK;

	// read magic bytes
	CHECK((cx9r_sread(magic, 1, KDBX_MAGIC_LENGTH, stream) == KDBX_MAGIC_LENGTH), err,
			CX9R_FILE_READ_ERR, kdbx_magic_bail);

	// compare magic bytes to expected
	CHECK((memcmp(magic, kdbx_magic, KDBX_MAGIC_LENGTH) == 0), err,
			CX9R_BAD_MAGIC, kdbx_magic_bail);

	kdbx_magic_bail:

	return err;
}

// read file format version from kdbx file
static cx9r_err kdbx_read_version(cx9r_stream_t *stream) {
	// version 2.20.1
	uint8_t const kdbx_version[KDBX_VERSION_LENGTH] = { 0x01, 0x00, 0x03, 0x00 };

	uint8_t version[KDBX_VERSION_LENGTH];

	// default return value
	cx9r_err err = CX9R_OK;

	// read version
	CHECK((cx9r_sread(version, 1, KDBX_VERSION_LENGTH, stream) == KDBX_VERSION_LENGTH),
			err, CX9R_FILE_READ_ERR, kdbx_read_version_bail);

	// compare version to expected
	CHECK((memcmp(version, kdbx_version, KDBX_VERSION_LENGTH) == 0), err,
			CX9R_UNSUPPORTED_VERSION, kdbx_read_version_bail);

	kdbx_read_version_bail:

	return err;
}

// check a cipher header field for known ciphers
static int handle_cipher_field(uint16_t size, uint8_t *data) {
	// TODO check for other ciphers?
	if ((size == KDBX_CIPHER_ID_LENGTH)
			&& (memcmp(data, aes_cbc_pkcs7_cipher_id, KDBX_CIPHER_ID_LENGTH)
					== 0)) {
		DEALLOC(data);
		return 1;
	} else {
		return 0;
	}
}

static int handle_compression_field(uint32_t *slot, uint16_t size, uint8_t *data) {

	uint32_t compression;

	if (size != KDBX_COMPRESSION_LENGTH) {
		return 0;
	}
	compression = cx9r_lsb_to_uint32(data);
	if ((compression != COMPRESSION_NONE)
			&& (compression != COMPRESSION_GZIP)) {
		return 0;
	}
	DEALLOC(data);
	*slot = compression;
	return 1;
}

static void handle_field_wo_size(uint8_t **slot, uint8_t *data) {
	DEALLOC(*slot);
	*slot = data;
}

static int handle_field_w_size(uint8_t **slot, uint16_t expected_size,
		uint16_t size, uint8_t *data) {
	if (size == expected_size) {
		handle_field_wo_size(slot, data);
		return 1;
	} else {
		return 0;
	}
}

static int handle_uint64_field(uint64_t *slot, uint16_t size, uint8_t *data) {
	if (size == sizeof(uint64_t)) {
		*slot = lsb_to_uint64(data);
		DEALLOC(data);
		return 1;
	} else {
		return 0;
	}
}

static int handle_uint32_field(uint32_t *slot, uint16_t size, uint8_t *data) {
	if (size == sizeof(uint32_t)) {
		*slot = cx9r_lsb_to_uint32(data);
		DEALLOC(data);
		return 1;
	} else {
		return 0;
	}
}

// read the kdbx file header
static cx9r_err kdbx_read_header(cx9r_stream_t *stream, ckpr_ctx_impl *ctx) {
	uint8_t id = 1;		// header field id
	uint16_t size;		// header field size
	uint8_t *data;		// header field data
	cx9r_err err = CX9R_OK;	// return value

	while (id) {
		// read id
		CHECK((cx9r_sread(&id, 1, sizeof(id), stream) == sizeof(id)), err,
				CX9R_FILE_READ_ERR, kdbx_read_header_bail);

		// read size
		CHECK((cx9r_sread(&size, 1, sizeof(size), stream) == sizeof(size)), err,
				CX9R_FILE_READ_ERR, kdbx_read_header_bail);

		CHECK(((data = (uint8_t*)malloc(size)) != NULL), err,
				CX9R_MEM_ALLOC_ERR, kdbx_read_header_bail);

		CHECK((cx9r_sread(data, 1, size, stream) == size), err, CX9R_FILE_READ_ERR,
				kdbx_read_header_cleanup_data);

		//printf("id: %d, size: %d\n", id, size);
		//dbg(data, size);

		// there is nothing in the format stopping us from having multiple instances
		// of one field. Therefore we need to make sure that the context slot is
		// clear to avoid memory leaks.
		switch (id) {
		case ID_EOH:
			// TODO verify size == 4 and data == "\r\n\r\n"?
			DEALLOC(data);
			break;
		case ID_COMMENT:
			// TODO save header comments?
			DEALLOC(data);
			break;
		case ID_CIPHER:
			CHECK((handle_cipher_field(size, data)), err, CX9R_UNKNOWN_CIPHER,
					kdbx_read_header_cleanup_data);
			break;
		case ID_COMPRESSION:
			CHECK((handle_compression_field(&ctx->compression, size, data)), err,
					CX9R_UNKNOWN_COMPRESSION, kdbx_read_header_cleanup_data);
			break;
		case ID_MASTER_SEED:
			CHECK(
					(handle_field_w_size(&ctx->master_seed, KDBX_MASTER_SEED_LENGTH, size, data)),
					err, CX9R_WRONG_MASTER_SEED_LENGTH,
					kdbx_read_header_cleanup_data);
			break;
		case ID_TRANSFORM_SEED:
			// KeePass writes 32 bytes, but does not check the length on reading
			handle_field_wo_size(&ctx->transform_seed, data);
			break;
		case ID_N_TRANSFORM_ROUNDS:
			CHECK((handle_uint64_field(&ctx->n_transform_rounds, size, data)),
					err, CX9R_WRONG_N_TRANSFORM_ROUNDS_LENGTH, kdbx_read_header_cleanup_data);
			break;
		case ID_IV:
			CHECK((handle_field_w_size(&ctx->iv, KDBX_IV_LENGTH, size, data)),
					err, CX9R_WRONG_IV_LENGTH, kdbx_read_header_cleanup_data);
			break;
		case ID_PROTECTED_STREAM_KEY:
			// KeePass writes 32 bytes, but does not check the length on reading
			ctx->protected_stream_key_length = size;
			handle_field_wo_size(&ctx->protected_stream_key, data);
			break;
		case ID_STREAM_START_BYTES:
			CHECK(
					(handle_field_w_size(&ctx->stream_start_bytes, KDBX_STREAM_START_BYTES_LENGTH, size, data)),
					err, CX9R_WRONG_STREAM_START_BYTES_LENGTH,
					kdbx_read_header_cleanup_data);
			break;
		case ID_INNER_RANDOM_STREAM_ID:
			CHECK((handle_uint32_field(&ctx->inner_random_stream_id, size, data)),
					err, CX9R_WRONG_INNER_RANDOM_STREAM_ID_LENGTH, kdbx_read_header_cleanup_data);
			break;
		default:
			CHECK((0), err, CX9R_BAD_HEADER_FIELD_ID,
					kdbx_read_header_cleanup_data);
			break;
		}

	}

	goto kdbx_read_header_bail;

	kdbx_read_header_cleanup_data:
	DEALLOC(data);

	kdbx_read_header_bail:

	return err;
}

// allocate a context
static ckpr_ctx_impl *
ctx_alloc(void) {
	ckpr_ctx_impl *ctx;

	ctx = (ckpr_ctx_impl*) malloc(sizeof(ckpr_ctx_impl));

	if (ctx == NULL )
		return ctx;

	ctx->master_seed = NULL;
	ctx->transform_seed = NULL;
	ctx->n_transform_rounds = 0;
	ctx->iv = NULL;
	ctx->protected_stream_key = NULL;
	ctx->stream_start_bytes = NULL;
	ctx->inner_random_stream_id = 0;
	ctx->key = NULL;

	return ctx;
}

// free a context
static void ctx_free(ckpr_ctx_impl *ctx) {
	DEALLOC(ctx->master_seed);
	DEALLOC(ctx->transform_seed);
	DEALLOC(ctx->iv);
	DEALLOC(ctx->protected_stream_key);
	DEALLOC(ctx->stream_start_bytes);
	DEALLOC(ctx->key);

	DEALLOC(ctx);
}

static cx9r_err generate_key(ckpr_ctx_impl *ctx, char *passphrase) {
	size_t length;
	uint8_t hash[CX9R_SHA256_HASH_LENGTH];
	cx9r_aes256_ecb_ctx aes_ctx;
	uint64_t i;
	cx9r_sha256_ctx sha_ctx;
	cx9r_err err = CX9R_OK;

	length = strlen(passphrase);

	CHEQ(((err = cx9r_sha256_hash_buffer(hash, passphrase, length)) == CX9R_OK),
			bail);

	CHEQ(((err = cx9r_sha256_hash_buffer(hash, hash, CX9R_SHA256_HASH_LENGTH))
			== CX9R_OK), bail);

	CHEQ(((err = cx9r_aes256_ecb_init(&aes_ctx, ctx->transform_seed)) == CX9R_OK),
			bail);

	for (i = 0; i < ctx->n_transform_rounds; i++) {
		CHEQ(((err = cx9r_aes256_ecb_encrypt_block(&aes_ctx, hash)) == CX9R_OK), cleanup_aes);
		CHEQ(((err = cx9r_aes256_ecb_encrypt_block(&aes_ctx,
				&hash[CX9R_AES256_BLOCK_LENGTH])) == CX9R_OK), cleanup_aes);
	}

	CHEQ(((err = cx9r_aes256_ecb_close(&aes_ctx)) == CX9R_OK), bail);

	CHEQ(((err = cx9r_sha256_hash_buffer(hash, hash, CX9R_SHA256_HASH_LENGTH)) == CX9R_OK),
			bail);

	CHEQ(((err = cx9r_sha256_init(&sha_ctx)) == CX9R_OK), bail);
	CHEQ(((err = cx9r_sha256_process(&sha_ctx, ctx->master_seed, KDBX_MASTER_SEED_LENGTH))
			== CX9R_OK), cleanup_sha);
	CHEQ(((err = cx9r_sha256_process(&sha_ctx, hash, CX9R_SHA256_HASH_LENGTH))
			== CX9R_OK), cleanup_sha);
	CHEQ(((err = cx9r_sha256_close(&sha_ctx, hash)) == CX9R_OK), bail);

	DEALLOC(ctx->key);
	CHECK(((ctx->key = malloc(CX9R_AES256_KEY_LENGTH)) != NULL),
			err, CX9R_MEM_ALLOC_ERR, bail);

	memcpy(ctx->key, hash, CX9R_AES256_KEY_LENGTH);

	goto bail;

cleanup_sha:

	cx9r_sha256_close(&sha_ctx, hash);
	goto bail;

cleanup_aes:

	cx9r_aes256_ecb_close(&aes_ctx);
	goto bail;

bail:

	return err;
}

static cx9r_err verify_start_bytes(cx9r_stream_t *stream, ckpr_ctx_impl *ctx) {
	uint8_t start_bytes[KDBX_STREAM_START_BYTES_LENGTH];
	cx9r_aes256_cbc_ctx aes_ctx;
	cx9r_err err = CX9R_OK;

	CHECK((cx9r_sread(start_bytes, 1, KDBX_STREAM_START_BYTES_LENGTH, stream) ==
			KDBX_STREAM_START_BYTES_LENGTH), err, CX9R_FILE_READ_ERR, bail);

	//CHEQ(((err = cx9r_aes256_cbc_init(&aes_ctx, ctx->key, ctx->iv)) == CX9R_OK),
	//		bail);
	//CHEQ(((err = cx9r_aes256_cbc_decrypt(&aes_ctx, start_bytes,
	//		KDBX_STREAM_START_BYTES_LENGTH)) == CX9R_OK), cleanup_aes);
	//CHEQ(((err = cx9r_aes256_cbc_close(&aes_ctx)) == CX9R_OK), bail);

	CHECK((memcmp(start_bytes, ctx->stream_start_bytes,
			KDBX_STREAM_START_BYTES_LENGTH) == 0), err,
			CX9R_KEY_VERIFICATION_FAILED, bail);

	goto bail;

cleanup_aes:

	cx9r_aes256_cbc_close(&aes_ctx);
	goto bail;

bail:

	return err;

}

enum parse_tag_enum {
	START,
	TOP,
	ROOT,
	GROUP,
	ENTRY,
	NAME,
	STRING,
	KEY,
	VALUE,
	OTHER,
	END
};

typedef enum parse_tag_enum parse_tag;

enum parse_state_enum {
	UNKNOWN,
	GROUP_NAME,
	ENTRY_KEY,
	ENTRY_NAME,
	ENTRY_VALUE
};

typedef enum parse_state_enum parse_state;

typedef struct parse_data_struct parse_data;

struct parse_data_struct {
	parse_tag state;
	parse_data *prev;
	parse_data *next;
};

typedef struct user_data_struct user_data;

struct user_data_struct {
	parse_data *stack_top;
	XML_Parser parser;
	parse_state state;
	cx9r_key_tree *key_tree;
	cx9r_kt_group *current_group;
	cx9r_kt_entry *current_entry;
	cx9r_kt_field *current_field;
	char *char_data_buf;
	int char_data_len;
	cx9r_salsa20_ctx salsa20_ctx;
	int obfuscated;
};

// not a pure pop - pops all elements above data
static parse_data *parse_data_pop(parse_data *data) {
	parse_data *prev;
	if (data->next != NULL) {
		parse_data_pop(data->next);
	}
	prev = data->prev;
	free(data);
	return prev;
}

// not a pure push - creates a new parse_data and pushes it onto data
static parse_data *parse_data_push(parse_data *top) {
	parse_data *pd;

	pd = malloc(sizeof(parse_data));
	if (pd == NULL) return NULL;

	pd->prev = top;
	pd->next = NULL;
	return pd;
}

#define N_TAGS 8
static char const *tags[N_TAGS] = {"KeePassFile", "Root", "Group", "Entry",
		"Name", "String", "Key", "Value"};
static parse_tag const states[N_TAGS] = {TOP, ROOT, GROUP, ENTRY, NAME,
		STRING, KEY, VALUE};
static parse_tag const root_condition[] = {GROUP, ROOT, TOP, END};
static parse_tag const root_name_condition[] = {NAME, GROUP, ROOT, TOP, END};
static parse_tag const group_condition[] = {GROUP, END};
static parse_tag const subgroup_condition[] = {GROUP, GROUP, END};
static parse_tag const subgroup_name_condition[] = {NAME, GROUP, GROUP, END};
static parse_tag const entry_condition[] = {ENTRY, GROUP, END};
static parse_tag const entry_key_condition[] = {KEY, STRING, ENTRY, GROUP, END};
static parse_tag const entry_value_condition[] = {VALUE, STRING, ENTRY, GROUP, END};

static char const *entry_name_tag = "Title";
static char const *protected_tag = "Protected";
static char const *true_tag = "True";

void new_state(user_data *ud, XML_Char const *name) {
	int i;

	if (ud->stack_top == NULL) return;
	ud->stack_top = parse_data_push(ud->stack_top);
	if (ud->stack_top == NULL) return;
	for (i = 0; i < N_TAGS; i++) {
		if (strcmp(name, tags[i]) == 0) {
			ud->stack_top->state = states[i];
			return;
		}
	}
	ud->stack_top->state = OTHER;
}

int check_state_condition(parse_tag const *condition, parse_data const *stack_top) {
	while (*condition != END) {
		if (stack_top == NULL) return 0;
		if (*condition != stack_top->state) return 0;
		stack_top = stack_top->prev;
		condition++;
	}
	return 1;
}

static void start_element_handler(void *userData,
		const XML_Char *name,
		const XML_Char **atts) {

	int i;
	user_data *ud;
	ud = (user_data*)userData;
	new_state(ud, name);
	if (ud->stack_top == NULL )	goto bail;

	if (check_state_condition(root_condition, ud->stack_top)) {
		ud->current_group = cx9r_key_tree_get_root(ud->key_tree);
	}
	else if (check_state_condition(root_name_condition, ud->stack_top)) {
		ud->state = GROUP_NAME;
	}
	else if (check_state_condition(subgroup_condition, ud->stack_top)) {
		ud->current_group = cx9r_kt_group_add_child(ud->current_group);
	}
	else if (check_state_condition(subgroup_name_condition, ud->stack_top)) {
		ud->state = GROUP_NAME;
	}
	else if (check_state_condition(entry_condition, ud->stack_top)) {
		ud->current_entry = cx9r_kt_group_add_entry(ud->current_group);
	}
	else if (check_state_condition(entry_key_condition, ud->stack_top)) {
		ud->state = ENTRY_KEY;
	}
	else if (check_state_condition(entry_value_condition, ud->stack_top)) {
		if (ud->state != ENTRY_NAME) {
			ud->state = ENTRY_VALUE;
		}
	}

	ud->char_data_len = 0;

	ud->obfuscated = 0;
	for (i = 0; atts[i] != NULL; i += 2) {
		if ((strcmp(atts[i], protected_tag) == 0)
				&& (strcmp(atts[i + 1], true_tag) == 0)) {
			ud->obfuscated = 1;
		}
	}

	return;

bail:

	ud->stack_top = NULL;
	XML_StopParser(ud->parser, XML_FALSE);
}

static void buffered_character_data_handler(void *userData,
		XML_Char *s,
		int len) {

	user_data *ud;
	ud = (user_data*)userData;
	if (ud->stack_top == NULL )	return;

	if (ud->obfuscated){
		len = base64_decode(s, s, len);
		cx9r_salsa20_decrypt(&ud->salsa20_ctx, s, s, len);
	}

	if (ud->state == GROUP_NAME) {
		cx9r_kt_group_set_name(ud->current_group, s, len);
	}
	else if (ud->state == ENTRY_KEY) {
		if (strncmp(s, entry_name_tag, len) == 0) {
			ud->state = ENTRY_NAME;
		}
		else {
			ud->current_field = cx9r_kt_entry_add_field(ud->current_entry);
			cx9r_kt_field_set_name(ud->current_field, s, len);
		}
	}
	else if (ud->state == ENTRY_NAME) {
		cx9r_kt_entry_set_name(ud->current_entry, s, len);
	}
	else if (ud->state == ENTRY_VALUE) {
		cx9r_kt_field_set_value(ud->current_field, s, len);
	}

}

static void end_element_handler(void *userData,
		const XML_Char *name) {

	user_data *ud;
	ud = (user_data*)userData;
	if (ud->stack_top == NULL )	return;

	if (ud->char_data_buf != NULL) {
		buffered_character_data_handler(ud, ud->char_data_buf, ud->char_data_len);
		free(ud->char_data_buf);
		ud->char_data_buf = NULL;
		ud->char_data_len = -1;
	}

	if (check_state_condition(group_condition, ud->stack_top)) {
		ud->current_group = cx9r_kt_group_get_parent(ud->current_group);
	}

	if ((check_state_condition(entry_key_condition, ud->stack_top))
			&& (ud->state == ENTRY_NAME)) {

	}
	else {
		ud->state = UNKNOWN;
	}

	ud->stack_top = parse_data_pop(ud->stack_top);


}

static void character_data_handler(void *userData,
		const XML_Char *s,
		int len) {

	user_data *ud;
	char *t;
	size_t t_len;

	ud = (user_data*)userData;
	if (ud->stack_top == NULL )	return;
	if (ud->char_data_len < 0) return;

	if (ud->char_data_buf == NULL) {
		ud->char_data_buf = malloc(len);
		if (ud->char_data_buf == NULL) {
			ud->stack_top = NULL;
			return;
		}
		memcpy(ud->char_data_buf, s, len);
		ud->char_data_len = len;
	}
	else {
		t_len = ud->char_data_len + len;
		t = malloc(t_len);
		if (t == NULL) {
			free(ud->char_data_buf);
			ud->char_data_buf = NULL;
			ud->char_data_len = 0;
			ud->stack_top = NULL;
			return;
		}
		memcpy(t, ud->char_data_buf, ud->char_data_len);
		memcpy(t + ud->char_data_len, s, len);
		free(ud->char_data_buf);
		ud->char_data_buf = t;
		ud->char_data_len = t_len;
	}

}

static cx9r_err parse_xml(cx9r_stream_t *stream, ckpr_ctx_impl *ctx) {
	cx9r_err err = CX9R_OK;
	XML_Parser parser;
	size_t n;
	uint8_t buf[1027];
	parse_data *parse_stack;
	cx9r_key_tree *kt;
	user_data ud;
	uint8_t const salsa20_iv[] = {0xE8, 0x30, 0x09, 0x4B,
			0x97, 0x20, 0x5D, 0x2A};
	uint8_t salsa20_key[CX9R_SHA256_HASH_LENGTH];

	CHECK(((parser = XML_ParserCreate(NULL)) != NULL), err,
			CX9R_MEM_ALLOC_ERR, bail);

	CHECK(((parse_stack = parse_data_push(NULL)) != NULL), err,
			CX9R_MEM_ALLOC_ERR, dealloc_parser);

	CHECK(((kt = cx9r_key_tree_create()) != NULL), err,
			CX9R_MEM_ALLOC_ERR, dealloc_key_tree);

	cx9r_sha256_hash_buffer(salsa20_key, ctx->protected_stream_key,
			ctx->protected_stream_key_length);

	ud.stack_top = parse_stack;
	ud.parser = parser;
	ud.state = UNKNOWN;
	ud.key_tree = kt;
	ud.current_group = NULL;
	ud.current_entry = NULL;
	ud.current_field = NULL;
	ud.char_data_buf = NULL;
	ud.char_data_len = 0;
	cx9r_salsa20_256_init(&ud.salsa20_ctx, salsa20_key, salsa20_iv);
	parse_stack->state = START;

	XML_SetUserData(parser, &ud);

	XML_SetElementHandler(parser, start_element_handler, end_element_handler);

	XML_SetCharacterDataHandler(parser, character_data_handler);

	while (!cx9r_seof(stream)) {
		n = cx9r_sread(buf, 1, 1028, stream);
		CHECK((XML_Parse(parser, buf, n, 0) == XML_STATUS_OK), err,
				CX9R_PARSE_ERR, dealloc_key_tree);
	}
	XML_Parse(parser, buf, 0, 1);
	cx9r_dump_tree(kt);

dealloc_key_tree:

	cx9r_key_tree_free(kt);

dealloc_stack:

	parse_data_pop(parse_stack);

dealloc_parser:

	XML_ParserFree(parser);

bail:

	return err;
}

cx9r_err cx9r_init() {
	if (!gcry_check_version("1.2.0")) {
		//fputs("libgcrypt version mismatch\n", stderr);
		return CX9R_INIT_FAILURE;
	}
	return CX9R_OK;
}

cx9r_err cx9r_kdbx_read(FILE *f, char *passphrase) {
	cx9r_err err = CX9R_OK;
	ckpr_ctx_impl *ctx;
	cx9r_stream_t *stream;
	cx9r_stream_t *decrypted_stream;
	cx9r_stream_t *hashed_stream;
	cx9r_stream_t *gzip_stream;
	uint8_t buf[1027];
	size_t n;
	FILE *o;

	CHECK(((stream = cx9r_file_sopen(f)) != NULL),
			err, CX9R_STREAM_OPEN_ERR, cleanup_file);

	CHEQ(((err = kdbx_read_magic(stream)) == CX9R_OK), cleanup_stream);

	CHEQ(((err = kdbx_read_version(stream)) == CX9R_OK), cleanup_stream);

	CHECK(((ctx = ctx_alloc()) != NULL), err, CX9R_MEM_ALLOC_ERR,
			cleanup_stream);

	CHEQ(((err = kdbx_read_header(stream, ctx)) == CX9R_OK), cleanup_ctx);

	CHEQ(((err = generate_key(ctx, passphrase)) == CX9R_OK), cleanup_ctx);

	CHECK(((decrypted_stream = cx9r_aes256_cbc_sopen(stream, ctx->key, ctx->iv)) != NULL),
			err, CX9R_STREAM_OPEN_ERR, cleanup_ctx);

	stream = decrypted_stream;

	CHEQ(((err = verify_start_bytes(stream, ctx)) == CX9R_OK), cleanup_ctx);

	CHECK(((hashed_stream = cx9r_hash_sopen(stream)) != NULL),
				err, CX9R_STREAM_OPEN_ERR, cleanup_ctx);

	stream = hashed_stream;

	if (ctx->compression == COMPRESSION_GZIP) {
		CHECK(((gzip_stream = cx9r_gzip_sopen(stream)) != NULL),
					err, CX9R_STREAM_OPEN_ERR, cleanup_ctx);
		stream = gzip_stream;
	}

//	o = fopen("raw.xml", "w");
//
//	while (!cx9r_seof(stream)) {
//		n = cx9r_sread(buf, 1, 1027, stream);
//		fwrite(buf, 1, n, o);
//	}
//
//	fclose(o);
	parse_xml(stream, ctx);

cleanup_ctx:
	ctx_free(ctx);

cleanup_stream:
	cx9r_sclose(stream);

bail:
	return err;

cleanup_file:
	fclose(f);
	return err;
}

