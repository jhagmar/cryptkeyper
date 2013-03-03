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

#include <stdint.h>
#include <stdlib.h>

//static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
//                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
//                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
//                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
//                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
//                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
//                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
//                                '4', '5', '6', '7', '8', '9', '+', '/'};

// decoding table
static uint8_t const dec[80] = { 0x3E, 0xFF, 0xFF, 0xFF, 0x3F, 0x34, 0x35, 0x36,
		0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
		0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1A, 0x1B,
		0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33 };

//static int mod_table[] = {0, 2, 1};

#define FORMAT_ERROR -1
#define FIRST_VALID_ASCII ('+')
#define LAST_VALID_ASCII ('z')
#define TERMINATOR ('=')
#define BASE64_BLOCK_LENGTH 4
#define BINARY_BLOCK_LENGTH 3
#define INVALID_ASCII 0xFF

#define PREPARE_INPUT(x, y) ((x = y - FIRST_VALID_ASCII) <= LAST_VALID_ASCII)
#define DECODE(x) ((x = dec[x]) != INVALID_ASCII)

size_t base64_decode(void *out, char const *in, size_t length) {
	uint8_t *o = (uint8_t*)out;
	uint8_t *o_orig = o;
	uint8_t buf[BASE64_BLOCK_LENGTH];
	size_t const mask = ~((size_t)3);

	length &= mask;

	// continue until end of string
	while (length) {
		length -= BASE64_BLOCK_LENGTH;

		// first validation of input
		if (!(PREPARE_INPUT(buf[0], in[0]) && PREPARE_INPUT(buf[1], in[1])
				&& PREPARE_INPUT(buf[2], in[2]) && PREPARE_INPUT(buf[3], in[3]))) {
			return FORMAT_ERROR;
		}

		// validate and decode
		if (in[3] != TERMINATOR) {
			// we have "xxxx"
			if (!(DECODE(buf[0]) && DECODE(buf[1]) && DECODE(buf[2])
					&& DECODE(buf[3]))) {
				return FORMAT_ERROR;
			}
			o[0] = ((buf[0] << 2) | (buf[1] >> 4));
			o[1] = ((buf[1] << 4) | (buf[2] >> 2));
			o[2] = ((buf[2] << 6) | (buf[3]));
			in += BASE64_BLOCK_LENGTH;
			o += BINARY_BLOCK_LENGTH;
		} else {
			// check that this is the last char
			if (length) {
				return FORMAT_ERROR;
			}
			if (in[2] == TERMINATOR) {
				// we have "xx=="
				if (!(DECODE(buf[0]) && DECODE(buf[1]))) {
					return FORMAT_ERROR;
				}
				o[0] = ((buf[0] << 2) | (buf[1] >> 4));
				o += BINARY_BLOCK_LENGTH - 2;
				break;
			} else {
				// we have "xxx="
				if (!(DECODE(buf[0]) && DECODE(buf[1]) && DECODE(buf[2]))) {
					return FORMAT_ERROR;
				}
				o[0] = ((buf[0] << 2) | (buf[1] >> 4));
				o[1] = ((buf[1] << 4) | (buf[2] >> 2));
				o += BINARY_BLOCK_LENGTH - 1;
				break;
			}
		}
	}

	return o - o_orig;
}
