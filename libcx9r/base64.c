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

//static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
//                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
//                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
//                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
//                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
//                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
//                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
//                                '4', '5', '6', '7', '8', '9', '+', '/'};

// decoding table
static char const dec[79] = {
	0x3E, 0xFF, 0xFF, 0xFF, 0x3F, 0x34, 0x35, 0x36,
	0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
	0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1A, 0x1B,
	0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
	0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
	0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32};

//static int mod_table[] = {0, 2, 1};

#define FORMAT_ERROR -1
#define FIRST_VALID_ASCII ('+')
#define LAST_VALID_ASCII ('z')
#define TERMINATOR ('=')
#define BASE64_BLOCK_LENGTH 4
#define BINARY_BLOCK_LENGTH 3
#define INVALID_ASCII 0xFF

#define IN_DECODING_RANGE(x) ((x >= FIRST_VALID_ASCII) && (x <= LAST_VALID_ASCII))

size_t *base64_decode(uint8_t *out, char *in) {

	size_t ret = 0;
	size_t binary_length;
	uint8_t buf[BASE64_BLOCK_LENGTH];

	// continue until end of string
	while (*in) {

		// validate base64 block of valid characters
		if (!(IN_DECODING_RANGE(in[0])
				&& IN_DECODING_RANGE(in[1])
				&& IN_DECODING_RANGE(in[2])
				&& IN_DECODING_RANGE(in[3]))) {
			return FORMAT_ERROR;
		}

		binary_length = BINARY_BLOCK_LENGTH;

		// decode ASCII to 6-bit equivalents
		if (in[3] == TERMINATOR) {
			if (in[4] != 0) {
				return FORMAT_ERROR;
			}
			buf[3] = 0;
			binary_length--;
			if (in[2] == TERMINATOR) {
				buf[2] = 0;
				binary_length--;
			}
			else {
				if ((buf[2] = dec[in[2]]) == INVALID_ASCII) {
					return FORMAT_ERROR;
				}
			}
		}
		else {
			if ((buf[3] = dec[in[3]]) == INVALID_ASCII) {
				return FORMAT_ERROR;
			}
		}
		if ((buf[1] = dec[in[1]]) == INVALID_ASCII) {
			return FORMAT_ERROR;
		}
		if ((buf[0] = dec[in[0]]) == INVALID_ASCII) {
			return FORMAT_ERROR;
		}

		out[0] = ((buf[0] << 2) | (buf[1] >> 4));
		if (binary_length > 1) {
			out[1] = ((buf[0] << 2) | (buf[1] >> 4));
		}

	}

}
