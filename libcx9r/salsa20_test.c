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

#include "salsa20.h"
#include <string.h>
#include <stdio.h>

static uint8_t const key[16] = {
		0x80, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
};

static uint8_t const iv[8] = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
};

static void dbg(uint8_t *data, uint32_t length) {
	uint32_t i;

	for (i = 0; i < length; i++) {
		printf("%02X", data[i]);
	}
	printf("\n");
}

int main() {

	uint8_t out[64];

	cx9r_salsa20_ctx ctx;

	cx9r_salsa20_init(&ctx, key, 128, iv);

	cx9r_salsa20_keystream(&ctx, out, 64);

	dbg(out, 64);

	return 0;
}


