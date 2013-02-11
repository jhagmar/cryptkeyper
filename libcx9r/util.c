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

#include "util.h"

// convert an lsb byte array to uint32
uint32_t cx9r_lsb_to_uint32(uint8_t *b) {
	return ((uint32_t) b[0])
		| (((uint32_t) b[1]) << 8)
		| (((uint32_t) b[2]) << 16)
		| (((uint32_t) b[3]) << 24);
}

// convert an lsb byte array to int32
int32_t cx9r_lsb_to_int32(uint8_t *b) {
	return ((int32_t) b[0])
		| (((int32_t) b[1]) << 8)
		| (((int32_t) b[2]) << 16)
		| (((int32_t) b[3]) << 24);
}
