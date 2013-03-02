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

#include "base64.h"
#include <string.h>
#include <stdio.h>

static int check_test_vector(char *out, char const *in, char const *correct_out) {

	size_t n;

	printf("Test vector: %s\n", in);
	printf("Expected response: \"%s\"\n", correct_out);
	n = base64_decode_string(out, in);
	if (n < 0) {
		printf("Decoding error\n");
		return 1;
	}
	out[n] = 0;
	if (strcmp(out, correct_out) != 0) {
		printf("Incorrect response: \"%s\"\n", out);
		return 1;
	}
	printf("Success.\n");
	return 0;

}

#define N_TEST_VECTORS 15

static char const *challenges[N_TEST_VECTORS] = {
		"TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz",
		"IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg",
		"dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu",
		"dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo",
		"ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=",
		"YW55IGNhcm5hbCBwbGVhc3VyZS4=",
		"YW55IGNhcm5hbCBwbGVhc3VyZQ==",
		"YW55IGNhcm5hbCBwbGVhc3Vy",
		"YW55IGNhcm5hbCBwbGVhc3U=",
		"YW55IGNhcm5hbCBwbGVhcw==",
		"cGxlYXN1cmUu",
		"bGVhc3VyZS4=",
		"ZWFzdXJlLg==",
		"YXN1cmUu",
		"c3VyZS4="
};

static char const *responses[N_TEST_VECTORS] = {
		"Man is distinguished, not only by his reason, but by this",
		" singular passion from other animals, which is a lust of ",
		"the mind, that by a perseverance of delight in the contin",
		"ued and indefatigable generation of knowledge, exceeds th",
		"e short vehemence of any carnal pleasure.",
		"any carnal pleasure.",
		"any carnal pleasure",
		"any carnal pleasur",
		"any carnal pleasu",
		"any carnal pleas",
		"pleasure.",
		"leasure.",
		"easure.",
		"asure.",
		"sure."
};


int main() {

	int i;
	char buf[256];

	for (i = 0; i < N_TEST_VECTORS; i++) {

		if (check_test_vector(buf, challenges[i], responses[i]) != 0)
			return 1;
	}

	return 0;
}


