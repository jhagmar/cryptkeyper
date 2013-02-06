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

#include <stream.h>
#include <stdio.h>
#include <stdint.h>

// number of values in the test file
#define N_VALUES (1<<18)

int main(void) {
	FILE *f;
	cx9r_stream_t *stream;
	uint32_t i;
	uint32_t j;

	printf("buffered file stream test\n");

	printf("generating test file...\n");
	f = fopen(TESTFILE, "w");
	if (f == NULL ) {
		printf("cannot open test file\n");
		goto bail;
	}

	for (i = 0; i < N_VALUES; i++) {
		if (fwrite(&i, sizeof(i), 1, f) != 1) {
			printf("cannot write to test file\n");
			goto close_file;
		}
	}

	if (fclose(f) == EOF) {
		printf("cannot close test file\n");
		goto bail;
	}

	printf("reading back testfile through buffered stream\n");

	f = fopen(TESTFILE, "r");
	if (f == NULL)
	{
		printf("cannot open test file\n");
		goto bail;
	}

	stream = cx9r_buf_file_sopen(f);
	if (stream == NULL) {
		printf("cannot create buffered file stream\n");
		goto close_file;
	}

	for (i = 0; i < N_VALUES; i++) {
		if (cx9r_sread(&j, sizeof(j), 1, stream) != 1)
		{
			printf("error reading from buffered file stream\n");
			goto close_stream;
		}
		if (i != j) {
			printf("value mismatch when reading testfile");
			goto close_stream;
		}
	}

	// close stream, closing the underlying file
	if (cx9r_sclose(stream) == EOF) {
		printf("error closing buffered file stream\n");
		goto bail;
	}

	remove(TESTFILE);

	printf("test passed\n");

	return 0;

	close_stream:

	cx9r_sclose(stream);
	return 1;

	close_file:

	fclose(f);

	bail:

	return 1;
}

