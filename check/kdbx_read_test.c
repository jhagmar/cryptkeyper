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
#include <stdio.h>

int main(void)
{
  FILE *f;
  cx9r_err err;

  f = fopen(TESTFILE, "r");
  if (f == NULL) return 1;

  if ((err = cx9r_init()) != CX9R_OK)
    goto cleanup_file;

  if ((err = cx9r_kdbx_read(f, "qwertyuiopqwertyuiop")) != CX9R_OK)
    goto bail;

bail:

  return err;

cleanup_file:

    fclose(f);
    return err;
}

