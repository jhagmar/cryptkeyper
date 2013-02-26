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

#include "key_tree.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define TEST_LENGTH 5

static char const test1[] = "test1";
static char const test2[] = "test2";

int main() {

	cx9r_key_tree *kt;
	cx9r_kt_group *g;
	cx9r_kt_group *c;
	cx9r_kt_entry *e;
	cx9r_kt_field *f;
	char const *s;

	printf("creating key tree...");
	kt = cx9r_key_tree_create();
	if (kt == NULL) goto bail;
	printf("ok\n");

	printf("obtaining key tree root...");
	g = cx9r_key_tree_get_root(kt);
	if (g == NULL) goto dealloc_tree;
	printf("ok\n");
	if (cx9r_kt_group_get_parent(g) != NULL) goto dealloc_tree;

	printf("creating groups...");
	c = cx9r_kt_group_get_children(g);
	if (c != NULL) goto dealloc_tree;

	// add one group
	c = cx9r_kt_group_add_child(g);
	if (c == NULL) goto dealloc_tree;
	s = cx9r_kt_group_get_name(c);
	if (s != NULL) goto dealloc_tree;
	s = cx9r_kt_group_set_zname(c, test1);
	if (s == NULL) goto dealloc_tree;
	// add another
	c = cx9r_kt_group_add_child(g);
	if (c == NULL) goto dealloc_tree;
	s = cx9r_kt_group_get_name(c);
	if (s != NULL) goto dealloc_tree;
	s = cx9r_kt_group_set_name(c, test2, TEST_LENGTH);
	if (s == NULL) goto dealloc_tree;

	//retrieve the child groups and check their names
	c = cx9r_kt_group_get_children(g);
	if (c == NULL) goto dealloc_tree;
	if (cx9r_kt_group_get_parent(c) != g) goto dealloc_tree;
	s = cx9r_kt_group_get_name(c);
	if (s == NULL) goto dealloc_tree;
	if (strcmp(s, test1) != 0) goto dealloc_tree;

	c = cx9r_kt_group_get_next(c);
	if (c == NULL) goto dealloc_tree;
	if (cx9r_kt_group_get_parent(c) != g) goto dealloc_tree;
	s = cx9r_kt_group_get_name(c);
	if (s == NULL) goto dealloc_tree;
	if (strcmp(s, test2) != 0) goto dealloc_tree;

	c = cx9r_kt_group_get_next(c);
	if (c != NULL) goto dealloc_tree;

	printf("ok\n");

	printf("creating entries...");
	e = cx9r_kt_group_get_entries(g);
	if (e != NULL) goto dealloc_tree;
	// create one entry
	e = cx9r_kt_group_add_entry(g);
	if (e == NULL) goto dealloc_tree;
	s = cx9r_kt_entry_get_name(e);
	if (s != NULL) goto dealloc_tree;
	s = cx9r_kt_entry_set_zname(e, test1);
	if (s == NULL) goto dealloc_tree;
	// create another (sibling) entry
	e = cx9r_kt_group_add_entry(g);
	if (e == NULL) goto dealloc_tree;
	s = cx9r_kt_entry_get_name(e);
	if (s != NULL) goto dealloc_tree;
	s = cx9r_kt_entry_set_name(e, test2, TEST_LENGTH);
	if (s == NULL) goto dealloc_tree;
	// retrieve the entries and check their names
	e = cx9r_kt_group_get_entries(g);
	if (e == NULL) goto dealloc_tree;
	s = cx9r_kt_entry_get_name(e);
	if (s == NULL) goto dealloc_tree;
	if (strcmp(s, test1) != 0) goto dealloc_tree;

	e = cx9r_kt_entry_get_next(e);
	if (e == NULL) goto dealloc_tree;
	s = cx9r_kt_entry_get_name(e);
	if (s == NULL) goto dealloc_tree;
	if (strcmp(s, test2) != 0) goto dealloc_tree;

	e = cx9r_kt_entry_get_next(e);
	if (e != NULL) goto dealloc_tree;
	printf("ok\n");

	printf("creating fields...");
	e = cx9r_kt_group_get_entries(g);
	f = cx9r_kt_entry_get_fields(e);
	if (f != NULL) goto dealloc_tree;

	// add one field
	f = cx9r_kt_entry_add_field(e);
	if (f == NULL) goto dealloc_tree;
	s = cx9r_kt_field_get_name(f);
	if (s != NULL) goto dealloc_tree;
	s = cx9r_kt_field_set_zname(f, test1);
	if (s == NULL) goto dealloc_tree;
	s = cx9r_kt_field_get_value(f);
	if (s != NULL) goto dealloc_tree;
	s = cx9r_kt_field_set_zvalue(f, test2);
	if (s == NULL) goto dealloc_tree;
	// add another field
	f = cx9r_kt_entry_add_field(e);
	if (f == NULL) goto dealloc_tree;
	s = cx9r_kt_field_get_name(f);
	if (s != NULL) goto dealloc_tree;
	s = cx9r_kt_field_set_name(f, test2, TEST_LENGTH);
	if (s == NULL) goto dealloc_tree;
	s = cx9r_kt_field_get_value(f);
	if (s != NULL) goto dealloc_tree;
	s = cx9r_kt_field_set_value(f, test1, TEST_LENGTH);
	if (s == NULL) goto dealloc_tree;

	// check fields
	f = cx9r_kt_entry_get_fields(e);
	if (f == NULL) goto dealloc_tree;
	s = cx9r_kt_field_get_name(f);
	if (s == NULL) goto dealloc_tree;
	if (strcmp(s, test1) != 0) goto dealloc_tree;
	s = cx9r_kt_field_get_value(f);
	if (s == NULL) goto dealloc_tree;
	if (strcmp(s, test2) != 0) goto dealloc_tree;

	f = cx9r_kt_field_get_next(f);
	if (f == NULL) goto dealloc_tree;
	s = cx9r_kt_field_get_name(f);
	if (s == NULL) goto dealloc_tree;
	if (strcmp(s, test2) != 0) goto dealloc_tree;
	s = cx9r_kt_field_get_value(f);
	if (s == NULL) goto dealloc_tree;
	if (strcmp(s, test1) != 0) goto dealloc_tree;

	f = cx9r_kt_field_get_next(f);
	if (f != NULL) goto dealloc_tree;
	printf("ok\n");

	cx9r_key_tree_free(kt);

	return 0;

dealloc_tree:

	cx9r_key_tree_free(kt);

bail:

	printf("fail\n");
	return 1;

}
