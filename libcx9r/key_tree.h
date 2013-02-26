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

#ifndef CX9R_KEY_TREE_H
#define CX9R_KEY_TREE_H

#include <stdlib.h>

typedef struct cx9r_ktf cx9r_kt_field;

struct cx9r_ktf {
	char *name;
	char *value;
	cx9r_kt_field *next;
};

typedef struct cx9r_kte cx9r_kt_entry;

struct cx9r_kte {
	char *name;
	cx9r_kt_field *fields;
	cx9r_kt_entry *next;
};

typedef struct cx9r_ktg cx9r_kt_group;

struct cx9r_ktg {
	char *name;
	cx9r_kt_group *parent;
	cx9r_kt_group *children;
	cx9r_kt_group *next;
	cx9r_kt_entry *entries;
};

typedef struct {
	cx9r_kt_group root;
} cx9r_key_tree;

cx9r_key_tree *cx9r_key_tree_create();
cx9r_kt_group *cx9r_key_tree_get_root(cx9r_key_tree *kt);
void cx9r_key_tree_free(cx9r_key_tree *kt);

cx9r_kt_group *cx9r_kt_group_get_parent(cx9r_kt_group const *ktg);
cx9r_kt_group *cx9r_kt_group_get_children(cx9r_kt_group const *ktg);
cx9r_kt_group *cx9r_kt_group_get_next(cx9r_kt_group const *ktg);
cx9r_kt_entry *cx9r_kt_group_get_entries(cx9r_kt_group const *ktg);
char const *cx9r_kt_group_get_name(cx9r_kt_group const *ktg);
char const *cx9r_kt_group_set_name(cx9r_kt_group *ktg, char const *name, size_t length);
char const *cx9r_kt_group_set_zname(cx9r_kt_group *ktg, char const *name);
cx9r_kt_group *cx9r_kt_group_add_child(cx9r_kt_group *ktg);
cx9r_kt_entry *cx9r_kt_group_add_entry(cx9r_kt_group *ktg);

char const *cx9r_kt_entry_get_name(cx9r_kt_entry *kte);
char const *cx9r_kt_entry_set_name(cx9r_kt_entry *kte, char const *name, size_t length);
char const *cx9r_kt_entry_set_zname(cx9r_kt_entry *kte, char const *name);
cx9r_kt_field *cx9r_kt_entry_get_fields(cx9r_kt_entry *kte);
cx9r_kt_field *cx9r_kt_entry_add_field(cx9r_kt_entry *kte);
cx9r_kt_entry *cx9r_kt_entry_get_next(cx9r_kt_entry *kte);

char const *cx9r_kt_field_get_name(cx9r_kt_field *ktf);
char const *cx9r_kt_field_set_name(cx9r_kt_field *ktf, char const *name, size_t length);
char const *cx9r_kt_field_set_zname(cx9r_kt_field *ktf, char const *name);
char const *cx9r_kt_field_get_value(cx9r_kt_field *ktf);
char const *cx9r_kt_field_set_value(cx9r_kt_field *ktf, char const *value, size_t length);
char const *cx9r_kt_field_set_zvalue(cx9r_kt_field *ktf, char const *value);
cx9r_kt_field *cx9r_kt_field_get_next(cx9r_kt_field *ktf);

#endif
