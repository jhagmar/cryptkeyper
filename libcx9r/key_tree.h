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

typedef struct {
	char *name;
	char *value;
} cx9r_kt_field;

typedef struct cx9r_kt_entry;

typedef struct {
	char *key;
	cx9r_kt_field *fields;
	cx9r_kt_entry *next;
} cx9r_kt_entry;

typedef struct cx9r_kt_group;

typedef struct {
	cx9r_kt_group *children;
	cx9r_kt_group *next;
	cx9r_kt_entry *entries;
} cx9r_kt_group;

typedef struct {
	cx9r_kt_group root;
} cx9r_key_tree;

cx9r_key_tree *cx9r_key_tree_create();
cx9r_kt_group *cx9r_key_tree_get_root(cx9r_key_tree const *kt);

cx9r_kt_group *cx9r_kt_group_get_children(cx9r_kt_group const *ktg);
cx9r_kt_group *cx9r_kt_group_get_next(cx9r_kt_group const *ktg);
cx9r_kt_entry *cx9r_kt_group_get_entries(cx9r_kt_group const *ktg);
cx9r_kt_group *cx9r_kt_group_add_child(cx9r_kt_group *ktg);


#endif
