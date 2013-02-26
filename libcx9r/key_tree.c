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
#include <string.h>

cx9r_key_tree *cx9r_key_tree_create() {
	cx9r_key_tree *kt;

	if ((kt = malloc(sizeof(cx9r_key_tree))) == NULL) {
		return NULL;
	}

	kt->root.parent = NULL;
	kt->root.children = NULL;
	kt->root.next = NULL;
	kt->root.entries = NULL;
	kt->root.name = NULL;

	return kt;
}

static void field_free(cx9r_kt_field *ktf) {
	if (ktf != NULL) {
		field_free(ktf->next);
		free(ktf->name);
		free(ktf->value);
		free(ktf);
	}
}

static void entry_free(cx9r_kt_entry *kte) {
	if (kte != NULL) {
		entry_free(kte->next);
		field_free(kte->fields);
		free(kte->name);
		free(kte);
	}
}

static void group_free(cx9r_kt_group *ktg) {
	if (ktg != NULL) {
		group_free(ktg->children);
		group_free(ktg->next);
		entry_free(ktg->entries);
		free(ktg->name);
		free(ktg);
	}
}

void cx9r_key_tree_free(cx9r_key_tree *kt) {
	group_free(kt->root.children);
	entry_free(kt->root.entries);
	free(kt->root.name);
	free(kt);
}

cx9r_kt_group *cx9r_key_tree_get_root(cx9r_key_tree *kt) {
	return &kt->root;
}

cx9r_kt_group *cx9r_kt_group_get_parent(cx9r_kt_group const *ktg) {
	return ktg->parent;
}

cx9r_kt_group *cx9r_kt_group_get_children(cx9r_kt_group const *ktg) {
	return ktg->children;
}

cx9r_kt_group *cx9r_kt_group_get_next(cx9r_kt_group const *ktg) {
	return ktg->next;
}

cx9r_kt_entry *cx9r_kt_group_get_entries(cx9r_kt_group const *ktg) {
	return ktg->entries;
}

char const *cx9r_kt_group_get_name(cx9r_kt_group const *ktg) {
	return ktg->name;
}

char const *cx9r_kt_group_set_name(cx9r_kt_group *ktg, char const *name, size_t length) {
	if (ktg->name != NULL) {
		free(ktg->name);
		ktg->name = NULL;
	}
	ktg->name = malloc(length + 1);
	if (ktg->name == NULL) {
		return NULL;
	}
	strncpy(ktg->name, name, length);
	ktg->name[length] = NULL;
	return ktg->name;
}

char const *cx9r_kt_group_set_zname(cx9r_kt_group *ktg, char const *name) {
	return cx9r_kt_group_set_name(ktg, name, strlen(name));
}

cx9r_kt_group *cx9r_kt_group_add_child(cx9r_kt_group *ktg) {
	cx9r_kt_group *c;
	cx9r_kt_group **slot;

	// find the slot to fill with a newly allocated group
	if (ktg->children == NULL) {
		slot = &ktg->children;
	}
	else {
		c = ktg->children;
		while (c->next != NULL) c = c->next;
		slot = &c->next;
	}

	if ((c = malloc(sizeof(cx9r_kt_group))) == NULL) {
		return NULL;
	}

	c->name = NULL;
	c->parent = ktg;
	c->children = NULL;
	c->entries = NULL;
	c->next = NULL;
	c->name = NULL;
	*slot = c;
	return c;
}

cx9r_kt_entry *cx9r_kt_group_add_entry(cx9r_kt_group *ktg) {
	cx9r_kt_entry *e;
	cx9r_kt_entry **slot;

	//find the slot to fill with the newly allocated entry
	if (ktg->entries == NULL) {
		slot = &ktg->entries;
	}
	else {
		e = ktg->entries;
		while (e->next != NULL) e = e->next;
		slot = &e->next;
	}

	if ((e = malloc(sizeof(cx9r_kt_entry))) == NULL) {
		return NULL;
	}

	e->next = NULL;
	e->fields = NULL;
	e->name = NULL;
	*slot = e;
	return e;
}

char const *cx9r_kt_entry_get_name(cx9r_kt_entry *kte) {
	return kte->name;
}

char const *cx9r_kt_entry_set_name(cx9r_kt_entry *kte, char const *name, size_t length) {
	if (length < 0) {
		length = strlen(name);
	}

	if (kte->name != NULL) {
		free(kte->name);
		kte->name = NULL;
	}
	kte->name = malloc(length + 1);
	if (kte->name == NULL) {
		return NULL;
	}
	strncpy(kte->name, name, length);
	kte->name[length] = 0;
	return kte->name;
}

char const *cx9r_kt_entry_set_zname(cx9r_kt_entry *kte, char const *name) {
	return cx9r_kt_entry_set_name(kte, name, strlen(name));
}

cx9r_kt_field *cx9r_kt_entry_get_fields(cx9r_kt_entry *kte) {
	return kte->fields;
}

cx9r_kt_field *cx9r_kt_entry_add_field(cx9r_kt_entry *kte) {
	cx9r_kt_field *f;
	cx9r_kt_field **slot;

	//find the slot to fill with the newly allocated entry
	if (kte->fields == NULL) {
		slot = &kte->fields;
	} else {
		f = kte->fields;
		while (f->next != NULL)
			f = f->next;
		slot = &f->next;
	}

	if ((f = malloc(sizeof(cx9r_kt_field))) == NULL) {
		return NULL;
	}

	f->name = NULL;
	f->next = NULL;
	f->value = NULL;
	*slot = f;
	return f;
}

cx9r_kt_entry *cx9r_kt_entry_get_next(cx9r_kt_entry *kte) {
	return kte->next;
}

char const *cx9r_kt_field_get_name(cx9r_kt_field *ktf) {
	return ktf->name;
}

char const *cx9r_kt_field_set_name(cx9r_kt_field *ktf, char const *name, size_t length) {
	if (ktf->name != NULL) {
		free(ktf->name);
		ktf->name = NULL;
	}
	ktf->name = malloc(length + 1);
	if (ktf->name == NULL) {
		return NULL;
	}
	strncpy(ktf->name, name, length);
	ktf->name[length] = NULL;
	return ktf->name;
}

char const *cx9r_kt_field_set_zname(cx9r_kt_field *ktf, char const *name) {
	return cx9r_kt_field_set_name(ktf, name, strlen(name));
}

char const *cx9r_kt_field_get_value(cx9r_kt_field *ktf) {
	return ktf->value;
}

char const *cx9r_kt_field_set_value(cx9r_kt_field *ktf, char const *value, size_t length) {
	if (ktf->value != NULL) {
		free(ktf->value);
		ktf->value = NULL;
	}
	ktf->value = malloc(length + 1);
	if (ktf->value == NULL) {
		return NULL;
	}
	strncpy(ktf->value, value, length);
	ktf->value[length] = NULL;
	return ktf->value;
}

char const *cx9r_kt_field_set_zvalue(cx9r_kt_field *ktf, char const *value) {
	return cx9r_kt_field_set_value(ktf, value, strlen(value));
}

cx9r_kt_field *cx9r_kt_field_get_next(cx9r_kt_field *ktf) {
	return ktf->next;
}
