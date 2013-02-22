/*
 * key_tree.c
 *
 *  Created on: 22 feb 2013
 *      Author: jhagmar
 */

#include "key_tree.h"
#include <stdlib.h>

cx9r_key_tree *cx9r_key_tree_create() {
	cx9r_key_tree *kt;

	if ((kt = malloc(sizeof(cx9r_key_tree))) == NULL) {
		return NULL;
	}

	kt->root.children = NULL;
	kt->root.next = NULL;
	kt->root.entries = NULL;

	return kt;
}

cx9r_kt_group *cx9r_key_tree_get_root(cx9r_key_tree const *kt) {
	return &kt->root;
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

	c->children = NULL;
	c->entries = NULL;
	c->next = NULL;
	*slot = c;
	return c;
}
