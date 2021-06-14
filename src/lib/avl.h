/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __AVL_H__
#define __AVL_H__

#include <stddef.h>

typedef struct avl_t * avl_t;

typedef int (* avl_comparator_t)(const void *, const void *);

avl_t avl_create(size_t data_size, size_t max_elements, \
    avl_comparator_t comparator);
void avl_dispose(avl_t avl);

int avl_set(avl_t avl, void * data);
void avl_get(avl_t avl, void * data);
void avl_delete(avl_t avl, void * data);
void avl_delete_if(avl_t avl, avl_comparator_t comparator, void * data);

size_t avl_size(avl_t avl);

#endif
