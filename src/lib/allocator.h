/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __ALLOCATOR_H__
#define __ALLOCATOR_H__

#include <stddef.h>

typedef struct allocator_t * allocator_t;

allocator_t allocator_create(size_t block_size, size_t block_count);
void allocator_despose(allocator_t allocator);
void * allocator_new(allocator_t allocator);
void allocator_free(allocator_t allocator, void * block);

#endif
