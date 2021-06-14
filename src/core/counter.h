/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __COUNTER_H__
#define __COUNTER_H__

#include <queue.h>

void counter_init(void);
void counter_done(void);

void counter_worker(void * data, size_t data_size);

#endif
