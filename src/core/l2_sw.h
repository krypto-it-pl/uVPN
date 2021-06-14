/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __L2_SW_H__
#define __L2_SW_H__

#include <queue.h>

void l2_sw_init(void);
void l2_sw_done(void);
void l2_sw_worker(void * data, size_t data_size);

#endif
