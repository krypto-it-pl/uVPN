/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __CRC32_H__
#define __CRC32_H__

#include <stdint.h>
#include <stddef.h>

uint32_t crc32(unsigned char * data, size_t data_len);

#endif
