/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "decrypt.h"
#include <stdio.h>
#include <string.h>
#include "global.h"
#include <crc32.h>
#include <logger.h>

#ifndef SYS_ENDIAN
#include <endian.h>
#else
#include <sys/endian.h>
#endif

void checksum_worker(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  if (data->msg_type != MSG_TYPE_RAW_NET)
    return;

  unsigned char * rawdata = (unsigned char *)&data->net.flags;
  uint16_t length = data_size - ((char *)&data->net.pkt_idx - (char *)data);

  uint32_t crc = crc32(rawdata, length);
  if (data->net.crc32 == 0) {
    data->net.crc32 = htobe32(crc);
  } else if (crc != be32toh(data->net.crc32)) {
      logger_printf(LOGGER_DEBUG, "Drop packet from " \
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (crc32)", \
        data->net.src_mac[0], data->net.src_mac[1], data->net.src_mac[2],
        data->net.src_mac[3], data->net.src_mac[4], data->net.src_mac[5]);
    data->msg_type = MSG_TYPE_DROP;
  }
}
