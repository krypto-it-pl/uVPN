/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "tap.h"
#include <stdio.h>
#include <string.h>
#include <tap_int.h>
#include <threads.h>
#include <logger.h>

#ifndef SYS_ENDIAN
#include <endian.h>
#else
#include <sys/endian.h>
#endif

void tap_io_read(void * arg)
{
  struct tap_conn_info * conn = (struct tap_conn_info *)arg;

  struct packet_record buffer;
  buffer.msg_type = MSG_TYPE_RAW_NET;
  buffer.source = conn->conn_id;
  buffer.net.crc32 = 0;
  memset(buffer.net.key.key, 0, sizeof(buffer.net.key.key));
  buffer.net.key.type = -1;

  while (!end_now) {
    unsigned int buffer_size = sizeof(buffer.net) - \
        ((char *)&buffer.net.flags - (char *)&buffer.net);

    tap_read(conn->dev_sock, &buffer.net.flags, &buffer_size);

    if (buffer_size < 16) {
      logger_printf(LOGGER_ERROR, "Packet from TAP is to small %u", buffer_size);
      continue;
    }

    if (buffer_size > MAX_MTU) {
      logger_printf(LOGGER_ERROR, "Packet from TAP is to big %u", buffer_size);
      continue;
    }

    buffer.net.length = htobe16(buffer_size);

    buffer_size = (buffer_size + 10 + 15) & ~0x0F;

    if (!is_bcast(buffer.net.dst_mac)) {
      buffer.destination = -1;
      buffer.net.pkt_idx = 0;

      queue_enqueue(global_queue, &buffer, buffer_size + \
          ((char *)&buffer.net.pkt_idx - (char *)&buffer), MAX_CONNECTIONS);
    } else {
      conn->bcast_counter++;
      if (!conn->bcast_counter)
        conn->bcast_counter++;
      buffer.net.pkt_idx = conn->bcast_counter;

      for (unsigned int i = 0; i < MAX_CONNECTIONS; i++) {
        if ((conn_mask[i >> 6] & (1LLU << (i & 0x3F))) \
            && (i != conn->conn_id)) {
          buffer.destination = i;
          queue_enqueue(global_queue, &buffer, buffer_size + \
              ((char *)&buffer.net.pkt_idx - (char *)&buffer), MAX_CONNECTIONS);
        }
      }
    }
  }
}

void tap_init(struct tap_conn_info * conn, int dev_sock, conn_id_t conn_id)
{
  conn->conn_id = conn_id;
  conn->dev_sock = dev_sock;
  conn->bcast_counter = 0;

  conn->io_read_thread = thread_new(tap_io_read, conn);
}

void tap_done(struct tap_conn_info * conn)
{
  thread_join(conn->io_read_thread);
}

void tap_worker(struct tap_conn_info * conn, void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  tap_write(conn->dev_sock, &data->net.flags, be16toh(data->net.length));
}
