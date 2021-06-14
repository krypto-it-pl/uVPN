/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "counter.h"
#include <string.h>
#include "global.h"
#include <avl.h>
#include <logger.h>

#define _BSD_SOURCE
#ifndef SYS_ENDIAN
#include <endian.h>
#else
#include <sys/endian.h>
#endif

typedef struct conn_entry
{
  conn_id_t conn;
  uint16_t flags;
  encrypt_key_t key;
} conn_entry_t;

avl_t g_conn_table = NULL;

static int comparator(const void * a, const void * b)
{
  const conn_entry_t * first = (const conn_entry_t *)a;
  const conn_entry_t * second = (const conn_entry_t *)b;

  return first->conn - second->conn;
}

void counter_init(void)
{
  g_conn_table = avl_create(sizeof(conn_entry_t), MAX_CONNECTIONS, \
      comparator);
}

void counter_done(void)
{
  avl_dispose(g_conn_table);
}

void counter_worker_new_conn(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  if (data->source != data->destination)
    return;

  conn_entry_t entry;
  entry.conn = data->source;
  entry.flags = 1;
  memcpy(&entry.key, &data->conn.encrypt_key, sizeof(entry.key));
  avl_set(g_conn_table, &entry);

  logger_printf(LOGGER_DEBUG, "New connection/unfreezing from %hu", \
      data->source);
}

void counter_worker_close_conn(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  conn_entry_t entry;
  entry.conn = data->source;
  entry.flags = 0;
  memset(&entry.key, 0, sizeof(entry.key));
  avl_delete(g_conn_table, &entry);

  logger_printf(LOGGER_DEBUG, "Closing connection from %hu", data->source);
}

void counter_worker_freeze(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  conn_entry_t entry;
  entry.conn = data->source;
  entry.flags = 2;
  avl_set(g_conn_table, &entry);

  logger_printf(LOGGER_DEBUG, "Start freezing packet from %hu", data->source);
}

void counter_worker_raw_net(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  conn_entry_t entry;
  entry.conn = data->destination;
  entry.flags = 0;
  avl_get(g_conn_table, &entry);

  if (entry.flags == 0)
    return;

  if (entry.flags == 2) {
    logger_printf(LOGGER_INFO, "Drop packet for unknown destination" \
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (counter)", \
        data->net.dst_mac[0], data->net.dst_mac[1], data->net.dst_mac[2],
        data->net.dst_mac[3], data->net.dst_mac[4], data->net.dst_mac[5]);
    data->msg_type = MSG_TYPE_DROP;
    return;
  }

  uint16_t length = data_size - ((char *)&data->net.pkt_idx - (char *)data);
  uint16_t key_step = length >> 4;
  uint64_t key[4];

  memcpy(key, entry.key.key, sizeof(key));
  memcpy(&data->net.key, &entry.key, sizeof(data->net.key));

  key[0] = be64toh(key[0]);
  key[1] = be64toh(key[1]);

  key[1] += key_step;
  if (key[1] < key_step)
    key[0]++;

  key[0] = htobe64(key[0]);
  key[1] = htobe64(key[1]);

  memcpy(entry.key.key, key, sizeof(key));

  avl_set(g_conn_table, &entry);
}

void counter_worker(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  switch (data->msg_type) {
    case MSG_TYPE_NEW_CONN:
      counter_worker_new_conn(void_data, data_size);
      break;
    case MSG_TYPE_CLOSE_CONN:
      counter_worker_close_conn(void_data, data_size);
      break;
    case MSG_TYPE_FREEZE_CONN:
      counter_worker_freeze(void_data, data_size);
      break;
    case MSG_TYPE_RAW_NET:
      counter_worker_raw_net(void_data, data_size);
      break;
  }
}
