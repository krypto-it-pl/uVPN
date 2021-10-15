/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "l2_sw.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "global.h"
#include <avl.h>
#include <logger.h>

#define MAC_TABLE_SIZE (1024 * 16)

avl_t g_mac_table = NULL;

typedef struct mac_table
{
  conn_id_t conn_id;
  unsigned char mac_addr[6];
  uint32_t pkt_idx;
} mac_table_t;

static int comparator(const void * a, const void * b)
{
  const mac_table_t * first = (const mac_table_t *)a;
  const mac_table_t * second = (const mac_table_t *)b;

  return memcmp(first->mac_addr, second->mac_addr, 6);
}

static int del_comparator(const void * a, const void * b)
{
  mac_table_t * first = (mac_table_t *)a;
  conn_id_t * second = (conn_id_t *)b;

  return first->conn_id == *second;
}

void l2_sw_init(void)
{
  g_mac_table = avl_create(sizeof(mac_table_t), MAC_TABLE_SIZE, comparator);
}

void l2_sw_done(void)
{
  avl_dispose(g_mac_table);
}

void l2_sw_clear_arp(void)
{
  avl_dispose(g_mac_table);
  g_mac_table = avl_create(sizeof(mac_table_t), MAC_TABLE_SIZE, comparator);
}

void l2_sw_worker(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  if (data->msg_type == MSG_TYPE_CLOSE_CONN) {
    avl_delete_if(g_mac_table, del_comparator, &data->source);
    return;
  }

  if (data->msg_type == MSG_TYPE_CLEAR_ARP) {
    l2_sw_clear_arp();
    return;
  }

  if (data->msg_type != MSG_TYPE_RAW_NET)
    return;

  if (data->net.length == 0)
    return;

  mac_table_t mac_entry;

  mac_entry.conn_id = -1;
  mac_entry.pkt_idx = data->net.pkt_idx;
  memcpy(mac_entry.mac_addr, data->net.src_mac, 6);

  avl_get(g_mac_table, &mac_entry);
  if (mac_entry.conn_id == -1) {
    mac_entry.conn_id = data->source;
    avl_set(g_mac_table, &mac_entry);
  }

  if (data->destination != -1) {
    if ((data->source == mac_entry.conn_id) && \
        (mac_entry.pkt_idx == data->net.pkt_idx))
      return;

    if ((mac_entry.pkt_idx >= data->net.pkt_idx) || \
        (((data->net.pkt_idx & 0xFFF00000) == 0) &&
        ((mac_entry.pkt_idx & 0xFFF00000) > 0))) {
      data->msg_type = MSG_TYPE_DROP;

      logger_printf(LOGGER_INFO, "Drop duplicated packet from " \
          " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", \
          data->net.src_mac[0], data->net.src_mac[1], data->net.src_mac[2],
          data->net.src_mac[3], data->net.src_mac[4], data->net.src_mac[5]);
      return;
    }

    mac_entry.conn_id = data->source;
    mac_entry.pkt_idx = data->net.pkt_idx;
    avl_set(g_mac_table, &mac_entry);

    return;
  }

  if (mac_entry.conn_id != data->source) {
    mac_entry.conn_id = data->source;
    avl_set(g_mac_table, &mac_entry);
  }

  mac_entry.conn_id = -1;
  memcpy(mac_entry.mac_addr, data->net.dst_mac, 6);

  avl_get(g_mac_table, &mac_entry);
  if (mac_entry.conn_id == -1) {
    logger_printf(LOGGER_INFO, "Drop packet for unknown destination" \
        " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (L2SW)", \
        data->net.dst_mac[0], data->net.dst_mac[1], data->net.dst_mac[2],
        data->net.dst_mac[3], data->net.dst_mac[4], data->net.dst_mac[5]);
    data->msg_type = MSG_TYPE_DROP;
  } else {
    data->destination = mac_entry.conn_id;
  }
}
