/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "tcp.h"

#include <stdio.h>
#include <string.h>
#include <semaphore.h>
#include <threads.h>
#include <twofish.h>
#include <rsa.h>
#include <logger.h>
#include <random.h>
#include <sys/select.h>
#include "config.h"

#define DEFAULT_MSS 1460
#define WRITE_PART_MULT (16)
#define MAX_WRITE_PART (DEFAULT_MSS * WRITE_PART_MULT)
#define MSS_WRITE_PART(mss) (mss * WRITE_PART_MULT)
#define WRITE_PART(mss) \
    ((MSS_WRITE_PART(mss) > MAX_WRITE_PART)?MAX_WRITE_PART:MSS_WRITE_PART(mss))

#define TCP_READ_AUTH_TIMEOUT_SEC 5

#define TCP_AUTH_KEY_PAIR 1

static void tcp_new_conn(struct tcp_conn_info * data)
{
  struct packet_record record;
  record.msg_type = MSG_TYPE_NEW_CONN;
  record.source = data->conn_id;
  record.destination = data->conn_id;

  uint64_t key[4] = {be64toh(data->enc_key[0]), be64toh(data->enc_key[1]), \
      data->enc_key[2], data->enc_key[3]};
  key[1] += data->written_blocks;
  if (key[1] < data->written_blocks)
    key[0]++;

  key[0] = htobe64(key[0]);
  key[1] = htobe64(key[1]);

  memcpy(&record.conn.encrypt_key.key, key, sizeof(key));
  record.conn.encrypt_key.type = data->cipher;

  size_t data_size = ((char *)&record.conn - (char *)&record + \
      sizeof(record.conn));

  queue_enqueue(global_queue, &record, data_size, 0);
}

void tcp_ping(struct tcp_conn_info * data, int flag)
{
  time_t now = time(NULL);

  if (!flag) {
    if (now > atomic_load(&data->last_read) + data->timeout[1]) {
      data->end_now = 1;

      struct packet_record record;
      record.msg_type = MSG_TYPE_CLOSE_CONN;
      record.source = data->conn_id;
      record.destination = data->conn_id;

      size_t data_size = ((char *)&record.conn - (char *)&record);

      logger_printf(LOGGER_ERROR, "Connection with %s timeouted. Closing it.", \
          data->name);

      queue_enqueue(global_queue, &record, data_size, 0);

      return;
    }

    if (now < atomic_load(&data->last_read) + data->timeout[0])
      return;
  }

  struct packet_record record;
  record.msg_type = MSG_TYPE_RAW_NET;
  record.source = data->conn_id;
  record.destination = data->conn_id;
  memset(&record.net.key, 0, sizeof(record.net.key));
  record.net.pkt_idx = 0;
  record.net.crc32 = 0;
  record.net.length = 0;

  size_t data_size = ((char *)&record.net.pkt_idx - (char *)&record) + \
      ((((char *)&record.net.flags - (char *)&record.net.pkt_idx) + 15) & \
      ~0x0F);

  logger_printf(LOGGER_ERROR, "Data transfer with %s timeouted. Pinging it.", \
      data->name);

  queue_enqueue(global_queue, &record, data_size, MAX_CONNECTIONS);
}

static const struct static_servers_config_t * tcp_find_server_by_name( \
    const char * name)
{
  const struct static_servers_config_t * servers = config->static_servers;
  if (!servers) {
    logger_printf(LOGGER_ERROR, "Servers list is empty!");
    return NULL;
  }

  for (size_t i = 0; i < config->static_servers_count; i++)
    if (strcmp(servers[i].name, name) == 0)
      return &config->static_servers[i];

  return NULL;
}

static struct RSA * tcp_find_rsa_by_name(const char * name)
{
  sem_wait(&config_sem);
  const struct static_servers_config_t * server = tcp_find_server_by_name(name);
  if (!server) {
    sem_post(&config_sem);
    logger_printf(LOGGER_ERROR, "Can't find config for server: %s", name);
    return NULL;
  }

  struct RSA * rsa = load_rsakey(server->public_key);
  if (!rsa) {
    logger_printf(LOGGER_ERROR, "Can't load public key from file: %s", \
        server->public_key);
    sem_post(&config_sem);
    return NULL;
  }
  sem_post(&config_sem);
  return rsa;
}

static int tcp_io_read_auth_send(struct tcp_conn_info * data)
{
  unsigned char local_buffer[BUFFER_SIZE];
  unsigned char local_buffer_2[BUFFER_SIZE];

  struct RSA * rsa_2nd = tcp_find_rsa_by_name(data->name);
  if (!rsa_2nd)
    return 1;

  local_buffer[0] = strlen(config->name);
  strcpy((char *)&local_buffer[1], config->name);

  size_t len = rsa_process_out(thiz_rsa, 0, local_buffer, local_buffer[0] + 1, \
      &local_buffer_2[1]);
  local_buffer_2[0] = TCP_AUTH_KEY_PAIR;
  len += 1;

  size_t out_size = rsa_process_out(rsa_2nd, 1, local_buffer_2, len, \
      &local_buffer[2]);
  local_buffer[0] = out_size >> 8;
  local_buffer[1] = out_size;

  out_size += 2;
  size_t pos = 0;
  while (pos < out_size) {
    tcp_conn_data_size_t length = out_size - pos;
    tcp_conn_stat_t stat = tcp_conn_write(&data->tcp_conn, \
        &local_buffer[pos], &length);
    if (stat != TCP_CONN_STAT_OK)
      return 1;
    pos += length;
  }

  return 0;
}

static int tcp_io_read_data(tcp_conn_t conn, unsigned char * buffer, \
    size_t (*need_read)(const unsigned char * buffer, size_t fill, void *), \
    void * cmp_data, time_t max_time, size_t * fill)
{
  size_t local_buffer_fill = 0;
  time_t start_time = time(NULL);
  size_t for_read;

  while ((for_read = need_read(buffer, local_buffer_fill, cmp_data))) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(conn->sock, &set);
    struct timeval timeout;
    timeout.tv_sec = start_time - time(NULL) + max_time;
    timeout.tv_usec = 0;
    int r = select(conn->sock + 1, &set, NULL, NULL, &timeout);
    if (r == 1) {
      tcp_conn_data_size_t length = for_read;
      tcp_conn_stat_t stat = tcp_conn_read(conn, buffer + local_buffer_fill, \
          &length);
      if (stat != TCP_CONN_STAT_OK) {
        logger_printf(LOGGER_ERROR, "Read error during auth");
        return 1;
      }

      local_buffer_fill += length;
    } else if (start_time - time(NULL) + max_time == 0) {
      return 2;
    }
  }

  *fill = local_buffer_fill;
  return 0;
}

static size_t tcp_io_need_read_rsa(const unsigned char * buffer, size_t fill, \
    void * data)
{
  size_t * max_size = (size_t *)data;

  if (fill <= 2)
    return *max_size - fill;

  size_t size = ((buffer[0] << 8) | buffer[1]);

  return size - fill + 2;
}

static int tcp_io_read_auth_recv(struct tcp_conn_info * data)
{
  unsigned char local_buffer[BUFFER_SIZE];
  unsigned char local_buffer_2[BUFFER_SIZE];
  size_t full_size;
  size_t max_size = BUFFER_SIZE;

  if (tcp_io_read_data(&data->tcp_conn, local_buffer, tcp_io_need_read_rsa, \
      &max_size, TCP_READ_AUTH_TIMEOUT_SEC, &full_size)) {
    return 1;
  }
  full_size -= 2;

  size_t len2 = rsa_process_in(thiz_rsa, 0, &local_buffer[2], full_size, \
      local_buffer_2);

  size_t i;
  sem_wait(&config_sem);
  for (i = 0; i < config->static_servers_count; i++) {
    if (!config->static_servers[i].public_key)
      continue;
    if (!config->static_servers[i].allow_new_connect)
      continue;

    if (local_buffer_2[0] != TCP_AUTH_KEY_PAIR) {
      logger_printf(LOGGER_DEBUG, "Auth error (1)");
      continue;
    }

    struct RSA * rsa = load_rsakey(config->static_servers[i].public_key);
    if (!rsa)
      continue;
    logger_printf(LOGGER_DEBUG, "Auth info - key found for %s", \
        config->static_servers[i].name);

    size_t len = rsa_process_in(rsa, 1, &local_buffer_2[1], len2 - 1, \
        local_buffer);
    if (len != strlen(config->static_servers[i].name) + 1) {
      logger_printf(LOGGER_DEBUG, "Auth error (2)");
      continue;
    }

    size_t len2 = local_buffer[0];
    if (len2 + 1 != len) {
      logger_printf(LOGGER_DEBUG, "Auth error (3)");
      continue;
    }

    if (memcmp(&local_buffer[1], config->static_servers[i].name, len2) == 0)
      break;

    logger_printf(LOGGER_ERROR, "Auth error (4)");
  }

  if (i == config->static_servers_count) {
    sem_post(&config_sem);
    logger_printf(LOGGER_ERROR, "Auth error - server not found");
    return 1;
  }

  if (data->name[0]) {
    if (strcmp(data->name, config->static_servers[i].name)) {
      sem_post(&config_sem);
      logger_printf(LOGGER_ERROR, "Auth error - invalid server name");
      return 1;
    }
  } else {
    strncpy(data->name, config->static_servers[i].name, \
        MAX_CLIENT_NAME_LENGTH - 1);
    data->timeout[0] = config->static_servers[i].keepalive[0];
    data->timeout[1] = config->static_servers[i].keepalive[1];
    if (data->cipher < 0)
      data->cipher = cipher_mode_str_to_int(config->static_servers[i].cipher);
    if (data->cipher < 0) {
      logger_printf(LOGGER_ERROR, "Auth error - invalid cipher (%s) for %s",
          config->static_servers[i].cipher, config->static_servers[i].name);
      return 1;
    }
  }

  logger_printf(LOGGER_INFO, "Auth success for server %s", data->name);

  sem_post(&config_sem);

  return 0;
}

int tcp_io_read_key_send(struct tcp_conn_info * data)
{
  size_t key_size = get_key_size(data->cipher);

  uint64_t key[4];
  if (random_bytes(sizeof(uint64_t) * key_size, (unsigned char *)key))
    return 1;

  memcpy(data->enc_key, key, sizeof(uint64_t) * key_size);

  unsigned char local_buffer[BUFFER_SIZE];

  struct RSA * rsa_2nd = tcp_find_rsa_by_name(data->name);
  if (!rsa_2nd)
    return 1;

  size_t out_size = rsa_process_out(rsa_2nd, 1, (unsigned char *)key, \
      sizeof(uint64_t) * key_size, &local_buffer[2]);

  local_buffer[0] = out_size >> 8;
  local_buffer[1] = out_size;

  out_size += 2;

  size_t pos = 0;
  while (pos < out_size) {
    tcp_conn_data_size_t length = out_size - pos;
    tcp_conn_stat_t stat = tcp_conn_write(&data->tcp_conn, \
        &local_buffer[pos], &length);
    if (stat != TCP_CONN_STAT_OK)
      return 1;
    pos += length;
  }

  return 0;
}

int tcp_io_read_key_recv(struct tcp_conn_info * data)
{
  unsigned char local_buffer[BUFFER_SIZE];
  unsigned char local_buffer_2[BUFFER_SIZE];
  size_t full_size;
  size_t max_size = BUFFER_SIZE;
  size_t key_size = get_key_size(data->cipher);

  if (tcp_io_read_data(&data->tcp_conn, local_buffer, tcp_io_need_read_rsa, \
      &max_size, TCP_READ_AUTH_TIMEOUT_SEC, &full_size)) {
    logger_printf(LOGGER_ERROR, "Key exchange - invalid key read");
    return 1;
  }
  full_size -= 2;

  size_t len2 = rsa_process_in(thiz_rsa, 0, &local_buffer[2], full_size, \
      local_buffer_2);

  if (len2 != sizeof(uint64_t) * key_size) {
    logger_printf(LOGGER_ERROR, \
        "Key exchange - invalid key size (%zd vs %zd)", \
        len2, sizeof(uint64_t) * key_size);
    return 1;
  }

  memcpy(data->dec_key, local_buffer_2, sizeof(uint64_t) * key_size);

  return 0;
}

static void tcp_io_read_thread(void * data_void)
{
  struct tcp_conn_info * data = (struct tcp_conn_info *)data_void;

  unsigned char local_buffer[BUFFER_SIZE];
  size_t local_buffer_fill = 0;

  if (data->auth) {
    if (tcp_io_read_auth_send(data))
      goto tcp_read_end;
    if (tcp_io_read_auth_recv(data))
      goto tcp_read_end;
  } else {
    if (tcp_io_read_auth_recv(data))
      goto tcp_read_end;
    if (tcp_io_read_auth_send(data))
      goto tcp_read_end;
  }

  if (tcp_io_read_key_send(data))
    goto tcp_read_end;
  if (tcp_io_read_key_recv(data))
    goto tcp_read_end;

  tcp_new_conn(data);

  int try_again = 0;
  while ((!end_now) && (!data->end_now)) {
    tcp_conn_data_size_t length = BUFFER_SIZE - local_buffer_fill;

    if (!try_again) {
      fd_set set;
      FD_ZERO(&set);
      FD_SET(data->tcp_conn.sock, &set);
      struct timeval timeout;
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
      int r = select(data->tcp_conn.sock + 1, &set, NULL, NULL, &timeout);
      if (r != 1)
        continue;

      tcp_conn_stat_t stat = tcp_conn_read(&data->tcp_conn, \
        local_buffer + local_buffer_fill, &length);
      local_buffer_fill += length;

      if (stat == TCP_CONN_STAT_ERROR_END_OF_STREAM) {
        logger_printf(LOGGER_ERROR, "TCP error - EOF with %s", data->name);
        break;
      }
      if (stat != TCP_CONN_STAT_OK) {
        logger_printf(LOGGER_ERROR, "TCP error with %s", data->name);
        break;
      }
    } else
      try_again = 0;
  
    if (local_buffer_fill < 16)
      continue;

    uint64_t key[4] = {be64toh(data->dec_key[0]), be64toh(data->dec_key[1]), \
        data->dec_key[2], data->dec_key[3]};
    key[1] += data->read_blocks;
    if (key[1] < data->read_blocks)
      key[0]++;
    key[0] = htobe64(key[0]);
    key[1] = htobe64(key[1]);

    uint8_t tmp[16];
    unsigned short size = 0;
    struct Twofish tf_key;
    if (data->cipher == CIPHER_TYPE_TWOFISH_MIXED) {
      twofish_init(&tf_key, 128, (unsigned char *)key);
      twofish_dec_block(&tf_key, local_buffer, (unsigned char *)tmp);
    } else {
      uint8_t tmp2[16], * lbuf = (uint8_t *)local_buffer;
      twofish_init(&tf_key, 128, (unsigned char *)&key[2]);
      twofish_enc_block(&tf_key, (unsigned char *)key, (unsigned char *)tmp2);
      tmp[0] = tmp2[0] ^ lbuf[0];
      tmp[1] = tmp2[1] ^ lbuf[1];
      tmp[2] = tmp2[2] ^ lbuf[2];
      tmp[3] = tmp2[3] ^ lbuf[3];
      tmp[4] = tmp2[4] ^ lbuf[4];
      tmp[5] = tmp2[5] ^ lbuf[5];
      tmp[6] = tmp2[6] ^ lbuf[6];
      tmp[7] = tmp2[7] ^ lbuf[7];
      tmp[8] = tmp2[8] ^ lbuf[8];
      tmp[9] = tmp2[9] ^ lbuf[9];
      tmp[10] = tmp2[10] ^ lbuf[10];
      tmp[11] = tmp2[11] ^ lbuf[11];
      tmp[12] = tmp2[12] ^ lbuf[12];
      tmp[13] = tmp2[13] ^ lbuf[13];
      tmp[14] = tmp2[14] ^ lbuf[14];
      tmp[15] = tmp2[15] ^ lbuf[15];
    }
    size = (tmp[8] << 8) | tmp[9];

    if (size > MAX_MTU) {
      logger_printf(LOGGER_ERROR, "Encrypted data error with %s (%hu > %u)", \
          data->name, size, MAX_MTU);
      break;
    }

    uint16_t pkg_length = ((size + 10 + 15) & ~0x0F);
    if (pkg_length > local_buffer_fill)
      continue;

    data->read_blocks += pkg_length >> 4;

    if (size > 0) {
      struct packet_record record;
      record.msg_type = MSG_TYPE_ENC_NET;
      record.source = data->conn_id;
      record.destination = -1;
      memcpy(&record.net.key.key, key, sizeof(key));
      record.net.key.type = data->cipher;
      memcpy(&record.net.pkt_idx, local_buffer, pkg_length);
      size_t data_length = ((unsigned char *)&record.net.pkt_idx - \
          (unsigned char *)&record) + pkg_length;

      if ((!tmp[0]) && (!tmp[1]) && (!tmp[2]) && (!tmp[3])) {
        queue_enqueue(global_queue, &record, data_length, MAX_CONNECTIONS);
      } else {
        for (unsigned int i = 0; i < MAX_CONNECTIONS; i++) {
          if ((conn_mask[i >> 6] & (1ULL << (i & 0x3F))) && \
                (i != data->conn_id)) {
            record.destination = i;
            queue_enqueue(global_queue, &record, data_length, MAX_CONNECTIONS);
          }
        }
      }
    } else {
      if (time(NULL) > atomic_load(&data->last_write) + data->timeout[0])
        tcp_ping(data, 1);
    }

    atomic_store(&data->last_read, time(NULL));

    if (pkg_length < local_buffer_fill) {
      memmove(local_buffer, &local_buffer[pkg_length], \
          local_buffer_fill - pkg_length);
      local_buffer_fill -= pkg_length;
    } else
      local_buffer_fill = 0;

    if (local_buffer_fill >= 16)
      try_again = 1;
  }

  tcp_read_end:;

  data->end_now = 1;
  
  struct packet_record record;
  record.msg_type = MSG_TYPE_CLOSE_CONN;
  record.source = data->conn_id;
  record.destination = data->conn_id;

  size_t data_size = ((char *)&record.conn - (char *)&record);

  queue_enqueue(global_queue, &record, data_size, 0);
  logger_printf(LOGGER_INFO, "Closing connection with %s", data->name);
}

static void tcp_io_write_thread(void * data_void)
{
  struct tcp_conn_info * data = (struct tcp_conn_info *)data_void;

  unsigned int local_buffer_fill = 0;
  unsigned char * local_buffer;
  unsigned char write_buffer[MAX_WRITE_PART];
  unsigned int write_buffer_fill = 0;

  while ((!end_now) && (!data->end_now)) {
    sem_wait(&data->write_sem);

    do {
      if (!atomic_load(&data->buffer_fill)) {
        break;
      }

      sem_wait(&data->buffer_sem);
      local_buffer_fill = atomic_load(&data->buffer_fill);
      atomic_store(&data->buffer_fill, 0);
      if (data->buffer == data->buffer_1) {
        local_buffer = data->buffer_1;
        data->buffer = data->buffer_2;
      } else {
        local_buffer = data->buffer_2;
        data->buffer = data->buffer_1;
      }

      sem_post(&data->buffer_sem);

      size_t offs = 0;

      while (offs < local_buffer_fill) {
        if (write_buffer_fill) {
          unsigned int to_copy = local_buffer_fill - offs;
          if (write_buffer_fill + to_copy > sizeof(write_buffer))
            to_copy = sizeof(write_buffer) - write_buffer_fill;
          memcpy(&write_buffer[write_buffer_fill], local_buffer + offs, \
              to_copy);
          write_buffer_fill += to_copy;

          if (write_buffer_fill == sizeof(write_buffer)) {
            size_t offs2 = 0, to_send = sizeof(write_buffer);
            while (to_send) {
              tcp_conn_data_size_t length = to_send;
              tcp_conn_write(&data->tcp_conn, write_buffer + offs2, &length);
              offs2 += length;
              to_send -= length;
            }
            offs += to_copy;
            write_buffer_fill = 0;
            continue;
          }

          int fill = atomic_load(&data->buffer_fill);
          if (!fill) {
            size_t offs2 = 0, to_send = write_buffer_fill;
            while (to_send) {
              tcp_conn_data_size_t length = to_send;
              tcp_conn_write(&data->tcp_conn, write_buffer + offs2, &length);
              offs2 += length;
              to_send -= length;
            }
            write_buffer_fill = 0;
          }
          break;
        } else {
          tcp_conn_data_size_t length = local_buffer_fill - offs;
          if (length > WRITE_PART(data->mss))
            length = WRITE_PART(data->mss);
          else if (length < WRITE_PART(data->mss)) {
            int fill = atomic_load(&data->buffer_fill);
            if (!fill) {
              size_t offs2 = offs, to_send = length;
              while (to_send) {
                length = to_send;
                tcp_conn_write(&data->tcp_conn, local_buffer + offs2, &length);
                offs2 += length;
                to_send -= length;
              }
            } else {
              memcpy(write_buffer, local_buffer + offs, length);
              write_buffer_fill = length;
            }
            break;
          }
          tcp_conn_write(&data->tcp_conn, local_buffer + offs, &length);
          offs += length;
        }
      }
      atomic_store(&data->last_write, time(NULL));
    } while((!end_now) && (!data->end_now));
  }
}

void tcp_init(struct tcp_conn_info * info, tcp_conn_t conn, conn_id_t conn_id, \
    const unsigned short keepalive[2], const char * name, unsigned int auth,
    const char * ipstr, unsigned short port, int cipher)
{
  memset(info, 0, sizeof(*info));

  info->conn_id = conn_id;
  memcpy(&info->tcp_conn, conn, sizeof(*conn));
  info->auth = auth;
  info->buffer = info->buffer_1;
  atomic_store(&info->buffer_fill, 0);
  info->end_now = 0;
  info->written_blocks = 0;
  info->read_blocks = 0;
  info->freeze = 0;

  sem_init(&info->buffer_sem, 0, 1);
  sem_init(&info->write_sem, 0, 1);

  info->enc_key[0] = 0x0llu;
  info->enc_key[1] = 0x0llu;
  info->dec_key[0] = 0x0llu;
  info->dec_key[1] = 0x0llu;

  info->io_read_thread = thread_new(tcp_io_read_thread, info);
  info->io_write_thread = thread_new(tcp_io_write_thread, info);
  atomic_store(&info->last_read, time(NULL));
  atomic_store(&info->last_write, time(NULL));
  info->timeout[0] = keepalive[0];
  info->timeout[1] = keepalive[1];
  info->mss = tcp_conn_get_mss(conn);
  if (!info->mss)
    info->mss = DEFAULT_MSS;
  strncpy(info->name, name, sizeof(info->name) - 1);
  strncpy(info->ipstr, ipstr, sizeof(info->ipstr) - 1);
  info->port = port;
  info->cipher = cipher;
}

void tcp_done(struct tcp_conn_info * info)
{
  info->end_now = 1;

  sem_post(&info->write_sem);

  tcp_conn_close(&info->tcp_conn);

  thread_join(info->io_read_thread);
  thread_join(info->io_write_thread);

  sem_destroy(&info->buffer_sem);
  sem_destroy(&info->write_sem);

  memset(info, 0, sizeof(*info));
}

static void send_freeze(struct tcp_conn_info * info)
{
  struct packet_record record;
  record.msg_type = MSG_TYPE_FREEZE_CONN;
  record.source = info->conn_id;
  record.destination = info->conn_id;

  size_t data_size = ((char *)&record.net - (char *)&record);

  queue_enqueue(global_queue, &record, data_size, 0);
}

void tcp_worker(struct tcp_conn_info * info, void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  if (data->msg_type == MSG_TYPE_DROP) {
    if ((info->freeze == 1) && (!atomic_load(&info->buffer_fill))) {
      info->freeze++;
      tcp_new_conn(info);
    }
    return;
  }

  if (data->msg_type == MSG_TYPE_CLOSE_CONN) {
    info->end_now = 1;
    sem_post(&info->write_sem);
    return;
  }

  if (info->freeze) {
    if ((data->msg_type != MSG_TYPE_NEW_CONN) || \
        (data->source != info->conn_id)) {
      if ((info->freeze == 1) && (!atomic_load(&info->buffer_fill))) {
        info->freeze++;
        tcp_new_conn(info);
      }
      return;
    }
    info->freeze = 0;
    return;
  }

  if (data->msg_type != MSG_TYPE_ENC_NET) {
    return;
  }

  sem_wait(&info->buffer_sem);
  int length = data_size - ((char *)&data->net.pkt_idx - (char *)data);
  int buffer_free = BUFFER_SIZE - atomic_load(&info->buffer_fill);
  if (buffer_free < length) {
    info->freeze = 1;
    sem_post(&info->write_sem);
    sem_post(&info->buffer_sem);
    send_freeze(info);
    return;
  }

  char * local_buffer = (char *)info->buffer;
  memcpy(&local_buffer[atomic_load(&info->buffer_fill)], &data->net.pkt_idx, \
      length);

  info->written_blocks += length >> 4;
  atomic_fetch_add(&info->buffer_fill, length);

  sem_post(&info->write_sem);
  sem_post(&info->buffer_sem);
}
