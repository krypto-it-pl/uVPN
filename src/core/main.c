/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "global.h"
#include "decrypt.h"
#include "checksum.h"
#include "l2_sw.h"
#include "counter.h"
#include "encrypt.h"
#include "tap.h"
#include "tcp.h"
#include "threads.h"
#include "config.h"

#include <queue.h>
#include <tap_int.h>
#include <tcpc.h>
#include <thpool.h>
#include <logger.h>
#include <random.h>
#include <dns.h>
#include <exec.h>

#define MAX_CRYPTO_WORKERS 32
#define MAX_CHECKSUM_WORKERS 16
#define DEFAULT_PORT 1193

struct thpool_data
{
  void * data;
  size_t data_size;

  void (*clean_up)(struct queue_desc_t volatile *, unsigned int);
  struct queue_desc_t volatile * cleanup_queue;
  unsigned int cleanup_task_id;

  atomic_int locked;
};

const unsigned short default_keepalive[2] = { 30, 45 };

volatile int end_now = 0;

queue_t global_queue;

struct RSA * thiz_rsa;

static const uint8_t bcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static const uint8_t ipv6mcast[2] = { 0x33, 0x33 };
static const uint8_t ipv4mcast[3] = { 0x01, 0x00, 0x5E };
static const uint8_t ieeemcast[3] = { 0x01, 0x80, 0xC2 };

uint64_t conn_mask[(MAX_CONNECTIONS + 63) >> 6] = { 0 };

struct thpool_t * decrypt_thpool;
struct thpool_t * encrypt_thpool;
struct thpool_t * checksum_thpool;

struct tap_conn_info tap_conn;
struct tcp_conn_info tcp_conn[MAX_CONNECTIONS - 1];

sem_t conns_sem;
sem_t config_sem;

static void decrypt_consumer(void * data, size_t data_size, \
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int), \
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);
static void checksum_consumer(void * data, size_t data_size, \
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int), \
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);
static void l2_sw_consumer(void * data, size_t data_size, \
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int), \
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);
static void counter_consumer(void * data, size_t data_size, \
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int), \
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);
static void encrypt_consumer(void * data, size_t data_size, \
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int), \
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);
static void conn_consumer(void * data, size_t data_size, \
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int), \
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id);

queue_worker_t queue_consumers[6] = {
  decrypt_consumer, checksum_consumer, l2_sw_consumer,
  counter_consumer, encrypt_consumer, conn_consumer
};

struct thpool_data decrypt_data[MAX_CRYPTO_WORKERS + 3];
struct thpool_data checksum_data[MAX_CHECKSUM_WORKERS + 3];
struct thpool_data encrypt_data[MAX_CRYPTO_WORKERS + 3];

int is_bcast(unsigned char * mac)
{
  if (memcmp(bcast, mac, sizeof(bcast)) == 0)
    return 1;
  if (memcmp(ipv6mcast, mac, sizeof(ipv6mcast)) == 0)
    return 1;
  if ((memcmp(ipv4mcast, mac, sizeof(ipv4mcast)) == 0) \
      && ((mac[3] & 0x80) == 0))
    return 1;
  if (memcmp(ieeemcast, mac, sizeof(ieeemcast)) == 0)
    return 1;
  return 0;
}

int cipher_mode_str_to_int(const char * cipher)
{
  if (!cipher)
    return CIPHER_TYPE_TWOFISH_MIXED;
  if (strcmp(cipher, "twofish:mixed") == 0)
    return CIPHER_TYPE_TWOFISH_MIXED;
  if (strcmp(cipher, "twofish") == 0)
    return CIPHER_TYPE_TWOFISH_MIXED;
  if (strcmp(cipher, "twofish:ctr") == 0)
    return CIPHER_TYPE_TWOFISH_CTR;
  if (strcmp(cipher, "aes:mixed") == 0)
    return CIPHER_TYPE_AES_MIXED;
  if (strcmp(cipher, "aes") == 0)
    return CIPHER_TYPE_AES_MIXED;
  if (strcmp(cipher, "aes:ctr") == 0)
    return CIPHER_TYPE_AES_CTR;
  if (strcmp(cipher, "null") == 0)
    return CIPHER_TYPE_NULL;
  return -1;
}

size_t get_key_size(int cipher)
{
  if (cipher == CIPHER_TYPE_TWOFISH_CTR)
    return CIPHER_KEY_SIZE_TWOFISH_CTR;
  return CIPHER_KEY_SIZE_TWOFISH_MIXED;
}

static void on_signal_term(int signum)
{
  end_now = 1;
}

static void on_signal_config_reload(int signum)
{
  sem_wait(&config_sem);

  if (config->servers_config) {
    if (parse_servers_file(config->servers_config, &config->static_servers,
      &config->static_servers_count)) {
      logger_printf(LOGGER_ERROR, "Reloaded ini file with error(s)");
    } else {
      logger_printf(LOGGER_ERROR, "Reloaded ini file without errors");
    }
  }

  for (size_t i = 0; i < config->static_servers_count; i++) {
    if (cipher_mode_str_to_int(config->static_servers[i].cipher) < 0) {
      logger_printf(LOGGER_ERROR, "Invalid cipher (%s) in %s", \
          config->static_servers[i].cipher, config->static_servers[i].name);
    }
  }

  sem_post(&config_sem);
}

static void on_signal_logs_reload(int signum)
{
  logger_reopen();
}

static void on_signal_clear_arp(int signum)
{
  struct packet_record record;
  memset(&record, 0, sizeof(record));

  record.msg_type = MSG_TYPE_CLEAR_ARP;

  size_t data_size = ((char *)&record.conn - (char *)&record);

  queue_enqueue(global_queue, &record, data_size, 0);
}

static void decrypt_init(void)
{
  for (size_t i = 0; i < sizeof(decrypt_data) / sizeof(decrypt_data[0]); i++) {
    atomic_store(&decrypt_data[i].locked, 0);
  }
}

static void decrypt_thread_executor(void * data_void)
{
  struct thpool_data * data = (struct thpool_data *)data_void;

  decrypt_worker(data->data, data->data_size);
  data->clean_up(data->cleanup_queue, data->cleanup_task_id);
  atomic_store(&data->locked, 0);
}

static void decrypt_consumer(void * data, size_t data_size, \
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int), \
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  static size_t idx = 0;

  while (!end_now) {
    int expected = 0;
    if (atomic_compare_exchange_strong(&decrypt_data[idx].locked, &expected, 1))
      break;
    idx = (idx + 1) % (sizeof(decrypt_data) / sizeof(decrypt_data[0]));
  }

  struct thpool_data * th_data = &decrypt_data[idx];
  th_data->data = data;
  th_data->data_size = data_size;
  th_data->clean_up = clean_up;
  th_data->cleanup_queue = cleanup_queue;
  th_data->cleanup_task_id = cleanup_task_id;

  thpool_push(decrypt_thpool, th_data);
}

static void checksum_init(void)
{
  for (size_t i = 0; i < sizeof(checksum_data) / sizeof(checksum_data[0]); \
      i++) {
    atomic_store(&checksum_data[i].locked, 0);
  }
}

static void checksum_thread_executor(void * data_void)
{
  struct thpool_data * data = (struct thpool_data *)data_void;

  checksum_worker(data->data, data->data_size);
  data->clean_up(data->cleanup_queue, data->cleanup_task_id);
  atomic_store(&data->locked, 0);
}

static void checksum_consumer(void * data, size_t data_size, \
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int), \
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  static size_t idx = 0;

  while (!end_now) {
    int expected = 0;
    if (atomic_compare_exchange_strong(&checksum_data[idx].locked, &expected, \
        1))
      break;
    idx = (idx + 1) % (sizeof(checksum_data) / sizeof(checksum_data[0]));
  }

  struct thpool_data * th_data = &checksum_data[idx];

  th_data->data = data;
  th_data->data_size = data_size;
  th_data->clean_up = clean_up;
  th_data->cleanup_queue = cleanup_queue;
  th_data->cleanup_task_id = cleanup_task_id;

  thpool_push(checksum_thpool, th_data);
}

static void l2_sw_consumer(void * data, size_t data_size, \
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int), \
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  l2_sw_worker(data, data_size);
  clean_up(cleanup_queue, cleanup_task_id);
}

static void counter_consumer(void * data, size_t data_size, \
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int), \
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  counter_worker(data, data_size);
  clean_up(cleanup_queue, cleanup_task_id);
}

static void encrypt_init(void)
{
  for (size_t i = 0; i < sizeof(encrypt_data) / sizeof(encrypt_data[0]); i++) {
    atomic_store(&encrypt_data[i].locked, 0);
  }
}

static void encrypt_thread_executor(void * data_void)
{
  struct thpool_data * data = (struct thpool_data *)data_void;

  encrypt_worker(data->data, data->data_size);
  data->clean_up(data->cleanup_queue, data->cleanup_task_id);
  atomic_store(&data->locked, 0);
}

static void encrypt_consumer(void * data, size_t data_size, \
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int), \
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  static size_t idx = 0;

  while (!end_now) {
    int expected = 0;
    if (atomic_compare_exchange_strong(&encrypt_data[idx].locked, &expected, 1))
      break;
    idx = (idx + 1) % (sizeof(encrypt_data) / sizeof(encrypt_data[0]));
  }

  struct thpool_data * th_data = &encrypt_data[idx];
  th_data->data = data;
  th_data->data_size = data_size;
  th_data->clean_up = clean_up;
  th_data->cleanup_queue = cleanup_queue;
  th_data->cleanup_task_id = cleanup_task_id;

  thpool_push(encrypt_thpool, th_data);
}

static void rem_tcp_conn(conn_id_t old_conn);

static void conn_consumer(void * data_void, size_t data_size, \
    void (*clean_up)(struct queue_desc_t volatile *, unsigned int), \
    struct queue_desc_t volatile * cleanup_queue, unsigned int cleanup_task_id)
{
  struct packet_record * data = (struct packet_record *)data_void;

  if ((data->msg_type == MSG_TYPE_RAW_NET) && \
      (data->destination == TAP_CONN_ID)) {
    tap_worker(&tap_conn, data, data_size);
    clean_up(cleanup_queue, cleanup_task_id);
    return;
  }

  if (data->destination == TAP_CONN_ID) {
    clean_up(cleanup_queue, cleanup_task_id);
    return;
  }

  if (data->destination < 1) {
    clean_up(cleanup_queue, cleanup_task_id);
    return;
  }

  int dest = data->destination - 1;
  sem_wait(&conns_sem);
  tcp_worker(&tcp_conn[dest], data, data_size);
  sem_post(&conns_sem);

  if (data->msg_type == MSG_TYPE_CLOSE_CONN)
    rem_tcp_conn(data->source);

  clean_up(cleanup_queue, cleanup_task_id);
}

static void add_tcp_conn(struct tcp_conn_desc_t new_conn, \
    const unsigned short keepalive[2], const char * name, unsigned int auth,
    const char * ipstr, unsigned short port, int cipher)
{
  for (int i = 0; i < MAX_CONNECTIONS - 1; i++) {
    sem_wait(&conns_sem);
    if (tcp_conn[i].conn_id == 0) {
      tcp_init(&tcp_conn[i], &new_conn, i + 1, keepalive, name, auth, ipstr, \
          port, cipher);
      conn_mask[(i + 1) >> 6] |= 1LLU << (i + 1);
      sem_post(&conns_sem);
      return;
    }
    sem_post(&conns_sem);
  }

  tcp_conn_close(&new_conn);
}

static void rem_tcp_conn(conn_id_t old_conn)
{
  if ((old_conn < 1) || (old_conn > MAX_CONNECTIONS))
    return;

  int i = old_conn - 1;
  sem_wait(&conns_sem);
  if (tcp_conn[i].conn_id != 0) {
    tcp_done(&tcp_conn[i]);
    tcp_conn[i].conn_id = 0;
    conn_mask[(i + 1) >> 6] &= ~(1LLU << (i + 1));
  }
  sem_post(&conns_sem);
}

static int is_connected(const char * name)
{
  sem_wait(&conns_sem);
  for (unsigned int i = 0; i < MAX_CONNECTIONS - 1; i++) {
    if (tcp_conn[i].conn_id) {
      if (strncmp(tcp_conn[i].name, name, sizeof(tcp_conn[i].name)) == 0) {
        sem_post(&conns_sem);
        return 1;
      }
    }
  }
  sem_post(&conns_sem);
  return 0;
}

static int iterate_over_dns(const char * address, unsigned short port, \
    void * void_data)
{
  struct static_servers_config_t * data = \
      (struct static_servers_config_t *)void_data;

  struct tcp_conn_desc_t next_conn;
  if (tcp_conn_connect(&next_conn, address, port) == TCP_CONN_STAT_OK) {
    logger_printf(LOGGER_INFO, "Connected to server %s (%s)", \
        data->name, address);

    add_tcp_conn(next_conn, data->keepalive, data->name, 1, \
        data->connect_addr, data->connect_port, \
        cipher_mode_str_to_int(data->cipher));

    data->last_reconnect_try = time(NULL);

    char buffer[128], buffer2[64], buffer3[64];;
    snprintf(buffer, sizeof(buffer) - 1, "SERVER_ADDR=%s:%hu", \
        data->connect_addr, data->connect_port);
    snprintf(buffer2, sizeof(buffer2) - 1, "NAME=%s", config->name);
    snprintf(buffer3, sizeof(buffer3) - 1, "SERVER_NAME=%s", data->name);

    exec_with_env(config->onConnect, buffer, buffer2, buffer3, NULL);

    return 1;
  }

  return 0;
}

static void reconnect_servers(void)
{
  if (!config->static_servers)
    return;

  time_t now = time(NULL);

  for (size_t i = 0; i < config->static_servers_count; i++) {
    if ((config->static_servers[i].auto_connect) && \
        (!is_connected(config->static_servers[i].name)) && \
        (strcmp(config->name, config->static_servers[i].name)) && \
        (now > config->static_servers[i].last_reconnect_try + \
        config->static_servers[i].try_reconnect_sec)) {
      int cipher = cipher_mode_str_to_int(config->static_servers[i].cipher);
      if (cipher < 0)
        continue;

      logger_printf(LOGGER_DEBUG, "Try to connect to %s", \
          config->static_servers[i].name);
 
      dns_iterate_by_hostname(config->static_servers[i].connect_addr, \
          config->static_servers[i].connect_port, iterate_over_dns, \
          &config->static_servers[i]);
      config->static_servers[i].last_reconnect_try = now;
    }
  }
}

int main(int argc, char * argv[])
{
  int r = config_load(argc - 1, argv + 1);
  if (r) {
    fprintf(stderr, "Configuration error!\n");
    return r;
  }
  if (config->crypto_workers > MAX_CRYPTO_WORKERS)
    config->crypto_workers = MAX_CRYPTO_WORKERS;
  if (config->checksum_workers > MAX_CHECKSUM_WORKERS)
    config->checksum_workers = MAX_CHECKSUM_WORKERS;

  if (!config->private_key) {
    fprintf(stderr, "Private key path not found!");
    return 1;
  }

  random_init();

  thiz_rsa = load_rsakey(config->private_key);
  if (!thiz_rsa) {
    fprintf(stderr, "Unable to load private key from file: %s!\n", \
        config->private_key);
    return 1;
  }

  if (config->log_file)
    logger_init(config->log_file, config->log_level);
  else
    logger_init("/dev/stderr", config->log_level);

  logger_printf(LOGGER_INFO, "Starting uVPN with 2x%u crypto workers and %u" \
      " checksum worker(s)", config->crypto_workers, config->checksum_workers);

  if (!config->forground) {
    logger_printf(LOGGER_INFO, "Daemonize uVPN - go background");
    daemon(1, 0);
  }

  if (config->pid_file) {
    FILE * file = fopen(config->pid_file, "w");
    fprintf(file, "%u\n", getpid());
    fclose(file);
  }

  decrypt_init();
  checksum_init();
  encrypt_init();

  sem_init(&conns_sem, 0, 1);
  sem_init(&config_sem, 0, 1);

  decrypt_thpool = thpool_create(config->crypto_workers, \
      decrypt_thread_executor);
  encrypt_thpool = thpool_create(config->crypto_workers, \
      encrypt_thread_executor);
  checksum_thpool = thpool_create(config->checksum_workers, \
      checksum_thread_executor);
  counter_init();
  l2_sw_init();

  queue_init(&global_queue, 12, 6, queue_consumers);

  signal(SIGTERM, &on_signal_term);
  signal(SIGINT, &on_signal_term);
  signal(SIGUSR1, &on_signal_config_reload);
  signal(SIGUSR2, &on_signal_clear_arp);
  signal(SIGHUP, &on_signal_logs_reload);
  conn_mask[0] = 1;

  logger_printf(LOGGER_INFO, "Creating tap interface (%s)", config->tap_name);

  int tapint = tap_create(config->tap_name);
  if (tapint < 0) {
    logger_printf(LOGGER_ERROR, "Uname to create tap interface (%s)", \
        config->tap_name);
    goto end;
  }

  char buffer[32], buffer2[64];
  snprintf(buffer, sizeof(buffer) - 1, "TAP=%s", config->tap_name);
  snprintf(buffer2, sizeof(buffer2) - 1, "NAME=%s", config->name);

  exec_with_env(config->onTapCreate, buffer, buffer2, NULL);

  on_signal_config_reload(0);

  sem_wait(&config_sem);

  logger_printf(LOGGER_INFO, "Loaded configuration for %zu servers", \
      config->static_servers_count);

  sem_post(&config_sem);

  tap_init(&tap_conn, tapint, 0);

  struct tcp_conn_desc_t conn;

  if (config->listen_addr && config->listen_port) {
    logger_printf(LOGGER_INFO, "Open TCP socket for listen at [%s]:%hu", \
        config->listen_addr, config->listen_port);

    if (tcp_conn_listen(&conn, config->listen_addr, config->listen_port) \
        != TCP_CONN_STAT_OK) {
      logger_printf(LOGGER_ERROR, "Unable to open TCP socket" \
          " for listen at [%s]:%hu", config->listen_addr, config->listen_port);
      goto end;
    }

    if (config->onTcpListen) {
      char buffer[128], buffer2[64];
      snprintf(buffer, sizeof(buffer) - 1, "LISTEN=%s:%hu", \
          config->listen_addr, config->listen_port);
      snprintf(buffer2, sizeof(buffer2) - 1, "NAME=%s", config->name);

      exec_with_env(config->onTcpListen, buffer, buffer2, NULL);
    }
  } else
    conn.sock = 0;

  while (!end_now) {
    int r = 0;

    while (!end_now) {
      sem_wait(&config_sem);
      reconnect_servers();
      sem_post(&config_sem);

      sem_wait(&conns_sem);
      for (unsigned int i = 0; i < MAX_CONNECTIONS - 1; i++) {
        if (tcp_conn[i].conn_id) {
          tcp_ping(&tcp_conn[i], 0);
        }
      }
      sem_post(&conns_sem);

      if (!conn.sock) {
        sleep(1);
        continue;
      }

      fd_set set;
      FD_ZERO(&set);
      FD_SET(conn.sock, &set);
      struct timeval timeout;
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
      r = select(conn.sock + 1, &set, NULL, NULL, &timeout);

      if (r != 0)
        break;
    }

    if (r == 1) {
      char ipstr[64];
      struct tcp_conn_desc_t new_conn;

      unsigned short port = 0;
      if (tcp_conn_accept(&conn, ipstr, &port, &new_conn) == TCP_CONN_STAT_OK) {
        logger_printf(LOGGER_INFO, "Accept new TCP connection" \
            " from listen at [%s]:%hu", ipstr, port);
        add_tcp_conn(new_conn, default_keepalive, "", 0, ipstr, port, -1);
      }
    }
  }

  tcp_conn_close(&conn);

end:;
  logger_printf(LOGGER_INFO, "Start closing uVPN");

  for (unsigned int i = 0; i < MAX_CONNECTIONS - 1; i++)
    rem_tcp_conn(i + 1);

  sleep(2);

  queue_close(global_queue);
  counter_done();
  l2_sw_done();

  thpool_dispose(decrypt_thpool);
  thpool_dispose(encrypt_thpool);
  thpool_dispose(checksum_thpool);

  sem_destroy(&conns_sem);
  sem_destroy(&config_sem);

  if (config->pid_file)
    unlink(config->pid_file);

  config_done();
  rsa_done(thiz_rsa);
  logger_close();
  random_done();

  return 0;
}
