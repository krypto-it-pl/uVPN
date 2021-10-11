/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __GLOBAL_H__
#define __GLOBAL_H__

#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <tcpc.h>
#include <semaphore.h>
#include <queue.h>
#include <rsa.h>

typedef int16_t conn_id_t;
typedef struct
{
  uint64_t key[4];
  int type;
} encrypt_key_t;

extern volatile int end_now;

#define CIPHER_TYPE_TWOFISH_MIXED 0
#define CIPHER_TYPE_TWOFISH_CTR   1
#define CIPHER_TYPE_AES_MIXED     2
#define CIPHER_TYPE_AES_CTR       3
#define CIPHER_TYPE_NULL          4

#define CIPHER_KEY_SIZE_TWOFISH_MIXED 2
#define CIPHER_KEY_SIZE_TWOFISH_CTR   4
#define CIPHER_KEY_SIZE_AES_MIXED     2
#define CIPHER_KEY_SIZE_AES_CTR       4
#define CIPHER_KEY_SIZE_NULL          0

#ifndef MAX_CONNS
#define MAX_CONNECTIONS 512
#else
#define MAX_CONNECTIONS ((MAX_CONNS + 63) & ~0x3F)
#endif

#define TAP_CONN_ID 0

#define BUFFER_SIZE (153600)

#define MAX_CLIENT_NAME_LENGTH 64

#define MSG_TYPE_CLOSE_APP   0
#define MSG_TYPE_RAW_NET     1
#define MSG_TYPE_ENC_NET     2
#define MSG_TYPE_DROP        3
#define MSG_TYPE_NEW_CONN    4
#define MSG_TYPE_CLOSE_CONN  5
#define MSG_TYPE_FREEZE_CONN 6

#define MAX_MTU 1540

#define LOGGER_ERROR  0 
#define LOGGER_INFO   1
#define LOGGER_DEBUG  2

struct packet_record
{
  int16_t msg_type;
  conn_id_t source;
  conn_id_t destination;

  union {
    struct {
      encrypt_key_t encrypt_key;
    } conn;
    struct {
      encrypt_key_t key;
      uint32_t pkt_idx;
      uint32_t crc32;
      uint16_t length;
      uint16_t flags;
      uint16_t proto;
      unsigned char dst_mac[6];
      unsigned char src_mac[6];
      unsigned char data[MAX_MTU - 6 - 6 - 2 - 2];
    } __attribute__((packed)) net;
  };
};

struct tcp_conn_info
{
  conn_id_t conn_id;
  struct tcp_conn_desc_t tcp_conn;
  unsigned int auth;
  unsigned char buffer_1[BUFFER_SIZE];
  unsigned char buffer_2[BUFFER_SIZE];
  volatile unsigned char * buffer;
  atomic_uint buffer_fill;
  volatile unsigned int end_now;
  sem_t buffer_sem;
  sem_t write_sem;
  uint64_t written_blocks;
  uint64_t read_blocks;
  uint64_t enc_key[4], dec_key[4];
  volatile unsigned int freeze;
  void * io_read_thread, * io_write_thread;
  atomic_ullong last_read;
  atomic_ullong last_write;
  unsigned int timeout[2];
  unsigned int mss;
  char name[MAX_CLIENT_NAME_LENGTH];
  char ipstr[64];
  unsigned short port;
  int cipher;
};

struct tap_conn_info
{
  conn_id_t conn_id;
  int dev_sock;
  uint32_t bcast_counter;
  void * io_read_thread;
};

extern uint64_t conn_mask[(MAX_CONNECTIONS + 63) >> 6];
extern queue_t global_queue;
extern struct RSA * thiz_rsa;
extern sem_t config_sem;

int is_bcast(unsigned char * mac);
int cipher_mode_str_to_int(const char * cipher);
size_t get_key_size(int cipher);

#endif
