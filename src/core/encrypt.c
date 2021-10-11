/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "decrypt.h"
#include <string.h>
#include "global.h"
#include <twofish.h>
#include <openssl/aes.h>

#define _BSD_SOURCE
#ifndef SYS_ENDIAN
#include <endian.h>
#else
#include <sys/endian.h>
#endif

void encrypt_worker(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;

  if (data->msg_type != MSG_TYPE_RAW_NET)
    return;
  if (data->net.key.type < 0)
    return;

  data->msg_type = MSG_TYPE_ENC_NET;

  unsigned char * rawdata = (unsigned char *)&data->net.pkt_idx;

  uint16_t length = data_size - ((char *)&data->net.pkt_idx - (char *)data);
  uint64_t key[4];
  memcpy(key, data->net.key.key, sizeof(key));

  if (data->net.key.type == CIPHER_TYPE_TWOFISH_MIXED) {
    struct Twofish tf_key;

    for (uint16_t i = 0; i < length; i += 16, rawdata += 16) {
      twofish_init(&tf_key, 128, (unsigned char *)key);
      twofish_enc_block(&tf_key, rawdata, rawdata);

      key[0] ^= *(uint64_t *)rawdata;
      key[1] ^= *(((uint64_t *)rawdata) + 1);

      key[0] = be64toh(key[0]);
      key[1] = be64toh(key[1]);

      key[1]++;
      if (!key[1])
        key[0]++;

      key[0] = htobe64(key[0]);
      key[1] = htobe64(key[1]);
    }
  } else if (data->net.key.type == CIPHER_TYPE_TWOFISH_CTR) {
    struct Twofish tf_key;
    twofish_init(&tf_key, 128, (unsigned char *)&key[2]);
    uint64_t tmp[2];

    for (uint16_t i = 0; i < length; i += 16, rawdata += 16) {
      twofish_enc_block(&tf_key, (unsigned char *)key, (unsigned char *)tmp);

      *(uint64_t *)rawdata ^= tmp[0];
      *(((uint64_t *)rawdata) + 1) ^= tmp[1];

      key[0] = be64toh(key[0]);
      key[1] = be64toh(key[1]);

      key[1]++;
      if (!key[1])
        key[0]++;

      key[0] = htobe64(key[0]);
      key[1] = htobe64(key[1]);
    }
  } else if (data->net.key.type == CIPHER_TYPE_AES_MIXED) {
    AES_KEY aes_key;

    for (uint16_t i = 0; i < length; i += 16, rawdata += 16) {
      AES_set_encrypt_key((unsigned char *)key, 128, &aes_key);
      AES_encrypt(rawdata, rawdata, &aes_key);

      key[0] ^= *(uint64_t *)rawdata;
      key[1] ^= *(((uint64_t *)rawdata) + 1);

      key[0] = be64toh(key[0]);
      key[1] = be64toh(key[1]);

      key[1]++;
      if (!key[1])
        key[0]++;

      key[0] = htobe64(key[0]);
      key[1] = htobe64(key[1]);
    }
  } else if (data->net.key.type == CIPHER_TYPE_AES_CTR) {
    AES_KEY aes_key;
    AES_set_encrypt_key((unsigned char *)&key[2], 128, &aes_key);
    uint64_t tmp[2];

    for (uint16_t i = 0; i < length; i += 16, rawdata += 16) {
      AES_encrypt((unsigned char *)key, (unsigned char *)tmp, &aes_key);

      *(uint64_t *)rawdata ^= tmp[0];
      *(((uint64_t *)rawdata) + 1) ^= tmp[1];

      key[0] = be64toh(key[0]);
      key[1] = be64toh(key[1]);

      key[1]++;
      if (!key[1])
        key[0]++;

      key[0] = htobe64(key[0]);
      key[1] = htobe64(key[1]);
    }
  }
}
