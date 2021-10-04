/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "decrypt.h"
#include <string.h>
#include "global.h"
#include <twofish.h>

#define _BSD_SOURCE
#ifndef SYS_ENDIAN
#include <endian.h>
#else
#include <sys/endian.h>
#endif

void decrypt_worker(void * void_data, size_t data_size)
{
  struct packet_record * data = (struct packet_record *)void_data;
  if (data->msg_type != MSG_TYPE_ENC_NET)
    return;

  data->msg_type = MSG_TYPE_RAW_NET;

  uint64_t key[4];
  memcpy(key, data->net.key.key, sizeof(key));
  memset(data->net.key.key, 0, sizeof(data->net.key.key));

  unsigned char * encdata = (unsigned char *)&data->net.pkt_idx;
  uint16_t length = data_size - ((char *)&data->net.pkt_idx - (char *)data);

  if (data->net.key.type == CIPHER_TYPE_TWOFISH_MIXED) {
    struct Twofish tf_key;

    for (uint16_t i = 0; i < length; i += 16, encdata += 16) {
      twofish_init(&tf_key, 128, (unsigned char *)key);

      key[0] ^= *(uint64_t *)encdata;
      key[1] ^= *(((uint64_t *)encdata) + 1);

      key[0] = be64toh(key[0]);
      key[1] = be64toh(key[1]);

      key[1]++;
      if (!key[1])
        key[0]++;

      key[0] = htobe64(key[0]);
      key[1] = htobe64(key[1]);

      twofish_dec_block(&tf_key, encdata, encdata);
    }
  } else {
    struct Twofish tf_key;
    twofish_init(&tf_key, 128, (unsigned char *)&key[2]);
    uint64_t tmp[2];

    for (uint16_t i = 0; i < length; i += 16, encdata += 16) {
      twofish_enc_block(&tf_key, (unsigned char *)key, (unsigned char *)tmp);

      *(uint64_t *)encdata ^= tmp[0];
      *(((uint64_t *)encdata) + 1) ^= tmp[1];

      key[0] = be64toh(key[0]);
      key[1] = be64toh(key[1]);

      key[1]++;
      if (!key[1])
        key[0]++;

      key[0] = htobe64(key[0]);
      key[1] = htobe64(key[1]);
    }
  }

  data->net.key.type = -1;
}
