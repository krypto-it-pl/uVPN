/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz */

#ifndef TWOFISH_H
#define TWOFISH_H

#include <stddef.h>
#include <stdint.h>

struct Twofish
{
  unsigned int keySize;
  uint32_t (*f32)(uint32_t in, uint32_t * key, size_t mult);
  uint32_t key[8];
  uint32_t sbox_key[4];
  uint32_t sub_key[40];
};

int twofish_init(struct Twofish * cipher, unsigned int key_size, \
    const unsigned char * key);

void twofish_enc_block(struct Twofish * cipher, const unsigned char *in, \
    unsigned char *out);
void twofish_dec_block(struct Twofish * cipher, const unsigned char *in, \
    unsigned char *out);

#endif
