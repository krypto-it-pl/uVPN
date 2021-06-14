/* Copyright (c) 2021 Krypto-IT Jakub Juszczakiewicz */

#include "twofish.h"

#include <string.h>
#include <inttypes.h>

#define _BSD_SOURCE
#ifndef SYS_ENDIAN
#include <endian.h>
#else
#include <sys/endian.h>
#endif

#define MINIMUM(a,b) (((a) < (b)) ? (a) : (b))

#define ROUND_COUNT (16)

#define SUBKEYS_COUNT (40)

#define RS_GF_FDBK 0x14D
#define RS_rem(x) \
        { unsigned char b = (unsigned char) (x >> 24); \
          unsigned int g2 = ((b << 1) ^ ((b >> 7) * RS_GF_FDBK)) & 0xFF; \
          unsigned int g3 = ((b >> 1) & 0x7F) ^ ((b & 1) * (RS_GF_FDBK >> 1)) ^ g2; \
          x = (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b; \
        }

#define MDS_GF_FDBK 0x169
#define LFSR1(x) (((x) >> 1) ^ (((x) & 0x01) * (MDS_GF_FDBK >> 1)))
#define LFSR2(x) (((x) >> 2) ^ ((((x) & 0x02) >> 1) * (MDS_GF_FDBK >> 1)) \
                              ^ (((x) & 0x01) * (MDS_GF_FDBK >> 2)))

#define Mx_1(x) ((uint32_t)(x))
#define Mx_X(x) ((uint32_t)((x) ^            LFSR2(x)))
#define Mx_Y(x) ((uint32_t)((x) ^ LFSR1(x) ^ LFSR2(x)))

#define M00 Mul_1
#define M01 Mul_Y
#define M02 Mul_X
#define M03 Mul_X
#define M10 Mul_X
#define M11 Mul_Y
#define M12 Mul_Y
#define M13 Mul_1

#define M20 Mul_Y
#define M21 Mul_X
#define M22 Mul_1
#define M23 Mul_Y

#define M30 Mul_Y
#define M31 Mul_1
#define M32 Mul_Y
#define M33 Mul_X

#define Mul_1 Mx_1
#define Mul_X Mx_X
#define Mul_Y Mx_Y

#define SK_STEP 0x02020202u
#define SK_BUMP 0x01010101u
#define SK_ROTL 9

#define ROL(x,n) (((x) << ((n) & 0x1F)) | ((x) >> (32-((n) & 0x1F))))
#define ROR(x,n) (((x) >> ((n) & 0x1F)) | ((x) << (32-((n) & 0x1F))))

uint8_t p8x8[512] =
{
  0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
  0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
  0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
  0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
  0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
  0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
  0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
  0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
  0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
  0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
  0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
  0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
  0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
  0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
  0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
  0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
  0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2,
  0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
  0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
  0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
  0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
  0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
  0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A,
  0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
  0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
  0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
  0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
  0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
  0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8,
  0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
  0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
  0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0,
  0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,

  0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
  0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
  0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
  0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D,
  0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
  0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
  0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
  0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
  0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
  0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
  0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
  0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
  0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
  0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
  0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
  0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3,
  0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
  0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
  0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
  0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
  0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
  0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19,
  0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
  0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
  0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
  0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
  0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
  0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB,
  0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
  0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
  0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
};

inline static uint32_t f32_ret(uint8_t *tab)
{
  return ((M00(tab[0]) ^ M01(tab[1]) ^ M02(tab[2]) ^ M03(tab[3])))
       ^ ((M10(tab[0]) ^ M11(tab[1]) ^ M12(tab[2]) ^ M13(tab[3])) <<  8)
       ^ ((M20(tab[0]) ^ M21(tab[1]) ^ M22(tab[2]) ^ M23(tab[3])) << 16)
       ^ ((M30(tab[0]) ^ M31(tab[1]) ^ M32(tab[2]) ^ M33(tab[3])) << 24);
}

static uint32_t f32_128(uint32_t in, uint32_t * key, size_t mult)
{
  uint8_t tab[4] = { in, in >> 8, in >> 16, in >> 24 };

  tab[0] = p8x8[256 + (p8x8[      p8x8[      tab[0]] ^ (key[mult] & 255)] ^ (key[0] & 255))];
  tab[1] = p8x8[      (p8x8[      p8x8[256 + tab[1]] ^ ((key[mult] >> 8) & 255)] ^ ((key[0] >> 8) & 255))];
  tab[2] = p8x8[256 + (p8x8[256 + (p8x8[      tab[2]] ^ ((key[mult] >> 16) & 255))] ^ ((key[0] >> 16) & 255))];
  tab[3] = p8x8[      (p8x8[256 + (p8x8[256 + tab[3]] ^ ((key[mult] >> 24) & 255))] ^ ((key[0] >> 24) & 255))];

  return f32_ret(tab);
}

static uint32_t f32_192(uint32_t in, uint32_t * key, size_t mult)
{
  uint8_t tab[4] = { in, in >> 8, in >> 16, in >> 24 };

  tab[0] = p8x8[256 + tab[0]] ^ (key[mult+mult] & 255);
  tab[1] = p8x8[256 + tab[1]] ^ ((key[mult+mult] >> 8) & 255);
  tab[2] = p8x8[      tab[2]] ^ ((key[mult+mult] >> 16) & 255);
  tab[3] = p8x8[      tab[3]] ^ ((key[mult+mult] >> 24));

  tab[0] = p8x8[256 + (p8x8[      p8x8[      tab[0]] ^ (key[mult] & 255)] ^ (key[0] & 255))];
  tab[1] = p8x8[      (p8x8[      p8x8[256 + tab[1]] ^ ((key[mult] >> 8) & 255)] ^ ((key[0] >> 8) & 255))];
  tab[2] = p8x8[256 + (p8x8[256 + (p8x8[      tab[2]] ^ ((key[mult] >> 16) & 255))] ^ ((key[0] >> 16) & 255))];
  tab[3] = p8x8[      (p8x8[256 + (p8x8[256 + tab[3]] ^ ((key[mult] >> 24)))] ^ ((key[0] >> 24)))];

  return f32_ret(tab);
}

static uint32_t f32_256(uint32_t in, uint32_t * key, size_t mult)
{
  uint8_t tab[4] = { in, in >> 8, in >> 16, in >> 24 };

  tab[0] = p8x8[256 + tab[0]] ^ (key[mult*3] & 255);
  tab[1] = p8x8[      tab[1]] ^ ((key[mult*3] >> 8) & 255);
  tab[2] = p8x8[      tab[2]] ^ ((key[mult*3] >> 16) & 255);
  tab[3] = p8x8[256 + tab[3]] ^ ((key[mult*3] >> 24));

  tab[0] = p8x8[256 + tab[0]] ^ (key[mult+mult] & 255);
  tab[1] = p8x8[256 + tab[1]] ^ ((key[mult+mult] >> 8) & 255);
  tab[2] = p8x8[      tab[2]] ^ ((key[mult+mult] >> 16) & 255);
  tab[3] = p8x8[      tab[3]] ^ ((key[mult+mult] >> 24));

  tab[0] = p8x8[256 + (p8x8[      p8x8[      tab[0]] ^ (key[mult] & 255)] ^ (key[0] & 255))];
  tab[1] = p8x8[      (p8x8[      p8x8[256 + tab[1]] ^ ((key[mult] >> 8) & 255)] ^ ((key[0] >> 8) & 255))];
  tab[2] = p8x8[256 + (p8x8[256 + (p8x8[      tab[2]] ^ ((key[mult] >> 16) & 255))] ^ ((key[0] >> 16) & 255))];
  tab[3] = p8x8[      (p8x8[256 + (p8x8[256 + tab[3]] ^ ((key[mult] >> 24)))] ^ ((key[0] >> 24)))];

  return f32_ret(tab);
}

int twofish_int_init(struct Twofish *thiz, unsigned int key_size, const unsigned char *key_bytes)
{
  if (!thiz)
  {
    return 0;
  }

  unsigned int copy_ints;
  unsigned int i;
  uint32_t (*f32)(uint32_t in, uint32_t * key, size_t mult);

  switch (key_size)
  {
    case 128:
      copy_ints = 4;
      f32 = f32_128;
      break;
    case 192:
      copy_ints = 6;
      f32 = f32_192;
      break;
    case 256:
      copy_ints = 8;
      f32 = f32_256;
      break;
    default:
      return 0;
  }

  thiz->f32 = f32;
  thiz->keySize = key_size;

  for (i = 0; i < copy_ints; i++)
  {
    thiz->key[i] = key_bytes[i << 2]
                 | (key_bytes[(i << 2) + 1] << 8)
                 | (key_bytes[(i << 2) + 2] << 16)
                 | (key_bytes[(i << 2) + 3] << 24);
  }
  for (i = 0; i < copy_ints; i += 2)
  {
    uint32_t r = thiz->key[i];
    RS_rem(r);
    RS_rem(r);
    RS_rem(r);
    RS_rem(r);
    r ^= thiz->key[i+1];

    RS_rem(r);
    RS_rem(r);
    RS_rem(r);
    RS_rem(r);
    thiz->sbox_key[i >> 1] = r;
  }
  for (i = 0; i < SUBKEYS_COUNT >> 1; i++)
  {
    uint32_t a = f32(i * SK_STEP, thiz->key, 2);
    uint32_t b = f32(i * SK_STEP + SK_BUMP, thiz->key + 1, 2);
    b = ROL(b, 8);
    thiz->sub_key[i << 1] = a + b;
    thiz->sub_key[(i << 1) + 1] = ROL(a + (b << 1), SK_ROTL);
  }

  return 1;
}

int twofish_init(struct Twofish * thiz, unsigned int key_size, const unsigned char *key)
{
  if (!twofish_int_init(thiz, key_size, key))
  {
    return 1;
  }
  return 0;
}


inline static void enc_round(struct Twofish *thiz, uint32_t *block, unsigned int r)
{
  uint32_t t0 = thiz->f32(block[0], thiz->sbox_key, 1);
  uint32_t t1 = thiz->f32(ROL(block[1], 8), thiz->sbox_key, 1);

  block[3] = ROL(block[3], 1);
  block[2] ^= t0 + t1 + thiz->sub_key[8 + (r << 1)];
  block[3] ^= t0 + (t1 << 1) + thiz->sub_key[9 + (r << 1)];
  block[2] = ROR(block[2], 1);
}

void twofish_enc_block(struct Twofish *thiz, const unsigned char *in, unsigned char *out)
{
  uint32_t block[4];
  unsigned int i;

  block[0] = ((uint32_t)in[ 0] | ((uint32_t)in[ 1] << 8)
           | ((uint32_t)in[ 2] << 16) | ((uint32_t)in[ 3] << 24)) ^ thiz->sub_key[0];
  block[1] = ((uint32_t)in[ 4] | ((uint32_t)in[ 5] << 8)
           | ((uint32_t)in[ 6] << 16) | ((uint32_t)in[ 7] << 24)) ^ thiz->sub_key[1];
  block[2] = ((uint32_t)in[ 8] | ((uint32_t)in[ 9] << 8)
           | ((uint32_t)in[10] << 16) | ((uint32_t)in[11] << 24)) ^ thiz->sub_key[2];
  block[3] = ((uint32_t)in[12] | ((uint32_t)in[13] << 8)
           | ((uint32_t)in[14] << 16) | ((uint32_t)in[15] << 24)) ^ thiz->sub_key[3];

  for (i = 0; i < 15; i++)
  {
    enc_round(thiz, block, i);

    uint32_t tmp = block[0];
    block[0] = block[2];
    block[2] = tmp;

    tmp = block[1];
    block[1] = block[3];
    block[3] = tmp;
  }
  enc_round(thiz, block, 15);

  block[0] ^= thiz->sub_key[4];
  block[1] ^= thiz->sub_key[5];
  block[2] ^= thiz->sub_key[6];
  block[3] ^= thiz->sub_key[7];

  out[ 0] = (uint8_t)block[0];
  out[ 1] = (uint8_t)(block[0] >> 8);
  out[ 2] = (uint8_t)(block[0] >> 16);
  out[ 3] = (uint8_t)(block[0] >> 24);

  out[ 4] = (uint8_t)block[1];
  out[ 5] = (uint8_t)(block[1] >> 8);
  out[ 6] = (uint8_t)(block[1] >> 16);
  out[ 7] = (uint8_t)(block[1] >> 24);

  out[ 8] = (uint8_t)block[2];
  out[ 9] = (uint8_t)(block[2] >> 8);
  out[10] = (uint8_t)(block[2] >> 16);
  out[11] = (uint8_t)(block[2] >> 24);

  out[12] = (uint8_t)block[3];
  out[13] = (uint8_t)(block[3] >> 8);
  out[14] = (uint8_t)(block[3] >> 16);
  out[15] = (uint8_t)(block[3] >> 24);
}

inline static void dec_round(struct Twofish *thiz, uint32_t *block, unsigned int r)
{
  uint32_t t0 = thiz->f32(block[0], thiz->sbox_key, 1);
  uint32_t t1 = thiz->f32(ROL(block[1], 8), thiz->sbox_key, 1);

  block[2] = ROL(block[2], 1);
  block[2] ^= t0 + t1 + thiz->sub_key[8 + (r << 1)];
  block[3] ^= t0 + (t1 << 1) + thiz->sub_key[9 + (r << 1)];
  block[3] = ROR(block[3], 1);
}

void twofish_dec_block(struct Twofish *thiz, const unsigned char *in, unsigned char *out)
{
  uint32_t block[4];
  unsigned int i;

  block[0] = ((uint32_t)in[ 0] | ((uint32_t)in[ 1] << 8)
           | ((uint32_t)in[ 2] << 16) | ((uint32_t)in[ 3] << 24)) ^ thiz->sub_key[4];
  block[1] = ((uint32_t)in[ 4] | ((uint32_t)in[ 5] << 8)
           | ((uint32_t)in[ 6] << 16) | ((uint32_t)in[ 7] << 24)) ^ thiz->sub_key[5];
  block[2] = ((uint32_t)in[ 8] | ((uint32_t)in[ 9] << 8)
           | ((uint32_t)in[10] << 16) | ((uint32_t)in[11] << 24)) ^ thiz->sub_key[6];
  block[3] = ((uint32_t)in[12] | ((uint32_t)in[13] << 8)
           | ((uint32_t)in[14] << 16) | ((uint32_t)in[15] << 24)) ^ thiz->sub_key[7];

  for (i = 15; i > 0; i--)
  {
    dec_round(thiz, block, i);

    uint32_t tmp = block[0];
    block[0] = block[2];
    block[2] = tmp;

    tmp = block[1];
    block[1] = block[3];
    block[3] = tmp;
  }
  dec_round(thiz, block, 0);

  block[0] ^= thiz->sub_key[0];
  block[1] ^= thiz->sub_key[1];
  block[2] ^= thiz->sub_key[2];
  block[3] ^= thiz->sub_key[3];

  out[ 0] = (uint8_t)block[0];
  out[ 1] = (uint8_t)(block[0] >> 8);
  out[ 2] = (uint8_t)(block[0] >> 16);
  out[ 3] = (uint8_t)(block[0] >> 24);

  out[ 4] = (uint8_t)block[1];
  out[ 5] = (uint8_t)(block[1] >> 8);
  out[ 6] = (uint8_t)(block[1] >> 16);
  out[ 7] = (uint8_t)(block[1] >> 24);

  out[ 8] = (uint8_t)block[2];
  out[ 9] = (uint8_t)(block[2] >> 8);
  out[10] = (uint8_t)(block[2] >> 16);
  out[11] = (uint8_t)(block[2] >> 24);

  out[12] = (uint8_t)block[3];
  out[13] = (uint8_t)(block[3] >> 8);
  out[14] = (uint8_t)(block[3] >> 16);
  out[15] = (uint8_t)(block[3] >> 24);
}
