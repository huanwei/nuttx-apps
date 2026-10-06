/****************************************************************************
 * testing/ortimg/ort_sha256.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] SHA-256（FIPS 180-4）—— 约定见 ort_sha256.h。
 *
 * 实现要点：
 *   · 大端序显式装配（不依赖宿主/目标字节序，双环境逐字一致的前提）
 *   · update 对满块直通（下载路径 4KB 大块不绕道缓冲）
 *   · final 用 (55-n)%64 的补零数 —— 55/56/63/64 边界由电池钉住
 ****************************************************************************/

#include <string.h>

#include "ort_sha256.h"

static const uint32_t g_k[64] =
{
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr(uint32_t x, unsigned n)
{
  return (x >> n) | (x << (32 - n));
}

static uint32_t load_be32(FAR const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static void store_be32(FAR uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static void sha256_block(FAR uint32_t h[8], FAR const uint8_t *p)
{
  uint32_t w[64];
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
  uint32_t e;
  uint32_t f;
  uint32_t g;
  uint32_t hh;
  uint32_t s0;
  uint32_t s1;
  uint32_t t1;
  uint32_t t2;
  int i;

  for (i = 0; i < 16; i++)
    {
      w[i] = load_be32(p + 4 * i);
    }

  for (i = 16; i < 64; i++)
    {
      s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

  a = h[0]; b = h[1]; c = h[2]; d = h[3];
  e = h[4]; f = h[5]; g = h[6]; hh = h[7];

  for (i = 0; i < 64; i++)
    {
      s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      t1 = hh + s1 + ((e & f) ^ (~e & g)) + g_k[i] + w[i];
      s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      t2 = s0 + ((a & b) ^ (a & c) ^ (b & c));
      hh = g; g = f; f = e; e = d + t1;
      d = c; c = b; b = a; a = t1 + t2;
    }

  h[0] += a; h[1] += b; h[2] += c; h[3] += d;
  h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void ort_sha256_init(FAR struct ort_sha256_s *c)
{
  c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85;
  c->h[2] = 0x3c6ef372; c->h[3] = 0xa54ff53a;
  c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c;
  c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
  c->nbits = 0;
  c->nbuf  = 0;
}

void ort_sha256_update(FAR struct ort_sha256_s *c, FAR const void *data,
                       size_t len)
{
  FAR const uint8_t *p = (FAR const uint8_t *)data;

  c->nbits += (uint64_t)len * 8;

  if (c->nbuf > 0)
    {
      size_t need = 64 - c->nbuf;

      if (len < need)
        {
          memcpy(c->buf + c->nbuf, p, len);
          c->nbuf += len;
          return;
        }

      memcpy(c->buf + c->nbuf, p, need);
      sha256_block(c->h, c->buf);
      c->nbuf = 0;
      p += need;
      len -= need;
    }

  while (len >= 64)
    {
      sha256_block(c->h, p);
      p += 64;
      len -= 64;
    }

  if (len > 0)
    {
      memcpy(c->buf, p, len);
      c->nbuf = len;
    }
}

void ort_sha256_final(FAR struct ort_sha256_s *c, FAR uint8_t out[32])
{
  static const uint8_t zeros[64];
  uint8_t lenb[8];
  uint8_t one = 0x80;
  uint64_t bits = c->nbits;
  size_t   padz = (55 - c->nbuf) % 64;
  int i;

  ort_sha256_update(c, &one, 1);
  if (padz > 0)
    {
      ort_sha256_update(c, zeros, padz);
    }

  for (i = 0; i < 8; i++)
    {
      lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
    }

  ort_sha256_update(c, lenb, 8);

  for (i = 0; i < 8; i++)
    {
      store_be32(out + 4 * i, c->h[i]);
    }
}

void ort_sha256_oneshot(FAR const void *data, size_t len,
                        FAR uint8_t out[32])
{
  struct ort_sha256_s c;

  ort_sha256_init(&c);
  ort_sha256_update(&c, data, len);
  ort_sha256_final(&c, out);
}

void ort_sha256_hex(FAR const uint8_t digest[32], FAR char out[65])
{
  static const char hexd[] = "0123456789abcdef";
  int i;

  for (i = 0; i < 32; i++)
    {
      out[2 * i]     = hexd[digest[i] >> 4];
      out[2 * i + 1] = hexd[digest[i] & 15];
    }

  out[64] = '\0';
}
