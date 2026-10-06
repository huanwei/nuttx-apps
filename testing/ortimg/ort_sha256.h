/****************************************************************************
 * testing/ortimg/ort_sha256.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] SHA-256（FIPS 180-4）流式实现 —— blob 内容寻址校验用。
 *
 * 为什么自持一份而不是用现成：
 *   · 内核树 crypto/sha2.c 存在于 NuttX，但 ORT-A 是 BUILD_KERNEL 构建，
 *     app 侧够不着（且它编进内核镜像，用户态无接口）；
 *   · 双环境电池（宿主 gcc / 目标机 qemu）要求**同一份源码**两边跑，
 *     自持最省事；
 *   · 正确性判据 = 电池里的 KAT（含 NIST 官方向量 1M×'a'），不是"能编过"。
 *
 * 接口刻意最小：init/update/final 流式（下载边收边算）+ oneshot + hex。
 * 无动态分配 —— 结构体由调用方持有（栈上 ~112B，或与其它大件一起静态）。
 ****************************************************************************/

#ifndef __APPS_TESTING_ORTIMG_ORT_SHA256_H
#define __APPS_TESTING_ORTIMG_ORT_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifndef FAR
#  define FAR
#endif

struct ort_sha256_s
{
  uint32_t h[8];        /* 中间状态 */
  uint64_t nbits;       /* 已喂入的总位数 */
  uint8_t  buf[64];     /* 未满一块的尾巴 */
  size_t   nbuf;        /* buf 内有效字节数（0..63） */
};

void ort_sha256_init(FAR struct ort_sha256_s *c);
void ort_sha256_update(FAR struct ort_sha256_s *c, FAR const void *data,
                       size_t len);
void ort_sha256_final(FAR struct ort_sha256_s *c, FAR uint8_t out[32]);

/* 一次性与十六进制便捷封装 */

void ort_sha256_oneshot(FAR const void *data, size_t len,
                        FAR uint8_t out[32]);
void ort_sha256_hex(FAR const uint8_t digest[32], FAR char out[65]);

#endif /* __APPS_TESTING_ORTIMG_ORT_SHA256_H */
