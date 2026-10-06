/****************************************************************************
 * testing/ortimg/ort_tar.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] 受限 tar（ustar/POSIX）解析 —— OCI 层体解包用。
 *
 * 风格同 ort_json：**无动态分配 / 有界 / 明确不支持并精确报错**。
 *
 * 支持：
 *   · ustar 头（POSIX magic "ustar\0"；GNU "ustar " 也收），checksum 必验
 *   · 成员类型：普通文件（'0'/'\0'，含"名字以 / 结尾当目录"的老式写法）、
 *     目录（'5'）。prefix 字段（155B）与 name（100B）拼接
 *   · 名字规范化：跳过 "." 与空组件（"a/./b"→"a/b"、"./x"→"x"）；其余原样
 *
 * 明确拒绝（各给专属错误码，不混成一句"格式错"）：
 *   · 路径逃逸：绝对路径（前导 /）、任一 ".." 组件 → E_PATH
 *       （解包器最经典的安全事故面；这里在**解析层**就断掉）
 *   · symlink('2')/hardlink('1')/设备/FIFO → E_TYPE（逃逸与权限语义
 *     要成对设计，未做前不放行）
 *   · pax 扩展头（'x'/'g'）→ E_TYPE（长名/扩展属性当普通项跳过会**静默
 *     丢语义**，宁可不收）；GNU longname('L'/'K') 同
 *   · gzip 魔数（0x1f 0x8b）→ E_GZIP（真 Hub 层几乎都是 tar+gzip；
 *     解压需要 zlib，排下一步——素材暂用未压缩 tar，mediaType 合法）
 *   · 单成员 > 64MB、条目数 > 4096 → E_LIMIT（防跑飞，同下载侧防线）
 *   · size/checksum 非八进制、头截断 → E_SYNTAX / E_BADSUM / E_SHORT
 *
 * walk 结束条件：全零块（end marker）或**恰好块边界的 EOF**（流式 tar
 * 没有 trailer 时也收——如实注记，不当"支持"）。
 ****************************************************************************/

#ifndef __APPS_TESTING_ORTIMG_ORT_TAR_H
#define __APPS_TESTING_ORTIMG_ORT_TAR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifndef FAR
#  define FAR
#endif

enum ort_tar_err_e
{
  ORT_TAR_OK = 0,
  ORT_TAR_E_SHORT,      /* 头/数据截断 */
  ORT_TAR_E_BADMAGIC,
  ORT_TAR_E_BADSUM,
  ORT_TAR_E_PATH,       /* 绝对路径 / ".." / 名字超长 */
  ORT_TAR_E_TYPE,       /* 未支持的成员类型（含 pax/GNU 扩展头） */
  ORT_TAR_E_SYNTAX,     /* 数字字段非八进制等 */
  ORT_TAR_E_GZIP,       /* 是 gzip，不是 tar */
  ORT_TAR_E_LIMIT,      /* 超单成员尺寸/条目数上限 */
  ORT_TAR_E_IO,
  ORT_TAR_E_CB          /* sink 主动中止（错误语义由 sink 定） */
};

struct ort_tar_entry_s
{
  char     name[256];   /* 规范化后的相对路径（无前导 /，无 "."/"..") */
  uint64_t size;
  uint32_t mode;        /* 八进制 mode 解析结果（低 12 位） */
  char     typeflag;    /* '0'=文件（含 '\0'），'5'=目录 */
};

/* 回调：头已解析、文件游标停在成员数据开头。回调可以读 e->size 字节；
 * 读多少都行，walk 之后会把游标对齐到下一成员。返回非 0 = 中止
 * （walk 返回 ORT_TAR_E_CB）。 */

typedef int (*ort_tar_sink_t)(FAR void *arg,
                              FAR const struct ort_tar_entry_s *e,
                              FAR FILE *f);

int ort_tar_walk(FAR FILE *f, FAR ort_tar_sink_t sink, FAR void *arg,
                 FAR uint32_t *nentries);

FAR const char *ort_tar_strerror(int err);

#endif /* __APPS_TESTING_ORTIMG_ORT_TAR_H */
