/****************************************************************************
 * testing/ortimg/ort_tar.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] 受限 tar（ustar）解析 —— OCI 层体解包用。
 *
 * 风格同 ort_json：**无动态分配自己不做 / 有界 / 明确不支持并精确报错**。
 * （§66：gzip 由 zlib 承担，它内部会 malloc 解压窗口——那是第三方库的
 * 事，本解析器自身仍零动态分配。）
 *
 * 支持：
 *   · 输入自动探测：**gzip（1f 8b）→ zlib inflate 流式解压**（含 CRC/
 *     ISIZE 校验，损坏/截断 → E_GZIP）；否则按未压缩 tar 直读
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
 *   · 单成员 > 64MB、条目数 > 4096 → E_LIMIT（防跑飞，同下载侧防线）
 *   · size/checksum 非八进制、头截断 → E_SYNTAX / E_BADSUM / E_SHORT
 *
 * 读源抽象（§66）：walk 不再自己 fseek —— 一切经 `struct ort_tar_src_s`
 * 的 read 推进（gzip 流不可 seek；未压缩文件也走同一路径，"数据区越
 * 文件尾"统一表现为短读 → E_SHORT）。sink 通过收到的 src 读成员数据，
 * walk 负责丢弃 sink 没读的余量。
 *
 * walk 结束条件：全零块（end marker）或**恰好块边界的 EOF**。
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
  ORT_TAR_E_GZIP,       /* gzip 数据损坏/截断/解压失败（含内存不足） */
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

/* 读源：read 返回读到的字节数；0 = 流末；<0 = 错误（如解压失败） */

struct ort_tar_src_s
{
  int (*read)(FAR void *arg, FAR void *buf, size_t len);
  FAR void *arg;
};

/* 回调：头已解析；成员数据经 src->read 读（读多少都行，walk 会丢弃
 * 余量并对齐）。返回非 0 = 中止（walk 返回 ORT_TAR_E_CB）。 */

typedef int (*ort_tar_sink_t)(FAR void *arg,
                              FAR const struct ort_tar_entry_s *e,
                              FAR struct ort_tar_src_s *src);

/* 文件入口（自动探测 gzip） */

int ort_tar_walk(FAR FILE *f, FAR ort_tar_sink_t sink, FAR void *arg,
                 FAR uint32_t *nentries);

/* 直接给定读源（测试/自定义流用） */

int ort_tar_walk_src(FAR struct ort_tar_src_s *src,
                     FAR ort_tar_sink_t sink, FAR void *arg,
                     FAR uint32_t *nentries);

FAR const char *ort_tar_strerror(int err);

#endif /* __APPS_TESTING_ORTIMG_ORT_TAR_H */
