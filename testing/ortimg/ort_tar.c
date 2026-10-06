/****************************************************************************
 * testing/ortimg/ort_tar.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] 受限 tar（ustar）解析 —— 约定见 ort_tar.h。
 *
 * 解析策略：逐头块读；头块起点由 walk 自己记（fseek 绝对定位对齐，
 * sink 读多读少都无所谓）—— 流式路径不依赖 sink 的"礼貌"。
 ****************************************************************************/

#include <string.h>
#include <stdlib.h>

#include "ort_tar.h"

#define TAR_BLOCK        512
#define TAR_NAME_OFF     0
#define TAR_NAME_LEN     100
#define TAR_MODE_OFF     100
#define TAR_MODE_LEN     8
#define TAR_SIZE_OFF     124
#define TAR_SIZE_LEN     12
#define TAR_CHKSUM_OFF   148
#define TAR_CHKSUM_LEN   8
#define TAR_TYPE_OFF     156
#define TAR_MAGIC_OFF    257
#define TAR_PREFIX_OFF   345
#define TAR_PREFIX_LEN   155

#define TAR_MAX_ENTRIES  4096
#define TAR_MAX_FILE     (64ull * 1024 * 1024)

FAR const char *ort_tar_strerror(int err)
{
  switch (err)
    {
      case ORT_TAR_OK:          return "OK";
      case ORT_TAR_E_SHORT:     return "SHORT";
      case ORT_TAR_E_BADMAGIC:  return "BADMAGIC";
      case ORT_TAR_E_BADSUM:    return "BADSUM";
      case ORT_TAR_E_PATH:      return "PATH";
      case ORT_TAR_E_TYPE:      return "TYPE";
      case ORT_TAR_E_SYNTAX:    return "SYNTAX";
      case ORT_TAR_E_GZIP:      return "GZIP（未支持，见头注）";
      case ORT_TAR_E_LIMIT:     return "LIMIT";
      case ORT_TAR_E_IO:        return "IO";
      case ORT_TAR_E_CB:        return "CB(中止)";
      default:                  return "?";
    }
}

/* 八进制字段解析：允许前导空格与结尾 NUL/空格；非八进制 -> E_SYNTAX；
 * 空字段当 0（ustar 的 uid/gid 常见全 NUL）。上限 TAR_MAX_FILE —— 对
 * size 就是要它的意思；对其它字段（mode/mtime）远够不着，无害。 */

static int tar_octal(FAR const uint8_t *p, size_t len, FAR uint64_t *out)
{
  uint64_t v = 0;
  size_t   i = 0;
  int      seen = 0;

  while (i < len && p[i] == ' ')
    {
      i++;
    }

  for (; i < len; i++)
    {
      if (p[i] == '\0' || p[i] == ' ')
        {
          break;
        }

      if (p[i] < '0' || p[i] > '7')
        {
          return ORT_TAR_E_SYNTAX;
        }

      v = (v << 3) | (uint64_t)(p[i] - '0');
      seen = 1;

      if (v > TAR_MAX_FILE)
        {
          return ORT_TAR_E_LIMIT;
        }
    }

  *out = seen ? v : 0;
  return ORT_TAR_OK;
}

static unsigned tar_checksum(FAR const uint8_t *h)
{
  unsigned sum = 0;
  int i;

  for (i = 0; i < TAR_BLOCK; i++)
    {
      sum += (i >= TAR_CHKSUM_OFF && i < TAR_CHKSUM_OFF + TAR_CHKSUM_LEN) ?
             (unsigned)' ' : (unsigned)h[i];
    }

  return sum;
}

/* 名字规范化 + 逃逸防护：跳空组件与 "."；任一 ".." 拒；前导 "/" 天然
 * 被"跳空组件"吞掉后成为普通相对路径 —— 不行！"/etc/x" 的逃逸意图
 * 必须拒而不是洗白：所以先看**原始**首字符。 */

static int tar_join_normalize(FAR const uint8_t *name, size_t nlen,
                              FAR const uint8_t *prefix, size_t plen,
                              FAR char *out, size_t outcap)
{
  size_t o = 0;
  int    segidx;

  if (nlen > 0 && name[0] == '/')
    {
      return ORT_TAR_E_PATH;
    }

  if (plen > 0 && prefix[0] == '/')
    {
      return ORT_TAR_E_PATH;            /* 逃逸的另一条路：prefix 带前导 / */
    }

  for (segidx = 0; segidx < 2; segidx++)
    {
      FAR const uint8_t *seg  = (segidx == 0) ? prefix : name;
      size_t              sgl  = (segidx == 0) ? plen : nlen;
      size_t              j    = 0;

      if (segidx == 0 && plen > 0 && prefix[0] == '\0')
        {
          continue;                     /* 无 prefix 字段 */
        }

      while (j < sgl)
        {
          size_t start;
          size_t clen;

          while (j < sgl && seg[j] == '/')
            {
              j++;
            }

          start = j;
          while (j < sgl && seg[j] != '/' && seg[j] != '\0')
            {
              j++;
            }

          clen = j - start;
          if (clen == 0)
            {
              break;                    /* 段尾 */
            }

          if (clen == 1 && seg[start] == '.')
            {
              continue;                 /* "." 组件：跳过 */
            }

          if (clen == 2 && seg[start] == '.' && seg[start + 1] == '.')
            {
              return ORT_TAR_E_PATH;    /* 逃逸 */
            }

          if (o != 0)
            {
              if (o + 1 >= outcap)
                {
                  return ORT_TAR_E_PATH;
                }

              out[o++] = '/';
            }

          if (o + clen >= outcap)
            {
              return ORT_TAR_E_PATH;
            }

          memcpy(out + o, seg + start, clen);
          o += clen;
        }
    }

  if (o == 0)
    {
      return ORT_TAR_E_PATH;            /* 规范化后为空 */
    }

  out[o] = '\0';
  return ORT_TAR_OK;
}

/* 原始 name 字段是否以 '/' 结尾（v7 老式目录写法；要在规范化前看） */

static int tar_raw_dir_slash(FAR const uint8_t *name, size_t nlen)
{
  size_t i = 0;

  while (i < nlen && name[i] != '\0')
    {
      i++;
    }

  return (i > 0 && name[i - 1] == '/');
}

int ort_tar_walk(FAR FILE *f, FAR ort_tar_sink_t sink, FAR void *arg,
                 FAR uint32_t *nentries)
{
  uint8_t  h[TAR_BLOCK];
  uint32_t n = 0;
  long     pos0;
  long     filelen;

  /* 文件总长先量好：数据区越过文件尾 = 截断（否则"声明 100 字节、
   * 实体只有一个头"会被上层的块边界 EOF 当干净结束放行） */

  pos0 = ftell(f);
  if (pos0 < 0 || fseek(f, 0, SEEK_END) != 0)
    {
      return ORT_TAR_E_IO;
    }

  filelen = ftell(f);
  if (filelen < 0 || fseek(f, pos0, SEEK_SET) != 0)
    {
      return ORT_TAR_E_IO;
    }

  for (;;)
    {
      size_t   got;
      size_t   i;
      int      allzero = 1;
      uint64_t size = 0;
      uint64_t tmp = 0;
      struct ort_tar_entry_s e;
      char     typeflag;
      int      raw_dir;
      int      ret;
      long     hdr_off;

      hdr_off = ftell(f);
      if (hdr_off < 0)
        {
          return ORT_TAR_E_IO;
        }

      got = fread(h, 1, TAR_BLOCK, f);
      if (got == 0)
        {
          break;                        /* 块边界 EOF：当结束（见头注） */
        }

      if (got < TAR_BLOCK)
        {
          return ORT_TAR_E_SHORT;
        }

      /* gzip 魔数：明确报"这是 gzip 不是 tar"，别让它掉进 checksum 里
       * 报个让人误解的 BADSUM */

      if (h[0] == 0x1f && h[1] == 0x8b)
        {
          return ORT_TAR_E_GZIP;
        }

      for (i = 0; i < TAR_BLOCK; i++)
        {
          if (h[i] != 0)
            {
              allzero = 0;
              break;
            }
        }

      if (allzero)
        {
          break;                        /* end marker */
        }

      /* magic：POSIX "ustar\0" 或 GNU "ustar " */

      if (memcmp(h + TAR_MAGIC_OFF, "ustar", 5) != 0)
        {
          return ORT_TAR_E_BADMAGIC;
        }

      ret = tar_octal(h + TAR_CHKSUM_OFF, TAR_CHKSUM_LEN, &tmp);
      if (ret != ORT_TAR_OK)
        {
          return ret;
        }

      if ((uint64_t)tar_checksum(h) != tmp)
        {
          return ORT_TAR_E_BADSUM;
        }

      ret = tar_octal(h + TAR_SIZE_OFF, TAR_SIZE_LEN, &size);
      if (ret != ORT_TAR_OK)
        {
          return ret;
        }

      typeflag = (char)h[TAR_TYPE_OFF];
      raw_dir  = tar_raw_dir_slash(h + TAR_NAME_OFF, TAR_NAME_LEN);

      memset(&e, 0, sizeof(e));
      ret = tar_join_normalize(h + TAR_NAME_OFF, TAR_NAME_LEN,
                               h + TAR_PREFIX_OFF, TAR_PREFIX_LEN,
                               e.name, sizeof(e.name));
      if (ret != ORT_TAR_OK)
        {
          return ret;
        }

      switch (typeflag)
        {
          case '0':
          case '\0':
            e.typeflag = raw_dir ? '5' : '0';   /* v7 老式目录 */
            break;

          case '5':
            e.typeflag = '5';
            break;

          case '1':
          case '2':
          case '3':
          case '4':
          case '6':
          case 'x':
          case 'g':
          case 'L':
          case 'K':

            /* 链接/设备/pax/GNU 扩展：都明确不收（见头注） */

            return ORT_TAR_E_TYPE;

          default:
            return ORT_TAR_E_TYPE;
        }

      e.size = (e.typeflag == '5') ? 0 : size;

      /* 数据区完整性（见函数头注） */

      if (hdr_off + TAR_BLOCK + (long)((size + 511) & ~511ull) > filelen)
        {
          return ORT_TAR_E_SHORT;
        }

      ret = tar_octal(h + TAR_MODE_OFF, TAR_MODE_LEN, &tmp);
      if (ret != ORT_TAR_OK)
        {
          return ret;                   /* mode 垃圾也精确报，不静默兜底 */
        }

      e.mode = (uint32_t)(tmp & 07777);

      if (++n > TAR_MAX_ENTRIES)
        {
          return ORT_TAR_E_LIMIT;
        }

      if (sink != NULL && sink(arg, &e, f) != 0)
        {
          return ORT_TAR_E_CB;
        }

      /* 对齐：下一头块起点 = 本头起点 + 512 + 数据块数×512（绝对定位，
       * sink 读了/没读/读多都无妨） */

      if (fseek(f, hdr_off + TAR_BLOCK + (long)((size + 511) & ~511ull),
                SEEK_SET) != 0)
        {
          return ORT_TAR_E_IO;
        }
    }

  if (nentries != NULL)
    {
      *nentries = n;
    }

  return ORT_TAR_OK;
}
