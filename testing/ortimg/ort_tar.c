/****************************************************************************
 * testing/ortimg/ort_tar.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] 受限 tar（ustar）解析 + gzip 流式解压 —— 约定见 ort_tar.h。
 *
 * §66 起：输入经**读源**推进（不再 fseek）——
 *   · 未压缩：plain src（fread），文件头部 2 字节用于 gzip 探测后回卷；
 *   · gzip（1f 8b）：zlib inflate（windowBits=15+16，含 CRC/ISIZE 校验），
 *     流式、不可回卷 —— 成员对齐靠"读弃余量"。
 * 截断统一表现为短读：头短读 → E_SHORT；数据区越尾 → E_SHORT；
 * gzip 流截断/损坏 → E_GZIP。
 ****************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <zlib.h>

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
#define TAR_LINK_OFF     157
#define TAR_LINK_LEN     100
#define TAR_MAGIC_OFF    257
#define TAR_PREFIX_OFF   345
#define TAR_PREFIX_LEN   155

#define TAR_MAX_ENTRIES  4096
#define TAR_MAX_FILE     (64ull * 1024 * 1024)

/* 读源约定的负值：-1 通用 IO，-2 gzip 解压失败（walk 分别映射） */

#define TAR_RD_IO        (-1)
#define TAR_RD_GZ        (-2)

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
      case ORT_TAR_E_GZIP:      return "GZIP（解压/校验失败）";
      case ORT_TAR_E_LIMIT:     return "LIMIT";
      case ORT_TAR_E_IO:        return "IO";
      case ORT_TAR_E_PAX:       return "PAX（扩展头畸形）";
      case ORT_TAR_E_CB:        return "CB(中止)";
      default:                  return "?";
    }
}

/* 本文件宿主电池与目标机**共用**（host/hosttest.c 直编）⇒ 不能用
 * NuttX libc 的 strlcpy（glibc 没有，链接期才炸）。语义同 strlcpy。 */

static void tar_strlcpy(FAR char *dst, FAR const char *src, size_t n)
{
  size_t l = strlen(src);

  if (l >= n)
    {
      l = n - 1;
    }

  memcpy(dst, src, l);
  dst[l] = '\0';
}

/* ── 未压缩文件源 ─────────────────────────────────────────────────── */

struct plain_src_s
{
  FAR FILE *f;
};

static int plain_read(FAR void *arg, FAR void *buf, size_t len)
{
  FAR struct plain_src_s *p = (FAR struct plain_src_s *)arg;
  size_t r = fread(buf, 1, len, p->f);

  if (r == 0 && ferror(p->f))
    {
      return TAR_RD_IO;
    }

  return (int)r;
}

/* ── gzip 源（zlib inflate，流式）────────────────────────────────── *
 *
 * 单例静态（解析器本身单线程使用；zlib 的解压窗口由它内部 malloc，
 * 那是第三方库的行为，本文件自身仍零动态分配）。
 */

#define GZ_IN  1024
#define GZ_OUT 1024

static struct gzsrc_s
{
  FAR FILE *f;
  z_stream  strm;
  uint8_t   in[GZ_IN];
  uint8_t   out[GZ_OUT];
  size_t    opos;
  size_t    oused;
  int       in_eof;
  int       done;
} g_gz;

static int gzsrc_open(FAR FILE *f)
{
  memset(&g_gz, 0, sizeof(g_gz));
  g_gz.f = f;

  /* 15 = 最大窗口；+16 = 只收 gzip 包装（CRC32/ISIZE 由 zlib 校验） */

  if (inflateInit2(&g_gz.strm, 15 + 16) != Z_OK)
    {
      return -1;
    }

  return 0;
}

static void gzsrc_close(void)
{
  inflateEnd(&g_gz.strm);
}

/* 把 gz 流剩余的字节读干净并要求到达 STREAM_END（CRC/ISIZE 由 zlib 在
 * STREAM_END 时校验）。为什么必须：tar 在**零块**处提前结束（end marker），
 * 若就此收工，gz 尾从没被读到 —— 截断/改尾都检不出来（§66 踩过）。 */

static int gz_read(FAR void *arg, FAR void *buf, size_t len);

static int gz_drain(void)
{
  static uint8_t sink[512];
  int r;

  while ((r = gz_read(&g_gz, sink, sizeof(sink))) > 0)
    {
    }

  return (r == 0 && g_gz.done) ? 0 : -1;
}

static int gz_read(FAR void *arg, FAR void *buf, size_t len)
{
  size_t got = 0;

  (void)arg;

  while (got < len)
    {
      size_t avail = g_gz.oused - g_gz.opos;

      if (avail > 0)
        {
          size_t n = (len - got < avail) ? (len - got) : avail;

          memcpy((FAR char *)buf + got, g_gz.out + g_gz.opos, n);
          g_gz.opos += n;
          got       += n;
          continue;
        }

      if (g_gz.done)
        {
          break;                      /* 流末：交付已得字节（0 = EOF） */
        }

      if (g_gz.strm.avail_in == 0 && !g_gz.in_eof)
        {
          size_t r = fread(g_gz.in, 1, GZ_IN, g_gz.f);

          g_gz.strm.next_in  = g_gz.in;
          g_gz.strm.avail_in = (uInt)r;
          if (r == 0)
            {
              g_gz.in_eof = 1;
            }
        }

      g_gz.strm.next_out  = g_gz.out;
      g_gz.strm.avail_out = GZ_OUT;

      {
        int ret = inflate(&g_gz.strm, Z_NO_FLUSH);

        g_gz.oused = GZ_OUT - g_gz.strm.avail_out;
        g_gz.opos  = 0;

        if (ret == Z_STREAM_END)
          {
            g_gz.done = 1;            /* CRC/ISIZE 已由 zlib 验证 */
          }
        else if (ret == Z_OK)
          {
            if (g_gz.oused == 0 && g_gz.in_eof)
              {
                return TAR_RD_GZ;     /* 输入尽而无进展 = 截断 */
              }
          }
        else if (ret == Z_BUF_ERROR)
          {
            if (g_gz.in_eof)
              {
                return TAR_RD_GZ;
              }
          }
        else
          {
            return TAR_RD_GZ;         /* Z_DATA_ERROR / Z_MEM_ERROR / ... */
          }
      }
    }

  return (int)got;
}

/* ── 头字段工具（与 §64 相同）────────────────────────────────────── */

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

static int tar_raw_dir_slash(FAR const uint8_t *name, size_t nlen)
{
  size_t i = 0;

  while (i < nlen && name[i] != '\0')
    {
      i++;
    }

  return (i > 0 && name[i - 1] == '/');
}

/* ── 成员读计数视图 ───────────────────────────────────────────────── */

struct memb_src_s
{
  FAR struct ort_tar_src_s *up;
  uint64_t consumed;
};

static int memb_read(FAR void *arg, FAR void *buf, size_t len)
{
  FAR struct memb_src_s *m = (FAR struct memb_src_s *)arg;
  int r = m->up->read(m->up->arg, buf, len);

  if (r > 0)
    {
      m->consumed += (uint64_t)r;
    }

  return r;
}

/* ── walk ─────────────────────────────────────────────────────────── */

int ort_tar_walk_src(FAR struct ort_tar_src_s *src,
                     FAR ort_tar_sink_t sink, FAR void *arg,
                     FAR uint32_t *nentries)
{
  uint8_t  h[TAR_BLOCK];
  static uint8_t scratch[TAR_BLOCK];
  uint32_t n = 0;

  for (;;)
    {
      size_t   got = 0;
      size_t   i;
      int      allzero = 1;
      int      r;
      uint64_t size = 0;
      uint64_t tmp = 0;
      struct ort_tar_entry_s e;
      char     typeflag;
      int      raw_dir;
      int      ret;
      static char pax_path[256];    /* [§94] pax 覆盖：path/linkpath/size */
      static char pax_link[256];
      static int64_t pax_size;
      static int  pax_have_path;
      static int  pax_have_link;
      static int  pax_have_size;

      for (;;)
        {
          r = src->read(src->arg, h + got, TAR_BLOCK - got);
          if (r == TAR_RD_GZ)
            {
              return ORT_TAR_E_GZIP;
            }

          if (r < 0)
            {
              return ORT_TAR_E_IO;
            }

          if (r == 0)
            {
              break;
            }

          got += (size_t)r;
        }

      if (got == 0)
        {
          break;                        /* 块边界 EOF：当结束（见头注） */
        }

      if (got < TAR_BLOCK)
        {
          return ORT_TAR_E_SHORT;
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

      /* [§94] pax 扩展头（'x'=下一成员 / 'g'=全局）：收数据、解析
       * path/linkpath/size 覆盖，**本身不作为成员交付**。 */

      if (typeflag == 'x' || typeflag == 'g')
        {
          static char paxbuf[4096];
          uint64_t left = size;
          uint64_t off  = 0;

          if (size > sizeof(paxbuf))
            {
              return ORT_TAR_E_LIMIT;
            }

          while (left > 0)
            {
              r = src->read(src->arg, paxbuf + off, (size_t)left);
              if (r == TAR_RD_GZ)
                {
                  return ORT_TAR_E_GZIP;
                }

              if (r <= 0)
                {
                  return ORT_TAR_E_IO;
                }

              off  += (uint64_t)r;
              left -= (uint64_t)r;
            }

          /* 跳过块对齐填充 */

          {
            uint64_t pad = (TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK;

            while (pad > 0)
              {
                r = src->read(src->arg, scratch, (size_t)pad);
                if (r <= 0)
                  {
                    return ORT_TAR_E_IO;
                  }

                pad -= (uint64_t)r;
              }
          }

          if (typeflag == 'x')
            {
              /* 解析 "<len> <key>=<value>\n" 记录 */

              uint64_t pos = 0;

              while (pos < off)
                {
                  uint64_t rlen = 0;

                  while (pos < off && paxbuf[pos] >= '0' &&
                         paxbuf[pos] <= '9')
                    {
                      rlen = rlen * 10 + (uint64_t)(paxbuf[pos] - '0');
                      pos++;
                    }

                  if (pos >= off || paxbuf[pos] != ' ')
                    {
                      return ORT_TAR_E_PAX;   /* 畸形记录 */
                    }

                  pos++;

                  /* 记录体到 '\n'（长度含长度字段本身） */

                  {
                    uint64_t bodyend = pos;   /* pos 现指向 key */

                    while (bodyend < off && paxbuf[bodyend] != '\n')
                      {
                        bodyend++;
                      }

                    if (bodyend >= off)
                      {
                        return ORT_TAR_E_PAX;
                      }

                    /* rlen 必须与 实际到 '\n' 的长度一致 */

                    if (rlen != bodyend + 1)
                      {
                        return ORT_TAR_E_PAX;
                      }

                    paxbuf[bodyend] = '\0';

                    {
                      FAR char *eq = strchr(paxbuf + pos, '=');

                      if (eq != NULL)
                        {
                          *eq = '\0';

                          if (strcmp(paxbuf + pos, "path") == 0)
                            {
                              if (tar_join_normalize(
                                      (FAR const uint8_t *)(eq + 1),
                                      strlen(eq + 1),
                                      (FAR const uint8_t *)"", 0,
                                      pax_path, sizeof(pax_path))
                                  != ORT_TAR_OK)
                                {
                                  return ORT_TAR_E_PAX;
                                }

                              pax_have_path = 1;
                            }
                          else if (strcmp(paxbuf + pos, "linkpath") == 0)
                            {
                              /* ★ 链接目标**不过路径规范化**：真镜像的
                               * 符号链接目标常是绝对路径（/bin/busybox）——
                               * 它只是字符串，不做成员路径策略。 */

                              tar_strlcpy(pax_link, eq + 1,
                                      sizeof(pax_link));
                              pax_have_link = 1;
                            }
                          else if (strcmp(paxbuf + pos, "size") == 0)
                            {
                              pax_size      = atoll(eq + 1);
                              pax_have_size = 1;
                            }
                        }
                    }

                    pos = bodyend + 1;
                  }
                }
            }

          continue;                     /* 扩展头不交付 */
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
            e.typeflag = typeflag;              /* 硬链接/符号链接 */
            break;

          case '3':
          case '4':
          case '6':
          case 'L':
          case 'K':

            /* 设备/FIFO/GNU 长名扩展：仍明确不收（见头注） */

            return ORT_TAR_E_TYPE;

          default:
            return ORT_TAR_E_TYPE;
        }

      /* pax 覆盖应用（一次性） */

      if (pax_have_path)
        {
          tar_strlcpy(e.name, pax_path, sizeof(e.name));
          pax_have_path = 0;
        }

      if (pax_have_size)
        {
          size = (uint64_t)pax_size;
          pax_have_size = 0;
        }

      if (pax_have_link)
        {
          tar_strlcpy(e.linkname, pax_link, sizeof(e.linkname));
          pax_have_link = 0;
        }
      else if (e.typeflag == '1' || e.typeflag == '2')
        {
          /* 头内 linkname（相对本成员所在目录的古老语义：tar 头里的
           * linkname 是相对归档根的路径，现代实现按原样用） */

          size_t ll = strnlen((FAR const char *)(h + TAR_LINK_OFF),
                              TAR_LINK_LEN);

          if (ll >= sizeof(e.linkname))
            {
              ll = sizeof(e.linkname) - 1;
            }

          memcpy(e.linkname, h + TAR_LINK_OFF, ll);
          e.linkname[ll] = '\0';
        }

      e.size = (e.typeflag == '5' || e.typeflag == '1' ||
                e.typeflag == '2') ? 0 : size;

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

      if (sink != NULL)
        {
          struct memb_src_s memb;
          struct ort_tar_src_s mview;

          memb.up = src;
          memb.consumed = 0;
          mview.read = memb_read;
          mview.arg  = &memb;

          if (sink(arg, &e, &mview) != 0)
            {
              return ORT_TAR_E_CB;
            }

          if (memb.consumed > e.size)
            {
              return ORT_TAR_E_CB;      /* sink 越读成员数据：契约破坏 */
            }

          /* 丢弃 sink 没读的余量 —— ★ 按 **512 对齐后的** 数据区长度算！
           * 旧实现靠绝对 fseek 天然对齐；流式后少算 padding 会让下一头
           * 读到数据块的填充零（"全零当 end marker"还会假通过，§66 踩过） */

          {
            uint64_t padded = (e.size + TAR_BLOCK - 1) & ~(uint64_t)(TAR_BLOCK - 1);
            uint64_t skip = padded - memb.consumed;

            while (skip > 0)
              {
                size_t c = (skip < TAR_BLOCK) ? (size_t)skip : TAR_BLOCK;

                r = src->read(src->arg, scratch, c);
                if (r == TAR_RD_GZ)
                  {
                    return ORT_TAR_E_GZIP;
                  }

                if (r < 0)
                  {
                    return ORT_TAR_E_IO;
                  }

                if (r == 0)
                  {
                    return ORT_TAR_E_SHORT;     /* 数据区越过流尾 */
                  }

                skip -= (uint64_t)r;
              }
          }
        }
      else
        {
          /* 无 sink 也必须推进过数据区（同样按 512 对齐的长度） */

          uint64_t skip = (e.size + TAR_BLOCK - 1) &
                          ~(uint64_t)(TAR_BLOCK - 1);

          while (skip > 0)
            {
              size_t c = (skip < TAR_BLOCK) ? (size_t)skip : TAR_BLOCK;

              r = src->read(src->arg, scratch, c);
              if (r == TAR_RD_GZ)
                {
                  return ORT_TAR_E_GZIP;
                }

              if (r < 0)
                {
                  return ORT_TAR_E_IO;
                }

              if (r == 0)
                {
                  return ORT_TAR_E_SHORT;
                }

              skip -= (uint64_t)r;
            }
        }
    }

  if (nentries != NULL)
    {
      *nentries = n;
    }

  return ORT_TAR_OK;
}

int ort_tar_walk(FAR FILE *f, FAR ort_tar_sink_t sink, FAR void *arg,
                 FAR uint32_t *nentries)
{
  uint8_t magic[2];
  size_t  r = fread(magic, 1, 2, f);

  /* 回卷（gzip 探测只借头两字节；真实文件都可 seek） */

  if (fseek(f, 0, SEEK_SET) != 0)
    {
      return ORT_TAR_E_IO;
    }

  if (r == 2 && magic[0] == 0x1f && magic[1] == 0x8b)
    {
      struct ort_tar_src_s s;
      int ret;

      if (gzsrc_open(f) != 0)
        {
          return ORT_TAR_E_GZIP;
        }

      s.read = gz_read;
      s.arg  = &g_gz;
      ret = ort_tar_walk_src(&s, sink, arg, nentries);
      if (ret == ORT_TAR_OK && gz_drain() != 0)
        {
          ret = ORT_TAR_E_GZIP;     /* 流未到 STREAM_END：截断/改尾 */
        }

      gzsrc_close();
      return ret;
    }

  {
    struct plain_src_s p;
    struct ort_tar_src_s s;

    p.f = f;
    s.read = plain_read;
    s.arg  = &p;
    return ort_tar_walk_src(&s, sink, arg, nentries);
  }
}
