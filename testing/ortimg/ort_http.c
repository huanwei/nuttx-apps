/****************************************************************************
 * testing/ortimg/ort_http.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] 极简 HTTP/1.0 GET 实现（约定见 ort_http.h）。
 *
 * 实现要点：
 *   · 请求头全部准备好**一次 write** —— 少一次往返，也少一类"部分写"
 *     的边界（NuttX 上小报文一次写完是常态，write 返回值仍检查）
 *   · 响应头逐行解析（大小写不敏感的前缀匹配），只抽四样：
 *     状态码 / Content-Length / WWW-Authenticate
 *   · 两条消费路径共用 http_open()（连接 + 请求 + 响应头），差异只在
 *     body 怎么消费：get 定长进内存 / get_stream 边收边交 sink
 *   · 全程有界：get 的 body_cap 之外只读不存（并置 truncated 标志）；
 *     stream 的缓冲只有 1KB（层体任意大，内存常数）
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* [ORT §94] TLS 后端：明文/TLS 统一连接抽象（mbedtls 3.x） */

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/error.h>

#include "ort_http.h"

#define ORT_HTTP_HDR_MAX 2048

/* [ORT §94] 连接抽象：全局单例（本 app 单线程、逐请求顺序发起）。
 * 明文 = 裸 socket；TLS = mbedtls（每次 http_open 新连接 + 握手，
 * SNI/CN 用**当次 host** —— 重定向跨主机时各自正确）。 */

struct ort_http_conn_s
{
  int fd;                        /* 明文模式的 socket（TLS 下不用） */
  int tls;
  mbedtls_net_context      net;
  mbedtls_ssl_context      ssl;
  mbedtls_ssl_config       conf;
  mbedtls_entropy_context  entropy;
  mbedtls_ctr_drbg_context drbg;
  mbedtls_x509_crt         ca;
};

static struct ort_http_conn_s g_conn;
static int g_tls_ready;

/* 启用 TLS 后端并解析 CA（一次性；进程内单调）。返回 0/负值。 */

int ort_http_set_tls(FAR const char *capath)
{
  static char ca_buf[8192];
  FAR FILE *f;
  size_t n;
  int ret;

  mbedtls_net_init(&g_conn.net);
  mbedtls_ssl_init(&g_conn.ssl);
  mbedtls_ssl_config_init(&g_conn.conf);
  mbedtls_entropy_init(&g_conn.entropy);
  mbedtls_ctr_drbg_init(&g_conn.drbg);
  mbedtls_x509_crt_init(&g_conn.ca);
  g_conn.tls = 1;

  ret = mbedtls_ctr_drbg_seed(&g_conn.drbg, mbedtls_entropy_func,
                              &g_conn.entropy,
                              (FAR const unsigned char *)"orthttp", 7);
  if (ret != 0)
    {
      return ret;
    }

  f = fopen(capath, "rb");
  if (f == NULL)
    {
      return -2;
    }

  n = fread(ca_buf, 1, sizeof(ca_buf) - 1, f);
  fclose(f);
  ca_buf[n] = '\0';

  ret = mbedtls_x509_crt_parse(&g_conn.ca,
                               (FAR const unsigned char *)ca_buf, n + 1);
  if (ret != 0)
    {
      return ret;
    }

  ret = mbedtls_ssl_config_defaults(&g_conn.conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0)
    {
      return ret;
    }

  mbedtls_ssl_conf_rng(&g_conn.conf, mbedtls_ctr_drbg_random, &g_conn.drbg);
  mbedtls_ssl_conf_ca_chain(&g_conn.conf, &g_conn.ca, NULL);
  mbedtls_ssl_conf_authmode(&g_conn.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_min_tls_version(&g_conn.conf,
                                   MBEDTLS_SSL_VERSION_TLS1_2);

  ret = mbedtls_ssl_setup(&g_conn.ssl, &g_conn.conf);
  if (ret != 0)
    {
      return ret;
    }

  g_tls_ready = 1;
  return 0;
}

/* 读/写/关：统一入口（调用点不再关心传输层） */

static ssize_t hx_read(FAR void *buf, size_t len)
{
  if (!g_conn.tls)
    {
      return recv(g_conn.fd, buf, len, 0);
    }

  for (;;)
    {
      int r = mbedtls_ssl_read(&g_conn.ssl, buf, len);

      if (r == MBEDTLS_ERR_SSL_WANT_READ ||
          r == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
          continue;
        }

      if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        {
          return 0;                /* 对端正常收尾 */
        }

      return (ssize_t)r;
    }
}

static ssize_t hx_write(FAR const void *buf, size_t len)
{
  if (!g_conn.tls)
    {
      return send(g_conn.fd, buf, len, 0);
    }

  for (;;)
    {
      int r = mbedtls_ssl_write(&g_conn.ssl, buf, len);

      if (r == MBEDTLS_ERR_SSL_WANT_READ ||
          r == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
          continue;
        }

      return (ssize_t)r;
    }
}

static void hx_close(void)
{
  if (!g_conn.tls)
    {
      if (g_conn.fd >= 0)
        {
          close(g_conn.fd);
          g_conn.fd = -1;
        }
    }
  else
    {
      if (g_tls_ready)
        {
          mbedtls_ssl_session_reset(&g_conn.ssl);
        }

      mbedtls_net_free(&g_conn.net);
      mbedtls_net_init(&g_conn.net);
    }
}

static int str_starts_ci(FAR const char *s, FAR const char *prefix)
{
  while (*prefix != '\0')
    {
      char a = *s++;
      char b = *prefix++;

      if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
      if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
      if (a != b)
        {
          return 0;
        }
    }

  return 1;
}

/* 收一行（以 \r\n 或 \n 结束；行太长 -> -1），NUL 结尾；返回行字节数（不含换行）。
 * 为了不把"越界"当"读完"，这里直接读 socket 一个字节一个字节 —— 头部总量
 * 有 ORT_HTTP_HDR_MAX 封顶，慢一点换个简单正确。 */

static int recv_line(int fd, FAR char *buf, size_t cap)
{
  size_t n = 0;

  for (;;)
    {
      char ch;

      if (hx_read(&ch, 1) <= 0)
        {
          return -1;
        }

      if (ch == '\n')
        {
          if (n > 0 && buf[n - 1] == '\r')
            {
              n--;
            }
          buf[n] = '\0';
          return (int)n;
        }

      if (n + 1 >= cap)
        {
          return -1;
        }

      buf[n++] = ch;
    }
}

static int recv_exact(int fd, FAR char *dst, size_t want, size_t drop_extra,
                      FAR size_t *stored, FAR int *truncated)
{
  size_t got = 0;

  while (got < want)
    {
      char   tmp[512];
      size_t chunk = want - got;
      ssize_t r;

      if (chunk > sizeof(tmp))
        {
          chunk = sizeof(tmp);
        }

      r = hx_read(tmp, chunk);
      if (r <= 0)
        {
          return -1;
        }

      if (drop_extra)
        {
          *truncated = 1;
        }
      else
        {
          memcpy(dst + got, tmp, (size_t)r);
        }

      got += (size_t)r;
      *stored += (size_t)r;
    }

  return 0;
}

/* 连接 + 请求 + 响应头（get / get_stream 共用）。成功返回 fd（>0），
 * 失败返回负值（与两个公开函数的错误码同一套）。 */

static int http_open(FAR const char *host, unsigned port,
                     FAR const char *path,
                     FAR const char *bearer, FAR const char *accept,
                     FAR const char *extra,
                     FAR struct ort_http_resp_s *resp)
{
  struct addrinfo hints;
  FAR struct addrinfo *ai = NULL;
  char   portstr[8];
  static char req[8192];                   /* ★ 静态化：目标机 app 栈 ~2KB，
                                            * 大件放栈上必炸（2026-10-06 实测）。
                                            * [§94] 768 → 8192：真 Hub 的
                                            * token 实测 2698B，768 字节缓冲
                                            * 把 Authorization 拦腰截断
                                            * （r3 标本：状态行读不到 -5） */
  static char line[ORT_HTTP_HDR_MAX];
  int    fd = -1;
  int    ret;

  memset(resp, 0, sizeof(*resp));
  resp->content_len       = -1;
  resp->content_range_from = -1;

  snprintf(portstr, sizeof(portstr), "%u", port);

  if (g_conn.tls)
    {
      /* [§94] TLS 路径：新连接 + 握手（SNI/CN = 当次 host）。 */

      ret = mbedtls_net_connect(&g_conn.net, host, portstr,
                                MBEDTLS_NET_PROTO_TCP);
      if (ret != 0)
        {
          return -1;
        }

      ret = mbedtls_ssl_set_hostname(&g_conn.ssl, host);
      if (ret != 0)
        {
          hx_close();
          return -1;
        }

      mbedtls_ssl_set_bio(&g_conn.ssl, &g_conn.net, mbedtls_net_send,
                          mbedtls_net_recv, NULL);

      for (;;)
        {
          ret = mbedtls_ssl_handshake(&g_conn.ssl);
          if (ret == 0)
            {
              break;
            }

          if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
              ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
              hx_close();
              return ret;          /* mbedtls 负码可读 */
            }
        }

      goto headers;                /* 复用同一套请求/头解析 */
    }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  ret = getaddrinfo(host, portstr, &hints, &ai);
  if (ret != 0 || ai == NULL)
    {
      return -1;
    }

  /* ★ 带界重连（3 次 × 2s）：启动初期网卡可能尚未 RUNNING ——
   *   嵌入式网络（链路抖动/延迟就绪）的真实需求，也让装置确定
   *   （不然测试会因为"9 秒 vs 11 秒"这种时序抖动时红时绿）。 */

  {
    int tries;

    for (tries = 0; ; tries++)
      {
        fd = socket(ai->ai_family, ai->ai_socktype, 0);
        if (fd < 0)
          {
            freeaddrinfo(ai);
            return -2;
          }

        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
          {
            break;
          }

        close(fd);                 /* 失败 connect 的本地 fd：本地关 */
        fd = -1;

        if (tries >= 2)
          {
            freeaddrinfo(ai);
            return -3;
          }

        sleep(2);
      }
  }

  freeaddrinfo(ai);
  g_conn.fd = fd;

headers:

  /* [§94] 请求头拼接：Authorization/Accept 各自带 CRLF；extra 自带。
   * 旧版 Accept 行漏了换行（其值直接粘上 "Connection:"），且超缓冲时
   * 静默截断 —— 现在:格式修正 + 超限显式 fail-closed（-11）。 */

  ret = snprintf(req, sizeof(req),
                 "GET %s HTTP/1.0\r\n"
                 "Host: %s:%u\r\n"
                 "%s%s%s%s%s%s%s"
                 "Connection: close\r\n"
                 "\r\n",
                 path, host, port,
                 bearer ? "Authorization: Bearer " : "",
                 bearer ? bearer : "",
                 bearer ? "\r\n" : "",
                 accept ? "Accept: " : "",
                 accept ? accept : "",
                 accept ? "\r\n" : "",
                 extra ? extra : "");
  if (ret < 0 || ret >= (int)sizeof(req))
    {
      hx_close();
      return -11;              /* 请求超缓冲：绝不发截断的请求 */
    }

  if (hx_write(req, (size_t)ret) < 0)
    {
      hx_close();
      return -4;
    }

  /* 状态行：HTTP/1.x <code> ... */

  ret = recv_line(fd, line, sizeof(line));
  if (ret < 0 || strncmp(line, "HTTP/", 5) != 0)
    {
      hx_close();
      return -5;
    }

  {
    FAR const char *sp = strchr(line, ' ');

    if (sp == NULL)
      {
        hx_close();
        return -5;
      }

    resp->status = atoi(sp + 1);
  }

  /* 响应头 */

  for (;;)
    {
      ret = recv_line(fd, line, sizeof(line));
      if (ret < 0)
        {
          hx_close();
          return -6;
        }

      if (ret == 0)
        {
          break;                     /* 空行 = 头结束 */
        }

      if (str_starts_ci(line, "content-length:"))
        {
          resp->content_len = atoll(line + 15);
        }
      else if (str_starts_ci(line, "www-authenticate:"))
        {
          strlcpy(resp->www_auth, line + 17, sizeof(resp->www_auth));
        }
      else if (str_starts_ci(line, "location:"))
        {
          /* [§90] 重定向目标（诊断 + 跟随用）。[§94] 真 Hub 的 blob
           * 307 指向 CloudFront **签名 URL，实测 558 字节**（path+
           * query 518）—— 256 字节时代只能拿到截断 URL；超缓冲现在
           * 显式 fail-closed，绝不拿截断的 URL 去跟随。 */

          FAR const char *v = line + 9;

          while (*v == ' ')
            {
              v++;
            }

          if (strlen(v) >= sizeof(resp->location))
            {
              hx_close();
              return -11;
            }

          strlcpy(resp->location, v, sizeof(resp->location));
        }
      else if (str_starts_ci(line, "content-range:"))
        {
          /* [§94] "Content-Range: bytes X-Y/Z" → 起始 X */

          FAR const char *v = line + 14;

          while (*v == ' ')
            {
              v++;
            }

          if (str_starts_ci(v, "bytes "))
            {
              resp->content_range_from = atoll(v + 6);
            }
        }
      else if (str_starts_ci(line, "transfer-encoding:"))
        {
          /* [§90] chunked：值与 content-length 互斥（RFC 7230） */

          FAR const char *v = line + 18;

          while (*v == ' ')
            {
              v++;
            }

          if (str_starts_ci(v, "chunked"))
            {
              resp->chunked = 1;
            }
        }
    }

  return OK;
}


/****************************************************************************
 * [§90] 统一响应体读取器 —— 三种模式一视同仁：
 *   ① chunked（已解码，畸形/短块 fail-closed）
 *   ② Content-Length（读齐即停；短 = 断流 -7）
 *   ③ 无长度（1.0 + Connection: close，读到 EOF）
 * get 用内存写者适配；get_stream 用调用者 sink。
 ****************************************************************************/

#define ORT_HTTP_REDIRECT_MAX 5

struct ort_http_writer_s
{
  FAR char *body;
  size_t    cap;
  size_t    stored;
  int       trunc;
};

static int http_writer_sink(FAR void *arg, FAR const char *buf, size_t len)
{
  FAR struct ort_http_writer_s *w = arg;

  if (w->stored < w->cap)
    {
      size_t room = w->cap - w->stored;
      size_t n    = len < room ? len : room;

      memcpy(w->body + w->stored, buf, n);
    }

  w->stored += len;

  if (w->stored > w->cap)
    {
      w->trunc = 1;
    }

  return 0;                       /* 内存写者从不中止（溢出=截断标记） */
}

/* 读 want 字节喂 sink，再吃 chunk 尾 CRLF。返回 0 / -1（断流或截断）/
 * -2（调用者 sink 中止）。 */

static int http_take(int fd, FAR char *buf, size_t cap, unsigned long want,
                     FAR ort_http_sink_t sink, FAR void *arg,
                     FAR size_t *total)
{
  unsigned long got = 0;

  while (got < want)
    {
      size_t  ask = cap;
      ssize_t r;

      if ((unsigned long)ask > want - got)
        {
          ask = (size_t)(want - got);
        }

      r = hx_read(buf, ask);
      if (r <= 0)
        {
          return -1;
        }

      if (sink != NULL && sink(arg, buf, (size_t)r) != 0)
        {
          return -2;
        }

      got    += (unsigned long)r;
      *total += (size_t)r;
    }

  {
    char    crlf[2];
    size_t  stored = 0;
    int     trunc  = 0;

    if (recv_exact(fd, crlf, 2, 0, &stored, &trunc) < 0 ||
        crlf[0] != '\r' || crlf[1] != '\n')
      {
        return -1;
      }
  }

  return 0;
}

static int http_read_body(int fd, FAR struct ort_http_resp_s *resp,
                          FAR ort_http_sink_t sink, FAR void *arg,
                          FAR size_t *out_total)
{
  static char buf[1024];
  size_t total = 0;
  int    ret   = 0;

  if (resp->chunked)
    {
      for (;;)
        {
          char szline[64];
          char *semi;
          char *end;
          unsigned long sz;

          if (recv_line(fd, szline, sizeof(szline)) < 0)
            {
              ret = -9;            /* 块头读不到 */
              break;
            }

          semi = strchr(szline, ';');     /* 块扩展：忽略 */
          if (semi != NULL)
            {
              *semi = '\0';
            }

          sz = strtoul(szline, &end, 16);
          if (end == szline)
            {
              ret = -9;            /* 畸形块头（非十六进制） */
              break;
            }

          if (sz == 0)
            {
              /* 尾零块：trailer 行直到空行 */

              for (;;)
                {
                  int lr = recv_line(fd, szline, sizeof(szline));

                  if (lr == 0)
                    {
                      break;
                    }

                  if (lr < 0)
                    {
                      ret = -9;
                      break;
                    }
                }

              break;
            }

          ret = http_take(fd, buf, sizeof(buf), sz, sink, arg, &total);
          if (ret != 0)
            {
              break;
            }
        }

      if (ret == -2)
        {
          ret = -8;                /* 同 sink 中止的既有错误码 */
        }
    }
  else if (resp->content_len >= 0)
    {
      unsigned long want = (unsigned long)resp->content_len;

      while (want > 0)
        {
          size_t  ask = sizeof(buf);
          ssize_t r;

          if ((unsigned long)ask > want)
            {
              ask = (size_t)want;
            }

          r = hx_read(buf, ask);
          if (r <= 0)
            {
              ret = -7;            /* 定长没读齐 = 断流 */
              break;
            }

          if (sink != NULL && sink(arg, buf, (size_t)r) != 0)
            {
              ret = -8;
              break;
            }

          want  -= (unsigned long)r;
          total += (size_t)r;
        }
    }
  else
    {
      for (;;)
        {
          ssize_t r = hx_read(buf, sizeof(buf));

          if (r <= 0)
            {
              break;               /* EOF = 正常结束（1.0 close 语义） */
            }

          if (sink != NULL && sink(arg, buf, (size_t)r) != 0)
            {
              ret = -8;
              break;
            }

          total += (size_t)r;
        }
    }

  *out_total = total;
  return ret;
}

static bool http_is_redirect(int st)
{
  return st == 301 || st == 302 || st == 303 || st == 307 || st == 308;
}

/* [§90] 连接 + 请求 + 响应头 + 重定向跟随。hostbuf/pathbuf 由调用者给
 * 静态缓冲（目标机栈小）。跨主机:端口跳转时剥 Authorization（凭据
 * 卫生——真 Hub 的 blob 会 307 去 CDN，凭据不该跟着走）。 */

static int http_open_follow(FAR const char *host, unsigned port,
                            FAR const char *path,
                            FAR const char *bearer, FAR const char *accept,
                            FAR const char *extra,
                            FAR struct ort_http_resp_s *resp,
                            FAR char *hostbuf, size_t hostcap,
                            FAR char *pathbuf, size_t pathcap)
{
  char newhost[128];
  char lastloc[640];             /* 沿路最后一跳的 Location（见证用——
                                  * 每次 http_open 会 memset resp，
                                  * 不存就会被清掉）。[§94] 256 → 640：
                                  * CloudFront 签名 URL 实测 558 字节 */
  unsigned cur_port = port;
  FAR const char *cur_bearer = bearer;
  int hops;

  if (strlen(path) + 1 > pathcap || strlen(host) + 1 > hostcap)
    {
      return -9;
    }

  strlcpy(hostbuf, host, hostcap);
  strlcpy(pathbuf, path, pathcap);

  for (hops = 0; ; hops++)
    {
      int fd;

      fd = http_open(hostbuf, cur_port, pathbuf, cur_bearer, accept, extra,
                     resp);
      if (fd < 0)
        {
          return fd;
        }

      if (!http_is_redirect(resp->status) || resp->location[0] == '\0')
        {
          resp->redirects = hops;

          if (hops > 0)
            {
              /* 见证 = 沿路最后一跳（终跳 http_open 已把 resp 清零） */

              strlcpy(resp->location, lastloc, sizeof(resp->location));
            }

          return fd;
        }

      strlcpy(lastloc, resp->location, sizeof(lastloc));
      hx_close();

      if (hops >= ORT_HTTP_REDIRECT_MAX)
        {
          return -10;              /* 重定向超限：fail-closed */
        }

      if (str_starts_ci(resp->location, "http://") ||
          str_starts_ci(resp->location, "https://"))
        {
          /* [§94] 真 Hub 的 blob 307 指向 https://…cloudfront…：两族
           * scheme 都认；端口缺省按 scheme（http=80 / https=443）。
           * TLS 开关是进程级（ort_http_set_tls），后续每跳自动用
           * TLS + 当次 host 作 SNI/CN —— scheme 只决定缺省端口。 */

          int             is_https = (resp->location[4] == 's' ||
                                      resp->location[4] == 'S');
          FAR const char *p        = resp->location + (is_https ? 8 : 7);
          FAR const char *slash    = strchr(p, '/');
          FAR const char *colon    = strchr(p, ':');
          size_t          hl;
          unsigned        np       = is_https ? 443 : 80;

          if (colon != NULL && (slash == NULL || colon < slash))
            {
              hl = (size_t)(colon - p);
              np = (unsigned)atoi(colon + 1);
            }
          else
            {
              hl = slash != NULL ? (size_t)(slash - p) : strlen(p);
            }

          if (hl == 0 || hl + 1 > sizeof(newhost))
            {
              return -9;
            }

          memcpy(newhost, p, hl);
          newhost[hl] = '\0';

          if (strcmp(newhost, hostbuf) != 0 || np != cur_port)
            {
              cur_bearer = NULL;   /* 跨主机:端口 → 剥凭据 */
            }

          if (strlen(slash != NULL ? slash : "/") + 1 > pathcap)
            {
              return -9;           /* [§94] 跳转路径超缓冲：fail-closed，
                                    * 绝不拿截断的 URL 去请求 */
            }

          strlcpy(hostbuf, newhost, hostcap);
          cur_port = np;
          strlcpy(pathbuf, slash != NULL ? slash : "/", pathcap);
        }
      else if (resp->location[0] == '/')
        {
          strlcpy(pathbuf, resp->location, pathcap);
        }
      else
        {
          return -9;               /* 裸相对 Location：不猜，fail-closed */
        }
    }
}

int ort_http_get(FAR const char *host, unsigned port, FAR const char *path,
                 FAR const char *bearer, FAR const char *accept,
                 FAR char *body, size_t body_cap,
                 FAR struct ort_http_resp_s *resp)
{
  static char hostbuf[128];      /* ★ 静态：重定向跟随要可变副本 */
  static char pathbuf[640];
  struct ort_http_writer_s w;
  int fd;
  int ret;

  fd = http_open_follow(host, port, path, bearer, accept, NULL, resp,
                        hostbuf, sizeof(hostbuf), pathbuf, sizeof(pathbuf));
  if (fd < 0)
    {
      return fd;
    }

  memset(&w, 0, sizeof(w));
  w.body = body;
  w.cap  = body_cap;

  ret = http_read_body(fd, resp, http_writer_sink, &w, &w.stored);
  hx_close();

  if (ret < 0)
    {
      return ret;
    }

  resp->body_truncated |= w.trunc;
  resp->body_len = w.stored > body_cap ? body_cap : w.stored;

  if (resp->body_len < body_cap)
    {
      body[resp->body_len] = '\0';
    }
  else if (!resp->body_truncated)
    {
      resp->body_truncated = 1;   /* 恰好填满也当截断处理（保守） */
    }

  return 0;
}

int ort_http_get_stream(FAR const char *host, unsigned port,
                        FAR const char *path,
                        FAR const char *bearer, FAR const char *accept,
                        FAR ort_http_sink_t sink, FAR void *arg,
                        FAR struct ort_http_resp_s *resp)
{
  static char hostbuf[128];
  static char pathbuf[640];
  int    fd;
  int    ret;
  size_t total = 0;

  fd = http_open_follow(host, port, path, bearer, accept, NULL, resp,
                        hostbuf, sizeof(hostbuf), pathbuf, sizeof(pathbuf));
  if (fd < 0)
    {
      return fd;
    }

  ret = http_read_body(fd, resp, sink, arg, &total);
  hx_close();

  resp->body_len = total;
  return ret;          /* 定长短读 -7 / sink 中止 -8 / 畸形 chunk -9 */
}

int ort_http_get_stream_from(FAR const char *host, unsigned port,
                             FAR const char *path,
                             FAR const char *bearer,
                             FAR const char *accept,
                             FAR ort_http_sink_t sink, FAR void *arg,
                             FAR struct ort_http_resp_s *resp,
                             long long from)
{
  static char hostbuf[128];
  static char pathbuf[640];
  static char rangehdr[48];
  FAR const char *extra = NULL;
  int    fd;
  int    ret;
  size_t total = 0;

  if (from > 0)
    {
      snprintf(rangehdr, sizeof(rangehdr), "Range: bytes=%lld-\r\n",
               from);
      extra = rangehdr;
    }

  fd = http_open_follow(host, port, path, bearer, accept, extra, resp,
                        hostbuf, sizeof(hostbuf), pathbuf, sizeof(pathbuf));
  if (fd < 0)
    {
      return fd;
    }

  ret = http_read_body(fd, resp, sink, arg, &total);
  hx_close();

  resp->body_len = total;
  return ret;
}
