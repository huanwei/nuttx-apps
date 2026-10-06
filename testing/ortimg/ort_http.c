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

#include "ort_http.h"

#define ORT_HTTP_HDR_MAX 2048

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

      if (recv(fd, &ch, 1, 0) <= 0)
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

      r = recv(fd, tmp, chunk, 0);
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
                     FAR struct ort_http_resp_s *resp)
{
  struct addrinfo hints;
  FAR struct addrinfo *ai = NULL;
  char   portstr[8];
  static char req[768];                    /* ★ 静态化：目标机 app 栈 ~2KB，
                                            * 大件放栈上必炸（2026-10-06 实测） */
  static char line[ORT_HTTP_HDR_MAX];
  int    fd = -1;
  int    ret;

  memset(resp, 0, sizeof(*resp));
  resp->content_len = -1;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  snprintf(portstr, sizeof(portstr), "%u", port);
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

        close(fd);
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

  ret = snprintf(req, sizeof(req),
                 "GET %s HTTP/1.0\r\n"
                 "Host: %s:%u\r\n"
                 "%s%s%s%s%s"
                 "Connection: close\r\n"
                 "\r\n",
                 path, host, port,
                 bearer ? "Authorization: Bearer " : "",
                 bearer ? bearer : "",
                 bearer ? "\r\n" : "",
                 accept ? "Accept: " : "",
                 accept ? accept : "");
  if (accept)
    {
      /* Accept 行需要换行收尾（上面简化了拼接，这里补） */
      size_t l = strlen(req);

      if (l + 2 < sizeof(req))
        {
          req[l]     = '\r';
          req[l + 1] = '\n';
          req[l + 2] = '\0';
        }
    }

  if (send(fd, req, strlen(req), 0) < 0)
    {
      close(fd);
      return -4;
    }

  /* 状态行：HTTP/1.x <code> ... */

  ret = recv_line(fd, line, sizeof(line));
  if (ret < 0 || strncmp(line, "HTTP/", 5) != 0)
    {
      close(fd);
      return -5;
    }

  {
    FAR const char *sp = strchr(line, ' ');

    if (sp == NULL)
      {
        close(fd);
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
          close(fd);
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
    }

  return fd;
}

int ort_http_get(FAR const char *host, unsigned port, FAR const char *path,
                 FAR const char *bearer, FAR const char *accept,
                 FAR char *body, size_t body_cap,
                 FAR struct ort_http_resp_s *resp)
{
  int    fd;
  long long content_len;
  size_t stored = 0;

  fd = http_open(host, port, path, bearer, accept, resp);
  if (fd < 0)
    {
      return fd;
    }

  content_len = resp->content_len;

  /* body */

  if (content_len >= 0)
    {
      size_t want = (size_t)content_len;

      if (want <= body_cap)
        {
          if (recv_exact(fd, body, want, 0, &stored, &resp->body_truncated)
              < 0)
            {
              close(fd);
              return -7;
            }
        }
      else
        {
          if (recv_exact(fd, NULL, want, 1, &stored, &resp->body_truncated)
              < 0)
            {
              close(fd);
              return -7;
            }
        }

      resp->body_len = stored > body_cap ? body_cap : stored;
    }
  else
    {
      /* 没有 Content-Length：读到 EOF（HTTP/1.0 + Connection: close 语义）*/

      for (;;)
        {
          ssize_t r;

          if (stored < body_cap)
            {
              r = recv(fd, body + stored, body_cap - stored, 0);
            }
          else
            {
              char sink[256];

              r = recv(fd, sink, sizeof(sink), 0);
              if (r > 0)
                {
                  resp->body_truncated = 1;
                  stored += (size_t)r;
                  continue;
                }
            }

          if (r <= 0)
            {
              break;
            }

          stored += (size_t)r;
        }

      resp->body_len = stored > body_cap ? body_cap : stored;
    }

  close(fd);

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
  static char chunk[1024];       /* ★ 静态：目标机 app 栈不见大件 */
  int fd;
  long long want;
  size_t total = 0;

  fd = http_open(host, port, path, bearer, accept, resp);
  if (fd < 0)
    {
      return fd;
    }

  want = resp->content_len;

  for (;;)
    {
      size_t ask = sizeof(chunk);
      ssize_t r;

      if (want >= 0)
        {
          if ((long long)total >= want)
            {
              break;                 /* 定长：读齐即停（多出的留给 close） */
            }

          if ((long long)ask > want - (long long)total)
            {
              ask = (size_t)(want - (long long)total);
            }
        }

      r = recv(fd, chunk, ask, 0);
      if (r < 0)
        {
          close(fd);
          return -7;
        }

      if (r == 0)
        {
          break;                     /* 对端关闭 */
        }

      if (sink != NULL && sink(arg, chunk, (size_t)r) != 0)
        {
          close(fd);
          return -8;                 /* sink 主动中止（如落盘失败） */
        }

      total += (size_t)r;
    }

  close(fd);
  resp->body_len = total;

  if (want >= 0 && (long long)total < want)
    {
      return -7;                     /* 定长没读齐 = 断流 */
    }

  return 0;
}
