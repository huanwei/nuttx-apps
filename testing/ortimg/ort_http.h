/****************************************************************************
 * testing/ortimg/ort_http.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] 极简 HTTP/1.0 GET（registry 客户端的地基）。
 *
 * §90（2026-10-09）起支持：
 *   · **chunked 传编码**——解码后语义与定长一致（get/stream 两条都走
 *     统一读取器）；畸形块头/短块 = fail-closed（负值错误）
 *   · **重定向（301/302/303/307/308）**——上限 5 跳；Location 支持
 *     "/abs" 与 "http://host[:port]/abs"；**跨主机时剥掉 Authorization**
 *     （凭据卫生；同主机:端口保持）。超限 = fail-closed
 *
 * 刻意不支持的东西（每一件都有明确的理由，不是"还没做"）：
 *   · HTTP/1.1 keep-alive —— 用 1.0 + Connection: close，读到 EOF 为止
 *   · TLS —— 增量二（mbedTLS）；本增量对 fixture 服务器走明文
 *   · 裸相对 Location（"foo" 无斜杠无 scheme）—— fail-closed，
 *     真 Hub 不发这种，不猜
 *
 * 两个消费者：
 *   · ort_http_get         —— 定长读进内存（manifest/token 用，KB 级）
 *   · ort_http_get_stream  —— 边收边交给 sink（blob 下载用，任意大小，
 *                             常数内存；sink 里做落盘 + SHA-256 边算）
 ****************************************************************************/

#ifndef __APPS_TESTING_ORTIMG_ORT_HTTP_H
#define __APPS_TESTING_ORTIMG_ORT_HTTP_H

#include <stddef.h>

#ifndef FAR
#  define FAR
#endif

struct ort_http_resp_s
{
  int      status;             /* HTTP 状态码；0 = 没拿到响应 */
  size_t   body_len;           /* 落进 body / 交给 sink 的字节数 */
  int      body_truncated;     /* 1 = 超过 body_cap 被截断（仅 get） */
  long long content_len;       /* 头里的 Content-Length；-1 = 没有 */
  char     www_auth[256];      /* WWW-Authenticate 头（空串=无）*/
  int      chunked;            /* [§90] 1 = Transfer-Encoding: chunked（已解码）*/
  int      redirects;          /* [§90] 跟随的重定向跳数 */
  char     location[256];      /* [§90] 最后一次的 Location 头（诊断） */
};

/* 流式回调：buf/len 是一块响应体；返回非 0 = 调用方要求中止（下载
 * 会以 -8 失败收场）。buf 不保证 NUL 结尾。 */
typedef int (*ort_http_sink_t)(FAR void *arg, FAR const char *buf,
                               size_t len);

/* 返回 0 = 完成了一次 HTTP 交换（状态码在 resp->status，哪怕是 4xx/5xx）；
 * 负值 = 传输层失败（连不上/断流/解析不了响应行/sink 中止）。 */

int ort_http_get(FAR const char *host, unsigned port,
                 FAR const char *path,
                 FAR const char *bearer,      /* 可空：Authorization: Bearer */
                 FAR const char *accept,      /* 可空：Accept 头 */
                 FAR char *body, size_t body_cap,
                 FAR struct ort_http_resp_s *resp);

int ort_http_get_stream(FAR const char *host, unsigned port,
                        FAR const char *path,
                        FAR const char *bearer,
                        FAR const char *accept,
                        FAR ort_http_sink_t sink, FAR void *arg,
                        FAR struct ort_http_resp_s *resp);

#endif /* __APPS_TESTING_ORTIMG_ORT_HTTP_H */
