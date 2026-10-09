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
 *     "/abs" 与 "http[s]://host[:port]/abs"（§94 起收 https://，端口
 *     缺省按 scheme：http=80 / https=443）；**跨主机时剥掉
 *     Authorization**（凭据卫生；同主机:端口保持）。超限 = fail-closed
 *   · **TLS（§94）**——ort_http_set_tls(capath) 一次性开：此后所有
 *     请求（含 token 跨主机与 CDN 重定向各跳）走 mbedTLS，
 *     VERIFY_REQUIRED + CA 束，SNI/CN 逐跳用当次 host
 *
 * 刻意不支持的东西（每一件都有明确的理由，不是"还没做"）：
 *   · HTTP/1.1 keep-alive —— 用 1.0 + Connection: close，读到 EOF 为止
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
  long long content_range_from; /* [§94] Content-Range 起始；-1=无 */

  int      status;             /* HTTP 状态码；0 = 没拿到响应 */
  size_t   body_len;           /* 落进 body / 交给 sink 的字节数 */
  int      body_truncated;     /* 1 = 超过 body_cap 被截断（仅 get） */
  long long content_len;       /* 头里的 Content-Length；-1 = 没有 */
  char     www_auth[256];      /* WWW-Authenticate 头（空串=无）*/
  int      chunked;            /* [§90] 1 = Transfer-Encoding: chunked（已解码）*/
  int      redirects;          /* [§90] 跟随的重定向跳数 */
  char     location[640];      /* [§90] 最后一次的 Location 头（诊断）;
                                * [§94] 256 → 640：CloudFront 签名 URL 实测 558 */
};

/* 流式回调：buf/len 是一块响应体；返回非 0 = 调用方要求中止（下载
 * 会以 -8 失败收场）。buf 不保证 NUL 结尾。 */
typedef int (*ort_http_sink_t)(FAR void *arg, FAR const char *buf,
                               size_t len);

/* 返回 0 = 完成了一次 HTTP 交换（状态码在 resp->status，哪怕是 4xx/5xx）；
 * 负值 = 传输层失败。速查：-1 连接/解析失败，-2 socket，-3 连接重试尽，
 * -4 写失败，-5/-6 响应行/头读取失败，-7 定长短读，-8 sink 中止，
 * -9 畸形 chunk / Location 形态非法 / 跳转超缓冲，-10 重定向超限，
 * -11 请求或响应头超缓冲（[§94]，真 Hub token 2698B 实证）。 */

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

/* [ORT §94] 断点续传：from>0 时发 `Range: bytes=<from>-`；206 且
 * resp->content_range_from == from ⇒ 续传成立（sink 收到的从 from 起）；
 * 200 ⇒ 服务端忽略 Range，调用方须从头重来（截断重收）。 */

int ort_http_get_stream_from(FAR const char *host, unsigned port,
                             FAR const char *path,
                             FAR const char *bearer,
                             FAR const char *accept,
                             FAR ort_http_sink_t sink, FAR void *arg,
                             FAR struct ort_http_resp_s *resp,
                             long long from);

/* [ORT §94] TLS 后端开关（进程内单调）：capath 指定 CA（可多证书
 * 拼接的束）；启用后**所有**请求走 TLS（含 token/重定向各跳，SNI/CN
 * 逐跳用当次 host）。返回 0/负值。 */

int ort_http_set_tls(FAR const char *capath);

#endif /* __APPS_TESTING_ORTIMG_ORT_HTTP_H */
