/****************************************************************************
 * testing/ortimg/ort_http.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] 极简 HTTP/1.0 GET（registry 客户端的地基）。
 *
 * 刻意不支持的东西（每一件都有明确的理由，不是"还没做"）：
 *   · chunked 传编码 —— 本增量先要求 Content-Length；registry 的
 *     manifest 响应都带长度。**如实标注**：真 Docker Hub 万一走
 *     chunked，增量二再补（判据：fixture 服务器无法覆盖真实行为）
 *   · HTTP/1.1 keep-alive —— 用 1.0 + Connection: close，读到 EOF 为止
 *   · TLS —— 增量二（mbedTLS）；本增量对 fixture 服务器走明文
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
  size_t   body_len;           /* 落进 body 的字节数          */
  int      body_truncated;     /* 1 = 超过 body_cap 被截断    */
  char     www_auth[256];      /* WWW-Authenticate 头（空串=无）*/
};

/* 返回 0 = 完成了一次 HTTP 交换（状态码在 resp->status，哪怕是 4xx/5xx）；
 * 负值 = 传输层失败（连不上/断流/解析不了响应行）。 */

int ort_http_get(FAR const char *host, unsigned port,
                 FAR const char *path,
                 FAR const char *bearer,      /* 可空：Authorization: Bearer */
                 FAR const char *accept,      /* 可空：Accept 头 */
                 FAR char *body, size_t body_cap,
                 FAR struct ort_http_resp_s *resp);

#endif /* __APPS_TESTING_ORTIMG_ORT_HTTP_H */
