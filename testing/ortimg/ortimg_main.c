/****************************************************************************
 * testing/ortimg/ortimg_main.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] ort_image 的第一块砖：受限 JSON + OCI manifest 提取。
 * 用法（nsh）：
 *   orting jsontest              —— 跑双环境电池（与宿主机同一份）
 *   orting manifest <path>       —— 解析一份真实 manifest 并打印字段
 *   orting validate <path>       —— 通用 JSON 校验（只报错名）
 *
 * 目标机上 /system 是 hostfs（宿主 nuttx-apps 树），所以夹具直接用
 * 仓库里的路径：/system/testing/ortimg/fixtures/xxx.json
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "ort_json.h"
#include "ortimg_battery.h"
#include "ort_http.h"

#define ORTIMG_MAX_FILE  (ORT_JSON_MAX_INPUT + 1)

static FAR char *g_buf;

/* ★ 大件全静态：app 栈只有 4KB（CONFIG_TESTING_ORTIMG_STACKSIZE），
 *   16KB 响应体和 index(32 条)/manifest(16 层) 结构都放不进栈。 */

static char g_http_body[16384];
static char g_http_body2[16384];
static char g_token[4096];
static struct ort_index_s    g_idx;
static struct ort_manifest_s g_mf;

static int read_file(FAR const char *path, FAR size_t *out_len)
{
  FAR FILE *f = fopen(path, "rb");
  size_t n;

  if (f == NULL)
    {
      printf("[ortimg] 打不开 %s\n", path);
      return -1;
    }

  n = fread(g_buf, 1, ORT_JSON_MAX_INPUT, f);
  fclose(f);

  if (n >= ORT_JSON_MAX_INPUT)
    {
      /* 注：>= 是保守写法 —— 可能正好读完也可能还有；manifest 现实尺寸
       * 是 KB 级，读满 64KB 本身就是"这不像是 manifest" */
    }

  *out_len = n;
  g_buf[n] = '\0';
  return 0;
}

static int do_manifest(FAR const char *path)
{
  FAR struct ort_manifest_s *mf = &g_mf;   /* ★ 静态（栈 ~2KB，见 do_pull 注） */
  size_t len = 0;
  int ret;
  uint32_t i;

  if (read_file(path, &len) != 0)
    {
      return 2;
    }

  ret = ort_manifest_parse(g_buf, len, mf);
  if (ret != ORT_JSON_OK)
    {
      printf("[ortimg] manifest 拒绝: %s（%zu 字节）\n",
             ort_json_strerror(ret), len);
      return 1;
    }

  printf("[ortimg] manifest OK（%zu 字节）\n", len);
  printf("[ortimg]   schemaVersion=%u mediaType=%s\n",
         (unsigned)mf->schema_version,
         mf->media_type[0] ? mf->media_type : "(缺省)");
  printf("[ortimg]   config: %s size=%llu\n",
         mf->config_digest, (unsigned long long)mf->config_size);
  printf("[ortimg]   层数=%u（白名单外字段跳过 %u 个）\n",
         (unsigned)mf->nlayers, (unsigned)mf->ignored_fields);
  for (i = 0; i < mf->nlayers && i < 3; i++)
    {
      printf("[ortimg]   layer[%u]: %s size=%llu\n", (unsigned)i,
             mf->layers[i].digest, (unsigned long long)mf->layers[i].size);
    }
  return 0;
}

static int do_validate(FAR const char *path)
{
  size_t len = 0;
  int ret;

  if (read_file(path, &len) != 0)
    {
      return 2;
    }

  ret = ort_json_validate(g_buf, len);
  printf("[ortimg] validate: %s（%zu 字节）\n", ort_json_strerror(ret), len);
  return ret == ORT_JSON_OK ? 0 : 1;
}

/* ── registry pull（A1：明文 HTTP 全流程；TLS 是下一增量）────────────── */

static int url_split(FAR const char *url, FAR char *host, size_t hostcap,
                     FAR unsigned *port, FAR char *path, size_t pathcap)
{
  FAR const char *p = url;

  if (strncmp(p, "http://", 7) == 0)
    {
      p += 7;
    }

  {
    FAR const char *slash = strchr(p, '/');
    FAR const char *colon = strchr(p, ':');
    size_t hlen;

    if (slash == NULL)
      {
        return -1;
      }

    if (colon != NULL && colon < slash)
      {
        hlen = (size_t)(colon - p);
        *port = (unsigned)atoi(colon + 1);
      }
    else
      {
        hlen = (size_t)(slash - p);
        *port = 80;
      }

    if (hlen == 0 || hlen >= hostcap)
      {
        return -1;
      }

    memcpy(host, p, hlen);
    host[hlen] = '\0';
    strlcpy(path, slash, pathcap);
  }

  return 0;
}

static void attr_get(FAR const char *hdr, FAR const char *name,
                     FAR char *out, size_t cap)
{
  char   pat[24];
  FAR const char *p;

  snprintf(pat, sizeof(pat), "%s=\"", name);
  p = strstr(hdr, pat);
  out[0] = '\0';
  if (p != NULL)
    {
      p += strlen(pat);
      while (*p != '\0' && *p != '"' && cap > 1)
        {
          *out++ = *p++;
          cap--;
        }
      *out = '\0';
    }
}

static int do_pull(FAR const char *host, unsigned port, FAR const char *repo,
                   FAR const char *tag)
{
  static struct ort_http_resp_s r;         /* ★ 全静态：目标机 app 栈 ~2KB */
  static char   path[320];
  static char   realm[256], service[64], scope[160];
  int    ret;
  int    step = 0;

  /* 1) /v2/：拿 401 挑战（或 200 = 开放仓库） */

  ret = ort_http_get(host, port, "/v2/", NULL, NULL,
                     g_http_body, sizeof(g_http_body), &r);
  if (ret != 0)
    {
      printf("[pull] 连不上 %s:%u（%d，errno=%d）\n", host, port, ret, errno);
      return 2;
    }

  printf("[pull] ① /v2/ → %d\n", r.status);

  if (r.status == 401)
    {
      attr_get(r.www_auth, "realm", realm, sizeof(realm));
      attr_get(r.www_auth, "service", service, sizeof(service));
      attr_get(r.www_auth, "scope", scope, sizeof(scope));
      printf("[pull]    挑战: realm=%s service=%s scope=%s\n",
             realm[0] ? realm : "(无)", service[0] ? service : "(无)",
             scope[0] ? scope : "(无)");

      /* 2) token 端点：真流程拿 token；scope 缺省时按 repo 构造 */

      {
        static char thost[64], tpath[160];
        static char q[320];
        unsigned tport = 80;
        char *sc = scope[0] ? scope : NULL;
        static char scbuf[160];

        if (sc == NULL)
          {
            snprintf(scbuf, sizeof(scbuf), "repository:%s:pull", repo);
            sc = scbuf;
          }

        if (url_split(realm, thost, sizeof(thost), &tport,
                      tpath, sizeof(tpath)) != 0)
          {
            printf("[pull] realm 解析失败\n");
            return 2;
          }

        snprintf(q, sizeof(q), "%s?service=%s&scope=%s", tpath, service, sc);

        ret = ort_http_get(thost, tport, q, NULL, NULL,
                           g_http_body, sizeof(g_http_body), &r);
        if (ret != 0)
          {
            printf("[pull] token 端点不可达（%d）\n", ret);
            return 2;
          }

        printf("[pull] ② token → %d\n", r.status);

        ret = ort_json_get_str(g_http_body, r.body_len, "token",
                               g_token, sizeof(g_token));
        if (ret != ORT_JSON_OK)
          {
            printf("[pull] token 提取失败: %s\n", ort_json_strerror(ret));
            return 1;
          }

        printf("[pull]    token 长度=%zu\n", strlen(g_token));
      }
    }
  else if (r.status != 200)
    {
      printf("[pull] /v2/ 异常状态 %d\n", r.status);
      return 1;
    }

  /* 3) 取 manifest（按 tag）——先当 index 试，再当 manifest 试 */

  snprintf(path, sizeof(path), "/v2/%s/manifests/%s", repo, tag);

  ret = ort_http_get(host, port, path, g_token[0] ? g_token : NULL,
                     "application/vnd.oci.image.index.v1+json, "
                     "application/vnd.oci.image.manifest.v1+json",
                     g_http_body, sizeof(g_http_body), &r);
  if (ret != 0)
    {
      printf("[pull] manifest 请求失败（%d）\n", ret);
      return 2;
    }

  printf("[pull] ③ %s → %d（%zu 字节）\n", path, r.status, r.body_len);
  if (r.status != 200)
    {
      printf("[pull]    拒绝: %s\n", g_http_body);
      return 1;
    }

  ret = ort_index_parse(g_http_body, r.body_len, &g_idx);
  if (ret == ORT_JSON_OK)
    {
      uint32_t i;
      int picked = -1;

      printf("[pull]    是 image index：%u 条\n", (unsigned)g_idx.nentries);
      for (i = 0; i < g_idx.nentries; i++)
        {
          printf("[pull]      [%u] %s %s/%s%s%s\n", (unsigned)i,
                 g_idx.entries[i].digest,
                 g_idx.entries[i].os, g_idx.entries[i].arch,
                 g_idx.entries[i].variant[0] ? "/" : "",
                 g_idx.entries[i].variant);

          if (picked < 0 && strcmp(g_idx.entries[i].os, "linux") == 0 &&
              strcmp(g_idx.entries[i].arch, "arm") == 0)
            {
              picked = (int)i;
            }
        }

      if (picked < 0)
        {
          printf("[pull]    没有 linux/arm 条目\n");
          return 1;
        }

      printf("[pull]    选 [%d]（linux/arm）→ 按 digest 再取\n", picked);

      snprintf(path, sizeof(path), "/v2/%s/manifests/%s", repo,
               g_idx.entries[picked].digest);

      ret = ort_http_get(host, port, path, g_token[0] ? g_token : NULL,
                         "application/vnd.oci.image.manifest.v1+json",
                         g_http_body2, sizeof(g_http_body2), &r);
      if (ret != 0 || r.status != 200)
        {
          printf("[pull]    digest 取回失败（%d/%d）\n", ret, r.status);
          return 2;
        }

      printf("[pull] ④ digest manifest → 200（%zu 字节）\n", r.body_len);
      step = 1;
    }
  else if (ret == ORT_JSON_E_REQUIRED)
    {
      printf("[pull]    不是 index，直接当 image manifest\n");
      memcpy(g_http_body2, g_http_body, r.body_len);
      step = 1;
    }
  else
    {
      printf("[pull]    index 解析报 %s\n", ort_json_strerror(ret));
      return 1;
    }

  /* 4) 最终 manifest */

  if (step)
    {
      ret = ort_manifest_parse(g_http_body2, r.body_len, &g_mf);
      if (ret != ORT_JSON_OK)
        {
          /* index 路径下 body2 长度是重新取的 r.body_len；manifest 直取路径
           * 下 memcpy 过一份、长度相同 —— 两条路共用这一段 */
          printf("[pull] manifest 解析失败: %s\n", ort_json_strerror(ret));
          return 1;
        }

      printf("[pull] ⑤ manifest: schema=%u 层数=%u（跳过未知字段 %u）\n",
             (unsigned)g_mf.schema_version, (unsigned)g_mf.nlayers,
             (unsigned)g_mf.ignored_fields);
      printf("[pull]    config %s (%llu)\n", g_mf.config_digest,
             (unsigned long long)g_mf.config_size);

      {
        uint32_t i;

        for (i = 0; i < g_mf.nlayers; i++)
          {
            printf("[pull]    layer[%u] %s (%llu)\n", (unsigned)i,
                   g_mf.layers[i].digest,
                   (unsigned long long)g_mf.layers[i].size);
          }
      }

      printf("[pull] PULL RESULT: OK\n");
    }

  return 0;
}

int main(int argc, FAR char *argv[])
{

  g_buf = malloc(ORTIMG_MAX_FILE);
  if (g_buf == NULL)
    {
      printf("[ortimg] 没有内存\n");
      return 2;
    }

  if (argc >= 2 && strcmp(argv[1], "jsontest") == 0)
    {
      int fails = ort_battery_run(stdout);

      printf("[ortimg] JSONTEST RESULT: %s（%u 用例 + 2 特殊例）\n",
             fails == 0 ? "PASS" : "*** FAIL ***",
             (unsigned)(ORT_NCASES + ORT_NSTRCASES + ORT_NIDXCASES));
      free(g_buf);
      return fails == 0 ? 0 : 1;
    }

  if (argc >= 3 && strcmp(argv[1], "manifest") == 0)
    {
      int r = do_manifest(argv[2]);
      free(g_buf);
      return r;
    }

  if (argc >= 3 && strcmp(argv[1], "validate") == 0)
    {
      int r = do_validate(argv[2]);
      free(g_buf);
      return r;
    }

  if (argc >= 5 && strcmp(argv[1], "httpget") == 0)
    {
      /* httpget <host> <port> <path> —— 连通性诊断 */
      struct ort_http_resp_s r;
      int rret = ort_http_get(argv[2], (unsigned)atoi(argv[3]), argv[4],
                              NULL, NULL, g_http_body, sizeof(g_http_body),
                              &r);

      if (rret != 0)
        {
          printf("[ortimg] httpget 传输失败（%d，errno=%d）\n", rret, errno);
          free(g_buf);
          return 2;
        }

      printf("[ortimg] httpget → %d（体 %zu 字节%s）\n", r.status,
             r.body_len, r.body_truncated ? "，截断" : "");
      if (r.www_auth[0])
        {
          printf("[ortimg] WWW-Authenticate: %s\n", r.www_auth);
        }
      free(g_buf);
      return 0;
    }

  if (argc >= 6 && strcmp(argv[1], "pull") == 0)
    {
      /* pull <host> <port> <repo> <tag> */
      int r = do_pull(argv[2], (unsigned)atoi(argv[3]), argv[4], argv[5]);
      free(g_buf);
      return r;
    }

  printf("用法: orting jsontest | manifest <path> | validate <path> |\n"
         "      httpget <host> <port> <path> | pull <host> <port> <repo> <tag>\n");
  free(g_buf);
  return 2;
}
