/****************************************************************************
 * testing/ortimg/host/hosttest.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] 宿主机侧电池（与目标机 `ortimg jsontest` 同一份用例表）。
 * 编译：scripts/ortimg-jsontest-host.sh（gcc，不需要 NuttX）。
 * 用法：hosttest <fixtures-dir>
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../ort_json.h"
#include "../ortimg_battery.h"

static char *slurp(const char *path, size_t *len)
{
  FILE *f = fopen(path, "rb");
  char *buf;
  size_t n;

  if (f == NULL) { printf("[host] 打不开 %s\n", path); return NULL; }
  buf = malloc(ORT_JSON_MAX_INPUT + 1);
  n = fread(buf, 1, ORT_JSON_MAX_INPUT, f);
  fclose(f);
  buf[n] = '\0';
  *len = n;
  return buf;
}

static int check(const char *name, int got, int expect)
{
  if (got != expect)
    {
      printf("[host] FAIL %s: got=%s expect=%s\n", name,
             ort_json_strerror(got), ort_json_strerror(expect));
      return 1;
    }
  printf("[host] ok   %s\n", name);
  return 0;
}

int main(int argc, char *argv[])
{
  const char *dir = argc > 1 ? argv[1] : "../fixtures";
  char path[512];
  int fails = 0;
  int got;

  /* 1) 内联电池（与目标机逐字同一份） */

  fails += ort_battery_run(stdout);

  /* 2) 真实夹具：alpine image manifest（含 annotations，白名单跳过） */

  {
    struct ort_manifest_s mf;
    size_t len;
    char *buf;

    snprintf(path, sizeof(path), "%s/alpine-manifest.json", dir);
    buf = slurp(path, &len);
    if (buf == NULL) { return 2; }

    got = ort_manifest_parse(buf, len, &mf);
    fails += check("F1 真实 alpine image manifest", got, ORT_JSON_OK);
    if (got == ORT_JSON_OK)
      {
        if (mf.nlayers != 1 || mf.schema_version != 2 ||
            strncmp(mf.config_digest, "sha256:320994c3", 15) != 0 ||
            mf.ignored_fields < 1 /* annotations 必须被计数 */)
          {
            printf("[host] FAIL F1 字段断言: layers=%u cfg=%.15s ignored=%u\n",
                   (unsigned)mf.nlayers, mf.config_digest,
                   (unsigned)mf.ignored_fields);
            fails++;
          }
        else
          {
            printf("[host] ok   F1 字段断言（层数/配置摘要/跳过计数）\n");
          }
      }
    free(buf);
  }

  /* 3) 真实 index（manifest list）：必须被拒 —— 那是上层平台选择的活 */

  {
    size_t len;
    char *buf;

    snprintf(path, sizeof(path), "%s/alpine-index.json", dir);
    buf = slurp(path, &len);
    if (buf == NULL) { return 2; }
    got = ort_json_validate(buf, len);
    fails += check("F2 真实 index 是合法 JSON", got, ORT_JSON_OK);
    /* 用 manifest 解析器吃它 → 必须 REQUIRED（没有 config/layers） */
    {
      struct ort_manifest_s mf;
      got = ort_manifest_parse(buf, len, &mf);
      fails += check("F3 index 不被当 image manifest", got,
                     ORT_JSON_E_REQUIRED);
    }
    free(buf);
  }

  /* 4) 截断的真实 manifest（取前 300 字节）→ 必须被拒（不是 OK） */

  {
    size_t len;
    char *buf;
    struct ort_manifest_s mf;

    snprintf(path, sizeof(path), "%s/alpine-manifest.json", dir);
    buf = slurp(path, &len);
    if (buf == NULL) { return 2; }
    got = ort_manifest_parse(buf, len > 300 ? 300 : len, &mf);
    if (got == ORT_JSON_OK)
      {
        printf("[host] FAIL F4 截断输入被当成 OK\n");
        fails++;
      }
    else
      {
        printf("[host] ok   F4 截断输入被拒（%s）\n", ort_json_strerror(got));
      }
    free(buf);
  }

  printf("[host] HOSTTEST RESULT: %s\n", fails == 0 ? "PASS" : "*** FAIL ***");
  return fails == 0 ? 0 : 1;
}
