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

#include "ort_json.h"
#include "ortimg_battery.h"

#define ORTIMG_MAX_FILE  (ORT_JSON_MAX_INPUT + 1)

static FAR char *g_buf;

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
  struct ort_manifest_s mf;
  size_t len = 0;
  int ret;
  uint32_t i;

  if (read_file(path, &len) != 0)
    {
      return 2;
    }

  ret = ort_manifest_parse(g_buf, len, &mf);
  if (ret != ORT_JSON_OK)
    {
      printf("[ortimg] manifest 拒绝: %s（%zu 字节）\n",
             ort_json_strerror(ret), len);
      return 1;
    }

  printf("[ortimg] manifest OK（%zu 字节）\n", len);
  printf("[ortimg]   schemaVersion=%u mediaType=%s\n",
         (unsigned)mf.schema_version,
         mf.media_type[0] ? mf.media_type : "(缺省)");
  printf("[ortimg]   config: %s size=%llu\n",
         mf.config_digest, (unsigned long long)mf.config_size);
  printf("[ortimg]   层数=%u（白名单外字段跳过 %u 个）\n",
         (unsigned)mf.nlayers, (unsigned)mf.ignored_fields);
  for (i = 0; i < mf.nlayers && i < 3; i++)
    {
      printf("[ortimg]   layer[%u]: %s size=%llu\n", (unsigned)i,
             mf.layers[i].digest, (unsigned long long)mf.layers[i].size);
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
             (unsigned)ORT_NCASES);
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

  printf("用法: orting jsontest | manifest <path> | validate <path>\n");
  free(g_buf);
  return 2;
}
