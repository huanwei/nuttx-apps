/****************************************************************************
 * testing/ortimg/ortimg_battery.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] 受限 JSON 的**同一份电池**，两个环境跑：
 *   · 宿主机（gcc，scripts/ortimg-jsontest-host.sh）
 *   · 目标机（qemu-armv7a，`ortimg jsontest`）
 * 老规矩：**"两边都通过"没有信息量，"两边逐字相同"才有。**
 *
 * 用例分三类：
 *   正例（P*）：必须 OK，且带字段断言（层数等）
 *   负例（N*）：必须**恰好**报出指定错误（不是"报错了就行"——
 *               报错类型错 = 判据分不清病理 = 假通过）
 *   文件例：真实 registry 夹具（host 传入路径；目标走 /system hostfs）
 ****************************************************************************/

#ifndef __APPS_TESTING_ORTIMG_ORTIMG_BATTERY_H
#define __APPS_TESTING_ORTIMG_ORTIMG_BATTERY_H

#include <stdio.h>
#include <string.h>

#include "ort_json.h"

/* 一个合法 digest（sha256: + 64 个小写 0） */

#define D64 \
  "0000000000000000000000000000000000000000000000000000000000000000"
#define D64B \
  "1111111111111111111111111111111111111111111111111111111111111111"

struct ort_case_s
{
  FAR const char *name;
  FAR const char *json;
  int             expect;        /* 期望的 ort_json_err_e */
  int             expect_layers; /* expect==OK 时断言层数；-1 = 不断言 */
};

static const struct ort_case_s g_ort_cases[] =
{
  /* ── 正例 ─────────────────────────────────────────────────────── */

  { "P1 最小合法 manifest（单层）",
    "{\"schemaVersion\":2,"
    "\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
    "\"digest\":\"sha256:" D64 "\",\"size\":611},"
    "\"layers\":[{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\","
    "\"digest\":\"sha256:" D64B "\",\"size\":3849738}]}",
    ORT_JSON_OK, 1 },

  { "P2 未知字段被跳过 + 注释串内转义",
    "{\"unknown_top\":[1,2,{\"nested\":true}],"
    "\"schemaVersion\":2,"
    "\"annotations\":{\"note\":\"a\\\"b\\\\c\\n\\t\"},"
    "\"config\":{\"extra\":\"skip\",\"digest\":\"sha256:" D64 "\",\"size\":1},"
    "\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":2,\"urls\":null}],"
    "\"tail_unknown\":12345}",
    ORT_JSON_OK, 1 },

  { "P3 空白/换行包裹",
    "\n \t{\r\n \"schemaVersion\" : 2 , "
    "\"config\" : { \"digest\" : \"sha256:" D64 "\" , \"size\" : 0 } , "
    "\"layers\" : [ { \"digest\" : \"sha256:" D64B "\" , \"size\" : 9 } ]\n}\t ",
    ORT_JSON_OK, 1 },

  { "P4 两层（层序保持）",
    "{\"schemaVersion\":2,"
    "\"config\":{\"digest\":\"sha256:" D64 "\",\"size\":1},"
    "\"layers\":["
    "{\"digest\":\"sha256:" D64 "\",\"size\":100},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":200}]}",
    ORT_JSON_OK, 2 },

  { "P5 UTF-8 原字节（非转义）通过",
    "{\"schemaVersion\":2,"
    "\"annotations\":{\"cn\":\"\xe9\xa1\xba\xe5\xba\x8f\"},"
    "\"config\":{\"digest\":\"sha256:" D64 "\",\"size\":1},"
    "\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":1}]}",
    ORT_JSON_OK, 1 },

  { "P6 schemaVersion 出现在最后（顺序无关）",
    "{\"config\":{\"digest\":\"sha256:" D64 "\",\"size\":1},"
    "\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":1}],"
    "\"schemaVersion\":2}",
    ORT_JSON_OK, 1 },

  /* ── 负例：必须精确报出指定错 ─────────────────────────────────── */

  { "N1 空输入", "", ORT_JSON_E_REQUIRED, 0 },
  { "N2 只开了个花括号", "{", ORT_JSON_E_SHORT, 0 },
  { "N3 空对象", "{}", ORT_JSON_E_REQUIRED, 0 },

  { "N4 schemaVersion=1（旧版本）",
    "{\"schemaVersion\":1,"
    "\"config\":{\"digest\":\"sha256:" D64 "\",\"size\":1},"
    "\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":1}]}",
    ORT_JSON_E_SCHEMA, 0 },

  { "N5 顶层值后有垃圾",
    "{\"schemaVersion\":2,"
    "\"config\":{\"digest\":\"sha256:" D64 "\",\"size\":1},"
    "\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":1}]}x",
    ORT_JSON_E_TRAILING, 0 },

  { "N6 深度炸弹（未知字段里 9 层数组）",
    "{\"x\":[[[[[[[[[[[]]]]]]]]]]],\"schemaVersion\":2}",
    ORT_JSON_E_DEPTH, 0 },

  { "N7 非法转义 \\q",
    "{\"schemaVersion\":2,\"config\":{\"digest\":\"sha256:" D64 "\","
    "\"size\":1},\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":1}],"
    "\"a\":\"\\q\"}",
    ORT_JSON_E_ESCAPE, 0 },

  { "N8 \\uXXXX（明确不支持）",
    "{\"schemaVersion\":2,\"config\":{\"digest\":\"sha256:" D64 "\","
    "\"size\":1},\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":1}],"
    "\"a\":\"\\u0041\"}",
    ORT_JSON_E_ESCAPE, 0 },

  { "N9 浮点数",
    "{\"schemaVersion\":2.0}",
    ORT_JSON_E_NUMBER, 0 },

  { "N10 前导零（严格 JSON）",
    "{\"schemaVersion\":02}",
    ORT_JSON_E_NUMBER, 0 },

  { "N11 uint64 溢出",
    "{\"schemaVersion\":2,"
    "\"config\":{\"digest\":\"sha256:" D64 "\",\"size\":99999999999999999999999},"
    "\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":1}]}",
    ORT_JSON_E_NUMBER, 0 },

  { "N12 负 size",
    "{\"schemaVersion\":2,"
    "\"config\":{\"digest\":\"sha256:" D64 "\",\"size\":-1},"
    "\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":1}]}",
    ORT_JSON_E_NUMBER, 0 },

  { "N13 digest 长度不对",
    "{\"schemaVersion\":2,"
    "\"config\":{\"digest\":\"sha256:abc\",\"size\":1},"
    "\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":1}]}",
    ORT_JSON_E_DIGEST, 0 },

  { "N14 digest 大写 hex（只收小写）",
    "{\"schemaVersion\":2,"
    "\"config\":{\"digest\":\"sha256:"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
    "\"size\":1},"
    "\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":1}]}",
    ORT_JSON_E_DIGEST, 0 },

  { "N15 层数超上限（17 层）",
    "{\"schemaVersion\":2,"
    "\"config\":{\"digest\":\"sha256:" D64 "\",\"size\":1},"
    "\"layers\":["
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1},"
    "{\"digest\":\"sha256:" D64B "\",\"size\":1}]}",
    ORT_JSON_E_LAYERS, 0 },

  { "N16 字符串里裸控制字符",
    "{\"schemaVersion\":2,\"a\":\"x\x01y\"}",
    ORT_JSON_E_SYNTAX, 0 },

  { "N17 缺冒号",
    "{\"schemaVersion\" 2}",
    ORT_JSON_E_SYNTAX, 0 },

  { "N18 单引号不是 JSON",
    "{'schemaVersion':2}",
    ORT_JSON_E_SYNTAX, 0 },

  { "N19 顶层数组（合法 JSON，不是 manifest）",
    "[1,2,3]",
    ORT_JSON_E_REQUIRED, 0 },

  { "N20 层数组为空",
    "{\"schemaVersion\":2,"
    "\"config\":{\"digest\":\"sha256:" D64 "\",\"size\":1},"
    "\"layers\":[]}",
    ORT_JSON_E_REQUIRED, 0 },

  { "N21 config 缺 size",
    "{\"schemaVersion\":2,"
    "\"config\":{\"digest\":\"sha256:" D64 "\"},"
    "\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":1}]}",
    ORT_JSON_E_REQUIRED, 0 },

  { "N22 截断在字符串中间",
    "{\"schemaVersion\":2,\"config\":{\"digest\":\"sha256:aaa",
    ORT_JSON_E_SHORT, 0 },
};

#define ORT_NCASES (sizeof(g_ort_cases) / sizeof(g_ort_cases[0]))

/* ── 运行器：返回失败数 ─────────────────────────────────────────────── */

static int ort_battery_run(FAR FILE *out)
{
  size_t i;
  int    fails = 0;

  for (i = 0; i < ORT_NCASES; i++)
    {
      FAR const struct ort_case_s *tc = &g_ort_cases[i];
      struct ort_manifest_s mf;
      int got = ort_manifest_parse(tc->json, strlen(tc->json), &mf);

      if (got != tc->expect)
        {
          fprintf(out, "[jtest] FAIL %s: got=%s expect=%s\n",
                  tc->name, ort_json_strerror(got),
                  ort_json_strerror(tc->expect));
          fails++;
          continue;
        }

      if (got == ORT_JSON_OK && tc->expect_layers >= 0 &&
          (int)mf.nlayers != tc->expect_layers)
        {
          fprintf(out, "[jtest] FAIL %s: layers=%u expect=%d\n",
                  tc->name, (unsigned)mf.nlayers, tc->expect_layers);
          fails++;
          continue;
        }

      fprintf(out, "[jtest] ok   %s\n", tc->name);
    }

  /* 非 NUL 结尾：把 P1 的字节拷进**恰好等长**的缓冲，紧贴另一块数据，
   * 解析器必须只读 len 界内（越界会把隔壁字节读进来，判据就脏了）。 */

  {
    static const char p1[] =
      "{\"schemaVersion\":2,"
      "\"config\":{\"digest\":\"sha256:" D64 "\",\"size\":1},"
      "\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":1}]}";
    static char raw[sizeof(p1) + 16];
    struct ort_manifest_s mf;
    int got;

    memcpy(raw, p1, sizeof(p1) - 1);
    memset(raw + sizeof(p1) - 1, 'Z', 16);   /* 隔壁是垃圾数据 */

    got = ort_manifest_parse(raw, sizeof(p1) - 1, &mf);
    if (got != ORT_JSON_OK || mf.nlayers != 1)
      {
        fprintf(out, "[jtest] FAIL P7 非 NUL 结尾（len 界内解析）: %s\n",
                ort_json_strerror(got));
        fails++;
      }
    else
      {
        fprintf(out, "[jtest] ok   P7 非 NUL 结尾（len 界内解析）\n");
      }
  }

  /* 超长输入：> ORT_JSON_MAX_INPUT 必须 E_SIZE，不读正文 */

  {
    static char big[ORT_JSON_MAX_INPUT + 16];
    int got;

    memset(big, ' ', sizeof(big));
    got = ort_manifest_parse(big, sizeof(big), NULL);
    if (got != ORT_JSON_E_SIZE)
      {
        fprintf(out, "[jtest] FAIL N23 超长输入: got=%s expect=SIZE\n",
                ort_json_strerror(got));
        fails++;
      }
    else
      {
        fprintf(out, "[jtest] ok   N23 超长输入（>64KB 拒，不读正文）\n");
      }
  }

  return fails;
}

#endif /* __APPS_TESTING_ORTIMG_ORTIMG_BATTERY_H */
