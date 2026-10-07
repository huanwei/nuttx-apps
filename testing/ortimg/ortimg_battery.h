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

/* ── get_str 用例（registry 握手取 token）───────────────────────────── */

struct ort_strcase_s
{
  FAR const char *name;
  FAR const char *json;
  FAR const char *key;
  size_t          cap;
  int             expect;
  FAR const char *expect_val;   /* expect==OK 时断言取值 */
};

static const struct ort_strcase_s g_ort_strcases[] =
{
  { "G1 正常取到 token", "{\"token\":\"abc.def.ghi\"}",
    "token", 64, ORT_JSON_OK, "abc.def.ghi" },
  { "G2 缺字段 → REQUIRED", "{\"a\":1}", "token", 64,
    ORT_JSON_E_REQUIRED, NULL },
  { "G3 值不是字符串 → SYNTAX", "{\"token\":123}", "token", 64,
    ORT_JSON_E_SYNTAX, NULL },
  { "G4 超过 cap → SYNTAX",
    "{\"token\":\"0123456789012345678901234567890123456789\"}",
    "token", 16, ORT_JSON_E_SYNTAX, NULL },
  { "G5 只认顶层（嵌套找不到）",
    "{\"x\":{\"token\":\"a\"}}", "token", 64,
    ORT_JSON_E_REQUIRED, NULL },
  { "G6 重复键取先出现的",
    "{\"token\":\"first\",\"token\":\"second\"}", "token", 64,
    ORT_JSON_OK, "first" },
};

#define ORT_NSTRCASES (sizeof(g_ort_strcases) / sizeof(g_ort_strcases[0]))

/* ── index 用例 ────────────────────────────────────────────────────── */

struct ort_idxcase_s
{
  FAR const char *name;
  FAR const char *json;
  int             expect;
  int             expect_n;      /* expect==OK 时断言条数 */
};

static const struct ort_idxcase_s g_ort_idxcases[] =
{
  { "I1 两条 index（合法）",
    "{\"schemaVersion\":2,"
    "\"mediaType\":\"application/vnd.oci.image.index.v1+json\","
    "\"manifests\":["
    "{\"digest\":\"sha256:" D64 "\","
    "\"platform\":{\"os\":\"linux\",\"architecture\":\"amd64\"}},"
    "{\"digest\":\"sha256:" D64B "\","
    "\"platform\":{\"os\":\"linux\",\"architecture\":\"arm\","
    "\"variant\":\"v7\"}}]}",
    ORT_JSON_OK, 2 },

  { "I2 image manifest 进 index 解析器 → REQUIRED",
    "{\"schemaVersion\":2,"
    "\"config\":{\"digest\":\"sha256:" D64 "\",\"size\":1},"
    "\"layers\":[{\"digest\":\"sha256:" D64B "\",\"size\":1}]}",
    ORT_JSON_E_REQUIRED, 0 },

  { "I3 条目缺 platform → REQUIRED",
    "{\"schemaVersion\":2,"
    "\"manifests\":[{\"digest\":\"sha256:" D64 "\"}]}",
    ORT_JSON_E_REQUIRED, 0 },

  { "I4 条目 digest 非法 → DIGEST",
    "{\"schemaVersion\":2,"
    "\"manifests\":[{\"digest\":\"sha256:zz\","
    "\"platform\":{\"os\":\"linux\",\"architecture\":\"arm\"}}]}",
    ORT_JSON_E_DIGEST, 0 },
};

#define ORT_NIDXCASES (sizeof(g_ort_idxcases) / sizeof(g_ort_idxcases[0]))

/* ── image config 用例（config blob）────────────────────────────────── */

struct ort_cfgcase_s
{
  FAR const char *name;
  FAR const char *json;
  int             expect;
  int             expect_ep;     /* expect==OK 时断言条数；-1 不断言 */
  int             expect_cmd;
  int             expect_env;
};

static const struct ort_cfgcase_s g_ort_cfgcases[] =
{
  { "CF1 完整合法（ep2/cmd1/env2/wd）",
    "{\"architecture\":\"arm\",\"os\":\"linux\","
    "\"config\":{\"Env\":[\"PATH=/bin\",\"ORT=1\"],"
    "\"Entrypoint\":[\"/bin/orthello\",\"--t\"],"
    "\"Cmd\":[\"/etc/hello.txt\"],\"WorkingDir\":\"/tmp/wd\"}}",
    ORT_JSON_OK, 2, 1, 2 },

  { "CF2 缺 config 对象 → REQUIRED",
    "{\"architecture\":\"arm\",\"os\":\"linux\"}",
    ORT_JSON_E_REQUIRED, 0, 0, 0 },

  { "CF3 Entrypoint 是字符串 → SYNTAX",
    "{\"architecture\":\"arm\",\"os\":\"linux\","
    "\"config\":{\"Entrypoint\":\"/bin/x\"}}",
    ORT_JSON_E_SYNTAX, 0, 0, 0 },

  { "CF4 Entrypoint 超上限（9 项）→ LIMIT（不截断）",
    "{\"architecture\":\"arm\",\"os\":\"linux\","
    "\"config\":{\"Entrypoint\":["
    "\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\",\"h\",\"i\"]}}",
    ORT_JSON_E_LIMIT, 0, 0, 0 },

  { "CF5 既无 Entrypoint 也无 Cmd → REQUIRED",
    "{\"architecture\":\"arm\",\"os\":\"linux\","
    "\"config\":{\"Env\":[\"A=B\"]}}",
    ORT_JSON_E_REQUIRED, 0, 0, 0 },

  { "CF6 未知字段跳过（rootfs/history）且计数",
    "{\"architecture\":\"arm\",\"os\":\"linux\","
    "\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[\"sha256:00\"]},"
    "\"history\":[{\"created_by\":\"x\"}],"
    "\"annotations\":{\"k\":\"v\"},"
    "\"config\":{\"Cmd\":[\"run\"]}}",
    ORT_JSON_OK, 0, 1, 0 },
};

#define ORT_NCFGCASES (sizeof(g_ort_cfgcases) / sizeof(g_ort_cfgcases[0]))

/* ── 运行器：返回失败数 ─────────────────────────────────────────────── */

static int ort_battery_run(FAR FILE *out)
{
  size_t i;
  int    fails = 0;

  {
    static struct ort_manifest_s mf;   /* ★ 静态：帧预算见文件尾注 */

    for (i = 0; i < ORT_NCASES; i++)
    {
      FAR const struct ort_case_s *tc = &g_ort_cases[i];
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

  /* get_str 族 */

  {
    size_t i;

    for (i = 0; i < ORT_NSTRCASES; i++)
      {
        FAR const struct ort_strcase_s *tc = &g_ort_strcases[i];
        char val[128];
        int  got = ort_json_get_str(tc->json, strlen(tc->json), tc->key,
                                    val, tc->cap);

        if (got != tc->expect ||
            (got == ORT_JSON_OK && tc->expect_val != NULL &&
             strcmp(val, tc->expect_val) != 0))
          {
            fprintf(out, "[jtest] FAIL %s\n", tc->name);
            fails++;
          }
        else
          {
            fprintf(out, "[jtest] ok   %s\n", tc->name);
          }
      }
  }

  /* index 族 —— ★ ix 必须 static：struct ort_index_s ≈4.5KB，目标机
   * app 栈默认 4KB —— 放栈上会溢出踩堆、且**无声**（宿主机不限栈所以
   * 宿主全绿、目标卡死；2026-10-06 实测踩过）。 */

  {
    static struct ort_index_s ix;
    size_t i;

    for (i = 0; i < ORT_NIDXCASES; i++)
      {
        FAR const struct ort_idxcase_s *tc = &g_ort_idxcases[i];
        int got = ort_index_parse(tc->json, strlen(tc->json), &ix);

        if (got != tc->expect ||
            (got == ORT_JSON_OK && (int)ix.nentries != tc->expect_n))
          {
            fprintf(out, "[jtest] FAIL %s: got=%s n=%u\n", tc->name,
                    ort_json_strerror(got), (unsigned)ix.nentries);
            fails++;
          }
        else
          {
            fprintf(out, "[jtest] ok   %s\n", tc->name);
          }
      }
  }

  /* config 族 —— ★ cf 静态（struct ort_config_s ≈1.4KB，栈预算同 §61） */

  {
    static struct ort_config_s cf;
    size_t i;

    for (i = 0; i < ORT_NCFGCASES; i++)
      {
        FAR const struct ort_cfgcase_s *tc = &g_ort_cfgcases[i];
        int got = ort_config_parse(tc->json, strlen(tc->json), &cf);

        if (got != tc->expect ||
            (got == ORT_JSON_OK &&
             ((tc->expect_ep >= 0 && (int)cf.nentrypoint != tc->expect_ep) ||
              (tc->expect_cmd >= 0 && (int)cf.ncmd != tc->expect_cmd) ||
              (tc->expect_env >= 0 && (int)cf.nenv != tc->expect_env))))
          {
            fprintf(out, "[jtest] FAIL %s: got=%s ep=%u cmd=%u env=%u\n",
                    tc->name, ort_json_strerror(got),
                    (unsigned)cf.nentrypoint, (unsigned)cf.ncmd,
                    (unsigned)cf.nenv);
            fails++;
          }
        else
          {
            fprintf(out, "[jtest] ok   %s\n", tc->name);
          }
      }
  }

  return fails;
}

/* ── SHA-256 电池（[htest]）────────────────────────────────────────── *
 *
 * 期望值来源：NIST 官方向量（空/abc/56B/1M×'a'）+ python hashlib 交叉
 * 生成（55/56/63/64/65/128 边界、模式串）——**不是**"自己实现自己验"。
 * H11/H12/H13 走 update 分段路径（下载就是流式的），一次性与流式在
 * 边界长度上必须同摘要。
 */

#include "ort_sha256.h"

struct ort_hashcase_s
{
  FAR const char *name;
  FAR const char *data;
  size_t          len;
  FAR const char *hex;
};

/* 128 × 'a'（H4-H9 共用；len 由用例给，字符串本身长 128） */

static const char g_ha[] =
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static const char g_nist56[] =
  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

static const struct ort_hashcase_s g_ort_hashcases[] =
{
  { "H1 空输入",
    "", 0,
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
  { "H2 \"abc\"（NIST）",
    "abc", 3,
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
  { "H3 56B 双块（NIST）",
    g_nist56, 56,
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
  { "H4 55x'a'（尾差 1 到 56）",
    g_ha, 55,
    "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318" },
  { "H5 56x'a'（尾恰 56）",
    g_ha, 56,
    "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a" },
  { "H6 63x'a'（尾差 1 满块）",
    g_ha, 63,
    "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34" },
  { "H7 64x'a'（尾恰满块）",
    g_ha, 64,
    "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb" },
  { "H8 65x'a'（跨块 1 字节）",
    g_ha, 65,
    "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0" },
  { "H9 128x'a'（两块整）",
    g_ha, 128,
    "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e" },
};

#define ORT_NHASHCASES (sizeof(g_ort_hashcases) / sizeof(g_ort_hashcases[0]))
#define ORT_NHASHSPECIAL 4     /* H10-H13：模式串/流式分段特殊例 */

static void hash_case_report(FAR FILE *out, FAR const char *name,
                             FAR const char *got, FAR const char *expect,
                             FAR int *fails)
{
  if (strcmp(got, expect) != 0)
    {
      fprintf(out, "[htest] FAIL %s: got=%s expect=%s\n", name, got, expect);
      (*fails)++;
    }
  else
    {
      fprintf(out, "[htest] ok   %s\n", name);
    }
}

static int ort_hash_battery_run(FAR FILE *out)
{
  /* 模式串缓冲（运行时构造，静态存储 —— 目标机栈预算见 §61 同族注） */

  static char pat300[300];                  /* "0123456789" x 30 */
  static char pat1000[1000];                /* (i*7+3)&0xff */
  char   hex[65];
  uint8_t dg[32];
  size_t i;
  int    fails = 0;

  for (i = 0; i < ORT_NHASHCASES; i++)
    {
      FAR const struct ort_hashcase_s *tc = &g_ort_hashcases[i];

      ort_sha256_oneshot(tc->data, tc->len, dg);
      ort_sha256_hex(dg, hex);
      hash_case_report(out, tc->name, hex, tc->hex, &fails);
    }

  for (i = 0; i < sizeof(pat300); i++)
    {
      pat300[i] = (char)('0' + (i % 10));
    }

  for (i = 0; i < sizeof(pat1000); i++)
    {
      pat1000[i] = (char)((i * 7 + 3) & 0xff);
    }

  /* H10 300B 模式一次性 */

  ort_sha256_oneshot(pat300, sizeof(pat300), dg);
  ort_sha256_hex(dg, hex);
  hash_case_report(out, "H10 300B 模式（一次性）", hex,
                   "ba6ab297dbb2bcbc66d54fb768e01920acb58b5552455834f4563807cbd46efb",
                   &fails);

  /* H11 同数据**逐字节**流式 —— 分段路径在 64B 块边界上的等价性 */

  {
    struct ort_sha256_s c;

    ort_sha256_init(&c);
    for (i = 0; i < sizeof(pat300); i++)
      {
        ort_sha256_update(&c, &pat300[i], 1);
      }

    ort_sha256_final(&c, dg);
    ort_sha256_hex(dg, hex);
    hash_case_report(out, "H11 300B 逐字节流式（=H10）", hex,
                     "ba6ab297dbb2bcbc66d54fb768e01920acb58b5552455834f4563807cbd46efb",
                     &fails);
  }

  /* H12 1000B 乱块粒度流式（7+13+1+64+215+700） */

  {
    struct ort_sha256_s c;
    static const size_t chunks[] = { 7, 13, 1, 64, 215, 700 };
    size_t off = 0;

    ort_sha256_init(&c);
    for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++)
      {
        ort_sha256_update(&c, pat1000 + off, chunks[i]);
        off += chunks[i];
      }

    ort_sha256_final(&c, dg);
    ort_sha256_hex(dg, hex);
    hash_case_report(out, "H12 1000B 乱块粒度流式", hex,
                     "1e9bc38cbf860b9ec31918b065f9b52476c549a782e0e7990bed8ce3868d2371",
                     &fails);
  }

  /* H13 1M x 'a' 按 1024B 块流式（NIST 向量；不占 1MB 内存） */

  {
    struct ort_sha256_s c;
    static char ablk[1024] =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    unsigned int k;

    /* 上面的字面量只有 128 字节（其余被补 0）—— 用首 128 字节铺满 */

    for (k = 128; k < sizeof(ablk); k += 128)
      {
        memcpy(ablk + k, ablk, 128);
      }

    /* 恰好 1,000,000 字节 = 976×1024 + 576（不是 1000×1024！——
     * 多喂 24000 字节就是另一种输入，NIST 向量对不上） */

    ort_sha256_init(&c);
    for (k = 0; k < 976; k++)
      {
        ort_sha256_update(&c, ablk, sizeof(ablk));
      }

    ort_sha256_update(&c, ablk, 576);

    ort_sha256_final(&c, dg);
    ort_sha256_hex(dg, hex);
    hash_case_report(out, "H13 1M x 'a' 流式（NIST）", hex,
                     "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
                     &fails);
  }

  return fails;
}

/* ── tar 电池（[ttest]）────────────────────────────────────────────── *
 *
 * 用例图在内存里现造（timg_* 小工具），落 /tmp 临时文件后走真实文件
 * 路径 —— 双环境同一份造图代码，避免"宿主 python 造的图和目标机读的
 * 不是一回事"。
 */

#include "ort_tar.h"

#define TARIMG_MAX 16384

static uint8_t g_timg[TARIMG_MAX];
static size_t  g_tlen;

static void timg_octal(FAR uint8_t *p, size_t len, uint64_t v)
{
  size_t i;

  for (i = 0; i < len; i++)
    {
      p[len - 1 - i] = (uint8_t)('0' + (v & 7));
      v >>= 3;
    }
}

static void timg_fixsum(FAR uint8_t *h)
{
  unsigned sum = 0;
  size_t i;

  memset(h + 148, ' ', 8);
  for (i = 0; i < 512; i++)
    {
      sum += h[i];
    }

  timg_octal(h + 148, 8, sum);
}

static void timg_reset(void)
{
  memset(g_timg, 0, sizeof(g_timg));
  g_tlen = 0;
}

static void timg_hdr(FAR const char *name, uint64_t size, char type,
                     FAR const char *prefix)
{
  uint8_t *h = g_timg + g_tlen;

  if (name != NULL)
    {
      size_t l = strlen(name);

      if (l > 100)
        {
          l = 100;
        }

      memcpy(h, name, l);
    }

  timg_octal(h + 100, 8, 0644);   /* mode */
  timg_octal(h + 108, 8, 0);      /* uid */
  timg_octal(h + 116, 8, 0);      /* gid */
  timg_octal(h + 124, 12, size);  /* size */
  timg_octal(h + 136, 12, 0);     /* mtime */
  h[156] = (uint8_t)type;
  memcpy(h + 257, "ustar", 5);
  h[262] = '\0';
  h[263] = '0';
  h[264] = '0';

  if (prefix != NULL)
    {
      size_t l = strlen(prefix);

      if (l > 155)
        {
          l = 155;
        }

      memcpy(h + 345, prefix, l);
    }

  timg_fixsum(h);
  g_tlen += 512;
}

static void timg_data(FAR const void *data, size_t len)
{
  memcpy(g_timg + g_tlen, data, len);
  g_tlen += (len + 511) & ~(size_t)511;
}

static void timg_end(void)
{
  g_tlen += 1024;                 /* 两个零块（reset 后本就全 0） */
}

struct tcollect_s
{
  int      n;
  char     name[8][80];
  uint64_t size[8];
  char     type[8];
  char     data[8][32];
  size_t   dlen[8];
};

static int tcollect_sink(FAR void *arg,
                         FAR const struct ort_tar_entry_s *e,
                         FAR struct ort_tar_src_s *src)
{
  FAR struct tcollect_s *c = (FAR struct tcollect_s *)arg;
  int i = c->n;

  if (i < 8)
    {
      size_t l = strlen(e->name);

      if (l > sizeof(c->name[0]) - 1)
        {
          l = sizeof(c->name[0]) - 1;
        }

      memcpy(c->name[i], e->name, l);
      c->name[i][l] = '\0';
      c->size[i] = e->size;
      c->type[i] = e->typeflag;
      c->data[i][0] = '\0';
      c->dlen[i] = 0;

      if (e->typeflag == '0' && e->size > 0)
        {
          size_t want = (e->size < sizeof(c->data[0]) - 1) ?
                        (size_t)e->size : sizeof(c->data[0]) - 1;
          int r = src->read(src->arg, c->data[i], want);

          c->dlen[i] = (r > 0) ? (size_t)r : 0;
          c->data[i][c->dlen[i]] = '\0';
        }
    }

  c->n++;
  return 0;
}

static int tar_run(FAR FILE *out, FAR const char *name, FAR uint32_t *nent,
                   FAR struct tcollect_s *c)
{
  static const char *tmp = "/tmp/ort-ttest.tar";
  FAR FILE *f = fopen(tmp, "wb");
  int ret;

  if (f == NULL)
    {
      fprintf(out, "[ttest] FAIL %s: 临时文件开不了\n", name);
      return -100;
    }

  fwrite(g_timg, 1, g_tlen, f);
  fclose(f);

  memset(c, 0, sizeof(*c));
  f = fopen(tmp, "rb");
  if (f == NULL)
    {
      fprintf(out, "[ttest] FAIL %s: 临时文件读不了\n", name);
      return -100;
    }

  ret = ort_tar_walk(f, tcollect_sink, c, nent);
  fclose(f);
  return ret;
}

/* 任意字节落临时文件后走文件入口（gzip 素材用） */

static int tar_run_bytes(FAR FILE *out, FAR const char *name,
                         FAR const void *p, size_t n,
                         FAR uint32_t *nent, FAR struct tcollect_s *c)
{
  static const char *tmp = "/tmp/ort-ttest.gz";
  FAR FILE *f = fopen(tmp, "wb");
  int ret;

  if (f == NULL)
    {
      fprintf(out, "[ttest] FAIL %s: 临时文件开不了\n", name);
      return -100;
    }

  fwrite(p, 1, n, f);
  fclose(f);

  memset(c, 0, sizeof(*c));
  f = fopen(tmp, "rb");
  if (f == NULL)
    {
      fprintf(out, "[ttest] FAIL %s: 临时文件读不了\n", name);
      return -100;
    }

  ret = ort_tar_walk(f, tcollect_sink, c, nent);
  fclose(f);
  return ret;
}

/* 用例数（T1-T18；tar 用例是命令式写的，没有表可数 —— 增删必须同步） */

#define ORT_NTARCASES 18

static int ort_tar_battery_run(FAR FILE *out)
{
  struct tcollect_s c;
  uint32_t nent;
  int      fails = 0;
  int      ret;

  /* T1 单文件 */

  timg_reset();
  timg_hdr("a.txt", 6, '0', NULL);
  timg_data("hello\n", 6);
  timg_end();
  ret = tar_run(out, "T1", &nent, &c);
  if (ret != ORT_TAR_OK || nent != 1 || strcmp(c.name[0], "a.txt") != 0 ||
      c.size[0] != 6 || strcmp(c.data[0], "hello\n") != 0)
    {
      fprintf(out, "[ttest] FAIL T1 单文件: ret=%s n=%u\n",
              ort_tar_strerror(ret), (unsigned)nent);
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T1 单文件（名字/大小/内容）\n");
    }

  /* T2 目录 + prefix 拼接 */

  timg_reset();
  timg_hdr("d", 0, '5', NULL);
  timg_hdr("a.txt", 3, '0', "deep");
  timg_data("xyz", 3);
  timg_end();
  ret = tar_run(out, "T2", &nent, &c);
  if (ret != ORT_TAR_OK || nent != 2 || c.type[0] != '5' ||
      strcmp(c.name[0], "d") != 0 || strcmp(c.name[1], "deep/a.txt") != 0 ||
      strcmp(c.data[1], "xyz") != 0)
    {
      fprintf(out, "[ttest] FAIL T2 目录+prefix: ret=%s n=%u n1=%s\n",
              ort_tar_strerror(ret), (unsigned)nent, c.name[1]);
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T2 目录 + prefix 拼接\n");
    }

  /* T3 名字规范化（./ 与 a/./b） */

  timg_reset();
  timg_hdr("./x", 1, '0', NULL);
  timg_data("X", 1);
  timg_hdr("a/./b", 1, '0', NULL);
  timg_data("B", 1);
  timg_end();
  ret = tar_run(out, "T3", &nent, &c);
  if (ret != ORT_TAR_OK || nent != 2 || strcmp(c.name[0], "x") != 0 ||
      strcmp(c.name[1], "a/b") != 0)
    {
      fprintf(out, "[ttest] FAIL T3 规范化: n0=%s n1=%s\n",
              c.name[0], c.name[1]);
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T3 规范化（./ 与 a/./b）\n");
    }

  /* T4 空 tar（仅 end marker） */

  timg_reset();
  timg_end();
  ret = tar_run(out, "T4", &nent, &c);
  if (ret != ORT_TAR_OK || nent != 0)
    {
      fprintf(out, "[ttest] FAIL T4 空 tar: ret=%s n=%u\n",
              ort_tar_strerror(ret), (unsigned)nent);
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T4 空 tar（0 条目）\n");
    }

  /* T5 magic 坏 */

  timg_reset();
  timg_hdr("a.txt", 0, '0', NULL);
  timg_end();
  g_timg[257] = 'X';
  ret = tar_run(out, "T5", &nent, &c);
  if (ret != ORT_TAR_E_BADMAGIC)
    {
      fprintf(out, "[ttest] FAIL T5 magic: got=%s expect=BADMAGIC\n",
              ort_tar_strerror(ret));
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T5 magic 坏 → BADMAGIC\n");
    }

  /* T6 checksum 坏（改一个字节不修校验和） */

  timg_reset();
  timg_hdr("a.txt", 1, '0', NULL);
  timg_data("A", 1);
  timg_end();
  g_timg[124] ^= 1;
  ret = tar_run(out, "T6", &nent, &c);
  if (ret != ORT_TAR_E_BADSUM)
    {
      fprintf(out, "[ttest] FAIL T6 checksum: got=%s expect=BADSUM\n",
              ort_tar_strerror(ret));
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T6 checksum 坏 → BADSUM\n");
    }

  /* T7 绝对路径 */

  timg_reset();
  timg_hdr("/etc/passwd", 1, '0', NULL);
  timg_data("x", 1);
  timg_end();
  ret = tar_run(out, "T7", &nent, &c);
  if (ret != ORT_TAR_E_PATH)
    {
      fprintf(out, "[ttest] FAIL T7 绝对路径: got=%s expect=PATH\n",
              ort_tar_strerror(ret));
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T7 绝对路径 → PATH\n");
    }

  /* T8 ".." 逃逸 */

  timg_reset();
  timg_hdr("a/../../x", 1, '0', NULL);
  timg_data("x", 1);
  timg_end();
  ret = tar_run(out, "T8", &nent, &c);
  if (ret != ORT_TAR_E_PATH)
    {
      fprintf(out, "[ttest] FAIL T8 ..逃逸: got=%s expect=PATH\n",
              ort_tar_strerror(ret));
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T8 \"..\" 逃逸 → PATH\n");
    }

  /* T9 symlink 不收 */

  timg_reset();
  timg_hdr("lnk", 0, '2', NULL);
  timg_end();
  ret = tar_run(out, "T9", &nent, &c);
  if (ret != ORT_TAR_E_TYPE)
    {
      fprintf(out, "[ttest] FAIL T9 symlink: got=%s expect=TYPE\n",
              ort_tar_strerror(ret));
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T9 symlink → TYPE（明确不收）\n");
    }

  /* T10 pax 扩展头不收 */

  timg_reset();
  timg_hdr("PaxHead", 0, 'x', NULL);
  timg_end();
  ret = tar_run(out, "T10", &nent, &c);
  if (ret != ORT_TAR_E_TYPE)
    {
      fprintf(out, "[ttest] FAIL T10 pax: got=%s expect=TYPE\n",
              ort_tar_strerror(ret));
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T10 pax 扩展头 → TYPE（不静默丢语义）\n");
    }

  /* T11 数据截断（声明 100B，实体只有一个头） */

  timg_reset();
  timg_hdr("a.txt", 100, '0', NULL);
  ret = tar_run(out, "T11", &nent, &c);
  if (ret != ORT_TAR_E_SHORT)
    {
      fprintf(out, "[ttest] FAIL T11 截断: got=%s expect=SHORT\n",
              ort_tar_strerror(ret));
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T11 数据截断 → SHORT\n");
    }

  /* T12 size 非八进制（修好校验和，确保报的是 SYNTAX 不是 BADSUM） */

  timg_reset();
  timg_hdr("a.txt", 1, '0', NULL);
  timg_data("A", 1);
  timg_end();
  g_timg[131] = '8';              /* size 字段内塞非八进制 */
  timg_fixsum(g_timg);            /* 头在 offset 0 */
  ret = tar_run(out, "T12", &nent, &c);
  if (ret != ORT_TAR_E_SYNTAX)
    {
      fprintf(out, "[ttest] FAIL T12 size 非八进制: got=%s expect=SYNTAX\n",
              ort_tar_strerror(ret));
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T12 size 非八进制 → SYNTAX\n");
    }

  /* T13 gzip 魔数但内容坏 → GZIP（§66 起 gzip 已支持，此为解压失败） */

  timg_reset();
  g_timg[0] = 0x1f;
  g_timg[1] = 0x8b;
  g_tlen = 512;
  ret = tar_run(out, "T13", &nent, &c);
  if (ret != ORT_TAR_E_GZIP)
    {
      fprintf(out, "[ttest] FAIL T13 gzip 坏数据: got=%s expect=GZIP\n",
              ort_tar_strerror(ret));
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T13 gzip 头但数据坏 → GZIP（解压失败）\n");
    }

  /* T14 v7 老式目录（type '0' + 名尾 /） */

  timg_reset();
  timg_hdr("dir/", 0, '0', NULL);
  timg_end();
  ret = tar_run(out, "T14", &nent, &c);
  if (ret != ORT_TAR_OK || nent != 1 || c.type[0] != '5' ||
      strcmp(c.name[0], "dir") != 0)
    {
      fprintf(out, "[ttest] FAIL T14 v7 目录: ret=%s type=%c name=%s\n",
              ort_tar_strerror(ret), c.type[0], c.name[0]);
      fails++;
    }
  else
    {
      fprintf(out, "[ttest] ok   T14 v7 老式目录（名尾 /）\n");
    }

  /* T15-T18：gzip（§66）—— 烧死的小素材（python gzip -9, mtime=0 生成，
   * 内含单文件 gz/a.txt="gz-ok\n"；raw=10240B，gz=108B）+ 两个坏例 */

  {
    static const uint8_t gzblob[] =
    {
      0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xed, 0xcd,
      0x31, 0x0e, 0x82, 0x40, 0x10, 0x05, 0xd0, 0xa9, 0x3d, 0x85, 0x17, 0x40,
      0x09, 0x6c, 0xf4, 0x3c, 0x54, 0x14, 0x16, 0x24, 0xb0, 0x24, 0x84, 0xd3,
      0xb3, 0x58, 0x19, 0x7b, 0x4d, 0x08, 0xef, 0x35, 0x7f, 0xf2, 0x7f, 0x31,
      0xfd, 0x7a, 0xef, 0x6e, 0x79, 0xc9, 0xf1, 0x43, 0x75, 0xf1, 0x48, 0xe9,
      0x9d, 0xc5, 0x77, 0xee, 0xeb, 0xc7, 0xbd, 0xf7, 0xcf, 0x36, 0x35, 0x71,
      0xad, 0xe3, 0x0f, 0xe6, 0x29, 0x77, 0x63, 0x79, 0x19, 0xe7, 0xd4, 0xaf,
      0xd5, 0xf0, 0xba, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x07, 0xb3, 0x01, 0xf6, 0x73, 0xb8, 0xf1, 0x00, 0x28, 0x00, 0x00,
    };

    ret = tar_run_bytes(out, "T15", gzblob, sizeof(gzblob), &nent, &c);
    if (ret != ORT_TAR_OK || nent != 1 ||
        strcmp(c.name[0], "gz/a.txt") != 0 ||
        strcmp(c.data[0], "gz-ok\n") != 0)
      {
        fprintf(out, "[ttest] FAIL T15 gzip 正常: ret=%s n=%u n0=%s\n",
                ort_tar_strerror(ret), (unsigned)nent, c.name[0]);
        fails++;
      }
    else
      {
        fprintf(out, "[ttest] ok   T15 gzip 正常（inflate + 条目内容）\n");
      }

    /* T16 翻一字节 → CRC/数据坏 */

    {
      uint8_t bad[sizeof(gzblob)];

      memcpy(bad, gzblob, sizeof(bad));
      bad[sizeof(bad) / 2] ^= 0xFF;
      ret = tar_run_bytes(out, "T16", bad, sizeof(bad), &nent, &c);
      if (ret != ORT_TAR_E_GZIP)
        {
          fprintf(out, "[ttest] FAIL T16 gzip 坏数据: got=%s expect=GZIP\n",
                  ort_tar_strerror(ret));
          fails++;
        }
      else
        {
          fprintf(out, "[ttest] ok   T16 gzip 翻一字节 → GZIP\n");
        }
    }

    /* T17 截尾（丢校验尾）→ 不完整 */

    ret = tar_run_bytes(out, "T17", gzblob, sizeof(gzblob) - 5, &nent, &c);
    if (ret != ORT_TAR_E_GZIP)
      {
        fprintf(out, "[ttest] FAIL T17 gzip 截尾: got=%s expect=GZIP\n",
                ort_tar_strerror(ret));
        fails++;
      }
    else
      {
        fprintf(out, "[ttest] ok   T17 gzip 截尾 → GZIP（不完整）\n");
      }

    /* T18 改尾（ISIZE 翻一字节）：tar 内容完好、**只有尾部被改** ——
     * 必须靠"读尽 gz 流 + STREAM_END 校验"才抓得住（§66 的 drain） */

    {
      uint8_t badtail[sizeof(gzblob)];

      memcpy(badtail, gzblob, sizeof(badtail));
      badtail[sizeof(badtail) - 5] ^= 0xFF;
      ret = tar_run_bytes(out, "T18", badtail, sizeof(badtail), &nent, &c);
      if (ret != ORT_TAR_E_GZIP)
        {
          fprintf(out, "[ttest] FAIL T18 gzip 改尾: got=%s expect=GZIP\n",
                  ort_tar_strerror(ret));
          fails++;
        }
      else
        {
          fprintf(out, "[ttest] ok   T18 gzip 改尾（ISIZE）→ GZIP\n");
        }
    }
  }

  return fails;
}

#endif /* __APPS_TESTING_ORTIMG_ORTIMG_BATTERY_H */
