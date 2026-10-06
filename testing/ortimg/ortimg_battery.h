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

#endif /* __APPS_TESTING_ORTIMG_ORTIMG_BATTERY_H */
