/****************************************************************************
 * testing/ortimg/ort_json.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] 受限 JSON 解析器实现（设计约定见 ort_json.h 头注释）。
 *
 * 实现形状：**递归下降 + 深度计数器**。递归层数被 ORT_JSON_MAX_DEPTH
 * 封顶（进入每个 { 或 [ 时 +1，超了直接报 E_DEPTH 返回）——所以栈用量
 * 有上界：最深 8 层 × 每层几十字节。
 *
 * 两个模式共用同一套 tokenizer：
 *   · ort_json_validate   —— 严格校验整段
 *   · ort_manifest_parse  —— 白名单提取（未知字段走"跳过"路径，
 *                             与校验共用同样的括号/字符串/数字规则）
 ****************************************************************************/

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "ort_json.h"

/****************************************************************************
 * 游标与低层工具
 ****************************************************************************/

struct ort_cur_s
{
  const char *p;
  const char *end;
  int         depth;
};

static void skip_ws(FAR struct ort_cur_s *c)
{
  while (c->p < c->end &&
         (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r'))
    {
      c->p++;
    }
}

/* 进入一个容器。返回 0 或 -E_DEPTH 对应的 err。 */

static int push_depth(FAR struct ort_cur_s *c)
{
  if (++c->depth > ORT_JSON_MAX_DEPTH)
    {
      return ORT_JSON_E_DEPTH;
    }

  return ORT_JSON_OK;
}

static void pop_depth(FAR struct ort_cur_s *c)
{
  c->depth--;
}

static int hexval(int ch)
{
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

/****************************************************************************
 * 字符串：从开引号吃到闭引号。
 *   dst==NULL  → 只校验（跳过模式），不落字节
 *   dst!=NULL  → 落进 dst（含 NUL），超过 cap 报 E_SYNTAX（白名单字段
 *                 都有合理上界；超长一律当"不像我们的 manifest"处理）
 * 返回 err；*out_len（可空）= 字符串实际长度。
 ****************************************************************************/

static int parse_string(FAR struct ort_cur_s *c, FAR char *dst, size_t cap,
                        FAR size_t *out_len)
{
  size_t n = 0;

  if (c->p >= c->end)
    {
      return ORT_JSON_E_SHORT;   /* 输入在值的位置就没了 = 截断 */
    }

  if (*c->p != '"')
    {
      return ORT_JSON_E_SYNTAX;  /* 有字节但不是引号 = 语法错 */
    }

  c->p++;

  while (c->p < c->end)
    {
      unsigned char ch = (unsigned char)*c->p;

      if (ch == '"')
        {
          c->p++;
          if (dst != NULL)
            {
              dst[n] = '\0';
            }
          if (out_len != NULL)
            {
              *out_len = n;
            }
          return ORT_JSON_OK;
        }

      if (ch == '\\')
        {
          c->p++;
          if (c->p >= c->end)
            {
              return ORT_JSON_E_SHORT;
            }

          switch (*c->p)
            {
              case '"':  case '\\': case '/':
              case 'b':  case 'f':  case 'n':
              case 'r':  case 't':
                /* 只收这一小组转义；\uXXXX 明确不支持（头注释） */

                if (dst != NULL)
                  {
                    if (n + 1 >= cap)
                      {
                        return ORT_JSON_E_SYNTAX;
                      }

                    /* 转义解码：只有这几类，直接映射 */

                    switch (*c->p)
                      {
                        case 'b': dst[n] = '\b'; break;
                        case 'f': dst[n] = '\f'; break;
                        case 'n': dst[n] = '\n'; break;
                        case 'r': dst[n] = '\r'; break;
                        case 't': dst[n] = '\t'; break;
                        default:  dst[n] = *c->p; break;
                      }
                  }

                n++;
                c->p++;
                continue;

              default:
                return ORT_JSON_E_ESCAPE;
            }
        }

      /* 裸控制字符在 JSON 里必须转义 —— 严格拒绝 */

      if (ch < 0x20)
        {
          return ORT_JSON_E_SYNTAX;
        }

      if (dst != NULL)
        {
          if (n + 1 >= cap)
            {
              return ORT_JSON_E_SYNTAX;
            }

          dst[n] = (char)ch;
        }

      n++;
      c->p++;
    }

  return ORT_JSON_E_SHORT;
}

/****************************************************************************
 * 数字：整数（可负）。拒绝 '.'、'e'、'E'、前导零；uint64 溢出报错。
 ****************************************************************************/

static int parse_number(FAR struct ort_cur_s *c, FAR bool *neg,
                        FAR uint64_t *val)
{
  bool   negative = false;
  uint64_t v = 0;
  int    digits = 0;

  if (c->p < c->end && *c->p == '-')
    {
      negative = true;
      c->p++;
    }

  while (c->p < c->end && *c->p >= '0' && *c->p <= '9')
    {
      int d = *c->p - '0';

      if (digits == 0 && d == 0 && (c->p + 1) < c->end &&
          c->p[1] >= '0' && c->p[1] <= '9')
        {
          return ORT_JSON_E_NUMBER;          /* 前导零：严格 JSON 拒绝 */
        }

      if (v > (UINT64_MAX - (uint64_t)d) / 10u)
        {
          return ORT_JSON_E_NUMBER;          /* 溢出 */
        }

      v = v * 10u + (uint64_t)d;
      digits++;
      c->p++;
    }

  if (digits == 0)
    {
      return ORT_JSON_E_SHORT;               /* 只有 '-' 或啥都没有 */
    }

  /* 小数点/指数一律不支持（manifest 全是整数） */

  if (c->p < c->end && (*c->p == '.' || *c->p == 'e' || *c->p == 'E'))
    {
      return ORT_JSON_E_NUMBER;
    }

  if (neg != NULL)
    {
      *neg = negative;
    }
  if (val != NULL)
    {
      *val = v;
    }

  return ORT_JSON_OK;
}

/* 通用值跳过/校验：结构与 parse_manifest 的容器逻辑一致，
 * 但一个字节都不落 —— 用于未知字段与 ort_json_validate。 */

static int parse_value(FAR struct ort_cur_s *c);

static int parse_array(FAR struct ort_cur_s *c)
{
  int ret = push_depth(c);

  if (ret != ORT_JSON_OK)
    {
      return ret;
    }

  skip_ws(c);
  if (c->p < c->end && *c->p == ']')
    {
      c->p++;
      pop_depth(c);
      return ORT_JSON_OK;
    }

  for (;;)
    {
      ret = parse_value(c);
      if (ret != ORT_JSON_OK)
        {
          pop_depth(c);
          return ret;
        }

      skip_ws(c);
      if (c->p >= c->end)
        {
          pop_depth(c);
          return ORT_JSON_E_SHORT;
        }

      if (*c->p == ',')
        {
          c->p++;
          skip_ws(c);
          continue;
        }

      if (*c->p == ']')
        {
          c->p++;
          pop_depth(c);
          return ORT_JSON_OK;
        }

      pop_depth(c);
      return ORT_JSON_E_SYNTAX;
    }
}

static int parse_object(FAR struct ort_cur_s *c)
{
  int ret = push_depth(c);

  if (ret != ORT_JSON_OK)
    {
      return ret;
    }

  skip_ws(c);
  if (c->p < c->end && *c->p == '}')
    {
      c->p++;
      pop_depth(c);
      return ORT_JSON_OK;
    }

  for (;;)
    {
      size_t klen = 0;

      ret = parse_string(c, NULL, 0, &klen);
      if (ret != ORT_JSON_OK)
        {
          pop_depth(c);
          return ret;
        }

      skip_ws(c);
      if (c->p >= c->end)
        {
          pop_depth(c);
          return ORT_JSON_E_SHORT;
        }
      if (*c->p != ':')
        {
          pop_depth(c);
          return ORT_JSON_E_SYNTAX;
        }

      c->p++;
      skip_ws(c);

      ret = parse_value(c);
      if (ret != ORT_JSON_OK)
        {
          pop_depth(c);
          return ret;
        }

      skip_ws(c);
      if (c->p >= c->end)
        {
          pop_depth(c);
          return ORT_JSON_E_SHORT;
        }

      if (*c->p == ',')
        {
          c->p++;
          skip_ws(c);
          continue;
        }

      if (*c->p == '}')
        {
          c->p++;
          pop_depth(c);
          return ORT_JSON_OK;
        }

      pop_depth(c);
      return ORT_JSON_E_SYNTAX;
    }
}

static int parse_value(FAR struct ort_cur_s *c)
{
  if (c->p >= c->end)
    {
      return ORT_JSON_E_SHORT;
    }

  switch (*c->p)
    {
      case '{':
        c->p++;
        skip_ws(c);
        return parse_object(c);

      case '[':
        c->p++;
        skip_ws(c);
        return parse_array(c);

      case '"':
        return parse_string(c, NULL, 0, NULL);

      case 't':
        if (c->end - c->p >= 4 && memcmp(c->p, "true", 4) == 0)
          {
            c->p += 4;
            return ORT_JSON_OK;
          }
        return ORT_JSON_E_SYNTAX;

      case 'f':
        if (c->end - c->p >= 5 && memcmp(c->p, "false", 5) == 0)
          {
            c->p += 5;
            return ORT_JSON_OK;
          }
        return ORT_JSON_E_SYNTAX;

      case 'n':
        if (c->end - c->p >= 4 && memcmp(c->p, "null", 4) == 0)
          {
            c->p += 4;
            return ORT_JSON_OK;
          }
        return ORT_JSON_E_SYNTAX;

      default:
        return parse_number(c, NULL, NULL);
    }
}

/****************************************************************************
 * 公共：校验
 ****************************************************************************/

int ort_json_validate(FAR const char *s, size_t len)
{
  struct ort_cur_s c;
  int ret;

  if (len > ORT_JSON_MAX_INPUT)
    {
      return ORT_JSON_E_SIZE;
    }

  c.p     = s;
  c.end   = s + len;
  c.depth = 0;

  skip_ws(&c);
  ret = parse_value(&c);
  if (ret != ORT_JSON_OK)
    {
      return ret;
    }

  skip_ws(&c);
  if (c.p != c.end)
    {
      return ORT_JSON_E_TRAILING;
    }

  return ORT_JSON_OK;
}

/****************************************************************************
 * 公共：manifest 提取（白名单）
 ****************************************************************************/

/* digest 白名单形态：sha256:<64 小写 hex>。别的算法/编码一律拒——
 * 我们只消费 sha256，收窄判据比"接受再说"安全（头注释第 3 条）。 */

static bool digest_ok(FAR const char *d)
{
  size_t i;

  if (strncmp(d, "sha256:", 7) != 0)
    {
      return false;
    }

  if (strlen(d) != 7 + 64)
    {
      return false;
    }

  for (i = 7; d[i] != '\0'; i++)
    {
      if (hexval((unsigned char)d[i]) < 0 || (d[i] >= 'A' && d[i] <= 'F'))
        {
          return false;             /* 只收小写 hex（运维惯例） */
        }
    }

  return true;
}

static int parse_size_field(FAR struct ort_cur_s *c, FAR uint64_t *out)
{
  bool     neg = false;
  uint64_t v   = 0;
  int      ret;

  ret = parse_number(c, &neg, &v);
  if (ret != ORT_JSON_OK)
    {
      return ret;
    }

  if (neg)
    {
      return ORT_JSON_E_NUMBER;     /* 尺寸不为负 */
    }

  *out = v;
  return ORT_JSON_OK;
}

/* descriptor 对象（config 与 layers[i] 同形）：
 *   { mediaType?, digest, size, 未知字段… }
 * 白名单：digest + size 必需；其余（含 mediaType）有界跳过。 */

static int parse_descriptor(FAR struct ort_cur_s *c, FAR char *digest,
                            FAR uint64_t *size, FAR uint32_t *ignored)
{
  bool have_digest = false;
  bool have_size   = false;
  int  ret;

  ret = push_depth(c);
  if (ret != ORT_JSON_OK)
    {
      return ret;
    }

  c->p++;                           /* '{' */
  skip_ws(c);

  if (c->p < c->end && *c->p == '}')
    {
      pop_depth(c);
      c->p++;
      return ORT_JSON_E_REQUIRED;   /* 空描述符 */
    }

  for (;;)
    {
      char   key[24];
      size_t klen = 0;

      ret = parse_string(c, key, sizeof(key), &klen);
      if (ret != ORT_JSON_OK)
        {
          pop_depth(c);
          return ret;
        }

      skip_ws(c);
      if (c->p >= c->end || *c->p != ':')
        {
          pop_depth(c);
          return c->p >= c->end ? ORT_JSON_E_SHORT : ORT_JSON_E_SYNTAX;
        }

      c->p++;
      skip_ws(c);

      if (strcmp(key, "digest") == 0)
        {
          ret = parse_string(c, digest, 72, NULL);
          if (ret != ORT_JSON_OK)
            {
              pop_depth(c);
              return ret;
            }
          if (!digest_ok(digest))
            {
              pop_depth(c);
              return ORT_JSON_E_DIGEST;
            }
          have_digest = true;
        }
      else if (strcmp(key, "size") == 0)
        {
          ret = parse_size_field(c, size);
          if (ret != ORT_JSON_OK)
            {
              pop_depth(c);
              return ret;
            }
          have_size = true;
        }
      else
        {
          ret = parse_value(c);     /* 白名单外：有界跳过，计数 */
          if (ret != ORT_JSON_OK)
            {
              pop_depth(c);
              return ret;
            }
          (*ignored)++;
        }

      skip_ws(c);
      if (c->p >= c->end)
        {
          pop_depth(c);
          return ORT_JSON_E_SHORT;
        }
      if (*c->p == ',')
        {
          c->p++;
          skip_ws(c);
          continue;
        }
      if (*c->p == '}')
        {
          c->p++;
          break;
        }

      pop_depth(c);
      return ORT_JSON_E_SYNTAX;
    }

  pop_depth(c);

  if (!have_digest || !have_size)
    {
      return ORT_JSON_E_REQUIRED;
    }

  return ORT_JSON_OK;
}

int ort_manifest_parse(FAR const char *s, size_t len,
                       FAR struct ort_manifest_s *out)
{
  struct ort_cur_s c;
  bool have_schema = false;
  bool have_config = false;
  bool have_layers = false;
  int  ret;

  if (len > ORT_JSON_MAX_INPUT)
    {
      return ORT_JSON_E_SIZE;
    }

  memset(out, 0, sizeof(*out));
  out->schema_version = 0;

  c.p     = s;
  c.end   = s + len;
  c.depth = 0;

  skip_ws(&c);
  if (c.p >= c.end || *c.p != '{')
    {
      return ORT_JSON_E_REQUIRED;   /* 顶层必须是对象（index 也不行） */
    }

  ret = push_depth(&c);
  if (ret != ORT_JSON_OK)
    {
      return ret;
    }

  c.p++;
  skip_ws(&c);

  if (c.p < c.end && *c.p == '}')
    {
      return ORT_JSON_E_REQUIRED;
    }

  for (;;)
    {
      char   key[24];
      size_t klen = 0;

      ret = parse_string(&c, key, sizeof(key), &klen);
      if (ret != ORT_JSON_OK)
        {
          return ret;
        }

      skip_ws(&c);
      if (c.p >= c.end || *c.p != ':')
        {
          return c.p >= c.end ? ORT_JSON_E_SHORT : ORT_JSON_E_SYNTAX;
        }

      c.p++;
      skip_ws(&c);

      if (strcmp(key, "schemaVersion") == 0)
        {
          bool     neg = false;
          uint64_t v   = 0;

          ret = parse_number(&c, &neg, &v);
          if (ret != ORT_JSON_OK)
            {
              return ret;
            }

          if (neg || v != 2)
            {
              return ORT_JSON_E_SCHEMA;
            }

          out->schema_version = (uint32_t)v;
          have_schema = true;
        }
      else if (strcmp(key, "mediaType") == 0)
        {
          ret = parse_string(&c, out->media_type,
                             sizeof(out->media_type), NULL);
          if (ret != ORT_JSON_OK)
            {
              return ret;
            }
        }
      else if (strcmp(key, "config") == 0)
        {
          /* config 必需是 descriptor 对象（image manifest 的形状）；
           * index 里 config 不存在，会走到"缺 config"→ REQUIRED ✓ */

          if (c.p >= c.end || *c.p != '{')
            {
              return ORT_JSON_E_SYNTAX;
            }

          ret = parse_descriptor(&c, out->config_digest,
                                 &out->config_size, &out->ignored_fields);
          if (ret != ORT_JSON_OK)
            {
              return ret;
            }
          have_config = true;
        }
      else if (strcmp(key, "layers") == 0)
        {
          if (c.p >= c.end || *c.p != '[')
            {
              return ORT_JSON_E_SYNTAX;
            }

          ret = push_depth(&c);
          if (ret != ORT_JSON_OK)
            {
              return ret;
            }

          c.p++;
          skip_ws(&c);

          if (c.p < c.end && *c.p == ']')
            {
              c.p++;
              pop_depth(&c);
              have_layers = true;   /* 空层数组 → 下面按 REQUIRED 拒 */
            }
          else
            {
              for (;;)
                {
                  if (out->nlayers >= ORT_MANIFEST_MAX_LAYERS)
                    {
                      return ORT_JSON_E_LAYERS;
                    }

                  if (c.p >= c.end || *c.p != '{')
                    {
                      return ORT_JSON_E_SYNTAX;
                    }

                  ret = parse_descriptor(&c,
                                         out->layers[out->nlayers].digest,
                                         &out->layers[out->nlayers].size,
                                         &out->ignored_fields);
                  if (ret != ORT_JSON_OK)
                    {
                      return ret;
                    }

                  out->nlayers++;

                  skip_ws(&c);
                  if (c.p >= c.end)
                    {
                      return ORT_JSON_E_SHORT;
                    }
                  if (*c.p == ',')
                    {
                      c.p++;
                      skip_ws(&c);
                      continue;
                    }
                  if (*c.p == ']')
                    {
                      c.p++;
                      break;
                    }

                  return ORT_JSON_E_SYNTAX;
                }

              pop_depth(&c);
              have_layers = true;
            }
        }
      else
        {
          ret = parse_value(&c);     /* 白名单外（annotations…）：跳过 */
          if (ret != ORT_JSON_OK)
            {
              return ret;
            }
          out->ignored_fields++;
        }

      skip_ws(&c);
      if (c.p >= c.end)
        {
          return ORT_JSON_E_SHORT;
        }
      if (*c.p == ',')
        {
          c.p++;
          skip_ws(&c);
          continue;
        }
      if (*c.p == '}')
        {
          c.p++;
          break;
        }

      return ORT_JSON_E_SYNTAX;
    }

  pop_depth(&c);

  skip_ws(&c);
  if (c.p != c.end)
    {
      return ORT_JSON_E_TRAILING;
    }

  if (!have_schema || !have_config || !have_layers || out->nlayers < 1)
    {
      return ORT_JSON_E_REQUIRED;
    }

  return ORT_JSON_OK;
}

/****************************************************************************
 * 公共：错误名
 ****************************************************************************/

const char *ort_json_strerror(int err)
{
  switch (err)
    {
      case ORT_JSON_OK:          return "OK";
      case ORT_JSON_E_SYNTAX:    return "SYNTAX";
      case ORT_JSON_E_DEPTH:     return "DEPTH";
      case ORT_JSON_E_ESCAPE:    return "ESCAPE";
      case ORT_JSON_E_NUMBER:    return "NUMBER";
      case ORT_JSON_E_TRAILING:  return "TRAILING";
      case ORT_JSON_E_SHORT:     return "SHORT";
      case ORT_JSON_E_SIZE:      return "SIZE";
      case ORT_JSON_E_SCHEMA:    return "SCHEMA";
      case ORT_JSON_E_REQUIRED:  return "REQUIRED";
      case ORT_JSON_E_LAYERS:    return "LAYERS";
      case ORT_JSON_E_DIGEST:    return "DIGEST";
      default:                   return "?";
    }
}
