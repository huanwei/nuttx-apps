/****************************************************************************
 * testing/ortimg/ort_json.h
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] 受限 JSON：OCI image manifest 的解析地基
 * （手册 §三·补六十一）
 *
 * ★ 为什么"受限"是设计要求，不是偷懒：
 *   这段解析器未来要吃的字节来自**网络对端**（registry）。通用 JSON 库
 *   在嵌入式上的三宗罪：动态分配（打爆堆）、递归深度不设界（打爆栈）、
 *   任意字段进任意逻辑（把"数据"变成了"控制面"）。所以设计三条钉死：
 *
 *     1. 无动态分配 —— 全部落在调用者提供的结构体/栈上；
 *     2. 深度有界   —— ORT_JSON_MAX_DEPTH，超了报错不递归；
 *     3. 字段白名单 —— 只对**已知字段**建语义；未知字段被**有界跳过**
 *                      （跳过 ≠ 报错：真实 manifest 带 annotations 之类，
 *                       但跳过的东西不进入任何决策，且计数可观测）。
 *
 * 明确的**不支持**（白名单式砍掉，明确报错好过隐性偏差）：
 *   · \uXXXX 转义 → ORT_JSON_E_ESCAPE（digest/mediaType 不需要它；
 *     UTF-8 原字节可直接出现，见 P6 用例）
 *   · 浮点/指数 → ORT_JSON_E_NUMBER（manifest 里全是整数）
 *   · 前导零（"01"）→ ORT_JSON_E_NUMBER（严格 JSON）
 *
 * 输入是 **(ptr,len)** 不是字符串：不依赖 NUL 结尾（网络流里没有）。
 ****************************************************************************/

#ifndef __APPS_TESTING_ORTIMG_ORT_JSON_H
#define __APPS_TESTING_ORTIMG_ORT_JSON_H

#include <stddef.h>
#include <stdint.h>

/* FAR 是 NuttX 的跨地址空间指针宏；本模块要能在**宿主机 gcc**下编译
 * （双环境电池），所以给一个回退 —— NuttX 构建里 FAR 已被定义，
 * 这里就是 no-op。 */

#ifndef FAR
#  define FAR
#endif

#define ORT_JSON_MAX_DEPTH      8       /* 容器（{ [）最大嵌套层数       */
#define ORT_JSON_MAX_INPUT      65536   /* 单份输入最大字节数            */
#define ORT_MANIFEST_MAX_LAYERS 16      /* 层数上限（真实镜像远小于此）  */

enum ort_json_err_e
{
  ORT_JSON_OK = 0,
  ORT_JSON_E_SYNTAX,       /* 语法不合法（含裸控制字符、单引号等）   */
  ORT_JSON_E_DEPTH,        /* 嵌套超过 ORT_JSON_MAX_DEPTH           */
  ORT_JSON_E_ESCAPE,       /* 不支持的转义（含 \uXXXX）             */
  ORT_JSON_E_NUMBER,       /* 非整数 / 溢出 / 前导零 / 该处不该为负 */
  ORT_JSON_E_TRAILING,     /* 顶层值之后还有内容                    */
  ORT_JSON_E_SHORT,        /* 输入在值中间截断                      */
  ORT_JSON_E_SIZE,         /* 输入超过 ORT_JSON_MAX_INPUT           */
  ORT_JSON_E_SCHEMA,       /* schemaVersion 缺失或 != 2             */
  ORT_JSON_E_REQUIRED,     /* 缺必需字段（config/layers/digest…）   */
  ORT_JSON_E_LAYERS,       /* 层数超过 ORT_MANIFEST_MAX_LAYERS      */
  ORT_JSON_E_DIGEST,
  ORT_JSON_E_LIMIT,       /* 数组超界（不截断——精确报）    */       /* digest 不是 sha256:<64 小写 hex>      */
};

struct ort_layer_s
{
  char     digest[72];     /* "sha256:" + 64 hex + NUL */
  uint64_t size;
};

struct ort_manifest_s
{
  uint32_t schema_version; /* 必须为 2 */
  char     media_type[96]; /* 顶层 mediaType；缺省为空串 */
  char     config_digest[72];
  uint64_t config_size;
  uint32_t nlayers;        /* 1..ORT_MANIFEST_MAX_LAYERS */
  struct ort_layer_s layers[ORT_MANIFEST_MAX_LAYERS];
  uint32_t ignored_fields; /* 白名单外被跳过的键数（可观测性）*/
};

const char *ort_json_strerror(int err);

/* 通用校验：整段输入是不是**合法且完整**的 JSON（含深度/转义/数字的
 * 受限条款）。不含任何 OCI 语义。返回 enum ort_json_err_e。 */

int ort_json_validate(const char *s, size_t len);

/* OCI image manifest 提取（白名单语义）。成功返回 ORT_JSON_OK。
 * ⚠️ 传入的是 **image manifest**；传 index（manifest list）会得
 *    ORT_JSON_E_REQUIRED —— 那是上层要做平台选择的另一层，不是 bug。 */

int ort_manifest_parse(const char *s, size_t len,
                       struct ort_manifest_s *out);

/* 顶层字符串字段取值（白名单式）：给 registry 握手取 "token" 用。
 *   只认**顶层**字段；找到且是字符串 → 拷进 dst（含 NUL，超 cap 报
 *   E_SYNTAX）；找不到 / 值不是字符串 → E_REQUIRED；重复键取**先**出现的。
 * 其余内容照常严格校验（不能因为只想要一个字段就放行畸形 JSON）。 */

int ort_json_get_str(FAR const char *s, size_t len, FAR const char *key,
                     FAR char *dst, size_t cap);

/* ── OCI image config（config blob）白名单提取 ────────────────────── *
 *   architecture / os / config.{Entrypoint, Cmd, Env, WorkingDir}
 * 数组有界：Entrypoint/Cmd ≤ ORT_CFG_MAX_ARG、Env ≤ ORT_CFG_MAX_ENV；
 * **超界报 E_LIMIT 不静默截断**（"要跑什么"不允许丢件——截断会让运行时
 * 跑出与镜像声明不同的东西）。Entrypoint 与 Cmd 至少有一个，否则
 * E_REQUIRED（不可运行的镜像配置不是"合法但空"，是缺件）。 */

#define ORT_CFG_MAX_ARG 8
#define ORT_CFG_MAX_ENV 8

struct ort_config_s
{
  char     arch[16];
  char     os[16];
  char     entrypoint[ORT_CFG_MAX_ARG][64];
  uint32_t nentrypoint;
  char     cmd[ORT_CFG_MAX_ARG][64];
  uint32_t ncmd;
  char     env[ORT_CFG_MAX_ENV][96];
  uint32_t nenv;
  char     workdir[64];
  uint32_t ignored_fields;
};

int ort_config_parse(FAR const char *s, size_t len,
                     FAR struct ort_config_s *out);

/* OCI image index（manifest list）白名单提取。
 *   manifests[].{digest, platform{os,architecture[,variant]}}
 * 传 image manifest 进来会得 E_REQUIRED（没有 manifests 数组）——
 * 客户端据此区分"这是索引"还是"这是镜像清单"（两个解析器互为判据）。 */

#define ORT_INDEX_MAX 32

struct ort_index_entry_s
{
  char digest[72];
  char os[16];
  char arch[16];
  char variant[16];
};

struct ort_index_s
{
  uint32_t schema_version;
  char     media_type[96];
  uint32_t nentries;          /* 1..ORT_INDEX_MAX */
  struct ort_index_entry_s entries[ORT_INDEX_MAX];
  uint32_t ignored_fields;
};

int ort_index_parse(FAR const char *s, size_t len,
                    FAR struct ort_index_s *out);

#endif /* __APPS_TESTING_ORTIMG_ORT_JSON_H */
