/****************************************************************************
 * testing/ortsup/ortsup_main.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT] ORT 监督者（ort_safety）原型
 *
 * 实现《降级状态机设计》的核心闭环：故障检测 → 状态迁移 → 动作调用。
 *
 * 为什么这个原型重要：
 *   在此之前我们验证的都是**机制**（MPU 隔离、故障终止、故障通道）。
 *   这个程序验证的是**架构** —— 一个容器失效之后，系统能不能按预先
 *   声明的策略、在有限时间内、单调地进入一个已知状态。
 *   后者才是功能安全关注的东西。
 *
 * 实现的状态机（《降级状态机设计》§2.1 / §3.2 的子集）：
 *
 *     BOOT ──全部 CG 就绪──► NOMINAL
 *       │                       │
 *       │                  非关键 CG 失效
 *       │                   ├─ 重启未耗尽 → 仍 NOMINAL
 *       │                   ├─ 重启耗尽   → DEGRADED（锁存）      T6
 *       │                   └─ 关键 CG    → SAFE_STATE（锁存）    T7
 *       │
 *       └──启动失败──► BOOT_FAILED（锁存）                        T4
 *
 *     DEGRADED ──关键 CG 失效──► SAFE_STATE（锁存）               T8
 *     DEGRADED ──其余 CG 失效──► DEGRADED（状态不变）             T9
 *
 * ★ 启动期 vs 运行期的分界（H29 的答案）：
 *
 *   两套策略需要一个**判据**才能切换。本原型采用：
 *
 *     就绪判据 = 「已准入（监督者绑完域）且经过 STARTUP_WINDOW_MS 无故障」
 *
 *   窗口内失效 → 走 §6 startup.onContainerGroupFail（全系统一套策略）
 *   窗口后失效 → 走 runtime.defaultOnFailure（可被单个 CG 覆盖）
 *
 *   为什么不是"BOOT 状态结束"作为分界：
 *     BOOT 是**监督者**的状态，容器是异步的 —— 监督者宣布 BOOT 完成时，
 *     容器可能还没初始化完。用"准入 + 时间窗"才是以**容器**为基准。
 *
 *   为什么窗口内失效要单独处理：
 *     它意味着"这个容器根本起不来"，而运行期失效意味着"它跑了、
 *     然后坏了"。前者是**部署问题**（该进安全态或拒绝启动），
 *     后者是**运行时问题**（可以先重启）。两者的正确响应完全不同。
 *
 *   用 STARTUP_WINDOW_MS 而不是容器主动上报 ready：
 *     主动上报更精确，但需要容器配合 —— 而公理 S1 要求不信任失效组件。
 *     超时窗口是**监督者单方面可判定**的，不依赖容器善意。
 *     正式实现可以两者结合：上报 ready 提前结束窗口，超时兜底。
 *
 * ★ 本原型要演示的两条性质：
 *
 *   ① **重启次数有界** —— maxRestarts 耗尽后不再重启（否则一个反复崩溃的
 *      容器会让监督者永远忙碌，等于没有降级）。
 *
 *   ② **状态迁移单调** —— 进入 DEGRADED / SAFE_STATE 后不会自动回到
 *      NOMINAL。这是《设计》§2.1 的"有效终态"，也是公理 S2（安全态锁存）。
 *      单调性是最容易通过认证的性质，所以被选为默认设计。
 *
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <spawn.h>
#include <nuttx/sched.h>

/* 容器用的就是**本 ELF 自己**（`ortsup container ...`）。
 *
 * 为什么不做一个独立的 ortctnr 程序：
 *   容器入口 ort_container_main 和状态机就在同一个文件里，
 *   拆出去要么复制一份、要么造一个只有几行的壳。
 *   自 spawn 的代价只是多认一个 "container" 标记 —— 见 main 开头。
 */

#define CONTAINER_PATH  "/system/bin/ortsup"

#define POOL_BASE   0x60840000u
#define BLOCK_SIZE  (16 * 1024u)
#define NBLOCKS     4

#define CONTAINER_PRIO   110
#define CONTAINER_STACK  2048

/* 启动窗口：准入之后多少毫秒内仍算「启动期」。
 * 对应《设计》§6 的 safetyPolicy.startup.startTimeoutMs。
 */

#define STARTUP_WINDOW_MS  1500     /* manifest 里的 startup_timeout_ms 覆盖它 */

static int g_startup_window_ms = STARTUP_WINDOW_MS;

/* 监督循环周期（也是下面 g_now_ms 的步长） */

#define LOOP_MS  5

/* manifest 轮询周期 */

#define RELOAD_POLL_MS  2000

/****************************************************************************
 * 状态定义（《设计》§2.1）
 ****************************************************************************/

enum ort_sysstate_e
{
  ORT_BOOT = 0,
  ORT_NOMINAL,
  ORT_DEGRADED,
  ORT_SAFE_STATE,
  ORT_BOOT_FAILED,
};

static FAR const char *state_name(enum ort_sysstate_e s)
{
  switch (s)
    {
      case ORT_BOOT:        return "BOOT";
      case ORT_NOMINAL:     return "NOMINAL";
      case ORT_DEGRADED:    return "DEGRADED";
      case ORT_SAFE_STATE:  return "SAFE_STATE";
      case ORT_BOOT_FAILED: return "BOOT_FAILED";
      default:              return "?";
    }
}

/****************************************************************************
 * 容器组规格（替代生产版的 YAML 配置）
 ****************************************************************************/

struct ort_cg_s
{
  char            namebuf[16];   /* 名字的所有权在这里，解析器不分配 */
  FAR const char *name;          /* 恒等于 namebuf */
  int             domain;
  bool            critical;      /* onFailure: 关键 → SAFE_STATE；否则 DEGRADE */
  int             max_restarts;  /* 0 = NEVER（SAFE_STATIC 推荐值） */

  /* manifest 声明：故障时本 CG 要**自己处理**（而不是被内核直接终止）。
   *
   * ★ 这条声明能不能兑现**取决于平台** —— 见 ORT_CAP_FAULT_HANDLER。
   *   兑现不了就必须在**准入阶段拒绝**，而不是等运行期默默降级成
   *   "处理器不被调用、直接杀掉"。后者会让同一份 manifest 在两个 SKU 上
   *   语义不同，而部署方没有任何地方能问出这件事。
   */

  bool            handles_fault;

  /* 运行时状态 */

  pid_t           pid;
  int             restarts;
  int             faults;
  bool            failed;        /* 已失效且不再重启 */
  int             admitted_ms;   /* 被准入的时刻（-1 = 尚未准入） */
};

/* CG 表**由 manifest 填**，不再写死在源码里。
 *
 * 为什么这是"编排框架"和"演示程序"的分界线：
 *   写死在源码里意味着"改部署要重新编译固件" —— 那不是编排，
 *   那是把配置烧进二进制。而 ORT 的卖点恰恰是同一份固件能承载
 *   不同的容器组合。
 *
 * 上限用静态数组而不是动态分配：配置解析发生在**启动路径**上，
 * 而《设计》要求启动路径不得依赖动态分配能否成功。
 */

#define MAX_CGS  8

static struct ort_cg_s g_cgs[MAX_CGS];
static int g_ncgs;

/* 平台能力位。读一次就够 —— 它是平台属性，不会变。
 * 必须在 main 里 prctl 查询后填好（用户态拿不到 ort_caps() 本身）。
 */

static unsigned int g_caps;

/* 监督者时钟（毫秒）。用循环计数而不是 clock()：
 * 周期是确定的（LOOP_MS），不必依赖系统时钟的精度与语义。
 */

static int g_now_ms;
static int g_last_reload_ms;

/* 上一次 reload 失败的原因。用于把重复的同一错误折叠成一条。 */

static char g_reload_lasterr[160];

#define NCGS (g_ncgs)

/****************************************************************************
 * Manifest：配置的加载与校验
 *
 * 格式（行式，无嵌套，无引号，无转义 —— 刻意如此）：
 *
 *     version = 1
 *     startup_timeout_ms = 1500
 *
 *     [app_cg]
 *     domain = 1
 *     critical = false
 *     max_restarts = 2
 *     handles_fault = false
 *
 * ★ 为什么不用 YAML/JSON：
 *   启动路径上跑的解析器必须满足三条 —— 不动态分配、执行时间有界、
 *   行为可穷举。YAML 三条都不满足（隐式类型转换、锚点、可嵌套到任意深度）。
 *   INI 风格的子集足够表达 CG 表，而且**能被人在五分钟内完整理解** ——
 *   这在功能安全语境下不是简陋，是要求。
 *
 * ★ 校验原则：**fail-closed，不是 fail-open**
 *
 *   任何一条不认识的键、格式不对的行、缺字段、重复名 ——
 *   一律**拒绝整份 manifest**，并指出行号。
 *
 *   为什么不"忽略不认识的东西继续跑"：
 *     那正是配置错误的经典传播方式。运维以为改了一个参数，
 *     实际那行被静默丢掉了，系统按**另一套**配置运行 ——
 *     而且没有任何地方会报错。
 *     对安全系统来说，"拒绝启动"永远优于"按我以为的配置启动"。
 ****************************************************************************/

#define MANIFEST_PATH      "/system/etc/ort.cfg"
#define MANIFEST_MAXLINE   256   /* 注释里有 UTF-8 中文，一字符 3 字节，别卡太紧 */

/* ★ 解析阶段的 startup_timeout_ms 落在这里，**不直接写 g_startup_window_ms**。
 *   否则一份校验失败的 manifest 也已经改掉了运行时配置 ——
 *   而"拒绝新配置、保持旧配置"要求的是**一个字段都不能动**。
 *   提交动作只在调用方确认加载成功后做。 */

static int g_mf_startup_ms = STARTUP_WINDOW_MS;

static char g_mf_buf[160];
static FAR const char *g_mf_err;   /* 校验失败说明（指向 g_mf_buf，不分配） */

/* 记录失败原因。lineno == 0 表示"整份配置"层面的问题（不是某一行的错），
 * 那种情况不该硬安一个行号上去。 */

static void mf_err(int lineno, FAR const char *msg)
{
  if (lineno > 0)
    {
      snprintf(g_mf_buf, sizeof(g_mf_buf), "第 %d 行: %s", lineno, msg);
    }
  else
    {
      snprintf(g_mf_buf, sizeof(g_mf_buf), "manifest: %s", msg);
    }

  g_mf_err = g_mf_buf;
}

/* 去掉首尾空白，原地修改。
 *
 * ★ 行尾的 \r\n 也必须去掉 —— 它们也是空白，但上一版漏了，
 *   后果很隐蔽：空行变成"\n"（非空，于是掉进"不是 key = value"分支），
 *   而 "version = 1\n" 的值会带上换行符。实测第一版把一份**合法**
 *   manifest 拒在了第 5 行（就是那个空行）。
 *   把 \r \n 归进空白集，两处一起解决。
 */

static FAR char *mf_trim(FAR char *s)
{
  FAR char *end;

  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
    {
      s++;
    }

  end = s + strlen(s);
  while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                     end[-1] == '\r' || end[-1] == '\n'))
    {
      end--;
    }

  *end = '\0';
  return s;
}

/* 严格整数：整串都必须是数字。
 *
 * 为什么不用 atoi()：atoi("abc") == 0，atoi("1x") == 1 ——
 * 把拼写错误静默变成一个合法值，正是我们要拒绝的那类错误。 */

static bool mf_int(FAR const char *v, FAR int *out)
{
  int acc = 0;

  if (*v == '\0')
    {
      return false;
    }

  for (; *v != '\0'; v++)
    {
      if (*v < '0' || *v > '9')
        {
          return false;
        }

      acc = acc * 10 + (*v - '0');
      if (acc > 1000000)
        {
          return false;    /* 荒谬值直接拒，不溢出 */
        }
    }

  *out = acc;
  return true;
}

/* 严格布尔：只认 true / false。不认 1/0/yes/on/TRUE ——
 * 多一种写法就多一种歧义，而歧义在安全配置里是纯负债。 */

static bool mf_bool(FAR const char *v, FAR bool *out)
{
  if (strcmp(v, "true") == 0)
    {
      *out = true;
      return true;
    }

  if (strcmp(v, "false") == 0)
    {
      *out = false;
      return true;
    }

  return false;
}

#define SEEN_DOMAIN   (1u << 0)
#define SEEN_CRITICAL (1u << 1)
#define SEEN_RESTARTS (1u << 2)
#define SEEN_HANDLES  (1u << 3)
#define SEEN_ALL      (SEEN_DOMAIN | SEEN_CRITICAL | SEEN_RESTARTS | SEEN_HANDLES)

/* 两份规格是否**等价**（只看声明，不看运行时状态）。
 *
 * 等价 = 不需要动它 —— 这正是"滚动更新"区别于"整体重启"的地方：
 * 只重启**声明变了**的容器，没变的绝不打断。 */

static bool cg_spec_equal(FAR const struct ort_cg_s *a,
                          FAR const struct ort_cg_s *b)
{
  return a->domain        == b->domain &&
         a->critical      == b->critical &&
         a->max_restarts  == b->max_restarts &&
         a->handles_fault == b->handles_fault;
}

/****************************************************************************
 * Name: manifest_load
 *
 * Description:
 *   解析并**校验** manifest。任何可疑之处一律拒绝整份配置。
 *
 * Returned Value:
 *   OK 成功；负 errno 失败，失败原因在 g_mf_err 里（含行号）。
 *
 ****************************************************************************/

static int manifest_load(FAR const char *path,
                         FAR struct ort_cg_s *cgs, int maxcgs,
                         FAR int *ncgs)
{
  FAR struct ort_cg_s *cg = NULL;
  char line[MANIFEST_MAXLINE];
  char names[MAX_CGS][16];        /* 每个 CG 的名字存这儿 —— 解析缓冲区每行复用 */
  unsigned int seen[MAX_CGS];     /* 每个 CG 已出现过的键 */
  FILE *fp;
  int lineno = 0;
  bool have_version = false;
  int n = 0;
  int k;

  *ncgs = 0;
  g_mf_err = NULL;

  fp = fopen(path, "r");
  if (fp == NULL)
    {
      mf_err(lineno, "打不开 manifest 文件");
      return -ENOENT;
    }

  while (fgets(line, sizeof(line), fp) != NULL)
    {
      FAR char *p;
      FAR char *eq;
      FAR char *key;
      FAR char *val;

      lineno++;

      /* 行太长会被截断成两行，第二行多半语法不合法 —— 但**可能**恰好合法，
       * 那就成了静默错配。所以宁可在这里就拒。 */

      if (strchr(line, '\n') == NULL && !feof(fp))
        {
          mf_err(lineno, "行超长（疑似被截断）");
          goto fail;
        }

      p = mf_trim(line);
      if (*p == '\0' || *p == '#')
        {
          continue;
        }

      /* ── 段头 [name] ─────────────────────────────────────────────── */

      if (*p == '[')
        {
          FAR char *end = strchr(p, ']');
          FAR char *name;

          if (end == NULL || *mf_trim(end + 1) != '\0')
            {
              mf_err(lineno, "段头格式不对（应为 [name] 且其后无其它内容）");
              goto fail;
            }

          *end = '\0';
          name = mf_trim(p + 1);

          if (*name == '\0')
            {
              mf_err(lineno, "段名为空");
              goto fail;
            }

          if (strlen(name) >= sizeof(names[0]))
            {
              mf_err(lineno, "段名过长");
              goto fail;
            }

          if (n >= maxcgs)
            {
              mf_err(lineno, "CG 数量超过 MAX_CGS");
              goto fail;
            }

          for (k = 0; k < n; k++)
            {
              if (strcmp(names[k], name) == 0)
                {
                  mf_err(lineno, "CG 重名（同一容器组只能出现一次）");
                  goto fail;
                }
            }

          cg          = &cgs[n];
          memset(cg, 0, sizeof(*cg));
          strcpy(cg->namebuf, name);
          cg->name    = cg->namebuf;
          cg->domain      = -1;      /* -1 = 未声明，后面校验会拦 */
          cg->pid         = -1;
          cg->admitted_ms = -1;

          seen[n] = 0;
          n++;
          continue;
        }

      /* ── key = value ─────────────────────────────────────────────── */

      eq = strchr(p, '=');
      if (eq == NULL)
        {
          mf_err(lineno, "不是 key = value，也不是段头");
          goto fail;
        }

      *eq  = '\0';
      key  = mf_trim(p);
      val  = mf_trim(eq + 1);

      if (*key == '\0')
        {
          mf_err(lineno, "键名为空");
          goto fail;
        }

      if (cg == NULL)
        {
          /* 全局段 */

          if (strcmp(key, "version") == 0)
            {
              int v;

              if (!mf_int(val, &v) || v != 1)
                {
                  mf_err(lineno, "version 只支持 1");
                  goto fail;
                }

              have_version = true;
            }
          else if (strcmp(key, "startup_timeout_ms") == 0)
            {
              if (!mf_int(val, &g_mf_startup_ms))
                {
                  mf_err(lineno, "startup_timeout_ms 必须是十进制非负整数");
                  goto fail;
                }
            }
          else
            {
              mf_err(lineno, "全局段不认识的键");
              goto fail;
            }

          continue;
        }

      /* CG 段 */

      if (strcmp(key, "domain") == 0)
        {
          if (!mf_int(val, &cg->domain) || cg->domain > 254)
            {
              mf_err(lineno, "domain 必须是 0..254 的整数");
              goto fail;
            }

          if (seen[n - 1] & SEEN_DOMAIN)
            {
              mf_err(lineno, "domain 重复");
              goto fail;
            }

          seen[n - 1] |= SEEN_DOMAIN;
        }
      else if (strcmp(key, "critical") == 0)
        {
          if (!mf_bool(val, &cg->critical))
            {
              mf_err(lineno, "critical 只接受 true / false");
              goto fail;
            }

          if (seen[n - 1] & SEEN_CRITICAL)
            {
              mf_err(lineno, "critical 重复");
              goto fail;
            }

          seen[n - 1] |= SEEN_CRITICAL;
        }
      else if (strcmp(key, "max_restarts") == 0)
        {
          if (!mf_int(val, &cg->max_restarts) || cg->max_restarts > 1000)
            {
              mf_err(lineno, "max_restarts 必须是 0..1000 的整数");
              goto fail;
            }

          if (seen[n - 1] & SEEN_RESTARTS)
            {
              mf_err(lineno, "max_restarts 重复");
              goto fail;
            }

          seen[n - 1] |= SEEN_RESTARTS;
        }
      else if (strcmp(key, "handles_fault") == 0)
        {
          if (!mf_bool(val, &cg->handles_fault))
            {
              mf_err(lineno, "handles_fault 只接受 true / false");
              goto fail;
            }

          if (seen[n - 1] & SEEN_HANDLES)
            {
              mf_err(lineno, "handles_fault 重复");
              goto fail;
            }

          seen[n - 1] |= SEEN_HANDLES;
        }
      else
        {
          /* ★ 不认识的键是**错误**，不是"忽略"。
           *   忽略它，运维就永远不知道那行没生效。 */

          mf_err(lineno, "CG 段不认识的键");
          goto fail;
        }
    }

  fclose(fp);
  fp = NULL;

  /* ── 整体校验 ──────────────────────────────────────────────────────── */

  if (!have_version)
    {
      mf_err(0, "缺少 version（无法确认格式版本，拒绝按猜的解析）");
      goto fail;
    }

  if (n < 1)
    {
      mf_err(0, "至少要有一个 CG（空配置等于没有可编排的对象）");
      goto fail;
    }

  for (k = 0; k < n; k++)
    {
      if (seen[k] != SEEN_ALL)
        {
          mf_err(0, "CG 段字段不全（domain/critical/max_restarts/"
                    "handles_fault 四项都必须显式给出）");
          goto fail;
        }

      /* 域号必须互不相同 —— 两个容器组共用一个域，
       * 等于它们的内存不隔离。这是配置错误，不是运行时才发现的。 */

      {
        int j;

        for (j = 0; j < k; j++)
          {
            if (cgs[j].domain == cgs[k].domain)
              {
                mf_err(0, "两个 CG 用了同一个 domain（等于它们不隔离）");
                goto fail;
              }
          }
      }
    }

  *ncgs = n;
  return OK;

fail:
  if (fp != NULL)
    {
      fclose(fp);
    }

  n = 0;
  return -EINVAL;
}


/****************************************************************************
 * 系统状态与单调迁移
 ****************************************************************************/

static enum ort_sysstate_e g_state = ORT_BOOT;

/* ★ 单调迁移的唯一入口。
 *
 * 为什么把"单调"做成代码而不是注释：状态机的安全性来自"不会自己变回去"
 * 这条性质，而性质要靠**唯一入口**来保证。散落的赋值迟早会漏。
 */

static void state_to(enum ort_sysstate_e next)
{
  static const int rank[] =
  {
    [ORT_BOOT]        = 0,
    [ORT_NOMINAL]     = 1,
    [ORT_DEGRADED]    = 2,   /* 有效终态 */
    [ORT_SAFE_STATE]  = 3,   /* 有效终态 */
    [ORT_BOOT_FAILED] = 3,   /* 有效终态 */
  };

  if (rank[next] < rank[g_state])
    {
      /* 不允许回退 —— 这就是"锁存"的实现 */

      printf("[ortsup] *** 拒绝非单调迁移 %s → %s ***\n",
             state_name(g_state), state_name(next));
      return;
    }

  if (next == g_state)
    {
      return;
    }

  printf("[ortsup] 状态 %s → %s%s\n", state_name(g_state), state_name(next),
         (next == ORT_DEGRADED || next == ORT_SAFE_STATE) ? "（锁存）" : "");
  fflush(stdout);

  g_state = next;
}

/****************************************************************************
 * 安全动作（《设计》§5.3：由应用提供，ORT 只负责调用）
 *
 * 生产版约束：不得动态分配、不得阻塞、执行时间有上限。
 * 原型里就是打印 + 记录，满足上述约束。
 ****************************************************************************/

static void app_enter_safe_state(void)
{
  printf("[ortsup] >>> 执行安全动作 app_enter_safe_state()\n");
  fflush(stdout);
}

/****************************************************************************
 * 故障通道
 ****************************************************************************/

/* ★ 用**队列**而不是"记住最近一次"。
 *
 * 第一版把 victim 存在一个全局变量里，靠 `g_fault_events > g_handled`
 * 逐条消费 —— 那在**并发故障**下是错的：多条事件到达时
 * `g_fault_victim` 只剩最后一个，前面几条会被配上错误的 victim。
 * 监督者据此决定重启谁就是错的。
 *
 * 现在每条事件独立入队，逐条取用，不共享任何"当前值"。
 */

#define MAX_EVENTS  16

static volatile int g_ev_victim[MAX_EVENTS];
static volatile int g_ev_addr[MAX_EVENTS];
static volatile int g_ev_faults[MAX_EVENTS];
static volatile int g_ev_count;    /* 已入队的事件数 */
static volatile int g_ev_lost;     /* 内核侧累计丢弃数 */

/* 排空内核队列。信号只作唤醒，可能合并，所以每次都要读干净。 */

static void drain_faults(void)
{
  struct ort_faultrec_s rec;
  int n;

  while ((n = prctl(PR_GET_ORT_FAULT, &rec)) > 0)
    {
      if (g_ev_count < MAX_EVENTS)
        {
          g_ev_victim[g_ev_count] = rec.victim;
          g_ev_addr[g_ev_count]   = (int)rec.addr;
          g_ev_faults[g_ev_count] = (int)rec.faults;
        }

      g_ev_count++;
      g_ev_lost = (int)rec.lost;

      printf("[ortsup] ← 故障事件 #%u victim=%d pc=%p addr=%p faults=%u%s\n",
             (unsigned)rec.seq, rec.victim, (void *)rec.pc, (void *)rec.addr,
             (unsigned)rec.faults,
             rec.lost ? "  ⚠️ 有事件丢失" : "");
      fflush(stdout);
    }
}

static void fault_sig_handler(int signo, FAR siginfo_t *info, FAR void *ctx)
{
  (void)signo;
  (void)info;
  (void)ctx;

  /* ★ 不用信号载荷里的 pid —— 队列记录才是权威来源。
   *   信号可能合并（载荷只反映最后一次），而且它没有故障详情。
   */

  drain_faults();
}

/****************************************************************************
 * 容器侧
 ****************************************************************************/

/* 容器入口。argv 由 task_create 传入 —— 注意 NuttX 会把任务名放在
 * argv[0]（见 ortmem 那边的注释），所以参数从 argv[1] 起。
 *
 *   argv[1] = "ok" | "fault"
 *   argv[2] = 域号
 *   argv[3] = 干活之前先等几秒（可选，默认 0）
 *
 * 为什么要有延迟参数：
 *   监督者的 BOOT 是**同步**的（拉起全部 CG 后立即进 NOMINAL），而容器是
 *   **异步**的。不留时间差的话，容器会在监督者还在 BOOT 时就故障 ——
 *   这时该走的是《设计》§6 的 `startup.onContainerGroupFail` 策略，
 *   而不是运行期策略。原型没实现启动期策略（见下方"已知缺口"），
 *   所以用延迟把 BOOT 阶段让出来，让日志反映的是运行期行为。
 */

static int ort_container_main(int argc, FAR char *argv[])
{
  FAR const char *mode = NULL;
  volatile uint32_t *own;
  volatile uint32_t *other;
  int delay = 0;
  int domain = 0;
  int k;

  /* ★ 按**标记**找参数，不按下标数。
   *
   *   两条创建路径的 argv 差一个位置：
   *     task_create()  （ORT-M / PROTECTED）—— 内核把程序名插到 argv[0]
   *     posix_spawn()  （ORT-A / KERNEL）  —— 实测原样传递，不插
   *   数下标在一条路上必然错位，而且错位后表现为"域号读成垃圾"，
   *   很难看出来。（ortbad 已经因为同一件事踩过一次，见手册 坑 3。）
   */

  for (k = 0; k < argc; k++)
    {
      if (argv[k] != NULL && strcmp(argv[k], "container") == 0)
        {
          break;
        }
    }

  if (k + 3 >= argc)
    {
      printf("[ortsup] 容器: 参数不足 (argc=%d, marker=%d)\n", argc, k);
      return 1;
    }

  mode   = argv[k + 1];
  domain = atoi(argv[k + 2]);
  delay  = atoi(argv[k + 3]);

  /* 准入等待：容器创建与监督者绑域之间有窗口（见 ortmem 的说明） */

  {
    int waited = 0;

    while (prctl(PR_GET_ORT_DOMAIN) < 0)
      {
        if (++waited > 2000)
          {
            printf("[ortsup] 容器 %d: 等不到绑域\n", domain);
            return 1;
          }

        usleep(1000);
      }
  }

#if defined(CONFIG_BUILD_KERNEL)

  /* ── ORT-A（MMU）：没有"内存域"这个维度 ─────────────────────────────
   *
   * 隔离由**独立地址空间**天然给出 —— 越界访问必然落到未映射地址上，
   * 不需要（也没有）一个"别人的块"可供比对。
   *
   *   own   = 本进程自己的静态变量（当然可写；只作成功对照）
   *   other = 一个必定未映射的地址
   *
   * 0xdeadbe00 的选法与 ortbad 一致：低地址、不在任何映射区、
   * 也不在栈附近 —— 免得测出来的是"栈溢出"而不是"越界"。
   *
   * ⚠️ 注意 POOL_BASE 那一组地址是 **MPU 侧**的内存池，在 ORT-A 上
   *    根本没有映射 —— 照搬过来会在第一次写就 fault，
   *    看起来像"隔离立即生效"，其实是地址压根不存在。
   */

  {
    static volatile uint32_t s_own;

    own   = &s_own;
    other = (volatile uint32_t *)0xdeadbe00u;
  }

#else

  own   = (volatile uint32_t *)(POOL_BASE + (uint32_t)domain * BLOCK_SIZE);
  other = (volatile uint32_t *)
            (POOL_BASE + ((uint32_t)domain + 1) % NBLOCKS * BLOCK_SIZE);

#endif

  if (strcmp(mode, "ok") == 0)
    {
      for (;;)
        {
          *own = 0xa5a5a5a5u;
          sleep(1);
        }
    }

  if (delay > 0)
    {
      printf("[ortsup] 容器(domain %d): 正常工作中，%d 秒后注入故障\n",
             domain, delay);
      fflush(stdout);

      sleep(delay);
    }

  printf("[ortsup] 容器(domain %d): 越界写 %p\n", domain, (void *)other);
  fflush(stdout);

  *other = 0xbadbadu;      /* ← 必然触发 MemManage fault */

  printf("[ortsup] *** 容器存活 *** 隔离失效\n");
  return 9;
}

/****************************************************************************
 * 监督者
 ****************************************************************************/

static int start_cg(FAR struct ort_cg_s *cg, FAR const char *mode, int delay);

/****************************************************************************
 * Name: manifest_reload
 *
 * Description:
 *   重新读 manifest，校验通过则**只把差异应用下去**。
 *
 * ★ reload 失败时的处置，与启动时**故意不同**：
 *
 *     启动时失败 → 拒绝启动（fail-closed）
 *     运行中失败 → **保持当前配置继续运行**（fail-safe）
 *
 *   看起来矛盾，其实是因为**处境不同**：
 *
 *     - 启动时手上没有任何"已知可用"的配置，唯一的诚实动作是拒绝。
 *       用默认值兜底 = 按一套没人写过的配置运行。
 *     - 运行中手上正跑着一份**已经工作着的**配置。此时新配置有问题，
 *       正确的动作是"不采纳" —— 退回一个不存在的配置才是荒谬的。
 *
 *   把这两件事写成同一个策略（要么都拒、要么都退回默认）都会错。
 *   这也是 functional safety 里 fail-safe / fail-closed 两个词
 *   不能混用的原因。
 *
 * Returned Value:
 *   OK      已应用（或无差异）
 *   -EINVAL 新配置不合法 —— 当前配置**原样保留**
 *
 ****************************************************************************/

static int manifest_reload(void)
{
  static struct ort_cg_s scratch[MAX_CGS];   /* 先解析到暂存区，验完再采纳 */
  int n_prev = g_ncgs;
  int n = 0;
  int k;
  int j;
  int applied = 0;

  if (manifest_load(MANIFEST_PATH, scratch, MAX_CGS, &n) != OK)
    {
      /* ★ 只在错误**变了**的时候打印。
       *
       *   轮询是每 2 秒一次，不折叠的话一份坏配置会把日志刷满 ——
       *   而运维真正需要的是"什么时候开始坏的、坏在哪"，
       *   不是"它重复了多少次"。实测：不折叠时 13 秒刷了 6 遍同一条。
       */

      if (strcmp(g_mf_err ? g_mf_err : "?", g_reload_lasterr) != 0)
        {
          printf("[ortsup] *** 拒绝新配置（当前配置原样继续运行）***\n");
          printf("[ortsup] %s: %s\n", MANIFEST_PATH,
                 g_mf_err ? g_mf_err : "未知原因");
          fflush(stdout);

          strncpy(g_reload_lasterr, g_mf_err ? g_mf_err : "?",
                  sizeof(g_reload_lasterr) - 1);
          g_reload_lasterr[sizeof(g_reload_lasterr) - 1] = '\0';
        }

      return -EINVAL;
    }

  g_reload_lasterr[0] = '\0';   /* 成功一次就把折叠状态清掉 */

  /* ── 已删除的 CG：停掉 ───────────────────────────────────────────── */

  for (k = 0; k < n_prev; k++)
    {
      bool still = false;

      for (j = 0; j < n; j++)
        {
          if (strcmp(scratch[j].namebuf, g_cgs[k].name) == 0)
            {
              still = true;
              break;
            }
        }

      if (!still && g_cgs[k].pid > 0)
        {
          printf("[ortsup] 配置变更: %s 已从 manifest 移除 → 停止 (pid=%d)\n",
                 g_cgs[k].name, (int)g_cgs[k].pid);
          if (kill(g_cgs[k].pid, SIGKILL) != 0)
            {
              printf("[ortsup]   ⚠ kill 失败 (errno=%d) —— 该容器仍在运行\n",
                     errno);
            }

          g_cgs[k].pid    = -1;
          g_cgs[k].failed = true;
        }
    }

  /* ── 新增 / 变更 ───────────────────────────────────────────────────
   *
   * 先把"变更"挑出来重启，最后再把 scratch 整体搬过去 ——
   * 顺序反了会把旧规格覆盖掉，就没法判断"变了没有"了。
   */

  for (k = 0; k < n; k++)
    {
      FAR struct ort_cg_s *live = NULL;

      for (j = 0; j < n_prev; j++)
        {
          if (strcmp(scratch[k].namebuf, g_cgs[j].name) == 0)
            {
              live = &g_cgs[j];
              break;
            }
        }

      if (live == NULL)
        {
          printf("[ortsup] 配置变更: %s 是新增的\n", scratch[k].namebuf);
          applied++;
        }
      else if (!cg_spec_equal(live, &scratch[k]))
        {
          printf("[ortsup] 配置变更: %s 的声明变了 → 重启 (pid=%d)\n",
                 scratch[k].namebuf, (int)live->pid);

          if (live->pid > 0 && kill(live->pid, SIGKILL) != 0)
            {
              printf("[ortsup]   ⚠ kill 失败 (errno=%d)\n", errno);
            }

          applied++;
        }
      else
        {
          /* ★ 声明没变 → **保持 pid 与计数器不动**。
           *   这条就是滚动更新的全部意义：不打断没变的容器。 */

          scratch[k].pid         = live->pid;
          scratch[k].admitted_ms = live->admitted_ms;
          scratch[k].restarts    = live->restarts;
          scratch[k].faults      = live->faults;
          scratch[k].failed      = live->failed;
        }
    }

  memcpy(g_cgs, scratch, sizeof(g_cgs[0]) * n);
  for (k = n; k < n_prev; k++)
    {
      memset(&g_cgs[k], 0, sizeof(g_cgs[0]));
    }

  /* 到这里才提交 —— 见 g_mf_startup_ms 的说明 */

  g_startup_window_ms = g_mf_startup_ms;
  g_ncgs              = n;

  printf("[ortsup] manifest 已重载: %d 个 CG，%d 项变更\n", n, applied);

  /* 新增或重启的 CG 现在拉起来 */

  for (k = 0; k < n; k++)
    {
      if (g_cgs[k].pid <= 0 && !g_cgs[k].failed)
        {
          start_cg(&g_cgs[k], "fault", g_cgs[k].critical ? 8 : 3);
        }
    }

  fflush(stdout);
  return OK;
}

/****************************************************************************
 * Name: admit_ok
 *
 * Description:
 *   准入判定：这份 manifest 在当前平台上**能不能被兑现**？
 *
 *   ★ 这是整个能力位机制存在的理由。
 *
 *   以前（隐式差异）：容器声明"故障我自己处理"，ORT-M 上处理器会被调用，
 *   ORT-A 上处理器被静默跳过、直接 SIGKILL。同一份 manifest、两套语义，
 *   而部署方没有任何地方能问出这件事 —— 只能靠踩坑发现。
 *
 *   现在（显式准入）：兑现不了就**在准入阶段拒绝**。
 *   拒绝是安全动作（fail-closed）：容器根本没被创建，
 *   而不是"创建了、跑起来了、出事时才发现承诺没兑现"。
 *
 ****************************************************************************/

static bool admit_ok(FAR const struct ort_cg_s *cg)
{
  return !cg->handles_fault ||
         (g_caps & ORT_CAP_FAULT_HANDLER) != 0;
}

static int start_cg(FAR struct ort_cg_s *cg, FAR const char *mode, int delay)
{
  FAR char *cargv[5];
  char dbuf[8];
  char lbuf[8];
  pid_t pid;

  /* ── 准入门禁 ──────────────────────────────────────────────────────
   *
   * ★ 必须在 task_create() **之前**判，不能创建了再杀。
   *   "拒绝准入"和"启动了再终止"是两回事：后者容器已经持有资源、
   *   可能已经碰过共享状态、而且会白白消耗一次重启预算。
   */

  if (!admit_ok(cg))
    {
      printf("[ortsup] *** 拒绝准入 %s: manifest 声明 handles_fault=1，"
             "但本平台不提供 ORT_CAP_FAULT_HANDLER ***\n", cg->name);
      printf("[ortsup]     兑现不了的声明不能默默降级 —— "
             "容器未被创建（fail-closed）\n");
      fflush(stdout);

      cg->failed = true;
      return -1;
    }

  snprintf(dbuf, sizeof(dbuf), "%d", cg->domain);
  snprintf(lbuf, sizeof(lbuf), "%d", delay);

  /* ── 拉起容器：两条路，取决于构建模式 ──────────────────────────────
   *
   * ★ 这里原来只有 task_create() 一条路，在 ORT-A 上**直接链接失败**：
   *
   *     undefined reference to `task_create'
   *
   *   不是缺 include —— syscall/syscall.csv 明确用
   *   !defined(CONFIG_BUILD_KERNEL) 把它排除了：
   *   KERNEL 构建下用户态任务**只能**通过 posix_spawn()/task_spawn()
   *   加载一个 ELF，没有"直接创建任务"这回事。
   *
   *   这也是 §三·补十七 那个硬发现的正面修法：监督者不该假设自己能
   *   凭空造任务 —— 那是 PROTECTED 才有的能力。
   *
   *   代价是容器必须是一个可执行的 ELF。这里让它 spawn **自己**
   *   （`ortsup container ...`），省掉一个只有几行的壳程序。
   */

  cargv[0] = (FAR char *)"container";   /* 标记位，两条路的唯一锚点 */
  cargv[1] = (FAR char *)mode;
  cargv[2] = dbuf;
  cargv[3] = lbuf;
  cargv[4] = NULL;

#if defined(CONFIG_BUILD_KERNEL)

  /* ORT-A：独立地址空间，容器是独立 ELF */

  {
    int ret = posix_spawn(&pid, CONTAINER_PATH, NULL, NULL, cargv, NULL);

    if (ret != 0)
      {
        printf("[ortsup] 启动 %s 失败: posix_spawn ret=%d\n",
               cg->name, ret);
        return -ret;
      }
  }

#else

  /* ORT-M：PROTECTED，可以直接创建一个任务，入口就是本文件里的函数 */

  pid = task_create(cg->name, CONTAINER_PRIO, CONTAINER_STACK,
                    ort_container_main, cargv);
  if (pid < 0)
    {
      printf("[ortsup] 启动 %s 失败: %d\n", cg->name, (int)pid);
      return (int)pid;
    }

#endif

  /* 在这里打印而不是回到 main 里统一打印：
   * 此刻容器已创建但还卡在准入等待（域未绑），不会抢先输出 ——
   * 否则监督者的 BOOT 行会和容器的首行交织成乱码。
   */

  if (!cg->restarts)
    {
      printf("[ortsup] BOOT: 启动 %s (domain %d, pid=%d, %s, maxRestarts=%d)\n",
             cg->name, cg->domain, (int)pid,
             cg->critical ? "关键" : "非关键", cg->max_restarts);
    }

  /* 绑域：**只有监督者能做**（容器自申报会被 -EPERM 拒绝）。
   * 这一步是"容器"与"一段任意代码"的分界线 —— 从此刻起它才有内存域。
   */

  if (prctl(PR_SET_ORT_DOMAIN, cg->domain, (int)pid) != 0)
    {
      printf("[ortsup] 绑域失败 %s pid=%d\n", cg->name, (int)pid);
      return -1;
    }

  cg->pid         = pid;
  cg->admitted_ms = g_now_ms;    /* ★ 准入时刻 —— 启动窗口从这里开始算 */
  return 0;
}

/* 一个 CG 失效时的策略决策（《设计》§3.2 的转移规则） */

/* 该 CG 是否仍处于启动期。
 *
 * ★ 判据是两部分的合取：
 *     ① 系统还在 BOOT 阶段（g_state == ORT_BOOT）
 *     ② 该 CG 尚未通过自己的启动窗口
 *
 * 为什么必须带上 ①：
 *   第一版只判 ②，于是**每次重启都会重新进入启动窗口** ——
 *   一个重启后 840ms 就崩的容器被判成"启动期失效"，直接跳 SAFE_STATE，
 *   重启预算形同虚设。
 *
 *   §6 的 `startup` 策略讲的是**系统启动阶段**，不是"每个容器每次启动"。
 *   进入 NOMINAL 之后，所有失效（包括重启后的立即失效）都是运行期问题，
 *   正确的升级路径是**耗尽重启预算**（→ DEGRADED），而不是跳安全态。
 */

static bool in_startup(FAR struct ort_cg_s *cg)
{
  return g_state == ORT_BOOT &&
         cg->admitted_ms >= 0 &&
         (g_now_ms - cg->admitted_ms) < g_startup_window_ms;
}

/* 是否全部 CG 都已通过启动窗口（= 系统可以进 NOMINAL 了） */

static bool all_cgs_ready(void)
{
  int i;

  for (i = 0; i < (int)NCGS; i++)
    {
      if (!g_cgs[i].failed && in_startup(&g_cgs[i]))
        {
          return false;
        }
    }

  return true;
}

static void on_cg_failed(FAR struct ort_cg_s *cg)
{
  cg->faults++;

  /* ★ H29：先判启动期还是运行期 —— 两套策略语义完全不同。
   *
   * 启动期失效 = "这个容器根本起不来" → 部署问题 → 按 §6 startup 策略
   * 运行期失效 = "它跑了、然后坏了"     → 运行时问题 → 可以先重启
   */

  if (in_startup(cg))
    {
      printf("[ortsup] %s 在启动窗口内失效（准入后 %d ms < %d ms）"
             "→ 按 startup 策略\n",
             cg->name, g_now_ms - cg->admitted_ms, g_startup_window_ms);

      /* 原型的 startup 策略取 SAFE_STATE：按 §6，
       * startup.onContainerGroupFail 是**全系统一套**策略（不像运行期
       * 那样可被单个 CG 覆盖）—— 因为"启动阶段就起不来"通常意味着
       * 部署/配置有问题，继续跑没有意义。
       */

      cg->failed = true;
      app_enter_safe_state();
      state_to(ORT_SAFE_STATE);
      return;
    }

  printf("[ortsup] %s 失效（第 %d 次，restart %d/%d）\n",
         cg->name, cg->faults, cg->restarts, cg->max_restarts);

  /* 以下为运行期策略。关键 CG：无论重启预算如何，直接进安全态（T7 / T8） */

  if (cg->critical)
    {
      printf("[ortsup] %s 是关键 CG → 执行安全动作\n", cg->name);
      app_enter_safe_state();
      cg->failed = true;
      state_to(ORT_SAFE_STATE);
      return;
    }

  /* 非关键 CG：先看重启预算（《设计》§5.4 restartPolicy: ON_FAILURE） */

  if (cg->restarts < cg->max_restarts)
    {
      cg->restarts++;
      printf("[ortsup] %s: 重启 %d/%d\n", cg->name, cg->restarts,
             cg->max_restarts);

      if (start_cg(cg, "fault", 1) != 0)
        {
          cg->failed = true;
          state_to(ORT_DEGRADED);
        }

      return;   /* 仍在 NOMINAL */
    }

  /* ★ 重启预算耗尽 —— 这就是"有界"的意义：
   *   一个反复崩溃的容器不能把监督者变成永动机。
   */

  printf("[ortsup] %s: 重启预算耗尽 → 降级\n", cg->name);
  cg->failed = true;
  state_to(ORT_DEGRADED);
}

/****************************************************************************
 * 入口
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  struct sigaction sa;

  /* ── 容器入口 ────────────────────────────────────────────────────────
   *
   * 本 ELF 也可以被自己 spawn 出来当**容器**跑（ORT-A 走这条路）。
   *
   * ★ 必须在做任何监督者初始化**之前**判：容器不该注册监督者、
   *   更不该去复位监督者槽位 —— 那会把真监督者顶掉。
   *   位置比判断本身更容易出错。
   */

  {
    int k;

    for (k = 0; k < argc; k++)
      {
        if (argv[k] != NULL && strcmp(argv[k], "container") == 0)
          {
            return ort_container_main(argc, argv);
          }
      }
  }

  bool boot_mode;
  bool admit_mode;
  bool settled;
  int i;
  int rounds = 0;
  int g_handled;

  /* 输出即交付物：容器与监督者并发打印，行缓冲会让整行被截断/交错，
   * 状态机看起来就像乱的。改成无缓冲。
   */

  setvbuf(stdout, NULL, _IOLBF, 0);

  boot_mode  = (argc > 1 && strcmp(argv[1], "boot") == 0);
  admit_mode = (argc > 1 && strcmp(argv[1], "admit") == 0);

  printf("[ortsup] === ORT 监督者原型（降级状态机）===\n");

  /* ── 加载 manifest ───────────────────────────────────────────────────
   *
   * ★ fail-closed：manifest 有任何问题就**拒绝启动**。
   *
   *   不"用默认值兜底继续跑" —— 那等于用一套运维没写过的配置运行系统，
   *   而且没人知道。安全系统里，"拒绝启动 + 说清哪里错" 永远优于
   *   "按我以为的配置启动"。
   *
   *   注意这里连 ENOMEM 之类的错误一视同仁：解析器不做动态分配，
   *   所以失败只可能是配置本身的问题。
   */

  {
    int ret = manifest_load(MANIFEST_PATH, g_cgs, MAX_CGS, &g_ncgs);

    if (ret != OK)
      {
        printf("[ortsup] *** 拒绝启动: manifest 校验失败 ***\n");
        printf("[ortsup] %s: %s\n", MANIFEST_PATH,
               g_mf_err ? g_mf_err : "未知原因");
        printf("[ortsup] 系统状态: BOOT_FAILED（锁存）\n");
        fflush(stdout);
        return 2;
      }

    /* 解析成功才提交（见 g_mf_startup_ms 的说明） */

    g_startup_window_ms = g_mf_startup_ms;
  }

  printf("[ortsup] manifest: %s（%d 个 CG，启动窗口 %d ms）\n",
         MANIFEST_PATH, (int)NCGS, g_startup_window_ms);

  {
    int k;

    for (k = 0; k < (int)NCGS; k++)
      {
        printf("[ortsup]   CG %-10s domain=%d %s maxRestarts=%d "
               "handles_fault=%s\n",
               g_cgs[k].name, g_cgs[k].domain,
               g_cgs[k].critical ? "关键" : "非关键",
               g_cgs[k].max_restarts,
               g_cgs[k].handles_fault ? "true" : "false");
      }
  }

  printf("[ortsup] 场景: %s\n",
         boot_mode ? "boot —— 启动期失效" : "runtime —— 运行期失效");
  printf("[ortsup] 系统状态: BOOT\n");

  /* ── 平台能力位 ──────────────────────────────────────────────────────
   *
   * 读一次就够 —— 它是平台属性，运行期不会变。
   * 用户态拿不到 ort_caps() 本身，只能走 prctl。
   */

  g_caps = (unsigned int)prctl(PR_GET_ORT_CAPS);

  printf("[ortsup] 平台能力位: 0x%08x（FAULT_HANDLER=%s）\n",
         g_caps, (g_caps & ORT_CAP_FAULT_HANDLER) ? "有" : "无");
  fflush(stdout);

  /* ── 准入演练（ortsup admit）────────────────────────────────────────
   *
   * 同一份 manifest（两个 CG 都声明 handles_fault=1），在两个 SKU 上
   * 得到**不同**的准入结论 —— 而且结论是被显式打印出来的。
   *
   * 这就是"隐式差异"和"显式准入"的区别：
   *   以前：跑起来、出事、发现承诺没兑现 —— 靠踩坑才知道平台不支持。
   *   现在：准入阶段就拒绝，容器根本没被创建。
   */

  if (admit_mode)
    {
      int k;

      printf("[ortsup] === 准入演练：manifest 声明 handles_fault=1 ===\n");

      for (k = 0; k < (int)NCGS; k++)
        {
          g_cgs[k].handles_fault = true;

          printf("[ortsup]   %-10s → %s\n", g_cgs[k].name,
                 admit_ok(&g_cgs[k]) ? "准入通过"
                                     : "*** 拒绝（平台不兑现）***");
          printf("[ortsup]      %s\n", admit_ok(&g_cgs[k])
                 ? "故障处理器会被调用（处理器是通知，容器仍须死）"
                 : "故障处理器不会被调用，内核直接升级 SIGKILL");
        }

      fflush(stdout);
      return 0;
    }

  /* 注册监督者 + 挂故障通道。注意信号用 SIGUSR1：
   * CONFIG_SIG_SIGUSR1_ACTION 默认为 n，内核不配默认动作，
   * 只有主动挂钩子的任务会收到。
   */

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = fault_sig_handler;
  sa.sa_flags     = SA_SIGINFO;
  sigaction(ORT_SIGFAULT, &sa, NULL);

  /* 监督者槽位是钉住的 —— 连续跑多轮需要先复位。
   * 那是仅原型可用的接口（CONFIG_ORT_SUPERVISOR_RESET）。
   */

  prctl(PR_ORT_SUPERVISOR_RESET);

  if (prctl(PR_SET_ORT_SUPERVISOR) != 0)
    {
      printf("[ortsup] FAIL: 注册监督者失败\n");
      return 1;
    }

  /* ── BOOT：按 startOrder 拉起全部 CG ──────────────────────────────── */

  /* 两个演示场景：
   *
   *   默认      —— 容器**跑起来之后**才失效 → 运行期策略（重启 → 降级）
   *   ortsup boot —— 容器**在启动窗口内**就失效 → 启动期策略（直接安全态）
   *
   * 同样的故障、同样的容器，两套策略给出完全不同的响应 ——
   * 这正是 H29 要回答的问题。
   *
   * 默认场景的延迟取值：首次故障必须晚于 STARTUP_WINDOW_MS(1500ms)，
   * 否则会被判成启动期失效。
   *   app_cg    3s → 窗口外；走 3s/6s/9s 三次 → 预算耗尽 → DEGRADED
   *   safety_cg 8s  → 留足余量，让 app_cg 先走完 3 轮
   *
   * ⚠️ 顺序本质上依赖时序。演示可以靠余量保证，但**状态机本身不能
   *    假设事件顺序** —— 真实系统里 safety_cg 完全可能先失效
   *    （那就是 T7：直接 NOMINAL → SAFE_STATE，同样正确）。
   */

  if (start_cg(&g_cgs[0], "fault", boot_mode ? 0 : 3) != 0 ||
      start_cg(&g_cgs[1], "fault", boot_mode ? 2 : 8) != 0)
    {
      state_to(ORT_BOOT_FAILED);
      return 1;
    }

  /* ★ 不在这里进 NOMINAL。
   *
   * 「全部 CG 已创建」不等于「全部 CG 已就绪」—— 容器是异步的，
   * 创建成功只说明 fork 成功，不代表它能跑起来。
   * BOOT → NOMINAL 的条件必须是**全部 CG 通过启动窗口**，
   * 由监督循环里的 all_cgs_ready() 判定。
   *
   * 这正是 H29 的核心：如果这里就宣布 NOMINAL，启动期失效会被记成
   * "运行期失效"，走完全错误的那套策略。
   */

  /* ── 监督循环 ──────────────────────────────────────────────────────
   *
   * 生产版是"ORT 可信周期任务"（《设计》§5.2）：固定周期执行，
   * 不依赖任何容器的事件，从而保证最坏响应时间可计算。
   * 原型里用固定周期轮询 + 事件标记，结构同构。
   */

  /* ★ 事件驱动，不收尸。
   *
   * 为什么不用 waitpid() 轮询子进程：
   *   NuttX 在 CONFIG_SCHED_WAITPID && !CONFIG_SCHED_HAVE_PARENT 下，
   *   `nxsched_waitpid()` 发现 `nxsched_get_tcb(pid) == NULL` 就直接返回
   *   -ECHILD（sched/sched/sched_waitpid.c）——**已死的子进程收不了**，
   *   只有「父进程正阻塞在 waitpid 上时子进程才死」才能拿到状态。
   *   所以轮询式的 waitpid(WNOHANG) 在这个配置下根本不工作。
   *
   * 而这恰恰是设计要的样子：ort_safety 靠**故障事件**驱动，
   * 不靠轮询子进程。终止由内核保证（见 arm_memfault.c 的终止权），
   * 监督者只需要知道"谁出事了"，然后决策。
   *
   * 代价：容器「正常退出」在原型里收不到通知。正式实现需要进程退出
   * 事件通道，或恢复 waitpid 语义。
   */

  g_handled = 0;
  for (;;)
    {
      if (++rounds > 20000)
        {
          printf("[ortsup] *** 监督循环超时 ***\n");
          break;
        }

      /* ── manifest 轮询 ─────────────────────────────────────────────
       *
       * 每 RELOAD_POLL_MS 重读一次。用轮询而不是 inotify/SIGHUP：
       * hostfs 下没有 inotify，而 SIGHUP 需要一个能发信号的助手 ——
       * 两者都会把"演示能不能跑"绑到别的东西上。
       *
       * 原型里轮询是可接受的：文件小、间隔长、解析不分配内存。
       * 正式实现应当换成变更通知，并把解析移到**优先级更低**的
       * 上下文 —— 现在它跑在监督循环里，会占掉这段时间。
       */

      if (g_now_ms - g_last_reload_ms >= RELOAD_POLL_MS)
        {
          g_last_reload_ms = g_now_ms;
          manifest_reload();
        }

      /* 排空内核队列，逐条投递给状态机（每条独立，不共享"当前值"） */

      drain_faults();

      while (g_handled < g_ev_count)
        {
          int victim = g_ev_victim[g_handled];

          g_handled++;

          for (i = 0; i < (int)NCGS; i++)
            {
              if (g_cgs[i].pid == (pid_t)victim)
                {
                  g_cgs[i].pid = -1;
                  on_cg_failed(&g_cgs[i]);
                  break;
                }
            }
        }

      /* ★ BOOT → NOMINAL 由「全部 CG 通过启动窗口」驱动 */

      if (g_state == ORT_BOOT && all_cgs_ready())
        {
          state_to(ORT_NOMINAL);
        }

      /* 安全态是锁存终态 —— 到了就停 */

      if (g_state == ORT_SAFE_STATE)
        {
          break;
        }

      /* 全部 CG 都不再运行 → 监督结束 */

      settled = true;
      for (i = 0; i < (int)NCGS; i++)
        {
          if (!g_cgs[i].failed)
            {
              settled = false;
              break;
            }
        }

      if (settled)
        {
          break;
        }

      usleep(LOOP_MS * 1000);
      g_now_ms += LOOP_MS;      /* 监督者时钟 */
    }

  /* ── 收尾 ──────────────────────────────────────────────────────── */

  /* ★ 演示公理 S2：安全态锁存。
   *
   * 安全态不是"自动恢复"的目标 —— 它只能通过**授权的外部动作**离开
   * （断电重启，或经鉴权的操作员复位）。这里模拟一次「非授权的自动
   * 恢复尝试」，状态机必须拒绝它。
   *
   * 为什么这条值得单独演示：它是 SAFE_STATIC 最容易通过认证的原因 ——
   * "不会自己变回去"是一个可以用代码穷举证明的性质，而"有条件恢复"
   * 需要论证所有恢复条件的安全性。
   */

  if (g_state == ORT_SAFE_STATE)
    {
      printf("[ortsup] 模拟非授权复位尝试: state_to(NOMINAL)\n");
      state_to(ORT_NOMINAL);
      printf("[ortsup] 尝试后状态仍为: %s\n", state_name(g_state));

      if (g_state != ORT_SAFE_STATE)
        {
          printf("[ortsup] *** FAIL *** 锁存被破坏\n");
          return 1;
        }
    }

  printf("[ortsup] SUPERVISOR RESULT: state=%s", state_name(g_state));

  for (i = 0; i < (int)NCGS; i++)
    {
      printf(" | %s: faults=%d restarts=%d", g_cgs[i].name,
             g_cgs[i].faults, g_cgs[i].restarts);
    }

  printf(" | events=%d lost=%d\n", g_ev_count, g_ev_lost);

  /* 最终态的断言：本原型跑完必须落在有效终态上 */

  if (g_state != ORT_SAFE_STATE && g_state != ORT_DEGRADED &&
      g_state != ORT_BOOT_FAILED)
    {
      printf("[ortsup] *** FAIL *** 结束时不在有效终态\n");
      return 1;
    }

  return 0;
}
