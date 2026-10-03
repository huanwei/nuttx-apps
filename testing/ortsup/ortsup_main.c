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
#include <sched.h>
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

/* 状态发布周期。要比启动窗口（1.5s）短一个数量级，
 * 否则接替者读到的是过期快照。 */

#define PUBLISH_PERIOD_US  100000

#define POOL_BASE   0x60840000u
#define BLOCK_SIZE  (16 * 1024u)
#define NBLOCKS     4

/* 监督者自己的调度优先级。理由与 ortd 里的同名宏相同（见那里的说明）：
 * Kconfig 的 PRIORITY 是内置应用的概念，在 ORT-A 上到不了源码，
 * 而"监督者必须高于它监督的对象"是架构不变量，不是可调项。
 *
 * ★ 三个值必须保持：监督者(100) < 容器(110) < 代理(120)
 *   —— NuttX 里数值越小优先级越高。 */

#define SUPERVISOR_PRIO  100

#define CONTAINER_PRIO   110
#define CONTAINER_STACK  2048

/* 启动窗口：准入之后多少毫秒内仍算「启动期」。
 * 对应《设计》§6 的 safetyPolicy.startup.startTimeoutMs。
 */

#define STARTUP_WINDOW_MS  1500     /* manifest 里的 startup_timeout_ms 覆盖它 */

static int g_startup_window_ms = STARTUP_WINDOW_MS;

/* 监督循环周期（也是下面 g_now_ms 的步长） */

#define LOOP_MS  5

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

  /* 容器**自己的**版本号（来自 manifest）。
   *
   * ★ 它决定状态快照能不能跨实例交接 —— 见容器里 state_blob 的说明。
   *   放在 manifest 而不是编译进容器，是因为"这次部署的是哪个版本"
   *   本来就是部署的属性，不是二进制的属性。 */

  int             version;

  /* 本 CG 实现了 ORT 的哪一版**生命周期协议**（来自 manifest）。
   *
   *   0 = 什么都没实现（第三方二进制、或没配合改造过的容器）
   *   1 = 实现了 v1：SIGTERM 有界退出 + 状态发布/跟踪/接管
   *
   * ★ 这是**容器维度**的能力，与 ort_caps() 那个**平台维度**的能力
   *   是两件正交的事。准入要同时看两边：
   *
   *     平台兑现不了 handles_fault  → 做不了  → **拒绝准入**
   *     容器没实现生命周期协议      → 做得差  → **降级替换方式并明示**
   *
   *   这两种后果不能混：前者是"这台机器给不了"，后者是"这个容器
   *   给不了"。混在一起会让人以为 protocol=0 的容器不能部署 ——
   *   它能部署，只是不能热替换。
   */

  int             protocol;

  /* 运行期**实测**到的兑现情况：1 = 声明被证伪。
   *
   * ★ 为什么必须有这个字段：protocol 是 manifest 作者的**声明**，
   *   不是容器的事实。声明只保护一个方向 ——
   *     声明 0 而实际支持 v1  → 走保守路径（冷替换），无害；
   *     声明 1 而实际没实现    → **危险方向**：监督者会按热替换办，
   *                              而容器既不响应 SIGTERM 也不发布状态，
   *                              于是"事务性替换 + 状态延续"两条承诺
   *                              同时落空，日志上却看不出任何异常。
   *
   *   所以监督者必须能**反向证伪**它（公理 S1：不信任失效组件）。
   *   判据见 audit_protocol()。
   */

  int             protocol_falsified;

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

/* 事件序审计（§三·补三十一 的验收装置） */

static uint32_t g_audit_last;    /* 上一条读到的事件号 */
static int      g_audit_gap;     /* 累计缺口（丢了但账对得上） */
static int      g_audit_bad;     /* 累计异常（倒退/重复/账对不上） */

/* 上一次 reload 失败的原因。用于把重复的同一错误折叠成一条。 */

static char g_reload_lasterr[160];

/* ── 配置通道的运行期状态 ──────────────────────────────────────────────
 *
 * 控制循环每周期只做两件**有界**的事：读一个代数、读一个心跳。
 * 两者都是标量，不阻塞、不分配、不做 I/O。
 */

static int  g_last_cfg_seq;      /* 上次处理过的配置代数 */
static int  g_last_cfg_tick;     /* 上次看到的代理心跳 */
static int  g_cfg_tick_ms;       /* 心跳最后一次变化的时刻（监督者时钟） */
static bool g_cfg_lost;          /* 已报告过"代理失联" */

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

#define MANIFEST_MAXLINE   256   /* 注释里有 UTF-8 中文，一字符 3 字节，别卡太紧 */

/* ── 部署/O&M 代理这条通道的三个常量 ─────────────────────────────────── */

#define CFG_FETCH_MAX   4096     /* 与内核的 ORT_CFG_MAX 一致 */
#define DEPLOY_WAIT_MS  5000     /* 等第一份配置的上限（Q2：有界等待） */
#define DEPLOY_LOST_MS  3000     /* 心跳停滞多久算失联（Q1：报告，不降级） */

static char g_cfg_buf[CFG_FETCH_MAX];

/* 从内核配置槽取回一份快照。
 *
 * ★ 这是控制循环**唯一**碰配置的地方，而且它是一次**有界 memcpy**：
 *   大小固定、不阻塞、无文件 I/O。这正是拆分的目的 ——
 *   "解析慢一点"是可分析的，"读文件最坏多久"不是。
 *
 * 返回字节数；<=0 表示代理还没送来过（-ENOENT）或接口出错。
 */

static int cfg_fetch(FAR char *buf, size_t cap)
{
  int n;
  int i;

  /* ★ -EAGAIN 与 -ENOENT 必须分开对待（内核侧 seqlock 的三种结果）：
   *     -ENOENT = 代理从来没送来过 → 调用者该走"没有配置"那条路
   *     -EAGAIN = 有配置，但这一轮没读到一致快照 → **重试**，
   *               绝不能当成"没有" —— 那会把一次读失败
   *               说成"配置不存在"，又是一个 H31。
   *
   * 归一化 errno：两个 SKU 的 prctl 返回形式不同（见容器里的说明）。 */

  for (i = 0; i < 8; i++)
    {
      n = (int)prctl(PR_ORT_CFG_GET, buf, (int)cap);

      if ((n == -1 ? errno : -n) != EAGAIN)
        {
          break;
        }
    }

  return n;
}

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
#define SEEN_VERSION  (1u << 4)
#define SEEN_PROTOCOL (1u << 5)
#define SEEN_ALL      (SEEN_DOMAIN | SEEN_CRITICAL | SEEN_RESTARTS | \
                       SEEN_HANDLES | SEEN_VERSION | SEEN_PROTOCOL)

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
         a->handles_fault == b->handles_fault &&
         a->version       == b->version &&   /* ★ 版本变了 = 要换实例 */
         a->protocol      == b->protocol;    /* ★ 协议变了 = 换法也变了 */
}

/****************************************************************************
 * Name: manifest_parse
 *
 * Description:
 *   解析并**校验** manifest。任何可疑之处一律拒绝整份配置。
 *
 * Returned Value:
 *   OK 成功；负 errno 失败，失败原因在 g_mf_err 里（含行号）。
 *
 ****************************************************************************/

static int manifest_parse(FAR const char *text, size_t len,
                          FAR struct ort_cg_s *cgs, int maxcgs,
                          FAR int *ncgs)
{
  FAR struct ort_cg_s *cg = NULL;
  char line[MANIFEST_MAXLINE];
  char names[MAX_CGS][16];        /* 每个 CG 的名字存这儿 —— 解析缓冲区每行复用 */
  unsigned int seen[MAX_CGS];     /* 每个 CG 已出现过的键 */
  size_t pos = 0;
  int lineno = 0;
  bool have_version = false;
  int n = 0;
  int k;

  *ncgs = 0;
  g_mf_err = NULL;

  /* ★ 解析的是**内存里的字节**，不是文件。
   *
   *   这一行是本轮拆分的落点：配置由部署/O&M 代理读进来放进内核配置槽，
   *   监督者只管解析。控制循环里因此不再有任何文件 I/O —— 而它的最坏
   *   耗时才是硬实时真正在意的（hostfs / flash 的最坏延迟不可控）。
   *
   *   解析本身仍然是**有界**的：缓冲区大小固定、无 syscall、无动态分配。
   *   这跟"读文件最坏耗时不可控"是两回事 —— 前者可以被 WCET 分析覆盖。
   *
   *   ⚠️ 文本未必以 '\0' 结尾（它来自一个有长度的槽），所以全程靠
   *      `pos < len` 界定，**不依赖字符串终止符**。
   */

  while (pos < len)
    {
      FAR char *p;
      FAR char *eq;
      FAR char *key;
      FAR char *val;
      size_t nl = 0;
      bool overlong = false;

      /* 取一行到 line[]，去掉行尾 '\n' */

      while (pos < len && text[pos] != '\n')
        {
          if (nl >= sizeof(line) - 1)
            {
              overlong = true;
            }
          else
            {
              line[nl++] = text[pos];
            }

          pos++;
        }

      if (pos < len)
        {
          pos++;                    /* 吃掉 '\n' */
        }

      line[nl] = '\0';
      lineno++;

      /* 行太长会被截断成两行，第二行多半语法不合法 —— 但**可能**恰好合法，
       * 那就成了静默错配。所以宁可在这里就拒。 */

      if (overlong)
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
      else if (strcmp(key, "protocol") == 0)
        {
          if (!mf_int(val, &cg->protocol) || cg->protocol > 1000)
            {
              mf_err(lineno, "protocol 必须是十进制非负整数");
              goto fail;
            }

          if (seen[n - 1] & SEEN_PROTOCOL)
            {
              mf_err(lineno, "protocol 重复");
              goto fail;
            }

          seen[n - 1] |= SEEN_PROTOCOL;
        }
      else if (strcmp(key, "revision") == 0)
        {
          /* ★ 刻意**不叫 version**：全局段的 version 是 **manifest 格式**
           *   的版本，这里是**容器**的版本。同名会让人（和脚本）改错 ——
           *   实测我自己就用一句 sed 把全局的那个也改了，
           *   而报错信息是"manifest 格式不支持"，跟容器半毛钱关系没有。 */

          if (!mf_int(val, &cg->version) || cg->version > 1000000)
            {
              mf_err(lineno, "revision 必须是十进制非负整数");
              goto fail;
            }

          if (seen[n - 1] & SEEN_VERSION)
            {
              mf_err(lineno, "revision 重复");
              goto fail;
            }

          seen[n - 1] |= SEEN_VERSION;
        }
      else
        {
          /* ★ 不认识的键是**错误**，不是"忽略"。
           *   忽略它，运维就永远不知道那行没生效。 */

          mf_err(lineno, "CG 段不认识的键");
          goto fail;
        }
    }

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

      /* ── 事件序审计（§三·补三十一 的验收装置）────────────────────
       *
       * 内核那边 seq 是**全局单调**的事件号。所以监督者这一侧能独立
       * 判断三件事，不需要相信内核：
       *
       *   seq 严格递增、缺口恰好等于 lost  → 事件流是好的
       *   seq 有缺口但没有报 lost          → **丢了却没记账**（R1/R4）
       *   seq 不增反退 / 重复              → **两条事件认领了同一个槽**（R1）
       *
       * 这是"监督者单方面可判定"的判据 —— 与 ort_caps()、
       * audit_protocol() 同一个思路。 */

      if (rec.seq <= g_audit_last)
        {
          g_audit_bad++;
          printf("[ortsup] *** 事件序异常: seq=%u 未递增"
                 "（上一条 %u）—— 可能有事件被覆盖或重复认领 ***\n",
                 (unsigned)rec.seq, (unsigned)g_audit_last);
        }
      else if (rec.seq > g_audit_last + 1)
        {
          uint32_t gap = rec.seq - g_audit_last - 1;

          g_audit_gap += gap;

          if (rec.lost == 0 && g_audit_last != 0)
            {
              /* 有缺口，但记录里说"一条都没丢" —— 账对不上 */
              g_audit_bad++;
              printf("[ortsup] *** 事件序异常: 缺口 %u 条，"
                     "但记录里 lost=0（账对不上）***\n", (unsigned)gap);
            }
        }

      g_audit_last = rec.seq;

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

/* 停止请求标志。SIGTERM 处理器只置位，不做别的事 ——
 * 处理器里能做的事越少越好（不可重入、不可阻塞、不可分配）。 */

/* 状态快照的**自描述头**。
 *
 * ★ 为什么格式的定义权在容器手里而不是内核：
 *   内核存的是不透明字节；"这堆字节是什么意思、能不能被新版本解释"
 *   是**格式拥有者**该回答的问题 —— 所有正经的序列化格式
 *   都是 magic + version 开头，理由相同。内核只负责存取和访问控制。
 *
 * ★ 为什么要 magic：快照可能来自一个**完全不同的**容器
 *   （比如监督者分配域时复用了同一个域号）。magic 不符就说明
 *   "这不是我这类快照"，必须冷启动，而不是硬按自己的结构去解。
 */

#define STATE_MAGIC  0x4f525453u   /* 'ORTS' */

struct state_blob_s
{
  uint32_t magic;
  uint32_t version;
  uint32_t tick;
};

/* ── 实例私有状态 ──────────────────────────────────────────────────────
 *
 * ★★ 为什么**不能**用 static（见手册 §三·补二十五）：
 *
 *   两个 SKU 的地址空间模型不同：
 *
 *     ORT-A（BUILD_KERNEL）   每个进程独立地址空间 → static 天然私有
 *     ORT-M（BUILD_PROTECTED）**所有容器共用同一个用户地址空间**
 *                             → static 是**共享的**
 *
 *   在 ORT-M 上实测到的症状（改一处、两处都动）：
 *     - app_cg(domain 1) 与 safety_cg(domain 2) 报出**同一个** tick=49
 *       —— 两个任务读写的是同一个 g_tick；
 *     - 给 pid=6 发 SIGTERM 撤下旧实例，pid=7（接替者）和 pid=8
 *       （另一个 CG 的重启实例）**一起**退出了 —— g_stop 也是共享的。
 *
 *   这个 bug 在 ORT-A 上**根本不会出现** —— 正是"只在一个 SKU 上验证过"
 *   会漏掉的那一类（与 H31、§三·补十四 同族）。
 *
 *   ★ 但**域块也不是安全的落点** —— 第一步的修法就踩了这个坑：
 *     ORT-M 上接替者被绑到**和现任同一个域**（重叠替换就是这么设计的），
 *     于是两个实例**共用同一块域内存**。实测：
 *       - 接替者启动时写了它自己的标志，把现任的"我还是 active"关掉了
 *         → 现任在整个 1.5 s 窗口里**一格都没走**（接续 24 → 接管 24，
 *         而 ORT-A 上同一段是 24 → 41）；
 *       - 重启实例报出 tick=30，与它自己刚打印的"从 0 开始"自相矛盾。
 *     两块都"看起来正常"，正是 H31 那一族。
 *
 *   落点因此分两类：
 *
 *     计数器等**只被主循环读写**的量 → **栈上的局部变量**。
 *       每个任务有自己的栈，ORT-M / ORT-A 两边都天然私有。
 *
 *     信号处理器要写的量 → 只能落在实例的内存里（处理器拿不到局部变量），
 *       并且**用 pid 打标**：`flags[PRIV_ACTIVE] == getpid()` 才算数。
 *       于是两个实例写同一个字也不会互相误解 —— 各认各的 pid。
 *
 * ★★ 为什么"在任"和"该退下"必须是**两个字**（踩了两次才定下来）：
 *
 *   第一版想省一个字，用 ACTIVE 同时表达两件事：
 *     "在任者不是我" 既可能是**新手期**（正常），也可能是**被顶掉**（该退）。
 *     靠一个"我当过在任者没有"的局部变量去区分 —— ORT-M 上能跑，
 *     ORT-A 上**接替者一出生就退出**：那边 ACTIVE 是**私有**的，
 *     新手期读到的是 0，"无人在任"被当成了"我被撤下了"。
 *
 *   也就是说：**同一个判据在两个 SKU 上语义不同**（共享 vs 私有），
 *   这种"省一个字"的设计不管怎么调都会在另一边翻车。
 *   拆成两个字之后，"谁在任"和"谁被要求停"各问各的，两边同构。
 *
 *     在任      ACTIVE == getpid()
 *     该退下    STOP   == getpid()
 *   两个问句都不依赖"这块内存是不是共享的"。
 */

#define PRIV_ACTIVE  1    /* 值 = 现任的 pid；0 = 无人在任 */
#define PRIV_STOP    2    /* 值 = 被要求停止的那个 pid；0 = 没有 */
#define PRIV_WORDS   4

/* 实例内存里私有字的起始偏移 —— 避开 own[0]（隔离演示用）。 */

#define PRIV_OFFSET  4

/* ORT-A 上的载体：独立地址空间，这份 static 就是私有的。
 * ORT-M 上只是"还没绑域"时的兜底，正常路径走域块。 */

static uint32_t g_priv_static[PRIV_WORDS];

/* 取本实例的私有状态块。信号处理器也要用。
 *
 * ★ 为什么一定要"现问内核"：处理器拿不到主循环的局部变量，
 *   而 static 在 ORT-M 上是**共享**的 —— 用它就会拿到**别的实例**的块。
 *   域号由监督者绑定、容器改不了，所以这个推导伪造不了。 */

static uint32_t *priv_self(void)
{
#if defined(CONFIG_BUILD_KERNEL)

  /* ORT-A：独立地址空间，static 就是私有的。
   * （不能去算 POOL_BASE —— 那组地址在 MMU 侧根本没有映射。） */

  return g_priv_static;

#else

  {
    int d = (int)prctl(PR_GET_ORT_DOMAIN);

    if (d >= 0 && d < NBLOCKS)
      {
        return (uint32_t *)(POOL_BASE + (uint32_t)d * BLOCK_SIZE)
               + PRIV_OFFSET;
      }
  }

  return g_priv_static;   /* 还没绑域 —— 只有启动早期会走到 */

#endif
}

/* 三个问句，各自只看自己那一个字 —— 两个 SKU 上语义相同。 */

static bool am_owner(void)
{
  return priv_self()[PRIV_ACTIVE] == (uint32_t)getpid();
}

static bool stop_requested(void)
{
  return priv_self()[PRIV_STOP] == (uint32_t)getpid();
}

/* 打包装箱后发布 —— 让"发布什么"只有一处定义 */

/* 每 100 ms 走一步：**现任发布，接替者跟踪**。
 *
 * ★ 为什么接替者要持续跟踪，而不是启动时读一次就完事：
 *
 *   重叠期里旧实例还在跑、状态还在变。启动时取的那份副本，
 *   到提交那一刻已经过期了 —— 实测差 18 个 tick
 *   （新实例读到 24，旧实例最终走到 42）。接替者会带着一份
 *   陈旧状态接管，而那正是"状态延续"失效的样子。
 *
 *   行业冗余也是这么做的：Emerson 的备用控制器**持续跟踪**主控
 *   （文档原话 "tracks the operation"），而不是切换时才去取一次快照。
 *   这不是实现细节，是"无扰切换"的前提。
 */

static void publish_tick(uint32_t tick, uint32_t version);

/* 计数器 `tick` 由**调用者持有**（栈上），不落任何共享存储 —— 见 PRIV_* 说明。
 * `announced` 同理：只有主循环读写它。 */

static void step_state(uint32_t *tick, int *announced, int standby, int nopub,
                       int domain, uint32_t version)
{
  struct state_blob_s snap;

  if (am_owner())
    {
      if (!*announced)
        {
          *announced = 1;

          /* ★ 区分「接了前任的班」和「开机第一个实例」。
           *
           *   两者都是"在任"，但语义完全不同：前者是**冗余切换**，
           *   后者只是启动。原来两种情况都打印"接管（tick=0）" ——
           *   开机时凭空多出一行"接管"，看起来像发生过一次切换。 */

          if (standby)
            {
              printf("[ortsup] 容器(domain %d): **接管**（tick=%u，"
                     "已持续跟踪到此刻）\n", domain, (unsigned)*tick);
            }
          else
            {
              printf("[ortsup] 容器(domain %d): **首次启动**（无前任，"
                     "tick=%u）\n", domain, (unsigned)*tick);
            }

          fflush(stdout);
        }

      (*tick)++;

      if (!nopub)          /* 测试装置：装作"没实现发布"的容器 */
        {
          publish_tick(*tick, version);
        }

      return;
    }

  /* 新手期：跟着现任走，不写 */

  if (prctl(PR_ORT_STATE_GET, &snap, sizeof(snap)) == (int)sizeof(snap) &&
      snap.magic == STATE_MAGIC && snap.version == version &&
      snap.tick > *tick)
    {
      *tick = snap.tick;
    }
}

static void publish_tick(uint32_t tick, uint32_t version)
{
  struct state_blob_s blob;

  blob.magic   = STATE_MAGIC;
  blob.version = version;
  blob.tick    = tick;

  prctl(PR_ORT_STATE_PUT, &blob, sizeof(blob));
}

static void stop_sig_handler(int signo)
{
  (void)signo;

  /* 只写"是我被要求停"这一个字。
   *
   * ★ 不碰 ACTIVE —— 这是踩过的坑：写成"清 ACTIVE"的时候，
   *   重叠期两代实例共用这一个字，旧实例收到 SIGTERM 顺手把
   *   ACTIVE 清了，**已经接任的接替者**一看"无人在任"就安静地
   *   "干净退出"了。日志上是一行普通的"干净退出"，
   *   而系统里那个关键 CG 已经没人服务 —— 它甚至让整轮跑不到
   *   SAFE_STATE（关键 CG 不再故障，状态机停在 DEGRADED）。
   *
   *   带上 pid 之后，只有被点名的那一个会退下。 */

  priv_self()[PRIV_STOP] = (uint32_t)getpid();
}

/* 监督者在**提交点**发来：从现在起你负责。 */

static void active_sig_handler(int signo)
{
  (void)signo;
  priv_self()[PRIV_ACTIVE] = (uint32_t)getpid();
}

static int ort_container_main(int argc, FAR char *argv[])
{
  FAR const char *mode = NULL;
  volatile uint32_t *own;
  volatile uint32_t *other;
  uint32_t tick = 0;             /* 私有计数器：放栈上，两边 SKU 都天然私有 */
  int announced = 0;             /* 已经报过一次"接管 / 首次启动" */
  int standby = 0;               /* 出生时带 standby 标记（有前任可接） */
  int nopub = 0;                 /* 测试装置：不发布状态 */
  int nosignal = 0;              /* 测试装置：忽略 SIGTERM */
  int hammer = 0;                /* 测试装置：紧循环读写快照（撞撕裂窗口） */
  int burst = 0;                 /* 测试装置：不等延迟立即故障（撞事件队列） */
  int delay = 0;
  int domain = 0;
  int version = 0;
  int i;
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

  if (k + 4 >= argc)
    {
      printf("[ortsup] 容器: 参数不足 (argc=%d, marker=%d)\n", argc, k);
      return 1;
    }

  /* 扫一遍看有没有 standby 标记 —— 不占位置参数，
   * 与 "container" 标记同一套认法。 */

  for (i = 0; i < argc; i++)
    {
      if (argv[i] == NULL)
        {
          continue;
        }

      if (strcmp(argv[i], "standby") == 0)
        {
          /* 新手期：只跟踪，不发布（见 step_state 的说明） */

          standby = 1;
        }
      else if (strcmp(argv[i], "nopub") == 0)
        {
          /* ★ 测试装置：故意不发布状态。
           *   用来造一个"声明了 protocol=1 但没实现"的容器 ——
           *   见 start_cg 里那段说明。产品路径不会带这个标记。 */

          nopub = 1;
        }
      else if (strcmp(argv[i], "nosignal") == 0)
        {
          /* ★ 测试装置：忽略 SIGTERM 且不注入故障。
           *   用来造一个"兑现不了 SIGTERM 有界退出"的容器。 */

          nosignal = 1;
        }
      else if (strcmp(argv[i], "burst") == 0)
        {
          /* ★ 测试装置：**不等延迟，立即故障**。
           *
           *   用途：让多个 CG 在**不同核上近乎同时**故障，去撞
           *   故障事件队列的生产者竞争（§三·补三十一 的 R1/R2/R5）。
           *   配合监督者对 burst_ 前缀的 CG 用 0 重启延迟，
           *   故障率能上去两三个数量级。 */

          burst = 1;
        }
      else if (strcmp(argv[i], "hammer") == 0)
        {
          /* ★ 测试装置：**紧循环**发布/校验 64 字节快照。
           *
           *   用途：把"两个核同时读写同一个状态槽"的碰撞窗口放大到
           *   能观测的程度。单核下 put/get 不可能交错（§三·补二十四），
           *   但 up_irq_save() 在 SMP 下**只关本核中断** ——
           *   这条路径存在的意义就是让那个窗口真的被撞上。
           *
           *   见 §三·补二十九·再补：4 核"跑通了、结果逐字相同"，
           *   但那不是保护生效，是时序运气。 */

          hammer = 1;
        }
    }

  mode    = argv[k + 1];
  domain  = atoi(argv[k + 2]);
  delay   = atoi(argv[k + 3]);
  version = atoi(argv[k + 4]);

  if (nosignal)
    {
      /* 一直跑到被杀 —— 否则它会在 delay 到点时自己 fault 掉，
       * 那 SIGTERM 兜底那条判据就永远验不到。
       *
       * ⚠️ 必须排在 `mode = argv[k+1]` **之后**：第一版写在前面，
       *    被那行赋值原地覆盖，"忽略 SIGTERM"的容器照样按 mode=fault
       *    跑，8 秒后自己崩掉 —— 于是宽限期那条判据**永远验不到**，
       *    而日志上一切正常（它"确实"跑起来了）。又是一次同族错误。 */

      mode = "ok";
    }

  /* ── 准入等待：先等监督者绑域 ────────────────────────────────────────
   *
   * ★★ 顺序很要紧：**状态接续必须排在准入之后**。
   *
   *   状态槽是**按域**索引的（见 arm_ortcommon.c 的 ort_state_slot()），
   *   没绑域就取不到自己的那一格。原来这一步写在准入之前 ——
   *   ORT-A 上没暴露，因为 posix_spawn 出来的进程要做动态装载，
   *   慢到监督者早就绑完了；ORT-M 上 task_create 立刻激活，
   *   子任务抢在监督者绑域之前就跑到了这里 → 永远读到 -EPERM。
   *
   *   也就是说：**原来那条"接续成功"的路径是抢赢得来的**，
   *   换个调度顺序就会静默退化成冷启动 —— 而且它看起来一模一样。
   *   （§三·补二十五 实测：ORT-M 上 100% 复现。）
   */

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

  /* ── 本实例的"现任"标志（信号处理器要写，只能落在实例内存里）──────
   *
   * ⚠️ **只写自己该写的那一个值**，不要"顺手清零"：
   *   重叠期里接替者和现任共用这一个字，接替者清一次零
   *   就把现任的在任状态抹掉了（实测：现任整整 1.5 s 一格没走）。
   *   standby 启动时**什么都不写**，让现任继续当它的现任。
   */

  {
    uint32_t *flags;

#if defined(CONFIG_BUILD_KERNEL)

    flags = g_priv_static;   /* ORT-A：独立地址空间，这份 static 就是私有的 */

#else

    flags = (uint32_t *)own + PRIV_OFFSET;   /* ORT-M：域块里，按域隔离 */

#endif

    if (!standby)                      /* 不是 standby：出生即在任 */
      {
        flags[PRIV_ACTIVE] = (uint32_t)getpid();
        flags[PRIV_STOP]   = 0;        /* 清掉上次开机留在域块里的陈旧值 */
      }

    /* ★ standby 两格都**不写**：它没有前任可取代、也不该动现任的字。 */
  }

  /* 停得下来，才谈得上"被替换"。
   *
   * 没有这个处理器，监督者只能 SIGKILL —— 容器没有机会把正在做的事
   * 收尾（写回、释放、报告）。有界退出是滚动更新的前提条件。
   *
   * ⚠️ 处理器**不读静态变量**：在 ORT-M 上静态变量是共享的，
   *    它会把标志写到**别的实例**的块里。改为 priv_self() 现问内核。 */

  signal(SIGTERM, nosignal ? SIG_IGN : stop_sig_handler);
  signal(SIGUSR2, active_sig_handler);   /* 监督者在提交点点名 */

  /* ── 状态接续 ────────────────────────────────────────────────────────
   *
   * 真实容器在这里是控制环的积分器 / 滤波器 / 上次输出。
   * 原型用一个**单调计数器**，因为它一眼可判：
   *   替换后从 0 重新开始 = 状态没接上；从 N 继续 = 接上了。
   *
   * ★ 这一步是行业冗余链在单板上的对应物（见假设审计 H32）：
   *   没有它，"先起后杀"只是让进程不缺席，功能仍然被打断。
   *
   * ★ 必须排在**绑域之后**（见上面准入等待的说明）。
   */

  {
    struct state_blob_s prev;
    int n = prctl(PR_ORT_STATE_GET, &prev, sizeof(prev));
    int e = (n == -1) ? errno : -n;

    /* ★ 归一化 errno：两个 SKU 的 prctl 返回形式不同 ——
     *   ORT-A 直接返回负 errno（实测 -2），
     *   ORT-M 走 syscall 包装，返回 -1 并把原因放进 errno。
     *   直接打印 ret 会让**同一份代码**在两台机器上输出不同，
     *   而"逐字相同"正是我们用来证明"两边跑的是同一个状态机"的判据
     *   （§三·补十九）。诊断输出上的差异同样会掩盖真实差异。 */

    if (e == EAGAIN)
      {
        /* ★ 读失败 ≠ 没有旧状态。
         *   内核在撞上并发写时会返回 EAGAIN（seqlock 重试用尽），
         *   把它当成"冷启动"就是把"没读到"说成了"没有" ——
         *   而这两种情况的正确处置完全不同。 */

        printf("[ortsup] 容器(domain %d): 旧状态**读不一致**（并发写中，"
               "errno=%d）→ **不交接**，冷启动\n", domain, e);
      }
    else if (n != (int)sizeof(prev))
      {
        printf("[ortsup] 容器(domain %d): 无旧状态可接续 (errno=%d)，从 0 开始\n",
               domain, e);
      }
    else if (prev.magic != STATE_MAGIC)
      {
        printf("[ortsup] 容器(domain %d): 快照标识不符 (0x%08x) → 冷启动\n",
               domain, (unsigned)prev.magic);
      }
    else if (prev.version != (unsigned)version)
      {
        /* ★ 这条是滚动更新最容易踩的坑：
         *   字节是**良构的**，但按新版本的结构去解释就是错的 ——
         *   比读到垃圾更危险，因为它不会崩，只会静默算错。
         *   所以**跨版本一律不交接**（fail-closed）。 */

        printf("[ortsup] 容器(domain %d): 快照版本不符（旧 v%u ≠ 本实例 v%d）"
               " → **不交接**，冷启动\n",
               domain, (unsigned)prev.version, version);
      }
    else
      {
        tick = prev.tick;
        printf("[ortsup] 容器(domain %d): **接续旧状态** tick=%u（v%d，"
               "之后持续跟踪直到被点名）\n",
               domain, (unsigned)tick, version);
      }

    fflush(stdout);
  }

  /* ── 压力模式：把状态槽的并发窗口放大（测试装置）──────────────────
   *
   * 现任：每轮写 64 字节，**16 个字全部相等**；
   * 接替者：紧循环读回，检查 16 个字是否仍然全相等。
   *
   * 判据为什么是这个形状：只要 memcpy 不是原子的，读端就会看到
   * "一半是旧值、一半是新值" —— 而"全字相等"让任何长度的撕裂
   * 都必然暴露，不需要事先知道哪几个字节会先落地。
   *
   * ⚠️ 这是**测试装置**，产品路径不会带 hammer 标记。
   */

  if (hammer)
    {
      static uint32_t snap[16];
      uint32_t seq = 0;
      unsigned long reads = 0;
      unsigned long busy = 0;
      int torn = 0;
      int k;

      printf("[ortsup] 容器(domain %d): **压力模式** —— %s\n", domain,
             standby ? "接替者（紧循环读+校验 64 字节）"
                     : "现任（紧循环写 64 字节）");
      fflush(stdout);

      for (;;)
        {
          if (standby)
            {
              int rn = (int)prctl(PR_ORT_STATE_GET, snap, sizeof(snap));

              if (rn != (int)sizeof(snap))
                {
                  /* -EAGAIN = 撞上并发写、重试用尽。**必须单独计数**：
                   * 否则"撕裂 0 次"可能只是"根本没读成功几次" ——
                   * 那是另一个假通过。 */

                  busy++;

                  if ((busy % 200000ul) == 0)
                    {
                      printf("[ortsup] 压力读端: 读成功 %lu 次 / 遇忙 %lu 次\n",
                             reads, busy);
                      fflush(stdout);
                    }
                }
              else
                {
                  uint32_t v = snap[0];

                  reads++;

                  if ((reads % 200000ul) == 0)
                    {
                      printf("[ortsup] 压力读端: 读成功 %lu 次 / 遇忙 %lu 次"
                             " / 撕裂 %d 次\n", reads, busy, torn);
                      fflush(stdout);
                    }

                  for (k = 1; k < 16; k++)
                    {
                      if (snap[k] != v)
                        {
                          torn++;

                          if (torn <= 5)
                            {
                              printf("[ortsup] *** 撕裂快照 *** domain=%d "
                                     "第 %d 次（读过 %lu 次）: "
                                     "w0=%08lx w%d=%08lx\n",
                                     domain, torn, reads,
                                     (unsigned long)v, k,
                                     (unsigned long)snap[k]);
                              fflush(stdout);
                            }
                          break;
                        }
                    }
                }
            }
          else
            {
              uint32_t v = ++seq;

              for (k = 0; k < 16; k++)
                {
                  snap[k] = v;
                }

              prctl(PR_ORT_STATE_PUT, snap, sizeof(snap));
            }
        }
    }

  if (strcmp(mode, "ok") == 0)
    {
      while (!stop_requested())
        {
          *own = 0xa5a5a5a5u;

          /* 周期发布 —— 模拟冗余链的"持续跟踪"。
           * 发布周期必须**明显短于**重启预算与启动窗口，
           * 否则接替者读到的是过期快照。 */

          step_state(&tick, &announced, standby, nopub, domain,
                     (uint32_t)version);
          usleep(PUBLISH_PERIOD_US);
        }

      printf("[ortsup] 容器(domain %d): 收到停止请求，干净退出（tick=%u）\n",
             domain, (unsigned)tick);
      fflush(stdout);
      return 0;
    }

  /* ★ burst **不覆盖** argv 里的延迟 —— 首次启动仍然按延迟来。
   *
   *   第一版在这里写了 `delay = 0`，结果容器在**启动窗口内**就故障，
   *   触发 startup 策略直接进 SAFE_STATE（H29 的设计是对的），
   *   整个压力测试第一步就终结了。
   *
   *   "故障要快"这件事由**监督者的重启路径**决定：它对 burst_ 前缀的
   *   CG 传 0 延迟。容器只管照 argv 办。 */

  (void)burst;
  if (delay > 0)
    {
      printf("[ortsup] 容器(domain %d): 正常工作中，%d 秒后注入故障\n",
             domain, delay);
      fflush(stdout);

      /* 分段睡：整段 sleep 会让停止请求最多晚 delay 秒才被响应，
       * 而监督者的宽限期是有界的 —— 那样宽限期就形同虚设。 */

      {
        int j;

        for (j = 0; j < delay * 10 && !stop_requested(); j++)
          {
            step_state(&tick, &announced, standby, nopub, domain,
                     (uint32_t)version);
            usleep(PUBLISH_PERIOD_US);
          }
      }

      if (stop_requested())
        {
          printf("[ortsup] 容器(domain %d): 故障注入前收到停止请求，"
                 "干净退出（tick=%u，已发布）\n",
                 domain, (unsigned)tick);
          fflush(stdout);
          return 0;
        }
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

static int start_cg(FAR struct ort_cg_s *cg, FAR const char *mode, int delay,
                    bool standby);

/* 停止宽限期：容器必须在这么久内响应 SIGTERM 并退出。 */

#define STOP_GRACE_MS  3000

/****************************************************************************
 * Name: stop_cg
 *
 * Description:
 *   请一个容器停下来：先 SIGTERM，宽限期内没走就 SIGKILL 兜底。
 *
 * ★ 为什么是**有界**等待：
 *   无界等待是不可接受的 —— 一个收不到（或故意不理）SIGTERM 的容器
 *   会把整个更新流程卡死。安全系统里，"等它自己走"必须有一个上限，
 *   然后由监督者接管。这与"不信任失效组件"是同一条公理。
 *
 * ★ 为什么不用 waitpid 判存活：
 *   见手册 §三·补四 坑 4 —— NuttX 在
 *   CONFIG_SCHED_HAVE_PARENT && !CONFIG_SCHED_CHILD_STATUS 下，
 *   waitpid 是**等 SIGCHLD**，会阻塞。
 *   改用 kill(pid, 0)：POSIX 的"存在性探测"，
 *   NuttX 侧实现就是 `nxsched_get_tcb(pid) != NULL`
 *   （见 sched/signal/sig_kill.c 的 signo == 0 分支），不阻塞、无副作用。
 *
 * Returned Value:
 *   true  = 已停止（干净退出或已 SIGKILL）
 *   false = 停不下来（SIGKILL 已发但 TCB 仍在）
 *
 ****************************************************************************/

static void protocol_falsify(FAR struct ort_cg_s *cg, FAR const char *why);

static bool stop_cg(FAR struct ort_cg_s *cg)
{
  int waited = 0;

  if (cg->pid <= 0)
    {
      return true;
    }

  if (kill(cg->pid, SIGTERM) != 0)
    {
      /* 投不出去通常就是已经没了 —— 拿不到"响应了没有"的证据，
       * 所以**不作结论**（见 audit_protocol 的"证据"一节）。 */

      cg->pid = -1;
      return true;
    }

  while (waited < STOP_GRACE_MS)
    {
      usleep(10000);
      waited += 10;

      if (kill(cg->pid, 0) != 0)
        {
          printf("[ortsup]   %s pid=%d 在 %d ms 内干净退出\n",
                 cg->name, (int)cg->pid, waited);
          cg->pid = -1;
          return true;
        }
    }

  printf("[ortsup]   ⚠ %s pid=%d 未在 %d ms 内响应 SIGTERM → SIGKILL 兜底\n",
         cg->name, (int)cg->pid, STOP_GRACE_MS);

  /* ★ 这是**证伪 protocol 声明的第二条判据**（第一条见 audit_protocol）。
   *
   *   声明里那条"实现了 SIGTERM 有界退出"是可以用这个观测直接推翻的：
   *   SIGTERM 投出去了、宽限期内它没走 —— 无论它是没装处理器、
   *   还是处理器里睡过了头，都说明**它兑现不了"停得下来"**。
   *
   *   注意这与"kill 投不出去"不同：那种情况容器已经没了，
   *   说明不了任何事，不能算证据。 */

  protocol_falsify(cg, "撤下时未在宽限期内响应 SIGTERM（SIGKILL 兜底）");

  kill(cg->pid, SIGKILL);
  cg->pid = -1;
  return false;
}

/****************************************************************************
 * Name: protocol_falsify
 *
 * Description:
 *   把某个 CG 的 protocol 声明标记为**不可信**，并明示后果。
 *
 *   标记是**锁存**的：一份被证伪的声明不会因为换了个实例就恢复可信 ——
 *   证据是关于**这个容器**的，不是关于这一次运行的。
 *
 ****************************************************************************/

static void protocol_falsify(FAR struct ort_cg_s *cg, FAR const char *why)
{
  if (cg->protocol_falsified)
    {
      return;                     /* 只报一次 */
    }


  cg->protocol_falsified = 1;

  printf("[ortsup] *** protocol 声明被证伪: %s（声明 protocol=%d）***\n",
         cg->name, cg->protocol);
  printf("[ortsup]     证据: %s\n", why);
  printf("[ortsup]     后果: 该 CG 后续替换**降级为冷替换**"
         "（先停后起，中间有一段服务空档）\n");
  printf("[ortsup]     声明是部署方写的，容器没有任何办法反驳它 —— "
         "所以只能由监督者实测推翻。\n");
  fflush(stdout);
}

/****************************************************************************
 * Name: audit_protocol
 *
 * Description:
 *   反向验证 protocol 声明。声明 protocol=1 意味着两件事，
 *   两件**监督者都能从外部观测**，不需要相信容器：
 *
 *     ① 撤下它时是否走了 SIGKILL 兜底   → 证伪「停得下来」
 *        （在 stop_cg 里记录，见那里的说明）
 *     ② 健康运行超过启动窗口之后，它自己域的状态槽是否仍为空
 *        → 证伪「在发布」（这里）
 *
 * ★ 为什么 ② 的判据落在**启动窗口之后**：
 *   窗口内可能确实还没开始发布（容器还在初始化）。窗口本来就是
 *   监督者单方面可判定的"应该已经就绪"的时刻 —— 复用它，
 *   不引入第二个时间常量，也就不会出现两个常量互相矛盾。
 *
 * ★ 为什么只看"写没写过"，不看"写得对不对"：
 *   槽里是不透明字节，格式的定义权在容器手里（见容器的 state_blob）。
 *   监督者能独立判断的事实只有一个 —— **那个域被写过没有** ——
 *   而它足以证伪"完全没实现"。
 *
 * ★ 什么时候查不到：容器刚故障被重启时，槽会被内核作废，
 *   而 admitted_ms 会随新实例重置 —— 两者同步，不会误伤。
 */

static void audit_protocol(void)
{
  int i;

  for (i = 0; i < (int)NCGS; i++)
    {
      FAR struct ort_cg_s *cg = &g_cgs[i];
      int seq;

      if (cg->protocol == 0 || cg->protocol_falsified || cg->failed)
        {
          continue;
        }

      if (cg->pid <= 0 || cg->admitted_ms < 0)
        {
          continue;
        }

      if ((g_now_ms - cg->admitted_ms) < g_startup_window_ms)
        {
          continue;
        }

      /* 权限在内核侧：只有监督者能调这个接口（见 <sys/prctl.h>）。
       * 返回 0 = 该域从未发布过；负值 = 接口本身出错，不作结论。 */

      seq = (int)prctl(PR_GET_ORT_STATE_SEQ, cg->domain);

      if (seq == 0)
        {
          protocol_falsify(cg,
                           "健康运行超过启动窗口，该域**从来没发布过**"
                           "（累计发布次数为 0）");
        }
    }
}


/****************************************************************************
 * Name: replace_cg
 *
 * Description:
 *   把 live 换成 spec，**先起新的、证明它活着、再停旧的**。
 *
 * ★ 修的是 §三·补二十一 的第 3 条限制："重载无事务性 —— 先 kill 再
 *   start，中间存在一个该容器不在运行的窗口"。
 *
 *   顺序反过来（现在的做法），窗口长度 = spawn + 新实例的启动时间，
 *   期间该 CG **无人服务**。容器越多、启动越慢，窗口越长。
 *
 *   正确的顺序是这个函数：旧的继续服务，新的在旁边起来，
 *   跑完启动窗口证明自己没坏，然后才把旧的撤下。
 *
 * "证明"用什么判据 —— 复用既有的启动窗口（STARTUP_WINDOW_MS）：
 *   它是**监督者单方面可判定**的，不依赖容器上报 ready
 *   （见文件头"用 STARTUP_WINDOW_MS 而不是容器主动上报 ready"）。
 *   一个新实例能撑过启动窗口不失效，就认为它可以接管。
 *
 * Returned Value:
 *   true  = 已提交（旧的已停，spec->pid 是新的）
 *   false = 已回滚（新实例没撑住，旧的仍在跑，spec 未被采纳）
 *
 ****************************************************************************/

static bool replace_cg(FAR struct ort_cg_s *live, FAR struct ort_cg_s *spec)
{
  pid_t newpid;
  int waited = 0;
  bool healthy = true;

  spec->pid = -1;

  /* ── 没声明生命周期协议 → 只能冷替换 ──────────────────────────────
   *
   * ★ 这里**必须明说**，不能悄悄按同一套流程走。装作能热替换的话：
   *   容器不理会 SIGTERM（默认动作把它杀掉，没有收尾），
   *   接替者读到的是过期快照 —— 而日志上看起来一切正常。
   *   那正是 H31/H32 那类错误。
   */

  if (spec->protocol == 0 || spec->protocol_falsified)
    {
      if (spec->protocol_falsified)
        {
          printf("[ortsup]   该 CG 的 protocol 声明**已被证伪**"
                 " → **冷替换**：先停后起，中间有一段服务空档\n");
        }
      else
        {
          printf("[ortsup]   该 CG 声明 protocol=0（未实现生命周期协议）"
                 " → **冷替换**：先停后起，中间有一段服务空档\n");
        }

      stop_cg(live);
      spec->pid = -1;

      if (start_cg(spec, "fault", spec->critical ? 8 : 3, false) != 0)
        {
          printf("[ortsup]   ✗ 冷替换也起不来 —— 该 CG 现在无人服务\n");
          spec->failed = true;
          return true;   /* 变更已采纳，只是这个 CG 没起来 */
        }

      return true;
    }

  if (start_cg(spec, "fault", spec->critical ? 8 : 3, true) != 0)
    {
      printf("[ortsup]   ✗ 新实例起不来 → 放弃本次变更，旧实例继续\n");
      return false;
    }

  newpid = spec->pid;
  printf("[ortsup]   新实例 pid=%d 已起，旧实例 pid=%d 继续服务，"
         "等启动窗口 %d ms\n", (int)newpid, (int)live->pid,
         g_startup_window_ms);

  /* 等它跑完启动窗口。
   *
   * ★ 这里**不去排空内核事件队列** —— 那会把其它 CG 的事件也吞掉，
   *   破坏主循环的消费顺序（事件队列是"逐条独立、按序消费"的）。
   *   所以直接用 kill(pid, 0) 探活，让事件老老实实待在队列里。
   */

  while (waited < g_startup_window_ms)
    {
      usleep(LOOP_MS * 1000);
      waited += LOOP_MS;

      if (kill(newpid, 0) != 0)
        {
          healthy = false;
          break;
        }
    }

  if (!healthy)
    {
      printf("[ortsup]   ✗ 新实例 pid=%d 未撑过启动窗口 → **回滚**，"
             "旧实例 pid=%d 原样继续\n", (int)newpid, (int)live->pid);
      spec->pid = -1;
      return false;
    }

  /* 新的证明了自己 → 撤下旧的。到这里才真正"提交" */

  printf("[ortsup]   ✓ 新实例 pid=%d 已过启动窗口(%d ms) → 撤下旧实例 pid=%d\n",
         (int)newpid, waited, (int)live->pid);

  /* ★ 顺序：先点名新实例（它开始发布自己的状态），再撤旧的
   *   （旧的收到 SIGTERM 会立刻停止发布）。
   *
   *   反过来的话，中间会有一个"没人发布"的空档；虽然状态是快照
   *   不是流，空档不至于出错，但会白白丢掉最后一段状态演进。 */

  kill(newpid, SIGUSR2);
  stop_cg(live);
  return true;
}

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

  /* ★ 从**内核配置槽**取回新配置 —— 这里没有 fopen，也不该有。
   *   代理负责搬，监督者负责校验与采纳。 */

  {
    int got = cfg_fetch(g_cfg_buf, sizeof(g_cfg_buf));

    if (got <= 0)
      {
        /* 槽里没有东西。正常情况下取不到就不会被调用（代数没变），
         * 所以走到这里说明代理把槽清空了或接口出错 —— 不作结论。 */

        return -ENOENT;
      }

    n = got;
  }

  if (manifest_parse(g_cfg_buf, (size_t)n, scratch, MAX_CGS, &n) != OK)
    {
      /* ★ 只在错误**变了**的时候打印。
       *
       *   不折叠的话一份坏配置会把日志刷满 —— 而运维真正需要的是
       *   "什么时候开始坏的、坏在哪"，不是"它重复了多少次"。
       *   实测：不折叠时 13 秒刷了 6 遍同一条。
       */

      if (strcmp(g_mf_err ? g_mf_err : "?", g_reload_lasterr) != 0)
        {
          printf("[ortsup] *** 拒绝新配置（当前配置原样继续运行）***\n");
          printf("[ortsup] 配置槽: %s\n",
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
          stop_cg(&g_cgs[k]);
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
          printf("[ortsup] 配置变更: %s 的声明变了（pid=%d）\n",
                 scratch[k].namebuf, (int)live->pid);

          /* ★ 证伪结论**先搬过来再换**。
           *
           *   它是运行期实测出来的，不是 manifest 里的声明 ——
           *   解析器刚 memset 出来的这一份里它是 0。
           *   不搬的话，replace_cg() 看到的是一份"声明可信"的新规格，
           *   于是又按热替换办 —— 而打印出来的"后果"那一行
           *   早就承诺了要降级。**承诺了却没做**比不做更糟。 */

          scratch[k].protocol_falsified = live->protocol_falsified;

          /* ★ 先起新的、证明活着、再停旧的 —— 见 replace_cg()。
           *   失败则回滚：scratch[k] 不被采纳，下面拷贝时
           *   让 live 的原规格继续生效。 */

          if (replace_cg(live, &scratch[k]))
            {
              applied++;
            }
          else
            {
              /* ★ 回滚必须**把 live 的原样写回 scratch[k]**。
               *
               *   光 `continue` 是不够的 —— 下面那句
               *   `memcpy(g_cgs, scratch, ...)` 是按位置整体覆盖的，
               *   scratch[k] 里此刻装的还是**新规格**，
               *   于是"回滚"照样会把变更应用下去。
               *   （写的时候差点就这么交了 —— 回滚路径最容易只写一半。）

               *   名字要拷进 scratch 自己的 namebuf：直接指 live->namebuf
               *   的话，memcpy 之后指针会跨条目指向别人的缓冲区。 */

              strcpy(scratch[k].namebuf, live->namebuf);
              scratch[k].name        = scratch[k].namebuf;
              scratch[k].domain      = live->domain;
              scratch[k].critical    = live->critical;
              scratch[k].max_restarts  = live->max_restarts;
              scratch[k].handles_fault = live->handles_fault;
              scratch[k].pid         = live->pid;
              scratch[k].admitted_ms = live->admitted_ms;
              scratch[k].restarts    = live->restarts;
              scratch[k].faults      = live->faults;
              scratch[k].failed      = live->failed;

              /* ★ 证伪结论必须跟着走。
               *   它是**运行期实测**出来的，不是 manifest 里的声明 ——
               *   解析器刚 memset 出来的那一份里它是 0，不显式搬过来的话
               *   每 2 秒一次的轮询就会把证伪结论"洗掉"，
               *   下一次替换又按热替换办。而这条路径恰恰是
               *   §三·补二十二 那个"回滚只写一半"的同一族。 */

              scratch[k].protocol_falsified = live->protocol_falsified;
            }
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
          scratch[k].protocol_falsified = live->protocol_falsified;
        }
    }

  /* ★ 最后再兜一次证伪结论 —— 这一次是**锁存**语义。
   *
   *   replace_cg() 自己也会造出新的证伪结论（stop_cg 里的 SIGKILL 兜底
   *   写在 live 上，而 live 就是 g_cgs[k]）。下面那句 memcpy 用 scratch
   *   整体覆盖 g_cgs，就会把它盖掉。
   *
   *   实测：stuck_cg 在变更 #1 里被判据①证伪，变更 #2 却**又走了热替换** ——
   *   打印出来的那句"后续替换降级为冷替换"当场变成空头支票。
   *   承诺了却没做，比不做更糟。
   *
   *   放在 memcpy 之前、循环之外：此时 g_cgs 里装的还是旧状态
   *   （含本轮 replace 期间新产生的结论），scratch 里是要提交的新规格。 */

  for (k = 0; k < n; k++)
    {
      for (j = 0; j < n_prev; j++)
        {
          if (strcmp(scratch[k].namebuf, g_cgs[j].name) == 0 &&
              g_cgs[j].protocol_falsified)
            {
              scratch[k].protocol_falsified = 1;
            }
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
          start_cg(&g_cgs[k], "fault", g_cgs[k].critical ? 8 : 3, false);
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

static int start_cg(FAR struct ort_cg_s *cg, FAR const char *mode, int delay,
                    bool standby)
{
  FAR char *cargv[9];
  char vbuf[12];
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
  snprintf(vbuf, sizeof(vbuf), "%d", cg->version);

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

  /* ── 测试装置：造一个"声明了 protocol 但没实现"的容器 ─────────────
   *
   * ★ 为什么必须有这么个开关：
   *   原型里**所有容器都是 ortsup 自己**，而 ortsup 是真实现了
   *   protocol v1 的。没有这个开关，"证伪"那条路**永远走不到** ——
   *   而没被走到的那条路，看起来和走对了没有区别
   *   （H31 / §三·补十四 的 grep / §三·补二十二 的回滚分支，同一族）。
   *
   *   正式实现不需要它：manifest 会指定镜像，第三方镜像天然就是
   *   "声明了但没实现"的来源。这里只是给那个场景一个替身。
   *
   *   触发方式是段名前缀，因为**段名是 manifest 唯一能自由表达的东西**：
   *     raw_*    给容器加 "nopub"    → 照常跑、照常响应 SIGTERM，但不发布状态
   *     stuck_*  给容器加 "nosignal" → 忽略 SIGTERM，且不注入故障（跑到被杀）
   *
   *   两个缺陷分开造，是因为它们对应**两条独立的证伪判据** ——
   *   合在一个容器上就分不清是哪条判据起的作用了（对照组的道理）。
   */

  {
    int n = 0;

    cargv[n++] = (FAR char *)"container";   /* 标记位，两条路的唯一锚点 */
    cargv[n++] = (FAR char *)mode;
    cargv[n++] = dbuf;
    cargv[n++] = lbuf;
    cargv[n++] = vbuf;

    if (standby)
      {
        cargv[n++] = (FAR char *)"standby";
      }

    if (strncmp(cg->name, "raw_", 4) == 0)
      {
        cargv[n++] = (FAR char *)"nopub";
      }
    else if (strncmp(cg->name, "stuck_", 6) == 0)
      {
        cargv[n++] = (FAR char *)"nosignal";
      }
    else if (strncmp(cg->name, "hammer_", 7) == 0)
      {
        cargv[n++] = (FAR char *)"hammer";
      }
    else if (strncmp(cg->name, "burst_", 6) == 0)
      {
        cargv[n++] = (FAR char *)"burst";
      }

    cargv[n] = NULL;
  }

  /* ★ 角色用 argv 传，不用信号。
   *
   *   信号有竞态：若在容器装好处理器之前到达，SIGUSR2 的**默认动作**
   *   可能直接把新实例杀掉 —— 而那正是我们要它活着的时候。
   *   argv 是出生时就定下的，没有这个窗口。 */

#if defined(CONFIG_BUILD_KERNEL)

  /* ORT-A：独立地址空间，容器是独立 ELF */

  {
    /* ★ 必须显式设调度参数 —— 这里原来传的是 NULL（默认属性）。
     *
     *   后果（实测 · §三·补三十）：ORT-A 上**监督者、容器、代理
     *   全都是优先级 100** —— 而设计要的是
     *   监督者(100) > 容器(110) > 代理(120)（NuttX 里数值越小优先级越高）。
     *
     *   监督者和它监督的对象同优先级意味着它们会**时间片轮转** ——
     *   一个硬实时监督者不能和被监督者平起平坐。
     *
     *   为什么在 ORT-M 上没暴露：那条路走 task_create()，本来就把
     *   CONTAINER_PRIO 传进去了。又是"只在一边验证"漏掉的那一类。
     */

    posix_spawnattr_t attr;
    struct sched_param sched;
    int ret;

    posix_spawnattr_init(&attr);

    sched.sched_priority = CONTAINER_PRIO;
    posix_spawnattr_setschedparam(&attr, &sched);
    posix_spawnattr_setschedpolicy(&attr, SCHED_RR);
    posix_spawnattr_setstacksize(&attr, CONTAINER_STACK);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSCHEDPARAM |
                                    POSIX_SPAWN_SETSCHEDULER);

    ret = posix_spawn(&pid, CONTAINER_PATH, NULL, &attr, cargv, NULL);
    posix_spawnattr_destroy(&attr);

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

      /* 故障重启：前身已经死了，没有重叠期 —— 它一上来就是现任。
       *
       * ★ 测试装置：burst_ 前缀的 CG 用 0 延迟 —— 让故障率上去，
       *   才有机会撞到故障事件队列的生产者竞争（§三·补三十一）。
       *   产品路径不会有这个前缀。 */

      if (start_cg(cg, "fault",
                   strncmp(cg->name, "burst_", 6) == 0 ? 0 : 1, false) != 0)
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

  /* ── 自己申报调度优先级 ──────────────────────────────────────────────
   *
   * ★ 为什么不靠启动者设置：`CONFIG_TESTING_ORTSUP_PRIORITY` 是**内置应用**
   *   的概念 —— ORT-M（PROTECTED，应用编进 nuttx_user.elf）上它生效，
   *   ORT-A（KERNEL，应用是文件系统上的独立 ELF）上**根本不经过内置表**，
   *   启动者只会给默认优先级。实测：两边 `ps` 看到的优先级不同。
   *
   *   "我要求的调度属性"本来就是组件自己的属性，由组件申报最不容易漂移：
   *   不依赖谁把它拉起来的、也不依赖那条启动路径实现得对不对。
   *
   * ⚠️ 失败不静默：拿不到**设计要求的**优先级必须说出来 ——
   *   否则"监督者和被监督者同优先级"这件事在日志上完全看不见。
   */

  {
    struct sched_param sched;

    sched.sched_priority = SUPERVISOR_PRIO;
    sched_setparam(0, &sched);

    if (sched_getparam(0, &sched) != 0 ||
        sched.sched_priority != SUPERVISOR_PRIO)
      {
        printf("[ortsup] *** 无法取得设计要求的优先级 %d（当前 %d）***\n"
               "        监督者与被监督者同优先级会让它们时间片轮转\n",
               SUPERVISOR_PRIO, (int)sched.sched_priority);
      }

    printf("[ortsup] 调度优先级: %d\n", (int)sched.sched_priority);
    fflush(stdout);
  }

  /* ── 先注册监督者 ────────────────────────────────────────────────────
   *
   * ★ 顺序变了：以前"先读 manifest、再注册"，现在反过来。
   *   原因：配置槽的读接口**只对监督者开放**（容器一律 -EPERM），
   *   没注册就取不到配置。
   *
   * 信号用 SIGUSR1：CONFIG_SIG_SIGUSR1_ACTION 默认为 n，
   * 内核不配默认动作，只有主动挂钩子的任务会收到。
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

  /* ── 从部署/O&M 代理取配置 ───────────────────────────────────────────
   *
   * ★★ 监督者**不再读文件**。配置由代理读进来放进内核配置槽，
   *    监督者只取回并解析。这是《部署与 O&M 组件设计》的落地：
   *    实时控制环里不再有不可控最坏耗时的操作。
   *
   * ★ Q2（已拍板）：等第一份配置**有界**，超时 → BOOT_FAILED。
   *   不等下去 —— 与既有 fail-closed 语义一致，"没有配置就运行"
   *   是明确的错误。不立刻失败 —— 代理是**另一个进程**，启动有先后。
   *
   * ★ 快照取回后仍然**由监督者自己校验**。代理是非实时、可重启、
   *   可能被降级的组件，按公理 S1 它的输出只能当**输入**看；
   *   校验逻辑只有这一份，不会出现"代理的规则和监督者的不一致"。
   */

  {
    int waited = 0;
    int n      = -1;

    while (waited < DEPLOY_WAIT_MS)
      {
        n = cfg_fetch(g_cfg_buf, sizeof(g_cfg_buf));

        if (n > 0)
          {
            break;
          }

        usleep(LOOP_MS * 1000);
        waited += LOOP_MS;
      }

    if (n <= 0)
      {
        printf("[ortsup] *** 拒绝启动: 等不到部署代理送来的配置（%d ms）***\n",
               DEPLOY_WAIT_MS);
        printf("[ortsup]     配置由部署/O&M 代理经内核配置槽递送 —— "
               "监督者不做文件 I/O。\n");
        printf("[ortsup] 系统状态: BOOT_FAILED（锁存）\n");
        fflush(stdout);
        return 2;
      }

    /* ★ fail-closed：manifest 有任何问题就**拒绝启动**。
     *
     *   不"用默认值兜底继续跑" —— 那等于用一套运维没写过的配置运行系统，
     *   而且没人知道。安全系统里，"拒绝启动 + 说清哪里错" 永远优于
     *   "按我以为的配置启动"。
     */

    if (manifest_parse(g_cfg_buf, (size_t)n, g_cgs, MAX_CGS, &g_ncgs)
        != OK)
      {
        printf("[ortsup] *** 拒绝启动: manifest 校验失败 ***\n");
        printf("[ortsup] 配置槽（%d 字节）: %s\n", n,
               g_mf_err ? g_mf_err : "未知原因");
        printf("[ortsup] 系统状态: BOOT_FAILED（锁存）\n");
        fflush(stdout);
        return 2;
      }

    /* 解析成功才提交（见 g_mf_startup_ms 的说明） */

    g_startup_window_ms = g_mf_startup_ms;
    g_last_cfg_seq      = (int)prctl(PR_GET_ORT_CFG_SEQ);
    g_last_cfg_tick     = (int)prctl(PR_GET_ORT_CFG_TICK);
    g_cfg_tick_ms       = g_now_ms;
  }

  printf("[ortsup] manifest: 由部署代理经配置槽递送"
         "（%d 个 CG，启动窗口 %d ms）\n", (int)NCGS, g_startup_window_ms);

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

  /* ★ 按 manifest 里**实际的** CG 数量拉起 —— 这里原来写死了两个下标
   *   （`&g_cgs[0]` 和 `&g_cgs[1]`）。
   *
   *   一份只有 1 个 CG 的 manifest 会让第二次 start_cg 去读
   *   `g_cgs[1].name` —— 而那一格是零初始化的 static，于是
   *   `printf("%s", NULL)` 直接把**监督者自己**打挂在启动路径上。
   *
   *   实测（SMP 撕裂实验的副产物）：监督者启动容器之后立刻
   *   `USER FAULT pid=<监督者> pc=... addr=00000000`。
   *   一直没暴露是因为此前每份 manifest 恰好都是 2 个 CG ——
   *   又是一个"只在一种输入下验证过"的坑（H31 那一族）。
   *
   *   延迟取值保留原来的演示语义：runtime 3s/8s，boot 0s/2s。 */

  {
    int i;

    for (i = 0; i < (int)NCGS; i++)
      {
        int delay = boot_mode ? ((i == 0) ? 0 : 2)
                              : ((i == 0) ? 3 : 8);

        if (start_cg(&g_cgs[i], "fault", delay, false) != 0)
          {
            state_to(ORT_BOOT_FAILED);
            return 1;
          }
      }
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

      /* ── 配置通道：读一个代数、读一个心跳 ───────────────────────────
       *
       * ★★ 控制循环在这里**不再碰文件**。
       *
       *   以前是每 2 秒一次 fopen + 逐行解析 + fclose ——
       *   也就是实时控制环里做文件 I/O，而 hostfs / flash 的最坏延迟
       *   不可控。现在两件事都是**标量读**：
       *
       *     代数（seq）  —— 变了才去取快照并解析（有界 memcpy + 有界解析）
       *     心跳（tick） —— 代理每跑一圈就加，与内容变没变无关
       *
       *   ★ 心跳是必需的，不是锦上添花：
       *     代理死了的症状是"配置再也不会变" —— 而它与
       *     "配置本来就不需要变"**看起来一模一样**。
       *     没有心跳，这两件事无法区分（H31 那一族）。
       */

      {
        int seq  = (int)prctl(PR_GET_ORT_CFG_SEQ);
        int tick = (int)prctl(PR_GET_ORT_CFG_TICK);

        if (seq >= 0 && seq != g_last_cfg_seq)
          {
            g_last_cfg_seq = seq;
            manifest_reload();
          }

        if (tick >= 0 && tick != g_last_cfg_tick)
          {
            g_last_cfg_tick = tick;
            g_cfg_tick_ms   = g_now_ms;
            g_cfg_lost      = false;
          }
        else if (!g_cfg_lost &&
                 (g_now_ms - g_cfg_tick_ms) >= DEPLOY_LOST_MS)
          {
            /* ★ Q1（已拍板）：失联 = **报告 + 保持当前配置**。
             *
             *   不自动降级、不重启代理 —— 代理是非实时组件，
             *   它的可用性不该绑住监督者的状态机。
             *   但**必须说出来**：沉默的失联正是 H31 那一族。 */

            g_cfg_lost = true;

            printf("[ortsup] *** 部署/O&M 代理失联"
                   "（心跳停滞 %d ms）***\n", DEPLOY_LOST_MS);
            printf("[ortsup]     当前配置保持原样继续运行。"
                   "配置不会再更新，直到代理恢复。\n");
            fflush(stdout);
          }
      }

      /* 反向验证 protocol 声明（见 audit_protocol）。放在故障排空之前：
       * 它读的是"这个 CG 现在是什么状态"，与被处理的事件无关。 */

      audit_protocol();

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

  printf(" | events=%d lost=%d | 审计: 缺口=%d 异常=%d\n",
         g_ev_count, g_ev_lost, g_audit_gap, g_audit_bad);

  /* 最终态的断言：本原型跑完必须落在有效终态上 */

  if (g_state != ORT_SAFE_STATE && g_state != ORT_DEGRADED &&
      g_state != ORT_BOOT_FAILED)
    {
      printf("[ortsup] *** FAIL *** 结束时不在有效终态\n");
      return 1;
    }

  return 0;
}
