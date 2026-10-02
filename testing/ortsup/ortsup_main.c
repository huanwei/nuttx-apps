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
#include <nuttx/sched.h>

#define POOL_BASE   0x60840000u
#define BLOCK_SIZE  (16 * 1024u)
#define NBLOCKS     4

#define CONTAINER_PRIO   110
#define CONTAINER_STACK  2048

/* 启动窗口：准入之后多少毫秒内仍算「启动期」。
 * 对应《设计》§6 的 safetyPolicy.startup.startTimeoutMs。
 */

#define STARTUP_WINDOW_MS  1500

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
  FAR const char *name;
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

static struct ort_cg_s g_cgs[] =
{
  /* 非关键 CG：失效只降级，允许有限次重启 */
  { "app_cg",    1, false, 2, false, -1, 0, 0, false, -1 },

  /* 关键 CG：失效即进安全态，不重启（SAFE_STATIC 推荐 NEVER） */
  { "safety_cg", 2, true,  0, false, -1, 0, 0, false, -1 },
};

/* 平台能力位。读一次就够 —— 它是平台属性，不会变。
 * 必须在 main 里 prctl 查询后填好（用户态拿不到 ort_caps() 本身）。
 */

static unsigned int g_caps;

/* 监督者时钟（毫秒）。用循环计数而不是 clock()：
 * 周期是确定的（LOOP_MS），不必依赖系统时钟的精度与语义。
 */

static int g_now_ms;

#define NCGS (sizeof(g_cgs) / sizeof(struct ort_cg_s))

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
  FAR const char *mode;
  volatile uint32_t *own;
  volatile uint32_t *other;
  int delay = 0;
  int domain;

  if (argc < 3)
    {
      return 1;
    }

  mode   = argv[1];        /* 父进程 cargv[0] → 子进程 argv[1] */
  domain = atoi(argv[2]);  /* 父进程 cargv[1] → 子进程 argv[2] */

  if (argc > 3)
    {
      delay = atoi(argv[3]);
    }

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

  own   = (volatile uint32_t *)(POOL_BASE + (uint32_t)domain * BLOCK_SIZE);
  other = (volatile uint32_t *)
            (POOL_BASE + ((uint32_t)domain + 1) % NBLOCKS * BLOCK_SIZE);

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
  FAR char *cargv[4];
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
  cargv[0] = (FAR char *)mode;
  cargv[1] = dbuf;
  cargv[2] = lbuf;
  cargv[3] = NULL;

  /* 注意参数顺序：NuttX 会把任务名插到 argv[0]，所以容器里看到的是
   * {name, mode, domain}。上面 ort_container_main 按这个布局读。
   */

  pid = task_create(cg->name, CONTAINER_PRIO, CONTAINER_STACK,
                    ort_container_main, cargv);
  if (pid < 0)
    {
      printf("[ortsup] 启动 %s 失败: %d\n", cg->name, (int)pid);
      return (int)pid;
    }

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
         (g_now_ms - cg->admitted_ms) < STARTUP_WINDOW_MS;
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
             cg->name, g_now_ms - cg->admitted_ms, STARTUP_WINDOW_MS);

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
  printf("[ortsup] 场景: %s（启动窗口 %d ms）\n",
         boot_mode ? "boot —— 启动期失效" : "runtime —— 运行期失效",
         STARTUP_WINDOW_MS);
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
