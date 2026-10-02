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
 * ⚠️ 已知缺口（原型未实现）：
 *   启动期策略（《设计》§6 `startup.onContainerGroupFail`）与运行期策略
 *   是**两套语义**，本原型只实现了运行期那套。若容器在 BOOT 完成前就失效，
 *   事件会被排队到 NOMINAL 之后才处理 —— 这是简化，不是正确行为。
 *   见容器入口处关于 delay 参数的说明。
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

  /* 运行时状态 */

  pid_t           pid;
  int             restarts;
  int             faults;
  bool            failed;        /* 已失效且不再重启 */
};

static struct ort_cg_s g_cgs[] =
{
  /* 非关键 CG：失效只降级，允许有限次重启 */
  { "app_cg",    1, false, 2, -1, 0, 0, false },

  /* 关键 CG：失效即进安全态，不重启（SAFE_STATIC 推荐 NEVER） */
  { "safety_cg", 2, true,  0, -1, 0, 0, false },
};

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

static volatile int g_fault_events;
static volatile int g_fault_victim;
static volatile int g_fault_faults;

static void fault_sig_handler(int signo, FAR siginfo_t *info, FAR void *ctx)
{
  struct ort_faultrec_s rec;

  /* 信号只带 victim pid（唤醒用），详情从内核的单槽记录取回。
   * 这是刻意的：信号载荷有限，而故障详情是结构化的。
   */

  memset(&rec, 0, sizeof(rec));
  prctl(PR_GET_ORT_FAULT, &rec);

  g_fault_victim = info->si_value.sival_int;
  g_fault_faults = (int)rec.faults;
  g_fault_events++;

  printf("[ortsup] ← 故障通知: victim=%d pc=%p addr=%p faults=%u\n",
         g_fault_victim, (void *)rec.pc, (void *)rec.addr,
         (unsigned)rec.faults);
  fflush(stdout);
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

static int start_cg(FAR struct ort_cg_s *cg, FAR const char *mode, int delay)
{
  FAR char *cargv[4];
  char dbuf[8];
  char lbuf[8];
  pid_t pid;

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

  cg->pid = pid;
  return 0;
}

/* 一个 CG 失效时的策略决策（《设计》§3.2 的转移规则） */

static void on_cg_failed(FAR struct ort_cg_s *cg)
{
  cg->faults++;

  printf("[ortsup] %s 失效（第 %d 次，restart %d/%d）\n",
         cg->name, cg->faults, cg->restarts, cg->max_restarts);

  /* 关键 CG：无论重启预算如何，直接进安全态（T7 / T8） */

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
  bool settled;
  int i;
  int rounds = 0;
  int g_handled;

  /* 输出即交付物：容器与监督者并发打印，行缓冲会让整行被截断/交错，
   * 状态机看起来就像乱的。改成无缓冲。
   */

  setvbuf(stdout, NULL, _IOLBF, 0);

  printf("[ortsup] === ORT 监督者原型（降级状态机）===\n");
  printf("[ortsup] 系统状态: BOOT\n");

  /* 注册监督者 + 挂故障通道。注意信号用 SIGUSR1：
   * CONFIG_SIG_SIGUSR1_ACTION 默认为 n，内核不配默认动作，
   * 只有主动挂钩子的任务会收到。
   */

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = fault_sig_handler;
  sa.sa_flags     = SA_SIGINFO;
  sigaction(ORT_SIGFAULT, &sa, NULL);

  if (prctl(PR_SET_ORT_SUPERVISOR) != 0)
    {
      printf("[ortsup] FAIL: 注册监督者失败\n");
      return 1;
    }

  /* ── BOOT：按 startOrder 拉起全部 CG ──────────────────────────────── */

  /* 延迟参数的取值不是随意的：
   *
   *   app_cg    1s —— 让 BOOT 先完成
   *   safety_cg 8s —— 必须晚于 app_cg **耗尽重启预算**
   *
   * app_cg 走 1s 故障 + 1s 故障 + 1s 故障，约 3s 后进 DEGRADED。
   * safety_cg 留 5s 余量，才能演示到完整的
   * NOMINAL → DEGRADED → SAFE_STATE 路径（T6 然后 T8）。
   *
   * ⚠️ 这个顺序本质上依赖时序。演示场景可以靠余量保证，但**状态机本身
   *    不能假设事件顺序** —— 真实系统里 safety_cg 完全可能先失效
   *    （那就是 T7：直接 NOMINAL → SAFE_STATE，同样是正确的）。
   */

  if (start_cg(&g_cgs[0], "fault", 1) != 0 ||
      start_cg(&g_cgs[1], "fault", 8) != 0)
    {
      state_to(ORT_BOOT_FAILED);
      return 1;
    }

  state_to(ORT_NOMINAL);

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

      /* 排空已到达的故障事件 */

      while (g_fault_events > g_handled)
        {
          int victim = g_fault_victim;

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

      usleep(5000);
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

  printf(" | events=%d\n", g_fault_events);

  /* 最终态的断言：本原型跑完必须落在有效终态上 */

  if (g_state != ORT_SAFE_STATE && g_state != ORT_DEGRADED &&
      g_state != ORT_BOOT_FAILED)
    {
      printf("[ortsup] *** FAIL *** 结束时不在有效终态\n");
      return 1;
    }

  return 0;
}
