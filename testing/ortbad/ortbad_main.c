/****************************************************************************
 * testing/ortbad/ortbad_main.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT] ORT-A（MMU 平台）用户故障隔离验证
 *
 * ★ 与 ortmem（MPU 平台）的验证目标完全不同：
 *
 *   ORT-M：验证「MPU 隔离机制」—— 上下文切换时重编程 region 是否管用。
 *   ORT-A：MMU 的隔离是**天然**给的（每个进程独立地址空间），
 *          不需要任何 per-switch 编程。要验证的是**故障处理策略** ——
 *
 *          NuttX 在 armv7-a/arm_dataabort.c 里对任何 data abort 直接
 *          PANIC_WITH_REGS。也就是说：**一个用户进程越界会带走整机**。
 *
 *          这和 ORT-M 的 H27 是同一类问题、不同的根因。
 *
 * 用法：
 *   ortbad           自己越界（验证：进程死、内核活、nsh 恢复）
 *   ortbad sup       监督者模式：注册 → posix_spawn 一个越界的子进程
 *                    → 等故障通知
 *   ortbad child     子进程角色：越界
 *
 ****************************************************************************/

#include <nuttx/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <spawn.h>

/* 一个必然未映射的地址。
 *
 * 不用 0 —— 有些配置会映射低地址；也不用栈附近的地址，
 * 免得测出来的是"栈溢出"而不是"越界"。
 */

#define BAD_ADDR  ((volatile uint32_t *)0xdeadbe00u)

static volatile int g_fault_events;
static volatile int g_fault_victim;

static void fault_sig_handler(int signo, FAR siginfo_t *info, FAR void *ctx)
{
  struct ort_faultrec_s rec;
  int n;

  (void)info;
  (void)ctx;

  /* hchild 模式下这一行就是"trampoline 路径确实把信号送到了用户态"的证据 */

  printf("[ortbad] 用户信号处理器被调用: signo=%d\n", signo);
  fflush(stdout);

  /* 排空事件队列（信号只作唤醒，可能合并） */

  while ((n = prctl(PR_GET_ORT_FAULT, &rec)) > 0)
    {
      g_fault_events++;
      g_fault_victim = rec.victim;

      printf("[ortbad] supervisor: 事件 #%u victim=%d pc=%p addr=%p "
             "faults=%u lost=%u\n",
             (unsigned)rec.seq, rec.victim, (void *)rec.pc, (void *)rec.addr,
             (unsigned)rec.faults, (unsigned)rec.lost);
      fflush(stdout);
    }
}

int main(int argc, FAR char *argv[])
{
  FAR const char *mode = "";
  int ai;

  /* ⚠️ NuttX 的 posix_spawn() 和 task_create() 一样，会把**程序名插到
   *    argv[0]**（见 sched/task/task_setup.c: nxtask_setup_stackargs）。
   *    所以不能按 POSIX 的惯例假设 argv[1] 是我们的第一个参数 ——
   *    扫描一遍最稳。
   */

  setvbuf(stdout, NULL, _IOLBF, 0);

  printf("[ortbad] argc=%d argv=[", argc);
  for (ai = 0; ai < argc; ai++)
    {
      printf("%s%s", argv[ai] ? argv[ai] : "(null)", ai + 1 < argc ? " " : "");
    }
  printf("]\n");
  fflush(stdout);

  for (ai = 0; ai < argc; ai++)
    {
      if (argv[ai] != NULL && strcmp(argv[ai], "child") == 0)
        {
          mode = "child";
        }
      else if (argv[ai] != NULL && strcmp(argv[ai], "sup") == 0)
        {
          mode = "sup";
        }
      else if (argv[ai] != NULL && strcmp(argv[ai], "hchild") == 0)
        {
          mode = "hchild";
        }
      else if (argv[ai] != NULL && strcmp(argv[ai], "caps") == 0)
        {
          mode = "caps";
        }
    }

  /* --- caps：查询本平台的 ORT 能力位 -----------------------------------
   *
   * 这条是给**准入检查**用的探针：容器的 manifest 里声明了
   * "故障时我要自己处理"，监督者必须先问平台能不能兑现，
   * 不能兑现就拒绝准入 —— 而不是等运行期默默降级成"直接杀掉"。
   */

  if (strcmp(mode, "caps") == 0)
    {
      int caps = prctl(PR_GET_ORT_CAPS);

      if (caps < 0)
        {
          printf("[ortbad] CAPS: prctl 失败 ret=%d\n", caps);
          return 1;
        }

      printf("[ortbad] CAPS: 0x%08x\n", (unsigned)caps);
      printf("[ortbad] CAPS: FAULT_HANDLER = %s —— 容器自装的故障处理器%s\n",
             (caps & ORT_CAP_FAULT_HANDLER) ? "有" : "无",
             (caps & ORT_CAP_FAULT_HANDLER)
               ? "会被调用（但容器仍须死）"
               : "不会被执行，内核直接升级 SIGKILL");

      /* 准入判定的实际写法：声明与能力对不上就拒绝，别默默降级 */

      printf("[ortbad] CAPS: 准入检查 —— 声明'自行处理故障'的容器：%s\n",
             (caps & ORT_CAP_FAULT_HANDLER) ? "接受" : "拒绝（平台不兑现）");

      fflush(stdout);
      return 0;
    }

  /* --- 监督者模式 ------------------------------------------------------ */

  if (strcmp(mode, "sup") == 0)
    {
      struct sigaction sa;
      FAR char *cargv[3];
      pid_t cpid;
      int i;


      printf("[ortbad] === ORT-A 故障隔离测试（监督者模式）===\n");

      memset(&sa, 0, sizeof(sa));
      sa.sa_sigaction = fault_sig_handler;
      sa.sa_flags     = SA_SIGINFO;
      sigaction(ORT_SIGFAULT, &sa, NULL);

      prctl(PR_ORT_SUPERVISOR_RESET);

      if (prctl(PR_SET_ORT_SUPERVISOR) != 0)
        {
          printf("[ortbad] FAIL: 注册监督者失败\n");
          return 1;
        }

      printf("[ortbad] 已注册为监督者，派生容器进程...\n");

      g_fault_events = 0;

      /* argv[0] 是程序名，模式放在 argv[1] */

      cargv[0] = (FAR char *)"ortbad";
      cargv[1] = (FAR char *)"child";
      cargv[2] = NULL;

      if (posix_spawn(&cpid, "/system/bin/ortbad", NULL, NULL,
                      cargv, NULL) != 0)
        {
          printf("[ortbad] FAIL: posix_spawn\n");
          return 1;
        }

      printf("[ortbad] 容器 pid=%d 已派生，等它被终止...\n", (int)cpid);
      fflush(stdout);

      /* ★ 不调用 waitpid()。
       *
       * 为什么：NuttX 在 CONFIG_SCHED_HAVE_PARENT && !CONFIG_SCHED_CHILD_STATUS
       * 下，waittcb() 是**等 SIGCHLD 信号**（nxsig_timedwait）——
       * 实测监督者会卡在里面不出来。
       *
       * 而且这本来也不是 ORT 监督者该有的样子：它靠**故障事件**驱动，
       * 不轮询子进程。终止由内核保证（终止权），监督者只需要知道
       * "谁出事了"。（同样的结论在 ORT-M 侧已经从另一个角度得出过。）
       */

      for (i = 0; i < 200 && g_fault_events == 0; i++)
        {
          usleep(10000);
        }

      for (i = 0; i < 20 && g_fault_events == 0; i++)
        {
          usleep(50000);
        }

      printf("[ortbad] SUPERVISE RESULT: %s (events=%d victim=%d)\n",
             g_fault_events >= 1 ? "PASS" : "*** FAIL ***",
             g_fault_events, g_fault_victim);
      return g_fault_events >= 1 ? 0 : 8;
    }

  /* --- 默认 / child：越界 ---------------------------------------------- */

  if (strcmp(mode, "hchild") == 0)
    {
      /* ★ 故意让进程"能接住"SIGSEGV，验证两条边：
       *   ① 用户处理器必须走 trampoline 回到**用户态/用户栈**去跑 ——
       *      绝不能被放到内核栈上执行（那样是特权提升）；
       *   ② 处理器返回后必然再踩同一条故障指令，内核由此升级到 SIGKILL，
       *      而 SIGKILL 的默认动作仍应在内核栈上完成。
       */

      struct sigaction sa;

      /* ★ 这里装的必须是 **SIGSEGV**，不是 ORT_SIGFAULT（=SIGUSR1，
       *   那是内核叫醒监督者用的）。装错信号这一模式就白测了。 */

      memset(&sa, 0, sizeof(sa));
      sa.sa_sigaction = fault_sig_handler;
      sa.sa_flags     = SA_SIGINFO;
      sigaction(SIGSEGV, &sa, NULL);

      printf("[ortbad] 容器进程: 已装 SIGSEGV 处理器，即将越界写 %p\n",
             (void *)BAD_ADDR);
      fflush(stdout);
    }
  else if (strcmp(mode, "child") == 0)
    {
      printf("[ortbad] 容器进程: 即将越界写 %p\n", (void *)BAD_ADDR);
      fflush(stdout);
    }
  else
    {
      printf("[ortbad] 用户进程: 即将越界写 %p\n", (void *)BAD_ADDR);
      fflush(stdout);
    }

  *BAD_ADDR = 0xbadbadu;      /* ← 必然触发 data abort */

  printf("[ortbad] *** SURVIVED *** 越界没被拦住 —— 隔离失效\n");
  return 9;
}
