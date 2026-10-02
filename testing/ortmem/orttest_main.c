/****************************************************************************
 * testing/ortmem/ortmem_main.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT] MPU 内存域隔离验证程序
 *
 * 验证目标：绑定到域 N 的任务，只能访问域 N 的块；
 *           访问其他域的块必须触发 MPU fault。
 *
 ****************************************************************************/

#include <nuttx/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <errno.h>
#include <nuttx/sched.h>

/* 与 arch/arm/src/armv7-m/arm_memdomain.h 保持一致 */

#define POOL_BASE   0x60840000u
#define BLOCK_SIZE  (16 * 1024u)
#define NBLOCKS     4

static int touch(volatile uint32_t *p, uint32_t val)
{
  *p = val;
  return (int)*p;
}

/* --- 并发测试 ------------------------------------------------------------
 *
 * 单线程测试只证明了「region 编程正确」，证明不了「切换时重编程正确」——
 * 后者才是这套机制的核心风险：如果 ort_memdomain_switch() 的时机或
 * region 编号搞错了，抢占发生时任务会拿到别人的块（读到别人的值）
 * 或者访问自己的块反而 fault。
 *
 * 所以让多个线程绑不同域、同时高频读写各自的块，制造大量上下文切换。
 */

#define CONC_ITERS  500

static volatile int g_conc_err;

/* --- 内核 → 监督者故障通道 ----------------------------------------------
 *
 * 为什么这条通道必须独立于容器的 SIGSEGV 处理器：
 *   容器可控。`sigaction(SIGSEGV, SIG_IGN)` 在 NuttX 里等于把动作整个删掉，
 *   容器一删，靠信号感知故障的监督者就瞎了。
 *
 *   ★ 终止权已经不由容器决定（arm_memfault.c 会升级到 SIGKILL），
 *     但「知道出事了」不能也依赖容器 —— 那是降级状态机的输入。
 */

static volatile int g_fault_events;
static volatile int g_fault_pid;
static volatile int g_fault_count_seen;

static void fault_sig_handler(int signo, FAR siginfo_t *info, FAR void *ctx)
{
  struct ort_faultrec_s rec;

  g_fault_events++;
  g_fault_pid = info->si_value.sival_int;

  prctl(PR_GET_ORT_FAULT, &rec);
  g_fault_count_seen = (int)rec.faults;

  printf("[ortmem] supervisor: 收到故障通知 #%u victim=%d pc=%p addr=%p faults=%u\n",
         rec.seq, rec.victim, (void *)rec.pc, (void *)rec.addr, rec.faults);
  fflush(stdout);
}

/* 被监督的容器：绑域 1，去写域 2 的块 —— 必然故障。
 *
 * ★ 必须是**独立任务**，不能是监督者的 pthread：
 *   nxsig_queue() 走的是 group 派发 —— 监督者与容器同组时，
 *   故障通知会被投进容器自己，监督者根本收不到。
 *   真实设计里 ort_safety 本来就是独立任务，这里如实模拟。
 */

static volatile uint32_t *g_container_target;

static int faulty_container(int argc, FAR char *argv[])
{
  FAR char *endp;
  long v = strtol(argv[1], &endp, 0);

  prctl(PR_SET_ORT_DOMAIN, (int)v);

  printf("[ortmem] container(domain %ld): writing %p, 应当被终止\n",
         v, (void *)g_container_target);
  fflush(stdout);

  touch(g_container_target, 0xbadbadu);

  printf("[ortmem] *** 容器存活 *** 隔离失效\n");
  return 9;
}

/* --- 容器可否决终止？ ----------------------------------------------------
 *
 * POSIX 允许忽略 SIGSEGV（结果未定义），NuttX 亦然：sig_action.c 只对
 * SIG_FLAG_NOCATCH 的信号返回 -EINVAL，而 SIGSEGV 没设这个标志。
 *
 * 所以「容器越界」必须由监督者保留终止权 —— 否则容器只要
 *   sigaction(SIGSEGV, SIG_IGN)
 * 就能把越界变成 no-op，异常返回后回到同一条指令再 fault，
 * 无限循环卡死 CPU。
 *
 * `orttest ignore` 就是这个攻击：预期容器**仍然死掉**（升级到 SIGKILL）。
 */

static void segv_observer(int signo)
{
  printf("[ortmem] SIGSEGV handler fired (signo=%d) — 容器感知到了越界\n",
         signo);
  fflush(stdout);
  _exit(42);
}

/* 危险版本：处理器打印一下就返回。
 *
 * 异常返回会**回到同一条故障指令**上再次 fault。若监督者不升级到
 * SIGKILL，这就是个无限循环 —— 容器可以借此卡死 CPU。
 */

static void segv_return(int signo)
{
  printf("[ortmem] SIGSEGV handler returned (signo=%d) — 任务将回到故障指令\n",
         signo);
  fflush(stdout);
}

static FAR void *conc_worker(FAR void *arg)
{
  int domain = (int)(uintptr_t)arg;
  volatile uint32_t *own =
      (volatile uint32_t *)(POOL_BASE + (uint32_t)domain * BLOCK_SIZE);
  uint32_t pattern = 0xc0de0000u + (uint32_t)domain;
  int i;

  if (prctl(PR_SET_ORT_DOMAIN, domain) != 0)
    {
      printf("[ortmem] worker %d: prctl FAILED\n", domain);
      g_conc_err++;
      return NULL;
    }

  for (i = 0; i < CONC_ITERS; i++)
    {
      *own = pattern;

      /* 写回后立刻读；若期间被切走且 region 没被正确重编程，
       * 要么读到别人的 pattern，要么直接 fault。
       */

      if (*own != pattern)
        {
          printf("[ortmem] worker %d: *** MISMATCH *** iter=%d got=%08x want=%08x\n",
                 domain, i, (unsigned)*own, (unsigned)pattern);
          g_conc_err++;
          break;
        }

      if ((i & 0x3f) == 0)
        {
          sched_yield();
        }
    }

  printf("[ortmem] worker domain %d: %d iters done\n", domain, i);
  return NULL;
}

int main(int argc, FAR char *argv[])
{
  volatile uint32_t *own;
  volatile uint32_t *other;
  int domain = 0;
  int ok;

  /* --- 负向对照 T0：未绑定任务不应该能访问任何域块 ---
   *
   * 用法：orttest probe
   *
   * 期望（修复后）：fault，任务被 SIGSEGV 终止
   * 反例（fail-open）：写入成功 —— 说明未绑定任务拿到了某个域
   */

  if (argc > 1 && strcmp(argv[1], "probe") == 0)
    {
      printf("[ortmem] T0 (negative control): UNBOUND task writing block 0 %p\n",
             (void *)POOL_BASE);
      fflush(stdout);

      ok = touch((volatile uint32_t *)POOL_BASE, 0xDEADBEEFu);
      printf("[ortmem] T0 RESULT: *** FAIL-OPEN *** unbound task wrote block 0, "
             "value=%08x\n", ok);
      return 3;
    }

  /* --- 监督者终止权：容器忽略 SIGSEGV 也必须死 ------------------------- */

  if (argc > 1 && strcmp(argv[1], "ignore") == 0)
    {
      struct sigaction sa;

      memset(&sa, 0, sizeof(sa));
      sa.sa_handler = SIG_IGN;
      sigaction(SIGSEGV, &sa, NULL);

      printf("[ortmem] hostile: SIGSEGV set to SIG_IGN, binding domain 0\n");
      prctl(PR_SET_ORT_DOMAIN, 0);

      other = (volatile uint32_t *)(POOL_BASE + BLOCK_SIZE);

      printf("[ortmem] writing other block %p (expect: 2nd fault -> SIGKILL)\n",
             (void *)other);
      fflush(stdout);

      touch(other, 0xbadbadu);

      /* 走到这里说明容器靠忽略 SIGSEGV 逃过了终止 —— 安全漏洞 */

      printf("[ortmem] *** SURVIVED *** 容器逃过了终止，越界被当成 no-op\n");
      return 5;
    }

  /* --- 容器可观测：注册处理器，自行决定退不退 --------------------------- */

  if (argc > 1 && strcmp(argv[1], "handler") == 0)
    {
      struct sigaction sa;

      memset(&sa, 0, sizeof(sa));
      sa.sa_handler = segv_observer;
      sigaction(SIGSEGV, &sa, NULL);

      printf("[ortmem] container installs SIGSEGV handler, binding domain 0\n");
      prctl(PR_SET_ORT_DOMAIN, 0);

      other = (volatile uint32_t *)(POOL_BASE + BLOCK_SIZE);

      printf("[ortmem] writing other block %p (expect: handler -> _exit(42))\n",
             (void *)other);
      fflush(stdout);

      touch(other, 0xbadbadu);

      printf("[ortmem] *** handler returned *** 监督者应当升级到 SIGKILL\n");
      return 6;
    }

  /* --- 监督者通道：容器故障必须能通知到监督者 --------------------------- */

  if (argc > 1 && strcmp(argv[1], "supervise") == 0)
    {
      struct sigaction sa;
      FAR char *cargv[2];
      int status;
      pid_t cpid;
      int i;

      printf("[ortmem] === supervisor channel test ===\n");

      memset(&sa, 0, sizeof(sa));
      sa.sa_sigaction = fault_sig_handler;
      sa.sa_flags     = SA_SIGINFO;
      sigaction(ORT_SIGFAULT, &sa, NULL);

      if (prctl(PR_SET_ORT_SUPERVISOR) != 0)
        {
          printf("[ortmem] FAIL: PR_SET_ORT_SUPERVISOR 注册失败\n");
          return 1;
        }

      printf("[ortmem] registered as supervisor (signal %d)\n", ORT_SIGFAULT);
      fflush(stdout);

      g_fault_events = 0;
      g_container_target = (volatile uint32_t *)(POOL_BASE + 2 * BLOCK_SIZE);

      /* 容器 = 独立任务（独立 group），绑域 1 去写域 2 */

      cargv[0] = (FAR char *)"1";
      cargv[1] = NULL;

      cpid = task_create("ortfault", 100, 2048, faulty_container, cargv);
      if (cpid < 0)
        {
          printf("[ortmem] FAIL: task_create = %d\n", (int)cpid);
          return 1;
        }

      printf("[ortmem] container pid=%d spawned\n", (int)cpid);

      /* 监督者等容器退出。注意 waitpid 会被 ORT_SIGFAULT 打断（EINTR）——
       * 这本身是**正确**行为：故障通知应当能立即打断监督者的等待。
       * 所以只重试 EINTR，其它错误才值得报。
       */

      while (waitpid(cpid, &status, 0) < 0 && errno == EINTR)
        {
        }

      /* 信号可能在容器退出之后才投递，等一小会儿 */

      for (i = 0; i < 20 && g_fault_events == 0; i++)
        {
          usleep(50000);
        }

      printf("[ortmem] SUPERVISE RESULT: %s (events=%d victim=%d faults=%d)\n",
             g_fault_events == 1 ? "PASS" : "*** FAIL ***",
             g_fault_events, g_fault_pid, g_fault_count_seen);
      return g_fault_events == 1 ? 0 : 8;
    }

  /* --- 危险路径：处理器返回 → 必须升级到 SIGKILL ------------------------ */

  if (argc > 1 && strcmp(argv[1], "handler-ret") == 0)
    {
      struct sigaction sa;

      memset(&sa, 0, sizeof(sa));
      sa.sa_handler = segv_return;
      sigaction(SIGSEGV, &sa, NULL);

      printf("[ortmem] container installs a RETURNING SIGSEGV handler\n");
      prctl(PR_SET_ORT_DOMAIN, 0);

      other = (volatile uint32_t *)(POOL_BASE + BLOCK_SIZE);

      printf("[ortmem] writing other block %p (expect: 2nd fault -> SIGKILL)\n",
             (void *)other);
      fflush(stdout);

      touch(other, 0xbadbadu);

      printf("[ortmem] *** SURVIVED *** 处理器返回后没被升级，容器卡死循环\n");
      return 7;
    }

  /* --- 并发测试：多个线程绑不同域，高频切换下验证各自只能碰自己的块 --- */

  if (argc > 1 && strcmp(argv[1], "conc") == 0)
    {
      pthread_t tid[NBLOCKS];
      int i;

      printf("[ortmem] === concurrent domain test (%d threads x %d iters) ===\n",
             NBLOCKS, CONC_ITERS);

      g_conc_err = 0;

      for (i = 0; i < NBLOCKS; i++)
        {
          if (pthread_create(&tid[i], NULL, conc_worker,
                             (FAR void *)(uintptr_t)i) != 0)
            {
              printf("[ortmem] pthread_create(%d) FAILED\n", i);
              return 1;
            }
        }

      for (i = 0; i < NBLOCKS; i++)
        {
          pthread_join(tid[i], NULL);
        }

      printf("[ortmem] CONC RESULT: %s (errors=%d)\n",
             g_conc_err == 0 ? "PASS" : "*** FAIL ***", g_conc_err);
      return g_conc_err == 0 ? 0 : 4;
    }

  if (argc > 1)
    {
      domain = atoi(argv[1]);
    }

  printf("[ortmem] === MPU domain isolation test ===\n");
  printf("[ortmem] pool=%p block=%u domains=%d\n",
         (void *)POOL_BASE, BLOCK_SIZE, NBLOCKS);
  printf("[ortmem] binding to domain %d ...\n", domain);

  if (prctl(PR_SET_ORT_DOMAIN, domain) != 0)
    {
      printf("[ortmem] FAIL: prctl returned error\n");
      return 1;
    }

  printf("[ortmem] bound OK\n");

  own   = (volatile uint32_t *)(POOL_BASE + (uint32_t)domain * BLOCK_SIZE);
  other = (volatile uint32_t *)
            (POOL_BASE + ((uint32_t)domain + 1) % NBLOCKS * BLOCK_SIZE);

  /* --- 测试 1：访问自己的块（应当成功）--- */

  printf("[ortmem] T1: write own block   %p ... ", (void *)own);
  ok = touch(own, 0x0A0A0A0Au);
  printf("value=%08x  %s\n", ok, (ok == 0x0A0A0A0Au) ? "OK" : "MISMATCH");
  printf("[ortmem] T1 RESULT: %s (expected PASS)\n",
         (ok == 0x0A0A0A0Au) ? "PASS" : "FAIL");

  /* --- 测试 2：访问别人的块（应当 fault）--- */

  printf("[ortmem] T2: write other block %p ... ", (void *)other);
  fflush(stdout);

  ok = touch(other, 0xBADBADu);

  /* 若执行到这里，说明 MPU 没拦住 */

  printf("value=%08x\n", ok);
  printf("[ortmem] T2 RESULT: *** FAIL *** (no fault, isolation broken)\n");
  return 2;
}
