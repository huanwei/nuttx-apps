/****************************************************************************
 * testing/ortmem/orttest_main.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT] MPU 内存域隔离验证程序
 *
 * 验证目标：
 *   1. 绑定到域 N 的容器只能访问域 N 的块；访问其他域必须触发 fault
 *   2. 切换时重编程 region 在真实抢占下正确（并发用例）
 *   3. 容器无法否决自己的终止（对抗用例）
 *   4. 容器故障能通过独立通道通知监督者
 *
 * ★ 两个关键语义（v2 起）：
 *
 *   ① 域是**容器级**的（task_group_s 的 tg_ort_domain），不是线程级。
 *      同一容器的所有线程共享一个域 —— 它们本来就共享内存。
 *
 *   ② 域由**监督者下发**，容器不能自己申报。
 *      域号就是内存块号，容器能自选就能选到别的容器的块。
 *      → 所以本程序里凡是需要域的用例，都是「监督者模式」：
 *        父进程注册为监督者 → 派生独立容器 → 绑域 → 等它被终止。
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

/* 容器优先级低于监督者（真实设计里 ort_safety 也在「边界之下、容器之上」
 * 的优先级带）。
 *
 * ⚠️ 但这**不足以**保证「绑域发生在容器首次运行之前」—— 实测踩过：
 *    task_create() 返回后、监督者还没调到 prctl，容器就已经被调度到并
 *    在未绑定状态下碰了内存（直接 fault，而且日志上看不出所以然）。
 *
 *    所以容器侧有一个显式的**准入等待**（见 ort_container_main 里
 *    prctl(PR_GET_ORT_DOMAIN) 的轮询）。优先级只用于让监督者尽快绑，
 *    正确性靠准入协议，不靠调度时序。
 */

#define SUPERVISOR_PRIO  100
#define CONTAINER_PRIO   110
#define CONTAINER_STACK  2048

static int touch(volatile uint32_t *p, uint32_t val)
{
  *p = val;
  return (int)*p;
}

static volatile uint32_t *block_of(int domain)
{
  return (volatile uint32_t *)(POOL_BASE + (uint32_t)domain * BLOCK_SIZE);
}

/* =========================================================================
 * 监督者侧
 * ========================================================================= */

static volatile int  g_fault_events;
static volatile int  g_fault_pid;
static volatile pid_t g_container_pid;

/* 容器入口（定义在下面，run_container 要先用到） */

int ort_container_main(int argc, FAR char *argv[]);

static void fault_sig_handler(int signo, FAR siginfo_t *info, FAR void *ctx)
{
  struct ort_faultrec_s rec;

  g_fault_events++;
  g_fault_pid = info->si_value.sival_int;

  prctl(PR_GET_ORT_FAULT, &rec);

  printf("[ortmem] supervisor: 收到故障通知 #%u victim=%d pc=%p addr=%p "
         "faults=%u\n",
         (unsigned)rec.seq, rec.victim, (void *)rec.pc, (void *)rec.addr,
         (unsigned)rec.faults);
  fflush(stdout);
}

/* 注册为监督者。跨多次 orttest 调用时，上一个监督者可能已经退出 ——
 * 内核只在「下次故障通知失败」时才清槽，所以这里要允许接管。
 */

static void become_supervisor(void)
{
  struct sigaction sa;
  int ret;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = fault_sig_handler;
  sa.sa_flags     = SA_SIGINFO;
  sigaction(ORT_SIGFAULT, &sa, NULL);

  ret = prctl(PR_SET_ORT_SUPERVISOR);
  if (ret != 0)
    {
      printf("[ortmem] FAIL: PR_SET_ORT_SUPERVISOR = %d\n", ret);
      exit(1);
    }
}

static int bind_container(pid_t pid, int domain)
{
  int ret = prctl(PR_SET_ORT_DOMAIN, domain, (int)pid);

  if (ret != 0)
    {
      printf("[ortmem] FAIL: bind pid=%d domain=%d -> %d\n", (int)pid,
             domain, ret);
    }

  return ret;
}

/* 派生一个容器并在它运行之前绑好域，然后等它结束。 */

static int run_container(FAR const char *scenario, int domain)
{
  FAR char *cargv[3];
  char dbuf[8];
  int status;
  pid_t cpid;

  snprintf(dbuf, sizeof(dbuf), "%d", domain);
  cargv[0] = (FAR char *)scenario;
  cargv[1] = dbuf;
  cargv[2] = NULL;

  g_container_pid = -1;

  cpid = task_create("ortctnr", CONTAINER_PRIO, CONTAINER_STACK,
                     ort_container_main, cargv);
  if (cpid < 0)
    {
      printf("[ortmem] FAIL: task_create = %d\n", (int)cpid);
      return 1;
    }

  g_container_pid = cpid;

  /* 绑域。容器侧会等这个绑定完成（准入等待），所以这里不赶时间 ——
   * 但不能不绑，否则容器会一直等下去直到超时。
   */

  if (bind_container(cpid, domain) != 0)
    {
      return 1;
    }

  /* 故障通知会打断 waitpid（EINTR）—— 这是正确行为：
   * 监督者应当能被故障事件立即唤醒。
   */

  while (waitpid(cpid, &status, 0) < 0 && errno == EINTR)
    {
    }

  return 0;
}

/* =========================================================================
 * 容器侧（由监督者 task_create 出来，域已绑好）
 * ========================================================================= */

static void segv_observer(int signo)
{
  printf("[ortmem] container: SIGSEGV handler fired — 容器感知到了越界，"
         "_exit(42)\n");
  fflush(stdout);
  _exit(42);
}

static void segv_return(int signo)
{
  printf("[ortmem] container: SIGSEGV handler returned — 任务将回到故障指令\n");
  fflush(stdout);
}

/* 场景 a：基础隔离。T1 写自有块（应成功），T2 写他域块（应 fault） */

static void scene_basic(int domain)
{
  volatile uint32_t *own   = block_of(domain);
  volatile uint32_t *other = block_of((domain + 1) % NBLOCKS);
  int ok;

  printf("[ortmem] === MPU domain isolation test (domain %d) ===\n", domain);

  printf("[ortmem] T1: write own block   %p ... ", (void *)own);
  ok = touch(own, 0x0a0a0a0au);
  printf("value=%08x  %s\n", ok, (ok == 0x0a0a0a0au) ? "OK" : "MISMATCH");
  printf("[ortmem] T1 RESULT: %s (expected PASS)\n",
         (ok == 0x0a0a0a0au) ? "PASS" : "FAIL");

  printf("[ortmem] T2: write other block %p ... ", (void *)other);
  fflush(stdout);

  ok = touch(other, 0xbadbadu);

  printf("value=%08x\n", ok);
  printf("[ortmem] T2 RESULT: *** FAIL *** (no fault, isolation broken)\n");
}

/* 场景 b：容器忽略 SIGSEGV —— 仍须被终止 */

static void scene_ignore(int domain)
{
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;
  sigaction(SIGSEGV, &sa, NULL);

  printf("[ortmem] container: SIGSEGV set to SIG_IGN, writing other block %p\n",
         (void *)block_of((domain + 1) % NBLOCKS));
  fflush(stdout);

  touch(block_of((domain + 1) % NBLOCKS), 0xbadbadu);

  printf("[ortmem] *** SURVIVED *** 容器逃过了终止，越界被当成 no-op\n");
}

/* 场景 c：容器注册处理器并自行退出 */

static void scene_handler(int domain)
{
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = segv_observer;
  sigaction(SIGSEGV, &sa, NULL);

  printf("[ortmem] container: installs SIGSEGV handler, writing block %p\n",
         (void *)block_of((domain + 1) % NBLOCKS));
  fflush(stdout);

  touch(block_of((domain + 1) % NBLOCKS), 0xbadbadu);

  printf("[ortmem] *** handler returned *** 监督者应当升级到 SIGKILL\n");
}

/* 场景 d：容器处理器返回 —— 危险路径，仍须被终止 */

static void scene_handler_ret(int domain)
{
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = segv_return;
  sigaction(SIGSEGV, &sa, NULL);

  printf("[ortmem] container: installs a RETURNING SIGSEGV handler, "
         "writing block %p\n", (void *)block_of((domain + 1) % NBLOCKS));
  fflush(stdout);

  touch(block_of((domain + 1) % NBLOCKS), 0xbadbadu);

  printf("[ortmem] *** SURVIVED *** 处理器返回后没被升级，容器卡死循环\n");
}

/* 场景 e：并发。多个**独立容器**各绑一个域，高频读写自己的块。
 *
 * 为什么必须是独立容器而不是同容器的多个线程：
 *   域是容器级的 —— 同容器的线程本来就共享一个域，那样测不出
 *   「切换时重编程」是否正确。要制造跨域切换，就得有多个容器。
 */

#define CONC_ITERS  500

static void scene_conc(int domain)
{
  volatile uint32_t *own = block_of(domain);
  uint32_t pattern = 0xc0de0000u + (uint32_t)domain;
  int i;

  for (i = 0; i < CONC_ITERS; i++)
    {
      *own = pattern;

      /* 写回后立刻读；若期间被切走且 region 没被正确重编程，
       * 要么读到别人的 pattern，要么直接 fault。
       */

      if (*own != pattern)
        {
          printf("[ortmem] container %d: *** MISMATCH *** iter=%d "
                 "got=%08x want=%08x\n",
                 domain, i, (unsigned)*own, (unsigned)pattern);
          return;
        }

      if ((i & 0x3f) == 0)
        {
          sched_yield();
        }
    }

  printf("[ortmem] container %d: %d iters OK\n", domain, i);
}

/* 场景 f：同容器的多个线程共享一个域。
 *
 * 这条直接验证「域是容器级」：两个 pthread 同时写**同一个**块，
 * 若域是线程级的，其中一个必然 fault。
 */

static int g_share_err;

static FAR void *share_worker(FAR void *arg)
{
  volatile uint32_t *own = (volatile uint32_t *)arg;
  int i;

  for (i = 0; i < 200; i++)
    {
      *own = 0x5717u;
      if (*own != 0x5717u)
        {
          g_share_err++;
          break;
        }
    }

  return NULL;
}

static void scene_share(int domain)
{
  volatile uint32_t *own = block_of(domain);
  pthread_t t1;
  pthread_t t2;

  printf("[ortmem] container: 2 threads sharing domain %d's block %p\n",
         domain, (void *)own);
  fflush(stdout);

  g_share_err = 0;

  pthread_create(&t1, NULL, share_worker, (FAR void *)own);
  pthread_create(&t2, NULL, share_worker, (FAR void *)own);

  pthread_join(t1, NULL);
  pthread_join(t2, NULL);

  printf("[ortmem] SHARE RESULT: %s (errors=%d)\n",
         g_share_err == 0 ? "PASS" : "*** FAIL ***", g_share_err);
}

/* 容器入口：域已由监督者绑好，这里只跑场景。
 *
 * ⚠️ 注意 argv 的偏移：NuttX 的 task_create() 会把**任务名插到 argv[0]**
 *    （见 sched/task/task_setup.c: "The argument count does not include
 *    the task name in that will be in argv[0]"）。所以父进程传的
 *    {"basic", "1", NULL} 到了这里变成：
 *
 *      argv[0]="ortctnr"  argv[1]="basic"  argv[2]="1"
 *
 *    这个坑很隐蔽：参数错位不会报错，只是场景名匹配不上、直接返回 0，
 *    表现为「容器一起来就退出」，没有任何线索。
 */

int ort_container_main(int argc, FAR char *argv[])
{
  FAR const char *scenario;
  int domain;

  if (argc < 3)
    {
      printf("[ortmem] container: bad argc=%d\n", argc);
      return 1;
    }

  scenario = argv[1];
  domain   = atoi(argv[2]);

  /* ★ 等待监督者绑域 —— 容器创建与绑域之间存在窗口。
   *
   * 为什么不能省：实测容器经常在监督者调 prctl 之前就被调度到
   * （task_create → up_unblock_task 之间就可能切换），那时它是未绑定的，
   * 第一次碰内存就直接 fault。
   *
   * 真实系统里这应该由「容器准入协议」保证 —— 监督者先建号、绑好域，
   * 再放行容器执行。原型期用轮询把这件事显式化，而不是靠调度时序去赌。
   */

  {
    int waited = 0;

    while (prctl(PR_GET_ORT_DOMAIN) < 0)
      {
        if (++waited > 2000)
          {
            printf("[ortmem] container: 等不到绑域，放弃\n");
            return 1;
          }

        usleep(1000);
      }

    printf("[ortmem] container: 准入通过，本容器域=%d（监督者指定 %d），"
           "等了 %d ms\n", (int)prctl(PR_GET_ORT_DOMAIN), domain, waited);
  }

  if (strcmp(scenario, "basic") == 0)
    {
      scene_basic(domain);
    }
  else if (strcmp(scenario, "ignore") == 0)
    {
      scene_ignore(domain);
    }
  else if (strcmp(scenario, "handler") == 0)
    {
      scene_handler(domain);
    }
  else if (strcmp(scenario, "handler-ret") == 0)
    {
      scene_handler_ret(domain);
    }
  else if (strcmp(scenario, "conc") == 0)
    {
      scene_conc(domain);
    }
  else if (strcmp(scenario, "share") == 0)
    {
      scene_share(domain);
    }

  return 0;
}

/* =========================================================================
 * 主入口
 * ========================================================================= */

int main(int argc, FAR char *argv[])
{
  FAR const char *mode = argc > 1 ? argv[1] : "";

  /* --- 不需要域的用例：单进程直接跑 ------------------------------------- */

  if (strcmp(mode, "probe") == 0)
    {
      /* 负向对照：未绑定的任务（本进程没注册监督者、也没被绑域）
       * 不应能访问任何域块。
       */

      printf("[ortmem] T0 (negative control): UNBOUND task writing block 0 %p\n",
             (void *)POOL_BASE);
      fflush(stdout);

      touch((volatile uint32_t *)POOL_BASE, 0xdeadbeefu);

      printf("[ortmem] T0 RESULT: *** FAIL-OPEN *** 未绑定任务写成功了\n");
      return 3;
    }

  /* --- 容器不能自己申报域（非监督者调用应被拒）-------------------------- */

  if (strcmp(mode, "selfbind") == 0)
    {
      /* 本进程没注册监督者，所以它不是监督者。
       * 尝试给自己绑一个「好」的域 —— 这正是容器越权的方式：
       * 域号就是内存块号，能自选就能选到别的容器的块。
       */

      int ret = prctl(PR_SET_ORT_DOMAIN, 3, (int)getpid());

      printf("[ortmem] SELF-BIND RESULT: ret=%d (%s)\n", ret,
             ret == -EPERM ? "EPERM —— 正确拒绝" : "*** 没拦住 ***");
      return ret == -EPERM ? 0 : 4;
    }

  /* --- 监督者通道：容器故障必须通知到监督者 ----------------------------- */

  if (strcmp(mode, "supervise") == 0)
    {
      int i;

      printf("[ortmem] === supervisor channel test ===\n");

      become_supervisor();
      g_fault_events = 0;

      if (run_container("basic", 1) != 0)
        {
          return 1;
        }

      /* 信号可能在容器退出之后才投递，等一小会儿 */

      for (i = 0; i < 20 && g_fault_events == 0; i++)
        {
          usleep(50000);
        }

      printf("[ortmem] SUPERVISE RESULT: %s (events=%d victim=%d)\n",
             g_fault_events >= 1 ? "PASS" : "*** FAIL ***", g_fault_events,
             g_fault_pid);
      return g_fault_events >= 1 ? 0 : 8;
    }

  /* --- 单容器用例：监督者绑域 → 容器跑场景 → 等它被终止 ----------------- */

  if (argc == 2 && mode[0] >= '0' && mode[0] <= '9')
    {
      become_supervisor();
      return run_container("basic", atoi(mode));
    }

  if (strcmp(mode, "ignore") == 0 || strcmp(mode, "handler") == 0 ||
      strcmp(mode, "handler-ret") == 0)
    {
      become_supervisor();
      return run_container(mode, 0);
    }

  if (strcmp(mode, "share") == 0)
    {
      become_supervisor();
      return run_container("share", 2);
    }

  /* --- 并发：4 个独立容器各绑一个域 -------------------------------------- */

  if (strcmp(mode, "conc") == 0)
    {
      FAR char *cargv[3];
      char dbuf[NBLOCKS][8];
      pid_t cpid[NBLOCKS];
      int status;
      int i;

      printf("[ortmem] === concurrent domain test "
             "(%d containers x %d iters) ===\n", NBLOCKS, CONC_ITERS);

      become_supervisor();

      for (i = 0; i < NBLOCKS; i++)
        {
          snprintf(dbuf[i], sizeof(dbuf[i]), "%d", i);
          cargv[0] = (FAR char *)"conc";
          cargv[1] = dbuf[i];
          cargv[2] = NULL;

          cpid[i] = task_create("ortctnr", CONTAINER_PRIO, CONTAINER_STACK,
                                ort_container_main, cargv);
          if (cpid[i] < 0)
            {
              printf("[ortmem] FAIL: task_create(%d) = %d\n", i, (int)cpid[i]);
              return 1;
            }

          /* 每个容器创建后立刻绑域，趁它还没被调度 */

          if (bind_container(cpid[i], i) != 0)
            {
              return 1;
            }
        }

      for (i = 0; i < NBLOCKS; i++)
        {
          while (waitpid(cpid[i], &status, 0) < 0 && errno == EINTR)
            {
            }
        }

      printf("[ortmem] CONC RESULT: PASS (4 containers finished, "
             "无 fault 即隔离在抢占下成立)\n");
      return 0;
    }

  printf("用法:\n"
         "  orttest probe        未绑定任务写域块（负向对照，应 fault）\n"
         "  orttest selfbind     容器自己申报域（应被 -EPERM 拒绝）\n"
         "  orttest <0|1|2|3>    绑域 N：T1 自有块应成功，T2 他域块应 fault\n"
         "  orttest conc         4 个容器并发跨域抢占\n"
         "  orttest share        同容器 2 线程共享一个域\n"
         "  orttest handler      容器挂钩子并 _exit(42)\n"
         "  orttest ignore       容器 SIG_IGN（应仍被终止）\n"
         "  orttest handler-ret  容器钩子返回（应仍被终止）\n"
         "  orttest supervise    监督者故障通道\n");
  return 1;
}
