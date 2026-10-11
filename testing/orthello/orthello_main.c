/****************************************************************************
 * testing/orthello/orthello_main.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1→A2] "镜像里的程序"——夹具角色：这个二进制会被打进镜像层
 * （fixture-gen 把 bin/orthello 嵌进 layer0 的 /bin/），运行时从
 * unionfs 挂载视图里 exec 出来，读一个镜像里的文件，把内容打印回去。
 *
 * 判据用法（手册 §三·补六十七）：
 *   nsh> /u/bin/orthello /u/etc/hello.txt
 *   ORTHELLO: from-image（就是本 ELF 从挂载视图被加载成功的证据）
 *   ORTHELLO: content=hello from layer1 (override)
 *   第二行是 **镜像里的程序读到镜像里的数据** 的闭环（-x 整行可判）。
 *
 * §70 起另印 env/cwd 两行（"照着 config 起进程"的回读判据）：
 *   经 `orting run` 跑 → env ORT_FIXTURE=1 + cwd=/u/tmp/ort/wd（被注入）；
 *   直接跑（对照臂）→ env ORT_FIXTURE=(无) + cwd=/（未注入）——
 *   两臂同形不同值，判据靠计数区分来源。
 *
 * §73 起第三个参数是**故障模式**（crash / udf / handler / crash-once，
 *   见 main 内注）——经侧配置（fixture-{crash,udf,handler,crash-once}
 *   .json，不走 digest 链）由 `orting run` 拉起，验证"容器崩、系统活"
 *   在镜像运行时路径上的闭环；§75 起 crash-once 供重启策略的恢复臂。
 *
 * §80 起另印 `res` 回读行（核集/优先级/所在 CPU 采样）—— 资源限制
 *   的判据面：`orting lim` 施加绑核+优先级后，这里回读核集掩码与
 *   优先级；未施加时 = 默认态（aff=0xf prio=100）作对照臂。
 *
 * 刻意极小：没有参数就读固定文件失败，有一参数读那一个文件。
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <fcntl.h>
#include <sched.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <errno.h>
#ifndef CONFIG_DISABLE_SIGNALS
#  include <signal.h>
#endif

#define ORT_MAX_CONTENT 512

#ifndef CONFIG_DISABLE_SIGNALS
/* §73：空 SIGSEGV 处理器 —— "逃法之一"（返回后重新执行故障指令） */
static void ort_sigsegv_handler(int signo)
{
  (void)signo;
}
#endif

int main(int argc, FAR char *argv[])
{
  printf("ORTHELLO: from-image\n");
  printf("ORTHELLO: argc=%d\n", argc);

  /* §70（A2）：环境与工作目录**回读**——"照着 config 起进程"的判据行。
   * 未设打印「(无)」：与"被注入"可整行区分（两臂同形不同值；
   * NuttX 的 cwd 就是 PWD 环境变量，getcwd 回读即运行时注入的见证）。 */

  {
    static char cwdbuf[128];
    FAR const char *v = getenv("ORT_FIXTURE");
    FAR char *cwd = getcwd(cwdbuf, sizeof(cwdbuf));

    printf("ORTHELLO: env ORT_FIXTURE=%s\n", v ? v : "(无)");
    printf("ORTHELLO: cwd=%s\n", cwd ? cwd : "(无)");
  }

  /* §86（A2 隔离）：容器 root 自报 + 逃逸探针 —— "隔离成立"的第一手
   * 判据（两行对两臂**不同形**才说明有分辨力）。
   *   root：经 `orting run` = 视图路径（内核按它重挂绝对路径）；
   *         直接跑（对照臂）=(无)。
   *   escape：/system/bin/init 是**宿主侧**文件（hostfs），容器视图里
   *         没有 —— rooted ⇒ 打不开；未 root ⇒ 读得到。 */

  {
    char rbuf[80];
    int rn = prctl(PR_GET_ORT_ROOT, rbuf, sizeof(rbuf));

    printf("ORTHELLO: root=%s\n", rn > 0 ? rbuf : "(无)");

    {
      FAR FILE *ef = fopen("/system/bin/init", "r");

      printf("ORTHELLO: escape=/system/bin/init:%s\n",
             ef != NULL ? "OK" : "打不开");

      if (ef != NULL)
        {
          fclose(ef);
        }
    }
  }

  /* §80（A2 资源限制）：**子进程看得见**的核集/优先级回读 + 所在 CPU
   * 采样 —— 运行时施加（lim：绑核 + 优先级），这里给出判据面。
   * 未施加时 = 默认态（aff=0xf 全核、prio=100）——天然对照臂。 */

  {
    cpu_set_t set;
    struct sched_param sp;
    uint32_t mask = 0;
    int i;

    if (sched_getaffinity(0, sizeof(set), &set) == 0)
      {
        for (i = 0; i < 32; i++)
          {
            if (CPU_ISSET(i, &set))
              {
                mask |= (1u << i);
              }
          }
      }

    if (sched_getparam(0, &sp) != 0)
      {
        sp.sched_priority = -1;
      }

    printf("ORTHELLO: res aff=0x%x prio=%d cpu=", (unsigned)mask,
           (int)sp.sched_priority);

    for (i = 0; i < 4; i++)
      {
        printf("%s%d", i ? "," : "", sched_getcpu());
        usleep(1000);
      }

    printf("\n");
  }

  if (argc >= 2)
    {
      FAR FILE *f = fopen(argv[1], "r");
      static char buf[ORT_MAX_CONTENT];

      if (f == NULL)
        {
          printf("ORTHELLO: open failed: %s\n", argv[1]);
          return 2;
        }

      {
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);

        buf[n] = '\0';

        /* 去掉行尾换行，让判据可以整行比对 */

        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
          {
            buf[--n] = '\0';
          }
      }

      fclose(f);
      printf("ORTHELLO: content=%s\n", buf);
    }

  /* §73：容器故障模式（argv[2]）——把"容器里的一个 bug"做成三种，
   * 全部经由**镜像运行时**（orting run + 侧配置）触发：
   *   crash    空指针写（data abort；无处理器 → 首次故障即死）
   *   udf      坏指令（Thumb UDF —— §37 那条"一条坏指令打停机"的路）
   *   handler  装 SIGSEGV 处理器且返回（§37 的"逃法之一" → 重新执行
   *            故障指令 → 第二次故障 → 内核升级 SIGKILL，打
   *            `ORT: escalating` 行）
   * 收容的终端形态（父进程所见）与"崩溃=exit(1) 不可分"的边界见 §73。
   * 正常模式（无第三参）不受影响。 */

  if (argc >= 3 && strcmp(argv[2], "crash") == 0)
    {
      FAR volatile unsigned *p = (FAR volatile unsigned *)0x10;

      *p = 0xbad;
      printf("ORTHELLO: crash 未发生（不该到这）\n");
    }
  else if (argc >= 3 && strcmp(argv[2], "udf") == 0)
    {
      __asm__ volatile (".inst 0xde00");   /* Thumb UDF #0 */
      printf("ORTHELLO: udf 未发生（不该到这）\n");
    }
  else if (argc >= 3 && strcmp(argv[2], "mem") == 0)
    {
      /* §81/§82：内存限额探针 —— 报堆区大小（mallinfo().arena 直读）+
       * 64KB 限内抽查 + **耗尽循环**（16KB 块 malloc 到失败）。
       *
       * ★ 耗尽循环曾是禁区：§81 实测 knsh 用户堆耗尽不走 ENOMEM 而撞
       *   sbrk/mm_extend 断言打停机（默认堆撞 arm_pgalloc.c:204、小堆
       *   撞 mm_extend.c:89）。§82 修 pgalloc（返回基地址契约 + 越界
       *   走 return 0）后，耗尽循环**应该优雅返回 NULL** —— 本行即是
       *   修复的验收判据。 */

      struct mallinfo mi = mallinfo();
      FAR void *p = malloc(64 * 1024);

      printf("ORTHELLO: mem arena=%u KB probe64=%s\n",
             (unsigned)(mi.arena / 1024), p ? "ok" : "fail");
      free(p);

      {
        size_t total = 0;
        int    chunks = 0;
        FAR void *first = NULL;
        FAR void *last = NULL;

        for (;;)
          {
            FAR void *q = malloc(16 * 1024);

            if (q == NULL || total > (8u * 1024 * 1024))
              {
                free(q);
                break;
              }

            if (first == NULL)
              {
                first = q;
              }

            last = q;
            total += 16 * 1024;
            chunks++;
          }

        printf("ORTHELLO: mem exhausted at %u KB（chunks=%d first=%p "
               "last=%p）\n", (unsigned)(total / 1024), chunks, first, last);
      }

      return 0;
    }
  else if (argc >= 3 && strcmp(argv[2], "crash-once") == 0)
    {
      /* §75：**首跑崩、次跑好** —— 重启策略的"恢复"臂。标记用**相对
       * 路径**（PWD 解析 → 落在视图工作目录，跨次 spawn 保留在 upper
       * 层）——顺带把 §70 的 PWD 相对解析从源码结论变成实跑。 */

      FAR FILE *m = fopen("crashed.once", "r");

      if (m != NULL)
        {
          fclose(m);
          printf("ORTHELLO: 第二次机会（标记在）→ 正常退出\n");
        }
      else
        {
          m = fopen("crashed.once", "w");
          if (m != NULL)
            {
              fputs("boom\n", m);
              fclose(m);
            }

          printf("ORTHELLO: 首次运行 → 建标记并崩溃\n");

          {
            FAR volatile unsigned *p = (FAR volatile unsigned *)0x10;

            *p = 0xbad;
          }

          printf("ORTHELLO: crash-once 未发生（不该到这）\n");
        }
    }
#ifndef CONFIG_DISABLE_SIGNALS
  else if (argc >= 3 && strcmp(argv[2], "handler") == 0)
    {
      struct sigaction sa;

      memset(&sa, 0, sizeof(sa));
      sa.sa_handler = ort_sigsegv_handler;
      sigaction(SIGSEGV, &sa, NULL);

      {
        FAR volatile unsigned *p = (FAR volatile unsigned *)0x10;

        *p = 0xbad;
      }

      printf("ORTHELLO: handler 逃法后未被打死（不该到这）\n");
    }
  else if (argc >= 3 && strcmp(argv[2], "sigprobe") == 0)
    {
      /* §87 信号面隔离探针：三条 `kill(pid, 0)`（**不发真信号**的
       * 存在性/权限探针）——
       *   init：pid 1（恒存在，内核静态任务）；
       *   sup ：监督者 pid，经 env ORT_SUP_PID 注入（`orting run` 加）；
       *   self：getpid()（自己组 —— 闸必须放行的正臂）。
       * 判据 = **两臂不同形**：容器（rooted）⇒ init/sup 应为 EPERM、
       * self OK；未 root（nsh 直 exec 对照臂）⇒ init OK。
       * 权限判定读 errno —— 每次 kill 后**立刻**取。 */

      FAR const char *sup = getenv("ORT_SUP_PID");
      int ri = kill(1, 0);
      int ei = errno;
      int rs = sup != NULL ? kill(atoi(sup), 0) : -4242;
      int es = errno;
      int rp = kill(getpid(), 0);
      int ep = errno;

      printf("ORTHELLO: sigprobe init=%s sup=%s self=%s\n",
             ri == 0 ? "OK" : (ri < 0 && ei == EPERM ? "EPERM" : "ERR"),
             rs == -4242 ? "n/a"
                         : (rs == 0 ? "OK"
                                    : (rs < 0 && es == EPERM ? "EPERM"
                                                             : "ERR")),
             rp == 0 ? "OK" : (rp < 0 && ep == EPERM ? "EPERM" : "ERR"));
    }
#endif

  else if (argc >= 3 && strcmp(argv[2], "schedprobe") == 0)
    {
      /* §96③ pid 面隔离探针：调度面两条**回写原值**的定向探针
       * （即便闸漏了也不改变局面 —— 零副作用）：
       *   aff1：sched_setaffinity(1, 读回的当前核集) —— 跨组应 EPERM
       *   par1：sched_setparam(1, 读回的当前优先级)   —— 跨组应 EPERM
       *   self：sched_setaffinity(getpid(), 读回核集) —— 正臂应 OK
       * 判据 = 两臂不同形：容器（rooted）⇒ aff1/par1 EPERM；
       * 未 root（nsh 直 exec 对照臂）⇒ 全 OK（施加面确实在别处可用，
       * 闸才有分辨力）。权限判定读 errno —— 每次调用后立刻取。 */

      cpu_set_t set;
      struct sched_param sp;
      int ra = -1, ea = 0, rp2 = -1, ep2 = 0, rsf = -1, esf = 0;

      /* 跨组目标 = getppid()：容器臂里是 orting（监督者，别组）；
       * 对照臂里是 nsh（普通任务）。**不用 pid 1** —— init 是
       * CPU-locked 特殊任务，施加面本身就会 EINVAL（第一版踩过，
       * 对照臂假 ERR）。 */

      /* [§98] 跨组目标：容器臂用 ORT_SUP_PID 注入的**全局**监督者号
       * （getppid 在容器内已按 pid 视图返回 0=自指的坑，§98 踩过）；
       * 对照臂（nsh 直 exec）无注入 → getppid()=nsh（普通任务）✓。 */

      {
        FAR const char *sup = getenv("ORT_SUP_PID");
        pid_t tgt = sup != NULL ? (pid_t)atoi(sup) : getppid();

        if (sched_getaffinity(tgt, sizeof(set), &set) == 0)
          {
            ra = sched_setaffinity(tgt, sizeof(set), &set);
            ea = errno;
          }

        if (sched_getparam(tgt, &sp) == 0)
          {
            rp2 = sched_setparam(tgt, &sp);
            ep2 = errno;
          }
      }

      if (sched_getaffinity(getpid(), sizeof(set), &set) == 0)
        {
          rsf = sched_setaffinity(getpid(), sizeof(set), &set);
          esf = errno;
        }

      printf("ORTHELLO: schedprobe affp=%s parp=%s self=%s\n",
             ra == 0 ? "OK" : (ra < 0 && ea == EPERM ? "EPERM" : "ERR"),
             rp2 == 0 ? "OK" : (rp2 < 0 && ep2 == EPERM ? "EPERM" : "ERR"),
             rsf == 0 ? "OK" : (rsf < 0 && esf == EPERM ? "EPERM" : "ERR"));
    }


  else if (argc >= 3 && strcmp(argv[2], "pidprobe") == 0)
    {
      /* §98 pid 视图第一刀（自省面）：容器内 getpid/getppid 应为
       * **本地号**（entrypoint=1；父在命名空间外 ⇒ 0）；kill(1,0)
       * 按**本地号优先**解析（= 本地 1 = 自己）应 OK。对照臂（nsh
       * 直 exec）全全局语义（me/pp 都是全局号；kill(1,0)=真 init）。 */

      pid_t me = getpid();
      pid_t pp = getppid();
      int k1 = kill(1, 0);
      int e1 = errno;
      int ks = kill(me, 0);
      int es = errno;

      printf("ORTHELLO: pidprobe me=%d pp=%d k1=%s kself=%s\n",
             (int)me, (int)pp,
             k1 == 0 ? "OK" : (k1 < 0 && e1 == EPERM ? "EPERM" : "ERR"),
             ks == 0 ? "OK" : (ks < 0 && es == EPERM ? "EPERM" : "ERR"));
    }

  else if (argc >= 3 && strcmp(argv[2], "selfid") == 0)
    {
      /* §99（pid 第二刀）子视角探针：读自己的 getpid/getppid 后**以 7
       * 退出** —— 父侧 waitpid 回读的是"本地号子进程 + 退出码"两个面。
       * 容器臂应 me=2 pp=1（子本地号/父本地号）；对照臂全全局号。 */

      printf("ORTHELLO: selfid me=%d pp=%d\n",
             (int)getpid(), (int)getppid());
      return 7;
    }

  else if (argc >= 3 && strcmp(argv[2], "devprobe") == 0)
    {
      /* §101 设备面第一刀（devacl）：开三个设备节点并报告 ——
       *   容器臂（rooted，经 orting run）：绝对路径被重挂 ⇒ 全"打不开"
       *     （路径层已挡；对象层闸在解析阶段之前就 ENOENT 了）；
       *   对照臂（nsh 直 exec）：全 OK（闸对非容器不设防）。
       * 两臂同形不同值 ⇒ 有分辨力。O_RDONLY 即可（不需要写权）。 */

      static const FAR char *devs[3] =
        {
          "/dev/console", "/dev/null", "/dev/zero"
        };

      char rdir[3][16];
      int fd;
      int i;

      for (i = 0; i < 3; i++)
        {
          fd = open(devs[i], O_RDONLY);
          if (fd >= 0)
            {
              close(fd);
              strlcpy(rdir[i], "OK", sizeof(rdir[i]));
            }
          else if (errno == EPERM)
            {
              strlcpy(rdir[i], "EPERM", sizeof(rdir[i]));
            }
          else
            {
              strlcpy(rdir[i], "打不开", sizeof(rdir[i]));
            }
        }

      printf("ORTHELLO: devprobe console=%s null=%s zero=%s\n",
             rdir[0], rdir[1], rdir[2]);
    }

  else if (argc >= 3 && strcmp(argv[2], "pidprobe2") == 0)
    {
      /* §99 pid 命名空间第二刀（进程管理号面）：
       *   ① spawn 回传号：本进程（容器 entrypoint=本地 1）posix_spawn
       *      拿到的应是**本地号**（2）；对照臂=全局号；
       *   ② waitpid 入口号：waitpid(上面那个号) 必须能解析到真子；
       *   ③ 回收号回传：waited 应与 child 同号（容器=2）；
       *   ④ waitpid(-1)：再起一个、任收一路 —— 回收号也要本地化（3）；
       *   ⑤ 子自视角：子（selfid 模式）自报 me/pp —— 容器=2/1。
       * 路径用 argv[0]（容器臂=/bin/orthello 经内核重挂；对照臂=
       * /u/bin/orthello 直路径）—— 两臂同代码不同世界。 */

      FAR char *cargv[4];
      int r1, r2;
      int st1 = 0, st2 = 0;
      pid_t me = getpid();
      pid_t c1 = -1, c2 = -1, w1 = -1, w2 = -1;

      cargv[0] = argv[0];
      cargv[1] = argv[1] != NULL ? argv[1] : "/etc/hello.txt";
      cargv[2] = "selfid";
      cargv[3] = NULL;

      r1 = posix_spawn(&c1, argv[0], NULL, NULL, cargv, environ);
      printf("ORTHELLO: pid2 me=%d child=%d r1=%d\n", (int)me, (int)c1, r1);

      w1 = waitpid(c1, &st1, 0);
      printf("ORTHELLO: pid2 waited=%d stat=%d\n",
             (int)w1, WIFEXITED(st1) ? WEXITSTATUS(st1) : -1);

      r2 = posix_spawn(&c2, argv[0], NULL, NULL, cargv, environ);

      w2 = waitpid(-1, &st2, 0);
      printf("ORTHELLO: pid2 any=%d stat=%d c2=%d r2=%d\n",
             (int)w2, WIFEXITED(st2) ? WEXITSTATUS(st2) : -1,
             (int)c2, r2);
    }

  return 0;
}
