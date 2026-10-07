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
 * 刻意极小：没有参数就读固定文件失败，有一参数读那一个文件。
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
#endif

  return 0;
}
