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
 * 刻意极小：没有参数就读固定文件失败，有一参数读那一个文件。
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ORT_MAX_CONTENT 512

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

  return 0;
}
