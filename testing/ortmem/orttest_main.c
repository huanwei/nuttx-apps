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
#include <pthread.h>
#include <sys/prctl.h>

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
