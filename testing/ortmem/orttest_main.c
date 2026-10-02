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

int main(int argc, FAR char *argv[])
{
  volatile uint32_t *own;
  volatile uint32_t *other;
  int domain = 0;
  int ok;

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
