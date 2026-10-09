/****************************************************************************
 * testing/ortimg/ortimg_main.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * [ORT-A / A1] ort_image 的第一块砖：受限 JSON + OCI manifest 提取。
 * 用法（nsh）：
 *   orting jsontest              —— 跑双环境电池（与宿主机同一份）
 *   orting manifest <path>       —— 解析一份真实 manifest 并打印字段
 *   orting config <path>         —— 解析 OCI image config（⑧ 落盘件的独立复读）
 *   orting run <view> <config>   —— 照着 config 起进程（Entrypoint+Env+WorkingDir）
 *   orting up <view> <host> <port> <repo> <tag>
 *                                —— 自动动线：pull → 组装 → 挂载视图（一条命令）
 *   orting start <view> <host> <port> <repo> <tag>
 *                                —— up + run：镜像到进程一条命令
 *   orting sup <view> <cfg1> [cfg2 ...]
 *                                —— 运行时兼任监督者：崩没崩的正面判别
 *   orting par <view> <cfg1> [cfg2 ...]
 *                                —— 并发容器：事件队列逐条配对压力
 *   orting supd <秒>             —— 长驻监督者：与派生者解耦的旁路观测
 *   orting orch <秒> <view> <cfg1> [cfg2 ...]
 *                                —— 多服务编排环：wait-any + 个体策略
 *   orting lim <view> <cpu-list> <prio> <cfg1> [cfg2 ...]
 *                                —— 资源限制：核集 + 优先级（fail-closed）
 *   orting memcap <view> <KB> <cfg1> [cfg2 ...]
 *                                —— 资源限制：派生进程堆上限（组级，无竞态）
 *   orting down <view>           —— 卸载视图（生命周期收尾）
 *   orting validate <path>       —— 通用 JSON 校验（只报错名）
 *
 * 目标机上 /system 是 hostfs（宿主 nuttx-apps 树），所以夹具直接用
 * 仓库里的路径：/system/testing/ortimg/fixtures/xxx.json
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sched.h>
#include <time.h>

#include "ort_json.h"
#include "ortimg_battery.h"
#include "ort_http.h"
#include "ort_sha256.h"
#include "ort_tar.h"

/* [ORT §91] TLS 起步：mbedTLS 客户端（apps/crypto/mbedtls；熵源经其
 * getrandom 补丁，X509 CRT 池补丁随源就位——链校验本轮**未开**，
 * 见 do_httpsget 的边界注） */
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/version.h>

#define ORTIMG_MAX_FILE  (ORT_JSON_MAX_INPUT + 1)

/* 镜像存储根：设计文档写 /var/ort/images —— 本板 /var 无挂载，tmpfs 在
 * /tmp（qemu_bringup 挂），故用 /tmp/ort 做根；产品化时由 init 把持久
 * 存储挂到 /var，路径前缀随挂载点平移（手册 §三·补六十三 边界）。 */
#define ORT_STORE_ROOT   "/tmp/ort"

/* 单层体上限（prototype 防线：tmpfs 在 RAM，别让一张大 manifest 抽干内存） */
#define ORT_BLOB_MAX     (64 * 1024 * 1024)

static FAR char *g_buf;

/* ★ 大件全静态：app 栈只有 4KB（CONFIG_TESTING_ORTIMG_STACKSIZE），
 *   16KB 响应体和 index(32 条)/manifest(16 层) 结构都放不进栈。 */

static char g_http_body[16384];
static char g_http_body2[16384];
static char g_token[4096];
static struct ort_index_s    g_idx;
static struct ort_manifest_s g_mf;
static struct ort_config_s   g_cfg;   /* ⑧ 配置体（~2.5KB，同样不放进栈） */

static int read_file(FAR const char *path, FAR size_t *out_len)
{
  FAR FILE *f = fopen(path, "rb");
  size_t n;

  if (f == NULL)
    {
      printf("[ortimg] 打不开 %s\n", path);
      return -1;
    }

  n = fread(g_buf, 1, ORT_JSON_MAX_INPUT, f);
  fclose(f);

  if (n >= ORT_JSON_MAX_INPUT)
    {
      /* 注：>= 是保守写法 —— 可能正好读完也可能还有；manifest 现实尺寸
       * 是 KB 级，读满 64KB 本身就是"这不像是 manifest" */
    }

  *out_len = n;
  g_buf[n] = '\0';
  return 0;
}

/* ── 小工具 ───────────────────────────────────────────────────────── */

static int mkdir_p(FAR const char *path)
{
  static char tmp[320];
  size_t i;

  if (strlen(path) >= sizeof(tmp))
    {
      return -1;
    }

  strlcpy(tmp, path, sizeof(tmp));

  for (i = 1; tmp[i] != '\0'; i++)
    {
      if (tmp[i] == '/')
        {
          tmp[i] = '\0';
          if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
            {
              return -1;
            }

          tmp[i] = '/';
        }
    }

  if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
    {
      return -1;
    }

  return 0;
}

/* ── SHA-256 电池 / 单文件摘要 ─────────────────────────────────────── */

static int do_sha(FAR const char *path)
{
  static char   buf[4096];        /* ★ 静态：目标机 app 栈预算 */
  FAR FILE     *f = fopen(path, "rb");
  struct ort_sha256_s c;
  uint8_t raw[32];
  char    hex[65];
  size_t  n;
  size_t  tot = 0;

  if (f == NULL)
    {
      printf("[ortimg] 打不开 %s\n", path);
      return 2;
    }

  ort_sha256_init(&c);
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    {
      ort_sha256_update(&c, buf, n);
      tot += n;
    }

  ort_sha256_final(&c, raw);
  ort_sha256_hex(raw, hex);

  printf("[ortimg] sha256 %s\n", path);
  printf("[ortimg]   = %s（%zu 字节）\n", hex, tot);

  /* ★ seek 复验（§67 排查用）：回卷后重读一遍再哈希。两次不一致 =
   * 该文件系统的 seek/重读语义不可靠（unionfs 的 ELF 装载故障即此类）。 */

  if (fseek(f, 0, SEEK_SET) == 0)
    {
      ort_sha256_init(&c);
      tot = 0;
      while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        {
          ort_sha256_update(&c, buf, n);
          tot += n;
        }

      ort_sha256_final(&c, raw);
      ort_sha256_hex(raw, hex);
      printf("[ortimg]   = %s（seek 重读，%zu 字节）\n", hex, tot);
    }
  else
    {
      printf("[ortimg]   = seek 不支持（errno=%d）\n", errno);
    }

  fclose(f);
  return 0;
}

/* ── 层体应用（tar → 目录，OCI 覆盖/whiteout 语义）─────────────────── *
 *
 * 受限递归的路径池：深度 ≤ 8，**每层独立静态缓冲**（递归的各级不互踩，
 * 也不吃目标机那点栈 —— 踩过 4KB 栈的坑，见 §61 注）。
 */

#define ORT_DEPTH_MAX 8
static char g_pfull[ORT_DEPTH_MAX][384];
static char g_prel[ORT_DEPTH_MAX][320];

/* 删除文件/整棵子树（whiteout 用；ENOENT 当成功——白掉不存在的名字
 * 是合法的）。 */

static int rm_subtree(FAR const char *path, int depth)
{
  struct stat st;

  if (depth >= ORT_DEPTH_MAX)
    {
      return -1;
    }

  if (stat(path, &st) != 0)
    {
      return (errno == ENOENT) ? 0 : -1;
    }

  if (S_ISDIR(st.st_mode))
    {
      FAR DIR *d = opendir(path);
      FAR struct dirent *de;
      FAR char *child = g_pfull[depth];

      if (d == NULL)
        {
          return -1;
        }

      while ((de = readdir(d)) != NULL)
        {
          if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            {
              continue;
            }

          snprintf(child, sizeof(g_pfull[0]), "%s/%s", path, de->d_name);
          if (rm_subtree(child, depth + 1) != 0)
            {
              closedir(d);
              return -1;
            }
        }

      closedir(d);
      return rmdir(path);
    }

  return unlink(path);
}

struct tapply_s
{
  FAR const char *dest;
  uint32_t        nent;
  int             err;
  FAR const char *errmsg;
};

static int rm_children(FAR const char *dir);

/* 拼路径 + 显式截断检查（"静默截断"是本项目的大忌，宁可 fail-closed） */

#define SPATH_OR_FAIL(...) \
  do { \
    if (snprintf(path, sizeof(path), __VA_ARGS__) >= (int)sizeof(path)) \
      { \
        a->err = 6; \
        a->errmsg = "路径过长"; \
        return -1; \
      } \
  } while (0)

static int apply_sink(FAR void *arg, FAR const struct ort_tar_entry_s *e,
                      FAR struct ort_tar_src_s *src)
{
  FAR struct tapply_s *a = (FAR struct tapply_s *)arg;
  static char path[384];
  FAR const char *base;
  int fd;

  a->nent++;

  base = strrchr(e->name, '/');
  base = (base != NULL) ? base + 1 : e->name;

  /* whiteout：.wh.<name> 删目标、自身不落盘；.wh..wh..opq 清空本目录
   * 现有内容（目录保留）。注：opq 按"遇到才清"，与同层先应用的条目
   * 的相对顺序语义有细微出入（tar 顺序通常把 opq 排前）——如实标注。 */

  if (strncmp(base, ".wh.", 4) == 0)
    {
      if (strcmp(base, ".wh..wh..opq") == 0)
        {
          size_t dl = (size_t)(base - e->name);   /* "dir/" 前缀长度（可 0） */

          if (dl >= 1)
            {
              SPATH_OR_FAIL("%s/%.*s", a->dest, (int)dl - 1, e->name);
            }
          else
            {
              SPATH_OR_FAIL("%s", a->dest);
            }

          if (rm_children(path) != 0)
            {
              a->err = 4;
              a->errmsg = "opaque 清理失败";
              return -1;
            }
        }
      else if (base == e->name)
        {
          SPATH_OR_FAIL("%s/%s", a->dest, base + 4);
          if (rm_subtree(path, 0) != 0)
            {
              a->err = 5;
              a->errmsg = "whiteout 删除失败";
              return -1;
            }
        }
      else
        {
          SPATH_OR_FAIL("%s/%.*s%s", a->dest,
                        (int)(base - e->name), e->name, base + 4);
          if (rm_subtree(path, 0) != 0)
            {
              a->err = 5;
              a->errmsg = "whiteout 删除失败";
              return -1;
            }
        }

      return 0;
    }

  SPATH_OR_FAIL("%s/%s", a->dest, e->name);

  if (e->typeflag == '5')
    {
      if (mkdir_p(path) != 0)
        {
          a->err = 1;
          a->errmsg = "建目录失败";
          return -1;
        }

      return 0;
    }

  /* 普通文件：先保父目录。注意 path 已被上面写过，父目录用 e->name 算。 */

  if (base != e->name)
    {
      static char pdir[384];

      if (snprintf(pdir, sizeof(pdir), "%s/%.*s", a->dest,
                   (int)(base - e->name) - 1, e->name) >= (int)sizeof(pdir))
        {
          a->err = 6;
          a->errmsg = "父路径过长";
          return -1;
        }

      if (mkdir_p(pdir) != 0)
        {
          a->err = 1;
          a->errmsg = "建父目录失败";
          return -1;
        }
    }

  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC,
            (e->mode & 0777) != 0 ? (e->mode & 0777) : 0644);
  if (fd < 0)
    {
      a->err = 2;
      a->errmsg = "建文件失败";
      return -1;
    }

  {
    static char buf[4096];
    uint64_t left = e->size;

    while (left > 0)
      {
        size_t want = (left < sizeof(buf)) ? (size_t)left : sizeof(buf);
        int got = src->read(src->arg, buf, want);
        ssize_t wr;

        if (got <= 0)
          {
            close(fd);
            a->err = 3;
            a->errmsg = "层体数据提前结束";
            return -1;
          }

        wr = write(fd, buf, (size_t)got);
        if (wr < 0 || wr != got)
          {
            close(fd);
            a->err = 3;
            a->errmsg = "落盘失败";
            return -1;
          }

        left -= (uint64_t)got;
      }
  }

  close(fd);
  return 0;
}

/* 清一个目录下的全部内容（不删目录本身）—— opaque 用 */

static int rm_children(FAR const char *dir)
{
  FAR DIR *d = opendir(dir);
  FAR struct dirent *de;

  if (d == NULL)
    {
      return (errno == ENOENT) ? 0 : -1;
    }

  while ((de = readdir(d)) != NULL)
    {
      if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
        {
          continue;
        }

      snprintf(g_pfull[0], sizeof(g_pfull[0]), "%s/%s", dir, de->d_name);
      if (rm_subtree(g_pfull[0], 1) != 0)
        {
          closedir(d);
          return -1;
        }
    }

  closedir(d);
  return 0;
}

static int do_tar_apply(FAR const char *archive, FAR const char *dest)
{
  static struct tapply_s a;
  FAR FILE *f;
  uint32_t nent = 0;
  int ret;

  if (mkdir_p(dest) != 0)
    {
      printf("[ortimg] untar: 建目标目录失败 %s\n", dest);
      return 2;
    }

  f = fopen(archive, "rb");
  if (f == NULL)
    {
      printf("[ortimg] untar: 打不开 %s（errno=%d）\n", archive, errno);
      return 2;
    }

  memset(&a, 0, sizeof(a));
  a.dest = dest;
  ret = ort_tar_walk(f, apply_sink, &a, &nent);
  fclose(f);

  if (ret != ORT_TAR_OK)
    {
      printf("[ortimg] untar FAIL: %s（已处理 %u 条目%s%s）\n",
             ort_tar_strerror(ret), (unsigned)nent,
             a.errmsg ? "，sink: " : "", a.errmsg ? a.errmsg : "");
      return 1;
    }

  printf("[ortimg] untar OK: %u 条目 → %s\n", (unsigned)nent, dest);
  return 0;
}

/* ── rootfs 清单（双环境逐字比较用）───────────────────────────────── *
 * 格式：<相对路径> <大小> <sha256>
 * 顺序规则：每层目录按名字字节序、遇到先序输出 —— 宿主 python 参考实现
 * 用同一规则（见 proposals/scripts/ort-rootfs-ref.py）。 */

static int file_hash_print(FAR FILE *out, FAR const char *full,
                           FAR const char *rel)
{
  static char buf[4096];
  struct ort_sha256_s c;
  uint8_t raw[32];
  char    hex[65];
  FAR FILE *f = fopen(full, "rb");
  size_t  n;
  size_t  tot = 0;

  if (f == NULL)
    {
      fprintf(out, "%s ??? 打不开（errno=%d）\n", rel, errno);
      return -1;
    }

  ort_sha256_init(&c);
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    {
      ort_sha256_update(&c, buf, n);
      tot += n;
    }

  fclose(f);
  ort_sha256_final(&c, raw);
  ort_sha256_hex(raw, hex);

  fprintf(out, "%s %zu %s\n", rel, tot, hex);
  return 0;
}

static int lsroot_walk(FAR FILE *out, FAR const char *full, FAR const char *rel,
                       int depth, FAR size_t *nfiles)
{
  char last[128] = "";

  for (;;)
    {
      FAR DIR *d = opendir(full);
      FAR struct dirent *de;
      char best[128] = "";

      if (d == NULL)
        {
          return -1;
        }

      /* 每轮找"比 last 大的最小名字"——目录小，多扫几遍换零分配/零排序 */

      while ((de = readdir(d)) != NULL)
        {
          if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            {
              continue;
            }

          if (strcmp(de->d_name, last) <= 0)
            {
              continue;
            }

          if (best[0] == '\0' || strcmp(de->d_name, best) < 0)
            {
              strncpy(best, de->d_name, sizeof(best) - 1);
              best[sizeof(best) - 1] = '\0';
            }
        }

      closedir(d);

      if (best[0] == '\0')
        {
          return 0;
        }

      if (depth >= ORT_DEPTH_MAX)
        {
          return -2;
        }

      {
        FAR char *full2 = g_pfull[depth];
        FAR char *rel2  = g_prel[depth];
        struct stat st;

        snprintf(full2, sizeof(g_pfull[0]), "%s/%s", full, best);
        if (rel[0] != '\0')
          {
            snprintf(rel2, sizeof(g_prel[0]), "%s/%s", rel, best);
          }
        else
          {
            snprintf(rel2, sizeof(g_prel[0]), "%s", best);
          }

        if (stat(full2, &st) != 0)
          {
            return -1;
          }

        if (S_ISDIR(st.st_mode))
          {
            int rr = lsroot_walk(out, full2, rel2, depth + 1, nfiles);

            if (rr != 0)
              {
                return rr;
              }
          }
        else
          {
            if (file_hash_print(out, full2, rel2) != 0)
              {
                return -1;
              }

            (*nfiles)++;
          }
      }

      strncpy(last, best, sizeof(last) - 1);
      last[sizeof(last) - 1] = '\0';
    }
}

static int do_lsroot(FAR const char *root)
{
  size_t nf = 0;
  int ret = lsroot_walk(stdout, root, "", 0, &nf);

  if (ret != 0)
    {
      printf("[ortimg] LSROOT FAIL（%d，errno=%d）: %s\n", ret, errno, root);
      return 1;
    }

  printf("[ortimg] lsroot: %zu 个文件\n", nf);
  return 0;
}

static int do_manifest(FAR const char *path)
{
  FAR struct ort_manifest_s *mf = &g_mf;   /* ★ 静态（栈 ~2KB，见 do_pull 注） */
  size_t len = 0;
  int ret;
  uint32_t i;

  if (read_file(path, &len) != 0)
    {
      return 2;
    }

  ret = ort_manifest_parse(g_buf, len, mf);
  if (ret != ORT_JSON_OK)
    {
      printf("[ortimg] manifest 拒绝: %s（%zu 字节）\n",
             ort_json_strerror(ret), len);
      return 1;
    }

  printf("[ortimg] manifest OK（%zu 字节）\n", len);
  printf("[ortimg]   schemaVersion=%u mediaType=%s\n",
         (unsigned)mf->schema_version,
         mf->media_type[0] ? mf->media_type : "(缺省)");
  printf("[ortimg]   config: %s size=%llu\n",
         mf->config_digest, (unsigned long long)mf->config_size);
  printf("[ortimg]   层数=%u（白名单外字段跳过 %u 个）\n",
         (unsigned)mf->nlayers, (unsigned)mf->ignored_fields);
  for (i = 0; i < mf->nlayers && i < 3; i++)
    {
      printf("[ortimg]   layer[%u]: %s size=%llu\n", (unsigned)i,
             mf->layers[i].digest, (unsigned long long)mf->layers[i].size);
    }
  return 0;
}

/* 运行参数摘要打印：pull ⑧（下载即解析）与 `orting config`（对同一份落
 * 盘件的独立复读）共用同一条输出 —— 两处见证口径逐字相同，判据才好对拍
 * （同 §63 哈希通道的思路：同一事实两条独立通道）。 */

static void config_dump(FAR FILE *out, FAR const char *head,
                        FAR const char *cont,
                        FAR const struct ort_config_s *cf)
{
  uint32_t i;

  fprintf(out, "%sconfig: arch=%s os=%s 入口=%u 命令=%u 环境=%u "
               "workdir=%s（跳过未知 %u）\n",
          head, cf->arch, cf->os, (unsigned)cf->nentrypoint,
          (unsigned)cf->ncmd, (unsigned)cf->nenv,
          cf->workdir[0] ? cf->workdir : "(无)",
          (unsigned)cf->ignored_fields);

  for (i = 0; i < cf->nentrypoint; i++)
    {
      fprintf(out, "%sentrypoint[%u]=%s\n", cont, (unsigned)i,
              cf->entrypoint[i]);
    }

  for (i = 0; i < cf->ncmd; i++)
    {
      fprintf(out, "%scmd[%u]=%s\n", cont, (unsigned)i, cf->cmd[i]);
    }

  for (i = 0; i < cf->nenv; i++)
    {
      fprintf(out, "%senv[%u]=%s\n", cont, (unsigned)i, cf->env[i]);
    }
}

static int do_config(FAR const char *path)
{
  size_t len = 0;
  int ret;

  if (read_file(path, &len) != 0)
    {
      return 2;
    }

  ret = ort_config_parse(g_buf, len, &g_cfg);
  if (ret != ORT_JSON_OK)
    {
      printf("[ortimg] config 拒绝: %s（%zu 字节）\n",
             ort_json_strerror(ret), len);
      return 1;
    }

  printf("[ortimg] config 解析 OK（%zu 字节）\n", len);
  config_dump(stdout, "[ortimg] ", "[ortimg]   ", &g_cfg);
  return 0;
}

/* ── 照着 config 起进程（A2 增量①）────────────────────────────────── *
 *
 * 原型期的"容器内路径"映射：**绝对路径** → <view>+<path>（argv 与
 * WorkingDir 统一按此映射；真解是 chroot/命名空间 —— A2 后续）。相对
 * 路径原样传参，由子进程按 PWD 解析。
 *
 * 环境：子环境 = **config Env + 运行时 PWD**。内核 binfmt 的语义
 * （binfmt_execmodule.c：envp!=NULL 时子环境就是 envp 本尊）决定了
 * **父亲环境不会漏进子进程** —— 这正是容器要的"干净环境"。config
 * 自带的 PWD= 被过滤：WorkingDir 由运行时说了算（PWD 唯一）。
 *
 * WorkingDir 走 PWD 环境通道的依据（NuttX 源码）：chdir() 写
 * setenv("PWD")、getcwd() 读 getenv("PWD")、相对路径解析在
 * fs/inodesearch 读 PWD —— cwd 就是环境变量本身；NuttX 的 spawn
 * 文件动作**没有** addchdir，这是唯一的正道。
 */

#define ORT_RUN_MAP_MAX 320

static char g_spawnpath[ORT_RUN_MAP_MAX];   /* [§86] exec 文件路径（视图映射） */
static FAR char *g_argv[2 * ORT_CFG_MAX_ARG + 1];
static char g_pwdbuf[ORT_RUN_MAP_MAX + 64];
static char g_supbuf[64];                   /* [§87] ORT_SUP_PID=… */
static FAR char *g_envp[ORT_CFG_MAX_ENV + 3];

static int map_path(FAR const char *view, FAR const char *in,
                    FAR char *out, size_t cap)
{
  if (in[0] != '/' || strcmp(view, "/") == 0)
    {
      if (strlen(in) + 1 > cap)
        {
          return -1;
        }

      strcpy(out, in);
      return 0;
    }

  if (snprintf(out, cap, "%s%s", view, in) >= (int)cap)
    {
      return -1;
    }

  return 0;
}

/* run 的"派生半"：视图先验 → 配置解析 → argv/环境/工作目录 → spawn。
 * do_run（wait + 报退出码）与 do_sup（绑域 + 抽事件队列 + 判别）共用
 * —— §74 拆分，行为不变。§80 起带 attr 变体（lim 用：优先级经
 * posix_spawnattr 施加）。 */

static int run_spawn_ex(FAR const char *view, FAR const char *path,
                        FAR const posix_spawnattr_t *attr,
                        FAR pid_t *outpid)
{
  struct stat vst;
  size_t len = 0;
  uint32_t i;
  int    na = 0;
  int    ne = 0;
  pid_t  pid;
  int    ret;

  /* 视图先验：根不成立就什么都不建、不拉（fail-closed） */

  if (stat(view, &vst) != 0)
    {
      printf("[run] 视图打不开: %s（errno=%d）\n", view, errno);
      return 1;
    }

  if (!S_ISDIR(vst.st_mode))
    {
      printf("[run] 视图不是目录: %s\n", view);
      return 1;
    }

  if (read_file(path, &len) != 0)
    {
      return 2;
    }

  ret = ort_config_parse(g_buf, len, &g_cfg);
  if (ret != ORT_JSON_OK)
    {
      printf("[run] 配置拒绝: %s（%zu 字节）\n", ort_json_strerror(ret), len);
      return 1;
    }

  /* argv := entrypoint + cmd（OCI 语义）。[§86] argv **原样**（自然
   * 路径）—— 绝对路径由内核按容器 root（下方 PR_SET_ORT_ROOT）重挂；
   * 只有 exec 文件路径（= 视图映射的 entrypoint[0]）留给 spawn。 */

  for (i = 0; i < g_cfg.nentrypoint; i++)
    {
      g_argv[na++] = g_cfg.entrypoint[i];
    }

  for (i = 0; i < g_cfg.ncmd; i++)
    {
      g_argv[na++] = g_cfg.cmd[i];
    }

  if (na == 0)
    {
      printf("[run] 无 argv（解析已保证不会发生）\n");
      return 1;
    }

  g_argv[na] = NULL;

  if (map_path(view, g_cfg.entrypoint[0], g_spawnpath,
               sizeof(g_spawnpath)) != 0)
    {
      printf("[run] exec 路径映射超界（entrypoint[0]）\n");
      return 1;
    }

  /* 环境：config Env（滤掉 PWD=）+ 运行时 PWD */

  for (i = 0; i < g_cfg.nenv; i++)
    {
      if (strncmp(g_cfg.env[i], "PWD=", 4) == 0)
        {
          continue;
        }

      g_envp[ne++] = g_cfg.env[i];
    }

  if (g_cfg.workdir[0])
    {
      static char wdbuf[ORT_RUN_MAP_MAX];

      if (map_path(view, g_cfg.workdir, wdbuf, sizeof(wdbuf)) != 0)
        {
          printf("[run] workdir 映射超界: %s\n", g_cfg.workdir);
          return 1;
        }

      if (mkdir_p(wdbuf) != 0)
        {
          printf("[run] workdir 建点失败: %s（errno=%d）\n", wdbuf, errno);
          return 1;
        }

      printf("[run] workdir 就绪: %s\n", wdbuf);

      /* [§86] PWD 给**自然路径**：子进程（容器 root 已挂）自己解析；
       * 落点建目录仍用上面的映射路径（本进程未重挂）。 */

      snprintf(g_pwdbuf, sizeof(g_pwdbuf), "PWD=%s", g_cfg.workdir);
      g_envp[ne++] = g_pwdbuf;
    }

  /* [ORT §87] 监督者 pid 注入（信号面判据用）：容器闸生效后它也只能
   * "看"这个 pid —— 注入不扩大权限面。 */

  snprintf(g_supbuf, sizeof(g_supbuf), "ORT_SUP_PID=%d", (int)getpid());
  g_envp[ne++] = g_supbuf;

  g_envp[ne] = NULL;

  printf("[run] view=%s 配置 arch=%s os=%s（入口 %u/命令 %u/环境 %u）\n",
         view, g_cfg.arch, g_cfg.os, (unsigned)g_cfg.nentrypoint,
         (unsigned)g_cfg.ncmd, (unsigned)g_cfg.nenv);

  for (i = 0; i < (uint32_t)na; i++)
    {
      printf("[run] argv[%u]=%s\n", (unsigned)i, g_argv[i]);
    }

  printf("[run] 环境 %d 条，PWD=%s\n", ne,
         g_cfg.workdir[0] ? g_pwdbuf + 4 : "(未设)");

  /* [ORT §86] 容器 root：视图设为**此后派生进程**的根（本进程自己
   * 不重挂）。失败 fail-closed —— 隔离不成立就不许起容器。 */

  if (prctl(PR_SET_ORT_ROOT, view) != 0)
    {
      printf("[run] 设根失败: %s（errno=%d）\n", view, errno);
      return 1;
    }

  ret = posix_spawn(&pid, g_spawnpath, NULL, attr, g_argv, g_envp);
  if (ret != 0)
    {
      printf("[run] spawn 失败 rc=%d errno=%d\n", ret, errno);
      return 1;
    }

  printf("[run] spawned pid=%d\n", (int)pid);
  *outpid = pid;
  return 0;
}

static int run_spawn(FAR const char *view, FAR const char *path,
                     FAR pid_t *outpid)
{
  return run_spawn_ex(view, path, NULL, outpid);
}

static int do_run(FAR const char *view, FAR const char *path)
{
  pid_t pid;
  int   st;
  int   ret;

  ret = run_spawn(view, path, &pid);
  if (ret != 0)
    {
      return ret;
    }

  if (waitpid(pid, &st, 0) < 0)
    {
      printf("[run] waitpid 失败（errno=%d）\n", errno);
      return 1;
    }

  /* NuttX 的 wait 语义（§73 源码定案+实测）：status = exitcode << 8
   * （task_exithook.c），且"异常终止"的默认动作**就是** _exit(EXIT_FAILURE)
   * （sig_default.c）—— `WIFSIGNALED` 硬编码 false ⇒ **崩溃与 exit(1)
   * 在 waitpid 层面不可分**。如实按"退出码"报；==1 时带注记。
   * （可分信号走 ORT 故障通道 —— §74 的 `orting sup`；边界见 §73。） */

  printf("[run] 退出码=%d%s\n", WEXITSTATUS(st),
         WEXITSTATUS(st) == 1
           ? "（=EXIT_FAILURE；NuttX 崩溃与 exit(1) 不可分——§73）" : "");
  return WEXITSTATUS(st) == 0 ? 0 : 1;
}

/* ── sup：运行时兼任监督者 —— "崩没崩"的**正面判别**（A2 增量⑤）───── *
 *
 * 背景（§73 边界）：NuttX 的 waitpid 里**崩溃与 exit(1) 不可分**；
 * 内核的 ORT 故障通道可以区分 —— 但它只对监督者开放，且监督者
 * **首次注册即钉 pid** ⇒ "每次 CLI 一个进程"的形态拿不到通道。
 * 正确形态是**一个进程兼三职**：注册监督者 → 依次拉起容器（spawn 后
 * 按 pid 绑域）→ 每个容器 wait 后抽事件队列 → 正面判别：
 *   有 FAULT 事件 → 崩溃（报 pc/addr/faults —— "容器为什么死"）
 *   有 EXIT 事件  → 正常退出（报 code；EXIT 事件要求域已绑）
 *   都无          → 无事件（如实报，不退化为瞎猜）
 * §75 起再加**重启策略**：崩溃且预算未耗尽 → 重启（ORT_SUP_RESTARTS）；
 * 耗尽 → 放弃（记一次降级）；重启后转好 → 报"恢复"；首跑即好 →
 * "直接正常"。段末汇总 —— M 侧降级状态机的最小版。
 * 退场释放监督者槽（PR_ORT_SUPERVISOR_RESET —— 原型测试 API）。
 * 白名单：CONFIG_ORT_SUPERVISOR_TASKNAMES 必须含 orting（本 SKU 已配）。
 *
 * 用法：orting sup <view> <config1> [config2 ...]
 */

/* 重启预算（§75 重启策略）：崩溃容器最多重启 ORT_SUP_RESTARTS 次，
 * 耗尽即放弃 —— M 侧降级状态机（重启预算 → DEGRADED）的最小版。 */

#define ORT_SUP_RESTARTS 2

static void ort_sup_wake(int signo)
{
  (void)signo;
}

static int do_sup(FAR const char *view, int ncfg, FAR char * const *cfgs)
{
  int given_up = 0;    /* 重启预算耗尽 */
  int recovered = 0;   /* 重启后正常退出 */
  int clean = 0;       /* 首跑即正常 */
  int rc = 0;
  int ret;
  int i;

  ret = prctl(PR_SET_ORT_SUPERVISOR);
  if (ret < 0)
    {
      printf("[sup] 注册监督者失败: %d（errno=%d）→ sup 中止\n",
             ret, errno);
      return 1;
    }

  /* 醒信号（ORT_SIGFAULT=SIGUSR1，内核 nxsig_queue 每事件一次）——
   * 必须装处理器：不装则投递会打断 waitpid（EINTR），装了按契约
   * 收下再继续等（事件本体在队列里，不靠信号传数据）。 */

  {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = ort_sup_wake;
    sigaction(ORT_SIGFAULT, &sa, NULL);
  }

  printf("[sup] 上任: pid=%d 能力位=0x%08x（醒信号 SIGUSR1 已装）\n",
         (int)getpid(), (unsigned)prctl(PR_GET_ORT_CAPS));

  for (i = 0; i < ncfg; i++)
    {
      int restarts = 0;
      int verdict = 0;   /* 0=无事件/未拉起 1=崩溃（预算耗尽）2=正常 */

      /* 每次尝试 = spawn → 绑域 → wait → 抽事件 → 判别；崩溃且预算
       * 未耗尽 → 重启（§75 重启策略）。 */

      for (;;)
        {
          struct ort_faultrec_s rec;
          pid_t pid = -1;
          int   st = 0;
          int   nev = 0;
          int   nf = 0;
          int   nx = 0;
          uintptr_t last_pc = 0;
          uintptr_t last_addr = 0;
          uint32_t  last_faults = 0;
          int       last_code = 0;

          ret = run_spawn(view, cfgs[i], &pid);
          if (ret != 0)
            {
              printf("[sup] 容器[%d] 未拉起（r=%d）——放弃该容器\n", i, ret);
              rc = 1;
              break;
            }

          /* 按 pid 绑域（监督者权限）：域≠0 时内核才发 EXIT 事件；
           * A 侧域语义是 no-op（MMU），绑域 = 记录 + 事件资格 */

          ret = prctl(PR_SET_ORT_DOMAIN, i + 1, (pid_t)pid);
          if (ret < 0)
            {
              printf("[sup] 容器[%d] 绑域失败: %d（继续——FAULT 不依赖域）\n",
                     i, ret);
            }

          do
            {
              ret = waitpid(pid, &st, 0);
            }
          while (ret < 0 && errno == EINTR);   /* 醒信号打断 → 继续等 */

          if (ret < 0)
            {
              printf("[sup] 容器[%d] waitpid 失败（errno=%d）\n", i, errno);
              rc = 1;
              break;
            }

          /* 抽事件队列（只认本容器；队列是监督者私有视图，串行下无夹杂） */

          while ((ret = prctl(PR_GET_ORT_FAULT, &rec)) > 0)
            {
              nev++;

              if (rec.kind == 0 && rec.victim == (int)pid)
                {
                  nf++;
                  last_pc = rec.pc;
                  last_addr = rec.addr;
                  last_faults = rec.faults;
                }
              else if (rec.kind == 1 && rec.victim == (int)pid)
                {
                  nx++;
                  last_code = rec.code;
                }
              else
                {
                  printf("[sup] （读到非本容器记录 seq=%u victim=%d kind=%u）\n",
                         (unsigned)rec.seq, rec.victim, (unsigned)rec.kind);
                }
            }

          if (ret < 0)
            {
              printf("[sup] 读事件失败: %d（errno=%d）\n", ret, errno);
              rc = 1;
            }

          printf("[sup] 容器[%d] pid=%d 退出码=%d 事件=%d（FAULT %d / EXIT %d）\n",
                 i, (int)pid, WEXITSTATUS(st), nev, nf, nx);

          if (nf > 0)
            {
              printf("[sup] 判别: 崩溃（FAULT pc=0x%x addr=0x%x faults=%u）\n",
                     (unsigned)last_pc, (unsigned)last_addr,
                     (unsigned)last_faults);

              if (restarts < ORT_SUP_RESTARTS)
                {
                  restarts++;
                  printf("[sup] 容器[%d] 重启 %d/%d（预算 %d）\n",
                         i, restarts, ORT_SUP_RESTARTS, ORT_SUP_RESTARTS);
                  continue;
                }

              printf("[sup] 容器[%d] 重启预算耗尽 → 放弃（记一次降级）\n", i);
              given_up++;
              verdict = 1;
              break;
            }

          /* [ORT §83] EXIT 事件在 **group 收尾期**才入队 —— waitpid 可见
           * 早于入队（实测签名：退出码=0 而事件=0）。判定"无事件"前稍候
           * 重抽一次（FAULT 无需：abort 期入队、早于死亡）。 */

          usleep(2000);

          {
            struct ort_faultrec_s rec2;

            while ((ret = prctl(PR_GET_ORT_FAULT, &rec2)) > 0)
              {
                if (rec2.kind == 0 && rec2.victim == (int)pid)
                  {
                    nf++;
                    last_pc = rec2.pc;
                    last_addr = rec2.addr;
                    last_faults = rec2.faults;
                  }
                else if (rec2.kind == 1 && rec2.victim == (int)pid)
                  {
                    nx++;
                    last_code = rec2.code;
                  }
              }
          }

          if (nx > 0)
            {
              printf("[sup] 判别: 正常退出（EXIT 事件 code=%d）\n", last_code);
              verdict = 2;
              break;
            }

          printf("[sup] 判别: 无事件（退出码=%d）\n", WEXITSTATUS(st));
          verdict = 0;
          break;
        }

      if (verdict == 2)
        {
          if (restarts > 0)
            {
              printf("[sup] 容器[%d] 恢复（重启 %d 次后正常退出）\n",
                     i, restarts);
              recovered++;
            }
          else
            {
              clean++;
            }
        }
      else if (verdict == 0)
        {
          printf("[sup] 容器[%d] 无可判结果——如实记（不计入汇总）\n", i);
        }
    }

  printf("[sup] 汇总: 放弃 %d 个 / 恢复 %d 个 / 直接正常 %d 个（预算 %d）\n",
         given_up, recovered, clean, ORT_SUP_RESTARTS);

  ret = prctl(PR_ORT_SUPERVISOR_RESET);
  printf("[sup] 卸任: %s（槽释放）\n", ret == 0 ? "OK" : "失败");
  return rc;
}

/* ── par：并发判别 —— 事件队列的"逐条配对"压力（A2 增量⑦，§76）──── *
 *
 * N 个容器**同时**跑、同时崩，然后一次性抽干故障事件队列，按 victim
 * （pid）逐条配对回各自的容器。压的是 §32 那套队列协议的运行时线：
 * 并发入队的序号原子性（R1/R4）、生产者/消费者游标协议（R3/R5）——
 * "A 的 pid 配 B 的详情"这类错配在这里现形。
 *
 * 打印纪律：par 自己的行**全部在子进程死光之后**打（记录/判别/汇总）——
 * 控制台是逐字符写，活着的子进程打印会把我们的行劈开；死后再打就没有
 * 竞争者（内核 syslog 行仍可能与子进程交错，判据用"平流计数"对付）。
 *
 * 用法：orting par <view> <config1> [config2 ...]（上限 8 个）
 */

#define ORT_PAR_MAX 8

static int do_par(FAR const char *view, int ncfg, FAR char * const *cfgs)
{
  struct
  {
    int       nf;
    int       nx;
    uintptr_t pc;
    uintptr_t addr;
    uint32_t  faults;
    int       code;
  } tally[ORT_PAR_MAX];

  pid_t pids[ORT_PAR_MAX];
  int   st[ORT_PAR_MAX];
  int   n = 0;
  int   matched;
  int   ret;
  int   i;

  if (ncfg > ORT_PAR_MAX)
    {
      ncfg = ORT_PAR_MAX;
    }

  ret = prctl(PR_SET_ORT_SUPERVISOR);
  if (ret < 0)
    {
      printf("[par] 注册监督者失败: %d（errno=%d）→ par 中止\n", ret, errno);
      return 1;
    }

  {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = ort_sup_wake;
    sigaction(ORT_SIGFAULT, &sa, NULL);
  }

  printf("[par] 上任: pid=%d（并发批次 %d 个）\n", (int)getpid(), ncfg);

  memset(tally, 0, sizeof(tally));

  /* ① 全部拉起（并发）：spawn + 按 pid 绑域 */

  for (i = 0; i < ncfg; i++)
    {
      pids[i] = -1;
      st[i] = 0;

      ret = run_spawn(view, cfgs[i], &pids[i]);
      if (ret != 0)
        {
          printf("[par] 容器[%d] 未拉起（r=%d）\n", i, ret);
          pids[i] = -1;
          continue;
        }

      n++;

      ret = prctl(PR_SET_ORT_DOMAIN, i + 1, (pid_t)pids[i]);
      if (ret < 0)
        {
          printf("[par] 容器[%d] 绑域失败: %d（继续——FAULT 不依赖域）\n",
                 i, ret);
        }
    }

  /* ② 全部等完（EINTR = 醒信号，重试） */

  for (i = 0; i < ncfg; i++)
    {
      if (pids[i] < 0)
        {
          continue;
        }

      do
        {
          ret = waitpid(pids[i], &st[i], 0);
        }
      while (ret < 0 && errno == EINTR);

      if (ret < 0)
        {
          printf("[par] 容器[%d] waitpid 失败（errno=%d）\n", i, errno);
        }
    }

  /* ③ 一次抽干队列 → 逐条打印 + 按 victim 配对（此刻无子进程在打印） */

  {
    struct ort_faultrec_s rec;

    while ((ret = prctl(PR_GET_ORT_FAULT, &rec)) > 0)
      {
        printf("[par] 记录 seq=%u victim=%d kind=%u pc=0x%x addr=0x%x "
               "faults=%u\n", (unsigned)rec.seq, rec.victim,
               (unsigned)rec.kind, (unsigned)rec.pc, (unsigned)rec.addr,
               (unsigned)rec.faults);

        matched = 0;

        for (i = 0; i < ncfg; i++)
          {
            if (pids[i] == rec.victim)
              {
                matched = 1;

                if (rec.kind == 0)
                  {
                    tally[i].nf++;
                    tally[i].pc = rec.pc;
                    tally[i].addr = rec.addr;
                    tally[i].faults = rec.faults;
                  }
                else if (rec.kind == 1)
                  {
                    tally[i].nx++;
                    tally[i].code = rec.code;
                  }

                break;
              }
          }

        if (!matched)
          {
            printf("[par] （记录 victim=%d 不在本批——如实记）\n",
                   rec.victim);
          }
      }

    if (ret < 0)
      {
        printf("[par] 读事件失败: %d（errno=%d）\n", ret, errno);
      }
  }

  /* ④ 逐容器判别（含 index/pid —— 配对证据在行内自带） */

  for (i = 0; i < ncfg; i++)
    {
      if (pids[i] < 0)
        {
          continue;
        }

      printf("[par] 容器[%d] pid=%d 退出码=%d（FAULT %d / EXIT %d）\n",
             i, (int)pids[i], WEXITSTATUS(st[i]), tally[i].nf, tally[i].nx);

      if (tally[i].nf > 0)
        {
          printf("[par] 容器[%d] 判别: 崩溃（FAULT pc=0x%x addr=0x%x "
                 "faults=%u）\n", i, (unsigned)tally[i].pc,
                 (unsigned)tally[i].addr, (unsigned)tally[i].faults);
        }
      else if (tally[i].nx > 0)
        {
          printf("[par] 容器[%d] 判别: 正常退出（EXIT code=%d）\n",
                 i, tally[i].code);
        }
      else
        {
          printf("[par] 容器[%d] 判别: 无事件\n", i);
        }
    }

  printf("[par] 汇总: 批次 %d 个 / 记录逐条配对完\n", n);

  ret = prctl(PR_ORT_SUPERVISOR_RESET);
  printf("[par] 卸任: %s（槽释放）\n", ret == 0 ? "OK" : "失败");
  return 0;
}

/* ── supd：长驻监督者 —— 与派生者解耦（A2 增量⑧，§77）────────────── *
 *
 * 前面几个模式的监督者是"派生者兼职"（自己拉的容器自己看）。产品形态
 * 是**编排者常驻**：监督者 ≠ 派生者 —— 容器由别处拉起（nsh / 别的
 * 进程），守护进程旁路观测整个系统。
 *
 * 形态：注册监督者 → 按**墙钟**巡检 secs 秒（睡 1 秒 → 抽干队列 →
 * 立即打印；醒信号打断睡眠就是即时抽一次——尽力而为的延迟优化）→
 * 到期打印退场汇总（条数 + 末序）→ 卸任。
 *
 * ⚠️ sleep 被信号打断会提前返回：循环用**时间**判退场，不用次数
 * （否则每次唤醒都烧掉一轮，守护提前死）。
 *
 * 用法：orting supd <秒>（建议 nsh 后台：`orting supd 15 &`）
 */

static int do_supd(int secs)
{
  time_t start;
  int    total = 0;
  uint32_t last_seq = 0;
  int    ret;

  if (secs <= 0)
    {
      secs = 10;
    }

  ret = prctl(PR_SET_ORT_SUPERVISOR);
  if (ret < 0)
    {
      printf("[supd] 注册监督者失败: %d（errno=%d）→ supd 中止\n",
             ret, errno);
      return 1;
    }

  {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = ort_sup_wake;
    sigaction(ORT_SIGFAULT, &sa, NULL);
  }

  printf("[supd] 上任: pid=%d（巡检 %d 秒，与派生者解耦）\n",
         (int)getpid(), secs);

  start = time(NULL);

  while (time(NULL) - start < (time_t)secs)
    {
      struct ort_faultrec_s rec;

      sleep(1);

      while ((ret = prctl(PR_GET_ORT_FAULT, &rec)) > 0)
        {
          total++;
          last_seq = rec.seq;
          printf("[supd] 事件 seq=%u victim=%d kind=%u pc=0x%x addr=0x%x "
                 "faults=%u\n", (unsigned)rec.seq, rec.victim,
                 (unsigned)rec.kind, (unsigned)rec.pc, (unsigned)rec.addr,
                 (unsigned)rec.faults);
        }
    }

  printf("[supd] 退场: 共 %d 条（末序 seq=%u）\n", total,
         (unsigned)last_seq);

  ret = prctl(PR_ORT_SUPERVISOR_RESET);
  printf("[supd] 卸任: %s（槽释放）\n", ret == 0 ? "OK" : "失败");
  return 0;
}

/* ── orch：多服务编排环 —— wait-any 驱动的个体策略（A2 增量⑨，§78）── *
 *
 * 一个进程管一组服务：并发拉起全部（按 pid 绑域），然后进**编排环**：
 *   轮询（抽事件队列 + waitpid(-1, WNOHANG) 把**已死的逐个捞出来**——
 *   不按固定顺序等谁）→ 按 victim 归到各自服务 → 个体策略：
 *     崩溃 → 预算未耗尽：重启（第 N 次）；耗尽：放弃（记降级）
 *     正常退出 → 完成（服务语义：退出即终态，不热重启）
 *     无事件   → 如实记（终态）
 *   **全部服务落定**（完成/放弃）即提前退场；否则到 <秒> 兜底。
 * 退场汇总：完成 / 放弃 / 重启次数 / 用时。
 *
 * 与 sup/par 的区别：sup=串行批量、par=同时崩只配对、orch=**异步死亡 +
 * 个体策略环**（谁死处理谁，处理完还能继续管剩下的）。
 *
 * 用法：orting orch <秒> <view> <config1> [config2 ...]（上限 4）
 */

#define ORT_ORCH_MAX 4

static int do_orch(int secs, FAR const char *view, int ncfg,
                   FAR char * const *cfgs)
{
  struct
  {
    pid_t pid;
    int   restarts;
    int   done;          /* 终态：完成/放弃/无事件 */
    int   dropped;
    int   nf;            /* 记账：按**当前 pid** 归拢（死亡可乱序到达） */
    int   nx;
    uintptr_t pc;
    uintptr_t addr;
    uint32_t  faults;
    int       code;
  } svc[ORT_ORCH_MAX];

  time_t start;
  int    n = 0;
  int    ret;
  int    i;

  if (secs <= 0)
    {
      secs = 10;
    }

  if (ncfg > ORT_ORCH_MAX)
    {
      ncfg = ORT_ORCH_MAX;
    }

  ret = prctl(PR_SET_ORT_SUPERVISOR);
  if (ret < 0)
    {
      printf("[orch] 注册监督者失败: %d（errno=%d）→ orch 中止\n",
             ret, errno);
      return 1;
    }

  {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = ort_sup_wake;
    sigaction(ORT_SIGFAULT, &sa, NULL);
  }

  memset(svc, 0, sizeof(svc));

  printf("[orch] 上任: pid=%d（服务 %d 个，上限 %d 秒）\n",
         (int)getpid(), ncfg, secs);

  /* 并发拉起全部服务（各自绑域） */

  for (i = 0; i < ncfg; i++)
    {
      svc[i].pid = -1;

      ret = run_spawn(view, cfgs[i], &svc[i].pid);
      if (ret != 0)
        {
          printf("[orch] 服务[%d] 未拉起（r=%d）→ 放弃\n", i, ret);
          svc[i].pid = -1;
          svc[i].done = 1;
          svc[i].dropped = 1;
          continue;
        }

      n++;

      ret = prctl(PR_SET_ORT_DOMAIN, i + 1, (pid_t)svc[i].pid);
      if (ret < 0)
        {
          printf("[orch] 服务[%d] 绑域失败: %d（继续——FAULT 不依赖域）\n",
                 i, ret);
        }
    }

  start = time(NULL);

  /* 编排环：谁死处理谁 */

  for (;;)
    {
      int settled = 1;
      int alive = 0;

      /* ① 处理所有**已死**的服务（wait-any，WNOHANG 捞干）。
       *
       * ★ 每趟先**抽干事件队列做全量记账**：死亡是**乱序**到达的，
       *   先死的服务的事件可能在后死的服务的趟里才被抽到。逐趟
       *   "只认本 pid、其余丢弃"会把别家记录吃掉（实测：服务[0] 的
       *   FAULT 被服务[1] 的趟吃掉 → 服务[0] 判成"无事件"）。按**各
       *   自当前 pid** 归拢到各服务的记账槽；重启时清零（新世代新账）。
       *   抽在 waitpid **之前**：记录一定先于"死亡可见"入队（入队在
       *   终止路径上），趟首抽同时覆盖"记录已到、死亡未可见"的竞态。 */

      for (;;)
        {
          struct ort_faultrec_s rec;
          pid_t dead;
          int   st = 0;
          int   idx = -1;
          int   j;

          while ((ret = prctl(PR_GET_ORT_FAULT, &rec)) > 0)
            {
              for (j = 0; j < ncfg; j++)
                {
                  if (svc[j].pid == rec.victim)
                    {
                      if (rec.kind == 0)
                        {
                          svc[j].nf++;
                          svc[j].pc = rec.pc;
                          svc[j].addr = rec.addr;
                          svc[j].faults = rec.faults;
                        }
                      else if (rec.kind == 1)
                        {
                          svc[j].nx++;
                          svc[j].code = rec.code;
                        }

                      break;
                    }
                }

              if (j >= ncfg)
                {
                  printf("[orch] （记录 victim=%d 不在编（旧世代？）——如实记）\n",
                         rec.victim);
                }
            }

          dead = waitpid(-1, &st, WNOHANG);
          if (dead <= 0)
            {
              break;
            }

          for (j = 0; j < ncfg; j++)
            {
              if (svc[j].pid == dead)
                {
                  idx = j;
                  break;
                }
            }

          if (idx < 0)
            {
              printf("[orch] 未知子进程 %d 退出（如实记）\n", (int)dead);
              continue;
            }

          printf("[orch] 服务[%d] pid=%d 退出码=%d 事件=%d（FAULT %d / EXIT %d）\n",
                 idx, (int)dead, WEXITSTATUS(st),
                 svc[idx].nf + svc[idx].nx, svc[idx].nf, svc[idx].nx);

          if (svc[idx].nf > 0)
            {
              printf("[orch] 服务[%d] 判别: 崩溃（FAULT pc=0x%x addr=0x%x "
                     "faults=%u）\n", idx, (unsigned)svc[idx].pc,
                     (unsigned)svc[idx].addr, (unsigned)svc[idx].faults);

              if (svc[idx].restarts < ORT_SUP_RESTARTS)
                {
                  svc[idx].restarts++;

                  ret = run_spawn(view, cfgs[idx], &svc[idx].pid);
                  if (ret != 0)
                    {
                      printf("[orch] 服务[%d] 重启未拉起（r=%d）→ 放弃\n",
                             idx, ret);
                      svc[idx].pid = -1;
                      svc[idx].done = 1;
                      svc[idx].dropped = 1;
                      continue;
                    }

                  prctl(PR_SET_ORT_DOMAIN, idx + 1, (pid_t)svc[idx].pid);

                  /* 新世代新账 */

                  svc[idx].nf = 0;
                  svc[idx].nx = 0;

                  printf("[orch] 服务[%d] 崩溃 → 重启 %d/%d\n",
                         idx, svc[idx].restarts, ORT_SUP_RESTARTS);
                }
              else
                {
                  printf("[orch] 服务[%d] 重启预算耗尽 → 放弃（记一次降级）\n",
                         idx);
                  svc[idx].pid = -1;
                  svc[idx].done = 1;
                  svc[idx].dropped = 1;
                }
            }
          else if (svc[idx].nx > 0)
            {
              printf("[orch] 服务[%d] 正常退出（EXIT code=%d）→ 完成\n",
                     idx, svc[idx].code);
              svc[idx].pid = -1;
              svc[idx].done = 1;
            }
          else
            {
              /* [ORT §83] EXIT 事件在 **group 收尾期**才入队 —— waitpid
               * 可见早于入队（实测签名：退出码=0 而事件=0，随后一趟才抽
               * 到 victim 记录 → "不在编"）。判定"无事件"前稍候重抽一次
               * （FAULT 无需：abort 期入队，早于死亡——§74 已鉴）。 */

              usleep(2000);

              {
                struct ort_faultrec_s rec2;
                int j2;

                while ((ret = prctl(PR_GET_ORT_FAULT, &rec2)) > 0)
                  {
                    for (j2 = 0; j2 < ncfg; j2++)
                      {
                        if (svc[j2].pid == rec2.victim)
                          {
                            if (rec2.kind == 0)
                              {
                                svc[j2].nf++;
                                svc[j2].pc = rec2.pc;
                                svc[j2].addr = rec2.addr;
                                svc[j2].faults = rec2.faults;
                              }
                            else if (rec2.kind == 1)
                              {
                                svc[j2].nx++;
                                svc[j2].code = rec2.code;
                              }

                            break;
                          }
                      }
                  }
              }

              if (svc[idx].nx > 0)
                {
                  printf("[orch] 服务[%d] 正常退出（EXIT code=%d）→ 完成\n",
                         idx, svc[idx].code);
                }
              else
                {
                  printf("[orch] 服务[%d] 无事件收尾（退出码=%d）→ 完成\n",
                         idx, WEXITSTATUS(st));
                }

              svc[idx].pid = -1;
              svc[idx].done = 1;
            }
        }

      /* ② 落定检查 / 时间兜底（等待下一批死亡用 sleep；WNOHANG 不阻塞） */

      for (i = 0; i < ncfg; i++)
        {
          if (!svc[i].done)
            {
              settled = 0;
              alive++;
            }
        }

      if (settled)
        {
          printf("[orch] 全部落定（用时约 %d 秒）\n",
                 (int)(time(NULL) - start));
          break;
        }

      if (time(NULL) - start >= (time_t)secs)
        {
          printf("[orch] 到时（%d 个服务仍在运行，放弃管理）\n", alive);
          break;
        }

      sleep(1);
    }

  {
    int done = 0;
    int dropped = 0;
    int restarts = 0;

    for (i = 0; i < ncfg; i++)
      {
        if (svc[i].done && !svc[i].dropped)
          {
            done++;
          }

        if (svc[i].dropped)
          {
            dropped++;
          }

        restarts += svc[i].restarts;
      }

    printf("[orch] 汇总: 完成 %d / 放弃 %d / 重启 %d 次（用时 %d 秒）\n",
           done, dropped, restarts, (int)(time(NULL) - start));
  }

  ret = prctl(PR_ORT_SUPERVISOR_RESET);
  printf("[orch] 卸任: %s（槽释放）\n", ret == 0 ? "OK" : "失败");
  return 0;
}

/* ── 自动动线：一条命令 = pull → 组装 → 挂载视图（A2 增量②）───────── *
 *
 * （do_pull 定义在本文件后段 —— 前向声明。） */

static int do_pull(FAR const char *host, unsigned port, FAR const char *repo,
                   FAR const char *tag);

/* 流程（`orting up <view> <host> <port> <repo> <tag>`）：
 *   ① mkdir 视图 + **派生**中转挂载点（<view>_ro 下层 / <view>_up 上层
 *      —— 派生名避免多实例/与手工装置互踩）
 *   ② 用户态 mount tmpfs ×2（mount 有系统调用槽；nsh 语义同款：
 *      mount(NULL, target, fstype, 0, data)）
 *   ③ 复用 do_pull（下载+内容寻址校验+落盘+rootfs 组装，打印照旧）
 *   ④ 两层 untar 到下层挂载点（复用 do_tar_apply）
 *   ⑤ mount unionfs（fspath1=<view>_up,fspath2=<view>_ro → <view>）
 *
 * fail-closed：任一步失败即精确报错并返回 1。
 * **重复 up 的收口（§71 实测 → §72 收紧）**：§71 实测 NuttX 允许 tmpfs
 * 叠挂，重试要走到 ⑤ 才被 unionfs 目标判据拒（ENOTDIR，整体 fail-closed
 * 但会重复下载）；§72 起入口加**形态闸 + statfs 预检**，同场景在 ⓪/②
 * 早退。statfs 语义（源码定案）：unionfs 的 statfs **转发到上层** ⇒ 视图
 * 上看到的是 TMPFS_MAGIC；root 伪 FS 目录 = PROC_SUPER_MAGIC。
 */

static int do_up(FAR const char *view, FAR const char *host, unsigned port,
                 FAR const char *repo, FAR const char *tag)
{
  static char ro[300];
  static char upsf[300];
  static char data[384];
  struct statfs fs;
  struct stat vst;
  uint32_t i;
  int ret;

  /* ⓪ 形态闸：unionfs 目标必须是**根伪文件系统下的一级目录**
   *    （fs_mount 只认 PSEUDODIR；/tmp 下的目录在 tmpfs 里、必被拒
   *    —— §65 实证）——这里一次判掉，报错才说得清 */

  if (view[0] != '/' || view[1] == '\0' || strchr(view + 1, '/') != NULL)
    {
      printf("[up] 视图须为根下一级目录（如 /v）: %s\n", view);
      return 1;
    }

  /* ① 视图 + 派生中转点 */

  if (snprintf(ro,   sizeof(ro),   "%s_ro", view) >= (int)sizeof(ro) ||
      snprintf(upsf, sizeof(upsf), "%s_up", view) >= (int)sizeof(upsf))
    {
      printf("[up] 视图名过长: %s\n", view);
      return 1;
    }

  if (mkdir_p(view) != 0 || mkdir_p(ro) != 0 || mkdir_p(upsf) != 0)
    {
      printf("[up] 建目录失败（view=%s errno=%d）\n", view, errno);
      return 1;
    }

  /* ② 挂载点预检：视图/中转点已是 tmpfs/union ⇒ 重复 up，pull 前早退 */

  if (statfs(view, &fs) == 0 &&
      (fs.f_type == TMPFS_MAGIC || fs.f_type == UNIONFS_MAGIC))
    {
      printf("[up] 视图已在用（重复 up？）: %s\n", view);
      return 1;
    }

  if (statfs(ro, &fs) == 0 && fs.f_type == TMPFS_MAGIC)
    {
      printf("[up] 中转点已在用: %s\n", ro);
      return 1;
    }

  if (statfs(upsf, &fs) == 0 && fs.f_type == TMPFS_MAGIC)
    {
      printf("[up] 中转点已在用: %s\n", upsf);
      return 1;
    }

  if (stat(view, &vst) != 0 || !S_ISDIR(vst.st_mode))
    {
      printf("[up] 视图不是目录: %s\n", view);
      return 1;
    }

  /* ③ tmpfs ×2（用户态 mount；重复 up 已在 ② 预检拦住） */

  if (mount(NULL, ro, "tmpfs", 0, NULL) != 0)
    {
      printf("[up] tmpfs 挂载失败（下层）: %s（errno=%d）\n", ro, errno);
      return 1;
    }

  if (mount(NULL, upsf, "tmpfs", 0, NULL) != 0)
    {
      printf("[up] tmpfs 挂载失败（上层）: %s（errno=%d）\n", upsf, errno);
      return 1;
    }

  /* ④ pull（下载 + 校验 + 落盘 + rootfs；复用全链） */

  ret = do_pull(host, port, repo, tag);
  if (ret != 0)
    {
      printf("[up] pull 未过（r=%d）→ up 中止\n", ret);
      return 1;
    }

  /* ⑤ 两层 → 下层挂载点 */

  for (i = 0; i < g_mf.nlayers && i < 8; i++)
    {
      static char lp[300];
      FAR const char *hex = g_mf.layers[i].digest;

      if (strncmp(hex, "sha256:", 7) == 0)
        {
          hex += 7;
        }

      snprintf(lp, sizeof(lp),
               ORT_STORE_ROOT "/images/sha256/%s/layer.tar", hex);

      printf("[up] 铺层[%u] → %s\n", (unsigned)i, ro);
      if (do_tar_apply(lp, ro) != 0)
        {
          printf("[up] 层[%u]铺入失败 → up 中止\n", (unsigned)i);
          return 1;
        }
    }

  /* ⑥ unionfs：上层可写 + 下层只读 → 视图 */

  snprintf(data, sizeof(data), "fspath1=%s,fspath2=%s", upsf, ro);

  if (mount(NULL, view, "unionfs", 0, data) != 0)
    {
      printf("[up] union 挂载失败: %s（errno=%d）\n", view, errno);
      return 1;
    }

  printf("[up] 视图就绪: %s（下层 %s + 上层 %s）\n", view, ro, upsf);
  return 0;
}

/* ── start：up + run 一条命令（镜像到进程）──────────────────────────── *
 *
 * 比"up 再手动 run"多知道一件事：config 落盘路径（pull 里 g_mf 已解析
 * 出 config_digest）——所以调用方不必再传。
 */

static int do_start(FAR const char *view, FAR const char *host, unsigned port,
                    FAR const char *repo, FAR const char *tag)
{
  static char cfgp[320];
  FAR const char *hex = g_mf.config_digest;
  int ret;

  ret = do_up(view, host, port, repo, tag);
  if (ret != 0)
    {
      printf("[start] up 未过（r=%d）→ start 中止\n", ret);
      return 1;
    }

  if (strncmp(hex, "sha256:", 7) == 0)
    {
      hex += 7;
    }

  snprintf(cfgp, sizeof(cfgp),
           ORT_STORE_ROOT "/images/sha256/%s/config.json", hex);

  ret = do_run(view, cfgp);
  printf("[start] 完成: view=%s（r=%d，收尾: orting down %s）\n",
         view, ret, view);
  return ret;
}

/* ── down：卸载视图（生命周期收尾）─────────────────────────────────── *
 *
 * 实测语义（§72，源码对账）：umount2 成功后 **挂载点目录本身也被
 * 从命名空间摘除**（fs_umount2.c：mountpt_inode->i_child 非空时
 * inode_remove(target)）—— 卸载后 `<view>` 路径**不存在**（opendir
 * ENOENT），不是"空目录"；重复 down 报 ENOENT，重建需 mkdir（各自
 * 的行为都是 fail-closed 的判据）。两个中转点则早在 bind 时就被
 * unionfs 摘除（inode_remove，§65），不可按路径回收。
 */

static int do_down(FAR const char *view)
{
  if (umount2(view, 0) != 0)
    {
      printf("[down] 卸载失败: %s（errno=%d）\n", view, errno);
      return 1;
    }

  printf("[down] 视图已卸载: %s\n", view);
  return 0;
}

/* ── lim：资源限制第一刀 —— 核集 + 优先级（A2 增量⑩，§80）──────────── *
 *
 * 架构注：OCI 的 CPU 限制属 **host 侧配置**（Docker 的 HostConfig），
 * 不在镜像 config 里 —— 所以资源限制由**运行时在派生前施加**（CLI），
 * 而不是塞进 image config；与"编排者分配资源"的形态一致。
 *
 * 施加两条：优先级走 posix_spawnattr（spawn 前）；**核集注意**——
 * spawnattr 没有亲和项，走 spawn 后 sched_setaffinity（按 pid）。
 * 绑核失败 = **fail-closed**：不许"带着默认全核"继续跑（那就是没
 * 限制的容器）—— 终止该容器并报错。
 *
 * 用法：orting lim <view> <cpu-list> <prio> <cfg1> [cfg2 ...]
 *       （cpu-list 形如 "2" / "2,3"；越界的核号交给内核判 —— 正好
 *        当"真闸门"的反证臂）
 */

static int do_lim(FAR const char *view, FAR const char *cpus, int prio,
                  int ncfg, FAR char * const *cfgs)
{
  static cpu_set_t want;
  posix_spawnattr_t attr;
  uint32_t mask = 0;
  int rc = 0;
  int ret;
  int i;

  if (prio < 1 || prio > 255)
    {
      printf("[lim] 优先级非法: %d（1..255）\n", prio);
      return 1;
    }

  /* 核集解析："2" / "2,3" / "0,1,2,3" */

  CPU_ZERO(&want);

  {
    FAR const char *p = cpus;

    while (*p != '\0')
      {
        FAR char *end;
        long v = strtol(p, &end, 10);

        if (end == p || v < 0 || v >= 32 ||
            (*end != '\0' && *end != ','))
          {
            printf("[lim] cpu-list 非法: %s\n", cpus);
            return 1;
          }

        CPU_SET((int)v, &want);
        mask |= (1u << (int)v);
        p = (*end == ',') ? end + 1 : end;
      }
  }

  if (mask == 0)
    {
      printf("[lim] cpu-list 为空: %s\n", cpus);
      return 1;
    }

  printf("[lim] 配置: cpus=%s mask=0x%x prio=%d\n", cpus, (unsigned)mask,
         prio);

  ret = posix_spawnattr_init(&attr);
  if (ret == 0)
    {
      ret = posix_spawnattr_setpriority(&attr, prio);
    }

  if (ret == 0)
    {
      ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSCHEDPARAM);
    }

  if (ret != 0)
    {
      printf("[lim] attr 设置失败: %d\n", ret);
      posix_spawnattr_destroy(&attr);
      return 1;
    }

  for (i = 0; i < ncfg; i++)
    {
      pid_t pid = -1;
      int   st = 0;

      ret = run_spawn_ex(view, cfgs[i], &attr, &pid);
      if (ret != 0)
        {
          printf("[lim] 容器[%d] 未拉起（r=%d）\n", i, ret);
          rc = 1;
          continue;
        }

      /* 绑核：后置施加；失败 = fail-closed（终止，不许无限制跑） */

      if (sched_setaffinity(pid, sizeof(cpu_set_t), &want) != 0)
        {
          printf("[lim] 容器[%d] 设核集失败（errno=%d）→ fail-closed 终止\n",
                 i, errno);
          kill(pid, SIGKILL);

          do
            {
              ret = waitpid(pid, &st, 0);
            }
          while (ret < 0 && errno == EINTR);

          rc = 1;
          continue;
        }

      printf("[lim] 容器[%d] 已施加: pid=%d mask=0x%x prio=%d\n",
             i, (int)pid, (unsigned)mask, prio);

      do
        {
          ret = waitpid(pid, &st, 0);
        }
      while (ret < 0 && errno == EINTR);

      if (ret < 0)
        {
          printf("[lim] 容器[%d] waitpid 失败（errno=%d）\n", i, errno);
          rc = 1;
          continue;
        }

      printf("[lim] 容器[%d] 退出码=%d\n", i, WEXITSTATUS(st));
    }

  posix_spawnattr_destroy(&attr);
  return rc;
}

/* ── memcap：内存限额 —— 派生进程堆上限（A2 增量⑪，§81）────────────── *
 *
 * 语义：**本进程派生的进程**，用户堆不超过 X KB（ELF 装载跑在调用方
 * 上下文，消费点在 libelf_addrenv_alloc —— 天然无竞态，不存在
 * "生出来才补设"的窗口）。不随容器代际传递（拉起的进程要再派生自带
 * 限额，除非它自己也设）。0 = 解除。
 *
 * 用法：orting memcap <view> <KB> <cfg1> [cfg2 ...]
 */

static int do_memcap(FAR const char *view, int kb, int ncfg,
                     FAR char * const *cfgs)
{
  int rc = 0;
  int ret;
  int i;

  if (kb <= 0)
    {
      printf("[memcap] 上限非法: %d KB\n", kb);
      return 1;
    }

  ret = prctl(PR_SET_ORT_MEMCAP, kb * 1024);
  if (ret < 0)
    {
      printf("[memcap] 设置失败: %d（errno=%d）\n", ret, errno);
      return 1;
    }

  printf("[memcap] 配置: %d KB（本进程组；此后拉起的进程堆上限）\n", kb);

  for (i = 0; i < ncfg; i++)
    {
      pid_t pid = -1;
      int   st = 0;

      ret = run_spawn(view, cfgs[i], &pid);
      if (ret != 0)
        {
          printf("[memcap] 容器[%d] 未拉起（r=%d）\n", i, ret);
          rc = 1;
          continue;
        }

      do
        {
          ret = waitpid(pid, &st, 0);
        }
      while (ret < 0 && errno == EINTR);

      if (ret < 0)
        {
          printf("[memcap] 容器[%d] waitpid 失败（errno=%d）\n", i, errno);
          rc = 1;
          continue;
        }

      printf("[memcap] 容器[%d] 退出码=%d\n", i, WEXITSTATUS(st));
    }

  return rc;
}

static int do_validate(FAR const char *path)
{
  size_t len = 0;
  int ret;

  if (read_file(path, &len) != 0)
    {
      return 2;
    }

  ret = ort_json_validate(g_buf, len);
  printf("[ortimg] validate: %s（%zu 字节）\n", ort_json_strerror(ret), len);
  return ret == ORT_JSON_OK ? 0 : 1;
}

/* ── registry pull（A1：明文 HTTP 全流程；TLS 是下一增量）────────────── */

static int url_split(FAR const char *url, FAR char *host, size_t hostcap,
                     FAR unsigned *port, FAR char *path, size_t pathcap)
{
  FAR const char *p = url;

  if (strncmp(p, "http://", 7) == 0)
    {
      p += 7;
    }

  {
    FAR const char *slash = strchr(p, '/');
    FAR const char *colon = strchr(p, ':');
    size_t hlen;

    if (slash == NULL)
      {
        return -1;
      }

    if (colon != NULL && colon < slash)
      {
        hlen = (size_t)(colon - p);
        *port = (unsigned)atoi(colon + 1);
      }
    else
      {
        hlen = (size_t)(slash - p);
        *port = 80;
      }

    if (hlen == 0 || hlen >= hostcap)
      {
        return -1;
      }

    memcpy(host, p, hlen);
    host[hlen] = '\0';
    strlcpy(path, slash, pathcap);
  }

  return 0;
}

static void attr_get(FAR const char *hdr, FAR const char *name,
                     FAR char *out, size_t cap)
{
  char   pat[24];
  FAR const char *p;

  snprintf(pat, sizeof(pat), "%s=\"", name);
  p = strstr(hdr, pat);
  out[0] = '\0';
  if (p != NULL)
    {
      p += strlen(pat);
      while (*p != '\0' && *p != '"' && cap > 1)
        {
          *out++ = *p++;
          cap--;
        }
      *out = '\0';
    }
}

/* 下载一个 blob（层体）：流式落盘 + 边收边算 SHA-256，收齐后与 digest
 * 比对（**内容寻址校验**）；通过才把 .part 改名转正，失败一律删掉
 * —— fail-closed。返回 0=通过 / 1=校验失败 / 2=传输或落盘失败。 */

struct dl_sink_s
{
  int    fd;
  struct ort_sha256_s sha;
  size_t n;
  int    err;
};

static int dl_sink(FAR void *arg, FAR const char *buf, size_t len)
{
  FAR struct dl_sink_s *d = (FAR struct dl_sink_s *)arg;
  size_t off = 0;

  if (d->n + len > ORT_BLOB_MAX)
    {
      d->err = 3;                   /* 超上限：sink 主动中止 */
      return -1;
    }

  while (off < len)
    {
      ssize_t w = write(d->fd, buf + off, len - off);

      if (w <= 0)
        {
          d->err = 1;
          return -1;
        }

      off += (size_t)w;
    }

  ort_sha256_update(&d->sha, buf, len);
  d->n += len;
  return 0;
}

static int blob_download(FAR const char *host, unsigned port,
                         FAR const char *repo, FAR const char *bearer,
                         FAR const char *digest, uint64_t msize,
                         FAR const char *leaf, FAR const char *tag)
{
  static char path[320];
  static char dir[256];
  static char part[300];
  static char final[300];
  static struct ort_http_resp_s r;
  static struct dl_sink_s d;
  FAR const char *hex = digest;
  uint8_t raw[32];
  char    got[65];
  int     fd;
  int     ret;

  if (strncmp(hex, "sha256:", 7) == 0)
    {
      hex += 7;
    }

  snprintf(dir,   sizeof(dir),   ORT_STORE_ROOT "/images/sha256/%s", hex);
  snprintf(part,  sizeof(part),  "%s/%s.part", dir, leaf);
  snprintf(final, sizeof(final), "%s/%s", dir, leaf);
  snprintf(path,  sizeof(path),  "/v2/%s/blobs/%s", repo, digest);

  printf("[pull] %s %s\n", tag, path);
  printf("[pull]    体 %llu 字节 → %s\n",
         (unsigned long long)msize, final);

  if (mkdir_p(dir) != 0)
    {
      printf("[pull]    建目录失败: %s（errno=%d）\n", dir, errno);
      return 2;
    }

  fd = open(part, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    {
      printf("[pull]    建文件失败: %s（errno=%d）\n", part, errno);
      return 2;
    }

  memset(&d, 0, sizeof(d));
  d.fd = fd;
  ort_sha256_init(&d.sha);

  ret = ort_http_get_stream(host, port, path, bearer, NULL,
                            dl_sink, &d, &r);
  close(fd);

  if (ret != 0 || r.status != 200)
    {
      printf("[pull]    blob 下载失败（ret=%d status=%d errno=%d）\n",
             ret, r.status, errno);
      unlink(part);
      return 2;
    }

  ort_sha256_final(&d.sha, raw);
  ort_sha256_hex(raw, got);

  printf("[pull]    收到 %zu 字节%s%s，算得 sha256:%s\n", d.n,
         r.chunked ? "（chunked 已解码）" : "",
         r.redirects ? "（经重定向）" : "", got);

  if (strcmp(got, hex) != 0)
    {
      printf("[pull]    sha256 校验 FAILED：算得 %s，期望 %s\n", got, hex);
      unlink(part);
      return 1;
    }

  if ((uint64_t)d.n != msize)
    {
      printf("[pull]    尺寸校验 FAILED：收到 %zu，manifest 记 %llu\n",
             d.n, (unsigned long long)msize);
      unlink(part);
      return 1;
    }

  if (rename(part, final) != 0)
    {
      printf("[pull]    转正失败: %s → %s（errno=%d）\n", part, final, errno);
      unlink(part);
      return 2;
    }

  printf("[pull]    sha256 校验 OK（与 manifest 一致），落盘 %s\n", final);
  return 0;
}

static int do_pull(FAR const char *host, unsigned port, FAR const char *repo,
                   FAR const char *tag)
{
  static struct ort_http_resp_s r;         /* ★ 全静态：目标机 app 栈 ~2KB */
  static char   path[320];
  static char   realm[256], service[64], scope[160];
  int    ret;
  int    step = 0;

  /* 1) /v2/：拿 401 挑战（或 200 = 开放仓库） */

  ret = ort_http_get(host, port, "/v2/", NULL, NULL,
                     g_http_body, sizeof(g_http_body), &r);
  if (ret != 0)
    {
      printf("[pull] 连不上 %s:%u（%d，errno=%d）\n", host, port, ret, errno);
      return 2;
    }

  printf("[pull] ① /v2/ → %d\n", r.status);

  if (r.status == 401)
    {
      attr_get(r.www_auth, "realm", realm, sizeof(realm));
      attr_get(r.www_auth, "service", service, sizeof(service));
      attr_get(r.www_auth, "scope", scope, sizeof(scope));
      printf("[pull]    挑战: realm=%s service=%s scope=%s\n",
             realm[0] ? realm : "(无)", service[0] ? service : "(无)",
             scope[0] ? scope : "(无)");

      /* 2) token 端点：真流程拿 token；scope 缺省时按 repo 构造 */

      {
        static char thost[64], tpath[160];
        static char q[320];
        unsigned tport = 80;
        char *sc = scope[0] ? scope : NULL;
        static char scbuf[160];

        if (sc == NULL)
          {
            snprintf(scbuf, sizeof(scbuf), "repository:%s:pull", repo);
            sc = scbuf;
          }

        if (url_split(realm, thost, sizeof(thost), &tport,
                      tpath, sizeof(tpath)) != 0)
          {
            printf("[pull] realm 解析失败\n");
            return 2;
          }

        snprintf(q, sizeof(q), "%s?service=%s&scope=%s", tpath, service, sc);

        ret = ort_http_get(thost, tport, q, NULL, NULL,
                           g_http_body, sizeof(g_http_body), &r);
        if (ret != 0)
          {
            printf("[pull] token 端点不可达（%d）\n", ret);
            return 2;
          }

        printf("[pull] ② token → %d\n", r.status);

        ret = ort_json_get_str(g_http_body, r.body_len, "token",
                               g_token, sizeof(g_token));
        if (ret != ORT_JSON_OK)
          {
            printf("[pull] token 提取失败: %s\n", ort_json_strerror(ret));
            return 1;
          }

        printf("[pull]    token 长度=%zu\n", strlen(g_token));
      }
    }
  else if (r.status != 200)
    {
      printf("[pull] /v2/ 异常状态 %d\n", r.status);
      return 1;
    }

  /* 3) 取 manifest（按 tag）——先当 index 试，再当 manifest 试 */

  snprintf(path, sizeof(path), "/v2/%s/manifests/%s", repo, tag);

  ret = ort_http_get(host, port, path, g_token[0] ? g_token : NULL,
                     "application/vnd.oci.image.index.v1+json, "
                     "application/vnd.oci.image.manifest.v1+json",
                     g_http_body, sizeof(g_http_body), &r);
  if (ret != 0)
    {
      printf("[pull] manifest 请求失败（%d）\n", ret);
      return 2;
    }

  printf("[pull] ③ %s → %d（%zu 字节%s%s）\n", path, r.status, r.body_len,
         r.chunked ? "，chunked 已解码" : "",
         r.redirects ? "，经重定向" : "");

  /* [§90] 大响应 fail-closed：此前超缓冲**静默截断**喂给解析器
   * （症状 = 没头没脑的解析错）；现在显式拒绝并报边界。 */

  if (r.body_truncated)
    {
      printf("[pull] *** manifest 响应超过缓冲（%zu 字节封顶）—— 拒绝继续 ***\n",
             sizeof(g_http_body));
      return 1;
    }

  if (r.status != 200)
    {
      printf("[pull]    拒绝: %s\n", g_http_body);
      return 1;
    }

  ret = ort_index_parse(g_http_body, r.body_len, &g_idx);
  if (ret == ORT_JSON_OK)
    {
      uint32_t i;
      int picked = -1;

      printf("[pull]    是 image index：%u 条\n", (unsigned)g_idx.nentries);
      for (i = 0; i < g_idx.nentries; i++)
        {
          printf("[pull]      [%u] %s %s/%s%s%s\n", (unsigned)i,
                 g_idx.entries[i].digest,
                 g_idx.entries[i].os, g_idx.entries[i].arch,
                 g_idx.entries[i].variant[0] ? "/" : "",
                 g_idx.entries[i].variant);

          if (picked < 0 && strcmp(g_idx.entries[i].os, "linux") == 0 &&
              strcmp(g_idx.entries[i].arch, "arm") == 0)
            {
              picked = (int)i;
            }
        }

      if (picked < 0)
        {
          printf("[pull]    没有 linux/arm 条目\n");
          return 1;
        }

      printf("[pull]    选 [%d]（linux/arm）→ 按 digest 再取\n", picked);

      snprintf(path, sizeof(path), "/v2/%s/manifests/%s", repo,
               g_idx.entries[picked].digest);

      ret = ort_http_get(host, port, path, g_token[0] ? g_token : NULL,
                         "application/vnd.oci.image.manifest.v1+json",
                         g_http_body2, sizeof(g_http_body2), &r);
      if (ret != 0 || r.status != 200)
        {
          printf("[pull]    digest 取回失败（%d/%d）\n", ret, r.status);
          return 2;
        }

      if (r.body_truncated)
        {
          printf("[pull] *** manifest 响应超过缓冲（%zu 字节封顶）—— 拒绝继续 ***\n",
                 sizeof(g_http_body2));
          return 1;
        }

      printf("[pull] ④ digest manifest → 200（%zu 字节%s%s）\n", r.body_len,
             r.chunked ? "，chunked 已解码" : "",
             r.redirects ? "，经重定向" : "");
      step = 1;
    }
  else if (ret == ORT_JSON_E_REQUIRED)
    {
      printf("[pull]    不是 index，直接当 image manifest\n");
      memcpy(g_http_body2, g_http_body, r.body_len);
      step = 1;
    }
  else
    {
      printf("[pull]    index 解析报 %s\n", ort_json_strerror(ret));
      return 1;
    }

  /* 4) 最终 manifest */

  if (step)
    {
      ret = ort_manifest_parse(g_http_body2, r.body_len, &g_mf);
      if (ret != ORT_JSON_OK)
        {
          /* index 路径下 body2 长度是重新取的 r.body_len；manifest 直取路径
           * 下 memcpy 过一份、长度相同 —— 两条路共用这一段 */
          printf("[pull] manifest 解析失败: %s\n", ort_json_strerror(ret));
          return 1;
        }

      printf("[pull] ⑤ manifest: schema=%u 层数=%u（跳过未知字段 %u）\n",
             (unsigned)g_mf.schema_version, (unsigned)g_mf.nlayers,
             (unsigned)g_mf.ignored_fields);
      printf("[pull]    config %s (%llu)\n", g_mf.config_digest,
             (unsigned long long)g_mf.config_size);

      {
        uint32_t i;

        for (i = 0; i < g_mf.nlayers; i++)
          {
            printf("[pull]    layer[%u] %s (%llu)\n", (unsigned)i,
                   g_mf.layers[i].digest,
                   (unsigned long long)g_mf.layers[i].size);
          }
      }

      /* ⑥ 层体下载 + 内容寻址校验 + 落盘（A1 第三步） */

      {
        uint32_t i;

        for (i = 0; i < g_mf.nlayers; i++)
          {
            int r;

            if (i >= 8)
              {
                printf("[pull]    （层数 %u 超原型上限 8，其余未下载）\n",
                       (unsigned)g_mf.nlayers);
                break;
              }

            r = blob_download(host, port, repo,
                              g_token[0] ? g_token : NULL,
                              g_mf.layers[i].digest, g_mf.layers[i].size,
                              "layer.tar", "⑥");
            if (r != 0)
              {
                printf("[pull]    layer[%u] 未通过（r=%d）→ pull 失败\n",
                       (unsigned)i, r);
                return 1;
              }
          }
      }

      /* ⑦ 层体解包 → rootfs（OCI 覆盖/whiteout 语义：后层盖前层） */

      {
        static char rootfs[256];
        char rs[160];
        size_t k = 0;
        uint32_t i;

        while (repo[k] != '\0' && k < sizeof(rs) - 1)
          {
            rs[k] = (repo[k] == '/') ? '_' : repo[k];
            k++;
          }

        rs[k] = '\0';

        if (snprintf(rootfs, sizeof(rootfs), ORT_STORE_ROOT "/rootfs/%s@%s",
                     rs, tag) >= (int)sizeof(rootfs))
          {
            printf("[pull]    rootfs 路径过长（repo/tag 请短些）\n");
            return 2;
          }

        for (i = 0; i < g_mf.nlayers && i < 8; i++)
          {
            static char lp[300];
            FAR const char *hex2 = g_mf.layers[i].digest;

            if (strncmp(hex2, "sha256:", 7) == 0)
              {
                hex2 += 7;
              }

            snprintf(lp, sizeof(lp),
                     ORT_STORE_ROOT "/images/sha256/%s/layer.tar", hex2);

            printf("[pull] ⑦ 应用层[%u] → %s\n", (unsigned)i, rootfs);
            if (do_tar_apply(lp, rootfs) != 0)
              {
                printf("[pull]    层[%u]应用失败 → pull 失败\n", (unsigned)i);
                return 1;
              }
          }

        printf("[pull]    rootfs: %s\n", rootfs);
      }

      /* ⑧ 配置 blob 下载 + 解析（A2 起步：运行时要跑什么 —— Entrypoint/
       *    Cmd/Env/WorkingDir）。路径与层同一条：内容寻址校验 + 原子落盘；
       *    解析走白名单解析器（有界、超界报错不截断）。 */

      {
        FAR const char *hex3 = g_mf.config_digest;
        static char cfgp[320];
        size_t clen = 0;
        int r8;

        r8 = blob_download(host, port, repo,
                           g_token[0] ? g_token : NULL,
                           g_mf.config_digest, g_mf.config_size,
                           "config.json", "⑧");
        if (r8 != 0)
          {
            printf("[pull]    配置体未通过（r=%d）→ pull 失败\n", r8);
            return 1;
          }

        if (strncmp(hex3, "sha256:", 7) == 0)
          {
            hex3 += 7;
          }

        snprintf(cfgp, sizeof(cfgp),
                 ORT_STORE_ROOT "/images/sha256/%s/config.json", hex3);

        if (read_file(cfgp, &clen) != 0)
          {
            return 1;
          }

        r8 = ort_config_parse(g_buf, clen, &g_cfg);
        if (r8 != ORT_JSON_OK)
          {
            printf("[pull]    配置解析失败: %s（%zu 字节）\n",
                   ort_json_strerror(r8), clen);
            return 1;
          }

        config_dump(stdout, "[pull] ⑧ ", "[pull]    ", &g_cfg);
      }

      printf("[pull] PULL RESULT: OK\n");
    }

  return 0;
}

/* [ORT §92] 证书验证 flags：回调里记下（错 CA / 未生效 / 过期可
 * 判别——负臂判据的关键细节；mbedtls 默认把 X509 细节吞成一句
 * "verification failed"）。 */

#define ORT_TLS_CA_MAX 4096
static char     g_tls_ca_buf[ORT_TLS_CA_MAX];
static uint32_t g_tls_verify_flags;
static char     g_tls_wwwauth[256];   /* [§93] 真 Hub 挑战头见证 */

static int httpsget_verify_cb(FAR void *data,
                              FAR mbedtls_x509_crt *crt, int depth,
                              uint32_t *flags)
{
  (void)data;
  (void)crt;
  (void)depth;

  g_tls_verify_flags |= *flags;  /* ★ OR 累积：回调按证书逐个调用，
                                  * 直接赋值会被后一次的 0 覆盖
                                  * （rogue-CA 臂实测踩过） */
  return 0;                      /* 让 mbedtls 按 flags 决断 */
}

/****************************************************************************
 * [ORT §91] httpsget <host> <port> <path> —— TLS 客户端（mbedTLS）
 *
 *   判据面：握手见证（TLS 版本/密码套件，mbedtls 自报）+ 响应体
 *   **边读边算 sha256**（与宿主对同一文件算的摘要逐字比——TLS 录音
 *   解密错一字节就露）。
 *
 *   ⚠️ 边界（如实）：`MBEDTLS_SSL_VERIFY_NONE` —— 自签测试服务器；
 *   证书链校验与时间校验**未开**（真 Hub 需要 CA 池 + 有效时钟，
 *   两个补丁已随源就位、留待对接轮）。本子命令证明的是**传输层**：
 *   真加密会话能建、数据能解、字节不差。
 ****************************************************************************/

static int do_httpsget(FAR const char *host, unsigned port,
                       FAR const char *path, FAR const char *capath)
{
  /* ★ 全部静态：目标机 app 栈 ~2KB，TLS 上下文放栈上必炸 */

  static mbedtls_ssl_context      ssl;
  static mbedtls_ssl_config       conf;
  static mbedtls_entropy_context  entropy;
  static mbedtls_ctr_drbg_context drbg;
  static mbedtls_net_context      srv;
  static mbedtls_x509_crt         ca;
  static char rbuf[1024];
  char portstr[8];
  char req[512];
  struct ort_sha256_s ctx;
  uint8_t raw[32];
  char    hex[65];
  size_t  total = 0;
  int     status = 0;
  int     hdr_done = 0;         /* 头已结束（其后都是体） */
  int     ret;

  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&drbg);
  mbedtls_net_init(&srv);
  mbedtls_x509_crt_init(&ca);

  snprintf(portstr, sizeof(portstr), "%u", port);

  ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                              (FAR const unsigned char *)"orting", 6);
  if (ret != 0)
    {
      printf("[httpsget] *** drbg seed 失败: -0x%04x ***\n", -ret);
      goto out;
    }

  ret = mbedtls_net_connect(&srv, host, portstr, MBEDTLS_NET_PROTO_TCP);
  if (ret != 0)
    {
      printf("[httpsget] *** 连接失败: -0x%04x ***\n", -ret);
      goto out;
    }

  ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0)
    {
      printf("[httpsget] *** ssl 默认配置失败: -0x%04x ***\n", -ret);
      goto out;
    }

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
  mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);

  /* [ORT §92] 给了 CA 路径 ⇒ 正验：VERIFY_REQUIRED + CA 链 + 回调记
   * flags；没给 ⇒ 维持 §91 的 VERIFY_NONE（过渡臂，如实标注）。 */

  if (capath != NULL)
    {
      FAR FILE *cf = fopen(capath, "rb");
      size_t    n;

      if (cf == NULL)
        {
          printf("[httpsget] *** 打不开 CA 文件: %s（errno=%d）***\n",
                 capath, errno);
          ret = -1;
          goto out;
        }

      n = fread(g_tls_ca_buf, 1, sizeof(g_tls_ca_buf) - 1, cf);
      fclose(cf);
      g_tls_ca_buf[n] = '\0';

      ret = mbedtls_x509_crt_parse(&ca,
                                   (FAR const unsigned char *)g_tls_ca_buf,
                                   n + 1);
      if (ret != 0)
        {
          printf("[httpsget] *** CA 解析失败: -0x%04x ***\n", -ret);
          goto out;
        }

      mbedtls_ssl_conf_ca_chain(&conf, &ca, NULL);
      mbedtls_ssl_conf_verify(&conf, httpsget_verify_cb, NULL);
      mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    }
  else
    {
      mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    }

  ret = mbedtls_ssl_setup(&ssl, &conf);
  if (ret != 0)
    {
      printf("[httpsget] *** ssl setup 失败: -0x%04x ***\n", -ret);
      goto out;
    }

  mbedtls_ssl_set_hostname(&ssl, host);
  mbedtls_ssl_set_bio(&ssl, &srv, mbedtls_net_send, mbedtls_net_recv, NULL);

  g_tls_verify_flags = 0;        /* 握手前清零（配合回调的 OR） */
  g_tls_wwwauth[0]    = '\0';

  for (;;)
    {
      ret = mbedtls_ssl_handshake(&ssl);
      if (ret == 0)
        {
          break;
        }

      if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
          ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
          char ebuf[96];

          mbedtls_strerror(ret, ebuf, sizeof(ebuf));

          if (capath != NULL && ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
            {
              printf("[httpsget] *** 认证失败: -0x%04x（flags=0x%02x %s）***\n",
                     -ret, (unsigned)g_tls_verify_flags, ebuf);
            }
          else
            {
              printf("[httpsget] *** 握手失败: -0x%04x（%s）***\n",
                     -ret, ebuf);
            }

          goto out;
        }
    }

  printf("[httpsget] TLS 握手完成: %s / %s\n",
         mbedtls_ssl_get_version(&ssl), mbedtls_ssl_get_ciphersuite(&ssl));
  if (capath != NULL)
    {
      printf("[httpsget] 认证: OK（CA 链校验通过）\n");
    }

  snprintf(req, sizeof(req),
           "GET %s HTTP/1.0\r\n"
           "Host: %s:%u\r\n"
           "Connection: close\r\n"
           "\r\n", path, host, port);

  {
    size_t off = 0;

    while (off < strlen(req))
      {
        ret = mbedtls_ssl_write(&ssl, (FAR const unsigned char *)req + off,
                                strlen(req) - off);
        if (ret > 0)
          {
            off += (size_t)ret;
          }
        else if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                 ret != MBEDTLS_ERR_SSL_WANT_WRITE)
          {
            printf("[httpsget] *** 请求发送失败: -0x%04x ***\n", -ret);
            goto out;
          }
      }
  }

  ort_sha256_init(&ctx);

  {
    uint32_t h4   = 0;            /* 4 字节移位寄存器：扫 "\r\n\r\n" */
    char     stbuf[256];
    size_t   stlen = 0;
    bool     stline_done = false;

    for (;;)
      {
        ret = mbedtls_ssl_read(&ssl, (FAR unsigned char *)rbuf, sizeof(rbuf));
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
          {
            continue;
          }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0)
          {
            break;                 /* close_notify / EOF = 正常收尾 */
          }

        if (ret < 0)
          {
            printf("[httpsget] *** 读取失败: -0x%04x ***\n", -ret);
            goto out;
          }

        {
          size_t n = (size_t)ret;
          size_t i = 0;

          while (i < n)
            {
              char c = rbuf[i++];

              if (!hdr_done)
                {
                  /* 首行收集（状态行；到 \n 为止）；

                   * [§93] 顺带把 WWW-Authenticate 头收下来（真 Hub 的
                   * 挑战头是"对接成功"的一等见证）。 */

                  if (!stline_done)
                    {
                      if (c != '\n' && stlen < sizeof(stbuf) - 1)
                        {
                          stbuf[stlen++] = c;
                        }
                      else
                        {
                          FAR const char *sp;

                          stbuf[stlen] = '\0';
                          sp = strchr(stbuf, ' ');
                          if (sp != NULL)
                            {
                              status = atoi(sp + 1);
                            }

                          stline_done = true;
                        }
                    }
                  else if (c == '\n' || stlen >= sizeof(stbuf) - 1)
                    {
                      /* 一行收齐：行末处理（复用 stbuf 收头行） */

                      stbuf[stlen] = '\0';

                      if (strncasecmp(stbuf, "WWW-Authenticate:", 17) == 0)
                        {
                          FAR const char *v = stbuf + 17;

                          while (*v == ' ')
                            {
                              v++;
                            }

                          strlcpy(g_tls_wwwauth, v,
                                  sizeof(g_tls_wwwauth));
                        }

                      stlen = 0;
                    }
                  else if (c != '\r')
                    {
                      stbuf[stlen++] = c;
                    }

                  h4 = (h4 << 8) | (unsigned char)c;
                  if (h4 == 0x0d0a0d0au)
                    {
                      hdr_done = true;   /* 头结束：其后都是体 */
                      break;             /* i 已越过结尾 \n */
                    }
                }
              else
                {
                  i--;                   /* 归位：整块余下都是体 */
                  break;
                }
            }

          if (hdr_done && i < n)
            {
              ort_sha256_update(&ctx, rbuf + i, n - i);
              total += n - i;
            }
        }
      }
  }

  ort_sha256_final(&ctx, raw);
  ort_sha256_hex(raw, hex);

  printf("[httpsget] → %d（体 %zu 字节）\n", status, total);
  if (g_tls_wwwauth[0])
    {
      printf("[httpsget] WWW-Authenticate: %s\n", g_tls_wwwauth);
    }

  if (status == 200 && total > 0)
    {
      printf("[httpsget] body sha256=%s\n", hex);
    }

  ret = 0;

out:
  mbedtls_ssl_close_notify(&ssl);
  mbedtls_x509_crt_free(&ca);
  mbedtls_net_free(&srv);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&drbg);
  mbedtls_entropy_free(&entropy);
  return ret == 0 ? 0 : 2;
}

int main(int argc, FAR char *argv[])
{

  g_buf = malloc(ORTIMG_MAX_FILE);
  if (g_buf == NULL)
    {
      printf("[ortimg] 没有内存\n");
      return 2;
    }

  if (argc >= 2 && strcmp(argv[1], "jsontest") == 0)
    {
      int fails = ort_battery_run(stdout);

      printf("[ortimg] JSONTEST RESULT: %s（%u 用例 + 2 特殊例）\n",
             fails == 0 ? "PASS" : "*** FAIL ***",
             (unsigned)(ORT_NCASES + ORT_NSTRCASES + ORT_NIDXCASES +
                        ORT_NCFGCASES));
      free(g_buf);
      return fails == 0 ? 0 : 1;
    }

  if (argc >= 2 && strcmp(argv[1], "shatest") == 0)
    {
      int fails = ort_hash_battery_run(stdout);

      printf("[ortimg] SHATEST RESULT: %s（%u 用例 + %u 特殊例）\n",
             fails == 0 ? "PASS" : "*** FAIL ***",
             (unsigned)ORT_NHASHCASES, (unsigned)ORT_NHASHSPECIAL);
      free(g_buf);
      return fails == 0 ? 0 : 1;
    }

  if (argc >= 2 && strcmp(argv[1], "tartest") == 0)
    {
      int fails = ort_tar_battery_run(stdout);

      printf("[ortimg] TARTEST RESULT: %s（%u 用例）\n",
             fails == 0 ? "PASS" : "*** FAIL ***",
             (unsigned)ORT_NTARCASES);
      free(g_buf);
      return fails == 0 ? 0 : 1;
    }

  if (argc >= 3 && strcmp(argv[1], "sha") == 0)
    {
      int r = do_sha(argv[2]);

      free(g_buf);
      return r;
    }

  if (argc >= 4 && strcmp(argv[1], "untar") == 0)
    {
      int r = do_tar_apply(argv[2], argv[3]);

      free(g_buf);
      return r;
    }

  if (argc >= 3 && strcmp(argv[1], "lsroot") == 0)
    {
      int r = do_lsroot(argv[2]);

      free(g_buf);
      return r;
    }

  if (argc >= 3 && strcmp(argv[1], "manifest") == 0)
    {
      int r = do_manifest(argv[2]);
      free(g_buf);
      return r;
    }

  if (argc >= 3 && strcmp(argv[1], "config") == 0)
    {
      int r = do_config(argv[2]);
      free(g_buf);
      return r;
    }

  if (argc >= 4 && strcmp(argv[1], "run") == 0)
    {
      /* run <view> <config> —— 照着 config 起进程 */
      int r = do_run(argv[2], argv[3]);
      free(g_buf);
      return r;
    }

  if (argc >= 7 && strcmp(argv[1], "up") == 0)
    {
      /* up <view> <host> <port> <repo> <tag> —— pull+组装+挂载 一条命令 */
      int r = do_up(argv[2], argv[3], (unsigned)atoi(argv[4]), argv[5],
                    argv[6]);
      free(g_buf);
      return r;
    }

  if (argc >= 7 && strcmp(argv[1], "start") == 0)
    {
      /* start <view> <host> <port> <repo> <tag> —— up+run 一条命令 */
      int r = do_start(argv[2], argv[3], (unsigned)atoi(argv[4]), argv[5],
                       argv[6]);
      free(g_buf);
      return r;
    }

  if (argc >= 3 && strcmp(argv[1], "down") == 0)
    {
      /* down <view> —— 卸载视图 */
      int r = do_down(argv[2]);
      free(g_buf);
      return r;
    }

  if (argc >= 6 && strcmp(argv[1], "lim") == 0)
    {
      /* lim <view> <cpu-list> <prio> <cfg1> [cfg2 ...] —— 核集+优先级 */
      int r = do_lim(argv[2], argv[3], atoi(argv[4]), argc - 5, &argv[5]);
      free(g_buf);
      return r;
    }

  if (argc >= 5 && strcmp(argv[1], "memcap") == 0)
    {
      /* memcap <view> <KB> <cfg1> [cfg2 ...] —— 派生进程堆上限 */
      int r = do_memcap(argv[2], atoi(argv[3]), argc - 4, &argv[4]);
      free(g_buf);
      return r;
    }

  if (argc >= 4 && strcmp(argv[1], "sup") == 0)
    {
      /* sup <view> <config1> [config2 ...] —— 运行时兼任监督者 */
      int r = do_sup(argv[2], argc - 3, &argv[3]);
      free(g_buf);
      return r;
    }

  if (argc >= 4 && strcmp(argv[1], "par") == 0)
    {
      /* par <view> <config1> [config2 ...] —— 并发判别（配对压力） */
      int r = do_par(argv[2], argc - 3, &argv[3]);
      free(g_buf);
      return r;
    }

  if (argc >= 3 && strcmp(argv[1], "supd") == 0)
    {
      /* supd <秒> —— 长驻监督者（与派生者解耦；建议后台 &） */
      int r = do_supd(atoi(argv[2]));
      free(g_buf);
      return r;
    }

  if (argc >= 5 && strcmp(argv[1], "orch") == 0)
    {
      /* orch <秒> <view> <cfg1> [cfg2 ...] —— 多服务编排环 */
      int r = do_orch(atoi(argv[2]), argv[3], argc - 4, &argv[4]);
      free(g_buf);
      return r;
    }

  if (argc >= 3 && strcmp(argv[1], "validate") == 0)
    {
      int r = do_validate(argv[2]);
      free(g_buf);
      return r;
    }

  if (argc >= 5 && strcmp(argv[1], "httpsget") == 0)
    {
      /* httpsget <host> <port> <path> —— TLS 客户端（§91） */
      int r = do_httpsget(argv[2], (unsigned)atoi(argv[3]), argv[4],
                          argc >= 6 ? argv[5] : NULL);

      free(g_buf);
      return r;
    }

  if (argc >= 3 && strcmp(argv[1], "settime") == 0)
    {
      /* [ORT §92] settime <epoch 秒> —— 对时（nsh 的 date 被裁；
       * 证书有效期校验要有有效时钟才活着）。 */

      struct timespec ts;

      ts.tv_sec  = (time_t)atoll(argv[2]);
      ts.tv_nsec = 0;

      {
        int r = clock_settime(CLOCK_REALTIME, &ts);

        printf("[settime] 时钟 → %lld（clock_settime=%d）\n",
               (long long)ts.tv_sec, r);
        free(g_buf);
        return r == 0 ? 0 : 2;
      }
    }

  if (argc >= 5 && strcmp(argv[1], "httpget") == 0)
    {
      /* httpget <host> <port> <path> —— 连通性诊断 */
      struct ort_http_resp_s r;
      int rret = ort_http_get(argv[2], (unsigned)atoi(argv[3]), argv[4],
                              NULL, NULL, g_http_body, sizeof(g_http_body),
                              &r);

      if (rret != 0)
        {
          printf("[ortimg] httpget 传输失败（%d，errno=%d）\n", rret, errno);
          free(g_buf);
          return 2;
        }

      printf("[ortimg] httpget → %d（体 %zu 字节%s%s）\n", r.status,
             r.body_len, r.body_truncated ? "，截断" : "",
             r.chunked ? "，chunked 已解码" : "");
      if (r.redirects)
        {
          printf("[ortimg] 重定向 %d 跳 → %s\n", r.redirects, r.location);
        }
      if (r.www_auth[0])
        {
          printf("[ortimg] WWW-Authenticate: %s\n", r.www_auth);
        }
      if (r.status == 200 && r.body_len > 0 && !r.body_truncated)
        {
          /* [§90] 体摘要见证：chunked/重定向解码正确的**逐字节判据**
           * （与宿主侧对同一文件算的摘要直接比） */

          uint8_t raw[32];
          char    hex[65];
          struct ort_sha256_s ctx;

          ort_sha256_init(&ctx);
          ort_sha256_update(&ctx, g_http_body, r.body_len);
          ort_sha256_final(&ctx, raw);
          ort_sha256_hex(raw, hex);
          printf("[ortimg] body sha256=%s\n", hex);
        }
      free(g_buf);
      return 0;
    }

  if (argc >= 6 && strcmp(argv[1], "pull") == 0)
    {
      /* pull <host> <port> <repo> <tag> */
      int r = do_pull(argv[2], (unsigned)atoi(argv[3]), argv[4], argv[5]);
      free(g_buf);
      return r;
    }

  printf("用法: orting jsontest | shatest | tartest |\n"
         "      manifest <path> | config <path> | validate <path> |\n"
         "      sha <path> | untar <archive> <destdir> | lsroot <dir> |\n"
         "      run <view> <config> | down <view> |\n"
         "      lim <view> <cpu-list> <prio> <cfg1> [cfg2 ...] |\n"
         "      memcap <view> <KB> <cfg1> [cfg2 ...] |\n"
         "      up <view> <host> <port> <repo> <tag> |\n"
         "      start <view> <host> <port> <repo> <tag> |\n"
         "      sup <view> <config1> [config2 ...] |\n"
         "      par <view> <config1> [config2 ...] |\n"
         "      supd <秒> | orch <秒> <view> <cfg1> [cfg2 ...] |\n"
         "      httpget <host> <port> <path> | pull <host> <port> <repo> <tag>\n");
  free(g_buf);
  return 2;
}
