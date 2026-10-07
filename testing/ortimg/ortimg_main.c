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

#include "ort_json.h"
#include "ortimg_battery.h"
#include "ort_http.h"
#include "ort_sha256.h"
#include "ort_tar.h"

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

static char g_avbuf[2 * ORT_CFG_MAX_ARG][ORT_RUN_MAP_MAX];
static FAR char *g_argv[2 * ORT_CFG_MAX_ARG + 1];
static char g_pwdbuf[ORT_RUN_MAP_MAX + 64];
static FAR char *g_envp[ORT_CFG_MAX_ENV + 2];

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

static int do_run(FAR const char *view, FAR const char *path)
{
  struct stat vst;
  size_t len = 0;
  uint32_t i;
  int    na = 0;
  int    ne = 0;
  pid_t  pid;
  int    st;
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

  /* argv := entrypoint + cmd（OCI 语义），绝对路径按视图映射 */

  for (i = 0; i < g_cfg.nentrypoint; i++)
    {
      if (map_path(view, g_cfg.entrypoint[i], g_avbuf[na],
                   sizeof(g_avbuf[0])) != 0)
        {
          printf("[run] argv 映射超界（entrypoint[%u]）\n", (unsigned)i);
          return 1;
        }

      g_argv[na] = g_avbuf[na];
      na++;
    }

  for (i = 0; i < g_cfg.ncmd; i++)
    {
      if (map_path(view, g_cfg.cmd[i], g_avbuf[na],
                   sizeof(g_avbuf[0])) != 0)
        {
          printf("[run] argv 映射超界（cmd[%u]）\n", (unsigned)i);
          return 1;
        }

      g_argv[na] = g_avbuf[na];
      na++;
    }

  if (na == 0)
    {
      printf("[run] 无 argv（解析已保证不会发生）\n");
      return 1;
    }

  g_argv[na] = NULL;

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

      snprintf(g_pwdbuf, sizeof(g_pwdbuf), "PWD=%s", wdbuf);
      g_envp[ne++] = g_pwdbuf;
    }

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

  ret = posix_spawn(&pid, g_argv[0], NULL, NULL, g_argv, g_envp);
  if (ret != 0)
    {
      printf("[run] spawn 失败 rc=%d errno=%d\n", ret, errno);
      return 1;
    }

  printf("[run] spawned pid=%d\n", (int)pid);

  if (waitpid(pid, &st, 0) < 0)
    {
      printf("[run] waitpid 失败（errno=%d）\n", errno);
      return 1;
    }

  /* NuttX 的 wait 语义（§73 源码定案+实测）：status = exitcode << 8
   * （task_exithook.c），且"异常终止"的默认动作**就是** _exit(EXIT_FAILURE)
   * （sig_default.c）—— `WIFSIGNALED` 硬编码 false ⇒ **崩溃与 exit(1)
   * 在 waitpid 层面不可分**。如实按"退出码"报；==1 时带注记。
   * （容器崩溃的**可分**信号要另开通道 —— 见手册 §三·补七十三 边界。） */

  printf("[run] 退出码=%d%s\n", WEXITSTATUS(st),
         WEXITSTATUS(st) == 1
           ? "（=EXIT_FAILURE；NuttX 崩溃与 exit(1) 不可分——§73）" : "");
  return WEXITSTATUS(st) == 0 ? 0 : 1;
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

  printf("[pull]    收到 %zu 字节，算得 sha256:%s\n", d.n, got);

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

  printf("[pull] ③ %s → %d（%zu 字节）\n", path, r.status, r.body_len);
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

      printf("[pull] ④ digest manifest → 200（%zu 字节）\n", r.body_len);
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

  if (argc >= 3 && strcmp(argv[1], "validate") == 0)
    {
      int r = do_validate(argv[2]);
      free(g_buf);
      return r;
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

      printf("[ortimg] httpget → %d（体 %zu 字节%s）\n", r.status,
             r.body_len, r.body_truncated ? "，截断" : "");
      if (r.www_auth[0])
        {
          printf("[ortimg] WWW-Authenticate: %s\n", r.www_auth);
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
         "      up <view> <host> <port> <repo> <tag> |\n"
         "      start <view> <host> <port> <repo> <tag> |\n"
         "      httpget <host> <port> <path> | pull <host> <port> <repo> <tag>\n");
  free(g_buf);
  return 2;
}
