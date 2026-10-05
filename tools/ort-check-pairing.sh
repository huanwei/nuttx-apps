#!/bin/bash
# [ORT] 两仓库一致性检查（手册 §三·补五十五）
#
# 为什么要有它：nuttx 与 nuttx-apps 是**两个仓库、一条产品线** ——
# 漂移的症状全是"不报错"：
#   · apps 按**旧**导出头编译（如 app 知道 PR_GET_ORT_DOMCAP=28，
#     内核不认识）→ 运行期一个没上下文的 -EINVAL；
#   · 内核推进了、apps 侧没人重验 → 像 ② 那样（M 侧直接编译不过，
#     但直到某次重建才暴露）；
#   · CONFIG_ORT_* 两边开关集合漂移 → 两个 SKU 行为分叉没人知道。
#
# 模式：
#   默认（工作树模式，A 构建面）：查 export/import 的**新鲜度**
#     ① import/include/sys/prctl.h == nuttx/include/sys/prctl.h（逐字）
#     ② import/.ort-kernel-commit == nuttx HEAD（戳由 orta-build.sh 写）
#     ③ nuttx/.config 与 import/.config 的 CONFIG_ORT_* 集合一致
#   --ci（干净检出模式）：
#     ④ tools/ort-pairing.txt 的 nuttx= == 远端内核分支 tip
#     ⑤ 本次推送的 HEAD 必须**动过**配对记录（每次发布=一次配对声明）
#
# 退出码：0 全过；非 0 有失败（逐条给出修法）。
set -u

MODE="${1:-}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"     # nuttx-apps/tools
APPS="$(cd "$HERE/.." && pwd)"
NUTTX="${ORT_NUTTX:-$(cd "$APPS/.." && pwd)/nuttx}"

fail=0
say() { printf '%s\n' "$*"; }

if [ "$MODE" = "--ci" ]; then
  P="$APPS/tools/ort-pairing.txt"
  if [ ! -f "$P" ]; then
    say "FAIL: 缺 tools/ort-pairing.txt（配对记录）"; exit 1
  fi

  rec_n="$(sed -n 's/^nuttx=//p' "$P" | head -1)"
  tip_n="$(git -C "$NUTTX" rev-parse HEAD)"

  if [ "$tip_n" = "$rec_n" ]; then
    say "OK  : ④ nuttx tip == 配对记录（$rec_n）"
  else
    say "FAIL: ④ nuttx tip=$tip_n != 配对记录 nuttx=$rec_n"
    say "      内核推进了 —— 更新 tools/ort-pairing.txt 并提交（app 侧）"
    fail=1
  fi

  if git -C "$APPS" show --name-only --format= HEAD | grep -q '^tools/ort-pairing\.txt$'; then
    say "OK  : ⑤ 本次推送 HEAD 动过配对记录"
  else
    say "FAIL: ⑤ 本次推送 HEAD 未动配对记录 —— 每次推 apps 都要把"
    say "      nuttx= 更新到当前内核 tip（一次推送 = 一次配对声明）"
    fail=1
  fi

  exit $fail
fi

# ── 工作树模式（A 构建面）────────────────────────────────────────────────

SRC_H="$NUTTX/include/sys/prctl.h"
IMP_H="$APPS/import/include/sys/prctl.h"
STAMP="$APPS/import/.ort-kernel-commit"

if [ ! -f "$IMP_H" ]; then
  say "SKIP: 未走 A 流程（无 import/ 产物；M 构建面不适用本检查）"
  exit 0
fi

if cmp -s "$SRC_H" "$IMP_H"; then
  say "OK  : ① prctl.h 源与 import 逐字一致"
else
  say "FAIL: ① import/include/sys/prctl.h 落后于 nuttx/include/sys/prctl.h"
  say "      （apps 会按旧 ABI 编译 —— 重跑 orta-build.sh）"
  fail=1
fi

head_nuttx="$(git -C "$NUTTX" rev-parse HEAD)"
if [ ! -f "$STAMP" ]; then
  say "FAIL: ② import/ 产物存在但**没有配对戳** —— 不是经 orta-build.sh"
  say "      构建的（绕过脚本 = 无法判断 export 新鲜度；重跑 orta-build.sh）"
  fail=1
else
  stamp="$(head -1 "$STAMP")"
  if [ "$head_nuttx" = "$stamp" ]; then
    say "OK  : ② import 戳 == nuttx HEAD（$stamp）"
  else
    say "FAIL: ② 戳=$stamp，nuttx HEAD=$head_nuttx（内核变了没重导出）"
    say "      （重跑 orta-build.sh，它会带出 export+mkimport 并刷新戳）"
    fail=1
  fi
fi

if diff <(grep -E '^(# )?CONFIG_ORT' "$NUTTX/.config" | sort) \
        <(grep -E '^(# )?CONFIG_ORT' "$APPS/import/.config" | sort) >/dev/null; then
  say "OK  : ③ CONFIG_ORT_* 集合一致"
else
  say "FAIL: ③ nuttx/.config 与 import/.config 的 CONFIG_ORT_* 集合不一致"
  say "      （重跑 export + mkimport，注意 mkimport 会覆盖 import/.config）"
  fail=1
fi

exit $fail
