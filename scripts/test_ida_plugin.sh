#!/usr/bin/env bash
set -euo pipefail

# -------------------------
# pwn-agent IDA 插件自动化冒烟测试
# -------------------------
# 目标：
# 1) 插件是否被 IDA 成功加载（哨兵文件）
# 2) 自动触发分析是否成功生成 quick-* 报告
# 3) 测试结束后自动关闭 IDA 进程

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IDA64="/home/xuanyuan/Ws/sec/tools/ctf/IDA/ida64.exe"
TARGET_DEFAULT="/home/xuanyuan/Ws/sec/ctf/active/workspace/pwn1.i64"
TARGET="${1:-$TARGET_DEFAULT}"
TASKS_DIR="$ROOT/tasks"
SENTINEL="/tmp/pwn-agent.plugin.loaded"
MARKER="/tmp/pwn-agent.marker.log"

if [[ ! -f "$IDA64" ]]; then
  echo "[-] ida64.exe not found: $IDA64" >&2
  exit 1
fi
if [[ ! -f "$TARGET" ]]; then
  echo "[-] Target not found: $TARGET" >&2
  exit 1
fi

# 安全保护：避免干扰用户正在进行的 IDA 会话
if pgrep -fa 'ida64\.exe|ida\.exe|idat64\.exe|idat\.exe' >/dev/null; then
  echo "[-] Existing IDA process detected. Please close IDA first, then rerun." >&2
  pgrep -fa 'ida64\.exe|ida\.exe|idat64\.exe|idat\.exe' || true
  exit 2
fi

bash "$ROOT/scripts/install_ida_plugin.sh"

BEFORE_LIST="$(mktemp)"
ls -1 "$TASKS_DIR" 2>/dev/null | grep '^quick-' > "$BEFORE_LIST" || true

LOG_FILE="/tmp/pwn-agent-ida-test.$(date +%s).log"
rm -f "$SENTINEL" "$MARKER"

echo "[*] Launching IDA for plugin autorun test..."
# 清理 Python 环境变量，减少 Wine + IDAPython 冲突
unset PYTHONHOME PYTHONPATH VIRTUAL_ENV CONDA_PREFIX CONDA_DEFAULT_ENV

PWN_AGENT_ROOT="$ROOT" \
PWN_AGENT_AUTORUN=1 \
PWN_AGENT_SENTINEL="$SENTINEL" \
PWN_AGENT_TEST_MARKER="$MARKER" \
WINEDEBUG=-all \
wine "$IDA64" "$TARGET" >"$LOG_FILE" 2>&1 &

# 等待插件加载 + 后台分析完成
sleep 35

if [[ ! -f "$SENTINEL" ]]; then
  echo "[-] FAIL: plugin sentinel not found: $SENTINEL"
  echo "--- IDA log tail ---"
  tail -n 120 "$LOG_FILE" || true
  echo "--- marker ---"
  cat "$MARKER" 2>/dev/null || true
  pkill -f 'ida64\.exe|ida\.exe|idat64\.exe|idat\.exe' || true
  pkill -f wineserver || true
  exit 3
fi

AFTER_LIST="$(mktemp)"
ls -1 "$TASKS_DIR" 2>/dev/null | grep '^quick-' > "$AFTER_LIST" || true
NEW_TASK="$(comm -13 "$BEFORE_LIST" "$AFTER_LIST" | tail -n1 || true)"

if [[ -z "$NEW_TASK" ]]; then
  echo "[-] FAIL: plugin loaded but no new quick-* task generated"
  echo "--- sentinel ---"
  cat "$SENTINEL" || true
  echo "--- marker ---"
  cat "$MARKER" 2>/dev/null || true
  echo "--- IDA log tail ---"
  tail -n 120 "$LOG_FILE" || true
  pkill -f 'ida64\.exe|ida\.exe|idat64\.exe|idat\.exe' || true
  pkill -f wineserver || true
  exit 4
fi

REPORT_MD="$TASKS_DIR/$NEW_TASK/final_report.md"
if [[ ! -f "$REPORT_MD" ]]; then
  echo "[-] FAIL: task created but final_report.md missing: $REPORT_MD"
  pkill -f 'ida64\.exe|ida\.exe|idat64\.exe|idat\.exe' || true
  pkill -f wineserver || true
  exit 5
fi

echo "[+] PASS: plugin triggered backend pipeline"
echo "    task: $NEW_TASK"
echo "    report: $REPORT_MD"
echo "    sentinel: $SENTINEL"

echo "[*] Closing IDA test instance..."
pkill -f 'ida64\.exe|ida\.exe|idat64\.exe|idat\.exe' || true
pkill -f wineserver || true
sleep 2

echo "[+] Done"
