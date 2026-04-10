#!/usr/bin/env bash
set -euo pipefail

echo "注意：该脚本会删除本目录下的 test.id0/test.id1/test.id2/test.nam/test.til 临时文件。"

# 仅匹配 IDA 相关进程，避免误杀其它包含 ida 字样的进程
pids="$(pgrep -f '(/|^)ida(64)?\.exe( |$)' || true)"
if [[ -z "$pids" ]]; then
  pids="$(pgrep -f '(^|/)idat(64)?\.exe( |$)' || true)"
fi

if [[ -n "$pids" ]]; then
  echo "找到 IDA 进程：$pids"
  # shellcheck disable=SC2086
  kill $pids || true
  sleep 1

  # 仍存活则强杀
  still="$(pgrep -f '(/|^)ida(64)?\.exe( |$)|(^|/)idat(64)?\.exe( |$)' || true)"
  if [[ -n "$still" ]]; then
    echo "仍有进程存活，执行强制结束：$still"
    # shellcheck disable=SC2086
    kill -9 $still || true
  fi
  echo "已关闭 IDA 进程"
else
  echo "未找到 IDA 进程"
fi

test_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$test_dir"
rm -f test.id0 test.id1 test.id2 test.nam test.til

echo "清理完成"
echo "已清除 IDA 生成的临时文件"
