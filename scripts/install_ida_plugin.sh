#!/usr/bin/env bash
set -euo pipefail

# 将 pwn-agent 插件以软链接方式安装到 IDA 插件目录。
# 好处：后续改代码无需重复复制文件。

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_SRC="$ROOT/ida_plugin/pwn_agent_ida_plugin.py"
IDA_USER_PLUGIN_DIR="$HOME/Ws/sec/tools/ctf/IDA/plugins/"
PLUGIN_DST="$IDA_USER_PLUGIN_DIR/pwn_agent_ida_plugin.py"

mkdir -p "$IDA_USER_PLUGIN_DIR"
ln -sfn "$PLUGIN_SRC" "$PLUGIN_DST"

echo "Installed symlink: $PLUGIN_DST -> $PLUGIN_SRC"
echo "建议在启动 IDA 前设置（可写入 shell rc）："
echo "  export PWN_AGENT_ROOT=$ROOT"
