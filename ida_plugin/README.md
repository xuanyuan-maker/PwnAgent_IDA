# ida_plugin

当前已提供：
- `pwn_agent_ida_plugin.py`：IDA 热键入口（Ctrl+Shift+A），触发后端 `quick-run` 全流程并输出 markdown 路径。

当前分析流会：
- 从 `main` 根调用图做 DFS，并按叶子优先 postorder 分析函数。
- 跳过明显库函数、thunk，以及 `init` / `sandbox` / `setup` 一类初始化函数。
- 在 round1 / final report 中保留 `sub_` 函数的语义化改名建议。

V1 计划补全固定只读接口：
- list_functions
- get_pseudocode
- get_disasm
- get_callers
- get_callees
- get_xrefs
- list_imports
- list_strings
- find_dangerous_calls
- function_summary

要求：
- 输出 JSON 格式固定
- 参数固定
- 只读为主
