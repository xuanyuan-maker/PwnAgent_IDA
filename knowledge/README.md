# Local Vulnerability Knowledge Base

本目录存放离线本地知识库，供 `host/model_adapter.py` 在 `round1` 和 `final` 阶段注入提示词。

当前知识条目：
- 栈溢出
- 格式化字符串漏洞
- 整数溢出
- 堆溢出
- UAF（释放后使用）

文件说明：
- `vuln_patterns.json`：知识库主文件，使用标准 JSON，避免依赖额外解析器。

维护原则：
- 只存放高频、可操作、可验证的漏洞模式。
- 每条模式都应包含触发信号、关键观察点、排查问题、误判陷阱。
- 不要写与样本无关的泛泛教材内容，保持面向离线 CTF/PWN 静态分析。
