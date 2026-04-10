# pwn-agent

> ⚠️ **重要声明：这是一个使用 AI 生成的工具，功能不全且不稳定。**
>
> 本项目由 AI 辅助生成，目前处于实验阶段。代码质量、功能完整性和稳定性均未经过充分验证。
> 使用前请自行评估风险，不建议用于生产环境。

离线、单任务串行、以 IDA 为中心的 CTF pwn 静态分析辅助系统。

## 当前能力
- 线性状态机：`INIT -> BASE_SNAPSHOT -> ROUND1 -> ROUND2 -> FINAL -> EXPORT -> DONE`
- 程序侧调用树构建：由 IDA API 生成 `call_tree`，并生成叶子优先任务队列 `analysis_queue`（包含根节点，通常最后分析）
- 双轨输出：
  - 机器：`final_report.json`
  - 人类：`final_report.md`
- IDA 热键触发：`Ctrl+Shift+A`
- 防重入：
  - 插件内运行锁（防止连按热键并发）
  - 后端全局锁文件（同一时刻只跑一个任务）
  - 支持陈旧锁自动清理（异常退出后不容易"永久卡锁"）
- 轻量 JSON Schema 校验（无第三方依赖）
- FINAL 阶段支持"原样透传"：模型输出不符合固定模板时，直接原文落盘到 `final_report.md`
- 任务级运行日志：`tasks/<task_id>/runtime.log`
- 项目级统一日志：`logs/pwn-agent.log`（CLI/服务层/模型层/IDA桥接层）
  - 每条日志带 `request_id` + `task_id`（全链路排障）

## 目录说明
- `host/`：宿主控制层（状态机、模型、存储、报告）
  - `ida_bridge_interface.py`：IDA 桥抽象接口
  - `ida_bridge_impl.py`：IDA 桥具体实现
  - `ida_bridge.py`：兼容门面（旧导入路径仍可用）
- `ida_plugin/`：IDA 插件入口（热键、后台触发）
- `schemas/`：结构化输出 schema
- `prompts/`：模型提示词模板
- `scripts/`：安装与测试脚本
- `tasks/`：任务产物目录

## CLI（开发调试）
```bash
cd /home/xuanyuan/Ws/dev/pwn-agent
python run.py new-task --binary ./sample.bin --idb ./sample.i64
python run.py run <task_id>
python run.py status <task_id>
python run.py report
python run.py report --task-id <task_id>
```

报告查看入口：
- 最新 Markdown 报告：`reports/latest_report.md`
- 最新 JSON 报告：`reports/latest_report.json`
- 报告索引：`reports/index.md`

## IDA 内一键触发（推荐）
1) 安装插件
```bash
cd /home/xuanyuan/Ws/dev/pwn-agent
bash scripts/install_ida_plugin.sh
```

2) 设置项目根环境变量（建议写入 `~/.zshrc`）
```bash
export PWN_AGENT_ROOT=/home/xuanyuan/Ws/dev/pwn-agent
```

3) 重启 IDA，按 `Ctrl+Shift+A`。

## 自动化测试
```bash
bash scripts/test_ida_plugin.sh
```

测试会验证：
- 插件是否加载（哨兵文件）
- 是否自动产生新 `quick-*` 任务
- 是否输出 `final_report.md`

## 稳定性建议（Wine/IDA）
如果遇到 `Could not find platform dependent libraries <exec_prefix>`：
- 启动 IDA 前清理 Python 环境变量（已在 `~/.local/bin/ida` 中加了清理）
  - `PYTHONHOME`
  - `PYTHONPATH`
  - `VIRTUAL_ENV`
  - `CONDA_PREFIX`
  - `CONDA_DEFAULT_ENV`
