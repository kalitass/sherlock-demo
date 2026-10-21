[English](README.md) · **中文**

# Sherlock —— ELK 上的智能体威胁狩猎

Sherlock 是一个跑在 ELK(Elasticsearch)日志上的 **AI 威胁狩猎工具**。你用大白话问一个
安全问题——比如"这台主机上是不是被建了后门账号?"——它就自己去 SIEM 里查日志、给出
判断,并且**每条结论都附上它实际跑过的那条查询**作为证据。这是我们 SE6014 的课程项目
(第一题)。

它的核心准则是 **无证据,不下结论(No evidence, no claim)**:任何没有查询支撑的结论,
都会在进报告前被拦掉。

## 为什么需要它

安全团队被日志淹没,查一次入侵往往要分析师一个假设一个假设地手写查询;可要是直接把
LLM 丢给日志,它又会一本正经地胡说——编造一次"入侵"白费一天,漏掉一次就是真被攻破。
Sherlock 让每个结论都能一路追回到数据:一个 verifier 只拿"查得到、对得上"的证据重新算
判决,于是 AI 给出的判决变得可审计、可信。

## 快速开始

需要 Docker Desktop + [uv](https://docs.astral.sh/uv/)。

```bash
make demo              # 启动 ELK + 下载并接入公开数据集
cp .env.example .env   # (可选)填一个 LLM key —— Scan 引擎不需要
make dashboard         # 打开 http://localhost:8080
```

输入一个假设点 **Run hunt**,或用 **Detection scan**(确定性,不需要 key)。没有 API key
也没关系,确定性引擎能把整条链路端到端跑通。

## 效果 · 证明了什么

在公开的 OTRF Security-Datasets 上——约 36,700 条真实事件、14 个 ATT&CK 技术横跨 7 个
战术、DeepSeek、温度 0:

| 指标 | 结果 |
|---|---|
| 检出攻击(召回) | **14 / 14 —— 100%** |
| 误报率 | **0%** |
| 准确率(20 条标注假设) | **100%** |
| 被拦下的 LLM 幻觉结论 | **6%**(0 条进入报告) |
| 同一假设跑两遍 | **判决每次都一致(4/4)** |
| 确定性扫描器覆盖 | **15 / 15** 个探测技术 |

原始跑批:[`docs/benchmark_results_deepseek.md`](docs/benchmark_results_deepseek.md)、
[`docs/experiment_results.md`](docs/experiment_results.md)、
[`docs/ablation_results.md`](docs/ablation_results.md)。

## 工作原理

```
假设 → 狩猎引擎 ──(MCP 查询工具)──→ Elasticsearch
            │           每次调用都记账 ↓
            └──────────────→ 证据账本(evidence ledger)
                                   ↓
                      verifier → reducer → 报告
   (丢掉任何"查询没跑成 / 没对上"的结论;判决只从幸存的证据推出,绝不信模型自己的话)
```

日志经 **拉取 / 推送 / 流式** 进入,一个**自动 schema 智能体**为每个新源现建解析器。
**狩猎引擎**(LLM 智能体或确定性扫描器)**只能**通过受限的 **MCP 工具层**碰数据,每次
调用都记进**证据账本**。**verifier** 只留下有成功查询支撑的结论,**reducer** 从这些已核验
的证据推出判决。**仪表盘**把全程实时推流。完整细节:[`docs/sherlock-spec.md`](docs/sherlock-spec.md)。

## 对照课程要求

| 要求 | 在哪 |
|---|---|
| 通过**拉取、推送、流式**接入 | `ingestion/pull.py`、`POST /api/ingest/push`、`ingestion/stream.py` |
| **智能体化接入** —— 指向一个源,其余交给智能体 | `ingestion/auto_schema.py` |
| **自动 schema**:检查 → 匹配 → 否则新建、校验、注册 | `ingestion/auto_schema.py`、`ingestion/schema_registry.py` |
| **≥3 种日志类型**(14 个公开 ATT&CK 数据集) | `datasets/mordor_import.py` |
| **MCP 服务**,暴露检索 / 聚合 | `mcp_server/server.py`、`mcp_server/tools.py` |
| **智能体化狩猎**:规划 → 查询 → 检验 → 带证据报告 | `hunt_engine/` |
| **完整性/准确性 + 防幻觉** | `hunt_engine/evidence_ledger.py`、`hunt_engine/verifier.py` |
| **同一次狩猎跑两遍 + 对比** | `experiment/run_twice.py` |

## 更多

- **LLM 厂商** —— 一个接口后面挂 13+ 后端(DeepSeek、OpenAI、Anthropic、Gemini、Groq、
  OpenRouter、本地 Ollama…)。看哪些就绪:`make providers`;适配器在 `common/providers.py`。
- **七种 SIEM 互通** —— 统一到一套 `n_*` 规范字段,一条查询同时命中 CEF / LEEF / CIM /
  ECS / OCSF / ASIM / UDM,由 `uv run pytest tests/test_core.py -k normalise_all_seven_agree` 证明。
- **数据集与来源** —— 14 份采集的清单(含各自 ATT&CK 编号)在 `datasets/mordor_import.py`。
- **架构 spec** —— [`docs/sherlock-spec.md`](docs/sherlock-spec.md)。
- **命令行** —— `uv run python -m cli hunt "…"` · `… status` · `… schemas`。
