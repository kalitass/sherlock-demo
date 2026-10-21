[English](README.md) · **中文**

# Sherlock —— ELK 上的智能体威胁狩猎

**自然语言假设进 → 带证据的判决出。**

Sherlock 是为 SE6014(第一题)做的 AI 辅助威胁狩猎平台。用户用自然语言输入一个假设;
智能体工作流规划狩猎、**只通过 MCP 工具层**查询 Elasticsearch SIEM、收集证据,最终
给出一个带证据的判决——**其中每一条结论都绑定到产生它的那条查询**,任何绑不上的
结论都会被 verifier 在进入报告前拒掉。

它自带一个独立实验环境:Docker 里的 ELK 栈、对 14 个公开 ATT&CK 标注数据集的智能体化
接入(自动识别 schema),以及一个能实时观看狩猎过程的仪表盘。

---

## 它做了什么(对照课程要求)

| 要求 | 在哪 |
|---|---|
| 通过**拉取、推送、流式**接入 | `ingestion/pull.py`、仪表盘 `POST /api/ingest/push`、`ingestion/stream.py` |
| **智能体化接入** —— 指向一个源,其余交给智能体 | `ingestion/auto_schema.py` |
| **自动 schema**:检查 → 匹配模板 → 否则新建、校验、注册 | `ingestion/auto_schema.py`、`ingestion/schema_registry.py` |
| **≥3 种日志类型**(14 个公开 ATT&CK 数据集:Windows Security、Sysmon、PowerShell…) | `datasets/mordor_import.py` |
| **MCP 服务**,暴露检索/聚合等能力 | `mcp_server/server.py`、`mcp_server/tools.py` |
| **智能体化狩猎**:规划 → 查询 → 检验 → 带证据报告 | `hunt_engine/` |
| **完整性/准确性 + 防幻觉** | `hunt_engine/evidence_ledger.py`、`hunt_engine/verifier.py` |
| **同一次狩猎跑两遍 + 对比** | `experiment/run_twice.py` |

---

## 环境要求

- **Docker Desktop**(支持 Apple Silicon —— 见下方说明)
- **[uv](https://docs.astral.sh/uv/)** 管理 Python 环境
- Docker 虚拟机约需 6 GB 空闲
- *(可选)* 一个 LLM API key 用于 LLM 引擎。**没有 key 时,Sherlock 用确定性引擎,
  整条链路照样端到端跑通。**

## 快速开始 —— 3 步

```bash
make demo              # 1. 启动 + 数据:ES + Kibana + 依赖,然后下载并接入数据集
cp .env.example .env   # 2. KEY(可选):加一个 LLM key —— 见下文;Scan 引擎不需要 key
make dashboard         # 3. 运行:网页 UI → http://localhost:8080
```

打开 **http://localhost:8080** → 输入一个假设 → **Run hunt**;或打开 **Detection
scan**(确定性,不需要 key)。要做原始数据透视用 **Kibana**:**http://localhost:5601**。

**2 · LLM key。** 一行选定模型。编辑 `.env`:

```bash
SHERLOCK_LLM_PROVIDER=deepseek     # 或 anthropic、openai、groq、gemini、openrouter、ollama …
DEEPSEEK_API_KEY=sk-...            # 你所选厂商对应的 *_API_KEY
```

`.env` 已被 gitignore。**没有 key?确定性 Scan 仍端到端可用 —— 只有 LLM Hunt 会被禁用。**
查看有哪些厂商、哪些已就绪:`make providers`。

**1 · 数据。** `make mordor`(已含在 `make demo` 里)拉取公开、MIT 许可的
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) —— 真实的
Windows/Sysmon/PowerShell 遥测,每份采集都标注了它运行的 ATT&CK 技术(14 个数据集、
约 36,700 条事件)。自动下载并缓存在 `datasets/mordor_cache/`;逐数据集的来源见
`docs/DATA_SOURCES.md`。

### 命令行

```bash
uv run python -m cli status                                  # 集群 + 索引
uv run python -m cli hunt "Was a backdoor local account created on this host?"
uv run python -m cli schemas                                 # 已注册的解析器
```

### 支持的 LLM 厂商

每个都是一个 `SHERLOCK_LLM_PROVIDER` 取值;在 `.env` 里设对应的 key 环境变量。路由在
装了 **LiteLLM** 时走 LiteLLM,否则走内置的原生适配器。

| 厂商 | Key 环境变量 | 备注 |
|---|---|---|
| `anthropic` | `ANTHROPIC_API_KEY` | 原生 Claude API |
| `openai` | `OPENAI_API_KEY` | |
| `azure` | `AZURE_OPENAI_API_KEY` | 还需设 `SHERLOCK_LLM_BASE_URL` |
| `groq` | `GROQ_API_KEY` | |
| `deepseek` | `DEEPSEEK_API_KEY` | |
| `together` | `TOGETHER_API_KEY` | |
| `openrouter` | `OPENROUTER_API_KEY` | OpenRouter 上的任意模型 |
| `mistral` | `MISTRAL_API_KEY` | |
| `xai` | `XAI_API_KEY` | Grok |
| `gemini` | `GEMINI_API_KEY` | Google 的 OpenAI 兼容端点 |
| `ollama` / `lmstudio` / `vllm` | *(无 —— 本地)* | 自托管,不需要 key |

`engine: auto` 在有 key 时用 LLM;`engine: deterministic` 强制走无 LLM 路径。接入一个
API 真正不同的新厂商,就是约 40 行的一个适配器类 —— 狩猎逻辑一概不变(见
`common/providers.py`)。

**健壮性:** 若所选 LLM 厂商在狩猎途中出问题(key 错、网络、端点挂了、限流),狩猎
**不会**崩 —— 它回退到确定性引擎,仍返回一个带证据的判决,并在报告里标出这次回退
(`meta.engine_fallback`)。可用 `SHERLOCK_LLM_TIMEOUT`(秒)和 `SHERLOCK_LLM_RETRIES` 调。

### SIEM schema 兼容 + “归一化优先”(SE6014 第 2 周)

*一个检测的可移植性,取决于它的 schema。* 同一起事件会以**课程讲的七种 schema**分别
导出,Sherlock 把它们全部归一到同一套规范字段,于是一条查询就能命中每一种。这七种
格式作为示例固定样本保留,并归一到 `n_*`;其一致性由一个单元测试证明(不接入任何
合成数据集):

```bash
uv run pytest tests/test_core.py -k normalise_all_seven_agree
```

| 文件 | 角色 | Schema |
|---|---|---|
| `cef.log` | 生产者(wire) | **CEF** —— ArcSight |
| `leef.log` | 生产者(wire) | **LEEF** —— IBM QRadar |
| `cim.json` | 消费者 | **CIM** —— Splunk |
| `ecs.json` | 消费者 | **ECS** —— Elastic |
| `ocsf.json` | 消费者 | **OCSF** |
| `asim.json` | 消费者 | **ASIM** —— MS Sentinel |
| `udm.json` | 消费者 | **UDM** —— Google SecOps |

每条事件都用讲义里的字段映射表归一到规范 `n_*` 字段(`n_user`、`n_src_ip`、
`n_event_id`、`n_action`…),于是**一条查询在全部七种 schema 上命中完全相同**:

```bash
# 同一条查询,命中在全部七种 schema 下渲染的同一条事件
n_event_id=4625  AND  n_user=administrator  AND  n_src_ip=203.0.113.66  AND  n_action=failure
```

CEF/LEEF 由确定性解析器处理(标准化的 wire 格式);JSON schema 靠自省 —— 全程不需要
API key。

**Schema 漂移检测**(第 2 周,幻灯片 36 —— *“漂移会悄悄让检测失效”*):每次接入都跑
一遍"观测 vs 预期"的契约检查。改名或删掉某个检测依赖的字段,接入会暴露 `drift`(列出
缺失 / 新增 / 类型变化的字段),而不是悄无声息地什么都匹配不到。契约存在
`sherlock-schema-contracts`;要重新接受一次有意的变更,用 `schema_drift.rebaseline()`。

### 三种接入模式

```bash
# PULL —— 把文件丢进被监听的目录
uv run python -m ingestion.pull            # 一个终端里
cp path/to/your-logs.json drop/            # 另一个终端里(任意 JSON/NDJSON 日志文件)

# PUSH —— 端点 agent 推一批
curl -X POST "http://localhost:8080/api/ingest/push?log_type=windows" \
     -H 'Content-Type: application/json' --data-binary @path/to/your-logs.json

# STREAM —— 持续的 syslog 风格数据流
uv run python -m ingestion.stream                          # 监听端
uv run python -m ingestion.stream --send path/to/logs.log  # 生产端
```

### 把 Claude Desktop 指向同一个 MCP 服务(可选)

这个 MCP 服务是个普通的 stdio server。在 Claude Desktop 的配置里:

```json
{ "mcpServers": { "sherlock": {
    "command": "uv",
    "args": ["run", "python", "-m", "mcp_server.server"],
    "cwd": "/absolute/path/to/sherlock"
}}}
```

---

## 架构(一段话)

日志经由 拉取/推送/流式 进入,汇入一个共享的**接入核心**。一个**自动 schema 智能体**
给每个源做指纹,复用已注册的解析器或新建一个(JSON 自省,或生成一条正则),对样本
校验后注册。解析后的事件落入按类型分的 Elasticsearch 索引。**MCP 服务**把检索/聚合/
计数等暴露成只读工具,限定在日志索引范围内并加了边界。**狩猎引擎**(LLM 智能体或
确定性引擎)规划一次狩猎、调用这些工具,并把每次调用连同可复现的精确请求
(`es_request`)和命中文档数记进**证据账本**。**verifier** 只保留有成功查询支撑的结论,
**reducer** 从这些已核验的证据加上真实覆盖率推导出最终判决 —— 所以引擎的自述永远
不决定判决,被拒的结论也真的不计入。**reporter** 展示已核验的判决、每条结论的查询、
以及每条被拒的结论。**仪表盘**把整个过程实时推流。完整细节:`docs/sherlock-spec.md`。

---

## Apple Silicon(M 系列)注意 —— 我们踩过并修好的坑

这些都已固化进仓库;列出来是让评审理解这些取舍。

1. **Elasticsearch 在 JVM 启动时 SIGILL。** ES 8.14+ 自带 JDK 22,而 JDK 22 / ES 自己的
   JDK 21.0.2 在 Apple Silicon 的 Docker Desktop 下探测 ARM SVE 向量长度时会崩。
   **修复:** `docker/es/Dockerfile` 换成 Temurin 21.0.12,它会优雅地禁用 SVE。锁定在
   ES **8.13.4**。
2. **索引翻成只读 / 集群变红。** 笔记本磁盘偏满时,ES 触到 95% 的洪泛水位线。
   **修复:** 本地实验环境在 `docker-compose.yml` 里禁用了基于磁盘的分配。
3. **内存。** ES 堆上限 768 MB、Kibana 512 MB,好让整栈塞进约 6–8 GB 的 Docker 虚拟机。

## 仓库布局

```
docker-compose.yml   docker/es/       # ELK,为 Apple Silicon 打了补丁
common/              # 设置、ES 客户端、LLM 客户端
datasets/            # OTRF Security-Datasets 接入(mordor_import.py)
ingestion/           # auto_schema、解析、接入核心、pull/push/stream
mcp_server/          # MCP 工具 + stdio server
hunt_engine/         # mcp_client、planner/executor(LLM)、heuristic、ledger、verifier、reporter
dashboard/           # FastAPI + 单页 SOC 控制台(SSE 实时轨迹)
experiment/          # 同一次狩猎跑两遍的对比
docs/                # 架构 spec、实验结果
```
