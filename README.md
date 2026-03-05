# CTI MCP Server — 威胁情报 MCP 服务

> 为 AI Agent 提供统一的网络威胁情报查询接口，覆盖通用 IT 安全、工业控制系统 (ICS/OT)、AI/LLM 安全三大领域，基于 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)。

---

## 🗂️ 能力全览

### 🔍 IOC 威胁情报（需 API Key）

| Tool | 功能描述 | 数据源 |
|---|---|---|
| `lookup_ioc` | 查询 IP/域名/URL/文件 Hash 的威胁声誉，并发聚合多源结果，返回统一 verdict | VT + OTX |
| `get_threat_summary` | 生成 Markdown 格式的综合威胁摘要报告，适合直接注入 AI 上下文 | VT + OTX |

### 🛡️ CVE 漏洞情报（无需 API Key）

| Tool | 功能描述 |
|---|---|
| `lookup_cve` | 查询单个 CVE 详情：CVSS 评分、CWE、受影响产品（会自动关联 CISA KEV 与 EPSS 预测）|
| `search_cves` | 按关键词+严重度搜索 CVE，支持分页 |
| `get_epss_score` | 查询 CVE 的利用概率预测分数 (EPSS) |
| `is_cve_known_exploited`| 判定漏洞是否已录入 CISA KEV 真实在野利用库 |
| `lookup_osv_package` | 精准查询 OSV 开源漏洞库 (SBOM 供应链安全/npm/PyPI/Maven 等) |

### ⚔️ MITRE ATT&CK Enterprise & D3FEND（无需 API Key）

| Tool | 功能描述 |
|---|---|
| `get_mitre_technique` | 获取 IT 攻击技术详情（T1059 等），含战术、平台、检测方法 |
| `search_mitre_techniques` | 全文检索 ATT&CK Enterprise 技术库 |
| `search_threat_actors` | 检索 APT 黑客组织（如 Sandworm、Lazarus），做归因分析 |
| `get_mitre_d3fend_countermeasures` | 查询特定攻击技术的 D3FEND 专属防御与应对策略 |

### 🏭 ICS/OT 工业安全（无需 API Key）

| Tool | 功能描述 |
|---|---|
| `search_ics_advisories` | 搜索 CISA ICS 安全公告，支持厂商/关键词/CVE 过滤 |
| `get_recent_ics_advisories` | 获取最近 N 条 CISA ICS 公告 |
| `get_mitre_ics_technique` | MITRE ATT&CK for ICS 技术详情（T0855 等 OT 专属技术）|
| `search_mitre_ics_techniques` | 检索 ATT&CK for ICS 技术库（含 Modbus/DNP3 相关技术）|
| `lookup_ot_asset_cves` | 按 OT 厂商/产品搜索 CVE（Siemens、Rockwell、Honeywell 等 15 家）|
| `lookup_mac_vendor` | 基于 IEEE OUI 库对 MAC 地址实现快速厂商指纹识别（OT/IT 皆可）|

### 🤖 AI/LLM/Agent 安全（无需 API Key）

| Tool | 功能描述 |
|---|---|
| `get_atlas_technique` | MITRE ATLAS AI 威胁矩阵技术详情（AML.T0051 Prompt Injection 等）|
| `search_atlas_techniques` | 检索 ATLAS 技术库（jailbreak/poisoning/extraction 等）|
| `get_owasp_llm_risk` | OWASP LLM Top 10 风险详情（2025 版，含缓解措施和 ATLAS 映射）|
| `lookup_ai_framework_cves` | 查询 AI/LLM 框架 CVE（LangChain/PyTorch/Ollama/HuggingFace 等 20 个）|
| `analyze_ai_agent_risk` | **AI Agent 威胁面评估**：输入框架+能力，输出 OWASP/ATLAS 风险矩阵 |

### 📡 OTX 威胁脉冲（需 OTX API Key）

| Tool | 功能描述 |
|---|---|
| `get_otx_pulse` | 获取 AlienVault OTX 威胁脉冲详情（含 IOC 列表）|
| `search_otx_pulses` | 按关键词搜索 OTX 威胁脉冲 |

### 💬 特色 Prompts（指导 AI 工作流）

本服务内置原生 MCP Prompts，引导大模型按标准流程进行深度安全研判：
| Prompt Name | 场景描述 |
|---|---|
| `analyze_threat_actor` | 指导 AI 分析某一黑客组织的攻击特征、关联技术，并提出针对性地防御措施 |
| `investigate_asset_supply_chain`| 提供供应链风险分析模板：结合 CVE 与 OSV 查询给特定资产定级 |

---

## 📚 Resources（只读上下文，AI Agent 可引用）

| URI | 内容 |
|---|---|
| `cti://status` | 服务状态、数据源、熔断器状态、速率限制概览 |
| `cti://mitre/tactics` | MITRE ATT&CK Enterprise 战术列表 |
| `cti://mitre/techniques` | MITRE ATT&CK Enterprise 技术全表（Markdown）|
| `cti://mitre/ics/techniques` | MITRE ATT&CK for ICS 技术全表 |
| `cti://ics/advisories/recent` | 最近 20 条 CISA ICS 安全公告 |
| `cti://ics/vendors` | 支持的 OT 厂商列表与 CPE 关键词映射 |
| `cti://ai/atlas/techniques` | MITRE ATLAS AI 威胁矩阵技术全表 |
| `cti://ai/owasp-llm-top10` | OWASP LLM Top 10 完整文档（2025）|
| `cti://ai/frameworks` | AI 框架 CVE 查询关键词映射表 |

---

## 🚀 快速开始

### 1. 安装依赖

```bash
cd c:\Users\songj\cti
pip install -e .
```

### 2. 配置 API Key

```bash
copy .env.example .env
# 编辑 .env，填入 API Key（没有 Key 的数据源自动禁用，不影响其他功能）
```

**.env 关键配置：**
```env
# IOC 查询（可选，无 Key 时 VT/OTX 数据源不可用）
VIRUSTOTAL_API_KEY=your_vt_key_here
OTX_API_KEY=your_otx_key_here

# HTTP 模式安全（可选，空表示无认证）
MCP_AUTH_TOKEN=your_token_here
MCP_HTTP_HOST=127.0.0.1

# 速率限制（默认值）
VT_RATE_LIMIT=4     # VT 免费版 4次/分钟
OTX_RATE_LIMIT=60
```

### 3. 启动服务 (本地开发)

**STDIO 模式**（接入 Claude Desktop / 本地 Agent）：
```bash
python -m src.server
```

**HTTP 模式**（多 Agent 并发）：
```bash
python -m src.server --transport=http
# 监听 127.0.0.1:8000（默认）
```

**调试模式**（MCP Inspector UI）：
```bash
fastmcp dev src/server.py
# 浏览器打开 http://localhost:5173
```

### 4. 生产环境部署 (高并发/Docker+Nginx)

对于生产级多 Agent 接入场景，由于 FastMCP 的 HTTP 传输依赖于细粒度的数据流 (SSE/Server-Sent Events) 和持久连接，推荐使用内置的 Nginx 优化模式来防止缓冲区超时或连接断开。

内置的 `docker-compose.prod.yml` 提供以下生产级特性：
- **安全加固**：Docker 容器以非 root (`appuser`) 全局降权运行，设置读写隔离。
- **SSE 防拥塞**：Nginx 已在 `nginx/nginx.conf` 中专门配置了 `proxy_buffering off;` 及长连接保持。
- **故障恢复**：内建进程监控、崩溃自动重启与内存日志轮转限制 (Log Rotation)。

```bash
# 启动生产级集群 (后台运行)
docker-compose -f docker-compose.prod.yml up -d --build

# 持续跟进运行日志
docker-compose -f docker-compose.prod.yml logs -f
```
*(MCP Server 将通过 Nginx 暴露在宿主机的 `80` 端口上，服务网关级调用，可按需自行修改配置文件添加 HTTPS 支持)*

---

## 🔧 接入方式

### Claude Desktop

编辑 `%APPDATA%\Claude\claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "cti": {
      "command": "python",
      "args": ["-m", "src.server"],
      "cwd": "c:\\Users\\songj\\cti"
    }
  }
}
```

### Python Agent（HTTP 模式）

```python
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client("http://localhost:8080/mcp") as (read, write, _):
    # 通过标准 MCP 协议调用 Tools
    ...
```

---

## 📊 数据源概览

| 数据源 | 覆盖领域 | API Key | 限制 | 申请 |
|---|---|---|---|---|
| VirusTotal v3 | IOC 声誉 | ✅ 必须 | 4 次/分 (免费) | [链接](https://www.virustotal.com/gui/join-us) |
| AlienVault OTX | 威胁脉冲 | ✅ 必须 | 免费无限制 | [链接](https://otx.alienvault.com/api) |
| NIST NVD CVE | 漏洞库 | ⬜ 可选 | 免费，有 Key 更快 | [链接](https://nvd.nist.gov/developers/request-an-api-key) |
| OSV Database | 软件供应链安全 | ❌ 无需 | 免费 | 在线开源 API |
| CISA KEV & EPSS | 漏洞实战情报 | ❌ 无需 | 在线查询 | 无需申请 |
| IEEE MAC OUI | 硬件 MAC 指纹 | ❌ 无需 | 离线查表 | 自动下载 |
| MITRE ATT&CK | TTP 及 APT 组织 | ❌ 无需 | 本地 STIX，离线 | 自动下载 |
| MITRE D3FEND | 针对性防御措施 | ❌ 无需 | 在线查询 | 无需申请 |
| MITRE ATT&CK for ICS | OT/SCADA TTP | ❌ 无需 | 本地 STIX，离线 | 自动下载 |
| MITRE ATLAS | AI/ML 威胁矩阵 | ❌ 无需 | 本地 YAML，离线 | 自动下载 |
| CISA ICS Advisories | OT 安全公告 | ❌ 无需 | RSS，在线 | 无需申请 |
| OWASP LLM Top 10 | LLM 应用风险 | ❌ 无需 | 内置静态数据 | 无需申请 |

> MITRE 数据首次运行自动下载（企业版 ~30MB，ICS ~5MB，ATLAS ~1MB），之后完全离线。

---

## 🔒 安全与鲁棒性

### 内置安全机制

| 机制 | 说明 |
|---|---|
| **SSRF 防护** | 拒绝私有 IP（10.x/192.168.x/127.x）、localhost、`file://` 等危险输入 |
| **输入验证** | IP 格式、Hash 长度（MD5/SHA1/SHA256）、CVE ID、MITRE ID 均有格式检查 |
| **速率限制** | 令牌桶算法，每个数据源独立限速，可通过 `.env` 调整 |
| **熔断器** | 3 次连续失败后快速失败，60s 后自动试探恢复 |
| **错误脱敏** | API Key 和本地路径不会出现在错误响应中 |
| **审计日志** | `logs/audit.jsonl` 记录每次工具调用（不含 IOC 原始值）|
| **HTTP 认证** | 可配置 Bearer Token，默认绑定 127.0.0.1 |

### 性能特性

- **并发查询** — `lookup_ioc` 同时查询 VT + OTX，延迟约减少 50%
- **TTL 缓存** — 默认 5 分钟缓存，防止重复查询消耗配额
- **启动预热** — 服务启动后后台异步加载 MITRE 本地数据，首次调用无等待
- **指数退避重试** — 对 429/5xx 响应最多重试 3 次

---

## 🧪 业务场景测试

运行端到端业务场景测试（真实 API 调用）：

```bash
# 单元测试（Mock，无需 API Key）
pytest tests/ -v

# 业务场景测试（真实 API，需要配置 .env）
python tests/test_business_scenarios.py
```

---

## 📁 项目结构

```
cti/
├── src/
│   ├── server.py               # FastMCP 主入口（18 Tools + 9 Resources）
│   ├── config.py               # 配置管理（速率/认证/审计）
│   ├── models.py               # Pydantic 数据模型
│   ├── cache.py                # TTL 内存缓存
│   ├── validators.py           # 输入验证 + SSRF 防护
│   ├── ratelimit.py            # 令牌桶速率限制
│   ├── circuit_breaker.py      # 熔断器状态机
│   ├── audit.py                # 结构化审计日志 (JSONL)
│   └── connectors/
│       ├── virustotal.py       # VirusTotal v3（熔断器+重试）
│       ├── otx.py              # AlienVault OTX（熔断器+重试）
│       ├── mitre_attack.py     # MITRE ATT&CK Enterprise（本地 STIX）
│       ├── mitre_ics.py        # MITRE ATT&CK for ICS（本地 STIX）
│       ├── mitre_atlas.py      # MITRE ATLAS（AI 威胁，本地 YAML）
│       ├── cisa_ics.py         # CISA ICS Advisories（RSS）
│       └── cve.py              # NIST NVD CVE API v2.0
├── tests/
│   ├── test_server.py          # 单元测试（63 tests）
│   └── test_business_scenarios.py  # 业务场景集成测试
├── logs/
│   └── audit.jsonl             # 审计日志（自动生成）
├── .mitre_cache/               # MITRE 本地 STIX/YAML 缓存（自动生成）
├── .env.example
├── pyproject.toml
└── README.md
```

---

## 💡 典型使用示例

### IT 安全运营

```
# 检查可疑 IP
lookup_ioc indicator="185.220.101.45" ioc_type="ip"

# Log4Shell 漏洞情报
lookup_cve cve_id="CVE-2021-44228"

# 检索横向移动技术
search_mitre_techniques query="lateral movement credential"
```

### OT/工业安全

```
# 查询 Siemens PLC 安全公告
search_ics_advisories vendor="Siemens" keyword="remote code"

# SCADA 攻击技术
get_mitre_ics_technique technique_id="T0855"

# Rockwell CVE 查询
lookup_ot_asset_cves vendor="rockwell" product="logix" severity="CRITICAL"
```

### AI/LLM 安全

```
# 评估 LangChain Agent 威胁面
analyze_ai_agent_risk agent_framework="langchain"
  capabilities="web_search,code_execution,file_access,multi_agent"

# Prompt Injection 技术详情
get_atlas_technique technique_id="AML.T0051"

# LangChain 历史漏洞
lookup_ai_framework_cves framework="langchain" severity="CRITICAL"

# OWASP LLM 过度代理风险
get_owasp_llm_risk risk_id="LLM08"
```
