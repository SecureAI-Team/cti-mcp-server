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

### 📢 厂商安全公告 Vendor Advisories（无需 API Key）

| Tool | 功能描述 |
|---|---|
| `get_recent_vendor_advisories` | 获取 13 家主流 IT/OT/AI 厂商的最新安全公告（如 Microsoft MSRC, Cisco, Siemens） |
| `search_vendor_advisories` | 按关键词或 CVE ID 跨厂商检索安全公告，支持按 `it`, `ot`, `ai` 分类过滤 |

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

### 💬 业务场景 Prompts（指导 AI 工作流）

本服务内置原生 MCP Prompts，引导大模型按标准流程进行深度安全研判，覆盖三大业务主线：

| 领域 | Prompt Name | 场景描述 |
|---|---|---|
| **通用** | `analyze_threat_actor` | 组织画像：查询黑客组织 APT 特征及关联 MITRE 技术与防御措施 |
| **通用** | `investigate_asset_supply_chain` | 供应链排查：结合 CVE 与 OSV 评估软件库/组件的安全风险 |
| **IT 安全** | `it_incident_triage` | SOC 告警研判：IOC 查询 → ATT&CK 映射 → D3FEND 响应止血建议 |
| **IT 安全** | `it_patch_prioritization` | 漏洞管理：依据 CVSS + EPSS + CISA KEV + 厂商公告的 Patch 优先级规划 |
| **OT 工业** | `ot_plant_security_assessment` | 工厂评估：针对 Siemens/Rockwell 等系统的漏洞排查及 IEC 62443 风险报告 |
| **OT 工业** | `ot_ics_compromise_investigation` | 应急响应：OT 异常现象 → 关联 ICS 专属 TTPs 及 CVE → 输出响应 Playbook |
| **AI LLM** | `ai_llm_deployment_security_review`| 上线评估：结合 OWASP LLM / ATLAS 与框架漏洞的投产前 Go/No-Go 安全审查 |
| **AI LLM** | `ai_vendor_security_posture` | 供应商尽调：AI 厂商历史漏洞/安全公告回顾，输出供应商安全概况评分卡 |

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
| `cti://vendors/advisory-sources`| 13 家主流 IT/OT/AI 厂商安全公告数据源状态表 |

---

## 🚀 快速开始

### 1. 安装依赖

```bash
cd /opt/cti-mcp-server # 若是本地，切换到项目根目录
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

### 4. 生产环境部署 (Ubuntu 24.04 一键部署)

我们为 Ubuntu Server 提供了一键自动化部署脚本。该脚本会自动为您安装 Docker、拉取代码、生成高强度且随机的访问 Token 并启动整个防拥塞架构：

```bash
curl -sSL https://raw.githubusercontent.com/SecureAI-Team/cti-mcp-server/main/scripts/deploy_ubuntu.sh | sudo bash
```
> *注：服务将默认部署在 `/opt/cti-mcp-server` 目录下。部署完成后控制台会打印出您的公网 IP 和访问 Token。*

---

### 5. 生产环境部署 (手动/Docker+Nginx)

对于跨平台的生产级多 Agent 接入场景，由于 FastMCP 的 HTTP 传输依赖于细粒度的数据流 (SSE/Server-Sent Events) 和持久连接，推荐使用内置的 Nginx 优化模式来防止缓冲区超时或连接断开。

内置的 `docker-compose.prod.yml` 提供以下生产级特性：
- **安全加固**：Docker 容器以非 root (`appuser`) 全局降权运行，设置读写隔离。
- **SSE 防拥塞**：Nginx 已在 `nginx/nginx.conf` 中专门配置了 `proxy_buffering off;` 及长连接保持。
- **故障恢复**：内建进程监控、崩溃自动重启与内存日志轮转限制 (Log Rotation)。

```bash
# 1. 确认 .env 中的 MCP_AUTH_TOKEN 已设置
# 2. 确认 nginx/nginx.conf 中的 map 块已填入相同的 Token
# 3. 启动生产级集群
docker-compose -f docker-compose.prod.yml up -d --build
```
*(MCP Server 将通过 Nginx 暴露在宿主机的 `80` 端口上。外部 AI Agent 调用时，必须在 HTTP Header 中加入 `Authorization: Bearer <Your-Token>`，否则将收到 401 错误)*

#### 🛡️ 公网暴露最佳实践 (Public Internet Access)
由于 MCP 协议传输涉及 API Token 的认证头，强烈建议在暴露到公网前配置以下安全网关层：
1. **强制 HTTPS/TLS 加密**：修改 `docker-compose.prod.yml` 开放 443 端口并挂载证书，或在 Nginx 外层接 Cloudflare/Traefik 代理提供自动化 TLS。千万不要在非安全的 HTTP 信道传输 `Bearer Token`。
2. **边缘 WAF (Web Application Firewall)**：对高威胁目标的服务端，配置 WAF 以过滤恶意的漏洞扫描器。
3. **严格限流 (Rate Limiting)**：当前的 `nginx.conf` 中已按客户端 IP 设定了基础限流（10请求/s 防止 DDoS）。若有多租户代理池的大并发请求，请根据情况调整 `nginx.conf` 中的 `limit_req_zone` 阈值。
4. **动态的 Token 管理**：目前 Nginx 采用的是静态 `map` 块鉴权。大规模生产化部署建议将认证下放至全职的 API 网关集成 JWT / OAuth2 校验。

---

## 🔧 接入方式

### Claude Desktop (本地模式)
本地直接通过 Python 启动，无需 API Key 验证（绑定 localhost 安全）。
... (保持原样)

### 企业级 Agent (HTTP 模式)

调用生产环境接口时，请确保客户端已注入 Token：

```python
import httpx

# 示例：通过 HTTP 直接调用
headers = {"Authorization": "Bearer your-secret-mcp-token"}
# ... 按照 MCP SSE 协议进行交互
```

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
| Vendor Advisories | IT/OT/AI 厂商公告 | ❌ 无需 | RSS/Atom + NVD 在线 | 无须申请 |
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
| **HTTP 认证** | **必须项**。生产环境由 Nginx 强制校验 `Authorization: Bearer <token>`，拒绝非法请求。|
| **HTTP 隐藏** | Nginx 关闭 server_tokens，隐藏后端技术栈信息。|

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
│   ├── server.py               # FastMCP 主入口（20 Tools + 8 Prompts + 10 Resources）
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
│       ├── vendor_advisories.py# 13 家主流厂商 IT/OT/AI 官方安全公告 (RSS/NVD)
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
