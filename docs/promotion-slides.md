# OpenSAST — 产品宣传幻灯片素材

> 按幻灯片页组织，每页一个主题，包含标题、核心内容、数据支撑和可选配图建议。

---

## Slide 1 — 封面

**OpenSAST**
多语言 AI 驱动静态应用安全测试平台

规则引擎 × LLM 分析 × AI Agent 推理 — 三层架构，超越传统 SAST

---

## Slide 2 — 问题：纯语法规则 SAST 的困境

### 规则引擎的三大痛点

| 痛点 | 现状（实测） |
|------|------|
| **误报泛滥** | MarqDex 真实项目：纯语法规则 17 个结果、0 真阳性（100% 误报率） |
| **能力天花板** | 纯内联模式在 OWASP Benchmark 上得 0%；加污点追踪后 **+39.6%**（FindSecBugs 水平） |
| **开发体验差** | 无 LLM 验证时，开发者对告警免疫；需要三层架构降噪 |

**一句话：语法规则 alone 不够，但污点规则 + LLM 层可形成有效检测链。**

---

## Slide 3 — 解决方案：三层 SAST 架构

```
┌─────────────────────────────────────────────┐
│  Layer 3: AI Agent 自由推理                   │
│  跨模块数据流 · 业务逻辑缺陷 · 代码意图理解       │
├─────────────────────────────────────────────┤
│  Layer 2: LLM 结构化分析（13 种发现类型）        │
│  IDOR · 凭据 · 认证链 · 加密 · SSRF · SQL注入  │
│  CSRF · 限流 · 批量赋值 · 安全头 · 配置安全      │
├─────────────────────────────────────────────┤
│  Layer 1: 规则引擎                            │
│  Semgrep · Gitleaks · Checkov · CodeQL        │
└─────────────────────────────────────────────┘
```

**层层递进，覆盖规则引擎无法触及的安全盲区。**

---

## Slide 4 — Layer 1：规则引擎（信号源）

### 多引擎编排

| 引擎 | 覆盖范围 | 定位 |
|------|----------|------|
| **Semgrep** | 13 种语言（含 C#）+ Java 污点规则 | 模式匹配 + 污点追踪 |
| **Gitleaks** | 全语言 | 凭据/密钥泄露检测 |
| **Checkov** | IaC/Terraform | 基础设施安全合规 |
| **CodeQL** | 6 种语言 | 深度数据流分析（deep profile） |
| **补充工具** | 按语言自动启用 | Bandit · gosec · ESLint · Brakeman · cppcheck · cargo-audit · SwiftLint · PHPStan |

### 三档配置

| 档位 | 耗时 | 引擎 | 场景 |
|------|------|------|------|
| Quick | 秒级 | Semgrep + Gitleaks | 提交前检查 |
| Standard | 2-10 分钟 | + Checkov | 日常扫描 |
| Deep | 10+ 分钟 | + CodeQL | 安全审计 |

---

## Slide 5 — Layer 2：LLM 结构化分析（核心创新）

### 13 种安全发现类型

| 类别 | 发现类型 | 检测能力 |
|------|----------|----------|
| **访问控制** | IDOR · Mass Assignment | 越权访问、字段注入 |
| **认证安全** | Auth Chain · CSRF · Rate Limiting | 鉴权缺失、时序攻击、暴力破解 |
| **注入攻击** | SQL Injection · SSRF | 参数化查询、服务端请求伪造 |
| **数据保护** | Credentials · Crypto | 硬编码密钥、弱加密、占位符密钥 |
| **配置安全** | Config Security · Security Headers · CLI Config | CORS *、Debug 模式、配置注入 |
| **跨领域** | Global Sweep | 邮件 XSS、Header 注入、Legacy 解密 |

**每种类型都有独立的发现策略和分析预算，避免单一类型占满资源。**

---

## Slide 6 — Layer 3：AI Agent 自由推理

### 覆盖结构化检查无法触及的安全盲区

| 能力 | 示例 |
|------|------|
| **跨模块数据流追踪** | LLM 输出 → 命令执行链，跨 3 个文件的危险路径 |
| **业务逻辑缺陷** | 策略引擎的 Default-Allow 逻辑漏洞 |
| **实现特定弱点** | SSH 参数注入、命令黑名单绕过、慢速滴漏攻击 |
| **组件交互分析** | 策略 → 权限 → 执行链的授权间隙 |
| **资源管理** | 无限制下载、内存耗尽、磁盘空间耗尽 |
| **敏感数据暴露** | 日志中的凭据、审计轨迹中的密钥、错误响应中的堆栈 |

**AI Agent 发现了 SecOpsCode 项目中 Phase B 未覆盖的 10 个额外漏洞。**

---

## Slide 7 — 基准测试：MarqDex（Web App）

### 项目概况
- Next.js 16 + React 19 + Prisma + NextAuth v5
- ~30,000 行 TypeScript，25+ API 端点
- 三种方式独立扫描

### 结果对比

| 指标 | 规则引擎 | SAST v1 | **SAST v2** | Claude 原生 |
|------|----------|---------|-------------|-------------|
| 真阳性 | **0** | 13 | **29** | 27 |
| CRITICAL | 0 | 2 | **7** | 5 |
| HIGH | 0 | 5 | **15** | 8 |
| 误报率 | 100% | 7% | **3%** | 4% |

### 关键数字

- **v2 超越 Claude 原生 7%**（29 vs 27）
- **CRITICAL 级别领先 40%**（7 vs 5）
- **规则引擎零发现** — LLM 是唯一有效检测手段

---

## Slide 8 — 基准测试：SecOpsCode（CLI Tool）

### 项目概况
- Go 1.26 + Bubble Tea TUI
- ~2,400,000 行（80 倍于 MarqDex）
- 终端原生 SecOps AI 助手

### 结果对比

| 指标 | **SAST v2** | Claude 原生 |
|------|-------------|-------------|
| 真阳性 | **11**（持平） | 11 |
| CRITICAL | **1** | 0 |
| HIGH | **4** | 2 |
| 互补独有发现 | **5** | **5** |

### 关键发现

- **SAST 发现了最严重的漏洞**：`resolve.go` 中的 `$(cmd)` 配置解析 → 远程代码执行（RCE）
- **Claude 原生完全遗漏了这一 CRITICAL 级别漏洞**
- **两者互补**：合计覆盖 16 个独特漏洞（去除重叠）

---

## Slide 9 — 完整工具链：四个 Skill

### 端到端安全工作流

```
/sast-scan          /sast-triage         /sast-baseline        /sast-fix
   扫描      →       分类       →        基线管理      →        修复
```

| Skill | 成熟度 | 核心能力 |
|-------|--------|----------|
| **sast-scan** | 100% | 三层扫描（规则 + LLM + Agent），13 种发现类型，SARIF/JSON/MD 报告 |
| **sast-triage** | 100% | 自动分桶 → LLM 验证 → 置信度评分 → 导出误报到基线 |
| **sast-baseline** | 100% | 10 个命令全生命周期管理（含 diff/stats/audit/cleanup/import） |
| **sast-fix** | 100% | 三层修复（15 模板 → LLM 自定义 → 验证），支持 apply/rollback/分支隔离 |

**397 个测试全部通过，四个 Skill 功能完整度一致。**

---

## Slide 10 — 技术架构

### 多语言支持（12 种语言 + IaC）

| 优先级 | 语言 |
|--------|------|
| P0 | JavaScript / TypeScript, Python, Java / Kotlin, Go, C# |
| P1 | C/C++, PHP, Ruby, Rust, Swift, Terraform / IaC |

### CI/CD 集成

- **GitHub Actions** — 一键接入，SARIF 自动上传到 Code Scanning
- **GitLab CI** — 开箱即用模板
- **Docker** — 容器化运行，零依赖部署

### 部署方式

```
方式 1：Claude Code 中直接使用 /sast-scan
方式 2：命令行 python3 sast_runner.py
方式 3：CI/CD 流水线自动触发
方式 4：Docker 容器化运行
```

---

## Slide 11 — 核心优势对比

### OpenSAST vs 传统 SAST 工具

| 维度 | 传统 SAST | OpenSAST |
|------|-----------|----------|
| 检测方式 | 纯规则匹配 | 规则 + LLM + AI Agent |
| 误报率（MarqDex LLM 层） | 50-100% | **3%** |
| OWASP Benchmark 规则分 | — | **+39.6%** |
| 业务逻辑检测 | 不支持 | **13 种结构化 + 自由推理** |
| 跨模块分析 | 不支持 | **AI Agent 数据流追踪** |
| 修复建议 | 无或泛泛 | **15 模板 + LLM 定制 + 验证** |
| 占位符密钥检测 | 不支持 | **预扫描 + change-me 模式识别** |
| CI/CD 集成 | SARIF 输出 | **SARIF + Gate + 基线 + 审计** |
| 可重复性 | 高（但无效） | **高且有效** |

---

## Slide 12 — 适用场景

| 场景 | 推荐配置 | 价值 |
|------|----------|------|
| **开发者提交前检查** | `/sast-scan --changed-only --profile quick` | 秒级反馈，不影响开发节奏 |
| **PR 安全门禁** | CI + `--fail-on high` + baseline | 自动阻断高危，人工审查中危 |
| **版本发布审计** | `/sast-scan --profile deep` + triage | 全面覆盖 + 优先级排序 |
| **第三方代码审查** | standard + 严格 gate | 发现供应链引入的安全问题 |
| **安全合规报告** | SARIF + CWE/OWASP 映射 | 直接对接 GitHub Code Scanning |
| **安全团队运营** | 全链路 scan → triage → baseline → fix | 闭环管理，审计可追溯 |

---

## Slide 13 — 快速开始

### 3 分钟上手

```bash
# 1. 克隆
git clone https://github.com/chenchunrun/opensast.git

# 2. 安装依赖
pip install -r requirements.txt

# 3. 扫描你的项目
cd your-project
/sast-scan . --profile standard --format all

# 4. 查看结果
cat .claude/sast/results/report.md
```

### 开源协议

Apache License 2.0 — 完全免费，可商用

---

## Slide 14 — 数据总结

### 一页看懂 OpenSAST

```
┌──────────────────────────────────────────────────┐
│                                                    │
│   三层架构     规则引擎 + LLM + AI Agent            │
│                                                    │
│   13 种分析    IDOR → SSRF → CSRF → Crypto → ...   │
│                                                    │
│   4 个 Skill   Scan → Triage → Baseline → Fix      │
│                                                    │
│   15 修复模板   SQL注入 → 命令注入 → XSS → ...      │
│                                                    │
│   397 测试     100% 功能覆盖                        │
│                                                    │
│   269 规则     Semgrep 100% fixture 覆盖            │
│                                                    │
│   13 语言规则   JS/TS, Python, Java, Go, C#, ...    │
│                                                    │
│   +39.6%       OWASP Benchmark 规则分               │
│                                                    │
│   29 发现       vs Claude 原生 27 (MarqDex)         │
│                                                    │
│   11 发现       vs Claude 原生 11 (SecOpsCode)      │
│                                                    │
└──────────────────────────────────────────────────┘
```

---

## Slide 15 — 联系方式 / CTA

### 开始使用 OpenSAST

- **GitHub**: github.com/chenchunrun/opensast
- **协议**: Apache 2.0（免费商用）
- **反馈**: GitHub Issues

**让 AI 为你的代码安全保驾护航。**

---

## 附录：配图建议

| Slide | 建议配图 |
|-------|----------|
| 1 | 产品 Logo + 三层架构示意动画 |
| 2 | 误报数据可视化柱状图（17 误报 vs 0 真阳性） |
| 3 | 三层金字塔架构图（底层大、顶层尖） |
| 5 | 13 种发现类型的雷达图或矩阵图 |
| 7 | MarqDex 四列对比柱状图（规则/v1/v2/Claude） |
| 8 | SecOpsCode 发现数量对比 + CRITICAL 高亮 |
| 9 | 四个 Skill 流程图（Scan → Triage → Baseline → Fix） |
| 11 | 双列对比表格，OpenSAST 列用绿色高亮 |
| 14 | 大数字卡片布局（3% / 29 / 11 / 397） |
