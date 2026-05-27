# OpenSAST vs Claude 原生检测 — 真实项目对比报告（SecOpsCode）

## 1. 测试设计

### 目标项目

**SecOpsCode (Crush)** — 终端原生 SecOps AI 助手

| 属性 | 值 |
|------|-----|
| 技术栈 | Go 1.26 + Bubble Tea TUI |
| 语言 | Go (100%) |
| 代码量 | ~2,400,000 行（4.5GB） |
| 项目类型 | CLI 工具（安全运维代理） |
| 核心功能 | LLM 驱动命令执行、策略引擎、权限系统、20+ SecOps 工具 |
| Archetype | cli-tool |

### 对比方法

两种方式对同一项目独立扫描：

| 方式 | 描述 |
|------|------|
| **SAST Skill v2** | Gitleaks 规则扫描 → LLM 验证 + 10 种 discover 类型分析 |
| **Claude 原生审查** | 直接让 Claude 阅读代码进行安全审查，不使用任何工具 |

---

## 2. 检测结果总览

### 按严重级别统计

| 严重级别 | SAST Skill v2 | Claude 原生 |
|----------|---------------|-------------|
| CRITICAL | **1** | 0 |
| HIGH | **4** | 2 |
| MEDIUM | **4** | 8 |
| LOW | **2** | 1 |
| **合计 (真阳性)** | **11** | **11** |

### 检出率对比

```
SAST Skill v2   ██████████████████████████ 11 (含 1 CRITICAL)
Claude 原生      ██████████████████████████ 11 (无 CRITICAL)
```

两者真阳性数量相同，但 SAST v2 发现了 1 个 CRITICAL 级别漏洞。

---

## 3. 逐项漏洞对比

### CRITICAL 级别

| 漏洞 | CWE | SAST v2 | Claude 原生 |
|------|-----|---------|-------------|
| Config $(cmd) Shell 命令注入 | CWE-78 | **✓** | ✗ |

**CRITICAL 检出率**: SAST v2 1/1, Claude 原生 0/1

### HIGH 级别

| 漏洞 | CWE | SAST v2 | Claude 原生 |
|------|-----|---------|-------------|
| 策略系统未知工具 Default-Allow | CWE-276 | ✓ | ✓ |
| Fetch/Download 无 SSRF 防护 | CWE-918 | ✓ | ✓ |
| OLX API Key 硬编码在运行时数据 | CWE-798 | **✓** | ✗ |
| 工作区 Config 从不可信仓库加载合并 | CWE-426 | **✓** | ✗ |
| LLM 输出直接传递到远程 Shell | CWE-78 | ✗ | **✓** |

**HIGH 检出率**: SAST v2 4/5, Claude 原生 2/5

### MEDIUM 级别

| 漏洞 | CWE | SAST v2 | Claude 原生 |
|------|-----|---------|-------------|
| Write Tool 绝对路径绕过工作目录 | CWE-22 | ✓ | ✓ |
| Sandbox 危险模式仅匹配前缀 | CWE-184 | ✓ | ✓ |
| 加密密钥从身份信息派生（弱回退） | CWE-330 | ✓ | ✓ |
| 敏感值解密失败后仍继续使用 | CWE-312 | **✓** | ✗ |
| ProxyJump 参数验证较弱 | CWE-88 | ✗ | **✓** |
| Skip 模式可被精心构造的命令绕过 | CWE-274 | ✗ | **✓** |
| 敏感数据可能出现在风险分析 JSON 中 | CWE-532 | ✗ | **✓** |

**MEDIUM 检出率**: SAST v2 4/7, Claude 原生 5/7

### LOW 级别

| 漏洞 | CWE | SAST v2 | Claude 原生 |
|------|-----|---------|-------------|
| Bash 禁止命令列表可通过路径变体绕过 | CWE-184 | ✓ | ✓ |
| PostHog 公开分析 Key 硬编码 | CWE-798 | **✓** | ✗ |
| Download 工具无大小限制 | CWE-400 | ✗ | **✓** |

**LOW 检出率**: SAST v2 2/3, Claude 原生 2/3

---

## 4. 互补分析

### SAST v2 独有发现（Claude 原生未检出）

| 漏洞 | 严重级别 | 发现方式 |
|------|----------|----------|
| **Config $(cmd) Shell 命令注入** | **CRITICAL** | discover_cli_config 分析 resolve.go 的 Shell 变量解析器 |
| OLX 第三方 API Key 硬编码 | HIGH | discover_credentials 预扫描 + Gitleaks 联合发现 |
| 工作区 Config 从不可信目录加载 | HIGH | discover_cli_config 分析 load.go 的目录搜索逻辑 |
| 敏感值解密失败后仍继续 | MEDIUM | discover_cli_config 分析 store.go 加密容错逻辑 |
| PostHog 分析 Key 硬编码 | LOW | discover_credentials + Gitleaks 联合发现 |

### Claude 原生独有发现（SAST v2 未检出）

| 漏洞 | 严重级别 | 未检出原因 |
|------|----------|-----------|
| LLM 输出到远程 Shell 直接执行 | HIGH | SAST agent 判定为 FP（设计意图） |
| ProxyJump 参数验证较弱 | MEDIUM | discover_cli_config 未覆盖 SSH 参数验证 |
| Skip 模式绕过风险门控 | MEDIUM | SAST agent 判定为 FP（有 forceInteractive 保护） |
| 敏感数据泄露到风险分析 JSON | MEDIUM | 跨模块数据流分析超出当前 discover 范围 |
| Download 工具无大小限制 | LOW | 未被任何 discover 类型覆盖 |

---

## 5. 定量对比

| 指标 | SAST Skill v2 | Claude 原生 |
|------|---------------|-------------|
| 真阳性发现 | **11** | **11** |
| CRITICAL 发现 | **1** | 0 |
| HIGH 发现 | **4** | 2 |
| 误报数 | 1 | 1 |
| 覆盖漏洞类型 | 7/9 | 8/9 |
| 最大发现 | **Config $(cmd) RCE** | Remote Shell 命令注入 |
| 可重复性 | 高（自动化） | 低（依赖人工） |

### 漏洞类型覆盖

| 漏洞类型 | SAST v2 | Claude 原生 |
|----------|---------|-------------|
| 硬编码凭据/密钥 | ✓ | ✗ |
| 命令注入 | **✓ (CRITICAL)** | ✓ |
| 策略/权限绕过 | ✓ | ✓ |
| SSRF | ✓ | ✓ |
| 路径穿越 | ✓ | ✓ |
| 加密缺陷 | ✓ | ✓ |
| 不完整黑名单 | ✓ | ✓ |
| 敏感数据泄露 | ✗ | ✓ |
| 资源消耗 | ✗ | ✓ |

---

## 6. 结论

### 核心发现

1. **真阳性数量持平（11 vs 11）**，但 SAST v2 在严重性上领先（1 CRITICAL + 4 HIGH vs 0 CRITICAL + 2 HIGH）。
2. **SAST v2 发现了最严重的漏洞**：`resolve.go` 中的 `$(cmd)` 配置解析会在加载时执行任意 Shell 命令，构成远程代码执行（RCE）。Claude 原生完全遗漏了这一漏洞。
3. **Claude 原生在横向安全分析上更强**：ProxyJump 验证、Skip 模式绕过、敏感数据泄露等跨模块问题。
4. **两者高度互补**：各有 5 个独有发现，合计覆盖 16 个独特漏洞（去除重叠后）。

### 对比 MarqDex 项目

| 指标 | MarqDex (Web App) | SecOpsCode (CLI Tool) |
|------|-------------------|----------------------|
| 代码量 | ~30K 行 | ~2.4M 行（80x） |
| SAST v2 发现 | **29** (超 Claude) | **11** (持平 Claude) |
| Claude 原生发现 | 27 | 11 |
| SAST v2 CRITICAL | **7** | **1** |
| Claude 原生 CRITICAL | 5 | 0 |
| 互补发现数 | 4 | 10 |

**Web App 场景**下 SAST v2 的 web-app 特定 discover 类型（CSRF、安全头等）贡献了大量额外发现。
**CLI Tool 场景**下 discover_cli_config 是核心贡献者，特别是对配置解析器的深入分析发现了 CRITICAL 级别的 RCE。

### 改进方向

针对 CLI Tool 场景，可以增加以下 discover 类型：
- `discover_ssh_safety` — SSH 参数注入和远程执行安全
- `discover_blocklist_bypass` — 命令/路径黑名单绕过检测
- `discover_data_flow` — 跨模块敏感数据流追踪（如 LLM 输出 → 命令执行）

---

*Generated: 2026-05-27 | Target: SecOpsCode (~2.4M LoC Go) | SAST v2: 11 findings (1 CRITICAL) vs Claude: 11 findings (0 CRITICAL)*
