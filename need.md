以下是一份可直接作为立项 / 研发评审材料使用的 **《Claude Code 多语言 SAST Skill 开发需求说明书》**。我按“需求目标、Claude Code 适配约束、功能需求、工具链、目录结构、`SKILL.md` 草案、验收标准、里程碑”的方式整理。

---

# Claude Code 多语言 SAST Skill 开发需求说明书

## 1. 项目背景

拟开发一个基于 **Claude Code Skills** 的多语言 SAST 安全扫描 Skill，使开发者可以在 Claude Code 中通过 `/sast-scan` 等命令，对当前代码仓库、指定目录、Git 变更文件或 PR 差异进行静态应用安全测试，并输出可读报告、SARIF 结果、修复建议和 CI 门禁结果。

SAST 的核心价值是：在不运行应用的情况下，对静态源代码进行安全缺陷识别，覆盖污点分析、数据流分析等常见静态分析技术。OWASP 对静态代码分析的描述也强调，它通常在安全开发生命周期的实现阶段执行，用于发现非运行态源码中的潜在漏洞。([OWASP基金会][1])

本 Skill 应定位为 **“Claude Code 中的安全扫描编排与结果解释能力”**，而不是重新实现完整静态分析引擎。实际漏洞识别主要依赖成熟扫描器，Claude 负责项目识别、工具编排、结果归并、上下文解释、误报初筛、修复建议和必要时代码修复。

---

## 2. Claude Code Skills 适配依据

Claude Code Skill 的标准入口是 `.claude/skills/<skill-name>/SKILL.md`，`SKILL.md` 由 YAML frontmatter 和 Markdown 指令组成；目录名会成为可调用的 slash command，`description` 用于帮助 Claude 判断何时自动加载 Skill。([Claude API Docs][2])

Skill 可以包含辅助文件，例如模板、示例、脚本、参考文档等；官方文档建议将 `SKILL.md` 保持聚焦，把详细材料拆分到辅助文件中，并建议 `SKILL.md` 不超过 500 行。([Claude API Docs][2])

Claude Code Skill frontmatter 支持 `description`、`when_to_use`、`argument-hint`、`arguments`、`disable-model-invocation`、`allowed-tools`、`model`、`effort`、`context`、`agent` 等字段，其中 `allowed-tools` 可在 Skill 激活时对指定工具预授权，但它不是限制清单；未列入的工具仍受全局权限设置控制。([Claude API Docs][2]) ([Claude API Docs][2])

Claude Code Skills 还支持动态上下文注入：在 Skill Markdown 中使用 `!` 命令语法时，Claude Code 会在 Skill 内容发送给模型前先执行命令，并把命令输出替换进上下文。这个能力适合用于注入 Git diff、语言检测结果、扫描摘要等运行时信息。([Claude API Docs][2])

对于需要确定性执行的安全策略，例如“Claude 修改代码后自动运行轻量扫描”“禁止读取 `.env` 和密钥目录”“Stop 时生成审计摘要”，应优先使用 Claude Code Hooks。Hooks 可在 Claude Code 生命周期中的特定事件自动执行命令或 HTTP 回调，用于格式化、拦截、通知、上下文注入和规则 enforcement。([Claude API Docs][3])

---

## 3. 项目目标

### 3.1 总体目标

开发一个可复用、可扩展、可配置的 **Claude Code SAST Skill**，支持多语言项目的安全扫描、报告生成、漏洞解释、误报初筛、修复建议和 CI 集成。

### 3.2 具体目标

1. 支持通过 Claude Code 命令快速执行 SAST：

   * `/sast-scan`
   * `/sast-scan . --profile quick`
   * `/sast-scan src --profile deep --format sarif`
   * `/sast-scan --changed-only --fail-on high`

2. 自动识别项目语言、框架、构建系统和包管理器。

3. 编排多种扫描工具：

   * 通用 SAST：Semgrep
   * 深度语义分析：CodeQL，可选
   * 密钥扫描：Gitleaks
   * IaC 扫描：Checkov
   * 语言原生扫描器：按语言选配

4. 统一结果格式：

   * Markdown 报告
   * JSON 结构化报告
   * SARIF 2.1.0 报告

5. 将发现映射到：

   * CWE
   * OWASP Top 10
   * OWASP ASVS
   * 内部安全规范

6. 对扫描结果进行上下文解释：

   * 漏洞成因
   * 触发路径
   * 影响范围
   * 利用难度
   * 修复建议
   * 误报可能性

7. 支持开发阶段、代码审查阶段和 CI/CD 阶段三类使用场景。

---

## 4. 范围定义

### 4.1 MVP 范围

MVP 版本应至少包含：

| 模块       | MVP 要求                                 |
| -------- | -------------------------------------- |
| Skill 文档 | 提供 `.claude/skills/sast-scan/SKILL.md` |
| 扫描入口     | 提供统一 CLI wrapper，例如 `sast_runner.py`   |
| 语言识别     | 支持通过文件扩展名、manifest 文件、构建文件识别语言         |
| 通用扫描     | 集成 Semgrep                             |
| 密钥扫描     | 集成 Gitleaks                            |
| IaC 扫描   | 集成 Checkov，可选启用                        |
| 结果格式     | 输出 Markdown、JSON、SARIF                 |
| 报告解释     | Claude 对结果进行分级、解释、修复建议                 |
| CI 门禁    | 支持按严重级别返回非零退出码                         |
| 配置文件     | 支持 `.claude/sast/config.yml`           |
| 基线机制     | 支持忽略历史存量问题，仅阻断新增高危问题                   |

### 4.2 非 MVP 范围

以下能力建议作为后续版本：

| 能力            | 说明                      |
| ------------- | ----------------------- |
| 自研完整 SAST 引擎  | 不建议在 Skill MVP 中实现      |
| 运行时 DAST      | 不属于 SAST Skill 核心范围     |
| SCA 深度依赖漏洞分析  | 可作为后续 `/sca-scan` Skill |
| 自动 exploit 生成 | 不纳入需求                   |
| 云端集中平台        | 后续可扩展                   |
| 组织级规则治理平台     | 后续可扩展                   |
| 多租户权限系统       | 后续平台化时考虑                |

---

## 5. 目标用户与使用场景

### 5.1 目标用户

| 用户角色          | 主要诉求                                 |
| ------------- | ------------------------------------ |
| 普通开发者         | 在提交前快速发现安全问题并获得修复建议                  |
| 安全工程师         | 对仓库进行批量扫描、规则调优、误报分析                  |
| Tech Lead     | 在代码审查阶段发现高风险变更                       |
| DevSecOps 工程师 | 将扫描结果接入 CI/CD 和 GitHub code scanning |
| AI 编程用户       | 让 Claude 修改代码后自动执行安全复核               |

### 5.2 典型场景

1. **本地开发自查**
   开发者运行 `/sast-scan --changed-only --profile quick`，扫描 Git 变更文件。

2. **全仓安全扫描**
   安全工程师运行 `/sast-scan . --profile deep --format markdown,sarif`。

3. **代码修复辅助**
   Claude 根据扫描结果定位漏洞代码，提出最小修复补丁，并建议回归测试。

4. **CI 门禁**
   在 GitHub Actions 或 GitLab CI 中执行统一 wrapper，若新增 High/Critical 问题则失败。

5. **规则开发**
   安全工程师通过 `/sast-rule-author` 生成或调整 Semgrep 规则，并运行测试样例验证。

---

## 6. 工具链选型要求

### 6.1 基础工具链

| 工具                      | 定位            | 是否 MVP 必须 |
| ----------------------- | ------------- | --------- |
| Semgrep                 | 多语言通用 SAST 扫描 | 必须        |
| CodeQL                  | 深度语义与数据流分析    | 建议 P1     |
| Gitleaks                | 密钥泄露扫描        | 必须        |
| Checkov                 | IaC 静态扫描      | 建议 MVP 可选 |
| SARIF parser / merger   | 结果标准化与合并      | 必须        |
| Python wrapper          | 统一编排工具        | 必须        |
| Docker image            | 统一运行环境        | 建议 P1     |
| GitHub Actions template | CI 集成         | 必须        |
| GitLab CI template      | CI 集成         | 建议 P1     |

Semgrep 官方文档显示其 SAST 能力覆盖多种语言，Semgrep Code 列表中包含 C/C++、C#、Go、Java、JavaScript、Kotlin、Python、TypeScript、Ruby、Rust、PHP、Scala、Swift、Terraform、JSON 等 GA 语言。([Semgrep][4])

CodeQL 官方文档列出了 C/C++、C#、Go、Java/Kotlin、JavaScript/TypeScript、Python、Ruby、Rust、Swift、GitHub Actions 等语言指南，适合作为深度分析引擎补充。([CodeQL][5])

Gitleaks 可用于检测 Git 仓库、文件和 stdin 中的密码、API key、token 等 secrets。([GitHub][6])

Checkov 是用于基础设施即代码的静态代码分析工具，也支持云配置、容器镜像和开源包相关检查。([GitHub][7])

### 6.2 SARIF 输出要求

SARIF 是静态分析工具结果输出的行业标准格式；GitHub code scanning 支持 SARIF 2.1.0，因此本项目应将 SARIF 2.1.0 作为标准输出格式之一。([SARIF][8]) ([GitHub Docs][9])

Semgrep CLI 支持 `--sarif` 和 `--sarif-output`，CodeQL CLI 也支持 SARIF 输出，因此扫描 wrapper 应优先调用各工具原生 SARIF 输出，再进行归并、标准化和去重。([Semgrep][10]) ([GitHub Docs][11])

---

## 7. 多语言适配要求

### 7.1 语言覆盖分级

| 级别 | 语言                       | 要求                   |
| -- | ------------------------ | -------------------- |
| P0 | JavaScript / TypeScript  | 必须支持                 |
| P0 | Python                   | 必须支持                 |
| P0 | Java / Kotlin            | 必须支持                 |
| P0 | Go                       | 必须支持                 |
| P0 | C#                       | 必须支持                 |
| P1 | C / C++                  | 支持深度扫描               |
| P1 | PHP                      | 支持通用扫描               |
| P1 | Ruby                     | 支持通用扫描               |
| P1 | Rust                     | 支持通用扫描               |
| P1 | Swift                    | 支持通用扫描               |
| P1 | Terraform / IaC          | 支持 Checkov / Semgrep |
| P2 | Scala、Dart、Elixir、Apex 等 | 基于 Semgrep 可用性扩展     |

### 7.2 语言扫描策略

| 语言                      | 基础扫描    | 深度扫描   | 原生补充工具                         | 重点漏洞类型                    |
| ----------------------- | ------- | ------ | ------------------------------ | ------------------------- |
| JavaScript / TypeScript | Semgrep | CodeQL | ESLint security 插件             | XSS、SSRF、命令注入、原型污染、路径穿越   |
| Python                  | Semgrep | CodeQL | Bandit                         | 反序列化、命令注入、SQL 注入、硬编码密钥    |
| Java / Kotlin           | Semgrep | CodeQL | SpotBugs / FindSecBugs         | SQL 注入、XXE、反序列化、SSRF、鉴权绕过 |
| Go                      | Semgrep | CodeQL | gosec                          | SSRF、命令注入、弱加密、路径穿越        |
| C# / .NET               | Semgrep | CodeQL | Roslyn analyzers               | 注入、反序列化、弱加密、身份认证缺陷        |
| C / C++                 | Semgrep | CodeQL | clang-tidy / cppcheck          | 缓冲区溢出、UAF、整数溢出、内存安全       |
| Ruby                    | Semgrep | CodeQL | Brakeman                       | Rails 注入、XSS、路径穿越         |
| PHP                     | Semgrep | 可选     | Psalm / PHPStan security rules | SQL 注入、文件包含、XSS、命令注入      |
| Rust                    | Semgrep | CodeQL | cargo-audit 可作为 SCA 补充         | unsafe 使用、命令注入、路径处理       |
| Swift                   | Semgrep | CodeQL | SwiftLint security rules       | 隐私泄露、不安全存储、弱加密            |
| Terraform / IaC         | Semgrep | 不适用    | Checkov                        | 云配置错误、公开存储桶、过宽 IAM        |

---

## 8. 核心功能需求

## 8.1 Skill 调用需求

### FR-001：提供主命令 `/sast-scan`

命令格式：

```bash
/sast-scan [target] [--profile quick|standard|deep] [--changed-only] [--lang auto|js|ts|python|java|go|csharp|cpp|php|ruby|rust|swift|iac] [--format markdown|json|sarif|all] [--fail-on low|medium|high|critical] [--baseline path] [--fix-suggestions]
```

默认行为：

```bash
/sast-scan .
```

等价于：

```bash
/sast-scan . --profile standard --lang auto --format markdown
```

### FR-002：提供辅助命令

建议拆分多个 Skill 或同一 Skill 的参数模式：

| 命令                  | 用途                        |
| ------------------- | ------------------------- |
| `/sast-scan`        | 执行扫描                      |
| `/sast-triage`      | 对已有结果进行误报分析和优先级排序         |
| `/sast-fix`         | 针对指定 finding 生成修复方案       |
| `/sast-rule-author` | 生成或调整 Semgrep / CodeQL 规则 |
| `/sast-baseline`    | 生成或更新基线                   |
| `/sast-ci-gate`     | 生成 CI 配置或执行门禁判断           |

MVP 可先实现 `/sast-scan`，其他命令作为后续扩展。

---

## 8.2 仓库识别需求

### FR-003：自动识别项目结构

扫描前必须识别：

1. Git 仓库根目录
2. 当前工作目录
3. 目标扫描路径
4. 是否 monorepo
5. 语言分布
6. manifest 文件
7. 构建文件
8. 忽略目录
9. 历史扫描基线
10. 是否存在已有 SAST / lint / CI 配置

识别文件示例：

| 生态      | 识别文件                                                            |
| ------- | --------------------------------------------------------------- |
| Node.js | `package.json`、`pnpm-lock.yaml`、`yarn.lock`、`package-lock.json` |
| Python  | `pyproject.toml`、`requirements.txt`、`Pipfile`、`poetry.lock`     |
| Java    | `pom.xml`、`build.gradle`、`settings.gradle`                      |
| Go      | `go.mod`、`go.sum`                                               |
| .NET    | `.csproj`、`.sln`                                                |
| Rust    | `Cargo.toml`、`Cargo.lock`                                       |
| PHP     | `composer.json`、`composer.lock`                                 |
| Ruby    | `Gemfile`、`Gemfile.lock`                                        |
| C/C++   | `CMakeLists.txt`、`Makefile`、`compile_commands.json`             |
| IaC     | `.tf`、`cloudformation.yaml`、`kubernetes/*.yaml`                 |

---

## 8.3 扫描配置需求

### FR-004：支持三种扫描 profile

| Profile  | 用途             | 扫描范围                       | 目标耗时      |
| -------- | -------------- | -------------------------- | --------- |
| quick    | 本地提交前快速检查      | Git changed files / 指定文件   | 秒级到 2 分钟  |
| standard | 常规仓库扫描         | 全仓主要语言 + secrets + IaC     | 2–10 分钟   |
| deep     | 安全评审 / CI 夜间任务 | 全仓 + CodeQL + 数据流分析 + 扩展规则 | 可超过 10 分钟 |

### FR-005：支持配置文件

配置文件路径：

```text
.claude/sast/config.yml
```

示例：

```yaml
version: 1

default_profile: standard

targets:
  include:
    - src
    - app
    - packages
  exclude:
    - node_modules
    - vendor
    - dist
    - build
    - .git
    - .venv

profiles:
  quick:
    changed_only: true
    tools:
      semgrep: true
      gitleaks: true
      codeql: false
      checkov: false
    fail_on: critical

  standard:
    changed_only: false
    tools:
      semgrep: true
      gitleaks: true
      codeql: false
      checkov: true
    fail_on: high

  deep:
    changed_only: false
    tools:
      semgrep: true
      gitleaks: true
      codeql: true
      checkov: true
    fail_on: medium

severity_mapping:
  block:
    - critical
    - high
  warn:
    - medium
  info:
    - low
    - info

report:
  formats:
    - markdown
    - json
    - sarif
  output_dir: .claude/sast/results

baseline:
  enabled: true
  file: .claude/sast/baseline.json

rules:
  semgrep:
    - auto
    - .claude/skills/sast-scan/rules/semgrep
  codeql:
    - security-extended
    - security-and-quality
```

---

## 8.4 扫描执行需求

### FR-006：统一扫描 wrapper

必须提供统一入口脚本：

```bash
python3 .claude/skills/sast-scan/tools/sast_runner.py
```

参数：

```bash
--target <path>
--profile <quick|standard|deep>
--changed-only
--lang <auto|...>
--format <markdown|json|sarif|all>
--output-dir <path>
--fail-on <severity>
--baseline <path>
--config <path>
--no-network
--tool-timeout <seconds>
--max-target-size-mb <number>
```

输出：

```text
.claude/sast/results/
├── summary.json
├── findings.json
├── report.md
├── merged.sarif
├── semgrep.sarif
├── gitleaks.sarif
├── checkov.sarif
├── codeql.sarif
└── logs/
    ├── runner.log
    └── tool-versions.txt
```

### FR-007：扫描器执行策略

扫描 wrapper 应按以下顺序执行：

1. 加载配置
2. 检测 Git 根目录
3. 识别语言和项目类型
4. 计算扫描目标
5. 检查工具是否安装
6. 执行 Semgrep
7. 执行 Gitleaks
8. 执行 Checkov
9. 条件执行 CodeQL
10. 收集 SARIF / JSON / CLI 输出
11. 统一归一化 findings
12. 去重和基线过滤
13. 生成报告
14. 根据门禁规则返回 exit code

---

## 8.5 结果归并与标准化需求

### FR-008：统一 finding schema

内部统一 finding 格式：

```json
{
  "id": "stable-finding-id",
  "tool": "semgrep",
  "rule_id": "python.lang.security.audit.subprocess-shell-true",
  "title": "Possible command injection",
  "severity": "high",
  "confidence": "medium",
  "language": "python",
  "file": "src/app.py",
  "start_line": 42,
  "end_line": 45,
  "cwe": ["CWE-78"],
  "owasp": ["A03: Injection"],
  "asvs": ["V5"],
  "message": "User controlled input reaches shell command execution.",
  "evidence": {
    "source": "request.args.get('cmd')",
    "sink": "subprocess.run(..., shell=True)",
    "dataflow": []
  },
  "recommendation": "Avoid shell=True and pass arguments as an array.",
  "fingerprint": "sha256(...)",
  "is_new": true,
  "is_suppressed": false,
  "suppression_reason": null
}
```

### FR-009：去重规则

同一个漏洞由多个工具报告时，应按以下字段聚合：

1. 文件路径
2. 起止行
3. CWE
4. sink 类型
5. 规则 ID
6. 代码片段 hash
7. 数据流 hash

聚合后保留：

* 所有来源工具
* 最高严重级别
* 最可信证据
* Claude 生成的综合解释

---

## 8.6 报告需求

### FR-010：Markdown 报告

报告结构：

```markdown
# SAST Scan Report

## Summary

- Target:
- Profile:
- Scan time:
- Languages:
- Tools:
- Total findings:
- New findings:
- Blocking findings:

## Risk Overview

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 2 |
| Medium | 5 |
| Low | 8 |

## Top Findings

### 1. Possible command injection

- Severity:
- Confidence:
- Tool:
- CWE:
- OWASP:
- File:
- Line:
- Why it matters:
- Evidence:
- Recommended fix:
- Suggested patch:
- Validation steps:

## Suppressed / Baseline Findings

## Tool Logs

## CI Gate Result
```

### FR-011：SARIF 报告

必须输出：

```text
merged.sarif
```

要求：

1. SARIF version 为 `2.1.0`
2. 每个 tool run 保留原始 tool 信息
3. 每个 result 包含 ruleId、level、message、locations
4. 能被 GitHub code scanning 接收
5. 不包含明文 secrets
6. 不包含绝对本地路径，除非配置允许

---

## 8.7 Claude 分析与修复需求

### FR-012：Claude 对结果进行安全解释

Claude 在读取扫描摘要后，应输出：

1. 最高风险问题
2. 是否可被外部输入触发
3. 是否存在明显数据流
4. 是否可能是误报
5. 修复优先级
6. 推荐修复方式
7. 回归测试建议

### FR-013：Claude 修复限制

Claude 不应默认自动修改代码。只有用户明确要求 `/sast-fix <finding-id>` 或“请修复这个问题”时，才允许生成补丁。

自动修复必须遵循：

1. 最小修改原则
2. 不改变业务行为
3. 不引入新依赖，除非用户确认
4. 修改后运行相关测试
5. 修改后重新执行目标扫描
6. 对无法确定的修复给出人工确认点

---

## 8.8 规则库需求

### FR-014：规则目录

```text
.claude/skills/sast-scan/rules/
├── semgrep/
│   ├── common/
│   ├── javascript/
│   ├── typescript/
│   ├── python/
│   ├── java/
│   ├── go/
│   ├── csharp/
│   ├── cpp/
│   ├── php/
│   ├── ruby/
│   ├── rust/
│   ├── swift/
│   └── iac/
├── codeql/
│   ├── javascript/
│   ├── python/
│   ├── java/
│   └── go/
└── tests/
    ├── vulnerable/
    └── safe/
```

### FR-015：规则元数据

每条自定义规则必须包含：

```yaml
id: org.security.python.command-injection.subprocess-shell
languages:
  - python
severity: ERROR
metadata:
  category: security
  cwe:
    - "CWE-78"
  owasp:
    - "A03:2021-Injection"
  confidence: HIGH
  likelihood: MEDIUM
  impact: HIGH
  references:
    - "internal-secure-coding-guide"
message: Avoid shell=True with user-controlled input.
```

### FR-016：规则测试

每条自定义规则必须提供：

1. 至少一个 positive case
2. 至少一个 negative case
3. 预期命中位置
4. 规则说明
5. 修复建议
6. 误报边界说明

Semgrep CLI 支持规则校验能力，例如 `--validate`，因此规则开发流程应包含规则 lint 和测试。([Semgrep][10])

---

## 9. 安全与权限需求

### 9.1 敏感文件保护

Claude Code 支持通过 `permissions.deny` 阻止读取 `.env`、secrets、credentials 等敏感文件；SAST Skill 应提供推荐配置，避免扫描过程和报告中泄露密钥。([Claude API Docs][12])

建议配置：

```json
{
  "permissions": {
    "deny": [
      "Read(./.env)",
      "Read(./.env.*)",
      "Read(./secrets/**)",
      "Read(./config/credentials.json)",
      "Read(./**/id_rsa)",
      "Read(./**/*.pem)",
      "Read(./**/*.key)"
    ]
  }
}
```

### 9.2 扫描数据保护

必须满足：

1. 默认本地执行扫描。
2. 默认不上传源码。
3. 默认不把 secrets 明文写入报告。
4. 所有 token、password、private key 在日志和报告中脱敏。
5. 扫描日志不得包含完整环境变量。
6. 网络访问默认关闭，除非用户明确启用。
7. CI 中不得输出敏感代码片段到公开日志。

### 9.3 工具执行权限

`allowed-tools` 只允许预授权必要命令，例如：

* `Read`
* `Grep`
* `Glob`
* `Bash(git status --short)`
* `Bash(git diff --name-only *)`
* `Bash(python3 .claude/skills/sast-scan/tools/sast_runner.py *)`

不得预授权：

* 任意 `curl`
* 任意 `wget`
* 任意包安装命令
* 任意删除命令
* 任意密钥读取命令
* 任意外部上传命令

---

## 10. 建议目录结构

```text
.claude/
├── skills/
│   └── sast-scan/
│       ├── SKILL.md
│       ├── README.md
│       ├── templates/
│       │   ├── report.md
│       │   ├── finding.md
│       │   └── ci-summary.md
│       ├── tools/
│       │   ├── sast_runner.py
│       │   ├── detect_project.py
│       │   ├── run_semgrep.py
│       │   ├── run_codeql.py
│       │   ├── run_gitleaks.py
│       │   ├── run_checkov.py
│       │   ├── sarif_merge.py
│       │   ├── normalize_findings.py
│       │   ├── baseline.py
│       │   ├── report_writer.py
│       │   ├── redact.py
│       │   └── ci_gate.py
│       ├── rules/
│       │   ├── semgrep/
│       │   ├── codeql/
│       │   └── tests/
│       ├── config/
│       │   ├── default.yml
│       │   ├── severity-map.yml
│       │   └── language-map.yml
│       ├── examples/
│       │   ├── vulnerable-python/
│       │   ├── vulnerable-node/
│       │   └── vulnerable-java/
│       └── docs/
│           ├── rule-authoring.md
│           ├── triage-guide.md
│           ├── ci-integration.md
│           └── suppression-policy.md
└── sast/
    ├── config.yml
    ├── baseline.json
    └── results/
```

---

## 11. `SKILL.md` 草案

````markdown
---
name: sast-scan
description: Run multi-language Static Application Security Testing for the current repository or selected paths. Use when the user asks to scan code for vulnerabilities, review security issues, analyze Git changes, generate SARIF, triage findings, or prepare CI security gates.
when_to_use: Use this skill for SAST, static code analysis, secure code review, vulnerability scanning, Semgrep, CodeQL, Gitleaks, Checkov, SARIF reports, CWE/OWASP mapping, and security fix recommendations.
argument-hint: "[target] [--profile quick|standard|deep] [--changed-only] [--format markdown|json|sarif|all] [--fail-on low|medium|high|critical]"
disable-model-invocation: true
allowed-tools:
  - Read
  - Grep
  - Glob
  - "Bash(git status --short)"
  - "Bash(git diff --name-only *)"
  - "Bash(python3 .claude/skills/sast-scan/tools/sast_runner.py *)"
---

# Multi-language SAST Scan

You are running a controlled Static Application Security Testing workflow.

## Operating principles

- Treat the scan as a security-sensitive workflow.
- Do not read `.env`, private keys, credentials, or secret files unless the user explicitly authorizes it.
- Do not print raw secrets in the response.
- Prefer local scanning.
- Do not install tools automatically unless the user explicitly asks.
- Do not modify source code unless the user explicitly asks for remediation.
- If scanner output and code context disagree, explain the uncertainty.
- Prioritize actionable findings over noisy findings.

## Input

User arguments:

```text
$ARGUMENTS
````

If no target is provided, scan the current repository root.

## Workflow

1. Determine the scan target and profile.
2. Inspect the repository structure.
3. Identify languages, frameworks, package managers, and IaC files.
4. Run the SAST wrapper with the requested profile.
5. Read the generated summary and report.
6. Explain the most important findings.
7. Highlight blocking issues based on the configured gate.
8. Provide remediation guidance.
9. Ask for explicit permission before applying code changes.

## Run scanner

Use the bundled runner:

```bash
python3 .claude/skills/sast-scan/tools/sast_runner.py $ARGUMENTS
```

The runner should produce:

* `.claude/sast/results/summary.json`
* `.claude/sast/results/findings.json`
* `.claude/sast/results/report.md`
* `.claude/sast/results/merged.sarif`

## Report format

After scanning, respond with:

1. Scan scope
2. Tools executed
3. Languages detected
4. Risk summary
5. Blocking findings
6. Top 5 actionable findings
7. False-positive notes
8. Recommended next actions
9. Paths to generated reports

## Finding explanation format

For each important finding:

* Title:
* Severity:
* Confidence:
* File and line:
* CWE / OWASP:
* Why it matters:
* Evidence:
* Exploitability:
* Recommended fix:
* Validation steps:

## Remediation policy

Only propose patches unless the user explicitly asks to modify code.

When fixing:

1. Make the smallest safe change.
2. Preserve behavior.
3. Add or update tests when appropriate.
4. Re-run the relevant scan.
5. Summarize what changed.

````

---

## 12. 核心脚本需求

### 12.1 `sast_runner.py`

职责：

1. 解析命令参数
2. 加载配置文件
3. 调用项目识别模块
4. 调用各扫描器
5. 统一收集结果
6. 调用 SARIF merge
7. 调用 baseline filter
8. 调用 report writer
9. 调用 CI gate
10. 返回标准 exit code

Exit code 设计：

| Exit Code | 含义 |
|---:|---|
| 0 | 扫描完成，无阻断问题 |
| 1 | 扫描完成，存在阻断问题 |
| 2 | 参数错误 |
| 3 | 工具缺失 |
| 4 | 扫描器执行失败 |
| 5 | 报告生成失败 |
| 6 | 配置错误 |

### 12.2 `detect_project.py`

输出示例：

```json
{
  "repo_root": "/repo",
  "is_git_repo": true,
  "languages": {
    "python": 42,
    "typescript": 28,
    "terraform": 5
  },
  "manifests": [
    "pyproject.toml",
    "package.json"
  ],
  "frameworks": [
    "fastapi",
    "react"
  ],
  "recommended_tools": [
    "semgrep",
    "gitleaks",
    "checkov"
  ]
}
````

### 12.3 `sarif_merge.py`

职责：

1. 读取多个 SARIF 文件
2. 校验 SARIF version
3. 合并 runs
4. 标准化 severity
5. 归一化路径
6. 删除 secrets
7. 输出 `merged.sarif`

### 12.4 `baseline.py`

职责：

1. 生成 finding fingerprint
2. 对比历史 baseline
3. 标注 `is_new`
4. 支持 suppression
5. 支持 suppression 到期时间

suppression 示例：

```yaml
suppressions:
  - fingerprint: "sha256:..."
    reason: "False positive: input is server-generated"
    owner: "security-team"
    expires_at: "2026-12-31"
```

### 12.5 `report_writer.py`

职责：

1. 生成 Markdown 报告
2. 生成 JSON summary
3. 生成 CI summary
4. 生成 Claude 可读摘要
5. 输出修复建议模板

---

## 13. CI/CD 集成需求

### 13.1 GitHub Actions

生成模板：

```yaml
name: SAST

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  sast:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install SAST tools
        run: |
          python -m pip install --upgrade pip
          pip install semgrep checkov

      - name: Run SAST
        run: |
          python3 .claude/skills/sast-scan/tools/sast_runner.py \
            --target . \
            --profile standard \
            --format all \
            --fail-on high

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: .claude/sast/results/merged.sarif
```

### 13.2 GitLab CI

生成模板：

```yaml
sast:
  stage: test
  image: python:3.11
  script:
    - pip install semgrep checkov
    - python3 .claude/skills/sast-scan/tools/sast_runner.py --target . --profile standard --format all --fail-on high
  artifacts:
    when: always
    paths:
      - .claude/sast/results/
```

---

## 14. Claude Code Hooks 集成建议

建议提供可选 hooks 配置，用于 Claude 修改文件后运行轻量扫描。

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "python3 .claude/skills/sast-scan/tools/sast_runner.py --changed-only --profile quick --format json"
          }
        ]
      }
    ],
    "Stop": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "test -f .claude/sast/results/summary.json && cat .claude/sast/results/summary.json || true"
          }
        ]
      }
    ]
  }
}
```

该配置应默认关闭，由用户或团队显式启用。Hooks 是确定性自动化机制，适合在 Claude Code 生命周期中特定事件运行命令。([Claude API Docs][13])

---

## 15. 安全分类与映射需求

### 15.1 必须支持 CWE 映射

MITRE CWE Top 25 是常用的软件弱点优先级参考；当前 CWE 官方页面显示 2025 Top 25 及相关列表已发布，并在 2026 年 1 月 29 日更新。([cwe.mitre.org][14])

### 15.2 必须支持 OWASP 映射

OWASP Top 10 是 Web 应用最关键安全风险的通用认知标准；OWASP 当前页面显示最新发布版本为 OWASP Top 10:2025。([OWASP基金会][15])

### 15.3 建议支持 ASVS 映射

OWASP ASVS 当前稳定版本为 5.0.0，发布日期为 2025 年 5 月，适合作为企业安全需求映射基线。([GitHub][16])

---

## 16. 非功能需求

| 类别   | 要求                       |
| ---- | ------------------------ |
| 可用性  | 一条命令完成扫描、解释和报告           |
| 可扩展性 | 可新增工具、语言、规则包             |
| 可维护性 | 工具 wrapper 与 Skill 指令解耦  |
| 可复现性 | 记录工具版本、参数、扫描范围           |
| 性能   | quick profile 应适合提交前使用   |
| 安全性  | 默认本地运行，不泄露 secrets       |
| 可审计性 | 记录扫描日志和配置快照              |
| 兼容性  | 支持 macOS、Linux、WSL、CI 容器 |
| 稳定性  | 单个工具失败不应导致所有报告不可用        |
| 可解释性 | 每个高危 finding 必须有证据和修复建议  |

---

## 17. 验收标准

### 17.1 MVP 验收

| 编号     | 验收项                     | 标准                            |
| ------ | ----------------------- | ----------------------------- |
| AC-001 | Skill 可被 Claude Code 识别 | `/sast-scan` 可调用              |
| AC-002 | 可扫描当前仓库                 | 默认 target 为 repo root         |
| AC-003 | 支持多语言识别                 | 至少识别 JS/TS、Python、Java、Go、C#  |
| AC-004 | Semgrep 可执行             | 生成 Semgrep 结果                 |
| AC-005 | Gitleaks 可执行            | 生成 secrets 扫描结果               |
| AC-006 | SARIF 可生成               | 输出 `merged.sarif`             |
| AC-007 | Markdown 报告可生成          | 输出 `report.md`                |
| AC-008 | 严重级别门禁可用                | High/Critical 可返回 exit code 1 |
| AC-009 | 基线过滤可用                  | 历史问题不阻断新增问题                   |
| AC-010 | Claude 可解释结果            | 输出 top findings、影响、修复建议       |
| AC-011 | 不泄露 secrets             | 报告中 secrets 被脱敏               |
| AC-012 | CI 模板可运行                | GitHub Actions 能上传 SARIF      |

### 17.2 质量验收

| 指标                  | 目标           |
| ------------------- | ------------ |
| quick profile 耗时    | 小型项目小于 2 分钟  |
| standard profile 耗时 | 中型项目小于 10 分钟 |
| 报告生成成功率             | 95% 以上       |
| SARIF 校验通过率         | 100%         |
| 高危 finding 解释完整率    | 100%         |
| secrets 脱敏覆盖率       | 100%         |
| 单工具失败容错             | 其他工具结果仍可报告   |

---

## 18. 里程碑建议

### Phase 0：设计与 PoC

交付：

1. `SKILL.md` 初版
2. `sast_runner.py` PoC
3. Semgrep 扫描集成
4. Markdown 报告 PoC
5. 一个 Python / Node.js 示例仓库验证

### Phase 1：MVP

交付：

1. Semgrep + Gitleaks + Checkov
2. 语言识别
3. SARIF merge
4. JSON / Markdown 报告
5. CI gate
6. baseline
7. GitHub Actions 模板
8. secrets 脱敏

### Phase 2：深度分析

交付：

1. CodeQL 集成
2. Java / JS / Python / Go 深度扫描
3. 自定义规则测试框架
4. `/sast-triage`
5. `/sast-fix`
6. Docker 运行环境

### Phase 3：企业化

交付：

1. 组织级规则包
2. ASVS / CWE / OWASP 映射平台
3. 规则版本管理
4. 扫描趋势报告
5. 多仓库批量扫描
6. IDE / PR Review 集成
7. 安全例外审批流

---

## 19. 风险与应对

| 风险                | 影响           | 应对                                   |
| ----------------- | ------------ | ------------------------------------ |
| SAST 误报较多         | 开发者不信任结果     | 引入 confidence、baseline、Claude triage |
| 多语言工具链复杂          | 安装维护成本高      | 使用 profile 和 Docker 镜像               |
| CodeQL 构建复杂       | deep scan 失败 | MVP 不强依赖 CodeQL，作为 P1                |
| secrets 泄露到报告     | 严重安全事故       | 强制 redaction，默认 deny sensitive files |
| Claude 自动修复引入 bug | 业务风险         | 默认只建议，不自动修改                          |
| monorepo 扫描耗时长    | CI 变慢        | changed-only、路径过滤、缓存                 |
| 规则维护成本高           | 规则老化         | 规则测试、版本化、owner 机制                    |
| 工具输出格式不一致         | 报告不可读        | 统一 finding schema 和 SARIF merge      |

---

## 20. 推荐最终交付物清单

```text
1. .claude/skills/sast-scan/SKILL.md
2. .claude/skills/sast-scan/README.md
3. .claude/skills/sast-scan/tools/sast_runner.py
4. .claude/skills/sast-scan/tools/detect_project.py
5. .claude/skills/sast-scan/tools/sarif_merge.py
6. .claude/skills/sast-scan/tools/normalize_findings.py
7. .claude/skills/sast-scan/tools/report_writer.py
8. .claude/skills/sast-scan/tools/baseline.py
9. .claude/skills/sast-scan/tools/redact.py
10. .claude/skills/sast-scan/config/default.yml
11. .claude/skills/sast-scan/rules/semgrep/
12. .claude/skills/sast-scan/templates/report.md
13. .claude/skills/sast-scan/docs/ci-integration.md
14. .claude/skills/sast-scan/docs/rule-authoring.md
15. .github/workflows/sast.yml
16. Dockerfile.sast
17. tests/fixtures/
18. tests/test_sast_runner.py
19. tests/test_sarif_merge.py
20. tests/test_redaction.py
```

---

## 21. 建议的 MVP 成品定位

MVP 不要追求“替代商业 SAST 平台”，而应聚焦为：

> 一个可在 Claude Code 内直接调用的、多语言 SAST 编排与解释 Skill。它负责识别项目、调用成熟扫描器、统一结果、生成 SARIF 和 Markdown 报告，并让 Claude 基于代码上下文给出可执行的安全修复建议。

这样设计的好处是工程可控、交付快、可扩展，并且符合 Claude Code Skill 的能力边界。

[1]: https://owasp.org/www-community/controls/Static_Code_Analysis?utm_source=chatgpt.com "Static Code Analysis"
[2]: https://docs.anthropic.com/en/docs/claude-code/skills "Extend Claude with skills - Claude Code Docs"
[3]: https://docs.anthropic.com/en/docs/claude-code/hooks-guide "Automate workflows with hooks - Claude Code Docs"
[4]: https://semgrep.dev/docs/supported-languages?utm_source=chatgpt.com "Supported languages"
[5]: https://codeql.github.com/docs/codeql-language-guides/?utm_source=chatgpt.com "CodeQL language guides - GitHub"
[6]: https://github.com/gitleaks/gitleaks?utm_source=chatgpt.com "Find secrets with Gitleaks"
[7]: https://github.com/bridgecrewio/checkov?utm_source=chatgpt.com "bridgecrewio/checkov: Prevent cloud misconfigurations ..."
[8]: https://sarifweb.azurewebsites.net/?utm_source=chatgpt.com "SARIF Home"
[9]: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support-for-code-scanning?utm_source=chatgpt.com "SARIF support for code scanning"
[10]: https://semgrep.dev/docs/cli-reference?utm_source=chatgpt.com "CLI reference"
[11]: https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli/sarif-output?utm_source=chatgpt.com "CodeQL CLI SARIF output"
[12]: https://docs.anthropic.com/en/docs/claude-code/settings "Claude Code settings - Claude Code Docs"
[13]: https://docs.anthropic.com/en/docs/claude-code/hooks "Hooks reference - Claude Code Docs"
[14]: https://cwe.mitre.org/top25/?utm_source=chatgpt.com "CWE Top 25 Most Dangerous Software Weaknesses - MITRE"
[15]: https://owasp.org/www-project-top-ten/?utm_source=chatgpt.com "OWASP Top Ten Web Application Security Risks"
[16]: https://github.com/OWASP/ASVS?utm_source=chatgpt.com "OWASP/ASVS: Application Security Verification Standard"

