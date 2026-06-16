# OpenSAST

**Claude Code 原生的多层 SAST Skill 平台** — 在 IDE 会话内编排「规则信号 → LLM 结构化分析 → Agent 自由推理」，并提供分类、基线、修复的完整安全工作流。

编排 Semgrep、Gitleaks、Checkov 等成熟扫描器作为 Layer 1 信号源；检测深度与降噪依赖 `/sast-scan` 等 Skill 会话中的 Layer 2/3，而非无人值守的 CI 魔法。

### 适用 / 不适用

| 场景 | 推荐 | 说明 |
|------|------|------|
| 开发者在 Claude Code 中做安全评审 | ✅ Skill 会话 | `quick → triage → fix` 端到端 |
| PR 规则门禁 + SARIF 归档 | ✅ CI `standard` | 仅 Layer 1；`--fail-on` 阻断 |
| 受信仓库深度审计 | ✅ `deep` + Skill 分析 | CodeQL 需构建上下文 |
| 无人值守 CI 内全自动 LLM 扫描 | ❌ | 违背定位；Layer 2/3 在 Skill 内执行 |
| 不可信仓库执行 `deep` 构建 | ❌ | 仅 `quick` / `standard` |
| 独立 SaaS 控制台 / Web UI | ❌ | 超出 Skill 平台范围 |

## 功能特性

### 多语言扫描

| 优先级 | 语言 | 基础扫描 | 深度扫描 | 补充工具 |
|--------|------|----------|----------|----------|
| P0 | JavaScript / TypeScript | Semgrep | CodeQL | ESLint security |
| P0 | Python | Semgrep | CodeQL | Bandit |
| P0 | Java / Kotlin | Semgrep | CodeQL | — (`deep` 用 CodeQL) |
| P0 | Go | Semgrep | CodeQL | gosec |
| P0 | C# | Semgrep | CodeQL | — (`deep` 用 CodeQL) |
| P1 | C/C++ | Semgrep | CodeQL | cppcheck |
| P1 | PHP | Semgrep | - | PHPStan |
| P1 | Ruby | Semgrep | CodeQL | Brakeman |
| P1 | Rust | Semgrep | CodeQL | cargo-audit |
| P1 | Swift | Semgrep | CodeQL | SwiftLint |
| P1 | Terraform / IaC | Checkov / Semgrep | - | - |

### 三级扫描配置

| Profile | 耗时 | 启用工具 | 适用场景 |
|---------|------|----------|----------|
| `quick` | 秒级 | Semgrep + Gitleaks | 提交前快速检查 |
| `standard` | 2-10 分钟 | Semgrep + Gitleaks + Checkov | 常规仓库扫描 |
| `deep` | 10+ 分钟 | 全部 + CodeQL | 安全审计 / CI 夜间任务 |

### LLM + AI Agent 三层架构

OpenSAST 采用三层 SAST 架构（Rules + LLM + AI Agent），规则扫描器产生原始信号，Claude 作为主分析器进行验证和发现，AI Agent 进行自由推理覆盖跨模块漏洞：

- **Phase A — 规则发现验证** — 对规则引擎的原始发现进行上下文验证，快速排除误报
- **Phase B — LLM 结构化发现** — 13 种 discover 类型分析（IDOR、凭据、认证链、加密、SSRF、SQL 注入、CSRF、限流、批量赋值、安全头、配置安全、CLI 配置、全局扫描）
- **Phase C — AI Agent 自由推理** — 跨模块数据流追踪、业务逻辑缺陷、代码意图理解

### 多格式报告

- **Markdown** — 包含发现详情、修复建议的可读报告
- **JSON** — 结构化的 `findings.json` 和 `summary.json`
- **SARIF 2.1.0** — 兼容 GitHub code scanning 的 `merged.sarif`

### 四个 Skill 命令

| 命令 | 用途 |
|------|------|
| `/sast-scan` | 三层架构安全扫描（规则 + LLM + AI Agent），主执行链 |
| `/sast-triage` | 三阶段分类（自动分桶 → LLM 验证 → 推荐修复），含基线导出 |
| `/sast-fix` | 三阶段修复（模板匹配 → LLM 自定义 → 验证），支持 apply/rollback/分支 |
| `/sast-baseline` | 全生命周期基线管理（10 个命令：create/update/show/suppress/unsuppress/diff/stats/audit/cleanup/import） |

说明：
- 四个 Skill 均已达到功能完整，具备三层/三阶段工作流、完整测试覆盖和互操作链路。
- 推荐 End-to-End 工作流：`/sast-scan` → `/sast-triage` → `/sast-baseline`（抑制误报）→ `/sast-fix`（修复真阳性）

## 使用方式

在 Claude Code 中执行：

```bash
# 扫描当前仓库（默认 standard profile）
/sast-scan .

# 快速扫描（仅 Git 变更文件）
/sast-scan --changed-only --profile quick

# 深度扫描并生成 SARIF 报告
/sast-scan . --profile deep --format sarif

# 合并外部 LLM findings
/sast-scan . --llm-findings .claude/sast/results/llm-findings.json

# 扫描指定目录
/sast-scan src --profile standard --format all

# 高危及以上阻断
/sast-scan . --fail-on high
```

### 推荐工作流

1. 扫描并产出主结果

```bash
/sast-scan . --profile standard --format all
```

2. 对结果做分类和优先级整理

```bash
python3 .claude/skills/sast-scan/tools/triage_findings.py \
  --findings .claude/sast/results/findings.json \
  --focus all \
  --output markdown
```

3. 对确认误报或接受风险的项维护基线

```bash
python3 .claude/skills/sast-scan/tools/baseline_manager.py show
python3 .claude/skills/sast-scan/tools/baseline_manager.py suppress \
  --fingerprint <fingerprint> \
  --reason "false positive with framework guard"
```

4. 对真实问题生成修复建议并做定向复扫

```bash
python3 .claude/skills/sast-scan/tools/fix_finding.py <finding-id-or-fingerprint> --test
```

推荐顺序：
- 开发者本地：`quick scan -> fix`
- 仓库级评审：`standard scan -> triage -> baseline/fix`
- 高信任审计：`deep scan -> triage -> fix -> strict gate`

### 参数说明

```
/sast-scan [target] [options]

Options:
  --profile quick|standard|deep   扫描配置（默认 standard）
  --changed-only                   仅扫描 Git 变更文件
  --format markdown|json|sarif|all 输出格式（默认 markdown）
  --fail-on low|medium|high|critical  阻断阈值
  --lang auto|js|ts|python|...     指定语言（默认 auto 自动检测）
  --llm-findings FILE                合并外部 LLM findings JSON
```

### 深度扫描安全边界

- `quick` / `standard` 默认适合常规仓库扫描。
- `deep` 模式会启用 CodeQL。对于需要构建的语言，OpenSAST 默认只允许包管理器构建命令，不默认执行仓库自带入口脚本。
- 仓库内的 `./mvnw`、`./gradlew`、`make`、`cmake` 等构建入口应视为高信任操作；仅在你信任目标仓库时，才应通过配置显式放开。
- 对不可信仓库，推荐先使用 `quick` 或 `standard`，再根据需要单独开启更深的分析。

## 快速上手

15 分钟指南：[`docs/quickstart.md`](docs/quickstart.md)

```bash
# 1. 检查环境
bash scripts/configure-sast-tools.sh

# 2. 扫描示例漏洞代码
/sast-scan examples/ --profile quick --format markdown

# 3. 查看结果
ls .claude/sast/results/
```

工具链检测：`bash scripts/configure-sast-tools.sh`

最小漏洞样例：[`examples/`](examples/)

## 安装

### 前置条件

- Python 3.11+
- Claude Code

### 安装依赖

```bash
pip install -r requirements.txt
```

### 扫描工具（按需安装）

| 工具 | 安装方式 | 必需 |
|------|----------|------|
| Semgrep | `pip install semgrep` | 是 |
| Gitleaks | 见 [gitleaks 文档](https://github.com/gitleaks/gitleaks) | 推荐 |
| Checkov | `pip install checkov` | 可选（IaC 扫描） |
| CodeQL | 见 [codeql 文档](https://codeql.github.com) | 可选（深度扫描） |
| Bandit | `pip install bandit` | 可选（Python 补充） |
| gosec | 见 [gosec 文档](https://github.com/securego/gosec) | 可选（Go 补充） |

未安装的工具会被自动跳过，不影响其他工具的扫描。

### Semgrep 本机运行说明

- OpenSAST 现在优先通过 `pysemgrep` 运行 Semgrep，而不是依赖最脆弱的默认 CLI 启动路径。
- 运行时会自动注入可写 `HOME`、关闭 metrics / version check，并显式设置证书路径，以规避部分 macOS / pipx 环境下的启动问题。
- 如果你手工直接执行 `semgrep --version`、`semgrep --validate` 或 `semgrep --test` 仍然失败，而仓库测试可以通过，这通常说明是你本机的 Semgrep 安装形态有问题，不是 OpenSAST 规则本身有问题。
- 如果需要手工验证，优先尝试 `pysemgrep`，或在更稳的 Python `3.11` / `3.12` 环境中重装 Semgrep。

### Docker 运行

```bash
docker build -f Dockerfile.sast -t opensast .
docker run -v /path/to/repo:/scan opensast
```

## 项目结构

```
opensast/
├── .claude/skills/
│   ├── sast-scan/          # 主扫描 Skill
│   │   ├── SKILL.md        # Skill 定义
│   │   ├── config/         # 默认配置和语言映射
│   │   ├── tools/          # 扫描引擎和工具链
│   │   ├── rules/          # Semgrep 自定义规则（按语言分目录）
│   │   ├── templates/      # 报告模板
│   │   ├── docs/           # CI 集成和规则编写文档
│   ├── sast-triage/        # 分类 Skill
│   ├── sast-fix/           # 修复 Skill
│   └── sast-baseline/      # 基线管理 Skill
├── examples/               # 漏洞示例代码
├── tests/                  # 测试和漏洞样本
├── Dockerfile.sast         # Docker 运行环境
├── requirements.txt        # Python 依赖
└── LICENSE                 # Apache 2.0
```

## 会话状态

扫描后可用一条命令查看进度与下一步：

```bash
python3 .claude/skills/sast-scan/tools/session_status.py --results .claude/sast/results
```

## CI/CD 集成

**CI 负责规则层门禁**（`standard` profile、`--fail-on`、SARIF 上传）。**LLM / Agent 层不在 CI 内自动执行** — 在 Claude Code Skill 会话中完成。

`deep` profile 仅用于受信仓库（启用 CodeQL，可能触发构建）。详见：

- `.claude/skills/sast-scan/docs/status-and-usage.md`
- `.claude/skills/sast-scan/docs/ci-integration.md`

### GitHub Actions

```yaml
name: SAST
on: [push, pull_request]
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install semgrep checkov pyyaml
      - run: python3 .claude/skills/sast-scan/tools/sast_runner.py --target . --profile standard --format all --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: .claude/sast/results/merged.sarif
```

### GitLab CI

```yaml
sast:
  stage: test
  image: python:3.12
  script:
    - pip install semgrep checkov pyyaml
    - python3 .claude/skills/sast-scan/tools/sast_runner.py --target . --profile standard --format all --fail-on high
  artifacts:
    when: always
    paths:
      - .claude/sast/results/
```

## 配置

默认配置位于 `.claude/skills/sast-scan/config/default.yml`，可通过项目级 `.claude/sast/config.yml` 覆盖。

CodeQL 相关安全选项：

```yaml
tools:
  codeql:
    allow_package_manager_builds: true
    allow_repo_build_commands: false

gate:
  review_findings_blocking: false
```

`review_findings_blocking` 默认关闭。开启后，`needs-review` 项也会参与 CI 阻断，适合想把人工复核项一并收紧的仓库。

## 开发

```bash
pip install -r requirements.txt
pytest tests/
python3 .claude/skills/sast-scan/tools/test_rules.py \
  --rules-dir .claude/skills/sast-scan/rules/semgrep \
  --coverage-report .claude/sast/results/rule-coverage.md
```

## 许可证

[Apache License 2.0](LICENSE)
