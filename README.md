# OpenSAST

基于 Claude Code Skills 的多语言静态应用安全测试（SAST）工具。编排 Semgrep、Gitleaks、Checkov 等成熟扫描器，结合 LLM 增强分析，提供统一的安全扫描结果、SARIF 报告和修复建议。

## 功能特性

### 多语言扫描

| 优先级 | 语言 | 基础扫描 | 深度扫描 | 补充工具 |
|--------|------|----------|----------|----------|
| P0 | JavaScript / TypeScript | Semgrep | CodeQL | ESLint security |
| P0 | Python | Semgrep | CodeQL | Bandit |
| P0 | Java / Kotlin | Semgrep | CodeQL | SpotBugs |
| P0 | Go | Semgrep | CodeQL | gosec |
| P0 | C# | Semgrep | CodeQL | Roslyn analyzers |
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

### LLM 增强分析

OpenSAST 采用 LLM-Primary 架构：规则扫描器产生原始信号，Claude 作为主分析器进行验证、上下文丰富和误报过滤。核心能力包括：

- **发现验证** — 对规则引擎的原始发现进行上下文验证，降低误报
- **安全发现** — 识别规则引擎无法覆盖的安全问题（如鉴权链缺失、RBAC 配置错误）
- **污点追踪** — 分析数据从 source 到 sink 的传播路径
- **数据流分析** — 追踪用户输入在代码中的流转
- **合规映射** — 将发现映射到 CWE、OWASP Top 10、OWASP ASVS

### 多格式报告

- **Markdown** — 包含发现详情、修复建议的可读报告
- **JSON** — 结构化的 `findings.json` 和 `summary.json`
- **SARIF 2.1.0** — 兼容 GitHub code scanning 的 `merged.sarif`

### 四个 Skill 命令

| 命令 | 用途 |
|------|------|
| `/sast-scan` | 执行安全扫描，当前最完整的主执行链 |
| `/sast-triage` | 分析误报、优先级排序、生成分类报告，已提供结构化 triage 入口 |
| `/sast-fix` | 针对指定发现生成标准化修复建议，并可触发定向复扫 |
| `/sast-baseline` | 管理基线，抑制已确认的风险，关注新增问题，已提供基线管理入口 |

说明：
- `/sast-scan` 已具备完整 runner、报告、gate、CI、LLM findings 导入与覆盖审计链路。
- `/sast-triage` 与 `/sast-baseline` 现在已有独立 helper 脚本和测试，但整体成熟度仍低于 `/sast-scan` 主链。
- `/sast-fix` 现在已有独立 helper，可按 finding 生成修复建议并触发定向复扫，但仍不自动改代码。

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
│   │   └── examples/       # 漏洞示例代码
│   ├── sast-triage/        # 分类 Skill
│   ├── sast-fix/           # 修复 Skill
│   └── sast-baseline/      # 基线管理 Skill
├── tests/                  # 测试和漏洞样本
├── Dockerfile.sast         # Docker 运行环境
├── requirements.txt        # Python 依赖
└── LICENSE                 # Apache 2.0
```

## CI/CD 集成

当前真实完成度、推荐使用路径和已知限制见：

- `.claude/skills/sast-scan/docs/status-and-usage.md`

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
