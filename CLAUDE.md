# OpenSAST - Claude Code 多语言 SAST Skill

基于 Claude Code Skills 的多语言 SAST 安全扫描工具，编排 Semgrep、Gitleaks、Checkov 等成熟扫描器，提供统一结果、SARIF 报告和修复建议。

## 使用方式

在 Claude Code 中执行：

```
/sast-scan .
/sast-scan src --profile quick
/sast-scan . --profile deep --format sarif
/sast-scan --changed-only --fail-on high
```

## 项目结构

- `.claude/skills/sast-scan/` — Skill 定义和工具链
- `.claude/sast/` — 用户配置和扫描结果
- `tests/` — 测试和漏洞样本

## 开发

```bash
pip install -r requirements.txt
pytest tests/
```
