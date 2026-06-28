# OpenSAST 最优使用指南

> 一句话：OpenSAST 不是"跑一次扫描器"，而是一条 **`scan → triage → fix → verify`** 流水线；**规则只是输入，LLM/Agent 才是主分析器**。把规则原始输出当最终结论，就是用错了。

本文从实操角度讲清楚心智模型、标准流水线、按场景的决策、baseline/CI 运营模型，以及真实踩坑提示。

---

## 1. 心智模型

| 概念 | 角色 | 说明 |
|---|---|---|
| **4 个 Skill** | 流水线工位 | `/sast-scan` → `/sast-triage` → `/sast-fix` → `/sast-baseline`，每步产物喂下一步 |
| **sast_runner.py** | 编排器 | 统一调度 Semgrep / Gitleaks / Checkov / CodeQL / Bandit，归一化成统一 findings |
| **三层分析**（`/sast-scan` 内部） | 检测深度 | Tier1 规则 → Tier2 LLM 结构化发现（13 类）→ Tier3 AI Agent 跨模块复核 |
| **baseline** | "已接受/误报"账本 | 把 FP 永久静默，是 CI 变绿的钥匙 |

**关键认知：** 规则引擎很吵（实测一个项目 12 条发现里 11 条误报）。真正价值在 Tier2/Tier3（找出规则漏报）+ triage（去噪）+ fix（生成补丁）。

---

## 2. 标准流水线（happy path）

```bash
# ① 扫描：产出 findings + LLM 分析计划
/sast-scan . --profile standard --format all

# ② 分诊：LLM 判每条 TP/FP，FP 进 baseline 静默
/sast-triage --findings .claude/sast/results/findings.json --bulk

# ③ 修真问题：先 --test 看补丁，确认后 --apply
/sast-fix <fingerprint> --test
/sast-fix <fingerprint> --apply

# ④ 验证：只扫改动文件，确认 TP 清零、无新发现
/sast-scan . --changed-only --profile quick

# ⑤ CI 持续守护（--fail-on high；历史 FP 已被 baseline 抑制）
```

**产物位置：**
- 扫描结果：`.claude/sast/results/`（`findings.json` / `report.md` / `merged.sarif` / `llm-findings.json` / `summary.json`）
- baseline：`.claude/sast/baseline.json`
- 用户配置：`.claude/sast/config.yml`（覆盖 `.claude/skills/sast-scan/config/default.yml`）

**查看会话进度与下一步：**
```bash
python3 .claude/skills/sast-scan/tools/session_status.py --results .claude/sast/results
```

---

## 3. 按场景决策

| 场景 | 扫描命令 | 后续 Skill |
|---|---|---|
| 提交前自检 | `/sast-scan . --changed-only --profile quick` | 直接 `/sast-fix` 高危项 |
| PR / 代码评审 | `/sast-scan . --profile standard --format all` | `/sast-triage --bulk` → `/sast-fix` |
| 新项目首次接入 | `/sast-scan . --profile standard` | `/sast-triage --bulk` **建 baseline** → fix |
| 发布前审计（受信仓库） | `/sast-scan . --profile deep --format all` | 跑完三层 → triage → fix → `--fail-on high` |

**Profile 区别：**

| Profile | 工具 | LLM/Agent | 耗时 | 用途 |
|---|---|---|---|---|
| `quick` | Semgrep + Gitleaks | ❌ 关 | 秒级 | 提交前自检 |
| `standard` | + Checkov | ✅ 三层全开 | 2–10 分钟 | 常规评审 / 首次接入 |
| `deep` | + CodeQL | ✅ 三层（深） | 10+ 分钟 | 受信仓库审计 |

> ⚠️ `deep` 会启用 CodeQL（可能触发构建），**仅用于受信仓库**。不可信仓库用 `quick`/`standard`。

---

## 4. baseline 与 CI 门禁（最容易模糊的部分）

### baseline 的作用
`--fail-on high` 门禁要求"历史/已接受的 FP 不再卡构建"。这些 FP 必须进 baseline 才会被静默。

```bash
# 分诊时批量导出 FP 到 baseline
/sast-triage --findings .claude/sast/results/findings.json --bulk

# 手工抑制单条
python3 .claude/skills/sast-scan/tools/baseline_manager.py suppress \
  --fingerprint <fp> --reason "framework provides CSRF guard"
```

### ⚠️ 重要 gotcha：baseline 是 per-machine 的
`.claude/sast/baseline.json` **被 `.gitignore` 排除** —— 每台机器各自维护，CI 拿不到你本地的 baseline。这意味着：

- **CI 要变绿**，必须用**不依赖 baseline** 的方式处理固有噪声：
  - 工具自检类仓库（自带 demo/fixture）：把 demo/fixture 目录加进 `.claude/sast/config.yml` 的 `targets.exclude`（OpenSAST 自身就是这么做的）。
  - 或在 CI 里现场生 baseline（不推荐，会掩盖新问题）。
- 单点静默用源码内 `# nosemgrep`（已端到端生效，会写进 SARIF `suppressions`）。

### CI 职责边界
- **CI 只跑规则层**（`standard` + `--fail-on` + SARIF 上传）。
- **LLM/Agent 层不在 CI 自动跑** —— 在 Claude Code Skill 会话里完成（需要人主导）。

---

## 5. 实战踩坑提示

1. **Tier1 规则是输入不是结论** —— 必须走 triage 或看 Tier2/3。别拿原始 findings 数当代码质量指标。
2. **`/sast-fix` Phase A 模板可能误匹配**（如把 timing-attack 误配成"硬编码密钥"）→ Phase B LLM 兜底纠正。建议不对就跑 `--phase B`。
3. **LLM 发现的问题没有规则 fingerprint** —— `/sast-fix` 只能修带 fingerprint 的规则真阳；LLM 新发现需手工改代码。
4. **工具缺失会静默降级** —— CodeQL/Bandit/Checkov 没装就跳过（带告警），结果不全。生产建议装齐。
5. **`--target` 与位置参数都支持** —— `sast_runner.py --target .` 和 `sast_runner.py .` 等价（CI/README 用前者）。

---

## 6. OpenSAST vs 裸跑 Semgrep

| 能力 | 裸 Semgrep | OpenSAST |
|---|---|---|
| 多扫描器统一 | ❌ | Semgrep+Gitleaks+Checkov+CodeQL 合并去重 |
| 误报处理 | 手工 | triage + baseline 自动静默 |
| 规则漏报 | ❌ | LLM discover + Agent 跨模块补漏 |
| 修复 | ❌ | `/sast-fix` 模板/LLM 出补丁 + `--test` 验证 |
| 合规映射 | ❌ | OWASP / CWE / NIST 800-53 / ISO 27001 自动映射 |
| CI 门禁 | 自建 | 内置 `--fail-on` + SARIF 上传 GitHub Security tab |

---

## 7. 4 个 Skill 速查

| Skill | 阶段 | 核心动作 |
|---|---|---|
| `/sast-scan` | 扫描 | 三层分析（规则→LLM discover→Agent），产出 findings + SARIF |
| `/sast-triage` | 分类 | 自动分桶 → LLM 验 TP/FP → 导出 FP 到 baseline |
| `/sast-fix` | 修复 | 模板匹配 → LLM 定制 → `--test` 验证 / `--apply` 落盘 / `--rollback` 回滚 |
| `/sast-baseline` | 基线 | create/update/show/suppress/unsuppress/diff/stats/audit/cleanup/import |

**End-to-End：** `/sast-scan` → `/sast-triage` → `/sast-baseline`（抑制误报）→ `/sast-fix`（修真阳）→ `/sast-scan --changed-only`（验证）

---

## 8. 参考命令

```bash
# 扫描当前仓库（默认 standard）
/sast-scan .

# 仅扫 git 变更
/sast-scan . --changed-only --profile quick

# 深度扫描 + SARIF
/sast-scan . --profile deep --format sarif

# 扫指定目录
/sast-scan src --profile standard --format all

# 合并外部 LLM findings
/sast-scan . --llm-findings .claude/sast/results/llm-findings.json

# 高危及以上阻断
/sast-scan . --fail-on high
```

参数全集见 README「参数说明」。新手 15 分钟入门见 [`docs/quickstart.md`](quickstart.md)。
