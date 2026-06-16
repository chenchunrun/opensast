# OpenSAST 开发路线图

> **产品定位（North Star）**  
> Claude Code 原生的多层 SAST Skill 平台 — 在 IDE 会话内编排「规则信号 → LLM 结构化分析 → Agent 自由推理」，并提供分类、基线、修复的完整安全工作流。  
> **不是**无人值守的商业 SAST 替代品；CI 负责规则层门禁与产物归档，检测价值的核心在 Skill 会话。

---

## 现状基线（2026-06）

| 维度 | 状态 |
|------|------|
| 四 Skill 闭环 | scan / triage / baseline / fix 功能齐全 |
| 测试 | 397 passed |
| 规则层 | 14 语言目录 + Java/Python/JS 污点规则；269 条 Semgrep；OWASP Benchmark +39.6% |
| 补充工具 | 8 个 runner（Bandit、gosec、ESLint、Brakeman、cppcheck、cargo-audit、SwiftLint、PHPStan） |
| LLM/Agent 层 | 仅在 Claude Code 会话内执行；`--llm-findings` 为手动桥接 |
| 文档 | slides 已校正；Benchmark harness 可复现 |

---

## 设计原则（后续所有 PR 的筛选标准）

1. **Skill-first**：优先改善 `/sast-scan` 等命令的会话体验，而非堆砌无人值守自动化。
2. **规则层是信号，不是终局**：投资污点规则与 Benchmark，但不替代 Layer 2/3。
3. **CI = 规则门禁 + 产物**：`standard` profile、`--fail-on`、SARIF 上传；不承诺 CI 内全自动 LLM 分析。
4. **可验证**：每个阶段有可运行命令与量化 exit criteria。
5. **诚实口径**：对外材料区分「Skill 会话检测」与「CI 规则扫描」。

---

## 阶段总览

```
Phase 0  定位与文档统一          [1 周]   ─┐
Phase 1  Skill 会话编排强化      [2–3 周]  ├─ 可并行
Phase 2  规则层巩固（支撑层）     [3–4 周] ─┘
Phase 3  LLM 层 Skill 内闭环      [3–4 周]   依赖 Phase 1
Phase 4  可信度与 Benchmark 扩展  [2–3 周]   可并行 Phase 2
Phase 5  生态与采纳               [持续]
```

---

## Phase 0 — 定位与文档统一

**目标**：全仓库对外叙事一致，消除 slides / README / status 之间的口径漂移。

### 交付物

- [x] 更新 `README.md` 首段定位语（Claude Code 原生 Skill 平台）
- [x] 统一 `docs/promotion-slides.md` 与 `status-and-usage.md` 数据（397 tests、Benchmark、SecOpsCode 11）
- [x] 新增「适用 / 不适用场景」表（Skill 会话 vs 无人值守 CI）
- [x] CI 文档明确：`deep` 仅 trusted repo；LLM 层不在 CI 自动跑

### 验证

```bash
grep -rE "(几乎无效|350 passed|21 发现)" docs/ README.md  # 应无过期口径
pytest tests/ -q
```

### Exit criteria

- 新人读 README 30 秒内能理解：这是 Skill 平台，不是独立 SaaS SAST
- 所有对外数字有单一来源（`status-and-usage.md`）

---

## Phase 1 — Skill 会话编排强化（核心差异化）

**目标**：让「扫描 → 分析 → 分类 → 修复」在单次 Claude Code 会话内更顺滑，减少用户记忆负担。

### 1.1 统一 End-to-End Skill 引导

- [x] 在 `sast-scan/SKILL.md` 增加 **Session Playbook**：
  - 开发者本地：`quick → fix`
  - PR 评审：`standard → triage → baseline`
  - 发布审计：`deep → triage → fix → gate`
- [x] 各 Skill 末尾增加 **Next Skill** 提示（scan 结束自动建议 triage 命令）
- [x] `sast-triage` / `sast-fix` SKILL 增加「所需输入文件路径」检查清单

### 1.2 会话状态与 handoff

- [x] 标准化 `.claude/sast/results/` 产物契约（`summary.json` 字段文档化）
- [x] `llm-analysis-plan.json` 增加 `session_id` / `completed_phases` 字段，支持跨轮次续跑
- [x] 新增 `tools/session_status.py`：一条命令输出「扫描完成度 / 待分析 discover 数 / 未修复 HIGH 数」

### 1.3 开发者体验

- [x] `quick` profile 默认 `--changed-only` 的行为写入 Skill 说明
- [x] 报告 `report.md` 顶部增加 **3 条可执行 next steps**（由 severity 驱动）
- [x] 错误信息统一：Semgrep 未安装 / 工具 skip 时给出 Skill 内可复制修复命令

### 验证

```bash
python3 .claude/skills/sast-scan/tools/session_status.py --results .claude/sast/results
python3 .claude/skills/sast-scan/tools/sast_runner.py --target . --profile quick --format json
```

### Exit criteria

- 用户只跑 `/sast-scan` 后，Skill 响应中必含下一步 triage/fix 指引
- `session_status.py` 在空结果 / 完整结果两种情况下均可用

**预估**：2–3 周，2–3 个 PR

---

## Phase 2 — 规则层巩固（支撑层，非主战场）

**目标**：规则层作为 Layer 1 信号源稳定、可测；不追求替代 LLM 层。

### 2.1 污点规则扩展

- [x] Java taint 规则覆盖 Benchmark 剩余 FN 类别（跨文件 helper 明确标注为 known limit）
- [x] 评估 Python / JS taint-rules.yml（各 5–8 条高频 sink）
- [x] C# 规则扩至 12–15 条并对齐 corpus 样本

### 2.2 规则测试与 CI

- [x] `test_rules.py --test` 纳入 CI 必跑（修复后验证全绿）
- [x] 规则 coverage 报告自动附到 CI artifact
- [x] 删除或填充空目录 `rules/semgrep/common/`、`typescript/`

### 2.3 补充工具收尾

- [x] PHPStan / ESLint JSON normalizer 补齐
- [x] `sast_runner.py` 工具 skip 原因写入 `summary.json`（可观测）
- [x] SpotBugs / Roslyn：文档化「deep + CodeQL」路径，不新增重型 runner

### 验证

```bash
python3 .claude/skills/sast-scan/tools/test_rules.py --rules-dir .claude/skills/sast-scan/rules/semgrep
python3 benchmark/run_owasp_benchmark.py
pytest tests/ -q
```

### Exit criteria

- OWASP Benchmark 分数不低于 +39.6%（回归门禁）
- 全语言规则 `semgrep --test` 在 CI 通过

**预估**：3–4 周，3–4 个 PR  
**可与 Phase 1 并行**（不同目录，无硬依赖）

---

## Phase 3 — LLM 层 Skill 内闭环（平台核心价值）

**目标**：Layer 2/3 在 Claude Code 会话内更可重复、更可续跑，而非搬到 CI。

### 3.1 结构化分析（Layer 2）硬化

- [x] `llm-analysis-plan.json` schema 版本化 + 校验测试
- [x] 每个 `discover_*` 类型增加 **最小代码上下文模板**（减少 Agent 盲读）
- [x] `dismissed_targets` / `confirmed_findings` 写入 `llm-findings.json` 标准格式，供 `--llm-findings` 导入
- [x] Skill 内 Phase A/B  checklist 固化到 `sast-scan/SKILL.md`（可勾选式）

### 3.2 Agent 推理（Layer 3）边界清晰

- [x] 定义 Layer 3 触发条件（例如：HIGH 以上 rule finding > N，或 discover 覆盖缺口）
- [x] Agent 输出 schema：`agent-findings.json` 与 `llm-findings.json` 对齐
- [x] 文档说明：Agent 适合 CLI/跨模块；Web 场景优先 discover 类型

### 3.3 会话内复扫闭环

- [x] `fix_finding.py --test` 与 `sast-scan --changed-only` 串联文档
- [x] fix 后自动生成「复扫建议」写入 `fix-result.json`

### 验证

```bash
pytest tests/test_llm_orchestrator.py tests/test_fix_finding.py -q
python3 .claude/skills/sast-scan/tools/sast_runner.py . --llm-findings .claude/sast/results/llm-findings.json --format json
```

### Exit criteria

- 一次标准扫描后，用户可通过 **一条 import 命令** 合并 Layer 2 产物，无需手改 JSON
- Skill 文档中 Layer 2/3 与 Layer 1 职责无重叠表述

**预估**：3–4 周，2–3 个 PR  
**依赖 Phase 1**（会话状态契约）

---

## Phase 4 — 可信度与 Benchmark 扩展

**目标**：建立「可对外引用的第三方口径」，支撑 Skill 平台可信度。

### 4.1 Benchmark 体系

- [x] `benchmark/` 目录文档化：OWASP 复现步骤、预期分数区间
- [x] CI optional job：`benchmark`（nightly 或 manual workflow_dispatch）
- [x] 增加 **corpus 汇总报告** 命令（precision/recall 一张表）

### 4.2 案例研究标准化

- [x] 统一 MarqDex / SecOpsCode 报告模板（TP/FP/互补发现/耗时）
- [x] 新增 **Skill 会话 vs 仅规则 CI** 对照实验章节（同一仓库）— 见 `docs/skill-vs-ci-comparison.md`

### 4.3 指标看板

- [x] `tools/metrics_summary.py`：输出 Markdown 指标块（测试数、规则数、Benchmark 分、语言覆盖）
- [x] `status-and-usage.md` 改为从脚本生成或引用单一数据源（`metrics_summary.py --sync-status-doc`）

### Exit criteria

- 任意贡献者可 `python3 benchmark/run_owasp_benchmark.py` 复现 ±2% 分数
- 对外材料只引用 `docs/benchmark-report*.md` 与 OWASP 报告

**预估**：2–3 周，1–2 个 PR  
**可与 Phase 2 并行**

---

## Phase 5 — 生态与采纳（持续）

**目标**：降低 Skill 安装与上手成本，扩大 Claude Code 用户采纳。

### 5.1 安装与分发

- [x] 发布「最小 Skill 包」说明：复制 `.claude/skills/sast-*` 即可用（见 `docs/quickstart.md`）
- [x] `configure` 文档：Semgrep / Gitleaks 一键检测脚本（`scripts/configure-sast-tools.sh`）
- [x] Docker 镜像定位为 **规则层 CI 侧车**，非完整 Skill 运行时

### 5.2 模板与示例

- [x] `examples/` 增加 3 个最小漏洞样例 + 预期 Skill 输出
- [x] GitHub Actions 模板区分 `skill-dev` 与 `ci-gate` 两种 workflow

### 5.3 社区与反馈

- [x] CONTRIBUTING.md：规则贡献流程 + `semgrep --test` 要求
- [x] Issue 模板：误报 / 漏报 / Skill UX 分类（见 CONTRIBUTING.md）

### Exit criteria

- 新用户 15 分钟内完成首次 `/sast-scan` 并看到 report.md

---

## 明确不做（Anti-goals）

| 不做 | 原因 |
|------|------|
| CI 内全自动调用 Claude API 跑 Layer 2/3 | 违背 Skill 定位；成本高、难复现 |
| 追求 OWASP 100% 分数 | 过拟合 Benchmark；与真实项目收益递减 |
| 内置 SpotBugs/Roslyn 重型构建链 | 破坏 Skill 轻量性；CodeQL deep 已覆盖 |
| 独立 Web UI / SaaS 控制台 | 超出 Skill 平台范围 |
| 对外宣称「全局 3% 误报」 | 仅 MarqDex LLM 层成立；需场景化表述 |

---

## 里程碑与验收

| 里程碑 | 时间 | 验收标准 |
|--------|------|----------|
| **M1 定位统一** | Phase 0 完成 | README/slides/status 口径一致 |
| **M2 Skill 可续跑** | Phase 1 完成 | session_status + Playbook 上线 |
| **M3 规则回归门禁** | Phase 2 完成 | CI 跑 test_rules + Benchmark ≥39.6% |
| **M4 LLM 产物可导入** | Phase 3 完成 | llm-findings 端到端无手改 |
| **M5 对外可信** | Phase 4 完成 | Benchmark 文档 + 案例模板 |
| **M6 可分发** | Phase 5 持续 | 15 分钟上手文档 |

---

## 建议执行顺序（PR 队列）

```
PR-1  docs: 定位与口径统一（Phase 0）
PR-2  feat: session_status + SKILL Playbook（Phase 1.1–1.2）
PR-3  feat: report next-steps + tool skip 可观测（Phase 1.3）
PR-4  feat: test_rules in CI + PHPStan/ESLint normalizer（Phase 2.2–2.3）
PR-5  feat: llm-findings schema + import 硬化（Phase 3.1）
PR-6  feat: benchmark nightly + metrics_summary（Phase 4）
PR-7  docs: 安装指南 + examples（Phase 5）
```

Phase 2 污点规则扩展（PR-4b）可与 PR-5 并行。

---

## 成功画像（6 个月后）

用户在 Claude Code 中：

1. `/sast-scan --changed-only` 秒级获得规则信号  
2. Skill 自动引导 Phase A/B/C 分析，产出可导入的 `llm-findings.json`  
3. `/sast-triage` 分类后，一键 suppress 误报到 baseline  
4. `/sast-fix` 修复并 `--test` 复扫  
5. CI 仅对 **规则层 + 已确认 HIGH** 做门禁，SARIF 进 GitHub Code Scanning  

对外一句话：

> **OpenSAST：在 Claude Code 里跑通多层 SAST 安全工作流的 Skill 平台；规则层有 Benchmark 背书，检测深度靠 LLM 会话而非无人值守魔法。**
