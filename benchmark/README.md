# OpenSAST Benchmarks

## OWASP Benchmark v1.2 (Java)

Reproduces the official **score = TPR − FPR** metric for OpenSAST Java Semgrep rules.

### One-time setup

```bash
mkdir -p benchmark/.cache && cd benchmark/.cache
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/OWASP-Benchmark/BenchmarkJava.git BenchmarkJava
cd BenchmarkJava
git sparse-checkout set --no-cone \
  '/src/main/java/org/owasp/benchmark/testcode/*.java' \
  '/expectedresults-1.2.csv'
```

### Run

```bash
python3 benchmark/run_owasp_benchmark.py
python3 benchmark/run_owasp_benchmark.py --output benchmark/results/owasp-benchmark-report.md
```

### Expected score (2026-06 baseline)

| Metric | Value |
|--------|-------|
| Score (TPR − FPR) | **≥ +39.6%** (regression gate) |
| TPR | ~61.8% |
| FPR | ~22.3% |

Syntax-only rules score **0%**; Java `taint-rules.yml` is required for non-zero recall.

**Known limit:** cross-file Java helpers (data built in one method, sunk in another) are not tracked — document as accepted FN in rule comments rather than overfitting Benchmark fixtures.

### CI

Optional manual workflow: `.github/workflows/benchmark.yml` (`workflow_dispatch`).
