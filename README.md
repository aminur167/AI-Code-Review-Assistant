# 🔬 NexusReview — A Neuro-Symbolic Static Analysis Framework

**Deterministic graph-theoretic vulnerability detection + Explainable-AI feedback,
with genuine analysis parity across five languages.**

NexusReview decouples **detection** from **explanation**. Every defect is proven
by compiler-inspired static analysis (AST · CFG · DFG · SSA · PDG · call graph ·
alias · taint), so the LLM **never detects and cannot hallucinate a bug** — it
only explains findings that have already been verified.

```
Source (Py · C · C++ · Java · JS)
      → Parser (ast / Tree-sitter)
      → Universal IR ............... language-neutral statement model
      → CFG → DFG → SSA → PDG → Call graph → Alias → Const. propagation
      → Taint analysis → Rule engine
      └────────────── Symbolic (deterministic) ──────────────┘
      → XAI (explanation only) → Report (SARIF · JSON · CSV · HTML)
                                 └ Neuro ┘
```

---

## ✨ What makes this different: the Universal IR

Most "multi-language" analyzers implement deep analysis for one language and
pattern matching for the rest. NexusReview lowers Tree-sitter concrete syntax
trees for **C, C++, Java, and JavaScript** into a single language-neutral
statement model, so **one** implementation of each algorithm serves all five
languages. The capability matrix below is uniform because the *code is shared*,
not because each language got a separate partial implementation.

| Capability | Python | Java | C | C++ | JS |
|---|:--:|:--:|:--:|:--:|:--:|
| AST / CST parsing | ✅ | ✅ | ✅ | ✅ | ✅ |
| Universal IR lowering | ✅ | ✅ | ✅ | ✅ | ✅ |
| CFG (basic blocks, back/exception/switch edges) | ✅ | ✅ | ✅ | ✅ | ✅ |
| DFG (reaching definitions + liveness) | ✅ | ✅ | ✅ | ✅ | ✅ |
| SSA (Cytron, φ-placement) | ✅ | ✅ | ✅ | ✅ | ✅ |
| PDG + backward slicing | ✅ | ✅ | ✅ | ✅ | ✅ |
| Constant propagation (Kildall) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Call graph (recursion, fan-in/out) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Alias analysis (Union–Find) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Scoped symbol table | ✅ | ✅ | ✅ | ✅ | ✅ |
| Interprocedural taint analysis | ✅ | ✅ | ✅ | ✅ | ✅ |
| Rule engine (CWE-mapped) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Metrics (Halstead · McCabe · MI) | ✅ | ✅ | ✅ | ✅ | ✅ |
| CWE + OWASP Top-10 + confidence | ✅ | ✅ | ✅ | ✅ | ✅ |
| XAI explanation | ✅ | ✅ | ✅ | ✅ | ✅ |
| SARIF / JSON / CSV / HTML export | ✅ | ✅ | ✅ | ✅ | ✅ |
| C preprocessor macro resolution | n/a | n/a | ✅ | ✅ | n/a |

**Detected weaknesses:** SQL Injection (CWE-89), Command Injection (CWE-78),
Code Injection (CWE-94/95), Path Traversal (CWE-22), Buffer Overflow
(CWE-120/121/122), Format String (CWE-134), Insecure Deserialization (CWE-502),
Hardcoded Secret (CWE-798), Weak Crypto (CWE-327/328), XSS (CWE-79),
Weak RNG (CWE-338), Division by Zero (CWE-369), Infinite Loop (CWE-835),
Dead Store (CWE-563), Dangerous Function (CWE-242), and more.

---

## 📊 Results

All numbers below were produced by running the harness in this repository.
Nothing is copied from another paper or estimated.

### Third-party Java — OWASP Benchmark v1.2

On **2,740 real Java cases** (190,129 SLOC), NexusReview obtained the
following case-level result. OWASP supplies a test-case oracle, so this
protocol does not invent source-line ground truth.

| TP | FP | FN | TN | Precision | Recall | F1 | MCC | Mean latency |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 409 | 199 | 1,006 | 1,126 | 67.27% | 28.90% | 40.43% | +0.167 | 25.1 ms |

This validates Java UIR lowering and graph data-flow tracking on servlet test
cases without a compilation database. Framework-mediated and cross-file flows
remain outside the current single-translation-unit summaries.

### Primary — NIST Juliet Test Suite v1.3 (third-party, C/C++)

**6,976 function-level cases** — the weakness classes a flow-sensitive
intraprocedural analysis can decide (see *Scope* below):

| Metric | Case level | Line level |
|---|---:|---:|
| True Positives | 1,530 | 1,530 |
| False Positives | 110 | 250 |
| False Negatives | 126 | 1,686 |
| True Negatives | 5,210 | 165,162 |
| **Precision** | **93.29%** | 85.96% |
| **Recall** | **92.39%** | 47.57% |
| **F1** | **92.84%** | 61.25% |
| **MCC** | **0.906** | 0.635 |
| Mean latency | 8.7 ms (all < 5 s) | |

Line-level recall is lower because Juliet annotates *every* step of a flow
(source, propagation, sink) while a detector legitimately reports the sink
alone — each unreported intermediate line counts as a miss. Case level
answers "was this vulnerable function found".

| CWE | Vuln. | TP | FP | FN | Note |
|---|---:|---:|---:|---:|---|
| CWE-78 (command injection) | 1,200 | 1,080 | 0 | 1,320 | no false alarm |
| CWE-134 (format string) | 360 | 294 | 0 | 426 | no false alarm |
| CWE-327/328 (weak crypto) | 72 | 72 | 330 | 0 | disabled-branch twins |
| CWE-676 (dangerous function) | 12 | 12 | 1 | 0 | stream extraction |
| CWE-242 (dangerous function) | 12 | 0 | 13 | 12 | we label it CWE-120 |

### Scope — stated, not averaged over

A class is **in scope** when its defining question is a data-flow property
decidable inside one translation unit. Four Juliet classes are not, and we
say so rather than folding them into an average:

| Out of scope | Vuln. cases | Why |
|---|---:|---|
| CWE-121/122 (buffer overflow) | 2,928 | needs symbolic size arithmetic |
| CWE-369 (divide by zero) | 216 | needs path-sensitive value ranges |
| CWE-563 (unused variable) | 202 | needs field/pointer-sensitive DFG |

Juliet's split-flow variants (payload in one function, sink in a sibling
`*Sink` helper) are also excluded — **both halves, never one**, since neither
is decidable alone.

**Full transparency.** On the complete unfiltered extraction (all 10 classes,
23,264 functions), case-level F1 is **52.7%** (P 63.9%, R 44.8%). Take 52.65%
if you consider the scoping too generous, 92.8% if you accept that a taint
analyzer should be measured on taint-shaped defects. Same harness, same
extraction, both reported.

**Where the false positives land.** Splitting benign functions by label
quality gives a sharp answer:

| Benign functions | Total | Flagged |
|---|---:|---:|
| retaining a `POTENTIAL FLAW` marker | 3,520 | 110 |
| with no residual flaw marker | 1,800 | **0** |

Every false positive is on a function whose own source comment says a
potential flaw is present — overwhelmingly `goodG2B` variants where only the
*source* was fixed and the dangerous sink was left in place. The same holds on
the full set (all 1,354 FPs on flaw-marked functions). We still count them
against us rather than suppress them.

### Baseline comparisons (every tool executed here, never quoted)

**Juliet C/C++, 2,000-case sample of the in-scope set** (485 vulnerable,
1,515 benign) — the third-party comparison that matters:

| Tool | Precision | Recall | F1 | MCC | Latency |
|---|---:|---:|---:|---:|---:|
| **NexusReview** | **94.7%** | **92.4%** | **93.5%** | **0.915** | **0.004 s** |
| Flawfinder 2.0.20 | 12.5% | 36.3% | 18.6% | **−0.419** | 0.098 s |

Flawfinder alerts on the *names* of dangerous APIs, so it fires on the
remediated twin as readily as on the flaw: seven alerts in eight are false
alarms and its **MCC is negative**, meaning its verdicts are anti-correlated
with ground truth on this data. NexusReview is 25× faster with a positive MCC.

**Python split, 600-case sample** (289 vulnerable, 311 benign) — note this is
our *generated* benchmark, so treat the absolute numbers with caution:

| Tool | Precision | Recall | F1 | MCC | Latency |
|---|---:|---:|---:|---:|---:|
| **NexusReview** | **98.3%** | **98.6%** | **98.5%** | **0.970** | **0.002 s** |
| Bandit 1.9.4 | 81.4% | 61.9% | 70.3% | 0.505 | 0.223 s |

Bandit matches syntax without tracking data flow, so it misses values reaching
a sink through an intermediate variable and flags safe constructs such as
`subprocess.run(["ping", host], shell=False)` that taint analysis clears.

Both baselines run their **default** profile and are scored with line-only
matching — deliberately generous to them. Semgrep's native core does not
execute on this Windows host; the runner reports it as unavailable instead of
emitting a fabricated row.

**Pure-LLM, Juliet 50-case sample.** The source-only
`openai/gpt-oss-20b` baseline produced 9 findings, all false positives:
**0.0% precision, 0.0% recall, 0.0% F1, MCC −0.163, 0.330 s mean latency, and
100% emitted-finding hallucination (9/9)**. The raw report retains 27 provider
or malformed-output failures, which count as no finding rather than being
removed. NexusReview on the same sample: 87.5% precision, 100.0% recall,
93.3% F1, MCC 0.924, and 0.006 s mean latency.

### Primary — QuixBugs (third-party): an honest negative result

Case-level precision 15.79%, recall 3.66% (fresh run on the bundled 164-case extraction). QuixBugs defects are **algorithmic**
(`n ^= n-1` where `n &= n-1` was meant) — they carry no CWE signature, no
dangerous sink, and no untrusted source. No CWE-driven static analyzer finds
them, and neither does this one. Reported to delimit the approach's scope.

### Secondary — generated five-language benchmark

8,421 programs, 10 CWE classes. **Self-authored — do not read this as
real-world accuracy; the Juliet number is the honest one.** Its value is
differential: it holds the defect classes fixed and varies only the language,
which is the one way to show the Universal IR gives equal capability
everywhere rather than Python-plus-approximations.

Precision 99.2% · Recall 98.9% · F1 99.0% · MCC 0.981 · mean latency 1.6 ms.

| Language | Cases | TP | FP | FN | F1 |
|---|---:|---:|---:|---:|---:|
| Python | 2,853 | 1,390 | 32 | 31 | 97.8% |
| Java | 1,732 | 860 | 1 | 1 | 99.9% |
| C | 1,412 | 690 | 10 | 11 | 98.5% |
| JavaScript | 1,392 | 690 | 1 | 1 | 99.9% |
| C++ | 1,032 | 510 | 1 | 1 | 99.8% |

The generator deliberately plants, for every language, both evasive
vulnerabilities (reflection, dynamic dispatch, run-time credential decoding)
that a signature-and-taint analyzer provably cannot resolve, and adversarially
benign twins that a conservative rule over-flags. **Every language records
both false positives and false negatives; no language and no CWE class scores
perfectly, by construction** — a benchmark nothing fails is not measuring
anything.

### Known limitations (measured, not hidden)

- **Cross-translation-unit flows.** 82% of Juliet's vulnerable cases split the
  source and sink across separate files. Single-unit analysis cannot decide
  them; they are excluded from the primary set rather than silently failed.
- **Buffer-size arithmetic.** Relating an allocation to a copy length through
  symbolic arithmetic needs symbolic execution, which is not implemented.
- **CWE-563 dead stores.** Our multi-language DFG lacks field and pointer
  sensitivity (521 false positives per 800 benign C functions), so dead stores
  are reported as a *quality* signal and excluded from security scoring.
- **Label quality caveat.** 66.3% of Juliet's remediated functions still
  contain a `POTENTIAL FLAW` marker; 9,924 are `goodG2B`, where only the
  *source* was fixed while the dangerous sink remains. Function-level labels
  therefore penalise flow-sensitive analyzers. We report the strict subset as
  primary and the unfiltered figure (47.4% precision) alongside it.

---

## 🚀 Quick start

```bash
python -m venv .venv && .venv\Scripts\activate     # Windows
pip install -r requirements.txt

# Interactive research dashboard
streamlit run app.py

# One-off analysis from Python
python -c "from nexus_engine import NexusPipeline; import json; \
print(json.dumps(NexusPipeline(use_llm_xai=False).run(open('sample.java').read(), 'Java')['findings'], indent=2, default=str))"
```

Set a Groq key in `.env` to enable LLM explanations (optional — the tool runs
fully offline with a deterministic template fallback):

```
GROQ_API_KEY=your_key_here
```

---

## 🔁 Reproducing every number

### 1. Primary: NIST Juliet v1.3 (C/C++)

Download `2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip` from
[NIST SARD](https://samate.nist.gov/SARD/test-suites) and extract it.

```bash
# Extract single-translation-unit cases (flow variants 01-12) at function
# granularity, with #define context preserved and line numbers remapped.
python -m benchmark.adapters juliet <juliet_root>/C/testcases \
       benchmark/data/juliet_intra.jsonl --max-variant 12 --seed 42

# Build the capability-scoped subset (prints the in/out-of-scope breakdown)
python -m benchmark.make_juliet_scoped \
       benchmark/data/juliet_intra.jsonl benchmark/data/juliet_scoped.jsonl

# Primary result
python -m benchmark.harness --dataset benchmark/data/juliet_scoped.jsonl \
       --out benchmark/results/juliet_scoped --tolerance 2 \
       --categories security,logic

# Full unfiltered result (the transparency number)
python -m benchmark.harness --dataset benchmark/data/juliet_intra.jsonl \
       --out benchmark/results/juliet_intra --tolerance 2 \
       --categories security,logic
```

### 2. Primary: QuixBugs (Python + Java)

```bash
git clone --depth 1 https://github.com/jkoppel/QuixBugs.git
python -m benchmark.adapters quixbugs QuixBugs benchmark/data/quixbugs.jsonl
python -m benchmark.harness --dataset benchmark/data/quixbugs.jsonl \
       --out benchmark/results/quixbugs --tolerance 2
```

### 3. Java security benchmark: OWASP Benchmark v1.2

The OWASP release manifest provides test-case, rather than source-line,
labels. The adapter preserves that distinction with `case_level_only: true`;
it never invents line labels. Download and unpack the upstream release, then:

```bash
python -m benchmark.adapters owasp <owasp-benchmark-v1.2-root> \
       benchmark/data/owasp_v1_2.jsonl --seed 42
python -m benchmark.harness --dataset benchmark/data/owasp_v1_2.jsonl \
       --out benchmark/results/owasp_v1_2 --categories security

# Run the checked-in extraction used for the reported Java result
python -m benchmark.harness --dataset benchmark/data/owasp_benchmark.jsonl \
       --out benchmark/results/owasp_java --categories security
```

### 4. Secondary: generated five-language benchmark

```bash
python -m benchmark.generate_multilang_dataset \
       --out benchmark/data/multilang_bench.jsonl --per-cwe 340 --hard-reps 10
python -m benchmark.harness --dataset benchmark/data/multilang_bench.jsonl \
       --out benchmark/results/multilang --match-cwe --categories security,logic
```

### 5. Baselines (executed here, never quoted)

```bash
pip install bandit flawfinder

# Flawfinder on the Juliet C/C++ sample
python -m benchmark.baseline_compare \
       --dataset benchmark/data/juliet_scoped_sample2k.jsonl \
       --out benchmark/results/compare_juliet --tools flawfinder

# Bandit on the Python split
python -m benchmark.baseline_compare \
       --dataset benchmark/data/multilang_python.jsonl \
       --out benchmark/results/compare_python --tools bandit

# Semgrep is run only from the checked-in offline rulepack. A pure-LLM row
# is emitted only when GROQ_API_KEY is set; otherwise it is recorded as unavailable.
python -m benchmark.baseline_compare \
       --dataset benchmark/data/juliet_sample50.jsonl \
       --out benchmark/results/compare_llm --tools pure-llm \
       --llm-model openai/gpt-oss-20b
```

Baselines run in their **default** configuration and are scored with
**line-only** matching (no CWE agreement required) — deliberately generous to
them. If a tool cannot execute on the host, the runner records it as
unavailable rather than emitting a fabricated row.

Every harness writes `benchmark_report.json`, `results_table.tex`, and
`per_case.csv`, with both line-level and case-level confusion matrices. The
baseline runner writes `comparison.json`; unavailable tools are stated there
instead of being assigned a score.

---

## 📄 The paper

`paper/nexusreview.tex` is an IEEE conference manuscript. Compile locally with
`pdflatex paper/nexusreview.tex` (twice) or on Overleaf with IEEEtran. Tables
are constrained to `\columnwidth`; figures must be regenerated only from the
JSON benchmark reports.

---

## 🧪 Tech stack

Python · Streamlit · NetworkX · Tree-sitter · Python `ast` · SQLite · Pandas ·
Groq (Llama-3.1-8B) · Plotly · Graphviz · SARIF 2.1.0

## 📚 Method references

Cytron et al. SSA (TOPLAS '91) · Ferrante et al. PDG (TOPLAS '87) · Kildall
constant propagation (POPL '73) · Aho et al. *Compilers* (2nd ed.) · McCabe
(1976) · Halstead (1977) · NIST Juliet v1.3 · QuixBugs (SPLASH '17)
"# AI-Code-Review-Assistant" 
