"""
Empirical Benchmark Harness
===========================
Runs NexusReview over a labeled dataset and produces the aggregate
confusion matrix, Precision/Recall/F1/MCC, per-CWE breakdown, and latency
distribution required for the paper's evaluation section.

Dataset format (JSONL) — one test case per line:
    {
      "id": "CWE89_sql_01",
      "language": "Python",
      "code": "....",                  # OR "file": "path/to/source.py"
      "ground_truth": [{"line": 10, "cwe": "CWE-89"}],
      "vulnerable": true               # optional; false = benign file
    }

To plug in a real benchmark (Juliet, OWASP Benchmark, QuixBugs, CodeXGLUE,
SV-COMP) write an adapter that emits this JSONL, then:

    python -m benchmark.harness --dataset data/juliet.jsonl --out results/juliet
"""

import argparse
import json
import statistics
import time
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexus_engine.pipeline import NexusPipeline
from nexus_engine.evaluator import evaluate, per_cwe_breakdown, EvalResult

# Minimum number of ground-truth cases before a per-language rate is treated
# as meaningful. Below this, only the raw counts are informative.
_MIN_STRATUM = 30


def load_dataset(path: str) -> list[dict]:
    cases = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def run_benchmark(dataset_path: str, out_dir: str, use_llm: bool = False,
                  line_tolerance: int = 2, match_cwe: bool = False,
                  categories: set | None = None) -> dict:
    """
    categories: if given (e.g. {"security", "logic"}), only findings in those
    rule categories are scored. This is standard for a security benchmark —
    style/quality warnings are out of scope and must not be counted as false
    positives against security ground truth.
    """
    cases = load_dataset(dataset_path)
    pipeline = NexusPipeline(use_llm_xai=use_llm)

    agg = EvalResult()
    latencies, per_case_eval = [], []
    per_case, total_sloc = [], 0
    per_lang: dict[str, EvalResult] = {}
    per_lang_lat: dict[str, list] = {}
    case_level = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    line_level_skipped = 0
    base = Path(dataset_path).parent

    for case in cases:
        code = case.get("code")
        if code is None and case.get("file"):
            code = (base / case["file"]).read_text(encoding="utf-8", errors="ignore")
        if not code:
            continue
        language = case.get("language", "Python")
        gt = case.get("ground_truth", [])

        t0 = time.perf_counter()
        result = pipeline.run(code, language)
        latency = time.perf_counter() - t0
        latencies.append(latency)

        findings = [f for f in result.get("findings", []) if f.get("severity") != "INFO"]
        if categories is not None:
            findings = [f for f in findings if f.get("category") in categories]
        sloc = result.get("metrics", {}).get("loc", {}).get("sloc", len(code.split("\n")))
        total_sloc += sloc

        case_level_only = case.get("case_level_only", False)
        r = evaluate(findings, gt, sloc, line_tolerance, match_cwe)
        if not case_level_only:
            agg.tp += r.tp; agg.fp += r.fp; agg.fn += r.fn; agg.tn += r.tn
        else:
            line_level_skipped += 1

        # Case-level (function-granularity) outcome, the protocol used by the
        # vulnerability-detection literature: a vulnerable case counts as
        # detected if ANY reported finding lands within tolerance of ANY
        # ground-truth line, and a benign case is a false positive if it
        # receives any finding at all. This is reported alongside the
        # line-level matrix because benchmarks such as Juliet annotate every
        # step of a flow (source, propagation, sink) while a detector
        # legitimately reports only the sink.
        is_vulnerable = case.get("vulnerable", bool(gt))
        detected = bool(findings) if case_level_only else any(
            any(abs(f.get("line", 0) - g["line"]) <= line_tolerance
                and (not match_cwe or not g.get("cwe") or f.get("cwe") == g["cwe"])
                for g in gt)
            for f in findings)
        if is_vulnerable:
            case_level["TP" if detected else "FN"] += 1
        else:
            case_level["FP" if findings else "TN"] += 1

        pl = per_lang.setdefault(language, EvalResult())
        if not case_level_only:
            pl.tp += r.tp; pl.fp += r.fp; pl.fn += r.fn; pl.tn += r.tn
        per_lang_lat.setdefault(language, []).append(latency)

        # Keep findings and ground truth grouped *per case*; the per-CWE
        # breakdown must match within a program, never across programs.
        if not case_level_only:
            per_case_eval.append((findings, gt, sloc))

        per_case.append({
            "id": case.get("id"), "language": language,
            "TP": r.tp, "FP": r.fp, "FN": r.fn,
            "precision": round(r.precision, 3), "recall": round(r.recall, 3),
            "f1": round(r.f1, 3), "latency_s": round(latency, 4),
            "detected": len(findings), "expected": len(gt),
        })

    summary = agg.to_dict()
    summary.pop("matched", None)
    summary.pop("missed_ground_truth", None)
    summary.pop("extra_findings", None)

    per_language = {}
    for lang, pl in sorted(per_lang.items()):
        d = pl.to_dict()
        d.pop("matched", None); d.pop("missed_ground_truth", None)
        d.pop("extra_findings", None)
        lats = per_lang_lat.get(lang, [])
        d["cases"] = sum(1 for c in cases if c.get("language") == lang)
        d["mean_latency_s"] = round(statistics.mean(lats), 4) if lats else 0
        # A stratum with only a handful of cases cannot support a rate: one
        # outcome moves precision or recall by tens of points, and a value of
        # 1.0 there says nothing about the analyzer. Flag it so the ratios are
        # read as the raw counts they are.
        if d["TP"] + d["FN"] < _MIN_STRATUM:
            d["insufficient_sample"] = True
        per_language[lang] = d

    cl = EvalResult(tp=case_level["TP"], fp=case_level["FP"],
                    fn=case_level["FN"], tn=case_level["TN"])
    case_summary = cl.to_dict()
    for k in ("matched", "missed_ground_truth", "extra_findings"):
        case_summary.pop(k, None)

    report = {
        "dataset": Path(dataset_path).name,
        "cases": len(cases),
        "total_sloc": total_sloc,
        "aggregate": summary,
        "line_level_cases_skipped": line_level_skipped,
        "case_level": case_summary,
        "per_language": per_language,
        "per_cwe": per_cwe_breakdown(per_case_eval, line_tolerance),
        "latency": {
            "mean_s": round(statistics.mean(latencies), 4) if latencies else 0,
            "median_s": round(statistics.median(latencies), 4) if latencies else 0,
            "p95_s": round(sorted(latencies)[int(len(latencies) * 0.95)], 4)
                     if len(latencies) > 1 else (round(latencies[0], 4) if latencies else 0),
            "max_s": round(max(latencies), 4) if latencies else 0,
            "under_5s_pct": round(100 * sum(1 for l in latencies if l < 5) / len(latencies), 1)
                            if latencies else 0,
        },
        "per_case": per_case,
    }

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "benchmark_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    _write_latex(report, out / "results_table.tex")
    _write_csv(per_case, out / "per_case.csv")

    try:
        from nexus_engine.db_manager import init_db, log_benchmark
        init_db()
        # OWASP Benchmark supplies test-case labels, not source-line labels;
        # persist the protocol-appropriate case matrix rather than an empty
        # line-level matrix.
        persisted = case_summary if line_level_skipped == len(cases) else summary
        log_benchmark(report["dataset"], report["cases"], persisted,
                      report["latency"]["mean_s"])
    except Exception:
        pass
    return report


def _write_latex(report: dict, path: Path):
    a = report["aggregate"]
    lat = report["latency"]
    lines = [
        "% Auto-generated by benchmark/harness.py",
        "\\begin{table}[t]\\centering",
        f"\\caption{{NexusReview results on {report['dataset']} "
        f"({report['cases']} cases, {report['total_sloc']} SLOC)}}",
        "\\label{tab:benchmark}",
        "\\begin{tabular}{lr}\\toprule",
        "Metric & Value \\\\\\midrule",
        f"True Positives & {a['TP']} \\\\",
        f"False Positives & {a['FP']} \\\\",
        f"False Negatives & {a['FN']} \\\\",
        f"Precision & {a['precision']*100:.2f}\\% \\\\",
        f"Recall & {a['recall']*100:.2f}\\% \\\\",
        f"F1-Score & {a['f1_score']*100:.2f}\\% \\\\",
        f"MCC & {a['mcc']:.3f} \\\\",
        f"False Positive Rate & {a['false_positive_rate']*100:.2f}\\% \\\\",
        f"Mean Latency & {lat['mean_s']:.3f} s \\\\",
        f"Analyses $<$ 5s & {lat['under_5s_pct']:.1f}\\% \\\\",
        "\\bottomrule\\end{tabular}\\end{table}",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_csv(per_case: list, path: Path):
    import csv
    if not per_case:
        return
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(per_case[0].keys()))
        w.writeheader()
        w.writerows(per_case)


def main():
    ap = argparse.ArgumentParser(description="NexusReview empirical benchmark harness")
    ap.add_argument("--dataset", required=True, help="Path to JSONL dataset")
    ap.add_argument("--out", default="benchmark/results", help="Output directory")
    ap.add_argument("--llm", action="store_true", help="Enable Groq XAI (slower)")
    ap.add_argument("--tolerance", type=int, default=2, help="Line-match tolerance")
    ap.add_argument("--match-cwe", action="store_true", help="Require CWE match for TP")
    ap.add_argument("--categories", default="", help="Comma-separated rule categories "
                    "to score (e.g. 'security,logic'). Empty = all.")
    args = ap.parse_args()

    cats = {c.strip() for c in args.categories.split(",") if c.strip()} or None
    report = run_benchmark(args.dataset, args.out, args.llm, args.tolerance,
                           args.match_cwe, cats)
    a = report["aggregate"]
    print(f"\n=== {report['dataset']} — {report['cases']} cases, {report['total_sloc']} SLOC ===")
    print(f"TP={a['TP']}  FP={a['FP']}  FN={a['FN']}  TN={a['TN']}")
    print(f"Precision={a['precision']*100:.2f}%  Recall={a['recall']*100:.2f}%  "
          f"F1={a['f1_score']*100:.2f}%  MCC={a['mcc']:.3f}  Acc={a['accuracy']*100:.2f}%")
    print(f"FPR={a['false_positive_rate']*100:.2f}%  FNR={a['false_negative_rate']*100:.2f}%")
    c = report["case_level"]
    print(f"\n[case level] TP={c['TP']}  FP={c['FP']}  FN={c['FN']}  TN={c['TN']}")
    print(f"[case level] Precision={c['precision']*100:.2f}%  "
          f"Recall={c['recall']*100:.2f}%  F1={c['f1_score']*100:.2f}%  "
          f"MCC={c['mcc']:.3f}  Acc={c['accuracy']*100:.2f}%")
    print(f"\nMean latency={report['latency']['mean_s']:.3f}s  "
          f"(<5s: {report['latency']['under_5s_pct']:.1f}%)")
    if report.get("per_language"):
        print("\nPer-language:")
        print(f"  {'Lang':<12}{'TP':>4}{'FP':>4}{'FN':>4}{'Prec':>8}{'Rec':>8}{'F1':>8}{'Lat(s)':>9}")
        for lang, d in report["per_language"].items():
            note = "  (n too small)" if d.get("insufficient_sample") else ""
            print(f"  {lang:<12}{d['TP']:>4}{d['FP']:>4}{d['FN']:>4}"
                  f"{d['precision']*100:>7.1f}%{d['recall']*100:>7.1f}%"
                  f"{d['f1_score']*100:>7.1f}%{d['mean_latency_s']:>9.4f}{note}")
    print(f"\nReports written to {args.out}/")


if __name__ == "__main__":
    main()
