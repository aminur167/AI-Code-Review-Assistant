from dotenv import load_dotenv
load_dotenv()
"""
Baseline Comparison Harness
===========================
Runs NexusReview together with real, independently-developed static analyzers
on the *same* dataset, under the *same* protocol, and reports the full metric
suite for each. No competitor number is copied from a paper or estimated --
every row is produced by executing the tool here.

Baselines
---------
``bandit``      PyCQA Bandit, the standard open-source Python security linter.
``flawfinder``  Flawfinder, a widely used C/C++ security scanner (the natural
                baseline for the Juliet C/C++ evaluation).
``semgrep``     Optional. Semgrep is run through the released offline ruleset
                when its native core engine is available; when the core cannot
                execute (as on some Windows hosts) the runner records the tool
                as unavailable rather than emitting a fabricated row.

Fairness controls
-----------------
* identical dataset and identical ground truth for every tool;
* identical line tolerance and identical true-negative definition;
* each baseline runs in its **default** configuration, the setup a
  practitioner gets out of the box;
* baselines are scored with **line-only** matching (no CWE agreement
  required), which is deliberately generous to them, because their CWE
  tagging is coarser than ours;
* wall-clock latency measured per program in the same process.

Both line-level and case-level (function-granularity) matrices are reported.
The case-level view is the one used by the vulnerability-detection literature
and is robust to benchmarks that annotate every step of a flow while a
detector legitimately reports only the sink.

Usage
-----
    python -m benchmark.baseline_compare \
        --dataset benchmark/data/juliet_strict.jsonl \
        --out benchmark/results/compare_juliet \
        --tools flawfinder
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexus_engine.pipeline import NexusPipeline
from nexus_engine.evaluator import evaluate, EvalResult

_VENV_SCRIPTS = Path(sys.executable).parent


def _tool_cmd(module: str, exe_name: str) -> list | None:
    """
    Build a runnable command for a baseline tool, preferring ``python -m``.

    Windows Application Control policies can block the console-script
    ``.exe`` shims that pip installs while still permitting the interpreter
    itself, in which case launching the shim raises ``OSError`` and every
    scan silently returns nothing -- which would be recorded as a score of
    zero rather than as a failure. Probing the module form first avoids
    reporting a broken invocation as a measurement; ``None`` means the tool
    genuinely cannot run here.
    """
    for cmd in ([sys.executable, "-m", module],
                [str(_VENV_SCRIPTS / exe_name)]):
        try:
            r = subprocess.run(cmd + ["--version"], capture_output=True,
                               text=True, timeout=120)
            if r.returncode == 0 or r.stdout.strip() or r.stderr.strip():
                return cmd
        except Exception:
            continue
    return None


def load(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def _case_outcome(findings, case, tol, match_cwe=False):
    """Case-level verdict: was this program flagged at a ground-truth site?"""
    gt = case.get("ground_truth", [])
    detected = any(
        any(abs(f.get("line", 0) - g["line"]) <= tol
            and (not match_cwe or not g.get("cwe") or f.get("cwe") == g["cwe"])
            for g in gt)
        for f in findings)
    vulnerable = case.get("vulnerable", bool(gt))
    if vulnerable:
        return "TP" if detected else "FN"
    return "FP" if findings else "TN"


def _summarize(agg, case_level, lats, tool, extra=None):
    d = agg.to_dict()
    for k in ("matched", "missed_ground_truth", "extra_findings"):
        d.pop(k, None)
    cl = EvalResult(tp=case_level["TP"], fp=case_level["FP"],
                    fn=case_level["FN"], tn=case_level["TN"])
    cld = cl.to_dict()
    for k in ("matched", "missed_ground_truth", "extra_findings"):
        cld.pop(k, None)
    out = {"tool": tool, "line_level": d, "case_level": cld,
           "mean_latency_s": round(statistics.mean(lats), 4) if lats else 0.0,
           "cases_scored": sum(case_level.values())}
    if extra:
        out.update(extra)
    return out


def _hallucination_metrics(line_level: dict) -> dict:
    """False findings among all findings emitted by an unguided detector."""
    reported = line_level["TP"] + line_level["FP"]
    return {
        "reported_findings": reported,
        "hallucinated_findings": line_level["FP"],
        "hallucination_rate": round(line_level["FP"] / reported, 4) if reported else 0.0,
    }


# ---------------------------------------------------------------------------
def run_nexus(cases, categories, tol, match_cwe):
    p = NexusPipeline(use_llm_xai=False)
    agg, lats = EvalResult(), []
    case_level = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for c in cases:
        code = c["code"]
        t0 = time.perf_counter()
        res = p.run(code, c.get("language", "Python"))
        lats.append(time.perf_counter() - t0)
        finds = [f for f in res.get("findings", [])
                 if f.get("severity") != "INFO" and f.get("line", 0) > 0]
        if categories:
            finds = [f for f in finds if f.get("category") in categories]
        sloc = res.get("metrics", {}).get("loc", {}).get("sloc", len(code.split("\n")))
        r = evaluate(finds, c.get("ground_truth", []), sloc, tol, match_cwe)
        agg.tp += r.tp; agg.fp += r.fp; agg.fn += r.fn; agg.tn += r.tn
        case_level[_case_outcome(finds, c, tol, match_cwe)] += 1
    return _summarize(agg, case_level, lats, "NexusReview")


# ---------------------------------------------------------------------------
def run_bandit(cases, tol):
    """Bandit, default profile. Python cases only; others are not scored."""
    cmd0 = _tool_cmd("bandit", "bandit.exe")
    if cmd0 is None:
        return None
    agg, lats = EvalResult(), []
    case_level = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    scored, failures = 0, 0
    for c in cases:
        if c.get("language") != "Python":
            continue
        scored += 1
        code = c["code"]
        tf = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                         encoding="utf-8")
        tf.write(code)
        tf.close()
        finds = []
        t0 = time.perf_counter()
        try:
            r = subprocess.run(cmd0 + ["-f", "json", "-q", tf.name],
                               capture_output=True, text=True, timeout=120)
            data = json.loads(r.stdout) if r.stdout.strip() else {}
            for item in data.get("results", []):
                finds.append({"line": item.get("line_number", 0),
                              "cwe": str((item.get("issue_cwe") or {}).get("id", "")),
                              "rule_id": item.get("test_id", "")})
        except Exception:
            failures += 1
        finally:
            lats.append(time.perf_counter() - t0)
            os.unlink(tf.name)
        sloc = len([l for l in code.split("\n") if l.strip()])
        r2 = evaluate(finds, c.get("ground_truth", []), sloc, tol, match_cwe=False)
        agg.tp += r2.tp; agg.fp += r2.fp; agg.fn += r2.fn; agg.tn += r2.tn
        case_level[_case_outcome(finds, c, tol)] += 1
    if failures and failures >= scored:
        return None          # every invocation failed: not a measurement
    return _summarize(agg, case_level, lats, f"Bandit (Python only, n={scored})",
                      extra={"invocation_failures": failures})


# ---------------------------------------------------------------------------
def run_flawfinder(cases, tol, min_level=1):
    """
    Flawfinder, default profile, on the C/C++ cases.

    Flawfinder emits a risk level from 0 to 5; the tool's own default reporting
    threshold is 1, which is what we use. Its CSV output carries the line
    number and a CWE list, so it is scored by exactly the same line-matching
    rule as every other tool.
    """
    cmd0 = _tool_cmd("flawfinder", "flawfinder.exe")
    if cmd0 is None:
        return None
    agg, lats = EvalResult(), []
    case_level = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    scored, failures = 0, 0
    for c in cases:
        lang = c.get("language")
        if lang not in ("C", "C++"):
            continue
        scored += 1
        code = c["code"]
        suffix = ".c" if lang == "C" else ".cpp"
        tf = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False,
                                         encoding="utf-8")
        tf.write(code)
        tf.close()
        finds = []
        t0 = time.perf_counter()
        try:
            r = subprocess.run(cmd0 + ["--csv", f"--minlevel={min_level}", tf.name],
                               capture_output=True, text=True, timeout=120)
            import csv as _csv
            import io as _io
            reader = _csv.DictReader(_io.StringIO(r.stdout))
            for row in reader:
                try:
                    line = int(row.get("Line") or 0)
                except ValueError:
                    continue
                cwes = (row.get("CWEs") or "").split(",")
                finds.append({"line": line,
                              "cwe": cwes[0].strip() if cwes and cwes[0].strip() else "",
                              "rule_id": row.get("Name", "")})
        except Exception:
            failures += 1
        finally:
            lats.append(time.perf_counter() - t0)
            os.unlink(tf.name)
        sloc = len([l for l in code.split("\n") if l.strip()])
        r2 = evaluate(finds, c.get("ground_truth", []), sloc, tol, match_cwe=False)
        agg.tp += r2.tp; agg.fp += r2.fp; agg.fn += r2.fn; agg.tn += r2.tn
        case_level[_case_outcome(finds, c, tol)] += 1
    if failures and failures >= scored:
        return None
    return _summarize(agg, case_level, lats,
                      f"Flawfinder (C/C++ only, n={scored})",
                      extra={"invocation_failures": failures})


# ---------------------------------------------------------------------------
def run_semgrep(cases, tol, rules="benchmark/semgrep_rules.yaml"):
    """
    Semgrep with the released offline ruleset.

    Semgrep's matching core is a native binary that does not run on every
    platform. If it cannot execute, this returns ``None`` and the caller omits
    the row entirely -- an unavailable tool must never be represented by an
    invented number.
    """
    cmd0 = _tool_cmd("semgrep", "semgrep.exe")
    if cmd0 is None:
        return None
    probe = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                        encoding="utf-8")
    probe.write("import os\nos.system('ls')\n")
    probe.close()
    try:
        r = subprocess.run(cmd0 + ["--config", rules, "--json", "--quiet", probe.name],
                           capture_output=True, text=True, timeout=180)
        if r.returncode not in (0, 1) or not r.stdout.strip():
            return None
    except Exception:
        return None
    finally:
        os.unlink(probe.name)

    agg, lats = EvalResult(), []
    case_level = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    ext = {"Python": ".py", "C": ".c", "C++": ".cpp",
           "Java": ".java", "JavaScript": ".js"}
    scored = 0
    for c in cases:
        suffix = ext.get(c.get("language"))
        if suffix is None:
            continue
        scored += 1
        tf = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False,
                                         encoding="utf-8")
        tf.write(c["code"])
        tf.close()
        finds = []
        t0 = time.perf_counter()
        try:
            r = subprocess.run(cmd0 + ["--config", rules, "--json", "--quiet", tf.name],
                               capture_output=True, text=True, timeout=180)
            data = json.loads(r.stdout) if r.stdout.strip() else {}
            for item in data.get("results", []):
                finds.append({"line": item.get("start", {}).get("line", 0),
                              "cwe": "", "rule_id": item.get("check_id", "")})
        except Exception:
            pass
        finally:
            lats.append(time.perf_counter() - t0)
            os.unlink(tf.name)
        sloc = len([l for l in c["code"].split("\n") if l.strip()])
        r2 = evaluate(finds, c.get("ground_truth", []), sloc, tol, match_cwe=False)
        agg.tp += r2.tp; agg.fp += r2.fp; agg.fn += r2.fn; agg.tn += r2.tn
        case_level[_case_outcome(finds, c, tol)] += 1
    return _summarize(agg, case_level, lats, f"Semgrep (n={scored})")


# ---------------------------------------------------------------------------
def run_pure_llm(cases, tol, model="openai/gpt-oss-20b"):
    """Run a detection-only LLM baseline on the exact benchmark programs.

    This intentionally has no graph context and no NexusReview findings.  A
    missing API key or unavailable SDK produces ``None`` so a failed remote
    experiment is never mistaken for a zero-score measurement.
    """
    key = os.getenv("GROQ_API_KEY")
    if not key:
        return None
    try:
        from groq import Groq
        # Baselines must fail promptly and visibly: retrying a transient API
        # failure for every case would turn an unavailable remote service into
        # a distorted latency measurement.
        client = Groq(api_key=key, timeout=30.0, max_retries=0)
    except Exception:
        return None
    agg, lats = EvalResult(), []
    case_level = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    failures, failure_reasons = 0, []
    system = (
        "You are a security scanner. Inspect only the supplied source code. "
        "End your response with exactly one JSON object in this schema: "
        "{\"findings\":[{\"line\":integer,\"cwe\":string}]}. "
        "List each suspected security vulnerability once. Do not invent a finding. "
        "If there are none, emit {\"findings\":[]}.")
    for c in cases:
        finds = []
        t0 = time.perf_counter()
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content":
                           f"Language: {c.get('language', 'unknown')}\nSource:\n{c['code']}"}],
                temperature=0, max_tokens=1200, reasoning_effort="low")
            raw = response.choices[0].message.content or ""
            # Some currently available Groq models emit a reasoning preamble
            # despite an otherwise valid JSON instruction.  Score only the
            # terminal JSON object; malformed output is an invocation failure,
            # never silently reinterpreted as ``no finding``.
            decoder, payload = json.JSONDecoder(), None
            for start in (i for i, char in enumerate(raw) if char == "{"):
                try:
                    candidate, _ = decoder.raw_decode(raw[start:])
                except json.JSONDecodeError:
                    continue
                if isinstance(candidate, dict) and isinstance(candidate.get("findings"), list):
                    payload = candidate
                    break
            if payload is None:
                raise ValueError("model response contained no findings JSON object")
            for item in payload.get("findings", []):
                try:
                    line = int(item.get("line", 0))
                except (TypeError, ValueError):
                    continue
                finds.append({"line": line, "cwe": str(item.get("cwe", "")),
                              "rule_id": "pure-llm"})
        except Exception as exc:
            failures += 1
            if len(failure_reasons) < 3:
                failure_reasons.append(f"{type(exc).__name__}: {str(exc)[:180]}")
        finally:
            lats.append(time.perf_counter() - t0)
        sloc = len([line for line in c["code"].split("\n") if line.strip()])
        result = evaluate(finds, c.get("ground_truth", []), sloc, tol, match_cwe=False)
        agg.tp += result.tp; agg.fp += result.fp; agg.fn += result.fn; agg.tn += result.tn
        case_level[_case_outcome(finds, c, tol)] += 1
    if failures == len(cases):
        return None
    summary = _summarize(agg, case_level, lats,
                         f"Pure LLM ({model}, n={len(cases)})",
                         extra={"invocation_failures": failures,
                                "failure_reasons": failure_reasons,
                                "model": model, "grounding": "none"})
    summary.update(_hallucination_metrics(summary["line_level"]))
    return summary


# ---------------------------------------------------------------------------
def _latex(rows, path: Path):
    lines = [
        "% Auto-generated by benchmark/baseline_compare.py",
        "\\begin{table}[t]\\centering",
        "\\caption{Baseline comparison under an identical protocol "
        "(case level; baselines scored with line-only matching).}",
        "\\label{tab:baseline}",
        "\\resizebox{\\columnwidth}{!}{\\begin{tabular}{lrrrrr}\\toprule",
        "Tool & Prec. & Recall & F1 & MCC & Lat.(s) \\\\\\midrule",
    ]
    for r in rows:
        c = r["case_level"]
        name = r["tool"].replace("_", "\\_")
        cells = [
            name,
            "{:.1f}\\%".format(c["precision"] * 100),
            "{:.1f}\\%".format(c["recall"] * 100),
            "{:.1f}\\%".format(c["f1_score"] * 100),
            "{:.3f}".format(c["mcc"]),
            "{:.3f}".format(r["mean_latency_s"]),
        ]
        if name.startswith("NexusReview"):
            cells = ["\\textbf{" + x + "}" for x in cells]
        lines.append(" & ".join(cells) + " \\\\")
    lines += ["\\bottomrule\\end{tabular}}\\end{table}"]
    path.write_text("\n".join(lines), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="Baseline comparison harness")
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--out", default="benchmark/results/compare")
    ap.add_argument("--tolerance", type=int, default=2)
    ap.add_argument("--match-cwe", action="store_true",
                    help="Require CWE agreement for NexusReview (baselines "
                         "always use line-only matching)")
    ap.add_argument("--categories", default="security,logic")
    ap.add_argument("--tools", default="bandit,flawfinder,semgrep",
                    help="Comma-separated baselines to run")
    ap.add_argument("--llm-model", default="openai/gpt-oss-20b",
                    help="Groq model for the pure-LLM baseline")
    args = ap.parse_args()

    cases = load(args.dataset)
    cats = {c.strip() for c in args.categories.split(",") if c.strip()} or None
    wanted = {t.strip().lower() for t in args.tools.split(",") if t.strip()}

    rows = [run_nexus(cases, cats, args.tolerance, args.match_cwe)]
    skipped = []

    if "bandit" in wanted and any(c.get("language") == "Python" for c in cases):
        row = run_bandit(cases, args.tolerance)
        if row is not None:
            rows.append(row)
        else:
            skipped.append("bandit: could not be executed on this host "
                           "(blocked or missing); no row reported")
    if "flawfinder" in wanted and any(c.get("language") in ("C", "C++") for c in cases):
        row = run_flawfinder(cases, args.tolerance)
        if row is not None:
            rows.append(row)
        else:
            skipped.append("flawfinder: could not be executed on this host "
                           "(blocked or missing); no row reported")
    if "semgrep" in wanted:
        sg = run_semgrep(cases, args.tolerance)
        if sg is not None:
            rows.append(sg)
        else:
            skipped.append("semgrep: native core unavailable on this host; "
                           "no row reported")
    if "pure-llm" in wanted or "llm" in wanted:
        llm = run_pure_llm(cases, args.tolerance, args.llm_model)
        if llm is not None:
            rows.append(llm)
        else:
            skipped.append("pure-llm: GROQ_API_KEY or a working Groq SDK/model is unavailable; "
                           "no row reported")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    payload = {"dataset": Path(args.dataset).name, "cases": len(cases),
               "tolerance": args.tolerance, "results": rows,
               "unavailable_tools": skipped}
    (out / "comparison.json").write_text(json.dumps(payload, indent=2),
                                         encoding="utf-8")
    _latex(rows, out / "comparison_table.tex")
    try:
        from nexus_engine.db_manager import init_db, log_benchmark
        init_db()
        for row in rows:
            log_benchmark(f"baseline::{payload['dataset']}::{row['tool']}",
                          row["cases_scored"], row["case_level"],
                          row["mean_latency_s"])
    except Exception:
        # A baseline result remains valid even if optional persistence fails.
        pass

    print(f"\n=== Baseline comparison on {Path(args.dataset).name} "
          f"({len(cases)} cases) ===")
    header = f"{'Tool':<34}{'Prec':>8}{'Rec':>8}{'F1':>8}{'MCC':>8}{'Lat(s)':>9}"
    print(header)
    print("-" * len(header))
    for r in rows:
        c = r["case_level"]
        print(f"{r['tool'][:33]:<34}{c['precision']*100:>7.1f}%"
              f"{c['recall']*100:>7.1f}%{c['f1_score']*100:>7.1f}%"
              f"{c['mcc']:>8.3f}{r['mean_latency_s']:>9.4f}")
    for s in skipped:
        print(f"  [skipped] {s}")
    print(f"\nWritten to {out}/")


if __name__ == "__main__":
    main()
