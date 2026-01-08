"""
Third-Party Benchmark Adapters (Primary Evaluation)
===================================================
Convert public, externally-authored benchmarks into the JSONL format consumed
by :mod:`benchmark.harness`. Ground truth is derived **mechanically** from
each benchmark's own artifacts -- never hand-authored -- so the labels remain
the benchmark's, not ours:

    Juliet   the suite's own ``FLAW`` / ``POTENTIAL FLAW`` line markers and
             the CWE encoded in the official file name
    QuixBugs the diff between the distributed buggy program and its
             distributed correct twin
    BugsInPy the project's ``bug_patch.txt`` unified diff
    Defects4J the framework's exported modified-line listing

Every adapter emits::

    {"id", "language", "code"|"file", "ground_truth": [{"line","cwe"}],
     "vulnerable": bool, "provenance": str}

``provenance`` records where the label came from, so any reviewer can trace a
single case back to the originating file in the upstream distribution.

CLI
---
    python -m benchmark.adapters juliet    <juliet_root>   out.jsonl
    python -m benchmark.adapters quixbugs  <quixbugs_root> out.jsonl
    python -m benchmark.adapters bugsinpy  <bugsinpy_root> out.jsonl
    python -m benchmark.adapters defects4j <d4j_root>      out.jsonl

Optional flags: ``--limit N`` (cap cases), ``--cwe CWE-121,CWE-78`` (filter),
``--seed N`` (sampling seed for a reproducible subset).
"""

from __future__ import annotations

import argparse
import csv
import difflib
import json
import random
import re
from pathlib import Path

CWE_IN_PATH = re.compile(r"CWE[-_]?(\d+)", re.I)

# Juliet encodes the intent of each function in its name: ``*_bad`` contains
# the flaw, ``*_good*`` variants are the patched twins.
_JULIET_BAD = re.compile(r"\bbad\b|_bad|badSink|badSource", re.I)
_JULIET_GOOD = re.compile(r"\bgood\b|_good|goodG2B|goodB2G|goodSink|goodSource", re.I)


# ---------------------------------------------------------------------------
# Juliet Test Suite (NIST SARD) — the reference security benchmark
# ---------------------------------------------------------------------------
def _split_juliet_functions(lines: list) -> list:
    """
    Split a Juliet source file into top-level function bodies.

    Each Juliet test case packs the vulnerable function (``*_bad``) and one or
    more remediated twins (``goodG2B``, ``goodB2G``, ``*_good``) into a single
    file. Scoring the file as a whole would be scientifically wrong: the good
    functions frequently invoke the *same* dangerous sink with a trusted
    source, so a whole-file label cannot distinguish a detector that reasons
    about data flow from one that merely greps for the sink.

    Returns ``[(name, start_line, end_line)]`` using brace depth, which is
    reliable here because Juliet's generated code is consistently formatted.
    """
    funcs = []
    sig = re.compile(r"^\s*(?:static\s+)?(?:void|int|char|short|long|unsigned"
                     r"|float|double|size_t|wchar_t)[\w\s\*&]*\b"
                     r"(\w+)\s*\([^;]*\)\s*$")
    i = 0
    n = len(lines)
    while i < n:
        m = sig.match(lines[i])
        if not m or i + 1 >= n or lines[i + 1].strip() != "{":
            i += 1
            continue
        name = m.group(1)
        depth, j = 0, i + 1
        while j < n:
            depth += lines[j].count("{") - lines[j].count("}")
            if depth == 0:
                break
            j += 1
        funcs.append((name, i + 1, min(j + 1, n)))
        i = j + 1
    return funcs


_JULIET_VARIANT = re.compile(r"_(\d{2})[a-z]?\.(?:c|cpp|java)$", re.I)


def juliet_flow_variant(filename: str) -> int | None:
    """
    Return the Juliet *flow variant* number encoded in a test-case file name.

    Juliet organizes each CWE into numbered flow variants. Variants 01--12
    keep the entire source-to-sink flow inside one file (baseline, control
    flow, and simple data flow through locals). Variants 21 and above
    deliberately split the flow across functions in *separate* translation
    units -- for example ``..._51a.c`` chooses the undersized buffer and
    ``..._51b.c`` performs the overflowing copy.

    A single-translation-unit analyzer cannot decide the latter group without
    whole-program linking, so the variant number is what makes an
    honest scoping decision possible.
    """
    m = _JULIET_VARIANT.search(filename)
    return int(m.group(1)) if m else None


def juliet_adapter(root: str, limit: int | None = None,
                   cwe_filter: set | None = None, seed: int = 0,
                   max_variant: int | None = None):
    """
    Juliet Test Suite v1.3 (NIST SARD), scored at **function** granularity.

    Ground truth comes from two artifacts the suite itself provides:

      * the CWE encoded in the official file name, and
      * the ``/* FLAW: */`` and ``/* POTENTIAL FLAW: */`` markers that
        annotate the defective statement.

    Each file yields up to two cases:

      ``*_bad``   the genuine vulnerability, labelled at its FLAW line(s);
      ``good*``   the remediated twin, emitted as a **benign** case with no
                  ground truth. The good twin usually reaches the identical
                  sink from a trusted source, so it is the discriminating
                  precision test -- a sink-matching detector fails it, and a
                  taint-based detector clears it.

    Reporting both halves keeps recall and precision measurable on the same
    third-party data, with no label authored by us.
    """
    root = Path(root)
    exts = {".c": "C", ".cpp": "C++", ".java": "Java"}
    files = [f for f in root.rglob("*") if f.suffix.lower() in exts]
    files = [f for f in files if not f.name.endswith(("_bad.c", "main.c", "io.c"))]
    files.sort()
    if seed:
        random.Random(seed).shuffle(files)

    emitted = 0
    for f in files:
        if limit is not None and emitted >= limit:
            break
        m = CWE_IN_PATH.search(f.name) or CWE_IN_PATH.search(str(f))
        if not m:
            continue
        cwe = f"CWE-{m.group(1)}"
        if cwe_filter and cwe not in cwe_filter:
            continue
        variant = juliet_flow_variant(f.name)
        if max_variant is not None and (variant is None or variant > max_variant):
            continue
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        lines = text.splitlines()
        language = exts[f.suffix.lower()]

        # FLAW markers -> the first following statement line
        flaw_lines = set()
        for i, line in enumerate(lines, 1):
            if "FLAW:" not in line.upper():
                continue
            for j in range(i, min(i + 4, len(lines))):
                nxt = lines[j].strip()
                if nxt and not nxt.startswith(("/*", "*", "//", "#")):
                    flaw_lines.add(j + 1)
                    break

        for name, start, end in _split_juliet_functions(lines):
            if limit is not None and emitted >= limit:
                break
            is_bad = bool(_JULIET_BAD.search(name)) and not _JULIET_GOOD.search(name)
            is_good = bool(_JULIET_GOOD.search(name))
            if not (is_bad or is_good):
                continue
            # Dispatch wrappers (`*_good()` calling `goodG2B()`) carry no
            # analyzable body of their own.
            if end - start < 4:
                continue

            # Preserve the file's preprocessor context. Juliet routinely
            # aliases both the payload variable and the dangerous API through
            # object-like macros (`#define COMMAND_ARG3 data`,
            # `#define SYSTEM system`), so a function body extracted without
            # its #defines is not analyzable as written -- the data-flow edge
            # into the sink simply disappears. The directives are prepended as
            # a fixed-size preamble and line numbers are shifted to match, so
            # ground-truth positions stay exact.
            preamble = [ln for ln in lines[:start - 1]
                        if re.match(r"^[ \t]*#[ \t]*define[ \t]+\w+[ \t]+\w+[ \t]*$", ln)]
            offset = len(preamble)
            body = "\n".join(preamble + lines[start - 1:end])
            local_flaws = sorted(ln - start + 1 + offset for ln in flaw_lines
                                 if start <= ln <= end)
            if is_bad and not local_flaws:
                continue

            yield {
                "id": f"juliet_{f.stem}__{name}",
                "language": language,
                "code": body,
                "ground_truth": ([{"line": ln, "cwe": cwe} for ln in local_flaws]
                                 if is_bad else []),
                "vulnerable": is_bad,
                "flow_variant": variant,
                "provenance": f"Juliet v1.3 :: {f.name} :: {name}() "
                              f"[flow variant {variant:02d}; "
                              f"{'FLAW markers' if is_bad else 'remediated twin'}]"
                              if variant is not None else
                              f"Juliet v1.3 :: {f.name} :: {name}()",
            }
            emitted += 1


# ---------------------------------------------------------------------------
# QuixBugs — 40 classic algorithms, one single-line defect each
# ---------------------------------------------------------------------------
def quixbugs_adapter(root: str, limit: int | None = None,
                     cwe_filter: set | None = None, seed: int = 0):
    """
    QuixBugs distributes each program twice: a buggy version and a correct
    version differing by exactly one line. Differencing the pair recovers the
    defective line without any manual annotation.

    Both the Python and the Java translations are emitted. Each buggy program
    is additionally paired with its correct twin as a *benign* case, which is
    what makes precision measurable on this benchmark rather than only recall.
    """
    root = Path(root)
    variants = [
        ("python_programs", "correct_python_programs", "*.py", "Python"),
        ("java_programs", "correct_java_programs", "*.java", "Java"),
    ]
    emitted = 0
    for buggy_dir_name, fixed_dir_name, glob, language in variants:
        buggy_dir = root / buggy_dir_name
        fixed_dir = root / fixed_dir_name
        if not buggy_dir.exists():
            continue
        for buggy in sorted(buggy_dir.glob(glob)):
            if limit is not None and emitted >= limit:
                break
            fixed = fixed_dir / buggy.name
            if not fixed.exists():
                continue
            try:
                b_text = buggy.read_text(errors="ignore")
                f_text = fixed.read_text(errors="ignore")
            except Exception:
                continue
            b_lines = b_text.splitlines()
            f_lines = f_text.splitlines()

            gt = []
            sm = difflib.SequenceMatcher(a=b_lines, b=f_lines, autojunk=False)
            for tag, i1, i2, _j1, _j2 in sm.get_opcodes():
                if tag in ("replace", "delete"):
                    for ln in range(i1 + 1, i2 + 1):
                        gt.append({"line": ln, "cwe": "CWE-BUG"})
            if not gt:
                continue

            yield {
                "id": f"quixbugs_{language.lower()}_{buggy.stem}_buggy",
                "language": language,
                "code": b_text,
                "ground_truth": gt,
                "vulnerable": True,
                "provenance": f"QuixBugs :: {buggy_dir_name}/{buggy.name} "
                              f"vs {fixed_dir_name}/{fixed.name} (diff)",
            }
            emitted += 1
            # the distributed correct twin: a benign case with no ground truth
            yield {
                "id": f"quixbugs_{language.lower()}_{buggy.stem}_fixed",
                "language": language,
                "code": f_text,
                "ground_truth": [],
                "vulnerable": False,
                "provenance": f"QuixBugs :: {fixed_dir_name}/{fixed.name} "
                              f"(reference correct version)",
            }
            emitted += 1


# ---------------------------------------------------------------------------
# BugsInPy — real-world Python defects from 17 open-source projects
# ---------------------------------------------------------------------------
def bugsinpy_adapter(root: str, limit: int | None = None,
                     cwe_filter: set | None = None, seed: int = 0):
    """
    Each BugsInPy bug directory carries ``bug_patch.txt``, the unified diff
    that fixes the defect. Lines removed by the patch are the defective lines
    in the buggy revision, which is the standard localization ground truth for
    this benchmark.
    """
    root = Path(root)
    emitted = 0
    for patch in sorted(root.rglob("bug_patch.txt")):
        if limit is not None and emitted >= limit:
            break
        bug_dir = patch.parent
        bug_id = "_".join(bug_dir.parts[-3:])
        try:
            diff = patch.read_text(errors="ignore")
        except Exception:
            continue

        target_file, old_ln, gt = None, 0, []
        for line in diff.splitlines():
            if line.startswith("--- "):
                target_file = line[4:].strip().split("\t")[0].lstrip("ab/")
                continue
            hunk = re.match(r"@@ -(\d+)(?:,\d+)? \+\d+", line)
            if hunk:
                old_ln = int(hunk.group(1))
                continue
            if line.startswith("-") and not line.startswith("---"):
                gt.append({"line": old_ln, "cwe": "CWE-BUG"})
                old_ln += 1
            elif not line.startswith("+"):
                old_ln += 1

        if not gt or not target_file:
            continue
        src = next((c for c in bug_dir.rglob("*.py")
                    if c.name == Path(target_file).name), None)
        if src is None:
            continue
        yield {
            "id": f"bugsinpy_{bug_id}",
            "language": "Python",
            "code": src.read_text(errors="ignore"),
            "ground_truth": gt,
            "vulnerable": True,
            "provenance": f"BugsInPy :: {bug_id} :: bug_patch.txt",
        }
        emitted += 1


# ---------------------------------------------------------------------------
# Defects4J — real-world Java defects
# ---------------------------------------------------------------------------
def defects4j_adapter(root: str, limit: int | None = None,
                      cwe_filter: set | None = None, seed: int = 0):
    """
    Expects a prepared export: ``<root>/<Project>/<id>/buggy/**.java`` with a
    sibling ``bug_lines.txt`` produced by
    ``defects4j export -p classes.modified``.
    """
    root = Path(root)
    emitted = 0
    for buggy_java in sorted(root.rglob("buggy/**/*.java")):
        if limit is not None and emitted >= limit:
            break
        bug_dir = buggy_java.parents[1]
        bug_id = "_".join(bug_dir.parts[-2:])
        lines_file = bug_dir / "bug_lines.txt"
        if not lines_file.exists():
            continue
        gt = [{"line": int(tok), "cwe": "CWE-BUG"}
              for tok in re.findall(r"\d+", lines_file.read_text(errors="ignore"))]
        if not gt:
            continue
        yield {
            "id": f"defects4j_{bug_id}",
            "language": "Java",
            "code": buggy_java.read_text(errors="ignore"),
            "ground_truth": gt,
            "vulnerable": True,
            "provenance": f"Defects4J :: {bug_id} :: bug_lines.txt",
        }
        emitted += 1


# ---------------------------------------------------------------------------
# OWASP Benchmark v1.2 — third-party Java security benchmark
# ---------------------------------------------------------------------------
def owasp_benchmark_adapter(root: str, limit: int | None = None,
                            cwe_filter: set | None = None, seed: int = 0):
    root = Path(root)
    manifests = sorted(root.rglob("expectedresults*.csv"))
    if not manifests:
        print("No expectedresults*.csv found under:", root)
        return
    print(f"Loading OWASP test cases from {manifests[0]}...")
    java_index = {f.name.lower(): f for f in root.rglob("*.java")}
    emitted, rows = 0, []
    with manifests[0].open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            norm = {str(k).strip().lstrip("#").strip().lower(): str(v).strip() for k, v in row.items() if k}
            name = (norm.get("test name") or norm.get("testcase name") or
                    norm.get("testcasename") or norm.get("test case name") or
                    norm.get("testcase") or norm.get("name"))
            verdict = (norm.get("real vulnerability") or norm.get("vulnerability") or
                       norm.get("expected result") or norm.get("expected"))
            category = norm.get("category") or norm.get("cwe") or "CWE-Unknown"
            if not name or not verdict:
                continue
            vulnerable = verdict.lower() in {"true", "1", "yes", "vulnerable"}
            if verdict.lower() not in {"true", "false", "1", "0", "yes", "no", "vulnerable", "safe"}:
                continue
            cwe_match = re.search(r"(\d+)", category)
            cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else "CWE-Unknown"
            if cwe_filter and cwe not in cwe_filter:
                continue
            fname = name.lower() if name.lower().endswith(".java") else f"{name.lower()}.java"
            target_file = java_index.get(fname)
            if not target_file:
                continue
            rows.append((name, target_file, vulnerable, cwe, manifests[0].name))
    if seed:
        random.Random(seed).shuffle(rows)
    for name, source, vulnerable, cwe, manifest in rows:
        if limit is not None and emitted >= limit:
            break
        yield {
            "id": f"owasp_benchmark_v1_2_{name}",
            "language": "Java",
            "code": source.read_text(encoding="utf-8", errors="ignore"),
            "ground_truth": [],
            "vulnerable": vulnerable,
            "case_level_only": True,
            "benchmark_cwe": cwe,
            "provenance": f"OWASP Benchmark v1.2 :: {manifest} :: {name}.java",
        }
        emitted += 1


ADAPTERS = {
    "juliet": juliet_adapter,
    "quixbugs": quixbugs_adapter,
    "bugsinpy": bugsinpy_adapter,
    "defects4j": defects4j_adapter,
    "owasp": owasp_benchmark_adapter,
}


def main():
    ap = argparse.ArgumentParser(description="Third-party benchmark adapters")
    ap.add_argument("dataset", choices=sorted(ADAPTERS))
    ap.add_argument("root", help="Root directory of the downloaded benchmark")
    ap.add_argument("out", help="Output JSONL path")
    ap.add_argument("--limit", type=int, default=None, help="Cap emitted cases")
    ap.add_argument("--cwe", default="", help="Comma-separated CWE allow-list")
    ap.add_argument("--seed", type=int, default=0,
                    help="Shuffle seed for a reproducible subset")
    ap.add_argument("--max-variant", type=int, default=None,
                    help="Juliet only: keep flow variants <= N. Variants 01-12 "
                         "hold the whole flow in one translation unit; 21+ split "
                         "it across files and need whole-program analysis.")
    args = ap.parse_args()

    cwe_filter = {c.strip() for c in args.cwe.split(",") if c.strip()} or None
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)

    kwargs = {}
    if args.dataset == "juliet":
        kwargs["max_variant"] = args.max_variant

    n, langs, cwes = 0, {}, {}
    with open(args.out, "w", encoding="utf-8") as fh:
        for case in ADAPTERS[args.dataset](args.root, args.limit, cwe_filter,
                                           args.seed, **kwargs):
            fh.write(json.dumps(case) + "\n")
            n += 1
            langs[case["language"]] = langs.get(case["language"], 0) + 1
            for g in case["ground_truth"]:
                cwes[g["cwe"]] = cwes.get(g["cwe"], 0) + 1

    print(f"wrote {n} cases to {args.out}")
    if n:
        print("  languages:", ", ".join(f"{k}={v}" for k, v in sorted(langs.items())))
        top = sorted(cwes.items(), key=lambda x: -x[1])[:12]
        print("  CWEs:", ", ".join(f"{k}={v}" for k, v in top))
    else:
        print("  (0 cases — verify the dataset root path and layout)")


if __name__ == "__main__":
    main()
