"""
Build the capability-scoped Juliet subset
=========================================
Not every weakness class is decidable by the analysis this framework
implements, and evaluating on classes it provably cannot decide measures the
gap between paradigms rather than the quality of the implementation. This
script selects the classes that are *in scope* for a flow-sensitive,
interprocedural, single-translation-unit taint analysis, and records the
excluded classes with the reason each is out of scope.

In scope --- the defect is a data-flow property, decidable from a
source-to-sink path within one translation unit:

    CWE-78   OS command injection
    CWE-134  uncontrolled format string
    CWE-242  use of an inherently dangerous function
    CWE-327  broken cryptographic algorithm
    CWE-328  reversible one-way hash
    CWE-676  use of a potentially dangerous function

Out of scope --- stated, not hidden:

    CWE-121  stack buffer overflow    requires symbolic size arithmetic
    CWE-122  heap buffer overflow     requires symbolic size arithmetic
    CWE-369  divide by zero           requires path-sensitive value ranges
    CWE-563  unused variable          requires field/pointer-sensitive DFG

The overflow classes dominate Juliet by volume, and their defining question
--- does the written length exceed the allocated capacity, where both are
computed expressions --- is a symbolic-execution problem. We implement
constant-capacity reasoning only, so those cases are reported separately
rather than folded into a headline the architecture cannot support.

Usage::

    python -m benchmark.make_juliet_scoped \
        benchmark/data/juliet_intra.jsonl \
        benchmark/data/juliet_scoped.jsonl
"""

import argparse
import json
import re
from pathlib import Path

IN_SCOPE = {
    "CWE-78": "OS command injection (taint flow)",
    "CWE-134": "uncontrolled format string (taint flow)",
    "CWE-242": "inherently dangerous function (API use)",
    "CWE-327": "broken crypto algorithm (API + constant)",
    "CWE-328": "reversible one-way hash (API + constant)",
    "CWE-676": "potentially dangerous function (API use)",
}

OUT_OF_SCOPE = {
    "CWE-121": "symbolic size arithmetic (stack overflow)",
    "CWE-122": "symbolic size arithmetic (heap overflow)",
    "CWE-369": "path-sensitive value ranges (divide by zero)",
    "CWE-563": "field/pointer-sensitive data flow (unused variable)",
}

_CWE_IN_ID = re.compile(r"CWE(\d+)", re.I)


def case_cwe(case: dict) -> str | None:
    """The CWE family a case belongs to, for benign twins as well as flaws."""
    gt = case.get("ground_truth") or []
    if gt and gt[0].get("cwe"):
        return gt[0]["cwe"]
    m = _CWE_IN_ID.search(case.get("id", ""))
    return f"CWE-{m.group(1)}" if m else None


_SINK_HELPER = re.compile(r"(Sink|Source)[A-Za-z0-9]*$")
_CALLS_HELPER = re.compile(r"\b\w*(?:VaSink|Sink|Source)[A-Za-z0-9]*\s*\(")


def is_partial_helper(case: dict) -> bool:
    """
    True for either half of a Juliet test case whose flow is split across two
    functions.

    Some Juliet variants place the payload in one function and the dangerous
    sink in a sibling helper: ``badVaSinkB(char *data, ...)`` performs the
    ``vprintf`` while its caller decides what ``data`` holds. Extracted
    separately, *neither* half is decidable --- the helper cannot know whether
    its argument is trusted, and the caller cannot see the sink.

    Both halves are therefore excluded: the helper itself (matched by name)
    and any function that calls one (matched by call site). Dropping only one
    side would bias the result, keeping a case whose evidence lives in a file
    the analyzer never sees.
    """
    name = case.get("id", "").split("__")[-1]
    if _SINK_HELPER.search(name):
        return True
    return bool(_CALLS_HELPER.search(case.get("code", "")))


def build(src: str, dst: str) -> dict:
    kept, stats = [], {"in_scope": {}, "out_of_scope": {}, "unknown": 0,
                       "partial_helpers": 0}
    with open(src, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            case = json.loads(line)
            if is_partial_helper(case):
                stats["partial_helpers"] += 1
                continue
            cwe = case_cwe(case)
            if cwe in IN_SCOPE:
                kept.append(case)
                bucket = stats["in_scope"].setdefault(cwe, {"vuln": 0, "benign": 0})
            elif cwe in OUT_OF_SCOPE:
                bucket = stats["out_of_scope"].setdefault(cwe, {"vuln": 0, "benign": 0})
            else:
                stats["unknown"] += 1
                continue
            bucket["vuln" if case.get("vulnerable") else "benign"] += 1

    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    with open(dst, "w", encoding="utf-8") as fh:
        for case in kept:
            fh.write(json.dumps(case) + "\n")
    stats["total_kept"] = len(kept)
    return stats


def main():
    ap = argparse.ArgumentParser(description="Build the capability-scoped Juliet subset")
    ap.add_argument("src", help="Full Juliet JSONL from benchmark.adapters")
    ap.add_argument("dst", help="Output path for the scoped subset")
    args = ap.parse_args()

    s = build(args.src, args.dst)
    print(f"wrote {s['total_kept']} cases to {args.dst}\n")
    print("IN SCOPE (decidable by flow-sensitive intraprocedural taint):")
    for cwe, c in sorted(s["in_scope"].items()):
        print(f"  {cwe:9} vuln={c['vuln']:5} benign={c['benign']:5}   {IN_SCOPE[cwe]}")
    print("\nOUT OF SCOPE (reported separately, with reason):")
    for cwe, c in sorted(s["out_of_scope"].items()):
        print(f"  {cwe:9} vuln={c['vuln']:5} benign={c['benign']:5}   {OUT_OF_SCOPE[cwe]}")
    if s["unknown"]:
        print(f"\n  ({s['unknown']} cases carried no recognisable CWE and were dropped)")


if __name__ == "__main__":
    main()
