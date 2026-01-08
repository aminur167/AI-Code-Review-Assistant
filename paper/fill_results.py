"""
Paper Results Auto-Filler (Primary Real-World Table)
====================================================
The SECONDARY (five-language synthetic) numbers are already hardcoded in
nexusreview.tex because they are produced by the bundled harness. This
script fills the PRIMARY real-world table (Table~\ref{tab:primary}) once you
have run the adapters + harness on the downloaded benchmarks.

Run the harness once per real benchmark, e.g.:
    python -m benchmark.adapters bugsinpy <root> benchmark/data/bugsinpy.jsonl
    python -m benchmark.harness --dataset benchmark/data/bugsinpy.jsonl \
        --out paper/results/bugsinpy
(repeat for quixbugs / defects4j / juliet)

Then:
    python paper/fill_results.py \
        --reports bugsinpy=paper/results/bugsinpy/benchmark_report.json \
                  quixbugs=paper/results/quixbugs/benchmark_report.json \
                  defects4j=paper/results/defects4j/benchmark_report.json \
                  juliet=paper/results/juliet/benchmark_report.json \
        --tex paper/nexusreview.tex --out paper/nexusreview_filled.tex
"""

import argparse
import json


ROW_ORDER = ["bugsinpy", "quixbugs", "defects4j", "juliet"]
ROW_PREFIX = {
    "bugsinpy": "BugsInPy   & Python &",
    "quixbugs": "QuixBugs   & Python &",
    "defects4j": "Defects4J  & Java   &",
    "juliet": "Juliet     & C/C++/Java &",
}


def _cells(report_path):
    if not report_path:
        return "<<< FILL >>> & <<< FILL >>> & <<< FILL >>> & <<< FILL >>> & <<< FILL >>>"
    a = json.load(open(report_path, encoding="utf-8"))["aggregate"]
    return (f"{a['TP']} & {a['FP']} & {a['FN']} & "
            f"{a['precision']*100:.1f}\\% & {a['recall']*100:.1f}\\%")


def fill(reports: dict, tex_path: str, out_path: str):
    tex = open(tex_path, encoding="utf-8").read()
    for key in ROW_ORDER:
        prefix = ROW_PREFIX[key]
        cells = _cells(reports.get(key))
        # replace the whole primary row for this dataset
        start = tex.find(prefix)
        if start == -1:
            continue
        end = tex.find("\\\\", start)
        if end == -1:
            continue
        tex = tex[:start] + f"{prefix} {cells} " + tex[end:]
    open(out_path, "w", encoding="utf-8").write(tex)

    remaining = tex.count("<<< FILL")
    filled = [k for k in ROW_ORDER if reports.get(k)]
    print(f"Wrote {out_path}")
    print(f"Filled primary rows: {filled or 'none (pass --reports key=path)'}")
    print(f"Remaining <<< FILL >>> markers: {remaining} "
          f"(unfilled datasets + repo URL).")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", nargs="*", default=[],
                    help="key=path pairs, keys: bugsinpy quixbugs defects4j juliet")
    ap.add_argument("--tex", default="paper/nexusreview.tex")
    ap.add_argument("--out", default="paper/nexusreview_filled.tex")
    args = ap.parse_args()

    reports = {}
    for item in args.reports:
        if "=" in item:
            k, _, v = item.partition("=")
            reports[k.strip()] = v.strip()
    fill(reports, args.tex, args.out)


if __name__ == "__main__":
    main()
