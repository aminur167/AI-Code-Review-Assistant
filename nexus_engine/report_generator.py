"""
Report Generator
================
Final pipeline stage: aggregates every artifact into exportable reports
(JSON / CSV / SARIF / LaTeX table) and a research quality score.
"""

import json

import pandas as pd

from .sarif_exporter import to_sarif_json

SEVERITY_PENALTY = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 3, "INFO": 0}


def quality_score(findings: list[dict], metrics: dict) -> float:
    """0-100 code health score: severity-weighted penalty + MI bonus."""
    penalty = sum(SEVERITY_PENALTY.get(f.get("severity", "LOW"), 3) for f in findings)
    mi = metrics.get("maintainability_index", 75) or 75
    score = 100 - penalty + (mi - 75) * 0.2
    return round(max(0.0, min(100.0, score)), 1)


def severity_stats(findings: list[dict]) -> dict:
    stats = {}
    for f in findings:
        stats[f.get("severity", "LOW")] = stats.get(f.get("severity", "LOW"), 0) + 1
    return stats


def to_json_report(result: dict) -> str:
    return json.dumps(result, indent=2, default=str)


def findings_dataframe(findings: list[dict]) -> pd.DataFrame:
    cols = ["id", "rule_id", "cwe", "owasp", "confidence", "severity",
            "category", "line", "message", "evidence", "fix_hint"]
    if not findings:
        return pd.DataFrame(columns=cols)
    rows = []
    for f in findings:
        rows.append({
            "id": f.get("id", ""), "rule_id": f.get("rule_id", ""),
            "cwe": f.get("cwe", ""), "owasp": f.get("owasp", ""),
            "confidence": f.get("confidence", ""),
            "severity": f.get("severity", ""),
            "category": f.get("category", ""), "line": f.get("line", 0),
            "message": f.get("message", ""), "evidence": f.get("evidence", ""),
            "fix_hint": f.get("fix_hint", ""),
        })
    return pd.DataFrame(rows)


def to_csv_report(findings: list[dict]) -> str:
    return findings_dataframe(findings).to_csv(index=False)


def to_sarif_report(findings: list[dict], uri: str = "input.py") -> str:
    return to_sarif_json(findings, uri)


_HTML_SEV_COLOR = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
                   "LOW": "#3b82f6", "INFO": "#64748b"}


def to_html_report(pipeline_result: dict, uri: str = "input") -> str:
    """Self-contained, printable HTML report (Phase 7 export)."""
    findings = pipeline_result.get("findings", [])
    metrics = pipeline_result.get("metrics", {})
    stats = severity_stats(findings)
    lang = pipeline_result.get("language", "?")
    score = pipeline_result.get("quality_score", "?")

    rows = []
    for f in findings:
        sev = f.get("severity", "LOW")
        color = _HTML_SEV_COLOR.get(sev, "#64748b")
        xai = f.get("xai", {})
        rows.append(f"""
        <div class="finding" style="border-left-color:{color}">
          <div class="head">
            <span class="badge" style="background:{color}">{sev}</span>
            <span class="cwe">{f.get('cwe','')}</span>
            <span class="owasp">{f.get('owasp','')}</span>
            <b>{f.get('id','')} &middot; Line {f.get('line')}</b>
            <span class="conf">confidence {int(f.get('confidence',0)*100)}%</span>
          </div>
          <div class="msg">{_esc(f.get('message',''))}</div>
          {f"<pre class='ev'>{_esc(f.get('evidence',''))}</pre>" if f.get('evidence') else ''}
          {f"<div class='fix'>&#128161; {_esc(f.get('fix_hint',''))}</div>" if f.get('fix_hint') else ''}
          {f"<div class='root'><b>Root cause:</b> {_esc(xai.get('root_cause',''))}</div>" if xai.get('root_cause') else ''}
        </div>""")

    stat_html = " ".join(
        f"<span class='chip' style='background:{_HTML_SEV_COLOR.get(k,'#64748b')}'>{k}: {v}</span>"
        for k, v in stats.items()) or "<span class='chip' style='background:#22c55e'>No issues</span>"

    m = metrics
    metric_html = (
        f"<tr><td>Language</td><td>{lang}</td></tr>"
        f"<tr><td>Quality score</td><td>{score}/100</td></tr>"
        f"<tr><td>LOC / SLOC</td><td>{m.get('loc',{}).get('total','?')} / {m.get('loc',{}).get('sloc','?')}</td></tr>"
        f"<tr><td>Cyclomatic complexity</td><td>{m.get('cyclomatic_complexity','?')}</td></tr>"
        f"<tr><td>Maintainability index</td><td>{m.get('maintainability_index','N/A')}</td></tr>"
        f"<tr><td>Functions / Classes</td><td>{m.get('functions','?')} / {m.get('classes','?')}</td></tr>"
    )

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>NexusReview Report &mdash; {_esc(uri)}</title>
<style>
  body{{font-family:Segoe UI,Arial,sans-serif;background:#0a0e1a;color:#e2e8f0;margin:0;padding:24px;}}
  h1{{color:#38bdf8;}} h2{{color:#cbd5e1;border-bottom:1px solid #1e293b;padding-bottom:6px;}}
  table{{border-collapse:collapse;margin:12px 0;}} td{{padding:4px 14px;border-bottom:1px solid #1e293b;}}
  .chip,.badge{{color:#fff;padding:2px 10px;border-radius:12px;font-size:.75rem;font-weight:700;margin-right:6px;}}
  .finding{{background:#111a2e;border-left:4px solid;border-radius:8px;padding:12px 16px;margin:10px 0;}}
  .head{{margin-bottom:6px;}} .cwe,.owasp,.conf{{color:#94a3b8;font-size:.8rem;margin-right:8px;}}
  .msg{{margin:4px 0;}} pre.ev{{background:#0d1424;color:#7dd3fc;padding:8px;border-radius:6px;overflow:auto;}}
  .fix{{color:#86efac;margin-top:4px;}} .root{{color:#cbd5e1;margin-top:4px;font-size:.9rem;}}
  .footer{{color:#64748b;font-size:.8rem;margin-top:24px;}}
</style></head><body>
<h1>&#128300; NexusReview Security &amp; Quality Report</h1>
<p class="footer">Neuro-Symbolic Static Analysis Framework &middot; deterministic detection, LLM explanation only</p>
<h2>Summary</h2>
<div>{stat_html}</div>
<table>{metric_html}</table>
<h2>Findings ({len(findings)})</h2>
{''.join(rows) or '<p>No issues detected.</p>'}
<p class="footer">Generated by NexusReview v1.0. CWE &amp; OWASP Top-10 (2021) mapped.
Confidence is a transparency signal, not a detection gate.</p>
</body></html>"""


def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def to_latex_table(eval_dict: dict, caption="NexusReview evaluation results") -> str:
    """Render an evaluation dict as an IEEE-style LaTeX table row set."""
    rows = "\n".join(
        f"    {k.replace('_', ' ').title()} & "
        f"{v if not isinstance(v, float) else f'{v * 100:.2f}\\%' if v <= 1 else v} \\\\"
        for k, v in eval_dict.items()
        if k in ("TP", "FP", "FN", "TN", "precision", "recall", "f1_score", "accuracy", "mcc")
    )
    return (
        "\\begin{table}[t]\n\\centering\n"
        f"\\caption{{{caption}}}\n\\label{{tab:results}}\n"
        "\\begin{tabular}{lr}\n\\toprule\nMetric & Value \\\\\n\\midrule\n"
        f"{rows}\n\\bottomrule\n\\end{{tabular}}\n\\end{{table}}\n"
    )


def build_full_report(pipeline_result: dict) -> dict:
    """Compact, serializable end-to-end report."""
    findings = pipeline_result.get("findings", [])
    return {
        "tool": "NexusReview v1.0 — Neuro-Symbolic Static Analysis Framework",
        "language": pipeline_result.get("language"),
        "quality_score": pipeline_result.get("quality_score"),
        "severity_stats": severity_stats(findings),
        "latency": pipeline_result.get("latency"),
        "metrics": pipeline_result.get("metrics"),
        "findings": findings,
        "taint_flows": pipeline_result.get("taint_findings", []),
        "graphs": {
            "cfg_stats": pipeline_result.get("cfg_stats"),
            "call_graph": pipeline_result.get("call_graph_summary"),
        },
    }
