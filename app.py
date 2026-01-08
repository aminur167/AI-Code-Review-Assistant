"""
NexusReview — Neuro-Symbolic Static Analysis Framework
======================================================
Streamlit research dashboard.

    Source Code -> Parser -> AST -> CFG -> DFG -> Call Graph
                -> Rule Engine -> Vulnerability Detector -> XAI -> Report

Deterministic detection (Symbolic) + LLM explanation only (Neuro).
"""

import json
import os

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from nexus_engine.pipeline import NexusPipeline
from nexus_engine.report_generator import (to_csv_report, to_json_report,
                                           findings_dataframe, build_full_report,
                                           to_html_report)
from nexus_engine.sarif_exporter import to_sarif_json
from nexus_engine import db_manager

st.set_page_config(page_title="NexusReview | Neuro-Symbolic Analyzer",
                   layout="wide", page_icon="🔬", initial_sidebar_state="expanded")

# ---------------------------------------------------------------- styling
st.markdown("""
<style>
    .stApp { background: #0a0e1a; }
    section[data-testid="stSidebar"] { background: #0d1424; border-right: 1px solid #1e293b; }
    h1, h2, h3 { color: #e2e8f0 !important; font-family: 'Segoe UI', sans-serif; }
    .block-container { padding-top: 2rem; }
    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, #131c31 0%, #0f1626 100%);
        border: 1px solid #1e293b; border-radius: 12px; padding: 16px 18px;
        box-shadow: 0 2px 12px rgba(0,0,0,0.35);
    }
    div[data-testid="stMetricValue"] { color: #38bdf8 !important; font-weight: 700; }
    div[data-testid="stMetricLabel"] { color: #94a3b8 !important; }
    .stTabs [data-baseweb="tab-list"] { gap: 4px; }
    .stTabs [data-baseweb="tab"] {
        background: #131c31; border-radius: 8px 8px 0 0; color: #94a3b8; padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] { background: #1e3a5f; color: #38bdf8; }
    .finding-card {
        border-radius: 10px; padding: 14px 18px; margin: 8px 0;
        border-left: 4px solid; background: #111a2e;
    }
    .sev-CRITICAL { border-color: #ef4444; }
    .sev-HIGH { border-color: #f97316; }
    .sev-MEDIUM { border-color: #eab308; }
    .sev-LOW { border-color: #3b82f6; }
    .sev-INFO { border-color: #64748b; }
    .badge { display:inline-block; padding:2px 10px; border-radius:12px;
             font-size:0.72rem; font-weight:700; margin-right:6px; }
    .b-CRITICAL{background:#7f1d1d;color:#fecaca;}
    .b-HIGH{background:#7c2d12;color:#fed7aa;}
    .b-MEDIUM{background:#713f12;color:#fef08a;}
    .b-LOW{background:#1e3a8a;color:#bfdbfe;}
    .b-INFO{background:#334155;color:#cbd5e1;}
    .pipeline-node { background:#131c31; border:1px solid #1e3a5f; border-radius:8px;
        padding:6px 10px; margin:3px 0; color:#7dd3fc; font-family:Consolas; font-size:0.8rem;}
</style>
""", unsafe_allow_html=True)

SEV_COLOR = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
             "LOW": "#3b82f6", "INFO": "#64748b"}


@st.cache_resource
def get_pipeline(use_llm):
    return NexusPipeline(use_llm_xai=use_llm)


def render_graphviz(dot: str, height=420):
    st.graphviz_chart(dot, width="stretch")


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.markdown("## 🔬 NexusReview")
    st.caption("Neuro-Symbolic Static Analysis Framework · v1.0")
    st.markdown("---")
    language = st.selectbox("Language", ["Python", "C", "C++", "Java", "JavaScript"])
    use_llm = st.toggle("Enable XAI (Groq LLM explanations)",
                        value=bool(os.getenv("GROQ_API_KEY")))
    if use_llm and not os.getenv("GROQ_API_KEY"):
        st.warning("No GROQ_API_KEY — XAI falls back to deterministic templates.")
    st.markdown("---")
    st.markdown("#### Pipeline")
    for node in ["Source Code", "Language Parser", "AST Generator", "CFG Builder",
                 "DFG Builder", "Call Graph", "Rule Engine", "Vulnerability Detector",
                 "XAI (Neuro)", "Report Generator"]:
        st.markdown(f"<div class='pipeline-node'>▸ {node}</div>", unsafe_allow_html=True)
    st.markdown("---")
    st.caption("Detection is 100% deterministic. The LLM only explains.")

SAMPLES = {
    "Python": '''import os, sqlite3, hashlib

API_KEY = "sk_live_51H8xSecretKey12345"

def get_user(conn, user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    conn.cursor().execute(query)

def handle_request():
    payload = request.args.get("cmd")
    forward(payload)

def forward(data):
    os.system(data)

def ratio(a):
    d = 0
    return a / d

def poll():
    i = 0
    while i < 100:
        print(i)
''',
    "C": '''#include <string.h>
void copy(char *src){
    char buf[16];
    strcpy(buf, src);
    system(src);
}
int main(){ char n[64]; gets(n); copy(n); }
''',
}

# ---------------------------------------------------------------- header
st.markdown("# 🔬 NexusReview")
st.markdown("##### A Neuro-Symbolic Static Analysis Framework — deterministic "
            "graph-theoretic detection with Explainable-AI feedback")

col_in, col_out = st.columns([1, 1.35], gap="large")

with col_in:
    st.markdown("### 📥 Source Code")
    code_input = st.text_area("Paste code", value=SAMPLES.get(language, ""),
                              height=340, label_visibility="collapsed")
    c_run, c_gt = st.columns([1, 1])
    with c_run:
        run = st.button("🚀 Run Analysis Pipeline", type="primary", width="stretch")
    with c_gt:
        with st.popover("🎯 Ground Truth (benchmark)", width="stretch"):
            gt_raw = st.text_area("One per line: `line,CWE-xx`",
                                  placeholder="6,CWE-89\n14,CWE-78", height=120)

    if run and code_input.strip():
        with st.spinner("Running Neuro-Symbolic pipeline…"):
            pipeline = get_pipeline(use_llm)
            result = pipeline.run(code_input, language)
            st.session_state.result = result
            # optional evaluation
            gt = []
            for line in (gt_raw or "").strip().split("\n"):
                if "," in line:
                    ln, _, cwe = line.partition(",")
                    try:
                        gt.append({"line": int(ln.strip()), "cwe": cwe.strip()})
                    except ValueError:
                        pass
            if gt:
                from nexus_engine.evaluator import evaluate
                sloc = result.get("metrics", {}).get("loc", {}).get("sloc", 1)
                st.session_state.eval = evaluate(
                    [f for f in result["findings"] if f.get("severity") != "INFO"],
                    gt, sloc, line_tolerance=2).to_dict()
            else:
                st.session_state.eval = None
            try:
                db_manager.init_db()
                db_manager.log_scan(result)
            except Exception:
                pass

# ---------------------------------------------------------------- results
with col_out:
    if "result" not in st.session_state:
        st.info("👈 Paste code and run the pipeline. A vulnerable sample is preloaded.")
    elif "error" in st.session_state.result:
        st.error(f"⚠️ {st.session_state.result['error']}")
    else:
        r = st.session_state.result
        findings = r["findings"]
        sev = r.get("severity_stats", {})

        st.markdown("### 📊 Analysis Summary")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Quality Score", f"{r['quality_score']}/100")
        m2.metric("Findings", len(findings),
                  delta=f"{sev.get('CRITICAL',0)} critical", delta_color="inverse")
        m3.metric("Latency", f"{r['latency']['total']*1000:.0f} ms")
        m4.metric("Maintainability",
                  f"{r['metrics'].get('maintainability_index') or 'N/A'}")

        if st.session_state.get("eval"):
            e = st.session_state.eval
            st.markdown("##### 🎯 Benchmark vs. Ground Truth")
            b1, b2, b3, b4 = st.columns(4)
            b1.metric("Precision", f"{e['precision']*100:.1f}%")
            b2.metric("Recall", f"{e['recall']*100:.1f}%")
            b3.metric("F1", f"{e['f1_score']*100:.1f}%")
            b4.metric("MCC", f"{e['mcc']:.3f}")

if "result" in st.session_state and "error" not in st.session_state.result:
    r = st.session_state.result
    findings = r["findings"]
    st.markdown("---")

    tabs = st.tabs(["🎯 Findings", "🧬 CFG", "🔀 DFG", "🌀 SSA", "🔗 PDG",
                    "📞 Call Graph", "📐 Metrics", "🧠 XAI", "⏱ Latency", "📦 Export"])

    # ---- Findings ----
    with tabs[0]:
        if not findings:
            st.success("✅ No issues detected.")
        # severity distribution
        sev_df = pd.DataFrame([(k, v) for k, v in r["severity_stats"].items()],
                              columns=["Severity", "Count"])
        if not sev_df.empty:
            fig = px.bar(sev_df, x="Severity", y="Count", color="Severity",
                         color_discrete_map=SEV_COLOR, template="plotly_dark")
            fig.update_layout(height=240, margin=dict(l=0, r=0, t=10, b=0),
                              paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                              showlegend=False)
            st.plotly_chart(fig, width="stretch")
        for f in findings:
            sev = f.get("severity", "LOW")
            owasp = f.get("owasp", "")
            conf = int(f.get("confidence", 0) * 100)
            owasp_badge = (f"<span class='badge b-INFO'>{owasp}</span>"
                           if owasp and not owasp.startswith("N/A") else "")
            st.markdown(
                f"<div class='finding-card sev-{sev}'>"
                f"<span class='badge b-{sev}'>{sev}</span>"
                f"<span class='badge b-INFO'>{f.get('cwe','')}</span>"
                f"{owasp_badge}"
                f"<b>{f.get('id','')} · Line {f.get('line')}</b> — {f.get('message')}"
                f"<br><span style='color:#64748b;font-size:0.8rem'>rule {f.get('rule_id')} "
                f"· {f.get('category')} · confidence {conf}%</span>"
                + (f"<br><code style='color:#7dd3fc'>{f.get('evidence','')}</code>"
                   if f.get("evidence") else "")
                + (f"<br>💡 <span style='color:#86efac'>{f.get('fix_hint','')}</span>"
                   if f.get("fix_hint") else "")
                + "</div>", unsafe_allow_html=True)

    # ---- CFG ----
    with tabs[1]:
        cfgs = r.get("cfgs", {})
        if cfgs:
            fn = st.selectbox("Function CFG", list(cfgs.keys()), key="cfg_fn")
            st.caption(f"Basic blocks with True/False, back, exception & return edges — "
                       f"{r['cfg_stats'][fn]}")
            render_graphviz(cfgs[fn].to_dot())
        else:
            st.info("No control-flow graph was produced — the source may have failed to parse.")

    # ---- DFG ----
    with tabs[2]:
        dfg = r.get("dfg_objects", {})
        if dfg:
            fn = st.selectbox("Function DFG", list(dfg.keys()), key="dfg_fn")
            d = r["dfg"][fn]
            cc1, cc2, cc3 = st.columns(3)
            cc1.metric("Definitions", d["definitions"])
            cc2.metric("Dead Stores", len(d["dead_stores"]))
            cc3.metric("Fixed-point iters", d["fixed_point_iterations"])
            if d["unused_variables"]:
                st.warning("Unused variables: " + ", ".join(d["unused_variables"]))
            if d["dead_stores"]:
                st.error("Dead stores: " + ", ".join(d["dead_stores"]))
            render_graphviz(dfg[fn].to_dot())
        else:
            st.info("No data-flow result was produced — the source may have failed to parse.")

    # ---- SSA ----
    with tabs[3]:
        ssa = r.get("ssa", {})
        if ssa:
            fn = st.selectbox("Function SSA", list(ssa.keys()), key="ssa_fn")
            s = ssa[fn]
            st.caption("Cytron SSA: dominance frontiers → φ-node placement → renaming")
            if s.get("phi_nodes"):
                st.markdown("**φ-nodes:**")
                for p in s["phi_nodes"]:
                    st.code(f"[{p['block'].split('::')[-1]}]  {p['phi']}")
            else:
                st.caption("No φ-nodes (no variable with multiple reaching definitions).")
            with st.expander("SSA-renamed form"):
                st.json(s.get("ssa_form", {}))
            with st.expander("Dominance frontiers"):
                st.json(s.get("dominance_frontiers", {}))
        else:
            st.info("No SSA form was produced — the source may have failed to parse.")

    # ---- PDG ----
    with tabs[4]:
        pdg = r.get("pdg_objects", {})
        if pdg:
            fn = st.selectbox("Function PDG", list(pdg.keys()), key="pdg_fn")
            p = r["pdg"][fn]
            st.caption(f"Program Dependence Graph — {len(p['control_dependencies'])} control + "
                       f"{len(p['data_dependencies'])} data dependencies")
            render_graphviz(pdg[fn].to_dot())
            crit = st.number_input("Backward slice from line", min_value=0, value=0, key="slice")
            if crit:
                sl = pdg[fn].slice_lines(int(crit))
                st.info(f"Program slice (lines affecting L{crit}): {sl}")
        else:
            st.info("No program dependence graph was produced — the source may have failed to parse.")

    # ---- Call Graph ----
    with tabs[5]:
        cg = r.get("call_graph_object")
        summ = r.get("call_graph_summary", {})
        if cg:
            g1, g2, g3 = st.columns(3)
            g1.metric("Functions", len(summ.get("defined_functions", [])))
            g2.metric("Call edges", summ.get("edges", 0))
            g3.metric("Recursion", len(summ.get("direct_recursion", []))
                      + len(summ.get("mutual_recursion", [])))
            render_graphviz(cg.to_dot())
            with st.expander("Fan-in / Fan-out (coupling)"):
                st.json({"fan_in": summ.get("fan_in"), "fan_out": summ.get("fan_out")})
        elif summ.get("interprocedural_edges"):
            st.json(summ["interprocedural_edges"])
        else:
            st.info("No calls detected.")

    # ---- Metrics ----
    with tabs[6]:
        met = r["metrics"]
        if met.get("halstead"):
            h = met["halstead"]
            mc1, mc2, mc3, mc4 = st.columns(4)
            mc1.metric("Cyclomatic", met["cyclomatic_complexity"])
            mc2.metric("Halstead Vol", f"{h['volume']:.0f}")
            mc3.metric("Difficulty", f"{h['difficulty']:.1f}")
            mc4.metric("Est. Bugs", f"{h['estimated_bugs']:.3f}")
            st.markdown("**LOC breakdown**")
            loc_df = pd.DataFrame([met["loc"]]).T.reset_index()
            loc_df.columns = ["Type", "Lines"]
            fig = px.pie(loc_df[loc_df.Type != "total"], names="Type", values="Lines",
                         template="plotly_dark", hole=0.5)
            fig.update_layout(height=260, paper_bgcolor="rgba(0,0,0,0)",
                              margin=dict(t=10, b=10))
            st.plotly_chart(fig, width="stretch")
            if met.get("per_function_complexity"):
                cc_df = pd.DataFrame(list(met["per_function_complexity"].items()),
                                     columns=["Function", "Complexity"])
                figc = px.bar(cc_df, x="Function", y="Complexity", template="plotly_dark",
                              color="Complexity", color_continuous_scale="reds")
                figc.add_hline(y=10, line_dash="dash", line_color="#ef4444",
                               annotation_text="McCabe threshold")
                figc.update_layout(height=280, paper_bgcolor="rgba(0,0,0,0)")
                st.plotly_chart(figc, width="stretch")
        cp = r.get("constant_propagation", {})
        if cp.get("total_constants"):
            st.markdown(f"**Constant propagation** — {cp['total_constants']} "
                        "provably-constant variable(s) folded:")
            st.json(cp["constant_variables"])
        st.json(met)

    # ---- XAI ----
    with tabs[7]:
        st.caption("The LLM explains verified bugs pedagogically — it performs NO detection.")
        explained = [f for f in findings if f.get("xai")]
        if not explained:
            st.info("No findings to explain.")
        for f in explained:
            x = f["xai"]
            with st.expander(f"[{f.get('severity')}] L{f.get('line')} · {f.get('message')[:60]}"):
                st.markdown(f"**🔍 Root Cause:** {x.get('root_cause')}")
                st.markdown(f"**📚 Explanation:** {x.get('education')}")
                st.markdown(f"**🔧 Fix:** {x.get('fix_suggestion')}")
                if x.get("secure_example"):
                    st.markdown("**✅ Secure Example:**")
                    st.code(x["secure_example"])
                st.caption(f"explained by: {x.get('explained_by')}")

    # ---- Latency ----
    with tabs[8]:
        lat = r["latency"]
        stages = {k: v for k, v in lat.items() if k not in ("total", "static_only")}
        lat_df = pd.DataFrame(list(stages.items()), columns=["Stage", "Seconds"])
        fig = px.bar(lat_df, x="Seconds", y="Stage", orientation="h",
                     template="plotly_dark", color="Seconds", color_continuous_scale="blues")
        fig.update_layout(height=360, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, width="stretch")
        lc1, lc2 = st.columns(2)
        lc1.metric("Total", f"{lat['total']*1000:.1f} ms")
        lc2.metric("Static-only (no LLM)", f"{lat.get('static_only', lat['total'])*1000:.1f} ms")

    # ---- Export ----
    with tabs[9]:
        report = build_full_report(r)
        e1, e2, e3, e4, e5 = st.columns(5)
        e1.download_button("📄 JSON", to_json_report(report), "nexus_report.json",
                           "application/json", width="stretch")
        e2.download_button("📊 CSV", to_csv_report(findings), "nexus_findings.csv",
                           "text/csv", width="stretch")
        e3.download_button("🛡 SARIF 2.1.0", to_sarif_json(findings, "input.py"),
                           "nexus.sarif", "application/json", width="stretch")
        e4.download_button("🌐 HTML", to_html_report(r, "input"),
                           "nexus_report.html", "text/html", width="stretch")
        try:
            hist = db_manager.scan_history(20)
            e5.download_button("🗃 History", pd.DataFrame(hist).to_csv(index=False),
                               "scan_history.csv", "text/csv", width="stretch")
        except Exception:
            pass
        st.caption("Every finding carries a CWE, an OWASP Top-10 (2021) category, "
                   "and a confidence score. SARIF is GitHub Code Scanning compatible.")
        st.markdown("**Full report preview**")
        st.json(report)
