"""
NexusReview Neuro-Symbolic Pipeline
===================================
Orchestrates the exact research architecture:

    Source Code
        -> Language Parser        (ast / tree-sitter)
        -> AST Generator          (ast_analyzer)
        -> CFG Builder            (basic blocks, true/false/back edges)
        -> DFG Builder            (reaching defs, liveness, def-use)
        -> Call Graph             (+ SSA, PDG, symbol table, aliases)
        -> Rule Engine            (plugin static rules — Symbolic)
        -> Vulnerability Detector (taint analysis — Symbolic)
        -> XAI                    (Groq LLM explanation only — Neuro)
        -> Report Generator       (JSON / CSV / SARIF / DB)

Per-stage wall-clock latency is recorded for the paper's RQ3 (latency).
"""

import time

from .ast_analyzer import analyze_ast
from .symbol_table_builder import build_symbol_table
from .cfg_builder import build_cfgs
from .dfg_analyzer import analyze_dfg
from .ssa_transformer import transform_ssa
from .call_graph_builder import build_call_graph
from .pdg_builder import build_pdgs
from .alias_analyzer import analyze_aliases
from .taint_analyzer import analyze_taint
from .rule_engine import RuleEngine, AnalysisContext, SEVERITY_ORDER
from .metrics_engine import compute_metrics
from .xai_explainer import explain_findings
from .cwe_owasp_map import enrich as enrich_findings
from .const_propagation import analyze_constants
from .report_generator import quality_score, severity_stats

# --- Universal (multi-language) deep-analysis stack -------------------------
from .universal_ir import lower_to_uir
from .uir_cfg_builder import build_uir_cfgs
from .uir_alias_analyzer import analyze_uir_aliases
from .uir_taint_analyzer import analyze_uir_taint
from .uir_analyses import (build_uir_call_graph, build_uir_symbol_table,
                           analyze_uir_constants, compute_uir_metrics)
from .uir_rules import run_uir_rules


def _taint_to_findings(taint: list) -> list:
    """Convert verified taint flows into normalized rule-engine findings."""
    out = []
    for t in taint:
        trace = " -> ".join(t.get("taint_trace", [])[:6])
        out.append({
            "rule_id": "UNI-TAINT",
            "cwe": t["cwe"],
            "severity": t["severity"],
            "category": "security",
            "line": t["line"],
            "message": f"{t['vuln']}: '{t['variable']}' from {t['source']} "
                       f"(L{t['source_line']}) reaches sink {t['sink']}",
            "evidence": trace,
            "fix_hint": "Validate, encode, or parameterize the value before it "
                        "reaches the sink.",
            "interprocedural": t.get("interprocedural", False),
            "taint_trace": t.get("taint_trace", []),
        })
    return out


def _dfg_to_findings(dfg: dict) -> list:
    """
    Surface data-flow defects that the DFG has already proven.

    A *dead store* is a definition that no execution path reads before the
    variable is redefined or leaves scope (CWE-563), read directly out of the
    liveness fixed point computed in stage 3.

    These are reported in the ``quality`` category rather than ``logic``.
    Without field-sensitive and pointer-sensitive modelling, a store performed
    through an alias or a pointer parameter can appear dead when a later read
    genuinely observes it, and the C and C++ idiom of initializing a variable
    before a conditional overwrite makes that pattern common. Ranking these
    below the proven security findings keeps them available to a reviewer
    without letting an imprecise analysis inflate the security results.
    """
    out = []
    for func, res in dfg.items():
        for d in res.dead_stores:
            if d.lineno <= 0:
                continue
            out.append({
                "rule_id": "UNI-DEADSTORE",
                "cwe": "CWE-563",
                "severity": "LOW",
                "category": "quality",
                "line": d.lineno,
                "message": f"Value assigned to '{d.var}' is never read before it "
                           f"is overwritten or leaves scope (dead store)",
                "evidence": f"{func}(): definition of '{d.var}' at line {d.lineno}",
                "fix_hint": "Remove the assignment, or use the value that was stored.",
            })
    return out


def _dedupe(findings: list) -> list:
    """
    One defect must produce exactly one finding.

    Findings are ordered by severity so the strongest report on a line wins,
    then collapsed on (line, CWE): a proven taint flow and a structural rule
    firing on the same line for the same weakness are the same bug.
    """
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["line"]))
    seen_exact, seen_loc, out = set(), set(), []
    for f in findings:
        exact = (f["rule_id"], f["line"], f["message"][:40])
        loc = (f["line"], f["cwe"])
        if exact in seen_exact:
            continue
        if loc in seen_loc and f["line"] > 0 and f["cwe"] not in ("CWE-Unknown", "N/A"):
            continue
        seen_exact.add(exact)
        seen_loc.add(loc)
        out.append(f)
    out.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["line"]))
    for i, f in enumerate(out, 1):
        f["id"] = f"BUG-{i:03d}"
    return out


def _attach_pdg_slices(findings: list, pdgs: dict) -> list:
    """Attach the exact deterministic backward slice for each finding.

    A finding can be explained only from nodes the PDG contains.  When a
    criterion line is not represented (for example a parser recovery node),
    the explicit empty context is retained instead of substituting a nearby
    snippet or inferred trace.
    """
    for finding in findings:
        line = finding.get("line", 0)
        contexts = [pdg.slice_context(line) for pdg in pdgs.values()
                    if line in pdg.slice_lines(line)]
        if contexts:
            finding["pdg_slice"] = contexts[0]
        else:
            finding["pdg_slice"] = {"function": None, "criterion_line": line,
                                    "slice_lines": [], "nodes": [], "edges": []}
    return findings


class NexusPipeline:
    def __init__(self, use_llm_xai: bool = True):
        self.use_llm_xai = use_llm_xai
        self.rule_engine = RuleEngine()

    def run(self, code: str, language: str = "Python") -> dict:
        if language == "Python":
            return self._run_python(code)
        return self._run_multilang(code, language)

    # ------------------------------------------------------------------
    def _run_python(self, code: str) -> dict:
        lat = {}
        t_total = time.perf_counter()

        def tick(key, t0):
            lat[key] = round(time.perf_counter() - t0, 4)

        # 1. Language Parser + AST Generator
        t = time.perf_counter()
        try:
            tree, ast_an = analyze_ast(code)
        except SyntaxError as e:
            return {"error": f"SyntaxError: {e}", "language": "Python",
                    "findings": [], "latency": {"total": 0}}
        symtab = build_symbol_table(tree)
        tick("1_ast_parse", t)

        # 2. CFG Builder
        t = time.perf_counter()
        cfgs = build_cfgs(code, tree)
        tick("2_cfg_build", t)

        # 3. DFG Builder
        t = time.perf_counter()
        dfg = analyze_dfg(cfgs)
        tick("3_dfg_analysis", t)

        # 4. SSA + Dominators
        t = time.perf_counter()
        ssa = transform_ssa(cfgs)
        tick("4_ssa_transform", t)

        # 5. Call Graph + PDG + Aliases
        t = time.perf_counter()
        call_graph = build_call_graph(tree)
        pdg = build_pdgs(cfgs, dfg)
        aliases = analyze_aliases(tree)
        tick("5_callgraph_pdg", t)

        # 6. Metrics + constant propagation
        t = time.perf_counter()
        metrics = compute_metrics(code, tree, ast_an)
        constants = analyze_constants(tree)
        tick("6_metrics", t)

        # 7. Vulnerability Detector — taint analysis
        t = time.perf_counter()
        taint = analyze_taint(cfgs, call_graph, aliases, ast_an)
        tick("7_taint_analysis", t)

        # 8. Rule Engine
        t = time.perf_counter()
        ctx = AnalysisContext(code=code, tree=tree, ast_analyzer=ast_an,
                              symbol_table=symtab, cfgs=cfgs, dfg=dfg, ssa=ssa,
                              pdg=pdg, call_graph=call_graph, aliases=aliases,
                              taint_findings=taint, metrics=metrics)
        findings = self.rule_engine.run(ctx)
        enrich_findings(findings)          # OWASP Top-10 + confidence score
        tick("8_rule_engine", t)

        # 9. XAI (Neuro) — explanation ONLY
        t = time.perf_counter()
        _attach_pdg_slices(findings, pdg)
        findings = explain_findings(findings, code, use_llm=self.use_llm_xai)
        tick("9_xai_explain", t)

        lat["total"] = round(time.perf_counter() - t_total, 4)
        lat["static_only"] = round(lat["total"] - lat["9_xai_explain"], 4)

        return {
            "language": "Python",
            "findings": findings,
            "taint_findings": taint,
            "metrics": metrics,
            "quality_score": quality_score(findings, metrics),
            "severity_stats": severity_stats(findings),
            "latency": lat,
            # graph artifacts for the dashboard
            "cfgs": cfgs,
            "cfg_stats": {name: c.stats() for name, c in cfgs.items()},
            "dfg": {name: d.to_dict() for name, d in dfg.items()},
            "dfg_objects": dfg,
            "ssa": {name: s.to_dict() for name, s in ssa.items()},
            "pdg_objects": pdg,
            "pdg": {name: p.to_dict() for name, p in pdg.items()},
            "call_graph_object": call_graph,
            "call_graph_summary": call_graph.result(),
            "symbol_table": symtab.to_dict(),
            "aliases": aliases.result(),
            "constant_propagation": constants,
            "rule_catalog": self.rule_engine.rule_catalog(),
        }

    # ------------------------------------------------------------------
    def _run_multilang(self, code: str, language: str) -> dict:
        """
        Deep pipeline for C, C++, Java, and JavaScript.

        Source is lowered to the Universal IR and then driven through the
        *same* analysis stages as Python -- CFG, DFG, SSA, PDG, call graph,
        aliases, constant propagation, and interprocedural taint -- so the
        four Tree-sitter languages receive full-depth analysis rather than a
        pattern scan.
        """
        lat = {}
        t_total = time.perf_counter()

        def tick(key, t0):
            lat[key] = round(time.perf_counter() - t0, 4)

        # 1. Language Parser + Universal IR lowering
        t = time.perf_counter()
        program = lower_to_uir(code, language)
        if not program.parse_ok:
            return {"error": program.parse_error or "parse failed",
                    "language": language, "findings": [], "latency": {"total": 0}}
        symtab = build_uir_symbol_table(program)
        tick("1_ast_parse", t)

        # 2. CFG Builder
        t = time.perf_counter()
        cfgs = build_uir_cfgs(program)
        tick("2_cfg_build", t)

        # 3. DFG Builder (reaching definitions + liveness)
        t = time.perf_counter()
        dfg = analyze_dfg(cfgs)
        tick("3_dfg_analysis", t)

        # 4. SSA + dominance frontiers
        t = time.perf_counter()
        ssa = transform_ssa(cfgs)
        tick("4_ssa_transform", t)

        # 5. Call graph + PDG + aliases
        t = time.perf_counter()
        call_graph = build_uir_call_graph(program)
        pdg = build_pdgs(cfgs, dfg)
        aliases = analyze_uir_aliases(program)
        tick("5_callgraph_pdg", t)

        # 6. Metrics + constant propagation
        t = time.perf_counter()
        metrics = compute_uir_metrics(code, program, language)
        constants = analyze_uir_constants(program)
        tick("6_metrics", t)

        # 7. Vulnerability Detector — interprocedural taint analysis
        t = time.perf_counter()
        taint = analyze_uir_taint(cfgs, aliases, program, language)
        tick("7_taint_analysis", t)

        # 8. Rule Engine (taint flows + structural detectors)
        t = time.perf_counter()
        findings = _taint_to_findings(taint)
        findings += run_uir_rules(program, code, language, constants)
        findings += _dfg_to_findings(dfg)
        findings = _dedupe(findings)
        enrich_findings(findings)          # OWASP Top-10 + confidence score
        tick("8_rule_engine", t)

        # 9. XAI (Neuro) — explanation ONLY
        t = time.perf_counter()
        _attach_pdg_slices(findings, pdg)
        findings = explain_findings(findings, code, use_llm=self.use_llm_xai)
        tick("9_xai_explain", t)

        lat["total"] = round(time.perf_counter() - t_total, 4)
        lat["static_only"] = round(lat["total"] - lat["9_xai_explain"], 4)

        return {
            "language": language,
            "findings": findings,
            "taint_findings": taint,
            "metrics": metrics,
            "quality_score": quality_score(findings, metrics),
            "severity_stats": severity_stats(findings),
            "latency": lat,
            # graph artifacts for the dashboard
            "cfgs": cfgs,
            "cfg_stats": {name: c.stats() for name, c in cfgs.items()},
            "dfg": {name: d.to_dict() for name, d in dfg.items()},
            "dfg_objects": dfg,
            "ssa": {name: s.to_dict() for name, s in ssa.items()},
            "pdg_objects": pdg,
            "pdg": {name: p.to_dict() for name, p in pdg.items()},
            "call_graph_object": call_graph,
            "call_graph_summary": call_graph.result(),
            "symbol_table": symtab.to_dict(),
            "aliases": aliases.result(),
            "constant_propagation": constants,
            "ast_status": f"Real {language} Tree-sitter AST → Universal IR "
                          f"({len(program.functions)} functions, "
                          f"{program.error_nodes} parse errors)",
        }
