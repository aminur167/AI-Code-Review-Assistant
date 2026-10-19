"""
Plugin-based Static Rule Engine
===============================
Deterministic, mathematical detection — NO AI, NO hallucination.

Every rule is a plugin (subclass of RulePlugin) registered automatically.
Rules receive an AnalysisContext holding every artifact produced by the
static pipeline (AST, CFG, DFG, SSA, PDG, call graph, aliases, taint,
metrics) and return normalized findings.

Finding schema:
    {rule_id, cwe, severity, line, message, category, evidence, fix_hint}
"""

import ast
from dataclasses import dataclass, field

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class AnalysisContext:
    code: str
    tree: ast.AST
    ast_analyzer: object = None
    symbol_table: object = None
    cfgs: dict = field(default_factory=dict)
    dfg: dict = field(default_factory=dict)
    ssa: dict = field(default_factory=dict)
    pdg: dict = field(default_factory=dict)
    call_graph: object = None
    aliases: object = None
    taint_findings: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    @property
    def lines(self):
        return self.code.split("\n")


class RulePlugin:
    """Base class. Subclasses are auto-registered."""
    rule_id = "NEXUS-000"
    cwe = "CWE-Unknown"
    severity = "MEDIUM"
    category = "quality"          # security | logic | quality
    description = ""

    registry: list = []

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        if cls not in RulePlugin.registry:
            RulePlugin.registry.append(cls)

    def check(self, ctx: AnalysisContext) -> list[dict]:
        raise NotImplementedError

    def finding(self, line, message, evidence="", fix_hint="", severity=None, cwe=None):
        return {
            "rule_id": self.rule_id,
            "cwe": cwe or self.cwe,
            "severity": severity or self.severity,
            "category": self.category,
            "line": line,
            "message": message,
            "evidence": evidence,
            "fix_hint": fix_hint,
        }


class RuleEngine:
    def __init__(self):
        # import rule modules so plugins register themselves
        from .rules import security_rules, logic_rules, quality_rules  # noqa: F401
        self.plugins = [cls() for cls in RulePlugin.registry]

    def run(self, ctx: AnalysisContext) -> list[dict]:
        findings = []
        for plugin in self.plugins:
            try:
                findings.extend(plugin.check(ctx))
            except Exception as e:
                findings.append({
                    "rule_id": plugin.rule_id, "cwe": "N/A", "severity": "INFO",
                    "category": "engine", "line": 0,
                    "message": f"rule crashed: {e}", "evidence": "", "fix_hint": "",
                })
        # sort by severity first so the strongest finding on a line wins dedup
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["line"]))
        # deduplicate exact repeats AND overlapping (line, cwe) reports:
        # a proven taint flow and a pattern rule on the same line+CWE are one bug.
        seen_exact, seen_loc, out = set(), set(), []
        for f in findings:
            exact = (f["rule_id"], f["line"], f["message"][:40])
            loc = (f["line"], f["cwe"])
            if exact in seen_exact:
                continue
            if loc in seen_loc and f["line"] > 0 and f["cwe"] not in ("CWE-Unknown", "N/A"):
                continue          # same vulnerability already reported on this line
            seen_exact.add(exact)
            seen_loc.add(loc)
            out.append(f)
        out.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["line"]))
        for i, f in enumerate(out, 1):
            f["id"] = f"BUG-{i:03d}"
        return out

    def rule_catalog(self) -> list[dict]:
        return [{"rule_id": p.rule_id, "cwe": p.cwe, "severity": p.severity,
                 "category": p.category, "description": p.description}
                for p in self.plugins]
