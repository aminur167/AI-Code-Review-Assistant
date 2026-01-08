"""
Quality Rule Plugins
====================
Maintainability detectors backed by DFG liveness facts and metrics.
"""

from ..rule_engine import RulePlugin


class UnusedVariableRule(RulePlugin):
    rule_id = "QUA-UNUSED"
    cwe = "CWE-563"
    severity = "LOW"
    category = "quality"
    description = "Variable defined but never used (from def-use chains)"

    def check(self, ctx):
        out = []
        reported = set()
        for fname, dfg in ctx.dfg.items():
            for var, lineno in dfg.unused_variables:
                if var in reported or var in ("self", "cls"):
                    continue
                # skip names that are functions/classes at module level
                if fname == "<module>" and ctx.ast_analyzer and (
                        var in {f.name for f in ctx.ast_analyzer.functions} or
                        var in {c.name for c in ctx.ast_analyzer.classes}):
                    continue
                reported.add(var)
                out.append(self.finding(
                    lineno,
                    f"Variable '{var}' is assigned but never used (scope: {fname})",
                    evidence=f"{var} = ...  # L{lineno}",
                    fix_hint=f"Remove '{var}' or prefix with underscore if intentional."))
        return out


class DeadStoreRule(RulePlugin):
    rule_id = "QUA-DEADSTORE"
    cwe = "CWE-563"
    severity = "LOW"
    category = "quality"
    description = "Assignment overwritten before any read (live-variable analysis)"

    def check(self, ctx):
        out = []
        seen = set()
        unused = set()
        for dfg in ctx.dfg.values():
            unused |= {v for v, _ in dfg.unused_variables}
        for fname, dfg in ctx.dfg.items():
            for d in dfg.dead_stores:
                if d.var in unused or (d.var, d.lineno) in seen:
                    continue          # already reported as fully unused
                seen.add((d.var, d.lineno))
                out.append(self.finding(
                    d.lineno,
                    f"Dead store: value of '{d.var}' at L{d.lineno} is never read "
                    f"before being overwritten (scope: {fname})",
                    evidence=f"{d.var} = ...",
                    fix_hint="Delete the redundant assignment."))
        return out


class HighComplexityRule(RulePlugin):
    rule_id = "QUA-COMPLEX"
    cwe = "CWE-1121"
    severity = "MEDIUM"
    category = "quality"
    description = "Cyclomatic complexity above the McCabe threshold (10)"

    def check(self, ctx):
        out = []
        per_func = ctx.metrics.get("per_function_complexity", {})
        for fname, cc in per_func.items():
            if cc > 10:
                lineno = next((f.lineno for f in (ctx.ast_analyzer.functions if ctx.ast_analyzer else [])
                               if f.name == fname), 0)
                out.append(self.finding(
                    lineno,
                    f"Function '{fname}' has cyclomatic complexity {cc} (> 10, McCabe threshold)",
                    evidence=f"CC({fname}) = {cc}",
                    fix_hint="Extract helper functions / simplify branching.",
                    severity="HIGH" if cc > 20 else "MEDIUM"))
        return out


class LowMaintainabilityRule(RulePlugin):
    rule_id = "QUA-MAINT"
    cwe = "CWE-1093"
    severity = "INFO"
    category = "quality"
    description = "Maintainability Index below 65 (Microsoft threshold)"

    def check(self, ctx):
        mi = ctx.metrics.get("maintainability_index")
        if mi is not None and mi < 65:
            return [self.finding(
                0, f"Maintainability Index is {mi} (< 65) — code is hard to maintain",
                evidence=f"MI = {mi}",
                fix_hint="Reduce complexity and function length; add cohesion.")]
        return []
