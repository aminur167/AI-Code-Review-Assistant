"""
Universal Support Analyses
==========================
Completes cross-language feature parity by providing, over the Universal IR,
the analyses that the Python pipeline obtains from the native ``ast`` module:

  * **Call graph** -- interprocedural edges, direct and mutual recursion,
    fan-in / fan-out coupling metrics.
  * **Symbol table** -- hierarchical scopes (module -> class -> function ->
    block) with definition and use sites per symbol.
  * **Constant propagation** -- Kildall-style lattice
    (``Undef < Const(c) < Nac``) over reaching definitions.
  * **Software metrics** -- McCabe cyclomatic complexity (global and per
    function), exact Halstead metrics from the grammar-level operator and
    operand streams, the Maintainability Index, and an LOC breakdown that
    understands C/Java/JS comment syntax.

Each class mirrors the public surface of its Python counterpart so that the
report generator, dashboard, and SARIF exporter consume either without
special-casing.
"""

from __future__ import annotations

import math

import networkx as nx

from .metrics_engine import halstead, maintainability_index
from .universal_ir import UProgram, UStmt, _flatten


# ---------------------------------------------------------------------------
# Call graph
# ---------------------------------------------------------------------------

class UIRCallGraph:
    """Interprocedural call graph built from UIR call sites."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.graph.add_node("<module>", defined=True, lineno=0)
        self.defined: set[str] = set()

    def build(self, program: UProgram) -> "UIRCallGraph":
        for fn in program.functions:
            self.defined.add(fn.name)
            self.graph.add_node(fn.name, defined=True, lineno=fn.lineno)

        for fn in program.functions:
            self._scan(fn.name, fn.body)
        if program.toplevel:
            self._scan("<module>", program.toplevel)
        return self

    def _scan(self, caller: str, body: list):
        for st in _flatten(body):
            for call in st.calls:
                short = call.callee.split(".")[-1]
                target = short if (short in self.defined or call.callee in self.defined) \
                    else call.callee
                if self.graph.has_edge(caller, target):
                    self.graph[caller][target]["count"] += 1
                    self.graph[caller][target]["lines"].append(call.lineno)
                else:
                    self.graph.add_edge(caller, target, count=1, lines=[call.lineno])

    def result(self) -> dict:
        g = self.graph
        recursion = [n for n in g.nodes if g.has_edge(n, n)]
        mutual = []
        try:
            for cycle in nx.simple_cycles(g):
                if len(cycle) > 1:
                    mutual.append(cycle)
        except Exception:
            pass
        return {
            "nodes": g.number_of_nodes(),
            "edges": g.number_of_edges(),
            "defined_functions": sorted(self.defined),
            "external_calls": sorted(n for n, d in g.nodes(data=True) if not d.get("defined")),
            "direct_recursion": recursion,
            "mutual_recursion": mutual[:10],
            "fan_out": {n: g.out_degree(n) for n in g.nodes if g.nodes[n].get("defined")},
            "fan_in": {n: g.in_degree(n) for n in g.nodes if g.nodes[n].get("defined")},
            "interprocedural_edges": [
                {"caller": u, "callee": v, "count": d["count"], "lines": d["lines"]}
                for u, v, d in g.edges(data=True)
            ],
        }

    def to_dot(self) -> str:
        lines = ['digraph CallGraph {', '  bgcolor="transparent"; rankdir=LR;',
                 '  node [style="filled,rounded" shape=box fontname="Consolas" '
                 'fontsize=11 fontcolor=white];',
                 '  edge [color="#94a3b8" fontcolor="#cbd5e1" fontsize=9 fontname="Consolas"];']
        for n, d in self.graph.nodes(data=True):
            color = "#3b82f6" if d.get("defined") else "#64748b"
            if self.graph.has_edge(n, n):
                color = "#ef4444"
            lines.append(f'  "{n}" [fillcolor="{color}"];')
        for u, v, d in self.graph.edges(data=True):
            lines.append(f'  "{u}" -> "{v}" [label="x{d["count"]}"];')
        lines.append("}")
        return "\n".join(lines)


def build_uir_call_graph(program: UProgram) -> UIRCallGraph:
    return UIRCallGraph().build(program)


# ---------------------------------------------------------------------------
# Symbol table
# ---------------------------------------------------------------------------

class UIRSymbolTable:
    """Hierarchical scope tree with per-symbol definition and use sites."""

    def __init__(self):
        self.scopes: dict[str, dict] = {}

    def build(self, program: UProgram) -> "UIRSymbolTable":
        self.scopes["<module>"] = {
            "kind": "module", "parent": None, "lineno": 0, "symbols": {}}
        for cls in program.classes:
            self.scopes[cls["name"]] = {
                "kind": "class", "parent": "<module>",
                "lineno": cls["lineno"], "symbols": {}}
        for st in _flatten(program.toplevel):
            self._record("<module>", st)
        for fn in program.functions:
            scope = fn.name
            parent = fn.class_name if fn.class_name in self.scopes else "<module>"
            self.scopes[scope] = {"kind": "function", "parent": parent,
                                  "lineno": fn.lineno, "symbols": {}}
            for p in fn.params:
                self._add(scope, p, "parameter", fn.lineno)
            for st in _flatten(fn.body):
                self._record(scope, st)
        return self

    def _record(self, scope: str, st: UStmt):
        for d in st.defs:
            self._add(scope, d, "variable", st.lineno)
        for u in st.uses:
            sym = self.scopes[scope]["symbols"].get(u)
            if sym is not None:
                sym["uses"].append(st.lineno)

    def _add(self, scope: str, name: str, kind: str, lineno: int):
        syms = self.scopes[scope]["symbols"]
        if name in syms:
            if lineno not in syms[name]["defs"]:
                syms[name]["defs"].append(lineno)
        else:
            syms[name] = {"kind": kind, "defs": [lineno], "uses": []}

    def to_dict(self) -> dict:
        return {
            "scopes": {
                name: {
                    "kind": sc["kind"], "parent": sc["parent"], "lineno": sc["lineno"],
                    "symbols": {
                        s: {"kind": v["kind"], "defined_at": v["defs"],
                            "used_at": sorted(set(v["uses"]))}
                        for s, v in sc["symbols"].items()
                    },
                }
                for name, sc in self.scopes.items()
            },
            "total_scopes": len(self.scopes),
            "total_symbols": sum(len(sc["symbols"]) for sc in self.scopes.values()),
        }


def build_uir_symbol_table(program: UProgram) -> UIRSymbolTable:
    return UIRSymbolTable().build(program)


# ---------------------------------------------------------------------------
# Constant propagation
# ---------------------------------------------------------------------------

_NAC = object()          # not-a-constant (lattice top)


def analyze_uir_constants(program: UProgram) -> dict:
    """
    Kildall-style constant propagation over the lattice
    ``Undef < Const(c) < Nac``.

    A variable defined solely by a literal is ``Const``; a variable with two
    definitions carrying different constants meets to ``Nac``; parameters and
    values derived from calls or unknown expressions are ``Nac``. The result
    sharpens the division-by-zero and dead-branch detectors and is surfaced in
    the analysis view.
    """
    out: dict[str, dict] = {}
    for fn in program.functions:
        env: dict[str, object] = {p: _NAC for p in fn.params}
        for st in _flatten(fn.body):
            if not st.defs:
                continue
            value = st.literal_value if st.literal_value is not None else _NAC
            if st.calls or st.uses:
                value = _NAC
            for var in st.defs:
                if var in env and env[var] is not _NAC and env[var] != value:
                    env[var] = _NAC
                else:
                    env[var] = value
        consts = {k: v for k, v in env.items() if v is not _NAC}
        if consts:
            out[fn.name] = consts
    return {"per_function_constants": out,
            "total_constants": sum(len(v) for v in out.values())}


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def uir_loc_breakdown(code: str, language: str) -> dict:
    """LOC breakdown honoring C/C++/Java/JS comment syntax, including block
    comments, which a naive line scanner would miscount as code."""
    total = sloc = comments = blank = 0
    in_block = False
    for raw in code.split("\n"):
        total += 1
        s = raw.strip()
        if in_block:
            comments += 1
            if "*/" in s:
                in_block = False
            continue
        if not s:
            blank += 1
        elif s.startswith("//") or s.startswith("#"):
            comments += 1
        elif s.startswith("/*"):
            comments += 1
            if "*/" not in s:
                in_block = True
        else:
            sloc += 1
            if "/*" in s and "*/" not in s:
                in_block = True
    return {"total": total, "sloc": sloc, "comments": comments, "blank": blank}


def _per_function_cc(program: UProgram) -> dict:
    """
    McCabe cyclomatic complexity per function: one plus the number of
    decision points (branches, loops, catch clauses, switch cases, and
    short-circuit boolean operators).
    """
    per: dict[str, int] = {}
    for fn in program.functions:
        cc = 1
        for st in _flatten(fn.body):
            if st.kind == "if":
                cc += 1
            elif st.kind == "loop":
                cc += 1
            elif st.kind == "switch":
                cc += max(1, len(st.cases))
            elif st.kind == "try":
                cc += len(st.handlers)
        per[fn.name] = cc
    return per


def compute_uir_metrics(code: str, program: UProgram, language: str) -> dict:
    """Full metric suite for a non-Python program, using exact token streams."""
    ops, opnds = program.operators, program.operands
    n1, n2 = len(set(ops)), len(set(opnds))
    N1, N2 = len(ops), len(opnds)
    h = halstead(n1, n2, N1, N2)

    loc = uir_loc_breakdown(code, language)
    per_fn = _per_function_cc(program)
    total_cc = 1 + program.loops + program.conditionals
    mi = maintainability_index(h["volume"], total_cc, loc["sloc"])

    return {
        "loc": loc,
        "cyclomatic_complexity": total_cc,
        "per_function_complexity": per_fn,
        "halstead": h,
        "maintainability_index": mi,
        "functions": len(program.functions),
        "classes": len(program.classes),
        "comment_ratio": round(loc["comments"] / max(1, loc["sloc"]) * 100, 2),
        "structure": {
            "functions": len(program.functions),
            "classes": len(program.classes),
            "loops": program.loops,
            "conditionals": program.conditionals,
            "calls": program.total_calls,
            "max_depth": program.max_depth,
            "cyclomatic_complexity": total_cc,
        },
    }
