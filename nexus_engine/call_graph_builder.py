"""
Call Graph Builder
==================
Real interprocedural call graph with caller/callee attribution, recursion
detection (direct + mutual via cycle detection), and fan-in / fan-out
metrics for coupling analysis.
"""

import ast
import networkx as nx

from .ast_analyzer import dotted_name


class CallGraphBuilder(ast.NodeVisitor):
    def __init__(self):
        self.graph = nx.DiGraph()
        self.graph.add_node("<module>", defined=True, lineno=0)
        self._scope = ["<module>"]
        self.defined: set[str] = set()

    def _visit_func(self, node):
        name = node.name
        self.defined.add(name)
        self.graph.add_node(name, defined=True, lineno=node.lineno)
        self._scope.append(name)
        self.generic_visit(node)
        self._scope.pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def visit_Call(self, node):
        callee = dotted_name(node.func)
        short = callee.split(".")[-1]
        target = short if short in self.defined or callee in self.defined else callee
        caller = self._scope[-1]
        if self.graph.has_edge(caller, target):
            self.graph[caller][target]["count"] += 1
            self.graph[caller][target]["lines"].append(node.lineno)
        else:
            self.graph.add_edge(caller, target, count=1, lines=[node.lineno])
        self.generic_visit(node)

    # ---------- analysis ----------
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
                 '  node [style="filled,rounded" shape=box fontname="Consolas" fontsize=11 fontcolor=white];',
                 '  edge [color="#94a3b8" fontcolor="#cbd5e1" fontsize=9 fontname="Consolas"];']
        for n, d in self.graph.nodes(data=True):
            color = "#3b82f6" if d.get("defined") else "#64748b"
            if self.graph.has_edge(n, n):
                color = "#ef4444"       # recursive
            lines.append(f'  "{n}" [fillcolor="{color}"];')
        for u, v, d in self.graph.edges(data=True):
            lines.append(f'  "{u}" -> "{v}" [label="x{d["count"]}"];')
        lines.append("}")
        return "\n".join(lines)


def build_call_graph(tree: ast.AST) -> CallGraphBuilder:
    b = CallGraphBuilder()
    # pre-pass: register every defined function first so calls resolve
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            b.defined.add(node.name)
    b.visit(tree)
    return b
