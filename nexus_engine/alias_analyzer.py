"""
Alias Analyzer
==============
Flow-insensitive intraprocedural alias analysis using Union-Find
(disjoint sets).

Detects:
  - Reference aliasing:  `b = a` where `a` is a mutable object / any name
  - Object aliasing:     `b = a` then both mutate the same object
  - Attribute aliasing:  `self.x = y` style reference sharing (tracked as
                          pseudo-names "self.x")

Alias information widens the taint analysis: if `a` is tainted and
`b = a`, then `b` is tainted too.
"""

import ast
from .ast_analyzer import dotted_name


class UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]   # path compression
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


class AliasAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.uf = UnionFind()
        self.pairs = []            # (target, source, lineno, scope)
        self._scope = ["<module>"]

    def _key(self, name):
        return f"{self._scope[-1]}::{name}"

    def _visit_func(self, node):
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    @staticmethod
    def _ref_name(node):
        """Return a name for reference-copy RHS (plain name or attribute chain)."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return dotted_name(node)
        return None

    def visit_Assign(self, node):
        src = self._ref_name(node.value)
        if src is not None:
            for t in node.targets:
                dst = self._ref_name(t)
                if dst is not None:
                    self.uf.union(self._key(src), self._key(dst))
                    self.pairs.append({"target": dst, "source": src,
                                       "lineno": node.lineno, "scope": self._scope[-1]})
        self.generic_visit(node)

    def alias_sets(self) -> list[list[str]]:
        groups = {}
        for key in self.uf.parent:
            groups.setdefault(self.uf.find(key), set()).add(key)
        return [sorted(g) for g in groups.values() if len(g) > 1]

    def aliases_of(self, scope: str, name: str) -> set[str]:
        """All names aliasing `name` inside `scope` (bare names, scope stripped)."""
        key = f"{scope}::{name}"
        if key not in self.uf.parent:
            return set()
        root = self.uf.find(key)
        out = set()
        for k in self.uf.parent:
            if self.uf.find(k) == root:
                s, _, n = k.partition("::")
                if s == scope:
                    out.add(n)
        return out

    def result(self) -> dict:
        return {
            "alias_pairs": self.pairs,
            "alias_sets": self.alias_sets(),
            "total_alias_groups": len(self.alias_sets()),
        }


def analyze_aliases(tree: ast.AST) -> AliasAnalyzer:
    a = AliasAnalyzer()
    a.visit(tree)
    return a
