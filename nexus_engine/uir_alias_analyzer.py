"""
Universal Alias Analyzer
========================
Flow-insensitive, intraprocedural alias analysis over the Universal IR,
using the same Union--Find (disjoint-set) formulation as the Python-side
:mod:`nexus_engine.alias_analyzer`.

An alias is created by a *reference copy*: a statement whose right-hand side
is a bare variable or a field path and whose left-hand side is a variable.
In C/C++ this additionally covers pointer copies (``p = q``) and
address-of bindings (``p = &q``); in Java and JavaScript it covers object
reference assignment, which is the default assignment semantics for
non-primitives.

Alias information *widens* taint propagation: if ``a`` is tainted and
``b = a``, then ``b`` is tainted too, and a sink reached through ``b`` is
still reported.

The class deliberately exposes the same public surface as the Python
``AliasAnalyzer`` (``aliases_of``, ``alias_sets``, ``result``) so the shared
taint engine can consume either implementation interchangeably.
"""

from __future__ import annotations

from .alias_analyzer import UnionFind
from .universal_ir import UProgram, UStmt, _flatten


class UIRAliasAnalyzer:
    """Union--Find alias analysis over UIR functions."""

    def __init__(self):
        self.uf = UnionFind()
        self.pairs: list[dict] = []

    def _key(self, scope: str, name: str) -> str:
        return f"{scope}::{name}"

    # ------------------------------------------------------------------
    def analyze(self, program: UProgram) -> "UIRAliasAnalyzer":
        for fn in program.functions:
            self._scan(fn.name, fn.body)
        if program.toplevel:
            self._scan("<module>", program.toplevel)
        return self

    def _scan(self, scope: str, body: list):
        for st in _flatten(body):
            self._stmt(scope, st)

    def _stmt(self, scope: str, st: UStmt):
        """
        A reference copy is a statement that defines exactly one variable and
        whose only use is a single variable, with no call performing a
        transformation in between (``b = a``, ``p = &q``, ``String s = t``).
        """
        if st.kind not in {"assign", "decl", "simple"}:
            return
        if len(st.defs) != 1 or len(st.uses) != 1 or st.calls:
            return
        dst = next(iter(st.defs))
        src = next(iter(st.uses))
        if dst == src:
            return
        self.uf.union(self._key(scope, src), self._key(scope, dst))
        self.pairs.append({"target": dst, "source": src,
                           "lineno": st.lineno, "scope": scope})

    # ------------------------------------------------------------------
    def alias_sets(self) -> list[list[str]]:
        groups: dict[str, set] = {}
        for key in self.uf.parent:
            groups.setdefault(self.uf.find(key), set()).add(key)
        return [sorted(g) for g in groups.values() if len(g) > 1]

    def aliases_of(self, scope: str, name: str) -> set[str]:
        key = self._key(scope, name)
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


def analyze_uir_aliases(program: UProgram) -> UIRAliasAnalyzer:
    return UIRAliasAnalyzer().analyze(program)
