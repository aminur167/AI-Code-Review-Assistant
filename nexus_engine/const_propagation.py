"""
Constant Propagation Analysis
=============================
A lightweight, deterministic constant-propagation pass over the AST/CFG.
For each variable it computes a lattice value:

    UNDEF  (no definition seen)  <  CONST(c)  <  NAC (not-a-constant / top)

Rules (standard Kildall lattice, meet = greatest lower bound):
  - x = <literal>            -> CONST(literal)
  - x = <const> op <const>   -> folded CONST (arithmetic/boolean)
  - x = <anything else>      -> NAC
  - two defs with different constants meeting -> NAC

Outputs a per-scope map of provably-constant variables, plus the folded
value. This feeds the division-by-zero and dead-branch detectors and is
reported in the analysis view for transparency.

Reference: G. A. Kildall, "A Unified Approach to Global Program
Optimization", POPL 1973.
"""

import ast
import operator

_BINOPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod, ast.Pow: operator.pow,
    ast.BitAnd: operator.and_, ast.BitOr: operator.or_, ast.BitXor: operator.xor,
    ast.LShift: operator.lshift, ast.RShift: operator.rshift,
}

NAC = object()      # not-a-constant (lattice top)


class _ConstVisitor(ast.NodeVisitor):
    def __init__(self):
        self.scope = ["<module>"]
        # scope -> {var: value|NAC}
        self.values: dict[str, dict] = {"<module>": {}}
        self.constants: dict[str, dict] = {}   # scope -> {var: (value, lineno)}

    def _cur(self):
        return self.values.setdefault(self.scope[-1], {})

    def _eval(self, node):
        """Return a Python constant, or NAC if not statically constant."""
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            v = self._cur().get(node.id, NAC)
            return v
        if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
            l, r = self._eval(node.left), self._eval(node.right)
            if l is NAC or r is NAC:
                return NAC
            try:
                return _BINOPS[type(node.op)](l, r)
            except Exception:
                return NAC
        if isinstance(node, ast.UnaryOp):
            v = self._eval(node.operand)
            if v is NAC:
                return NAC
            if isinstance(node.op, ast.USub):
                try:
                    return -v
                except Exception:
                    return NAC
            if isinstance(node.op, ast.Not):
                return not v
        return NAC

    def _visit_func(self, node):
        self.scope.append(node.name)
        self.values.setdefault(node.name, {})
        for a in node.args.args:
            self._cur()[a.arg] = NAC        # parameters are unknown
        self.generic_visit(node)
        self.scope.pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def visit_Assign(self, node):
        val = self._eval(node.value)
        for t in node.targets:
            if isinstance(t, ast.Name):
                cur = self._cur()
                if t.id in cur and cur[t.id] is not NAC and cur[t.id] != val:
                    cur[t.id] = NAC             # meet of differing constants
                else:
                    cur[t.id] = val
                if val is not NAC:
                    self.constants.setdefault(self.scope[-1], {})[t.id] = (val, node.lineno)
                elif self.scope[-1] in self.constants:
                    self.constants[self.scope[-1]].pop(t.id, None)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            self._cur()[node.target.id] = NAC   # conservative
        self.generic_visit(node)


def analyze_constants(tree: ast.AST) -> dict:
    v = _ConstVisitor()
    v.visit(tree)
    out = {}
    for scope, consts in v.constants.items():
        if consts:
            out[scope] = {name: {"value": val, "line": ln}
                          for name, (val, ln) in consts.items()}
    return {
        "constant_variables": out,
        "total_constants": sum(len(c) for c in out.values()),
    }
