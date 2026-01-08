"""
Software Metrics Engine
=======================
Mathematically exact implementations of the classical software metrics:

  - McCabe Cyclomatic Complexity (1976): CC = D + 1 (decision points),
    computed globally and per function.
  - Halstead metrics (1977): from REAL operator/operand streams extracted
    by the ASTAnalyzer (n1, n2, N1, N2 -> vocabulary, length, volume,
    difficulty, effort, time, delivered-bug estimate).
  - Maintainability Index (Oman & Hagemeister, Microsoft variant):
        MI = max(0, (171 - 5.2 ln(V) - 0.23 CC - 16.2 ln(LOC)) * 100/171)
  - LOC breakdown: physical, logical (SLOC), comments, blank.
"""

import ast
import math


class _CCVisitor(ast.NodeVisitor):
    """Per-function cyclomatic complexity."""

    def __init__(self):
        self.per_function = {}
        self.total = 1
        self._stack = []

    def _bump(self, n=1):
        self.total += n
        if self._stack:
            self.per_function[self._stack[-1]] += n

    def _visit_func(self, node):
        self.per_function[node.name] = 1
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def visit_If(self, node):
        self._bump(); self.generic_visit(node)

    def visit_For(self, node):
        self._bump(); self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self._bump(); self.generic_visit(node)

    def visit_Try(self, node):
        self._bump(len(node.handlers)); self.generic_visit(node)

    def visit_BoolOp(self, node):
        self._bump(len(node.values) - 1); self.generic_visit(node)

    def visit_IfExp(self, node):
        self._bump(); self.generic_visit(node)

    def visit_Assert(self, node):
        self._bump(); self.generic_visit(node)

    def _visit_comp(self, node):
        self._bump(len(node.generators)); self.generic_visit(node)

    visit_ListComp = _visit_comp
    visit_SetComp = _visit_comp
    visit_DictComp = _visit_comp
    visit_GeneratorExp = _visit_comp


def loc_breakdown(code: str) -> dict:
    total = sloc = comments = blank = 0
    for line in code.split("\n"):
        total += 1
        s = line.strip()
        if not s:
            blank += 1
        elif s.startswith("#"):
            comments += 1
        else:
            sloc += 1
    return {"total": total, "sloc": sloc, "comments": comments, "blank": blank}


def halstead(n1, n2, N1, N2) -> dict:
    n = n1 + n2
    N = N1 + N2
    vocabulary = n
    length = N
    volume = N * math.log2(n) if n > 1 else 0.0
    difficulty = (n1 / 2) * (N2 / n2) if n2 > 0 else 0.0
    effort = difficulty * volume
    time_s = effort / 18                     # Stroud number
    bugs = volume / 3000                     # Halstead delivered-bug estimate
    return {
        "n1_distinct_operators": n1, "n2_distinct_operands": n2,
        "N1_total_operators": N1, "N2_total_operands": N2,
        "vocabulary": vocabulary, "length": length,
        "volume": round(volume, 2), "difficulty": round(difficulty, 2),
        "effort": round(effort, 2), "time_seconds": round(time_s, 2),
        "estimated_bugs": round(bugs, 4),
    }


def maintainability_index(volume: float, cc: int, sloc: int) -> float:
    if sloc <= 0:
        return 100.0
    mi = (171 - 5.2 * math.log(max(1.0, volume))
          - 0.23 * cc - 16.2 * math.log(max(1, sloc))) * 100 / 171
    return round(max(0.0, min(100.0, mi)), 2)


def compute_metrics(code: str, tree: ast.AST, ast_analyzer) -> dict:
    cc = _CCVisitor()
    cc.visit(tree)
    n1, n2, N1, N2 = ast_analyzer.halstead_counts()
    h = halstead(n1, n2, N1, N2)
    loc = loc_breakdown(code)
    mi = maintainability_index(h["volume"], cc.total, loc["sloc"])
    return {
        "loc": loc,
        "cyclomatic_complexity": cc.total,
        "per_function_complexity": cc.per_function,
        "halstead": h,
        "maintainability_index": mi,
        "functions": len(ast_analyzer.functions),
        "classes": len(ast_analyzer.classes),
        "comment_ratio": round(loc["comments"] / max(1, loc["sloc"]) * 100, 2),
    }
