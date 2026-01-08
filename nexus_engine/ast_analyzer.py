"""
AST Analysis Layer
==================
Deep structural analysis of Python source code using the native `ast` module.

Extracts:
  - Functions, classes, assignments, calls, loops, conditionals
  - Halstead operator/operand streams (distinct + total counts)
  - Literals, variable occurrences, expression statistics

This module performs NO detection. It is the first stage of the
Neuro-Symbolic pipeline: Source Code -> Language Parser -> AST Generator.
"""

import ast
from dataclasses import dataclass, field


@dataclass
class FunctionInfo:
    name: str
    lineno: int
    end_lineno: int
    args: list
    defaults: int
    decorators: list
    is_method: bool
    docstring: str | None
    returns_value: bool = False


@dataclass
class ClassInfo:
    name: str
    lineno: int
    bases: list
    methods: list = field(default_factory=list)


@dataclass
class CallInfo:
    callee: str          # dotted name, e.g. "os.system"
    lineno: int
    scope: str           # enclosing function ("<module>" at top level)
    n_args: int
    keywords: list


def dotted_name(node) -> str:
    """Flatten a call target (Name / Attribute chain) into a dotted string."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(dotted_name(node.func) + "()")
    return ".".join(reversed(parts)) if parts else "<expr>"


class ASTAnalyzer(ast.NodeVisitor):
    """Single-pass structural + Halstead analyzer."""

    def __init__(self):
        self.functions: list[FunctionInfo] = []
        self.classes: list[ClassInfo] = []
        self.calls: list[CallInfo] = []
        self.assignments: list[tuple] = []       # (targets, lineno, value_type)
        self.literals: list[tuple] = []          # (repr, type, lineno)
        self.loops = 0
        self.conditionals = 0
        self.try_blocks = 0
        self.returns = 0
        self.lambdas = 0
        self.comprehensions = 0

        # Halstead streams
        self.operators: dict[str, int] = {}      # distinct operator -> total count
        self.operands: dict[str, int] = {}       # distinct operand  -> total count

        self._scope_stack: list[str] = ["<module>"]
        self._class_stack: list[ClassInfo] = []

    # ---------- helpers ----------
    @property
    def scope(self) -> str:
        return self._scope_stack[-1]

    def _op(self, name: str):
        self.operators[name] = self.operators.get(name, 0) + 1

    def _operand(self, name: str):
        self.operands[str(name)] = self.operands.get(str(name), 0) + 1

    # ---------- structure ----------
    def _visit_func(self, node):
        info = FunctionInfo(
            name=node.name,
            lineno=node.lineno,
            end_lineno=getattr(node, "end_lineno", node.lineno),
            args=[a.arg for a in node.args.args],
            defaults=len(node.args.defaults),
            decorators=[dotted_name(d) if not isinstance(d, ast.Call) else dotted_name(d.func) for d in node.decorator_list],
            is_method=bool(self._class_stack),
            docstring=ast.get_docstring(node),
            returns_value=any(isinstance(n, ast.Return) and n.value is not None for n in ast.walk(node)),
        )
        self.functions.append(info)
        if self._class_stack:
            self._class_stack[-1].methods.append(node.name)
        self._op("def")
        for a in node.args.args:
            self._operand(a.arg)
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def visit_ClassDef(self, node):
        info = ClassInfo(name=node.name, lineno=node.lineno,
                         bases=[dotted_name(b) for b in node.bases])
        self.classes.append(info)
        self._op("class")
        self._class_stack.append(info)
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()
        self._class_stack.pop()

    # ---------- statements ----------
    def visit_Assign(self, node):
        self._op("=")
        targets = []
        for t in node.targets:
            for n in ast.walk(t):
                if isinstance(n, ast.Name):
                    targets.append(n.id)
        self.assignments.append((targets, node.lineno, type(node.value).__name__))
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        self._op(type(node.op).__name__ + "=")
        if isinstance(node.target, ast.Name):
            self.assignments.append(([node.target.id], node.lineno, type(node.value).__name__))
        self.generic_visit(node)

    def visit_If(self, node):
        self.conditionals += 1
        self._op("if")
        self.generic_visit(node)

    def visit_For(self, node):
        self.loops += 1
        self._op("for")
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self.loops += 1
        self._op("while")
        self.generic_visit(node)

    def visit_Try(self, node):
        self.try_blocks += 1
        self._op("try")
        self.generic_visit(node)

    def visit_Return(self, node):
        self.returns += 1
        self._op("return")
        self.generic_visit(node)

    def visit_Lambda(self, node):
        self.lambdas += 1
        self._op("lambda")
        self.generic_visit(node)

    def _visit_comp(self, node):
        self.comprehensions += 1
        self._op("comprehension")
        self.generic_visit(node)

    visit_ListComp = _visit_comp
    visit_SetComp = _visit_comp
    visit_DictComp = _visit_comp
    visit_GeneratorExp = _visit_comp

    # ---------- expressions ----------
    def visit_BinOp(self, node):
        self._op(type(node.op).__name__)
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        self._op(type(node.op).__name__)
        self.generic_visit(node)

    def visit_UnaryOp(self, node):
        self._op(type(node.op).__name__)
        self.generic_visit(node)

    def visit_Compare(self, node):
        for op in node.ops:
            self._op(type(op).__name__)
        self.generic_visit(node)

    def visit_Call(self, node):
        self._op("()")
        self.calls.append(CallInfo(
            callee=dotted_name(node.func),
            lineno=node.lineno,
            scope=self.scope,
            n_args=len(node.args),
            keywords=[k.arg for k in node.keywords if k.arg],
        ))
        self.generic_visit(node)

    def visit_Name(self, node):
        self._operand(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        self._operand(node.attr)
        self.generic_visit(node)

    def visit_Constant(self, node):
        self.literals.append((repr(node.value)[:60], type(node.value).__name__, node.lineno))
        self._operand(repr(node.value)[:60])
        self.generic_visit(node)

    def visit_Subscript(self, node):
        self._op("[]")
        self.generic_visit(node)

    # ---------- summary ----------
    def halstead_counts(self):
        n1, n2 = len(self.operators), len(self.operands)
        N1, N2 = sum(self.operators.values()), sum(self.operands.values())
        return n1, n2, N1, N2

    def summary(self) -> dict:
        n1, n2, N1, N2 = self.halstead_counts()
        return {
            "functions": len(self.functions),
            "classes": len(self.classes),
            "loops": self.loops,
            "conditionals": self.conditionals,
            "try_blocks": self.try_blocks,
            "returns": self.returns,
            "lambdas": self.lambdas,
            "comprehensions": self.comprehensions,
            "calls": len(self.calls),
            "assignments": len(self.assignments),
            "literals": len(self.literals),
            "distinct_operators_n1": n1,
            "distinct_operands_n2": n2,
            "total_operators_N1": N1,
            "total_operands_N2": N2,
        }


def analyze_ast(code: str):
    """Parse `code` and return (tree, ASTAnalyzer) or raise SyntaxError."""
    tree = ast.parse(code)
    analyzer = ASTAnalyzer()
    analyzer.visit(tree)
    return tree, analyzer
