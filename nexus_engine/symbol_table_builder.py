"""
Symbol Table Builder
====================
Hierarchical, scope-aware symbol table (module / class / function scopes).

Tracks for every symbol: kind (param | local | global-decl | import |
function | class), definition lines, and usage lines. This feeds the
DFG, alias analysis, and the rule engine.
"""

import ast
from dataclasses import dataclass, field


@dataclass
class Symbol:
    name: str
    kind: str                       # param|local|global|import|function|class
    def_lines: list = field(default_factory=list)
    use_lines: list = field(default_factory=list)


@dataclass
class Scope:
    name: str
    kind: str                       # module|function|class
    lineno: int
    parent: "Scope | None" = None
    symbols: dict = field(default_factory=dict)
    children: list = field(default_factory=list)

    def qualified_name(self):
        parts, s = [], self
        while s:
            parts.append(s.name)
            s = s.parent
        return ".".join(reversed(parts))

    def define(self, name, kind, lineno):
        sym = self.symbols.setdefault(name, Symbol(name, kind))
        sym.def_lines.append(lineno)

    def use(self, name, lineno):
        s = self
        while s:                                   # lexical scoping lookup
            if name in s.symbols:
                s.symbols[name].use_lines.append(lineno)
                return
            s = s.parent

    def to_dict(self):
        return {
            "scope": self.qualified_name(),
            "kind": self.kind,
            "symbols": {
                n: {"kind": s.kind, "defs": s.def_lines, "uses": s.use_lines}
                for n, s in self.symbols.items()
            },
            "children": [c.to_dict() for c in self.children],
        }


class SymbolTableBuilder(ast.NodeVisitor):
    def __init__(self):
        self.root = Scope("<module>", "module", 0)
        self.current = self.root

    def _push(self, name, kind, lineno):
        scope = Scope(name, kind, lineno, parent=self.current)
        self.current.children.append(scope)
        self.current = scope

    def _pop(self):
        self.current = self.current.parent

    def _visit_func(self, node):
        self.current.define(node.name, "function", node.lineno)
        self._push(node.name, "function", node.lineno)
        for a in node.args.args + node.args.kwonlyargs:
            self.current.define(a.arg, "param", node.lineno)
        if node.args.vararg:
            self.current.define(node.args.vararg.arg, "param", node.lineno)
        if node.args.kwarg:
            self.current.define(node.args.kwarg.arg, "param", node.lineno)
        self.generic_visit(node)
        self._pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def visit_ClassDef(self, node):
        self.current.define(node.name, "class", node.lineno)
        self._push(node.name, "class", node.lineno)
        self.generic_visit(node)
        self._pop()

    def visit_Import(self, node):
        for alias in node.names:
            self.current.define(alias.asname or alias.name.split(".")[0], "import", node.lineno)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.current.define(alias.asname or alias.name, "import", node.lineno)

    def visit_Global(self, node):
        for name in node.names:
            self.current.define(name, "global", node.lineno)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            if node.id not in self.current.symbols:
                self.current.define(node.id, "local", node.lineno)
            else:
                self.current.symbols[node.id].def_lines.append(node.lineno)
        elif isinstance(node.ctx, ast.Load):
            self.current.use(node.id, node.lineno)
        self.generic_visit(node)


def build_symbol_table(tree: ast.AST) -> Scope:
    builder = SymbolTableBuilder()
    builder.visit(tree)
    return builder.root
