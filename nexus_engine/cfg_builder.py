"""
Control Flow Graph (CFG) Builder
================================
Real basic-block CFG construction from the Python AST, per function and
for the module body.

Features:
  - Entry / Exit nodes per graph
  - If: labelled True/False edges + merge node
  - While/For: loop header, back edge, loop-exit (False) edge
  - Break / Continue edges to loop exit / loop header
  - Return edges to Exit
  - Try/Except/Finally: exception edges from protected region to handlers
  - Each statement carries def/use/call information for the DFG & taint stages
"""

import ast
import networkx as nx
from dataclasses import dataclass, field

from .ast_analyzer import dotted_name


# --------------------------------------------------------------------------
# Statement-level def/use extraction
# --------------------------------------------------------------------------

def _names(node, ctx_type):
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ctx_type):
            out.add(n.id)
    return out


def _calls_in(node):
    """All calls inside an expression/statement: (dotted_callee, arg descriptors, lineno, keywords)."""
    calls = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            args = []
            for a in n.args:
                if isinstance(a, ast.Name):
                    args.append(("name", a.id))
                elif isinstance(a, ast.Constant):
                    args.append(("const", a.value))
                else:
                    args.append(("expr", frozenset(_names(a, ast.Load))))
            kw = {}
            for k in n.keywords:
                if k.arg:
                    if isinstance(k.value, ast.Constant):
                        kw[k.arg] = ("const", k.value.value)
                    else:
                        kw[k.arg] = ("expr", frozenset(_names(k.value, ast.Load)))
            calls.append({"callee": dotted_name(n.func),
                          "args": args, "keywords": kw,
                          "lineno": getattr(n, "lineno", 0)})
    return calls


def stmt_def_use(node):
    """Compute (defs, uses, calls) for a *simple* statement or a compound header."""
    defs, uses = set(), set()
    if isinstance(node, ast.Assign):
        for t in node.targets:
            defs |= _names(t, ast.Store)
            uses |= _names(t, ast.Load)          # a[i] = x uses a, i
        uses |= _names(node.value, ast.Load)
    elif isinstance(node, ast.AugAssign):
        if isinstance(node.target, ast.Name):
            defs.add(node.target.id)
            uses.add(node.target.id)
        uses |= _names(node.value, ast.Load)
    elif isinstance(node, ast.AnnAssign):
        if node.target is not None:
            defs |= _names(node.target, ast.Store)
        if node.value is not None:
            uses |= _names(node.value, ast.Load)
    elif isinstance(node, (ast.If, ast.While)):
        uses |= _names(node.test, ast.Load)
    elif isinstance(node, ast.For):
        defs |= _names(node.target, ast.Store)
        uses |= _names(node.iter, ast.Load)
    elif isinstance(node, (ast.Return, ast.Expr, ast.Raise, ast.Assert, ast.Delete)):
        uses |= _names(node, ast.Load)
    elif isinstance(node, ast.With):
        for item in node.items:
            uses |= _names(item.context_expr, ast.Load)
            if item.optional_vars is not None:
                defs |= _names(item.optional_vars, ast.Store)
    else:
        uses |= _names(node, ast.Load)
        defs |= _names(node, ast.Store)
    return defs, uses, _calls_in(node)


@dataclass
class Stmt:
    lineno: int
    text: str
    defs: set
    uses: set
    calls: list
    node: ast.AST = field(repr=False, default=None)
    is_return: bool = False


@dataclass
class BasicBlock:
    id: str
    kind: str = "block"          # entry|exit|block|cond|loop_header|merge|handler|finally
    statements: list = field(default_factory=list)

    def add(self, node, src_lines):
        defs, uses, calls = stmt_def_use(node)
        line = getattr(node, "lineno", 0)
        text = src_lines[line - 1].strip() if 0 < line <= len(src_lines) else type(node).__name__
        self.statements.append(Stmt(line, text[:90], defs, uses, calls, node,
                                    is_return=isinstance(node, ast.Return)))

    @property
    def first_line(self):
        return self.statements[0].lineno if self.statements else None


class CFG:
    """CFG for one function (or the module body)."""

    def __init__(self, name: str):
        self.name = name
        self.graph = nx.DiGraph()
        self.blocks: dict[str, BasicBlock] = {}
        self.entry = self._new_block("entry").id
        self.exit = self._new_block("exit").id
        self._counter = 0

    def _new_block(self, kind="block") -> BasicBlock:
        n = len(self.blocks)
        bid = f"{self.name}::B{n}" if kind not in ("entry", "exit") else f"{self.name}::{kind.upper()}"
        block = BasicBlock(bid, kind)
        self.blocks[bid] = block
        self.graph.add_node(bid, kind=kind)
        return block

    def add_edge(self, src: str, dst: str, label: str = ""):
        if src and dst:
            self.graph.add_edge(src, dst, label=label)

    # ---------- exports ----------
    def stats(self):
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "back_edges": sum(1 for _, _, d in self.graph.edges(data=True) if d.get("label") == "back"),
            "exception_edges": sum(1 for _, _, d in self.graph.edges(data=True) if d.get("label") == "exception"),
        }

    def to_dot(self) -> str:
        colors = {"entry": "#22c55e", "exit": "#ef4444", "cond": "#f59e0b",
                  "loop_header": "#8b5cf6", "merge": "#64748b", "handler": "#ec4899",
                  "finally": "#14b8a6", "block": "#3b82f6"}
        lines = [f'digraph "{self.name}" {{',
                 '  bgcolor="transparent"; rankdir=TB;',
                 '  node [style="filled,rounded" shape=box fontname="Consolas" fontsize=10 fontcolor=white];',
                 '  edge [fontname="Consolas" fontsize=9 color="#94a3b8" fontcolor="#cbd5e1"];']
        for bid, block in self.blocks.items():
            if block.kind == "entry":
                label = f"ENTRY: {self.name}"
            elif block.kind == "exit":
                label = "EXIT"
            else:
                body = "\\l".join(f"L{s.lineno}: {s.text[:38]}" for s in block.statements[:6]) or block.kind
                label = f"{bid.split('::')[-1]} [{block.kind}]\\l{body}\\l"
            color = colors.get(block.kind, "#3b82f6")
            lines.append(f'  "{bid}" [label="{label}" fillcolor="{color}"];')
        for u, v, d in self.graph.edges(data=True):
            lbl = d.get("label", "")
            attr = f' [label="{lbl}"]' if lbl else ""
            lines.append(f'  "{u}" -> "{v}"{attr};')
        lines.append("}")
        return "\n".join(lines)


class CFGBuilder:
    """Builds one CFG per function plus a module-level CFG."""

    SIMPLE = (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Expr, ast.Pass,
              ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
              ast.Delete, ast.Assert, ast.Raise)

    def __init__(self, code: str, tree: ast.AST):
        self.src_lines = code.split("\n")
        self.tree = tree
        self.cfgs: dict[str, CFG] = {}

    def build_all(self) -> dict[str, CFG]:
        self.cfgs["<module>"] = self._build("<module>", self.tree.body)
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.cfgs[node.name] = self._build(node.name, node.body)
        return self.cfgs

    def _build(self, name: str, body: list) -> CFG:
        cfg = CFG(name)
        self._cfg = cfg
        self._loop_stack = []                 # (header_id, exit_block_id)
        first = cfg._new_block()
        cfg.add_edge(cfg.entry, first.id)
        last = self._stmts(body, first)
        if last is not None:
            cfg.add_edge(last.id, cfg.exit)
        # any dangling blocks with no successor also flow to exit
        for bid in list(cfg.graph.nodes):
            if bid != cfg.exit and cfg.graph.out_degree(bid) == 0:
                cfg.add_edge(bid, cfg.exit)
        return cfg

    def _stmts(self, stmts, cur: BasicBlock):
        """Process a statement list; return the open trailing block or None if control diverted."""
        cfg = self._cfg
        for stmt in stmts:
            if cur is None:                   # unreachable code after return/break
                cur = cfg._new_block()
            if isinstance(stmt, self.SIMPLE):
                cur.add(stmt, self.src_lines)
                if isinstance(stmt, ast.Raise):
                    cfg.add_edge(cur.id, cfg.exit, "raise")
                    cur = None
            elif isinstance(stmt, ast.Return):
                cur.add(stmt, self.src_lines)
                cfg.add_edge(cur.id, cfg.exit, "return")
                cur = None
            elif isinstance(stmt, ast.Break):
                header, loop_exit = self._loop_stack[-1] if self._loop_stack else (None, None)
                if loop_exit:
                    cfg.add_edge(cur.id, loop_exit, "break")
                cur = None
            elif isinstance(stmt, ast.Continue):
                header, _ = self._loop_stack[-1] if self._loop_stack else (None, None)
                if header:
                    cfg.add_edge(cur.id, header, "continue")
                cur = None
            elif isinstance(stmt, ast.If):
                cur = self._if(stmt, cur)
            elif isinstance(stmt, (ast.While, ast.For, ast.AsyncFor)):
                cur = self._loop(stmt, cur)
            elif isinstance(stmt, ast.Try):
                cur = self._try(stmt, cur)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                cur.add(stmt, self.src_lines)
                cur = self._stmts(stmt.body, cur)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # definitions are straight-line at this level; their bodies get their own CFG
                cur.statements.append(Stmt(stmt.lineno, f"def {stmt.name}(...)",
                                           {stmt.name}, set(), [], None))
            else:
                cur.add(stmt, self.src_lines)
        return cur

    def _if(self, stmt, cur):
        cfg = self._cfg
        cond = cfg._new_block("cond")
        cond.add(stmt, self.src_lines)
        cfg.add_edge(cur.id, cond.id)

        merge = cfg._new_block("merge")

        then_b = cfg._new_block()
        cfg.add_edge(cond.id, then_b.id, "True")
        then_end = self._stmts(stmt.body, then_b)
        if then_end is not None:
            cfg.add_edge(then_end.id, merge.id)

        if stmt.orelse:
            else_b = cfg._new_block()
            cfg.add_edge(cond.id, else_b.id, "False")
            else_end = self._stmts(stmt.orelse, else_b)
            if else_end is not None:
                cfg.add_edge(else_end.id, merge.id)
        else:
            cfg.add_edge(cond.id, merge.id, "False")
        return merge

    def _loop(self, stmt, cur):
        cfg = self._cfg
        header = cfg._new_block("loop_header")
        header.add(stmt, self.src_lines)
        cfg.add_edge(cur.id, header.id)

        exit_b = cfg._new_block("merge")
        body_b = cfg._new_block()
        cfg.add_edge(header.id, body_b.id, "True")
        cfg.add_edge(header.id, exit_b.id, "False")

        self._loop_stack.append((header.id, exit_b.id))
        body_end = self._stmts(stmt.body, body_b)
        self._loop_stack.pop()
        if body_end is not None:
            cfg.add_edge(body_end.id, header.id, "back")

        if getattr(stmt, "orelse", None):
            else_b = cfg._new_block()
            cfg.add_edge(header.id, else_b.id, "else")
            else_end = self._stmts(stmt.orelse, else_b)
            if else_end is not None:
                cfg.add_edge(else_end.id, exit_b.id)
        return exit_b

    def _try(self, stmt, cur):
        cfg = self._cfg
        try_b = cfg._new_block()
        cfg.add_edge(cur.id, try_b.id)
        try_end = self._stmts(stmt.body, try_b)

        merge = cfg._new_block("merge")

        handler_ends = []
        for handler in stmt.handlers:
            h_b = cfg._new_block("handler")
            exc_name = dotted_name(handler.type) if handler.type else "Exception"
            cfg.add_edge(try_b.id, h_b.id, "exception")
            if try_end is not None and try_end.id != try_b.id:
                cfg.add_edge(try_end.id, h_b.id, "exception")
            if handler.name:
                h_b.statements.append(Stmt(handler.lineno, f"except {exc_name} as {handler.name}",
                                           {handler.name}, set(), [], None))
            h_end = self._stmts(handler.body, h_b)
            handler_ends.append(h_end)

        if stmt.orelse:
            else_b = cfg._new_block()
            if try_end is not None:
                cfg.add_edge(try_end.id, else_b.id, "no-exception")
            try_end = self._stmts(stmt.orelse, else_b)

        targets = [try_end] + handler_ends
        if stmt.finalbody:
            fin = cfg._new_block("finally")
            for t in targets:
                if t is not None:
                    cfg.add_edge(t.id, fin.id)
            fin_end = self._stmts(stmt.finalbody, fin)
            if fin_end is not None:
                cfg.add_edge(fin_end.id, merge.id)
        else:
            for t in targets:
                if t is not None:
                    cfg.add_edge(t.id, merge.id)
        return merge


def build_cfgs(code: str, tree: ast.AST) -> dict[str, CFG]:
    return CFGBuilder(code, tree).build_all()
