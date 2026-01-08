"""
Universal CFG Builder
=====================
Constructs real basic-block Control-Flow Graphs from the Universal IR
(:mod:`nexus_engine.universal_ir`), giving C, C++, Java, and JavaScript the
same CFG quality the Python path obtains from the native ``ast`` module.

The graphs are instances of the *same* :class:`~nexus_engine.cfg_builder.CFG`
class used by the Python pipeline, so every downstream consumer -- the DFG
analyzer, SSA transformer, PDG builder, and taint engine -- operates on them
without modification. That shared representation is what makes full
cross-language feature parity possible.

Edge vocabulary (identical to the Python builder):

    ``True`` / ``False``  conditional branches with an explicit merge node
    ``back``              loop back edge (header re-entry)
    ``break``             jump to the loop exit block
    ``continue``          jump to the loop header
    ``return`` / ``raise``diversion to the function exit node
    ``exception``         protected region to each catch handler
    ``case`` / ``default``switch dispatch edges

Both structured loops (``for``/``while``/``do-while``/for-each) and
``switch`` dispatch are lowered faithfully, including fall-through between
switch cases, which C, C++, Java, and JavaScript all permit.
"""

from __future__ import annotations

from .cfg_builder import CFG, BasicBlock, Stmt
from .universal_ir import UFunc, UProgram, UStmt


class UIRCFGBuilder:
    """Builds one CFG per :class:`UFunc`, plus one for top-level code."""

    def __init__(self, program: UProgram):
        self.program = program
        self.cfgs: dict[str, CFG] = {}

    # ------------------------------------------------------------------
    def build_all(self) -> dict[str, CFG]:
        if self.program.toplevel:
            self.cfgs["<module>"] = self._build("<module>", self.program.toplevel)
        for fn in self.program.functions:
            name = fn.name
            if name in self.cfgs:                     # overloads / same-name methods
                name = f"{fn.class_name}.{fn.name}" if fn.class_name else f"{fn.name}@L{fn.lineno}"
                if name in self.cfgs:
                    name = f"{fn.name}@L{fn.lineno}"
            self.cfgs[name] = self._build(name, fn.body, params=fn.params)
        return self.cfgs

    # ------------------------------------------------------------------
    def _build(self, name: str, body: list, params: list | None = None) -> CFG:
        cfg = CFG(name)
        self._cfg = cfg
        self._loop_stack: list[tuple[str, str]] = []   # (header_id, exit_id)
        self._switch_stack: list[str] = []             # exit block of the switch

        first = cfg._new_block()
        cfg.add_edge(cfg.entry, first.id)

        # Parameters are definitions at function entry, which reaching
        # definitions and liveness need in order to resolve uses that have no
        # in-body definition. They are placed in the *entry* block rather than
        # the first body block so that a taint state seeded on a parameter is
        # not killed by its own declaration.
        if params:
            entry_block = cfg.blocks[cfg.entry]
            for p in params:
                entry_block.statements.append(
                    Stmt(0, f"param {p}", {p}, set(), [], None))

        last = self._stmts(body, first)
        if last is not None:
            cfg.add_edge(last.id, cfg.exit)
        for bid in list(cfg.graph.nodes):
            if bid != cfg.exit and cfg.graph.out_degree(bid) == 0:
                cfg.add_edge(bid, cfg.exit)
        return cfg

    # ------------------------------------------------------------------
    def _stmts(self, stmts: list, cur: BasicBlock | None) -> BasicBlock | None:
        """Process a statement list; return the open trailing block, or None
        if control was diverted (return/break/continue/throw)."""
        cfg = self._cfg
        for st in stmts:
            if cur is None:                            # unreachable continuation
                cur = cfg._new_block()
            kind = st.kind

            if kind == "if":
                cur = self._if(st, cur)
            elif kind == "loop":
                cur = self._loop(st, cur)
            elif kind == "switch":
                cur = self._switch(st, cur)
            elif kind == "try":
                cur = self._try(st, cur)
            elif kind == "return":
                self._emit(cur, st)
                cfg.add_edge(cur.id, cfg.exit, "return")
                cur = None
            elif kind == "throw":
                self._emit(cur, st)
                cfg.add_edge(cur.id, cfg.exit, "raise")
                cur = None
            elif kind == "break":
                target = None
                if self._switch_stack:
                    target = self._switch_stack[-1]
                if self._loop_stack:
                    target = self._loop_stack[-1][1]
                if target:
                    cfg.add_edge(cur.id, target, "break")
                cur = None
            elif kind == "continue":
                if self._loop_stack:
                    cfg.add_edge(cur.id, self._loop_stack[-1][0], "continue")
                cur = None
            else:
                self._emit(cur, st)
        return cur

    @staticmethod
    def _emit(block: BasicBlock, st: UStmt):
        """Append a UIR statement to a basic block as a CFG ``Stmt``."""
        block.statements.append(Stmt(
            lineno=st.lineno,
            text=st.text or st.kind,
            defs=set(st.defs),
            uses=set(st.uses),
            calls=st.call_dicts,
            node=st,
            is_return=st.is_return,
        ))

    # ------------------------------------------------------------------
    def _if(self, st: UStmt, cur: BasicBlock) -> BasicBlock:
        cfg = self._cfg
        cond = cfg._new_block("cond")
        self._emit(cond, st)
        cfg.add_edge(cur.id, cond.id)

        merge = cfg._new_block("merge")

        then_b = cfg._new_block()
        cfg.add_edge(cond.id, then_b.id, "True")
        then_end = self._stmts(st.then_body, then_b)
        if then_end is not None:
            cfg.add_edge(then_end.id, merge.id)

        if st.else_body:
            else_b = cfg._new_block()
            cfg.add_edge(cond.id, else_b.id, "False")
            else_end = self._stmts(st.else_body, else_b)
            if else_end is not None:
                cfg.add_edge(else_end.id, merge.id)
        else:
            cfg.add_edge(cond.id, merge.id, "False")
        return merge

    def _loop(self, st: UStmt, cur: BasicBlock) -> BasicBlock:
        """
        ``while``/``for``/for-each lower to a guarded loop (header tested
        before the body); ``do-while`` executes the body once before the
        test, so the entry edge targets the body directly.
        """
        cfg = self._cfg
        is_do_while = bool(st.node is not None and
                           getattr(st.node, "type", "") == "do_statement")

        header = cfg._new_block("loop_header")
        self._emit(header, st)
        exit_b = cfg._new_block("merge")
        body_b = cfg._new_block()

        if is_do_while:
            cfg.add_edge(cur.id, body_b.id)            # body runs at least once
        else:
            cfg.add_edge(cur.id, header.id)
        cfg.add_edge(header.id, body_b.id, "True")
        cfg.add_edge(header.id, exit_b.id, "False")

        self._loop_stack.append((header.id, exit_b.id))
        body_end = self._stmts(st.body, body_b)
        self._loop_stack.pop()
        if body_end is not None:
            cfg.add_edge(body_end.id, header.id, "back")
        return exit_b

    def _switch(self, st: UStmt, cur: BasicBlock) -> BasicBlock:
        """Switch dispatch with C-style fall-through between cases."""
        cfg = self._cfg
        disp = cfg._new_block("cond")
        self._emit(disp, st)
        cfg.add_edge(cur.id, disp.id)

        exit_b = cfg._new_block("merge")
        self._switch_stack.append(exit_b.id)

        prev_end: BasicBlock | None = None
        has_default = False
        for label, cbody in st.cases:
            cb = cfg._new_block()
            cfg.add_edge(disp.id, cb.id, "default" if label == "default" else f"case {label}"[:24])
            if label == "default":
                has_default = True
            if prev_end is not None:                   # fall-through from previous case
                cfg.add_edge(prev_end.id, cb.id, "fallthrough")
            prev_end = self._stmts(cbody, cb)

        self._switch_stack.pop()
        if prev_end is not None:
            cfg.add_edge(prev_end.id, exit_b.id)
        if not has_default:
            cfg.add_edge(disp.id, exit_b.id, "no match")
        return exit_b

    def _try(self, st: UStmt, cur: BasicBlock) -> BasicBlock:
        cfg = self._cfg
        try_b = cfg._new_block()
        cfg.add_edge(cur.id, try_b.id)
        try_end = self._stmts(st.body, try_b)

        merge = cfg._new_block("merge")
        handler_ends = []
        for exc_name, hbody in st.handlers:
            h_b = cfg._new_block("handler")
            cfg.add_edge(try_b.id, h_b.id, "exception")
            if try_end is not None and try_end.id != try_b.id:
                cfg.add_edge(try_end.id, h_b.id, "exception")
            handler_ends.append(self._stmts(hbody, h_b))

        targets = [try_end] + handler_ends
        if st.finalbody:
            fin = cfg._new_block("finally")
            for t in targets:
                if t is not None:
                    cfg.add_edge(t.id, fin.id)
            fin_end = self._stmts(st.finalbody, fin)
            if fin_end is not None:
                cfg.add_edge(fin_end.id, merge.id)
        else:
            for t in targets:
                if t is not None:
                    cfg.add_edge(t.id, merge.id)
        return merge


def build_uir_cfgs(program: UProgram) -> dict[str, CFG]:
    """Public entry point: :class:`UProgram` -> ``{function_name: CFG}``."""
    return UIRCFGBuilder(program).build_all()
