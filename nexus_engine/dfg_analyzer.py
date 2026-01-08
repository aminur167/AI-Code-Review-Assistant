"""
Data Flow Graph (DFG) Analyzer
==============================
Classical iterative (fixed-point) data-flow analyses over the CFG:

  1. Reaching Definitions  — forward, GEN/KILL bit-vector style
  2. Live Variable Analysis — backward
  3. Def-Use Chains         — built from reaching definitions
  4. Dead Store detection   — a definition never used before redefinition
  5. Unused Variables       — defined, never used anywhere

References: Aho, Lam, Sethi, Ullman — "Compilers: Principles, Techniques,
and Tools" (Dragon Book), Ch. 9 Data-Flow Analysis.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Definition:
    var: str
    block: str
    lineno: int
    index: int          # statement index inside the block


@dataclass
class DFGResult:
    function: str
    definitions: list = field(default_factory=list)
    def_use_chains: dict = field(default_factory=dict)   # Definition -> [use linenos]
    reach_in: dict = field(default_factory=dict)
    reach_out: dict = field(default_factory=dict)
    live_in: dict = field(default_factory=dict)
    live_out: dict = field(default_factory=dict)
    dead_stores: list = field(default_factory=list)      # Definition list
    unused_variables: list = field(default_factory=list) # (var, lineno)
    variable_lifetime: dict = field(default_factory=dict)  # var -> (first_def, last_use)
    iterations: int = 0

    def to_dict(self):
        return {
            "function": self.function,
            "definitions": len(self.definitions),
            "def_use_chains": {
                f"{d.var}@L{d.lineno}": uses for d, uses in self.def_use_chains.items()
            },
            "dead_stores": [f"{d.var}@L{d.lineno}" for d in self.dead_stores],
            "unused_variables": [f"{v}@L{l}" for v, l in self.unused_variables],
            "variable_lifetime": self.variable_lifetime,
            "fixed_point_iterations": self.iterations,
        }

    def to_dot(self) -> str:
        """Def-use chain graph: definition nodes -> use-line nodes."""
        lines = ['digraph DFG {', '  bgcolor="transparent"; rankdir=LR;',
                 '  node [style="filled,rounded" shape=box fontname="Consolas" fontsize=10 fontcolor=white];',
                 '  edge [color="#94a3b8"];']
        for d, uses in self.def_use_chains.items():
            dn = f"def_{d.var}_L{d.lineno}"
            color = "#ef4444" if d in self.dead_stores else "#3b82f6"
            lines.append(f'  "{dn}" [label="DEF {d.var}\\nL{d.lineno}" fillcolor="{color}"];')
            for u in sorted(set(uses)):
                un = f"use_{d.var}_L{u}"
                lines.append(f'  "{un}" [label="USE {d.var}\\nL{u}" fillcolor="#22c55e"];')
                lines.append(f'  "{dn}" -> "{un}";')
        lines.append("}")
        return "\n".join(lines)


class DFGAnalyzer:
    def __init__(self, cfg):
        self.cfg = cfg

    def analyze(self) -> DFGResult:
        res = DFGResult(self.cfg.name)
        blocks = self.cfg.blocks
        graph = self.cfg.graph

        # ---- collect all definitions -------------------------------------
        all_defs: list[Definition] = []
        block_defs: dict[str, list[Definition]] = {b: [] for b in blocks}
        for bid, block in blocks.items():
            for i, s in enumerate(block.statements):
                for var in s.defs:
                    d = Definition(var, bid, s.lineno, i)
                    all_defs.append(d)
                    block_defs[bid].append(d)
        res.definitions = all_defs
        defs_of_var: dict[str, set] = {}
        for d in all_defs:
            defs_of_var.setdefault(d.var, set()).add(d)

        # ---- GEN / KILL per block ----------------------------------------
        GEN, KILL = {}, {}
        for bid in blocks:
            gen: dict[str, Definition] = {}
            for d in block_defs[bid]:          # later defs overwrite earlier (downward-exposed)
                gen[d.var] = d
            GEN[bid] = set(gen.values())
            KILL[bid] = set().union(*(defs_of_var[v] for v in gen)) - GEN[bid] if gen else set()

        # ---- Reaching Definitions (forward, fixed point) ------------------
        IN = {b: set() for b in blocks}
        OUT = {b: GEN[b].copy() for b in blocks}
        changed, iters = True, 0
        order = list(blocks)
        while changed:
            changed, iters = False, iters + 1
            for bid in order:
                new_in = set()
                for pred in graph.predecessors(bid):
                    new_in |= OUT.get(pred, set())
                new_out = GEN[bid] | (new_in - KILL[bid])
                if new_in != IN[bid] or new_out != OUT[bid]:
                    IN[bid], OUT[bid] = new_in, new_out
                    changed = True
        res.reach_in = {b: sorted(f"{d.var}@L{d.lineno}" for d in IN[b]) for b in blocks}
        res.reach_out = {b: sorted(f"{d.var}@L{d.lineno}" for d in OUT[b]) for b in blocks}
        res.iterations = iters

        # ---- Def-Use chains ----------------------------------------------
        chains: dict[Definition, list] = {d: [] for d in all_defs}
        for bid, block in blocks.items():
            current: dict[str, set] = {}
            for d in IN[bid]:
                current.setdefault(d.var, set()).add(d)
            for s in block.statements:
                for var in s.uses:
                    for d in current.get(var, set()):
                        chains[d].append(s.lineno)
                for var in s.defs:               # this statement's defs kill previous
                    current[var] = {d for d in block_defs[bid]
                                    if d.var == var and d.lineno == s.lineno}
        res.def_use_chains = chains

        # ---- Live Variables (backward, fixed point) -----------------------
        USE, DEF = {}, {}
        for bid, block in blocks.items():
            use, define = set(), set()
            for s in block.statements:
                use |= (s.uses - define)          # upward-exposed uses
                define |= s.defs
            USE[bid], DEF[bid] = use, define
        LIVE_IN = {b: set() for b in blocks}
        LIVE_OUT = {b: set() for b in blocks}
        changed = True
        while changed:
            changed = False
            for bid in order:
                out = set()
                for succ in graph.successors(bid):
                    out |= LIVE_IN.get(succ, set())
                new_in = USE[bid] | (out - DEF[bid])
                if out != LIVE_OUT[bid] or new_in != LIVE_IN[bid]:
                    LIVE_OUT[bid], LIVE_IN[bid] = out, new_in
                    changed = True
        res.live_in = {b: sorted(LIVE_IN[b]) for b in blocks}
        res.live_out = {b: sorted(LIVE_OUT[b]) for b in blocks}

        # ---- Dead stores & unused variables ------------------------------
        for d, uses in chains.items():
            if not uses:
                live_after = d.var in LIVE_OUT.get(d.block, set())
                if not live_after and not d.var.startswith("_"):
                    res.dead_stores.append(d)
        seen_use = {d.var for d, uses in chains.items() if uses}
        first_def: dict[str, int] = {}
        for d in all_defs:
            first_def[d.var] = min(first_def.get(d.var, d.lineno), d.lineno)
        for var, lineno in sorted(first_def.items(), key=lambda x: x[1]):
            if var not in seen_use and not var.startswith("_"):
                res.unused_variables.append((var, lineno))

        # ---- Variable lifetime -------------------------------------------
        for var, dset in defs_of_var.items():
            uses = [u for d in dset for u in chains[d]]
            res.variable_lifetime[var] = {
                "first_def": min(d.lineno for d in dset),
                "last_use": max(uses) if uses else None,
            }
        return res


def analyze_dfg(cfgs: dict) -> dict[str, DFGResult]:
    return {name: DFGAnalyzer(cfg).analyze() for name, cfg in cfgs.items()}
