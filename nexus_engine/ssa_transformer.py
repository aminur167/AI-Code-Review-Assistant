"""
SSA Transformer (Static Single Assignment)
==========================================
Implements Cytron et al. (1991) SSA construction on top of the CFG:

  1. Dominator tree        — Cooper-Harvey-Kennedy iterative algorithm
                             (via networkx.immediate_dominators)
  2. Dominance frontiers   — networkx.dominance_frontiers
  3. Phi-node placement    — iterated dominance frontier of each variable's
                             definition sites
  4. Variable renaming     — stack-based recursive renaming over the
                             dominator tree (Cytron Fig. 12)

Reference: R. Cytron, J. Ferrante, B. K. Rosen, M. N. Wegman, F. K. Zadeck,
"Efficiently Computing Static Single Assignment Form and the Control
Dependence Graph", ACM TOPLAS 13(4), 1991.
"""

import networkx as nx
from dataclasses import dataclass, field


@dataclass
class PhiNode:
    var: str
    block: str
    target: str = ""                 # renamed target, e.g. x_3
    args: list = field(default_factory=list)   # one renamed arg per predecessor


@dataclass
class SSAResult:
    function: str
    idom: dict = field(default_factory=dict)
    dominance_frontiers: dict = field(default_factory=dict)
    phi_nodes: list = field(default_factory=list)
    renamed: dict = field(default_factory=dict)     # block -> [renamed stmt strings]
    version_count: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "function": self.function,
            "dominator_tree": {k: v for k, v in self.idom.items() if k != v},
            "dominance_frontiers": {k: sorted(v) for k, v in self.dominance_frontiers.items() if v},
            "phi_nodes": [
                {"block": p.block, "phi": f"{p.target} = φ({', '.join(p.args)})"}
                for p in self.phi_nodes
            ],
            "ssa_form": self.renamed,
            "versions_per_variable": self.version_count,
        }


class SSATransformer:
    def __init__(self, cfg):
        self.cfg = cfg

    def transform(self) -> SSAResult:
        res = SSAResult(self.cfg.name)
        G, entry = self.cfg.graph, self.cfg.entry
        reachable = nx.descendants(G, entry) | {entry}
        G = G.subgraph(reachable).copy()

        # ---- 1. dominators & 2. dominance frontiers ----------------------
        idom = nx.immediate_dominators(G, entry)
        res.idom = dict(idom)
        df = nx.dominance_frontiers(G, entry)
        res.dominance_frontiers = {k: set(v) for k, v in df.items()}

        dom_children: dict[str, list] = {}
        for node, dom in idom.items():
            if node != dom:
                dom_children.setdefault(dom, []).append(node)

        # ---- 3. phi placement (iterated dominance frontier) ---------------
        defsites: dict[str, set] = {}
        for bid, block in self.cfg.blocks.items():
            if bid not in reachable:
                continue
            for s in block.statements:
                for v in s.defs:
                    defsites.setdefault(v, set()).add(bid)

        phis: dict[str, dict[str, PhiNode]] = {}   # block -> var -> PhiNode
        for var, sites in defsites.items():
            if len(sites) < 2:
                continue
            work = list(sites)
            placed = set()
            while work:
                b = work.pop()
                for y in df.get(b, ()):
                    if y not in placed:
                        placed.add(y)
                        phis.setdefault(y, {})[var] = PhiNode(var, y)
                        if y not in sites:
                            work.append(y)
        res.phi_nodes = [p for by_var in phis.values() for p in by_var.values()]

        # ---- 4. renaming (Cytron stack-based) -----------------------------
        counter: dict[str, int] = {}
        stacks: dict[str, list] = {}

        def new_name(v):
            counter[v] = counter.get(v, 0) + 1
            name = f"{v}_{counter[v]}"
            stacks.setdefault(v, []).append(name)
            return name

        def top(v):
            return stacks[v][-1] if stacks.get(v) else f"{v}_0"

        renamed: dict[str, list] = {}
        pred_index: dict[str, list] = {b: list(G.predecessors(b)) for b in G.nodes}
        for by_var in phis.values():
            for p in by_var.values():
                p.args = [""] * len(pred_index[p.block])

        def rename(block_id):
            pushed = []
            out_lines = []
            for p in phis.get(block_id, {}).values():
                p.target = new_name(p.var)
                pushed.append(p.var)
            for s in self.cfg.blocks[block_id].statements:
                use_map = {v: top(v) for v in s.uses}
                def_map = {}
                for v in s.defs:
                    def_map[v] = new_name(v)
                    pushed.append(v)
                text = s.text
                rendered = (f"L{s.lineno}: {text}   "
                            f"[uses: {', '.join(use_map.values()) or '-'}]"
                            f" [defs: {', '.join(def_map.values()) or '-'}]")
                out_lines.append(rendered)
            renamed[block_id] = ([f"{p.target} = φ({p.var})" for p in phis.get(block_id, {}).values()]
                                 + out_lines)
            for succ in G.successors(block_id):
                j = pred_index[succ].index(block_id)
                for p in phis.get(succ, {}).values():
                    p.args[j] = top(p.var)
            for child in sorted(dom_children.get(block_id, [])):
                rename(child)
            for v in pushed:
                if stacks.get(v):
                    stacks[v].pop()

        import sys
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(max(old_limit, 10000))
        try:
            rename(self.cfg.entry)
        finally:
            sys.setrecursionlimit(old_limit)

        for by_var in phis.values():
            for p in by_var.values():
                p.args = [a or f"{p.var}_0" for a in p.args]
        res.renamed = renamed
        res.version_count = dict(counter)
        return res


def transform_ssa(cfgs: dict) -> dict[str, SSAResult]:
    out = {}
    for name, cfg in cfgs.items():
        try:
            out[name] = SSATransformer(cfg).transform()
        except Exception as e:  # SSA must never crash the pipeline
            r = SSAResult(name)
            r.renamed = {"error": [str(e)]}
            out[name] = r
    return out
