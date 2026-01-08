"""
Program Dependence Graph (PDG) Builder
======================================
Combines Control Dependence and Data Dependence into a single graph and
supports backward Program Slicing.

  - Control dependence: Ferrante-Ottenstein-Warren construction using the
    post-dominator tree (computed as dominators of the reverse CFG).
  - Data dependence: def-use chains from the DFG (reaching definitions).
  - Program slice: backward reachability over PDG edges from a slicing
    criterion (a source line).

Reference: J. Ferrante, K. J. Ottenstein, J. D. Warren, "The Program
Dependence Graph and Its Use in Optimization", ACM TOPLAS 9(3), 1987.
"""

import networkx as nx
from dataclasses import dataclass, field


@dataclass
class PDGResult:
    function: str
    graph: nx.MultiDiGraph = field(default_factory=nx.MultiDiGraph)
    control_edges: list = field(default_factory=list)
    data_edges: list = field(default_factory=list)

    def to_dict(self):
        return {
            "function": self.function,
            "nodes": self.graph.number_of_nodes(),
            "control_dependencies": self.control_edges,
            "data_dependencies": self.data_edges,
        }

    def slice_lines(self, criterion_line: int) -> list[int]:
        """Backward program slice: all lines the criterion line depends on."""
        node_of_line = {}
        for n, d in self.graph.nodes(data=True):
            for ln in d.get("lines", []):
                node_of_line.setdefault(ln, n)
        start = node_of_line.get(criterion_line)
        if start is None:
            return []
        rev = self.graph.reverse()
        reached = nx.descendants(rev, start) | {start}
        lines = set()
        for n in reached:
            lines.update(self.graph.nodes[n].get("lines", []))
        return sorted(l for l in lines if l)

    def slice_context(self, criterion_line: int) -> dict:
        """Return an auditable, JSON-safe backward slice for an XAI consumer.

        This is deliberately graph evidence, not a natural-language summary:
        the caller can hand it to an LLM without granting the model authority
        to infer nodes or dependencies that the deterministic analysis did not
        establish.
        """
        node_of_line = {}
        for node, data in self.graph.nodes(data=True):
            for line in data.get("lines", []):
                node_of_line.setdefault(line, node)
        criterion = node_of_line.get(criterion_line)
        if criterion is None:
            return {"function": self.function, "criterion_line": criterion_line,
                    "slice_lines": [], "nodes": [], "edges": []}
        reached = nx.descendants(self.graph.reverse(), criterion) | {criterion}
        nodes = [{"id": str(node), "lines": sorted(
                    line for line in self.graph.nodes[node].get("lines", []) if line)}
                 for node in sorted(reached, key=str)]
        edges = []
        for source, target, data in self.graph.edges(data=True):
            if source in reached and target in reached:
                edge = {"from": str(source), "to": str(target),
                        "kind": data.get("kind", "unknown")}
                if data.get("var"):
                    edge["variable"] = data["var"]
                edges.append(edge)
        return {"function": self.function, "criterion_line": criterion_line,
                "slice_lines": sorted({line for node in nodes for line in node["lines"]}),
                "nodes": nodes, "edges": edges}

    def to_dot(self) -> str:
        lines = ['digraph PDG {', '  bgcolor="transparent"; rankdir=TB;',
                 '  node [style="filled,rounded" shape=box fontname="Consolas" fontsize=10 fontcolor=white fillcolor="#3b82f6"];']
        for n, d in self.graph.nodes(data=True):
            ln = d.get("lines", [])
            label = f"{n.split('::')[-1]}\\nL{min(ln)}-{max(ln)}" if ln else n.split("::")[-1]
            lines.append(f'  "{n}" [label="{label}"];')
        for u, v, d in self.graph.edges(data=True):
            style = ('color="#f59e0b" label="CD" fontcolor="#f59e0b"'
                     if d.get("kind") == "control"
                     else f'color="#22c55e" label="DD:{d.get("var", "")}" fontcolor="#22c55e"')
            lines.append(f'  "{u}" -> "{v}" [{style} fontsize=9];')
        lines.append("}")
        return "\n".join(lines)


class PDGBuilder:
    def __init__(self, cfg, dfg_result):
        self.cfg = cfg
        self.dfg = dfg_result

    def build(self) -> PDGResult:
        res = PDGResult(self.cfg.name)
        G, entry, exit_ = self.cfg.graph, self.cfg.entry, self.cfg.exit
        reachable = nx.descendants(G, entry) | {entry}
        G = G.subgraph(reachable).copy()
        if exit_ not in G:
            G.add_node(exit_)

        for bid in G.nodes:
            block = self.cfg.blocks.get(bid)
            res.graph.add_node(bid, lines=[s.lineno for s in block.statements] if block else [])

        # ---- control dependence (via post-dominators) ---------------------
        rev = G.reverse()
        # ensure exit reaches all nodes in reverse graph
        for n in G.nodes:
            if n != exit_ and not nx.has_path(rev, exit_, n):
                rev.add_edge(exit_, n)
        ipdom = nx.immediate_dominators(rev, exit_)
        for u, v in G.edges:
            # walk from v up the post-dominator tree until ipdom(u);
            # every node passed is control dependent on u  (FOW 1987)
            stop = ipdom.get(u)
            runner = v
            seen = set()
            while runner is not None and runner != stop and runner not in seen:
                seen.add(runner)
                if runner != u:
                    res.graph.add_edge(u, runner, kind="control")
                    res.control_edges.append({"from": u, "to": runner})
                nxt = ipdom.get(runner)
                runner = None if nxt == runner else nxt

        # ---- data dependence (def-use chains) -----------------------------
        line_block = {}
        for bid in G.nodes:
            block = self.cfg.blocks.get(bid)
            if block:
                for s in block.statements:
                    line_block.setdefault(s.lineno, bid)
        for d, uses in self.dfg.def_use_chains.items():
            for use_line in set(uses):
                src, dst = d.block, line_block.get(use_line)
                if src in res.graph and dst in res.graph and src != dst:
                    res.graph.add_edge(src, dst, kind="data", var=d.var)
                    res.data_edges.append({"from": f"{d.var}@L{d.lineno}",
                                           "to": f"L{use_line}", "var": d.var})
        # dedupe control edge list
        seen = set()
        res.control_edges = [e for e in res.control_edges
                             if (t := (e["from"], e["to"])) not in seen and not seen.add(t)]
        return res


def build_pdgs(cfgs: dict, dfg_results: dict) -> dict[str, PDGResult]:
    out = {}
    for name, cfg in cfgs.items():
        try:
            out[name] = PDGBuilder(cfg, dfg_results[name]).build()
        except Exception:
            out[name] = PDGResult(name)
    return out
