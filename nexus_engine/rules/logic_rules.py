"""
Logic Rule Plugins
==================
Deterministic logic-bug detectors driven by CFG/DFG facts.
"""

import ast

from ..rule_engine import RulePlugin


class DivisionByZeroRule(RulePlugin):
    rule_id = "LOG-DIVZERO"
    cwe = "CWE-369"
    severity = "HIGH"
    category = "logic"
    description = "Division/modulo by a value proven or likely to be zero"

    def check(self, ctx):
        out = []
        # variables whose ONLY reaching definition is the constant 0
        zero_vars = {}
        for node in ast.walk(ctx.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                    and node.value.value == 0:
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        zero_vars.setdefault(t.id, []).append(node.lineno)
        redefined = set()
        for node in ast.walk(ctx.tree):
            if isinstance(node, (ast.Assign, ast.AugAssign)):
                val = getattr(node, "value", None)
                is_zero = isinstance(val, ast.Constant) and val.value == 0
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Name) and t.id in zero_vars and not is_zero:
                        redefined.add(t.id)

        for node in ast.walk(ctx.tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                d = node.right
                if isinstance(d, ast.Constant) and d.value == 0:
                    out.append(self.finding(
                        node.lineno, "Division by constant zero — guaranteed ZeroDivisionError",
                        evidence=ast.unparse(node) if hasattr(ast, "unparse") else "x / 0",
                        fix_hint="Guard the denominator: if d != 0: ... else handle the case."))
                elif isinstance(d, ast.Name) and d.id in zero_vars and d.id not in redefined:
                    out.append(self.finding(
                        node.lineno,
                        f"Division by '{d.id}' whose only reaching definition is 0 "
                        f"(defined at L{zero_vars[d.id][0]})",
                        evidence=ast.unparse(node) if hasattr(ast, "unparse") else f"x / {d.id}",
                        fix_hint=f"Check '{d.id} != 0' before dividing, or fix its initialization."))
        return out


class InfiniteLoopRule(RulePlugin):
    rule_id = "LOG-INFLOOP"
    cwe = "CWE-835"
    severity = "HIGH"
    category = "logic"
    description = "Loop whose condition can never become false"

    def check(self, ctx):
        out = []
        for node in ast.walk(ctx.tree):
            if not isinstance(node, ast.While):
                continue
            has_break = any(isinstance(n, ast.Break) for n in ast.walk(node))
            has_return = any(isinstance(n, ast.Return) for n in ast.walk(node))
            has_raise = any(isinstance(n, ast.Raise) for n in ast.walk(node))
            # while True without any exit
            if isinstance(node.test, ast.Constant) and node.test.value:
                if not (has_break or has_return or has_raise):
                    out.append(self.finding(
                        node.lineno,
                        "Infinite loop: 'while True' with no break/return/raise in body",
                        evidence="while True: ...",
                        fix_hint="Add a break condition or loop bound."))
                continue
            # while <cond>: condition variables never modified inside the body
            cond_vars = {n.id for n in ast.walk(node.test)
                         if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
            if not cond_vars:
                continue
            modified = set()
            for n in ast.walk(node):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    modified.add(n.id)      # x = ..., for x in ...
                elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
                    modified.add(n.target.id)
                elif isinstance(n, ast.Call):
                    # only a method call ON a condition var may mutate it:
                    # e.g. queue.pop(); NOT a bare read like print(i)
                    f = n.func
                    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                        modified.add(f.value.id)
            if not (cond_vars & modified) and not (has_break or has_return or has_raise):
                out.append(self.finding(
                    node.lineno,
                    f"Potential infinite loop: condition variable(s) "
                    f"{sorted(cond_vars)} never modified in loop body",
                    evidence=f"while {ast.unparse(node.test) if hasattr(ast, 'unparse') else '...'}:",
                    fix_hint="Update the condition variable inside the loop or add a break."))
        return out


class MutableDefaultArgRule(RulePlugin):
    rule_id = "LOG-MUTDEF"
    cwe = "CWE-1188"
    severity = "MEDIUM"
    category = "logic"
    description = "Mutable default argument shared across calls"

    def check(self, ctx):
        out = []
        for node in ast.walk(ctx.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in node.args.defaults + node.args.kw_defaults:
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        out.append(self.finding(
                            node.lineno,
                            f"Function '{node.name}' has a mutable default argument — "
                            "it is shared across ALL calls",
                            evidence=f"def {node.name}(...=[]/{{}}):",
                            fix_hint="Use None as default and create the object inside: "
                                     "if x is None: x = []"))
                        break
        return out


class BareExceptRule(RulePlugin):
    rule_id = "LOG-BAREEXC"
    cwe = "CWE-390"
    severity = "MEDIUM"
    category = "logic"
    description = "Swallowed exception (bare except / except: pass)"

    def check(self, ctx):
        out = []
        for node in ast.walk(ctx.tree):
            if isinstance(node, ast.ExceptHandler):
                bare = node.type is None
                swallow = all(isinstance(s, ast.Pass) for s in node.body)
                if bare or swallow:
                    what = []
                    if bare:
                        what.append("bare 'except:' catches SystemExit/KeyboardInterrupt too")
                    if swallow:
                        what.append("handler silently swallows the error")
                    out.append(self.finding(
                        node.lineno, "; ".join(what).capitalize(),
                        evidence="except: pass" if swallow else "except:",
                        fix_hint="Catch the specific exception type and at minimum log it."))
        return out


class UnreachableCodeRule(RulePlugin):
    rule_id = "LOG-UNREACH"
    cwe = "CWE-561"
    severity = "LOW"
    category = "logic"
    description = "Statements after return/raise/break can never execute"

    def check(self, ctx):
        out = []
        for node in ast.walk(ctx.tree):
            body = getattr(node, "body", None)
            if not isinstance(body, list):
                continue
            for i, stmt in enumerate(body[:-1]):
                if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                    nxt = body[i + 1]
                    out.append(self.finding(
                        nxt.lineno,
                        f"Unreachable code after {type(stmt).__name__.lower()} at L{stmt.lineno}",
                        evidence=ctx.lines[nxt.lineno - 1].strip()[:60] if nxt.lineno <= len(ctx.lines) else "",
                        fix_hint="Remove the dead statements or fix the control flow."))
                    break
        return out
