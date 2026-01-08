"""
Security Rule Plugins
=====================
CWE-mapped, deterministic security detectors. Taint-based rules consume
the interprocedural taint analysis; pattern rules operate on the AST.
"""

import ast
import math
import re

from ..rule_engine import RulePlugin
from ..ast_analyzer import dotted_name

SECRET_NAME = re.compile(r"(password|passwd|pwd|secret|api_?key|token|auth|credential|private_?key)", re.I)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


class TaintFlowRule(RulePlugin):
    """Surfaces every verified Source->Sink taint flow as a finding."""
    rule_id = "SEC-TAINT"
    cwe = "CWE-89"
    severity = "CRITICAL"
    category = "security"
    description = "Interprocedural taint flow from untrusted source to dangerous sink"

    def check(self, ctx):
        out = []
        for t in ctx.taint_findings:
            trace = " -> ".join(t.get("taint_trace", [])[:6])
            out.append(self.finding(
                line=t["line"],
                message=f"{t['vuln']}: variable '{t['variable']}' from {t['source']} "
                        f"(L{t['source_line']}) reaches sink {t['sink']}()",
                evidence=trace,
                fix_hint="Sanitize/validate the input (parameterized queries, shlex.quote, "
                         "html.escape) before it reaches the sink.",
                severity=t["severity"], cwe=t["cwe"],
            ))
        return out


class HardcodedSecretRule(RulePlugin):
    rule_id = "SEC-SECRET"
    cwe = "CWE-798"
    severity = "HIGH"
    category = "security"
    description = "Hardcoded credential / API key / secret in source"

    def check(self, ctx):
        out = []
        for node in ast.walk(ctx.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                    and isinstance(node.value.value, str) and node.value.value:
                for t in node.targets:
                    if isinstance(t, ast.Name) and SECRET_NAME.search(t.id):
                        val = node.value.value
                        ent = round(_entropy(val), 2)
                        out.append(self.finding(
                            node.lineno,
                            f"Hardcoded secret in variable '{t.id}' (entropy={ent})",
                            evidence=f'{t.id} = "{val[:4]}{"*" * min(8, len(val))}"',
                            fix_hint="Load secrets from environment variables or a vault "
                                     "(os.environ / python-dotenv), never commit them.",
                        ))
        return out


class WeakHashRule(RulePlugin):
    rule_id = "SEC-WEAKHASH"
    cwe = "CWE-327"
    severity = "MEDIUM"
    category = "security"
    description = "Cryptographically broken hash (MD5 / SHA1)"

    WEAK = {"hashlib.md5": "MD5", "md5": "MD5", "hashlib.sha1": "SHA1", "sha1": "SHA1"}

    def check(self, ctx):
        out = []
        for node in ast.walk(ctx.tree):
            if isinstance(node, ast.Call):
                name = dotted_name(node.func)
                algo = self.WEAK.get(name) or self.WEAK.get(name.split(".")[-1])
                if name.split(".")[-1] == "new" and node.args:      # hashlib.new("md5")
                    a0 = node.args[0]
                    if isinstance(a0, ast.Constant) and str(a0.value).lower() in ("md5", "sha1"):
                        algo = str(a0.value).upper()
                if algo:
                    out.append(self.finding(
                        node.lineno,
                        f"Use of cryptographically broken hash function {algo}",
                        evidence=f"{name}(...)",
                        fix_hint="Use hashlib.sha256 / sha3_256, or bcrypt/argon2 for passwords.",
                    ))
        return out


class UnsafeCallRule(RulePlugin):
    """Direct use of dangerous primitives even without a confirmed taint flow."""
    rule_id = "SEC-UNSAFE"
    cwe = "CWE-676"
    severity = "MEDIUM"
    category = "security"
    description = "Dangerous primitive (eval/exec/pickle/yaml.load/shell=True)"

    DANGEROUS = {
        "eval": ("eval() executes arbitrary expressions", "CWE-95", "HIGH"),
        "exec": ("exec() executes arbitrary code", "CWE-94", "HIGH"),
        "pickle.loads": ("pickle can execute code on load", "CWE-502", "MEDIUM"),
        "pickle.load": ("pickle can execute code on load", "CWE-502", "MEDIUM"),
        "yaml.load": ("yaml.load without SafeLoader is unsafe", "CWE-502", "MEDIUM"),
        "tempfile.mktemp": ("race-prone temp file creation", "CWE-377", "MEDIUM"),
        "assert": ("", "", ""),
    }

    def check(self, ctx):
        out = []
        taint_lines = {t["line"] for t in ctx.taint_findings}
        for node in ast.walk(ctx.tree):
            if isinstance(node, ast.Call):
                name = dotted_name(node.func)
                key = name if name in self.DANGEROUS else name.split(".")[-1]
                info = self.DANGEROUS.get(name) or (
                    self.DANGEROUS.get(key) if key in ("eval", "exec") else None)
                if name == "yaml.load":
                    safe = any(k == "Loader" for k in
                               [kw.arg for kw in node.keywords])
                    if safe:
                        info = None
                if info and info[0] and node.lineno not in taint_lines:
                    out.append(self.finding(
                        node.lineno, info[0], evidence=f"{name}(...)",
                        fix_hint="Replace with a safe alternative "
                                 "(ast.literal_eval, yaml.safe_load, json).",
                        cwe=info[1], severity=info[2]))
                # subprocess shell=True
                if name.startswith("subprocess.") and node.lineno not in taint_lines:
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            out.append(self.finding(
                                node.lineno, "subprocess with shell=True enables command injection",
                                evidence=f"{name}(..., shell=True)",
                                fix_hint="Pass an argument list and shell=False.",
                                cwe="CWE-78", severity="HIGH"))
        return out


class CommandConcatRule(RulePlugin):
    """A command sink (os.system/os.popen/subprocess) fed a variable that was
    locally built by string concatenation — a classic command-injection shape
    that survives even when the tainted seed is a function parameter."""
    rule_id = "SEC-CMDCONCAT"
    cwe = "CWE-78"
    severity = "HIGH"
    category = "security"
    description = "Command sink fed a concatenation-built string"

    SINKS = {"os.system", "os.popen", "system", "popen",
             "subprocess.call", "subprocess.run", "subprocess.Popen",
             "subprocess.check_output", "call", "run", "Popen"}

    def check(self, ctx):
        out = []
        taint_lines = {t["line"] for t in ctx.taint_findings}
        # variables whose definition is a str concatenation (BinOp with +)
        concat_vars = {}
        for node in ast.walk(ctx.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.BinOp) \
                    and isinstance(node.value.op, ast.Add):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        concat_vars[t.id] = node.lineno
        for node in ast.walk(ctx.tree):
            if isinstance(node, ast.Call):
                name = dotted_name(node.func)
                if name in self.SINKS or name.split(".")[-1] in self.SINKS:
                    for a in node.args:
                        if isinstance(a, ast.Name) and a.id in concat_vars \
                                and node.lineno not in taint_lines:
                            out.append(self.finding(
                                node.lineno,
                                f"Command sink {name}() receives '{a.id}', a "
                                f"concatenation-built string (defined at "
                                f"L{concat_vars[a.id]}) — command injection risk",
                                evidence=f"{name}({a.id})",
                                fix_hint="Pass an argument list with shell=False and "
                                         "validate each token."))
                            break
        return out


class SQLStringBuildRule(RulePlugin):
    """SQL query assembled with string concatenation / f-string (even before execute)."""
    rule_id = "SEC-SQLBUILD"
    cwe = "CWE-89"
    severity = "MEDIUM"
    category = "security"
    description = "SQL built by string formatting/concatenation"

    SQL = re.compile(r"^\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s", re.I)

    def check(self, ctx):
        out = []
        # Suppress this pattern wherever taint analysis has already proven the
        # same injection. A proven flow spans several lines -- the query is
        # assembled on one and executed on another -- so matching only the sink
        # line reports a single defect twice: once as a proven flow at the
        # execute() call and again as a pattern at the concatenation.
        taint_lines = set()
        for t in ctx.taint_findings:
            if t.get("cwe") != self.cwe:
                continue
            sink = t["line"]
            # An entry-point flow reports source_line 0 because the untrusted
            # value arrives through the signature, so fall back to the
            # enclosing function's span; otherwise use the proven source.
            src = t.get("source_line") or 0
            if src <= 0:
                fn = next((f for f in ctx.ast_analyzer.functions
                           if f.name == t.get("function")), None)
                src = fn.lineno if fn is not None else sink
            taint_lines.update(range(min(src, sink), sink + 1))
        for node in ast.walk(ctx.tree):
            sql_part = None
            if isinstance(node, ast.JoinedStr):        # f-string
                for v in node.values:
                    if isinstance(v, ast.Constant) and isinstance(v.value, str) \
                            and self.SQL.match(v.value):
                        sql_part = v.value
            elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
                left = node.left
                if isinstance(left, ast.Constant) and isinstance(left.value, str) \
                        and self.SQL.match(left.value):
                    sql_part = left.value
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "format":
                # 'SELECT ... {}'.format(user) — injectable string building
                recv = node.func.value
                if isinstance(recv, ast.Constant) and isinstance(recv.value, str) \
                        and self.SQL.match(recv.value) and node.args:
                    sql_part = recv.value
            if sql_part and node.lineno not in taint_lines:
                out.append(self.finding(
                    node.lineno,
                    "SQL query assembled with string interpolation — injectable if any "
                    "operand is user-controlled",
                    evidence=sql_part.strip()[:60],
                    fix_hint='Use parameterized queries: cursor.execute("... WHERE id=?", (uid,))',
                ))
        return out
