"""
Taint Analyzer
==============
Interprocedural, flow-sensitive taint analysis over the CFG:

    Source  ->  Propagation  ->  (Sanitizer?)  ->  Sink

  - Forward worklist algorithm over basic blocks (union at join points,
    iterated to a fixed point).
  - Alias-aware propagation (via AliasAnalyzer).
  - Interprocedural via function summaries computed over the call graph:
      * param_to_sink   : calling f(tainted) triggers a sink inside f
      * returns_taint   : f() returns source-derived data
      * param_to_return : f(tainted) returns tainted data
    Summaries are iterated until stable (handles transitive chains).

Sink -> vulnerability mapping follows MITRE CWE identifiers.
"""

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Taint configuration (extensible)
# ---------------------------------------------------------------------------

TAINT_SOURCES = {
    "input", "raw_input", "sys.argv", "argv",
    "os.environ.get", "os.getenv", "environ.get",
    "request.args.get", "request.form.get", "request.values.get",
    "request.args", "request.form", "request.GET.get", "request.POST.get",
    "request.get_json", "request.cookies.get", "request.headers.get",
    "socket.recv", "recv", "readline", "read", "file.read",
    "flask.request", "self.get_argument",
}

SANITIZERS = {
    "int", "float", "bool", "abs", "len", "hash",
    "html.escape", "escape", "cgi.escape", "markupsafe.escape",
    "shlex.quote", "quote", "re.escape",
    "bleach.clean", "urllib.parse.quote", "urllib.parse.quote_plus",
    "secure_filename", "os.path.basename", "basename",
    "str.isdigit", "isdigit", "isalnum",
}

# sink -> (vuln name, CWE, severity)
TAINT_SINKS = {
    "eval":               ("Code Injection via eval()", "CWE-95", "CRITICAL"),
    "exec":               ("Code Injection via exec()", "CWE-94", "CRITICAL"),
    "os.system":          ("OS Command Injection", "CWE-78", "CRITICAL"),
    "os.popen":           ("OS Command Injection", "CWE-78", "CRITICAL"),
    "subprocess.call":    ("Command Injection", "CWE-78", "HIGH"),
    "subprocess.run":     ("Command Injection", "CWE-78", "HIGH"),
    "subprocess.Popen":   ("Command Injection", "CWE-78", "HIGH"),
    "subprocess.check_output": ("Command Injection", "CWE-78", "HIGH"),
    "cursor.execute":     ("SQL Injection", "CWE-89", "CRITICAL"),
    "execute":            ("SQL Injection", "CWE-89", "CRITICAL"),
    "executemany":        ("SQL Injection", "CWE-89", "CRITICAL"),
    "executescript":      ("SQL Injection", "CWE-89", "CRITICAL"),
    "open":               ("Path Traversal", "CWE-22", "HIGH"),
    "os.remove":          ("Path Traversal (delete)", "CWE-22", "HIGH"),
    "os.unlink":          ("Path Traversal (delete)", "CWE-22", "HIGH"),
    "pickle.loads":       ("Insecure Deserialization", "CWE-502", "CRITICAL"),
    "pickle.load":        ("Insecure Deserialization", "CWE-502", "CRITICAL"),
    "yaml.load":          ("Insecure Deserialization", "CWE-502", "HIGH"),
    "marshal.loads":      ("Insecure Deserialization", "CWE-502", "HIGH"),
    "send_file":          ("Path Traversal (send_file)", "CWE-22", "HIGH"),
    "redirect":           ("Open Redirect", "CWE-601", "MEDIUM"),
    "render_template_string": ("Server-Side Template Injection", "CWE-1336", "CRITICAL"),
}


@dataclass
class TaintFinding:
    vuln: str
    cwe: str
    severity: str
    sink: str
    sink_line: int
    source: str
    source_line: int
    variable: str
    function: str
    trace: list = field(default_factory=list)   # [(line, event)]
    interprocedural: bool = False

    def to_dict(self):
        return {
            "rule_id": "TAINT-" + self.cwe,
            "vuln": self.vuln, "cwe": self.cwe, "severity": self.severity,
            "sink": self.sink, "line": self.sink_line,
            "source": self.source, "source_line": self.source_line,
            "variable": self.variable, "function": self.function,
            "interprocedural": self.interprocedural,
            "taint_trace": [f"L{l}: {e}" for l, e in self.trace],
        }


@dataclass
class FunctionSummary:
    name: str
    params: list = field(default_factory=list)
    param_to_sink: dict = field(default_factory=dict)     # param idx -> (sink, line, vuln)
    returns_taint: bool = False
    param_to_return: set = field(default_factory=set)     # param idx set


def _match(name: str, table) -> str | None:
    """Match dotted call name against a config table (exact or suffix)."""
    if name in table:
        return name
    short = name.split(".")[-1]
    if short in table:
        return short
    for entry in table:
        if name.endswith("." + entry):
            return entry
    return None


class TaintAnalyzer:
    def __init__(self, cfgs: dict, call_graph, aliases, function_args: dict):
        """
        cfgs          : {name: CFG}
        call_graph    : CallGraphBuilder
        aliases       : AliasAnalyzer
        function_args : {func_name: [param names]}
        """
        self.cfgs = cfgs
        self.call_graph = call_graph
        self.aliases = aliases
        self.function_args = function_args
        self.summaries: dict[str, FunctionSummary] = {}
        self.findings: list[TaintFinding] = []

    # ------------------------------------------------------------------
    def analyze(self) -> list[TaintFinding]:
        # 1. build summaries iteratively (transitive interprocedural flows)
        for fname, params in self.function_args.items():
            self.summaries[fname] = FunctionSummary(fname, params)
        for _ in range(3):                       # fixed-point over call graph
            changed = False
            for fname in self.function_args:
                if fname in self.cfgs:
                    changed |= self._summarize(fname)
            if not changed:
                break

        # 2. main pass: every CFG with real sources
        seen = set()
        for name, cfg in self.cfgs.items():
            for f in self._run_cfg(cfg, name, initial_taint={}):
                key = (f.cwe, f.sink_line, f.variable)
                if key not in seen:
                    seen.add(key)
                    self.findings.append(f)

        # 3. Entry-point parameter flows. A function that nothing in the
        # analyzed unit calls is an *entry point*: its arguments arrive from
        # outside and are therefore untrusted. When a summary proves such a
        # parameter reaches a dangerous sink with no sanitizer in between,
        # that is a real defect -- and it is the shape most library, handler,
        # and view-function vulnerabilities actually take, since the untrusted
        # value enters through the signature rather than through an inline
        # input() call.
        called = {c["callee"].split(".")[-1]
                  for cfg in self.cfgs.values()
                  for b in cfg.blocks.values()
                  for s in b.statements
                  for c in s.calls}
        covered = {f.sink_line for f in self.findings}
        for fname, summ in self.summaries.items():
            if fname in called or not summ.param_to_sink:
                continue
            for idx, (sink_name, sink_line, vuln_name) in sorted(summ.param_to_sink.items()):
                if sink_line in covered:
                    continue
                param = summ.params[idx] if idx < len(summ.params) else f"arg{idx}"
                matched = _match(sink_name, TAINT_SINKS)
                vuln, cwe, sev = TAINT_SINKS.get(matched, (vuln_name, "CWE-20", "HIGH"))
                key = (cwe, sink_line, param)
                if key in seen:
                    continue
                seen.add(key)
                covered.add(sink_line)
                self.findings.append(TaintFinding(
                    vuln=vuln, cwe=cwe, severity=sev, sink=sink_name,
                    sink_line=sink_line, source="<untrusted parameter>",
                    source_line=0, variable=param, function=fname,
                    trace=[(0, f"parameter '{param}' of entry point {fname}() "
                               f"is untrusted"),
                           (sink_line, f"reaches sink {sink_name}() unsanitized")],
                    interprocedural=True))
        return self.findings

    # ------------------------------------------------------------------
    def _summarize(self, fname: str) -> bool:
        """Run the function CFG with each param tainted; record what happens."""
        summ = self.summaries[fname]
        changed = False
        for idx, param in enumerate(summ.params):
            taint0 = {param: ("<param>", 0, [(0, f"parameter '{param}' assumed tainted")])}
            findings, returned = self._propagate(self.cfgs[fname], fname, taint0,
                                                 collect_return=True)
            if findings and idx not in summ.param_to_sink:
                f0 = findings[0]
                summ.param_to_sink[idx] = (f0.sink, f0.sink_line, f0.vuln)
                changed = True
            if returned and idx not in summ.param_to_return:
                summ.param_to_return.add(idx)
                changed = True
        # does it return source-derived taint with NO tainted params?
        _, returned = self._propagate(self.cfgs[fname], fname, {}, collect_return=True)
        if returned and not summ.returns_taint:
            summ.returns_taint = True
            changed = True
        return changed

    # ------------------------------------------------------------------
    def _run_cfg(self, cfg, func_name, initial_taint):
        findings, _ = self._propagate(cfg, func_name, initial_taint)
        return findings

    def _propagate(self, cfg, func_name, initial_taint, collect_return=False):
        """Forward worklist taint propagation. Returns (findings, return_tainted)."""
        findings = []
        return_tainted = False
        graph = cfg.graph
        state_in: dict[str, dict] = {b: {} for b in cfg.blocks}
        state_in[cfg.entry] = dict(initial_taint)
        work = [cfg.entry]
        visits: dict[str, int] = {}

        while work:
            bid = work.pop(0)
            visits[bid] = visits.get(bid, 0) + 1
            if visits[bid] > 25:                # termination guard
                continue
            taint = dict(state_in.get(bid, {}))
            block = cfg.blocks[bid]

            for s in block.statements:
                new_taint = self._transfer(s, taint, func_name, findings)
                if s.is_return and collect_return:
                    if any(u in taint for u in s.uses) or new_taint.get("<return>"):
                        return_tainted = True
                taint = new_taint

            for succ in graph.successors(bid):
                merged = dict(state_in.get(succ, {}))
                grew = False
                for var, info in taint.items():
                    if var not in merged:
                        merged[var] = info
                        grew = True
                if grew or succ not in state_in or visits.get(succ, 0) == 0:
                    state_in[succ] = merged
                    if succ not in work:
                        work.append(succ)
        return findings, return_tainted

    # ------------------------------------------------------------------
    def _transfer(self, s, taint, func_name, findings):
        """Transfer function for one statement. Returns updated taint map."""
        taint = dict(taint)
        rhs_tainted = None                       # (source, line, trace)

        # (a) does the statement read any tainted variable?
        for var in s.uses:
            if var in taint:
                rhs_tainted = taint[var]
                break

        # Variables that a sanitizer consumes *within this statement* are
        # clean by the time the sink executes. `os.system("ls " + shlex.quote(u))`
        # names both the sink and the sanitizer on one line, and the calls are
        # visited in source order, so without this pre-pass the sink would be
        # judged against the still-tainted argument.
        sanitized_vars: set = set()
        for call in s.calls:
            if _match(call["callee"], SANITIZERS):
                for a in call["args"]:
                    if a[0] == "name":
                        sanitized_vars.add(a[1])
                    elif a[0] == "expr":
                        sanitized_vars |= set(a[1])
        # A sanitized value is often re-wrapped before it reaches the sink, as
        # in `str(int(u))`. Any call whose arguments are all already clean
        # yields a clean result, so one propagation pass over the statement's
        # remaining calls extends the clean set through those wrappers.
        for call in s.calls:
            if _match(call["callee"], SANITIZERS) or _match(call["callee"], TAINT_SINKS):
                continue
            names = set()
            for a in call["args"]:
                if a[0] == "name":
                    names.add(a[1])
                elif a[0] == "expr":
                    names |= set(a[1])
            if names and names <= sanitized_vars:
                sanitized_vars |= names

        for call in s.calls:
            callee = call["callee"]

            # (b) source call?  (skip if the source is wrapped by a sanitizer,
            #     e.g. os.path.basename(input(...)) yields a clean value)
            src = _match(callee, TAINT_SOURCES)
            if src and not self._source_is_sanitized(src, s):
                rhs_tainted = (src, s.lineno,
                               [(s.lineno, f"tainted source: {src}()")])

            # (c) sanitizer call wrapping tainted data -> cleanse
            san = _match(callee, SANITIZERS)
            if san:
                arg_names = {a[1] for a in call["args"] if a[0] == "name"}
                arg_names |= {n for a in call["args"] if a[0] == "expr" for n in a[1]}
                if rhs_tainted and (not arg_names or any(a in taint for a in arg_names)):
                    rhs_tainted = None           # sanitized

            # (d) sink call with tainted argument?
            sink = _match(callee, TAINT_SINKS)
            if sink and self._is_safe_subprocess(callee, call, s):
                sink = None
            if sink:
                tainted_arg = None
                # direct nesting: sink(source())  e.g. os.system(input())
                direct_source = self._nested_source(call, s)
                if direct_source and not _match(callee, SANITIZERS):
                    vuln, cwe, sev = TAINT_SINKS[sink]
                    findings.append(TaintFinding(
                        vuln=vuln, cwe=cwe, severity=sev, sink=callee,
                        sink_line=s.lineno, source=direct_source, source_line=s.lineno,
                        variable="<inline>", function=func_name,
                        trace=[(s.lineno, f"tainted source {direct_source}() passed "
                                          f"directly into sink {callee}()")]))
                for a in call["args"]:
                    if a[0] == "name" and a[1] not in sanitized_vars and (
                            a[1] in taint or self._alias_tainted(func_name, a[1], taint)):
                        tainted_arg = a[1] if a[1] in taint else next(
                            x for x in self.aliases.aliases_of(func_name, a[1]) if x in taint)
                        break
                    if a[0] == "expr":
                        hit = next((n for n in a[1]
                                    if n in taint and n not in sanitized_vars), None)
                        if hit:
                            tainted_arg = hit
                            break
                # parameterized query exception: execute(sql, params) is safe
                if sink in ("execute", "cursor.execute", "executemany") and len(call["args"]) > 1 \
                        and tainted_arg and not self._arg_is_first_tainted(call, taint):
                    tainted_arg = None
                if tainted_arg:
                    vuln, cwe, sev = TAINT_SINKS[sink]
                    origin, oline, trace = taint[tainted_arg]
                    findings.append(TaintFinding(
                        vuln=vuln, cwe=cwe, severity=sev, sink=callee,
                        sink_line=s.lineno, source=origin, source_line=oline,
                        variable=tainted_arg, function=func_name,
                        trace=trace + [(s.lineno, f"reaches sink {callee}()")],
                        interprocedural=origin == "<param>",
                    ))

            # (e) interprocedural: call to summarized user function
            summ = self.summaries.get(callee.split(".")[-1]) or self.summaries.get(callee)
            if summ:
                for idx, a in enumerate(call["args"]):
                    names = {a[1]} if a[0] == "name" else (a[1] if a[0] == "expr" else set())
                    hit = next((n for n in names if n in taint), None)
                    if hit is None:
                        continue
                    if idx in summ.param_to_sink:
                        sink_name, sink_line, vuln_name = summ.param_to_sink[idx]
                        vuln, cwe, sev = next(
                            (v for k, v in TAINT_SINKS.items() if k == _match(sink_name, TAINT_SINKS)),
                            (vuln_name, "CWE-20", "HIGH"))
                        origin, oline, trace = taint[hit]
                        findings.append(TaintFinding(
                            vuln=vuln_name, cwe=cwe, severity=sev,
                            sink=f"{callee}() -> {sink_name}",
                            sink_line=sink_line,          # actual sink line in the callee
                            source=origin, source_line=oline, variable=hit,
                            function=func_name,
                            trace=trace + [(s.lineno, f"passed into {callee}(), "
                                                      f"reaches {sink_name}() at L{sink_line}")],
                            interprocedural=True))
                    if idx in summ.param_to_return:
                        origin, oline, trace = taint[hit]
                        rhs_tainted = (origin, oline,
                                       trace + [(s.lineno, f"returned tainted from {callee}()")])
                if summ.returns_taint:
                    rhs_tainted = (f"{callee}() [returns user input]", s.lineno,
                                   [(s.lineno, f"{callee}() returns tainted data")])

        # (f) propagate into defined variables (+ aliases)
        if rhs_tainted:
            for var in s.defs:
                origin, oline, trace = rhs_tainted
                taint[var] = (origin, oline, trace + [(s.lineno, f"propagates to '{var}'")])
                for al in self.aliases.aliases_of(func_name, var):
                    taint.setdefault(al, taint[var])
        elif s.defs:
            # redefinition with clean value kills taint (flow-sensitivity)
            for var in s.defs:
                if not any(u in taint for u in s.uses):
                    taint.pop(var, None)
        return taint

    @staticmethod
    def _is_safe_subprocess(callee, call, stmt) -> bool:
        """
        True for a ``subprocess`` call that cannot be shell-injected.

        ``subprocess.run(["ping", host], shell=False)`` hands the argument
        vector straight to ``execve``: no shell parses it, so metacharacters
        in ``host`` are inert and the call is safe however untrusted the value
        is. Only the string form, or ``shell=True``, reintroduces the risk.
        Treating the list form as a sink would flag the very construct the
        fix advice recommends.
        """
        import ast as _ast
        if not callee.startswith("subprocess.") and \
                callee.split(".")[-1] not in ("run", "call", "Popen", "check_output",
                                              "check_call"):
            return False
        shell_kw = call.get("keywords", {}).get("shell")
        if shell_kw is not None and shell_kw[0] == "const" and shell_kw[1] is True:
            return False                      # shell=True: a shell does parse it
        node = getattr(stmt, "node", None)
        if node is None:
            return False
        for c in _ast.walk(node):
            if not isinstance(c, _ast.Call):
                continue
            from .ast_analyzer import dotted_name as _dn
            if _dn(c.func) != callee or not c.args:
                continue
            # first positional argument is a literal argv sequence
            return isinstance(c.args[0], (_ast.List, _ast.Tuple))
        return False

    def _alias_tainted(self, scope, name, taint):
        return any(a in taint for a in self.aliases.aliases_of(scope, name))

    @staticmethod
    def _source_is_sanitized(src_name, stmt):
        """True if the source call is nested inside a sanitizer call in this
        statement, e.g. os.path.basename(input()) or int(input())."""
        import ast as _ast
        from .ast_analyzer import dotted_name as _dn
        node = getattr(stmt, "node", None)
        if node is None:
            return False
        for c in _ast.walk(node):
            if isinstance(c, _ast.Call) and _match(_dn(c.func), SANITIZERS):
                for inner in _ast.walk(c):
                    if inner is c:
                        continue
                    if isinstance(inner, _ast.Call) and _match(_dn(inner.func), TAINT_SOURCES) == src_name:
                        return True
        return False

    @staticmethod
    def _nested_source(call, stmt):
        """Detect a source call textually nested inside this sink call's args,
        e.g. os.system(input()). Uses the statement AST node when available."""
        import ast as _ast
        from .ast_analyzer import dotted_name as _dn
        node = getattr(stmt, "node", None)
        if node is None:
            return None
        for c in _ast.walk(node):
            if isinstance(c, _ast.Call) and _dn(c.func) == call["callee"]:
                for arg in list(c.args) + [kw.value for kw in c.keywords]:
                    for inner in _ast.walk(arg):
                        if isinstance(inner, _ast.Call):
                            name = _dn(inner.func)
                            if _match(name, TAINT_SOURCES):
                                return name
        return None

    @staticmethod
    def _arg_is_first_tainted(call, taint):
        if not call["args"]:
            return False
        a = call["args"][0]
        names = {a[1]} if a[0] == "name" else (a[1] if a[0] == "expr" else set())
        return any(n in taint for n in names)


def analyze_taint(cfgs, call_graph, aliases, ast_analyzer) -> list[dict]:
    function_args = {f.name: f.args for f in ast_analyzer.functions}
    analyzer = TaintAnalyzer(cfgs, call_graph, aliases, function_args)
    findings = analyzer.analyze()
    return [f.to_dict() for f in findings]
