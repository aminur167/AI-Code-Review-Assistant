"""
Universal Taint Analyzer
========================
Flow-sensitive, alias-aware, **interprocedural** taint analysis for C, C++,
Java, and JavaScript, operating on the Universal IR CFGs.

This module replaces the earlier line-oriented "taint-lite" tracker with the
same analysis quality the Python pipeline provides:

    Source -> Propagation -> (Sanitizer) -> Sink

  * Forward worklist over basic blocks, union at join points, iterated to a
    fixed point (so taint that arrives on only one branch is still seen at
    the merge).
  * Alias-aware: taint flows through reference copies (``b = a``, ``p = &q``).
  * Interprocedural via function summaries computed over the call graph:
      ``param_to_sink``   -- calling ``f(tainted)`` triggers a sink inside ``f``
      ``returns_taint``   -- ``f()`` returns source-derived data
      ``param_to_return`` -- ``f(tainted)`` returns tainted data
    Summaries are iterated until stable, so transitive chains
    (``read -> wrap -> helper -> system``) are resolved.
  * Sanitizer-aware: a value that passes through a recognized validator or
    encoder is cleared, which is what keeps the false-positive rate low on
    benign twins that *do* validate their input.

Every sink is mapped to a MITRE CWE identifier. Language-specific tables are
kept separate because the dangerous API surface genuinely differs (``strcpy``
matters in C, ``innerHTML`` in JavaScript), while the *algorithm* is shared.
"""

from __future__ import annotations

from .taint_analyzer import TaintFinding, FunctionSummary

# ---------------------------------------------------------------------------
# Language-specific taint configuration
# ---------------------------------------------------------------------------
# Each entry: sink name -> (vulnerability, CWE, severity)

_C_SINKS = {
    # --- command execution (CWE-78) -------------------------------------
    "system": ("OS Command Injection", "CWE-78", "CRITICAL"),
    "popen": ("OS Command Injection", "CWE-78", "CRITICAL"),
    "_popen": ("OS Command Injection", "CWE-78", "CRITICAL"),
    "execl": ("OS Command Injection", "CWE-78", "HIGH"),
    "execlp": ("OS Command Injection", "CWE-78", "HIGH"),
    "execle": ("OS Command Injection", "CWE-78", "HIGH"),
    "execv": ("OS Command Injection", "CWE-78", "HIGH"),
    "execvp": ("OS Command Injection", "CWE-78", "HIGH"),
    "execve": ("OS Command Injection", "CWE-78", "HIGH"),
    "EXECL": ("OS Command Injection", "CWE-78", "HIGH"),
    "EXECLP": ("OS Command Injection", "CWE-78", "HIGH"),
    "EXECV": ("OS Command Injection", "CWE-78", "HIGH"),
    "EXECVP": ("OS Command Injection", "CWE-78", "HIGH"),
    "SYSTEM": ("OS Command Injection", "CWE-78", "CRITICAL"),
    # Windows process-spawn family used throughout the Juliet CWE-78 tests
    "_spawnl": ("OS Command Injection", "CWE-78", "HIGH"),
    "_spawnlp": ("OS Command Injection", "CWE-78", "HIGH"),
    "_spawnv": ("OS Command Injection", "CWE-78", "HIGH"),
    "_spawnvp": ("OS Command Injection", "CWE-78", "HIGH"),
    "SPAWNL": ("OS Command Injection", "CWE-78", "HIGH"),
    "SPAWNV": ("OS Command Injection", "CWE-78", "HIGH"),
    # wide-character (UTF-16) variants of the same Windows APIs
    "_wspawnl": ("OS Command Injection", "CWE-78", "HIGH"),
    "_wspawnlp": ("OS Command Injection", "CWE-78", "HIGH"),
    "_wspawnv": ("OS Command Injection", "CWE-78", "HIGH"),
    "_wspawnvp": ("OS Command Injection", "CWE-78", "HIGH"),
    "_wsystem": ("OS Command Injection", "CWE-78", "CRITICAL"),
    "_wpopen": ("OS Command Injection", "CWE-78", "CRITICAL"),
    "_wexecl": ("OS Command Injection", "CWE-78", "HIGH"),
    "_wexecv": ("OS Command Injection", "CWE-78", "HIGH"),
    "_wexecvp": ("OS Command Injection", "CWE-78", "HIGH"),
    "CreateProcess": ("OS Command Injection", "CWE-78", "HIGH"),
    "CreateProcessA": ("OS Command Injection", "CWE-78", "HIGH"),
    "CreateProcessW": ("OS Command Injection", "CWE-78", "HIGH"),
    "ShellExecute": ("OS Command Injection", "CWE-78", "HIGH"),
    "WinExec": ("OS Command Injection", "CWE-78", "HIGH"),
    # --- memory safety (CWE-120) ----------------------------------------
    "strcpy": ("Buffer Overflow", "CWE-120", "HIGH"),
    "strcat": ("Buffer Overflow", "CWE-120", "HIGH"),
    "wcscpy": ("Buffer Overflow", "CWE-120", "HIGH"),
    "wcscat": ("Buffer Overflow", "CWE-120", "HIGH"),
    "sprintf": ("Buffer Overflow", "CWE-120", "HIGH"),
    "vsprintf": ("Buffer Overflow", "CWE-120", "HIGH"),
    "swprintf": ("Buffer Overflow", "CWE-120", "MEDIUM"),
    "gets": ("Buffer Overflow", "CWE-120", "CRITICAL"),
    "memcpy": ("Buffer Overflow", "CWE-120", "HIGH"),
    "memmove": ("Buffer Overflow", "CWE-120", "MEDIUM"),
    "wmemcpy": ("Buffer Overflow", "CWE-120", "HIGH"),
    "wmemmove": ("Buffer Overflow", "CWE-120", "MEDIUM"),
    "alloca": ("Stack Overflow via alloca", "CWE-770", "MEDIUM"),
    # --- path traversal (CWE-22) ----------------------------------------
    "fopen": ("Path Traversal", "CWE-22", "HIGH"),
    "freopen": ("Path Traversal", "CWE-22", "HIGH"),
    "_wfopen": ("Path Traversal", "CWE-22", "HIGH"),
    "open": ("Path Traversal", "CWE-22", "HIGH"),
    "remove": ("Path Traversal (delete)", "CWE-22", "HIGH"),
    "unlink": ("Path Traversal (delete)", "CWE-22", "HIGH"),
    "CreateFile": ("Path Traversal", "CWE-22", "MEDIUM"),
    # --- format string (CWE-134) ----------------------------------------
    "printf": ("Format String", "CWE-134", "HIGH"),
    "fprintf": ("Format String", "CWE-134", "MEDIUM"),
    "vfprintf": ("Format String", "CWE-134", "MEDIUM"),
    "vprintf": ("Format String", "CWE-134", "HIGH"),
    "syslog": ("Format String", "CWE-134", "MEDIUM"),
}

_JAVA_SINKS = {
    "executeQuery": ("SQL Injection", "CWE-89", "CRITICAL"),
    "executeUpdate": ("SQL Injection", "CWE-89", "CRITICAL"),
    "execute": ("SQL Injection", "CWE-89", "CRITICAL"),
    "addBatch": ("SQL Injection", "CWE-89", "HIGH"),
    "createQuery": ("SQL Injection", "CWE-89", "HIGH"),
    "Runtime.getRuntime.exec": ("OS Command Injection", "CWE-78", "CRITICAL"),
    "exec": ("OS Command Injection", "CWE-78", "CRITICAL"),
    "ProcessBuilder": ("OS Command Injection", "CWE-78", "HIGH"),
    "readObject": ("Insecure Deserialization", "CWE-502", "CRITICAL"),
    "ObjectInputStream": ("Insecure Deserialization", "CWE-502", "HIGH"),
    "FileInputStream": ("Path Traversal", "CWE-22", "HIGH"),
    "FileOutputStream": ("Path Traversal", "CWE-22", "HIGH"),
    "FileReader": ("Path Traversal", "CWE-22", "HIGH"),
    "File": ("Path Traversal", "CWE-22", "MEDIUM"),
    "getWriter.println": ("Cross-Site Scripting", "CWE-79", "HIGH"),
    "sendRedirect": ("Open Redirect", "CWE-601", "MEDIUM"),
}

_JS_SINKS = {
    "eval": ("Code Injection via eval()", "CWE-95", "CRITICAL"),
    "Function": ("Code Injection via Function()", "CWE-95", "HIGH"),
    "setTimeout": ("Code Injection via setTimeout(string)", "CWE-95", "MEDIUM"),
    "setInterval": ("Code Injection via setInterval(string)", "CWE-95", "MEDIUM"),
    "child_process.exec": ("OS Command Injection", "CWE-78", "CRITICAL"),
    "child_process.execSync": ("OS Command Injection", "CWE-78", "CRITICAL"),
    "exec": ("OS Command Injection", "CWE-78", "CRITICAL"),
    "execSync": ("OS Command Injection", "CWE-78", "CRITICAL"),
    "spawn": ("OS Command Injection", "CWE-78", "HIGH"),
    "query": ("SQL Injection", "CWE-89", "CRITICAL"),
    "document.write": ("Cross-Site Scripting", "CWE-79", "HIGH"),
    "insertAdjacentHTML": ("Cross-Site Scripting", "CWE-79", "HIGH"),
    "fs.readFile": ("Path Traversal", "CWE-22", "HIGH"),
    "fs.readFileSync": ("Path Traversal", "CWE-22", "HIGH"),
    "fs.writeFile": ("Path Traversal", "CWE-22", "HIGH"),
    "fs.unlink": ("Path Traversal (delete)", "CWE-22", "HIGH"),
    "readFile": ("Path Traversal", "CWE-22", "MEDIUM"),
    "JSON.parse": ("Insecure Deserialization", "CWE-502", "LOW"),
}

# assignment targets that are XSS sinks (property writes, not calls)
_JS_SINK_PROPERTIES = {
    "innerHTML": ("Cross-Site Scripting", "CWE-79", "HIGH"),
    "outerHTML": ("Cross-Site Scripting", "CWE-79", "HIGH"),
    "dangerouslySetInnerHTML": ("Cross-Site Scripting", "CWE-79", "MEDIUM"),
}

_C_SOURCES = {
    "gets", "fgets", "fgetws", "scanf", "fscanf", "sscanf", "swscanf",
    "wscanf", "read", "recv", "recvfrom", "accept",
    "getenv", "_wgetenv", "GETENV", "fread", "readline", "getline",
    "argv", "cin", "wcin", "getchar", "fgetc",
    # Juliet's generated helpers that stand in for untrusted input
    "RECV", "READ", "FGETS", "SCANF",
}
_JAVA_SOURCES = {
    "getParameter", "getParameterValues", "getHeader", "getQueryString",
    "getInputStream", "getReader", "getCookies", "getRequestURI",
    "getRequestURL", "System.getenv", "getenv", "getProperty",
    "readLine", "nextLine", "next", "nextInt", "getRemoteUser",
    "getPathInfo", "getPathTranslated", "getAttribute",
}
_JS_SOURCES = {
    "req.query", "req.body", "req.params", "req.headers", "req.cookies",
    "request.query", "request.body", "request.params",
    "process.argv", "process.env", "location.hash", "location.search",
    "location.href", "document.URL", "document.referrer", "window.name",
    "localStorage.getItem", "sessionStorage.getItem", "prompt",
    "url.parse", "querystring.parse",
}

_C_SANITIZERS = {
    # Conversions to a numeric type genuinely destroy attacker control over
    # the value's *content*, which is what a sanitizer must do.
    "atoi", "atol", "atof", "strtol", "strtoul", "strtod",
    "isalnum", "isdigit", "isalpha", "basename", "realpath",
}

# Bounded copies are NOT sanitizers. `strncat(dst, tainted, n)` limits how
# many bytes are written -- it prevents the overflow -- but the bytes that do
# land in `dst` are still attacker-controlled, so a later `system(dst)` is
# still command injection. Treating them as sanitizers silently terminated
# every flow that passed through one, which is the single most common shape
# in the Juliet command-injection tests.
_BOUNDED_COPY_PROPAGATES = {
    "strncpy", "strncat", "snprintf", "strlcpy", "strlcat",
    "wcsncpy", "wcsncat", "swprintf", "memcpy_s", "strcpy_s", "strcat_s",
}
_JAVA_SANITIZERS = {
    "parseInt", "parseLong", "parseDouble", "parseFloat", "valueOf",
    "Integer.parseInt", "Long.parseLong", "Double.parseDouble",
    "encode", "escapeHtml", "escapeHtml4", "escapeSql", "escapeJava",
    "StringEscapeUtils.escapeHtml4", "URLEncoder.encode",
    "matches", "replaceAll", "getName", "getCanonicalPath",
    "setString", "setInt", "setLong",           # PreparedStatement binding
}
_JS_SANITIZERS = {
    "parseInt", "parseFloat", "Number", "encodeURI", "encodeURIComponent",
    "escape", "escapeHtml", "sanitize", "DOMPurify.sanitize",
    "path.basename", "basename", "validator.escape", "textContent",
    "JSON.stringify",
}

LANG_CONFIG = {
    "C": (_C_SOURCES, _C_SANITIZERS, _C_SINKS, {}),
    "C++": (_C_SOURCES | {"getline", "cin"}, _C_SANITIZERS,
            dict(_C_SINKS, **{"system": ("OS Command Injection", "CWE-78", "CRITICAL")}), {}),
    "Java": (_JAVA_SOURCES, _JAVA_SANITIZERS, _JAVA_SINKS, {}),
    "JavaScript": (_JS_SOURCES, _JS_SANITIZERS, _JS_SINKS, _JS_SINK_PROPERTIES),
}

# Sinks whose *first* argument is a destination buffer rather than the
# attacker-controlled value; taint in a later argument is what matters.
_DEST_FIRST_SINKS = {"strcpy", "strcat", "memcpy", "memmove", "sprintf", "vsprintf"}

# Every copy routine whose first argument is the destination buffer. Taint in
# any later argument flows *into* that destination, whether or not the copy is
# length-bounded, so the chain
#   environment = getenv(...); strncat(data, environment, n); system(data)
# stays connected end to end.
_COPY_DEST_FIRST = _DEST_FIRST_SINKS | _BOUNDED_COPY_PROPAGATES

# Java/JS calls that make a query safe when the tainted value is *bound*
# rather than concatenated.
_PARAMETERIZED = {"prepareStatement", "setString", "setInt", "setLong",
                  "setDouble", "createQuery", "setParameter"}

# Builder-style APIs that accumulate their argument into the receiver, and the
# methods that read the accumulated value back out.
_BUILDER_MUTATORS = {"append", "insert", "concat", "add", "push", "write",
                     "addAll", "put", "format"}
_BUILDER_READERS = {"toString", "build", "join", "getvalue", "toValue", "str"}


def _match(name: str, table) -> str | None:
    """
    Match a (possibly dotted) callee against a configuration table.

    Resolution order is most-specific first: an exact hit, then a
    fully-qualified suffix (``a.b.exec`` matching the entry ``b.exec``), then
    the bare method name. The bare-name step is what lets
    ``Runtime.getRuntime().exec(cmd)`` -- which tree-sitter surfaces simply as
    ``exec`` -- resolve to the command-execution sink.
    """
    if not name:
        return None
    if name in table:
        return name
    for entry in table:                      # qualified suffix, e.g. cp.execSync
        if "." in entry and name.endswith("." + entry):
            return entry
    short = name.split(".")[-1]
    if short in table:
        return short
    for entry in table:                      # entry is a suffix of the callee
        if name.endswith("." + entry):
            return entry
    return None


def _is_param_decl(stmt) -> bool:
    """True for the synthetic entry-block statements that declare parameters."""
    return stmt.lineno == 0 and str(stmt.text).startswith("param ")


def _prefix_match(name: str, table) -> str | None:
    """Match dotted *paths* such as ``req.query.name`` against ``req.query``."""
    if not name:
        return None
    hit = _match(name, table)
    if hit:
        return hit
    for entry in table:
        if "." in entry and name.startswith(entry + "."):
            return entry
    return None


class UIRTaintAnalyzer:
    """Interprocedural taint analysis over Universal IR CFGs."""

    MAX_BLOCK_VISITS = 25
    SUMMARY_ROUNDS = 3

    def __init__(self, cfgs: dict, aliases, function_args: dict, language: str):
        self.cfgs = cfgs
        self.aliases = aliases
        self.function_args = function_args
        self.language = language
        sources, sanitizers, sinks, sink_props = LANG_CONFIG.get(
            language, (set(), set(), {}, {}))
        self.SOURCES = sources
        self.SANITIZERS = sanitizers
        self.SINKS = sinks
        self.SINK_PROPERTIES = sink_props
        self.summaries: dict[str, FunctionSummary] = {}
        self.findings: list[TaintFinding] = []

    # ------------------------------------------------------------------
    def analyze(self) -> list[TaintFinding]:
        for fname, params in self.function_args.items():
            self.summaries[fname] = FunctionSummary(fname, params)
        for _ in range(self.SUMMARY_ROUNDS):
            changed = False
            for fname in self.function_args:
                if fname in self.cfgs:
                    changed |= self._summarize(fname)
            if not changed:
                break

        seen = set()
        for name, cfg in self.cfgs.items():
            for f in self._propagate(cfg, name, {})[0]:
                key = (f.cwe, f.sink_line, f.variable)
                if key not in seen:
                    seen.add(key)
                    self.findings.append(f)

        # Entry-point parameter flows. A function that is never called within
        # the analyzed unit is an *entry point*: its parameters come from
        # outside and are therefore untrusted. If a summary proves that such a
        # parameter reaches a dangerous sink without passing a sanitizer, that
        # is a genuine defect, and it is exactly the shape most real
        # vulnerabilities take in library and handler code.
        called = {c.split(".")[-1] for cfg in self.cfgs.values()
                  for b in cfg.blocks.values()
                  for s in b.statements
                  for c in (x["callee"] for x in s.calls)}
        # Lines already explained by an intraprocedural source->sink flow must
        # not be reported a second time from the parameter's point of view;
        # one defect must yield exactly one finding.
        covered_lines = {f.sink_line for f in self.findings}
        for fname, summ in self.summaries.items():
            if fname in called or not summ.param_to_sink:
                continue
            for idx, (sink_name, sink_line, vuln_name) in sorted(summ.param_to_sink.items()):
                if sink_line in covered_lines:
                    continue
                param = summ.params[idx] if idx < len(summ.params) else f"arg{idx}"
                vuln, cwe, sev = self._classify(sink_name, vuln_name)
                key = (cwe, sink_line, param)
                if key in seen:
                    continue
                seen.add(key)
                covered_lines.add(sink_line)
                self.findings.append(TaintFinding(
                    vuln=vuln, cwe=cwe, severity=sev, sink=sink_name,
                    sink_line=sink_line, source="<untrusted parameter>",
                    source_line=0, variable=param, function=fname,
                    trace=[(0, f"parameter '{param}' of entry point {fname}() is untrusted"),
                           (sink_line, f"reaches sink {sink_name}() unsanitized")],
                    interprocedural=True))
        return self.findings

    # ------------------------------------------------------------------
    def _summarize(self, fname: str) -> bool:
        summ = self.summaries[fname]
        changed = False
        for idx, param in enumerate(summ.params):
            taint0 = {param: ("<param>", 0,
                              [(0, f"parameter '{param}' assumed tainted")])}
            findings, returned = self._propagate(self.cfgs[fname], fname, taint0,
                                                 collect_return=True)
            if findings and idx not in summ.param_to_sink:
                f0 = findings[0]
                summ.param_to_sink[idx] = (f0.sink, f0.sink_line, f0.vuln)
                changed = True
            if returned and idx not in summ.param_to_return:
                summ.param_to_return.add(idx)
                changed = True
        _, returned = self._propagate(self.cfgs[fname], fname, {}, collect_return=True)
        if returned and not summ.returns_taint:
            summ.returns_taint = True
            changed = True
        return changed

    # ------------------------------------------------------------------
    def _propagate(self, cfg, func_name, initial_taint, collect_return=False):
        """Forward worklist propagation. Returns (findings, return_tainted)."""
        findings: list[TaintFinding] = []
        return_tainted = False
        graph = cfg.graph
        state_in: dict[str, dict] = {b: {} for b in cfg.blocks}
        state_in[cfg.entry] = dict(initial_taint)
        work = [cfg.entry]
        visits: dict[str, int] = {}

        while work:
            bid = work.pop(0)
            visits[bid] = visits.get(bid, 0) + 1
            if visits[bid] > self.MAX_BLOCK_VISITS:
                continue
            taint = dict(state_in.get(bid, {}))
            block = cfg.blocks[bid]

            for s in block.statements:
                new_taint = self._transfer(s, taint, func_name, findings)
                if s.is_return and collect_return:
                    if any(u in taint for u in s.uses):
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
        """Transfer function for a single statement."""
        taint = dict(taint)
        rhs_tainted = None

        # (a) reading a tainted variable taints the statement's value.
        # This also covers aggregate initialization: `char *args[] = {p, data}`
        # uses `data`, so the array `args` inherits the taint and a later
        # `execv(path, args)` is still recognized as reachable.
        for var in s.uses:
            if var in taint:
                rhs_tainted = taint[var]
                break

        # (b) A use that is itself a source path, e.g. `req.query.name`.
        # Skipped when the statement also applies a sanitizer, because the
        # sanitizer consumes that very value: in
        # `const n = encodeURIComponent(req.query.name)` the untrusted path is
        # an argument to the encoder, so what reaches `n` is already clean.
        _stmt_sanitizes = any(_match(c["callee"], self.SANITIZERS) for c in s.calls)
        if rhs_tainted is None and not _stmt_sanitizes:
            for var in s.uses:
                hit = _prefix_match(var, self.SOURCES)
                if hit:
                    rhs_tainted = (hit, s.lineno,
                                   [(s.lineno, f"tainted source: {var}")])
                    break

        sanitized_here = False
        for call in s.calls:
            callee = call["callee"]
            short = callee.split(".")[-1]

            # (b2) Mutating builder methods write their argument *into* the
            # receiver, so `sb.append(userInput)` taints `sb` itself and a
            # later `sb.toString()` carries the taint to the sink. Without
            # this, SQL assembled through StringBuilder -- the idiomatic Java
            # form -- would be invisible.
            if short in _BUILDER_MUTATORS:
                arg_names = {a[1] for a in call["args"] if a[0] == "name"}
                arg_names |= {n for a in call["args"] if a[0] == "expr" for n in a[1]}
                hit = next((a for a in arg_names if a in taint), None)
                if hit:
                    origin, oline, trace = taint[hit]
                    for receiver in self._receivers_of(callee, s, arg_names):
                        taint[receiver] = (origin, oline,
                                           trace + [(s.lineno,
                                                     f"appended into '{receiver}'")])
            # A read-back method inherits the receiver's taint.
            if short in _BUILDER_READERS:
                for receiver in self._receivers_of(callee, s, set()):
                    if receiver in taint:
                        rhs_tainted = taint[receiver]
                        break

            # (c) Source call. A source whose result is consumed by a
            # sanitizer in the same statement produces a clean value:
            # `Integer.parseInt(request.getParameter("u"))` yields an int, not
            # attacker-controlled text, so it must not seed taint.
            src = _match(callee, self.SOURCES)
            if src and _stmt_sanitizes and not _match(callee, self.SANITIZERS):
                src = None
            if src:
                rhs_tainted = (src, s.lineno,
                               [(s.lineno, f"tainted source: {src}()")])
                # A read-into-buffer source (gets/fgets/scanf/recv) writes the
                # untrusted bytes into its destination argument, so that
                # buffer becomes tainted even though nothing is assigned.
                # The destination is routinely an offset expression, as in
                # `fgets(data + dataLen, n, f)`, so expression arguments taint
                # each variable they read -- assigning rather than
                # `setdefault`, because a buffer that already held clean data
                # is untrusted once a source has written into it.
                for a in call["args"]:
                    names = ({a[1]} if a[0] == "name"
                             else (set(a[1]) if a[0] == "expr" else set()))
                    for n in names:
                        taint[n] = (src, s.lineno,
                                    [(s.lineno, f"buffer filled by {src}()")])

            # (d) sanitizer clears taint
            san = _match(callee, self.SANITIZERS)
            if san:
                arg_names = {a[1] for a in call["args"] if a[0] == "name"}
                arg_names |= {n for a in call["args"] if a[0] == "expr" for n in a[1]}
                if not arg_names or any(a in taint for a in arg_names):
                    rhs_tainted = None
                    sanitized_here = True
                for a in arg_names:                    # bound parameter is safe
                    if _match(callee, _PARAMETERIZED):
                        taint.pop(a, None)

            # (d2) Copy routines move taint into their destination buffer.
            # This runs for *every* copy, bounded or not: a length limit stops
            # an overflow but does not make the copied bytes trustworthy, so
            #   env = getenv(); strncat(data, env, n); system(data)
            # must stay connected. The destination is frequently an offset
            # expression (`data+dataLen`), so expression arguments contribute
            # each of their base variables.
            if _match(callee, _COPY_DEST_FIRST) and len(call["args"]) > 1:
                src_names = set()
                for a in call["args"][1:]:
                    if a[0] == "name":
                        src_names.add(a[1])
                    elif a[0] == "expr":
                        src_names |= set(a[1])
                hit = next((n for n in src_names if n in taint), None)
                if hit:
                    origin, oline, trace = taint[hit]
                    dest = call["args"][0]
                    dnames = ({dest[1]} if dest[0] == "name"
                              else (set(dest[1]) if dest[0] == "expr" else set()))
                    for dn in dnames:
                        taint[dn] = (origin, oline,
                                     trace + [(s.lineno,
                                               f"copied into '{dn}' by {callee}()")])

            # (e) sink call carrying tainted data. A call that is *both* a
            # source and a sink (e.g. `gets(buf)`) is reported by the rule
            # engine as an unbounded-read defect, not here -- otherwise the
            # taint it introduces would immediately "reach" itself.
            sink = _match(callee, self.SINKS)
            if sink and src:
                sink = None
            # `printf("%s", data)` is the recommended fix for CWE-134, not an
            # instance of it: the format is a literal, so tainted data is
            # consumed as an argument and never parsed as a directive.
            if sink and self._format_is_literal(call, sink):
                sink = None
            if sink and not sanitized_here:
                tainted_arg = self._tainted_argument(call, taint, func_name, sink)
                if tainted_arg:
                    vuln, cwe, sev = self.SINKS[sink]
                    origin, oline, trace = taint[tainted_arg]
                    findings.append(TaintFinding(
                        vuln=vuln, cwe=cwe, severity=sev, sink=callee,
                        sink_line=s.lineno, source=origin, source_line=oline,
                        variable=tainted_arg, function=func_name,
                        trace=trace + [(s.lineno, f"reaches sink {callee}()")],
                        interprocedural=origin == "<param>"))
                    # A copy-style sink also *writes* the tainted data into its
                    # destination buffer, so the taint keeps flowing:
                    #   sprintf(cmd, "ls %s", user) ; system(cmd)
                    if sink in _DEST_FIRST_SINKS and call["args"]:
                        dest = call["args"][0]
                        dnames = ({dest[1]} if dest[0] == "name"
                                  else (dest[1] if dest[0] == "expr" else set()))
                        for dn in dnames:
                            taint[dn] = (origin, oline,
                                         trace + [(s.lineno,
                                                   f"copied into '{dn}' by {callee}()")])

            # (f) interprocedural: user function with a summary
            summ = self.summaries.get(callee.split(".")[-1]) or self.summaries.get(callee)
            if summ:
                for idx, a in enumerate(call["args"]):
                    names = {a[1]} if a[0] == "name" else (a[1] if a[0] == "expr" else set())
                    hit = next((n for n in names if n in taint), None)
                    if hit is None:
                        continue
                    if idx in summ.param_to_sink:
                        sink_name, sink_line, vuln_name = summ.param_to_sink[idx]
                        vuln, cwe, sev = self._classify(sink_name, vuln_name)
                        origin, oline, trace = taint[hit]
                        findings.append(TaintFinding(
                            vuln=vuln, cwe=cwe, severity=sev,
                            sink=f"{callee}() -> {sink_name}", sink_line=sink_line,
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
                    rhs_tainted = (f"{callee}() [returns untrusted data]", s.lineno,
                                   [(s.lineno, f"{callee}() returns tainted data")])

        # (g) property-write sinks (JS DOM XSS: `el.innerHTML = tainted`)
        if self.SINK_PROPERTIES and rhs_tainted:
            for d in s.defs:
                prop = d.split(".")[-1]
                if prop in self.SINK_PROPERTIES:
                    vuln, cwe, sev = self.SINK_PROPERTIES[prop]
                    origin, oline, trace = rhs_tainted
                    findings.append(TaintFinding(
                        vuln=vuln, cwe=cwe, severity=sev, sink=d,
                        sink_line=s.lineno, source=origin, source_line=oline,
                        variable=d, function=func_name,
                        trace=trace + [(s.lineno, f"assigned into DOM sink {prop}")],
                        interprocedural=origin == "<param>"))

        # (h) propagate into defined variables and their aliases
        if rhs_tainted:
            for var in s.defs:
                origin, oline, trace = rhs_tainted
                taint[var] = (origin, oline,
                              trace + [(s.lineno, f"propagates to '{var}'")])
                for al in self.aliases.aliases_of(func_name, var):
                    taint.setdefault(al, taint[var])
        elif s.defs and not _is_param_decl(s):
            # A redefinition from a clean value kills the variable's taint
            # (flow sensitivity). Synthetic parameter declarations in the
            # entry block are exempt: they *introduce* the parameter that a
            # summary run has deliberately seeded as tainted.
            for var in s.defs:
                if not any(u in taint for u in s.uses):
                    taint.pop(var, None)
        return taint

    # ------------------------------------------------------------------
    def _classify(self, sink_name: str, vuln_name: str):
        """
        Resolve a summarised sink to its (vulnerability, CWE, severity).

        When taint reaches a sink *inside a callee*, the summary records the
        name of the innermost dangerous call. If that name is a user-defined
        wrapper rather than a library sink -- `render()` forwarding to
        `innerHTML`, say -- looking it up in the sink table fails, and falling
        back to a generic CWE-20 would mislabel a precisely-identified
        weakness. The vulnerability text carried in the summary already names
        the real class, so it is matched instead.
        """
        matched = _match(sink_name, self.SINKS)
        if matched:
            return self.SINKS[matched]
        for tbl in (self.SINKS, self.SINK_PROPERTIES):
            for vuln, cwe, sev in tbl.values():
                if vuln == vuln_name:
                    return vuln, cwe, sev
        return vuln_name, "CWE-20", "HIGH"

    @staticmethod
    def _receivers_of(callee: str, stmt, exclude: set) -> list:
        """
        Candidate receiver objects for a method call.

        A qualified callee (``sb.append``) names its receiver directly. Some
        grammars expose only the bare method name, in which case the receiver
        is recovered from the statement's other uses -- the variables read by
        the statement that are not the call's own arguments.
        """
        if "." in callee:
            return [callee.rsplit(".", 1)[0]]
        short = callee.split(".")[-1]
        return [u for u in stmt.uses
                if u not in exclude and u != short and "." not in u]

    # printf-family sinks and the index of their format argument. The defect
    # (CWE-134) is that *the format itself* is attacker-controlled; tainted
    # data passed as a later argument to a constant format is the documented
    # safe form, `printf("%s", data)`.
    _FORMAT_ARG_INDEX = {"printf": 0, "wprintf": 0, "vprintf": 0, "vwprintf": 0,
                         "fprintf": 1, "fwprintf": 1, "vfprintf": 1,
                         "sprintf": 1, "swprintf": 1, "vsprintf": 1,
                         "snprintf": 2, "_snprintf": 2, "swprintf_s": 2,
                         "syslog": 1}

    def _format_is_literal(self, call, sink) -> bool:
        """True when a printf-family call supplies a compile-time format."""
        base = sink.split(".")[-1]
        idx = self._FORMAT_ARG_INDEX.get(base)
        if idx is None or len(call["args"]) <= idx:
            return False
        return call["args"][idx][0] == "const"

    def _tainted_argument(self, call, taint, func_name, sink):
        """
        Return the tainted argument that makes this call dangerous, or None.

        For destination-first sinks (``strcpy(dst, src)``) the *source*
        argument carries the attacker data, so argument 0 is skipped; the
        buffer being written is the victim, not the payload.
        """
        args = call["args"]
        start = 1 if sink in _DEST_FIRST_SINKS and len(args) > 1 else 0
        for a in args[start:]:
            if a[0] == "name":
                if a[1] in taint:
                    return a[1]
                for al in self.aliases.aliases_of(func_name, a[1]):
                    if al in taint:
                        return al
            elif a[0] == "expr":
                hit = next((n for n in a[1] if n in taint), None)
                if hit:
                    return hit
        return None


def analyze_uir_taint(cfgs: dict, aliases, program, language: str) -> list[dict]:
    """Public entry point returning serializable findings."""
    analyzer = UIRTaintAnalyzer(cfgs, aliases, program.function_args(), language)
    return [f.to_dict() for f in analyzer.analyze()]
