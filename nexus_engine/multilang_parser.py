"""
Multi-Language Analyzer (SUPERSEDED — retained for ablation only)
================================================================
.. deprecated::
   This module is the original *shallow* analyzer for C, C++, Java, and
   JavaScript: Tree-sitter for structural metrics plus regular-expression
   pattern rules and a line-oriented "taint-lite" tracker. **It is no longer
   part of the pipeline.**

   Those four languages are now handled by the deep stack built on the
   Universal IR, which gives them the same analysis depth as Python:

       ``universal_ir``        CST -> language-neutral statement model
       ``uir_cfg_builder``     real basic-block CFGs
       ``uir_taint_analyzer``  flow-sensitive interprocedural taint
       ``uir_analyses``        call graph, symbols, constants, metrics
       ``uir_rules``           structural CWE detectors

   The file is kept because it is the "pattern rules only" configuration in
   the paper's ablation table (Sec. Ablation), and deleting it would make
   that row unreproducible. New code must not import it.
"""

import re
import warnings

# tree_sitter_languages ships a slightly older Language() call convention;
# the deprecation is internal to that package and harmless. Silence it so the
# console/logs stay clean.
warnings.filterwarnings("ignore", category=FutureWarning, module="tree_sitter")

try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from tree_sitter import Parser
        from tree_sitter_languages import get_language
    TS_AVAILABLE = True
except Exception:                                      # pragma: no cover
    TS_AVAILABLE = False

LANG_MAP = {"C": "c", "C++": "cpp", "Java": "java", "JavaScript": "javascript"}

FUNC_NODES = {"function_definition", "method_declaration", "function_declaration",
              "arrow_function", "method_definition", "constructor_declaration"}
CLASS_NODES = {"class_specifier", "class_declaration", "struct_specifier", "interface_declaration"}
LOOP_NODES = {"for_statement", "while_statement", "do_statement", "enhanced_for_statement",
              "for_in_statement", "for_of_statement"}
COND_NODES = {"if_statement", "switch_statement", "conditional_expression",
              "ternary_expression", "catch_clause", "case_statement"}
CALL_NODES = {"call_expression", "method_invocation", "new_expression"}

# ---------------------------------------------------------------------------
# (1) Pattern rules — (regex, message, cwe, severity)
# ---------------------------------------------------------------------------
UNSAFE_PATTERNS = [
    # --- memory safety (C/C++) ---
    (re.compile(r"\bgets\s*\("), "gets() has no bounds check (buffer overflow)", "CWE-120", "CRITICAL"),
    (re.compile(r"\bstrcpy\s*\("), "strcpy() without bounds check", "CWE-120", "HIGH"),
    (re.compile(r"\bstrcat\s*\("), "strcat() without bounds check", "CWE-120", "HIGH"),
    (re.compile(r"\bsprintf\s*\("), "sprintf() can overflow the destination buffer", "CWE-120", "HIGH"),
    (re.compile(r"\bscanf\s*\(\s*\"[^\"]*%s"), "scanf(\"%s\") unbounded read", "CWE-120", "HIGH"),
    (re.compile(r"\bmemcpy\s*\([^,]+,[^,]+,\s*[a-zA-Z_]"), "memcpy() with variable/attacker-controlled length (buffer overflow)", "CWE-120", "HIGH"),
    (re.compile(r"\bfree\s*\([^)]+\).*\bfree\s*\("), "possible double free", "CWE-415", "MEDIUM"),
    # --- command execution ---
    (re.compile(r"\bsystem\s*\("), "system() OS command execution", "CWE-78", "HIGH"),
    (re.compile(r"\bpopen\s*\("), "popen() OS command execution", "CWE-78", "HIGH"),
    # exec*() with a concatenated / variable command (a literal path like
    # execl("/bin/ls","ls",NULL) is safe and intentionally not matched here)
    (re.compile(r"\bexec[lv]p?e?\s*\([^)]*\+"), "exec*() with concatenated command", "CWE-78", "HIGH"),
    # Runtime.exec() with a concatenated/variable command; the array form with
    # string literals (new String[]{"ping","host"}) is safe and not matched.
    (re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+"),
     "Runtime.exec() with concatenated command", "CWE-78", "HIGH"),
    (re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(\s*[a-z_]\w*\s*\)"),
     "Runtime.exec() with variable command (verify input)", "CWE-78", "HIGH"),
    (re.compile(r"ProcessBuilder\s*\("), "ProcessBuilder command execution (verify input)", "CWE-78", "MEDIUM"),
    (re.compile(r"child_process\.(exec|execSync)\s*\("), "child_process.exec() command execution", "CWE-78", "HIGH"),
    (re.compile(r"\.exec(Sync)?\s*\([^)]*\+"), "exec() with concatenated command (command injection)", "CWE-78", "HIGH"),
    # --- code injection ---
    (re.compile(r"\beval\s*\("), "eval() executes arbitrary code", "CWE-95", "CRITICAL"),
    (re.compile(r"new\s+Function\s*\("), "new Function() executes arbitrary code", "CWE-95", "HIGH"),
    (re.compile(r"setTimeout\s*\(\s*[\"']"), "setTimeout() with string arg behaves like eval", "CWE-95", "MEDIUM"),
    # --- XSS (JS) ---
    (re.compile(r"\.innerHTML\s*="), "innerHTML assignment (DOM XSS)", "CWE-79", "HIGH"),
    (re.compile(r"\.outerHTML\s*="), "outerHTML assignment (DOM XSS)", "CWE-79", "HIGH"),
    (re.compile(r"document\.write\s*\("), "document.write() XSS sink", "CWE-79", "HIGH"),
    (re.compile(r"\.insertAdjacentHTML\s*\("), "insertAdjacentHTML() XSS sink", "CWE-79", "MEDIUM"),
    (re.compile(r"dangerouslySetInnerHTML"), "dangerouslySetInnerHTML (React XSS)", "CWE-79", "MEDIUM"),
    # --- SQL (same-line concat) ---
    (re.compile(r"executeQuery\s*\([^)]*\+"), "SQL built with concatenation", "CWE-89", "CRITICAL"),
    (re.compile(r"execute(Update|Batch)?\s*\(\s*\"[^\"]*\"\s*\+"), "SQL built with concatenation", "CWE-89", "CRITICAL"),
    (re.compile(r"createStatement\s*\(\s*\)"), "Statement (use PreparedStatement for user input)", "CWE-89", "LOW"),
    (re.compile(r"\.query\s*\(\s*[`\"'][^`\"']*\$\{"), "SQL template literal with interpolation", "CWE-89", "HIGH"),
    # --- weak crypto ---
    (re.compile(r"\b(MD5|md5)\b"), "Weak hash algorithm MD5", "CWE-327", "MEDIUM"),
    (re.compile(r"MessageDigest\.getInstance\(\s*\"MD5\"\)", re.I), "Weak hash MD5", "CWE-327", "MEDIUM"),
    (re.compile(r"MessageDigest\.getInstance\(\s*\"SHA-?1\"\)", re.I), "Weak hash SHA-1", "CWE-327", "MEDIUM"),
    (re.compile(r"createHash\s*\(\s*[\"']md5[\"']\)", re.I), "Weak hash MD5", "CWE-327", "MEDIUM"),
    (re.compile(r"\bDES\b|\"DES\"|Cipher\.getInstance\(\s*\"DES"), "Weak cipher DES", "CWE-327", "MEDIUM"),
    (re.compile(r"ECB", ), "ECB mode is insecure", "CWE-327", "LOW"),
    # --- secrets ---
    (re.compile(r"(password|passwd|pwd|secret|api_?key|token|auth_?key|private_?key)\s*[:=]\s*[\"'][^\"']{5,}[\"']", re.I),
     "Hardcoded credential/secret", "CWE-798", "HIGH"),
    # --- deserialization / path ---
    (re.compile(r"ObjectInputStream|readObject\s*\("), "Java deserialization (CWE-502)", "CWE-502", "HIGH"),
    (re.compile(r"JSON\.parse\s*\(\s*[a-zA-Z_]"), "", "", ""),   # benign-ish placeholder
    (re.compile(r"new\s+File\s*\([^)]*\+"), "File path built with concatenation (path traversal)", "CWE-22", "MEDIUM"),
    # --- misc ---
    (re.compile(r"Math\.random\s*\(\)"), "Math.random() is not cryptographically secure", "CWE-338", "LOW"),
    (re.compile(r"verify\s*\(\s*\)\s*\{\s*return\s+true"), "TLS verification disabled", "CWE-295", "HIGH"),
    (re.compile(r"printStackTrace\s*\("), "", "", ""),   # placeholder (noise)
]

# ---------------------------------------------------------------------------
# (2) Taint-lite configuration
# ---------------------------------------------------------------------------
# untrusted-source expressions (RHS of an assignment taints the LHS var)
TAINT_SOURCE_RX = re.compile(
    r"(getParameter|getHeader|getQueryString|getInputStream|"
    r"request\.(getParameter|param|query|body|args)|"
    r"req\.(query|body|params)|process\.argv|"
    r"System\.getenv|scanf|fgets|gets|readLine|nextLine|"
    r"location\.(hash|search|href)|document\.URL|window\.name|"
    r"\$_GET|\$_POST|\$_REQUEST)")

# sink patterns: (regex, vuln, cwe, severity) — checked against a line that
# uses a tainted variable
TAINT_SINKS = [
    (re.compile(r"executeQuery|executeUpdate|\.execute\s*\(|\.query\s*\("), "SQL Injection", "CWE-89", "CRITICAL"),
    (re.compile(r"\.exec\s*\(|system\s*\(|popen\s*\(|ProcessBuilder|child_process"), "Command Injection", "CWE-78", "CRITICAL"),
    (re.compile(r"\beval\s*\(|new\s+Function"), "Code Injection", "CWE-95", "CRITICAL"),
    (re.compile(r"innerHTML|outerHTML|document\.write|insertAdjacentHTML"), "Cross-Site Scripting", "CWE-79", "HIGH"),
    (re.compile(r"new\s+File\s*\(|FileInputStream|fopen\s*\(|readFile"), "Path Traversal", "CWE-22", "HIGH"),
]

# same-line concatenation into a sink (very high confidence)
CONCAT = re.compile(r"[\"'`].*[\"'`]\s*\+|\+\s*[a-zA-Z_]|\$\{")


PARAM_RX = re.compile(r"\b(?:String|char\s*\*|int|var|let|const|Object)\s+"
                      r"([A-Za-z_]\w*)\s*[,)]")
SQL_STR = re.compile(r"[\"'`]\s*(SELECT|INSERT|UPDATE|DELETE|DROP)\s", re.I)


def _run_taint_lite(lines):
    """Cross-line source->sink tracking. Returns findings list."""
    findings = []
    tainted = {}          # var -> line where it became tainted
    assign_rx = re.compile(r"^\s*(?:\w[\w<>\[\]]*\s+)?([A-Za-z_]\w*)\s*=\s*(.+?);?\s*$")

    # method/function parameters are treated as potentially untrusted input
    # (standard assumption for public-entry security analysis)
    for i, line in enumerate(lines[:3], 1):
        for pm in PARAM_RX.finditer(line):
            tainted.setdefault(pm.group(1), i)

    for i, line in enumerate(lines, 1):
        # also pick up parameters declared on a function signature anywhere
        if re.search(r"\b(void|public|private|function|def|int|String)\b.*\(", line):
            for pm in PARAM_RX.finditer(line):
                tainted.setdefault(pm.group(1), i)

        # (a) taint introduction: var = <source-or-concat>
        m = assign_rx.match(line)
        if m:
            var, rhs = m.group(1), m.group(2)
            if TAINT_SOURCE_RX.search(rhs):
                tainted[var] = i
            elif SQL_STR.search(rhs) and re.search(r"\+", rhs):
                tainted[var] = i          # SQL string built via concatenation
            elif re.search(r"new\s+StringBuilder\s*\(\s*[\"'].*(SELECT|INSERT|UPDATE|DELETE)",
                           rhs, re.I):
                tainted[var] = i          # SQL built via StringBuilder
            elif CONCAT.search(rhs) and any(re.search(rf"\b{re.escape(t)}\b", rhs) for t in tainted):
                tainted[var] = i          # propagates taint through concat

        # StringBuilder.append(userVar) keeps the builder tainted / taints it
        mb = re.match(r"^\s*([A-Za-z_]\w*)\.append\s*\(", line)
        if mb and mb.group(1) in tainted:
            tainted[mb.group(1)] = tainted.get(mb.group(1), i)

        # (b) sink usage with a tainted variable on this line
        for rx, vuln, cwe, sev in TAINT_SINKS:
            if rx.search(line):
                hit = next((v for v in tainted if re.search(rf"\b{re.escape(v)}\b", line)), None)
                if hit:
                    findings.append({
                        "rule_id": f"ML-TAINT-{cwe}", "cwe": cwe, "severity": sev,
                        "category": "security", "line": i,
                        "message": f"{vuln}: tainted '{hit}' (from L{tainted[hit]}) reaches sink",
                        "evidence": line.strip()[:80],
                        "fix_hint": "Validate/parameterize/escape the input before the sink.",
                    })
    return findings


def analyze_multilang(code: str, language: str) -> dict:
    """Full non-Python analysis: tree-sitter AST metrics + pattern + taint-lite."""
    result = {"language": language, "tree_sitter": TS_AVAILABLE}
    findings = []
    lines = code.split("\n")

    # ---- (1) pattern-based security scan (line-accurate) -----------------
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(("//", "*", "#")):        # skip comments
            continue
        for rx, msg, cwe, sev in UNSAFE_PATTERNS:
            if msg and rx.search(line):
                findings.append({
                    "rule_id": f"ML-{cwe}", "cwe": cwe, "severity": sev,
                    "category": "security", "line": i, "message": msg,
                    "evidence": stripped[:80],
                    "fix_hint": "Use the safe alternative (bounded copy, parameterized "
                                "query, textContent, strong hash, prepared statement).",
                })

    # ---- (2) cross-line taint-lite ---------------------------------------
    findings.extend(_run_taint_lite(lines))

    # dedupe by (line, cwe) — keep the highest severity
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    seen, deduped = set(), []
    for f in findings:
        key = (f["line"], f["cwe"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    findings = deduped

    # ---- (3) tree-sitter structural metrics ------------------------------
    m = {"functions": 0, "classes": 0, "loops": 0, "conditionals": 0,
         "calls": 0, "max_depth": 0, "cyclomatic_complexity": 1}
    call_edges = []
    if TS_AVAILABLE and language in LANG_MAP:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                parser = Parser()
                lang = get_language(LANG_MAP[language])
                try:
                    parser.language = lang
                except (AttributeError, TypeError):
                    parser.set_language(lang)
                tree = parser.parse(bytes(code, "utf8"))

            def text(n):
                return code[n.start_byte:n.end_byte]

            def walk(node, depth=0, scope="<global>"):
                m["max_depth"] = max(m["max_depth"], depth)
                t = node.type
                if t in FUNC_NODES:
                    m["functions"] += 1
                    for c in node.children:
                        if c.type in ("identifier", "name", "function_declarator"):
                            scope = text(c).split("(")[0].strip()
                            break
                elif t in CLASS_NODES:
                    m["classes"] += 1
                elif t in LOOP_NODES:
                    m["loops"] += 1
                    m["cyclomatic_complexity"] += 1
                elif t in COND_NODES:
                    m["conditionals"] += 1
                    m["cyclomatic_complexity"] += 1
                elif t in CALL_NODES:
                    m["calls"] += 1
                    for c in node.children:
                        if c.type in ("identifier", "field_identifier", "member_expression"):
                            call_edges.append((scope, text(c).split(".")[-1],
                                               node.start_point[0] + 1))
                            break
                for child in node.children:
                    walk(child, depth + 1, scope)

            walk(tree.root_node)
            result["ast_status"] = f"Real {language} tree-sitter AST parsed"
        except Exception as e:
            result["ast_status"] = f"tree-sitter unavailable: {e}"
    else:
        result["ast_status"] = "tree-sitter not installed - pattern scan only"

    code_lines = [l for l in lines if l.strip()]
    comment_prefixes = ("//", "/*", "*", "#")
    sloc = len([l for l in code_lines if not l.strip().startswith(comment_prefixes)])
    result.update({
        "metrics": m,
        "loc": {"total": len(lines), "sloc": sloc},
        "call_graph_edges": [{"caller": a, "callee": b, "line": l} for a, b, l in call_edges],
        "findings": findings,
    })
    return result
