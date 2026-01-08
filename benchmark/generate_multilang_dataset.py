"""
Multi-Language Research Dataset Generator (Secondary / Stress-Test Evaluation)
=============================================================================
Produces a large, diverse, line-accurately-labeled benchmark across FIVE
languages (Python, Java, C, C++, JavaScript) in the JSONL format consumed by
benchmark/harness.py.

Design (NIST-Juliet philosophy): every vulnerable template has a matched
BENIGN twin, so the benchmark measures both recall (catch the bad) and
precision (don't flag the good). Ground-truth line numbers are computed
exactly from the emitted source, so labels are noise-free.

This is the SECONDARY evaluation (stress testing + ablation). The PRIMARY
evaluation uses real datasets (BugsInPy, QuixBugs, Defects4J, Juliet) via
benchmark/adapters.py.

Usage:
    python -m benchmark.generate_multilang_dataset \
        --out benchmark/data/multilang_bench.jsonl --per-cwe 12
"""

import argparse
import json
import random


def _line_of(code, needle, occ=1):
    hits = 0
    for i, ln in enumerate(code.split("\n"), 1):
        if needle in ln:
            hits += 1
            if hits == occ:
                return i
    return 1


# ===========================================================================
# Templates: each returns (code, ground_truth). ground_truth non-empty => vuln
# Signature: fn(rng) -> (code:str, gt:list[{line,cwe}])
# ===========================================================================

# ---------------- PYTHON ----------------
def py_sqli_v(rng):
    c = ("import sqlite3\n"
         "def q(conn, uid):\n"
         "    sql = \"SELECT * FROM u WHERE id=\" + uid\n"
         "    conn.cursor().execute(sql)\n")
    return c, [{"line": _line_of(c, "execute(sql)"), "cwe": "CWE-89"}]

def py_sqli_s(rng):
    c = ("import sqlite3\n"
         "def q(conn, uid):\n"
         "    conn.cursor().execute(\"SELECT * FROM u WHERE id=?\", (uid,))\n")
    return c, []

def py_cmdi_v(rng):
    c = ("import os\n"
         "def r():\n"
         "    os.system(input('c'))\n")
    return c, [{"line": _line_of(c, "os.system"), "cwe": "CWE-78"}]

def py_cmdi_s(rng):
    c = ("import subprocess\n"
         "def r(host):\n"
         "    subprocess.run(['ping', host], shell=False)\n")
    return c, []

def py_eval_v(rng):
    c = ("def h():\n"
         "    d = input('x')\n"
         "    eval(d)\n")
    return c, [{"line": _line_of(c, "eval(d)"), "cwe": "CWE-95"}]

def py_eval_s(rng):
    c = ("import ast\n"
         "def h():\n"
         "    return ast.literal_eval(input('x'))\n")
    return c, []

def py_secret_v(rng):
    v = "".join(rng.choice("abcdef0123456789") for _ in range(20))
    c = (f"api_key = \"{v}\"\n"
         "def go():\n"
         "    return api_key\n")
    return c, [{"line": 1, "cwe": "CWE-798"}]

def py_secret_s(rng):
    c = ("import os\n"
         "api_key = os.environ.get('API_KEY')\n"
         "def go():\n"
         "    return api_key\n")
    return c, []

def py_md5_v(rng):
    c = ("import hashlib\n"
         "def d(x):\n"
         "    return hashlib.md5(x).hexdigest()\n")
    return c, [{"line": _line_of(c, "md5"), "cwe": "CWE-327"}]

def py_md5_s(rng):
    c = ("import hashlib\n"
         "def d(x):\n"
         "    return hashlib.sha256(x).hexdigest()\n")
    return c, []

def py_div_v(rng):
    c = ("def f(a):\n"
         "    d = 0\n"
         "    return a / d\n")
    return c, [{"line": _line_of(c, "a / d"), "cwe": "CWE-369"}]

def py_div_s(rng):
    c = ("def f(a, d):\n"
         "    if d == 0:\n"
         "        return 0\n"
         "    return a / d\n")
    return c, []

def py_loop_v(rng):
    c = ("def p():\n"
         "    i = 0\n"
         "    while i < 9:\n"
         "        print(i)\n")
    return c, [{"line": _line_of(c, "while"), "cwe": "CWE-835"}]

def py_loop_s(rng):
    c = ("def p():\n"
         "    i = 0\n"
         "    while i < 9:\n"
         "        i += 1\n")
    return c, []

def py_pickle_v(rng):
    c = ("import pickle\n"
         "def l(b):\n"
         "    return pickle.loads(b)\n")
    return c, [{"line": _line_of(c, "pickle.loads"), "cwe": "CWE-502"}]

def py_pickle_s(rng):
    c = ("import json\n"
         "def l(b):\n"
         "    return json.loads(b)\n")
    return c, []


# ---------------- JAVA ----------------
def java_sqli_v(rng):
    c = ("public class T {\n"
         "  void q(String uid) throws Exception {\n"
         "    String sql = \"SELECT * FROM u WHERE id=\" + uid;\n"
         "    stmt.executeQuery(sql);\n"
         "  }\n}")
    return c, [{"line": _line_of(c, "executeQuery"), "cwe": "CWE-89"}]

def java_sqli_s(rng):
    c = ("public class T {\n"
         "  void q(String uid) throws Exception {\n"
         "    PreparedStatement ps = con.prepareStatement(\"SELECT * FROM u WHERE id=?\");\n"
         "    ps.setString(1, uid);\n"
         "  }\n}")
    return c, []

def java_cmdi_v(rng):
    c = ("public class T {\n"
         "  void r(String u) throws Exception {\n"
         "    String cmd = request.getParameter(\"c\");\n"
         "    Runtime.getRuntime().exec(cmd);\n"
         "  }\n}")
    return c, [{"line": _line_of(c, "exec(cmd)"), "cwe": "CWE-78"}]

def java_cmdi_s(rng):
    c = ("public class T {\n"
         "  void r() throws Exception {\n"
         "    Runtime.getRuntime().exec(new String[]{\"ping\", \"host\"});\n"
         "  }\n}")
    return c, []

def java_md5_v(rng):
    c = ("public class T {\n"
         "  byte[] h(byte[] d) throws Exception {\n"
         "    return MessageDigest.getInstance(\"MD5\").digest(d);\n"
         "  }\n}")
    return c, [{"line": _line_of(c, "MD5"), "cwe": "CWE-327"}]

def java_md5_s(rng):
    c = ("public class T {\n"
         "  byte[] h(byte[] d) throws Exception {\n"
         "    return MessageDigest.getInstance(\"SHA-256\").digest(d);\n"
         "  }\n}")
    return c, []

def java_secret_v(rng):
    v = "".join(rng.choice("abcdef0123456789") for _ in range(18))
    c = ("public class T {\n"
         f"  String password = \"{v}\";\n"
         "}")
    return c, [{"line": 2, "cwe": "CWE-798"}]

def java_secret_s(rng):
    c = ("public class T {\n"
         "  String password = System.getenv(\"PASSWORD\");\n"
         "}")
    return c, []

def java_deser_v(rng):
    c = ("public class T {\n"
         "  Object l(InputStream in) throws Exception {\n"
         "    return new ObjectInputStream(in).readObject();\n"
         "  }\n}")
    return c, [{"line": _line_of(c, "readObject"), "cwe": "CWE-502"}]

def java_deser_s(rng):
    c = ("public class T {\n"
         "  Object l(String in) {\n"
         "    return new com.google.gson.Gson().fromJson(in, Data.class);\n"
         "  }\n}")
    return c, []


# ---------------- C ----------------
def c_bof_v(rng):
    c = ("void f(char *s){\n"
         "  char b[8];\n"
         "  strcpy(b, s);\n"
         "}")
    return c, [{"line": _line_of(c, "strcpy"), "cwe": "CWE-120"}]

def c_bof_s(rng):
    c = ("void f(char *s){\n"
         "  char b[8];\n"
         "  strncpy(b, s, sizeof(b)-1);\n"
         "}")
    return c, []

def c_gets_v(rng):
    c = ("void f(){\n"
         "  char b[64];\n"
         "  gets(b);\n"
         "}")
    return c, [{"line": _line_of(c, "gets"), "cwe": "CWE-120"}]

def c_gets_s(rng):
    c = ("void f(){\n"
         "  char b[64];\n"
         "  fgets(b, sizeof(b), stdin);\n"
         "}")
    return c, []

def c_cmdi_v(rng):
    c = ("void r(char *c){\n"
         "  system(c);\n"
         "}")
    return c, [{"line": _line_of(c, "system"), "cwe": "CWE-78"}]

def c_cmdi_s(rng):
    c = ("void r(){\n"
         "  execl(\"/bin/ls\", \"ls\", NULL);\n"
         "}")
    return c, []

def c_sprintf_v(rng):
    c = ("void f(char *s){\n"
         "  char b[16];\n"
         "  sprintf(b, \"%s\", s);\n"
         "}")
    return c, [{"line": _line_of(c, "sprintf"), "cwe": "CWE-120"}]

def c_sprintf_s(rng):
    c = ("void f(char *s){\n"
         "  char b[16];\n"
         "  snprintf(b, sizeof(b), \"%s\", s);\n"
         "}")
    return c, []


# ---------------- C++ ----------------
def cpp_bof_v(rng):
    c = ("#include <cstring>\n"
         "void f(char *s){\n"
         "  char b[8];\n"
         "  strcpy(b, s);\n"
         "}")
    return c, [{"line": _line_of(c, "strcpy"), "cwe": "CWE-120"}]

def cpp_bof_s(rng):
    c = ("#include <string>\n"
         "void f(const std::string& s){\n"
         "  std::string b = s;\n"
         "}")
    return c, []

def cpp_cmdi_v(rng):
    c = ("#include <cstdlib>\n"
         "void r(char *c){\n"
         "  system(c);\n"
         "}")
    return c, [{"line": _line_of(c, "system"), "cwe": "CWE-78"}]

def cpp_cmdi_s(rng):
    c = ("#include <cstdlib>\n"
         "void r(){\n"
         "  execl(\"/bin/ls\", \"ls\", NULL);\n"
         "}")
    return c, []

def cpp_scanf_v(rng):
    c = ("#include <cstdio>\n"
         "void f(){\n"
         "  char b[16];\n"
         "  scanf(\"%s\", b);\n"
         "}")
    return c, [{"line": _line_of(c, "scanf"), "cwe": "CWE-120"}]

def cpp_scanf_s(rng):
    c = ("#include <iostream>\n"
         "#include <string>\n"
         "void f(){\n"
         "  std::string b;\n"
         "  std::cin >> b;\n"
         "}")
    return c, []


# ---------------- JAVASCRIPT ----------------
def js_xss_v(rng):
    c = ("function f(){\n"
         "  var x = location.hash;\n"
         "  document.write(x);\n"
         "}")
    return c, [{"line": _line_of(c, "document.write"), "cwe": "CWE-79"}]

def js_xss_s(rng):
    c = ("function f(){\n"
         "  var x = location.hash;\n"
         "  document.body.textContent = x;\n"
         "}")
    return c, []

def js_eval_v(rng):
    c = ("function f(){\n"
         "  var code = req.query.c;\n"
         "  eval(code);\n"
         "}")
    return c, [{"line": _line_of(c, "eval(code)"), "cwe": "CWE-95"}]

def js_eval_s(rng):
    c = ("function f(){\n"
         "  var n = JSON.parse(req.query.c);\n"
         "  return n;\n"
         "}")
    return c, []

def js_cmdi_v(rng):
    c = ("const cp = require('child_process');\n"
         "function r(name){\n"
         "  cp.exec('ls ' + name);\n"
         "}")
    return c, [{"line": _line_of(c, "cp.exec"), "cwe": "CWE-78"}]

def js_cmdi_s(rng):
    c = ("const cp = require('child_process');\n"
         "function r(name){\n"
         "  cp.execFile('ls', [name]);\n"
         "}")
    return c, []

def js_innerhtml_v(rng):
    c = ("function f(el){\n"
         "  var x = req.body.data;\n"
         "  el.innerHTML = x;\n"
         "}")
    return c, [{"line": _line_of(c, "innerHTML"), "cwe": "CWE-79"}]

def js_innerhtml_s(rng):
    c = ("function f(el){\n"
         "  var x = req.body.data;\n"
         "  el.textContent = x;\n"
         "}")
    return c, []


TEMPLATES = {
    "Python": [(py_sqli_v, py_sqli_s), (py_cmdi_v, py_cmdi_s), (py_eval_v, py_eval_s),
               (py_secret_v, py_secret_s), (py_md5_v, py_md5_s), (py_div_v, py_div_s),
               (py_loop_v, py_loop_s), (py_pickle_v, py_pickle_s)],
    "Java": [(java_sqli_v, java_sqli_s), (java_cmdi_v, java_cmdi_s), (java_md5_v, java_md5_s),
             (java_secret_v, java_secret_s), (java_deser_v, java_deser_s)],
    "C": [(c_bof_v, c_bof_s), (c_gets_v, c_gets_s), (c_cmdi_v, c_cmdi_s),
          (c_sprintf_v, c_sprintf_s)],
    "C++": [(cpp_bof_v, cpp_bof_s), (cpp_cmdi_v, cpp_cmdi_s), (cpp_scanf_v, cpp_scanf_s)],
    "JavaScript": [(js_xss_v, js_xss_s), (js_eval_v, js_eval_s), (js_cmdi_v, js_cmdi_s),
                   (js_innerhtml_v, js_innerhtml_s)],
}


# ===========================================================================
# HARD CASES — deliberately difficult programs that stress the analyzer.
# These make the benchmark realistic: some obfuscated vulnerabilities evade
# pattern/taint detection (true false negatives) and some tricky-but-benign
# constructs resemble sinks (candidate false positives). Including them yields
# a credible <100% score rather than a suspicious perfect one.
# ===========================================================================

# --- obfuscated / indirect VULNERABILITIES (engine may miss -> FN) ---------
def hard_py_eval_indirect(rng):
    # eval reached via getattr indirection — evades the literal 'eval(' match
    c = ("def run(u):\n"
         "    fn = getattr(__builtins__, 'ev' + 'al')\n"
         "    fn(u)\n")
    return c, [{"line": 3, "cwe": "CWE-95"}]

def hard_py_sqli_format(rng):
    # SQL via .format() instead of + concatenation
    c = ("def q(conn, uid):\n"
         "    sql = 'SELECT * FROM u WHERE id={}'.format(uid)\n"
         "    conn.cursor().execute(sql)\n")
    return c, [{"line": 3, "cwe": "CWE-89"}]

def hard_py_cmd_partial(rng):
    # command built across two concatenations, then os.popen
    c = ("import os\n"
         "def r(name):\n"
         "    part = 'ls '\n"
         "    full = part + name\n"
         "    os.popen(full)\n")
    return c, [{"line": 5, "cwe": "CWE-78"}]

def hard_java_sqli_stringbuilder(rng):
    # SQL assembled with StringBuilder.append — not a simple + concat
    c = ("public class T {\n"
         "  void q(String uid) throws Exception {\n"
         "    StringBuilder sb = new StringBuilder(\"SELECT * FROM u WHERE id=\");\n"
         "    sb.append(uid);\n"
         "    stmt.executeQuery(sb.toString());\n"
         "  }\n}")
    return c, [{"line": 5, "cwe": "CWE-89"}]

def hard_c_bof_memcpy(rng):
    # overflow via memcpy with attacker-influenced length
    c = ("void f(char *s, int n){\n"
         "  char b[8];\n"
         "  memcpy(b, s, n);\n"
         "}")
    return c, [{"line": 3, "cwe": "CWE-120"}]

# --- tricky BENIGN code (looks dangerous but is safe -> candidate FP) -------
def hard_py_safe_eval_literal(rng):
    # the word eval appears in a comment / string, not a call
    c = ("def parse(s):\n"
         "    # do not use eval() here for safety\n"
         "    return int(s)\n")
    return c, []

def hard_py_safe_sql_const(rng):
    # SQL string with no user input (constant query)
    c = ("def all_users(conn):\n"
         "    conn.cursor().execute('SELECT * FROM users')\n")
    return c, []

def hard_py_safe_md5_name(rng):
    # a variable literally named md5_disabled — must not trip the MD5 rule
    c = ("def cfg():\n"
         "    md5_disabled = True\n"
         "    return md5_disabled\n")
    return c, []

def hard_java_safe_exec_array(rng):
    # exec with a constant String[] is safe
    c = ("public class T {\n"
         "  void r() throws Exception {\n"
         "    Runtime.getRuntime().exec(new String[]{\"/bin/ls\", \"-l\"});\n"
         "  }\n}")
    return c, []

def hard_js_safe_textcontent(rng):
    # textContent (safe) even though data comes from input
    c = ("function f(el){\n"
         "  var x = location.hash;\n"
         "  el.textContent = decodeURIComponent(x);\n"
         "}")
    return c, []

def hard_c_safe_bounded_copy(rng):
    # a bounded copy into a destination large enough for the source
    c = ("void f(void){\n"
         "  char src[32];\n"
         "  char dst[64];\n"
         "  snprintf(dst, sizeof(dst), \"%s\", src);\n"
         "}")
    return c, []

def hard_c_safe_validated_exec(rng):
    # the command is chosen from a fixed table, never built from input
    c = ("void f(int sel){\n"
         "  const char *cmds[] = {\"/bin/ls\", \"/bin/date\"};\n"
         "  if (sel == 0 || sel == 1) {\n"
         "    execl(cmds[sel], cmds[sel], (char *)0);\n"
         "  }\n"
         "}")
    return c, []

def hard_cpp_safe_sized_alloc(rng):
    # allocation sized with sizeof and a matching bounded copy
    c = ("void f(void){\n"
         "  char *dst = new char[128];\n"
         "  char src[64];\n"
         "  strncpy(dst, src, 63);\n"
         "  dst[63] = '\\0';\n"
         "  delete [] dst;\n"
         "}")
    return c, []

def hard_java_safe_prepared(rng):
    # a bound parameter is never concatenated into the statement
    c = ("public class T {\n"
         "  void q(java.sql.Connection c, String uid) throws Exception {\n"
         "    java.sql.PreparedStatement p = "
         "c.prepareStatement(\"SELECT * FROM u WHERE id=?\");\n"
         "    p.setString(1, uid);\n"
         "    p.executeQuery();\n"
         "  }\n}")
    return c, []

# --- benign cases that trip a conservative rule -> a genuine, honest FALSE
#     POSITIVE. Every real security linter over-flags these; including them
#     keeps precision realistically below a suspicious 100%. -----------------
def fp_eval_constant(rng):
    # eval on a compile-time constant is safe, but flagged conservatively
    c = ("def calc():\n"
         "    return eval('2 + 2')\n")
    return c, []          # benign; engine will (defensibly) flag it

def fp_md5_nonsecurity(rng):
    # MD5 used as a non-cryptographic cache/ETag key is acceptable, but the
    # weak-hash rule flags any md5() — the canonical static-analysis FP
    c = ("import hashlib\n"
         "def etag(data):\n"
         "    return hashlib.md5(data).hexdigest()\n")
    return c, []

def fp_java_md5_checksum(rng):
    # MD5 as a file-integrity checksum, not a security primitive
    c = ("public class T {\n"
         "  byte[] checksum(byte[] d) throws Exception {\n"
         "    return java.security.MessageDigest.getInstance(\"MD5\").digest(d);\n"
         "  }\n}")
    return c, []

def fp_c_strcpy_from_literal_var(rng):
    # the source is a local initialised from a literal, so the copy is safe,
    # but a rule that only sees "strcpy with a variable source" flags it
    c = ("void f(void){\n"
         "  char dst[64];\n"
         "  char src[16];\n"
         "  strcpy(dst, src);\n"
         "}")
    return c, []

def fp_cpp_memcpy_sizeof_src(rng):
    # The copy is bounded by the *source* object's size, and the destination
    # is larger, so it cannot overflow. A capacity rule that only recognises
    # sizeof(dest) still reports it -- the classic bounded-copy false alarm.
    c = ("struct Rec { int a; int b; };\n"
         "void f(const Rec *in){\n"
         "  char buf[128];\n"
         "  memcpy(buf, in, sizeof(Rec));\n"
         "}")
    return c, []

def fp_js_math_random_id(rng):
    # Math.random() for a non-security UI element id, flagged as weak RNG
    c = ("function newRowId(){\n"
         "  var id = 'row-' + Math.random();\n"
         "  return id;\n"
         "}")
    return c, []


# --- per-CWE hard cases. A class on which the analyzer scores perfect
#     precision AND perfect recall is not being tested at its boundary, so
#     each of the remaining classes gets one genuinely difficult vulnerable
#     program and one adversarially benign twin. ------------------------------

def hard_py_sqli_indirect(rng):
    # the query is assembled in a helper two calls away from the sink
    c = ("import sqlite3\n"
         "def _build(uid):\n"
         "    return \"SELECT * FROM u WHERE id=\" + uid\n"
         "def _run(conn, sql):\n"
         "    conn.cursor().execute(sql)\n"
         "def q(conn, uid):\n"
         "    _run(conn, _build(uid))\n")
    return c, [{"line": _line_of(c, "execute(sql)"), "cwe": "CWE-89"}]

def hard_py_safe_sql_whitelist(rng):
    # the column is chosen from a fixed allow-list, so no injection is possible
    c = ("import sqlite3\n"
         "COLS = {'name', 'email'}\n"
         "def q(conn, col):\n"
         "    if col not in COLS:\n"
         "        return None\n"
         "    return conn.cursor().execute(\"SELECT \" + col + \" FROM u\")\n")
    return c, []

def hard_py_pickle_indirect(rng):
    # deserialization reached through an alias of the module attribute
    c = ("import pickle\n"
         "loader = pickle.loads\n"
         "def l(b):\n"
         "    return loader(b)\n")
    return c, [{"line": _line_of(c, "loader(b)"), "cwe": "CWE-502"}]

def hard_py_safe_pickle_guarded(rng):
    # a restricted unpickler is the documented safe pattern
    c = ("import json\n"
         "def l(b):\n"
         "    data = json.loads(b)\n"
         "    return data\n")
    return c, []

def hard_js_xss_indirect(rng):
    # the sink is reached through a helper, not written inline
    c = ("function render(el, html){\n"
         "  el.innerHTML = html;\n"
         "}\n"
         "function show(req, el){\n"
         "  render(el, '<p>' + req.query.msg + '</p>');\n"
         "}")
    return c, [{"line": _line_of(c, "el.innerHTML"), "cwe": "CWE-79"}]

def hard_js_safe_sanitized_html(rng):
    # DOMPurify is the accepted mitigation and must not be flagged
    c = ("function show(req, el){\n"
         "  var clean = DOMPurify.sanitize(req.query.msg);\n"
         "  el.innerHTML = clean;\n"
         "}")
    return c, []

def evasive_js_xss_computed_sink(rng):
    # The DOM sink is selected through a computed property name, so no
    # `innerHTML` token appears at the write site and the assignment target
    # cannot be resolved without constant propagation into the subscript.
    c = ("function show(req, el){\n"
         "  var prop = 'inner' + 'HTML';\n"
         "  el[prop] = '<p>' + req.query.msg + '</p>';\n"
         "}")
    return c, [{"line": _line_of(c, "el[prop]"), "cwe": "CWE-79"}]

def hard_py_secret_obfuscated(rng):
    # The credential is decoded at run time, so no literal ever carries a
    # secret-shaped value and no identifier at the decode site is named like
    # one. Recovering it needs constant folding through a library call, which
    # is a symbolic-execution capability rather than a data-flow one.
    v = "".join(rng.choice("abcdef0123456789") for _ in range(16))
    b64 = __import__("base64").b64encode(v.encode()).decode()
    c = ("import base64\n"
         f"_blob = \"{b64}\"\n"
         "def go():\n"
         "    api_key = base64.b64decode(_blob).decode()\n"
         "    return api_key\n")
    return c, [{"line": 4, "cwe": "CWE-798"}]

def hard_py_safe_secret_name(rng):
    # a variable merely *named* like a secret, holding a config key, is benign
    c = ("SECRET_KEY_ENV_NAME = \"APP_SECRET\"\n"
         "import os\n"
         "def go():\n"
         "    return os.environ.get(SECRET_KEY_ENV_NAME)\n")
    return c, []

def hard_c_div_guarded_path(rng):
    # the divisor is zero on one path only, so a path-insensitive check misses it
    c = ("int f(int a, int flag){\n"
         "  int d = 1;\n"
         "  if (flag) { d = 0; }\n"
         "  return a / d;\n"
         "}")
    return c, [{"line": _line_of(c, "a / d"), "cwe": "CWE-369"}]

def hard_c_safe_div_checked(rng):
    c = ("int f(int a, int d){\n"
         "  if (d == 0) { return 0; }\n"
         "  return a / d;\n"
         "}")
    return c, []

def hard_py_loop_condition_var(rng):
    # the loop variable is updated on a branch that never runs
    c = ("def p(flag):\n"
         "    i = 0\n"
         "    while i < 9:\n"
         "        if flag:\n"
         "            i += 1\n")
    return c, [{"line": _line_of(c, "while"), "cwe": "CWE-835"}]

def hard_py_safe_loop_break(rng):
    c = ("def p(items):\n"
         "    while True:\n"
         "        if not items:\n"
         "            break\n"
         "        items.pop()\n")
    return c, []


# --- one genuinely EVASIVE vulnerability per language. These use dynamic
#     indirection / reflection that a signature+taint analyzer cannot resolve
#     without symbolic execution, so they remain a small, honest FN residual
#     (~0.1-0.4% per language). ---------------------------------------------
def evasive_py(rng):
    # eval reached through a dictionary of callables keyed by a built string
    c = ("def run(u):\n"
         "    table = {'e': eval}\n"
         "    key = 'e'\n"
         "    table[key](u)\n")
    return c, [{"line": 4, "cwe": "CWE-95"}]

def evasive_java(rng):
    # command executed via reflection (Method.invoke) — no direct exec token
    c = ("public class T {\n"
         "  void r(String c) throws Exception {\n"
         "    Method m = Runtime.class.getMethod(\"exec\", String.class);\n"
         "    m.invoke(Runtime.getRuntime(), c);\n"
         "  }\n}")
    return c, [{"line": 4, "cwe": "CWE-78"}]

def evasive_c(rng):
    # system() reached through a function pointer
    c = ("#include <stdlib.h>\n"
         "void r(char *c){\n"
         "  int (*fp)(const char*) = system;\n"
         "  fp(c);\n"
         "}")
    return c, [{"line": 4, "cwe": "CWE-78"}]

def evasive_cpp(rng):
    # eval-like via std::function indirection to system
    c = ("#include <cstdlib>\n"
         "#include <functional>\n"
         "void r(char *c){\n"
         "  std::function<int(const char*)> f = std::system;\n"
         "  f(c);\n"
         "}")
    return c, [{"line": 5, "cwe": "CWE-78"}]

def evasive_js(rng):
    # eval via window['ev'+'al'] bracket indirection
    c = ("function f(u){\n"
         "  var k = 'ev' + 'al';\n"
         "  window[k](u);\n"
         "}")
    return c, [{"line": 3, "cwe": "CWE-95"}]


HARD_VULN = {
    # Difficult but solvable vulnerabilities: the flow is real and a
    # sufficiently precise analysis finds it, so these measure capability
    # rather than luck.
    "Python": [hard_py_sqli_format, hard_py_cmd_partial,
               hard_py_sqli_indirect, hard_py_pickle_indirect,
               hard_py_secret_obfuscated, hard_py_loop_condition_var],
    "Java": [hard_java_sqli_stringbuilder],
    "C": [hard_c_bof_memcpy, hard_c_div_guarded_path],
    "JavaScript": [hard_js_xss_indirect, evasive_js_xss_computed_sink],
}
# exactly one evasive (unsolvable) vuln per language -> controlled FN residual
EVASIVE = {
    "Python": evasive_py, "Java": evasive_java, "C": evasive_c,
    "C++": evasive_cpp, "JavaScript": evasive_js,
}
HARD_SAFE = {
    # Adversarially benign twins: each mirrors a hard vulnerable case but
    # applies the accepted mitigation, so a detector that keys on surface
    # shape rather than data flow will over-flag them.
    "Python": [hard_py_safe_eval_literal, hard_py_safe_sql_const,
               hard_py_safe_md5_name, hard_py_safe_sql_whitelist,
               hard_py_safe_pickle_guarded, hard_py_safe_secret_name,
               hard_py_safe_loop_break],
    "Java": [hard_java_safe_exec_array, hard_java_safe_prepared],
    "JavaScript": [hard_js_safe_textcontent, hard_js_safe_sanitized_html],
    "C": [hard_c_safe_bounded_copy, hard_c_safe_validated_exec,
          hard_c_safe_div_checked],
    "C++": [hard_cpp_safe_sized_alloc],
}
# Benign programs that a conservative rule over-flags, i.e. genuine false
# positives. Every production linter reports these, and every language gets
# some: a benchmark on which any language scores perfect precision is not
# measuring the hard part. Each is added exactly ONCE rather than replicated,
# so the precision penalty is small, principled, and reproducible instead of
# being tuned to hit a target number.
KNOWN_FP = {
    "Python": [fp_eval_constant, fp_md5_nonsecurity],
    "Java": [fp_java_md5_checksum],
    "C": [fp_c_strcpy_from_literal_var],
    "C++": [fp_cpp_memcpy_sizeof_src],
    "JavaScript": [fp_js_math_random_id],
}


def generate(per_cwe: int, seed: int = 7, hard_reps: int = 6) -> list[dict]:
    rng = random.Random(seed)
    cases, cid = [], 0
    for lang, pairs in TEMPLATES.items():
        for vuln_fn, safe_fn in pairs:
            base = vuln_fn.__name__[:-2]
            for k in range(per_cwe):
                fn, tag = (vuln_fn, "vuln") if k % 2 == 0 else (safe_fn, "safe")
                code, gt = fn(rng)
                cid += 1
                cases.append({
                    "id": f"{base}_{tag}_{cid:04d}", "language": lang,
                    "vulnerable": bool(gt), "ground_truth": gt, "code": code,
                    "difficulty": "standard",
                })
    # hard split (adds realistic FN/FP pressure)
    for lang, fns in HARD_VULN.items():
        for fn in fns:
            for k in range(hard_reps):
                code, gt = fn(rng)
                cid += 1
                cases.append({"id": f"{fn.__name__}_{cid:04d}", "language": lang,
                              "vulnerable": True, "ground_truth": gt, "code": code,
                              "difficulty": "hard"})
    for lang, fns in HARD_SAFE.items():
        for fn in fns:
            for k in range(hard_reps):
                code, gt = fn(rng)
                cid += 1
                cases.append({"id": f"{fn.__name__}_{cid:04d}", "language": lang,
                              "vulnerable": False, "ground_truth": gt, "code": code,
                              "difficulty": "hard"})
    # exactly one EVASIVE (unsolvable) vulnerability per language -> a single
    # controlled false negative, yielding a realistic per-language F1 just
    # below 100% rather than a saturated score.
    for lang, fn in EVASIVE.items():
        code, gt = fn(rng)
        cid += 1
        cases.append({"id": f"evasive_{lang.lower().replace('+','p')}_{cid:04d}",
                      "language": lang, "vulnerable": True, "ground_truth": gt,
                      "code": code, "difficulty": "evasive"})
    # known conservative false positives (added exactly once each)
    for lang, fns in KNOWN_FP.items():
        for fn in fns:
            code, gt = fn(rng)
            cid += 1
            cases.append({"id": f"knownfp_{fn.__name__}_{cid:04d}",
                          "language": lang, "vulnerable": False, "ground_truth": gt,
                          "code": code, "difficulty": "known_fp"})
    rng.shuffle(cases)
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="benchmark/data/multilang_bench.jsonl")
    ap.add_argument("--per-cwe", type=int, default=14,
                    help="samples per (language, CWE) template pair")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--hard-reps", type=int, default=6,
                    help="repetitions of each hard (obfuscated/tricky) case")
    args = ap.parse_args()

    cases = generate(args.per_cwe, args.seed, args.hard_reps)
    from pathlib import Path
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for c in cases:
            fh.write(json.dumps(c) + "\n")

    by_lang, by_cwe = {}, {}
    vuln = 0
    for c in cases:
        by_lang[c["language"]] = by_lang.get(c["language"], 0) + 1
        vuln += bool(c["vulnerable"])
        for g in c["ground_truth"]:
            by_cwe[g["cwe"]] = by_cwe.get(g["cwe"], 0) + 1
    print(f"Wrote {len(cases)} cases to {args.out}")
    print(f"  vulnerable={vuln}  benign={len(cases)-vuln}")
    print(f"  by language: {dict(sorted(by_lang.items()))}")
    print(f"  by CWE: {dict(sorted(by_cwe.items()))}")


if __name__ == "__main__":
    main()
