"""
NexusReview regression tests
============================
Behavioural tests for the analysis engine, organised around the claims the
paper makes:

  * the Universal IR lowers all four Tree-sitter languages into a usable
    statement model (definitions, uses, calls, structure);
  * every deep analysis -- CFG, DFG, SSA, PDG, call graph, metrics -- runs for
    all five languages;
  * taint analysis finds real source-to-sink flows, including interprocedural
    ones, and stays silent on sanitized code;
  * the detectors that were added in response to real-benchmark failures
    (macro resolution, buffer capacity, loop bounds, CryptoAPI) keep working.

Run with::

    python -m pytest tests/ -q
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nexus_engine.pipeline import NexusPipeline
from nexus_engine.universal_ir import lower_to_uir, _flatten
from nexus_engine.uir_cfg_builder import build_uir_cfgs

LANGS = ["Python", "Java", "C", "C++", "JavaScript"]


@pytest.fixture(scope="module")
def pipeline():
    return NexusPipeline(use_llm_xai=False)


def findings_of(result, categories=("security", "logic")):
    return [f for f in result.get("findings", [])
            if f.get("category") in categories]


def cwes_of(result):
    return {f["cwe"] for f in findings_of(result)}


# ---------------------------------------------------------------------------
# Universal IR
# ---------------------------------------------------------------------------

class TestUniversalIR:
    def test_all_languages_parse(self):
        samples = {
            "Java": "public class A { int f(int a) { return a + 1; } }",
            "C": "int f(int a) { return a + 1; }",
            "C++": "int f(int a) { return a + 1; }",
            "JavaScript": "function f(a) { return a + 1; }",
        }
        for lang, code in samples.items():
            prog = lower_to_uir(code, lang)
            assert prog.parse_ok, f"{lang} failed to parse: {prog.parse_error}"
            assert prog.functions, f"{lang} produced no functions"
            assert prog.functions[0].params == ["a"], f"{lang} lost its parameter"

    def test_types_are_not_variables(self):
        """`String q = ...` defines q, not String."""
        prog = lower_to_uir(
            "public class A { void f() { String q = \"x\"; int n = 1; } }", "Java")
        defs = set()
        for fn in prog.functions:
            for st in _flatten(fn.body):
                defs |= st.defs
        assert defs == {"q", "n"}, f"type names leaked into defs: {defs}"

    def test_member_path_is_a_read(self):
        """`req.query.name` is a use of the path and its base, never a def."""
        prog = lower_to_uir("function f(req){ const n = req.query.name; }",
                            "JavaScript")
        st = next(s for fn in prog.functions for s in _flatten(fn.body))
        assert "n" in st.defs
        assert "req" in st.uses and "req.query.name" in st.uses

    def test_object_macros_resolve(self):
        """Object-like #define must not hide a variable from data flow."""
        code = ("#define ARG data\n"
                "void f(){ char *data = getenv(\"X\"); system(ARG); }")
        prog = lower_to_uir(code, "C")
        call = next(c for fn in prog.functions for s in _flatten(fn.body)
                    for c in s.calls if c.callee == "system")
        assert ("name", "data") in call.args, \
            f"macro was not resolved: {call.args}"

    def test_fluent_chain_records_inner_call(self):
        code = ("public class A { byte[] h(byte[] d) throws Exception {"
                " return MessageDigest.getInstance(\"MD5\").digest(d); } }")
        prog = lower_to_uir(code, "Java")
        callees = {c.callee for fn in prog.functions
                   for s in _flatten(fn.body) for c in s.calls}
        assert "getInstance" in callees and "digest" in callees


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

class TestCFG:
    def test_loop_emits_back_edge(self):
        prog = lower_to_uir("void f(){ int i=0; while(i<10){ i++; } }", "C")
        cfg = build_uir_cfgs(prog)["f"]
        assert cfg.stats()["back_edges"] >= 1

    def test_try_emits_exception_edge(self):
        code = ("public class A { void f(){ try { g(); } "
                "catch (Exception e) { h(); } } }")
        prog = lower_to_uir(code, "Java")
        cfg = build_uir_cfgs(prog)["f"]
        assert cfg.stats()["exception_edges"] >= 1

    def test_branch_has_true_and_false_edges(self):
        prog = lower_to_uir("void f(int a){ if(a){ g(); } else { h(); } }", "C")
        cfg = build_uir_cfgs(prog)["f"]
        labels = {d.get("label") for _, _, d in cfg.graph.edges(data=True)}
        assert {"True", "False"} <= labels

    def test_switch_falls_through(self):
        code = "void f(int a){ switch(a){ case 1: g(); case 2: h(); break; } }"
        prog = lower_to_uir(code, "C")
        cfg = build_uir_cfgs(prog)["f"]
        labels = {d.get("label") for _, _, d in cfg.graph.edges(data=True)}
        assert "fallthrough" in labels


# ---------------------------------------------------------------------------
# Cross-language feature parity (the paper's capability matrix)
# ---------------------------------------------------------------------------

SAMPLES = {
    "Python": "def f(a, b):\n    x = a + 1\n    if x > 0:\n        return x\n    return b\n",
    "Java": ("public class A { int f(int a, int b){ int x = a + 1;"
             " if (x > 0) { return x; } return b; } }"),
    "C": "int f(int a, int b){ int x = a + 1; if (x > 0) { return x; } return b; }",
    "C++": "int f(int a, int b){ int x = a + 1; if (x > 0) { return x; } return b; }",
    "JavaScript": ("function f(a, b){ let x = a + 1;"
                   " if (x > 0) { return x; } return b; }"),
}


@pytest.mark.parametrize("lang", LANGS)
def test_every_analysis_runs_for_every_language(pipeline, lang):
    r = pipeline.run(SAMPLES[lang], lang)
    assert not r.get("error"), r.get("error")
    for artifact in ("cfgs", "dfg", "ssa", "pdg", "call_graph_summary",
                     "symbol_table", "metrics", "constant_propagation"):
        assert r.get(artifact), f"{lang}: missing {artifact}"


@pytest.mark.parametrize("lang", LANGS)
def test_metrics_are_computed(pipeline, lang):
    m = pipeline.run(SAMPLES[lang], lang)["metrics"]
    assert m["cyclomatic_complexity"] >= 1
    assert m["halstead"]["volume"] > 0
    assert 0 <= m["maintainability_index"] <= 100
    assert m["loc"]["sloc"] > 0


def test_backward_slice_is_dependency_correct(pipeline):
    code = ("int f(int a, int b) {\n"
            "    int x = a + 1;\n"
            "    int y = b * 2;\n"
            "    int z;\n"
            "    if (x > 0) {\n"
            "        z = x + y;\n"
            "    } else {\n"
            "        z = y;\n"
            "    }\n"
            "    return z;\n"
            "}")
    r = pipeline.run(code, "C")
    pdg = r["pdg_objects"]["f"]
    sl = pdg.slice_lines(6)
    assert 2 in sl and 3 in sl, f"slice lost a dependency: {sl}"
    assert max(sl) <= 6, f"slice reached forward in time: {sl}"


def test_finding_carries_structured_pdg_grounding(pipeline):
    code = ("void f(){\n"
            " char b[64];\n"
            " gets(b);\n"
            " system(b);\n"
            "}\n")
    finding = next(f for f in pipeline.run(code, "C")["findings"]
                   if f.get("cwe") == "CWE-78")
    context = finding["pdg_slice"]
    assert context["criterion_line"] == finding["line"]
    assert finding["line"] in context["slice_lines"]
    assert context["nodes"]


# ---------------------------------------------------------------------------
# Taint analysis
# ---------------------------------------------------------------------------

class TestTaint:
    def test_java_sql_injection(self, pipeline):
        code = ("public class A { void h(HttpServletRequest req) throws Exception {"
                " String u = req.getParameter(\"u\");"
                " conn.createStatement().executeQuery(\"SELECT \" + u); } }")
        assert "CWE-89" in cwes_of(pipeline.run(code, "Java"))

    def test_java_stringbuilder_sql_injection(self, pipeline):
        code = ("public class A { void q(HttpServletRequest r) throws Exception {"
                " String uid = r.getParameter(\"id\");"
                " StringBuilder sb = new StringBuilder(\"SELECT * FROM u WHERE id=\");"
                " sb.append(uid);"
                " stmt.executeQuery(sb.toString()); } }")
        assert "CWE-89" in cwes_of(pipeline.run(code, "Java"))

    def test_java_interprocedural(self, pipeline):
        code = ("public class A {"
                " void run(HttpServletRequest req){ String u = req.getParameter(\"c\");"
                " doIt(u); }"
                " void doIt(String cmd) throws Exception {"
                " Runtime.getRuntime().exec(cmd); } }")
        r = pipeline.run(code, "Java")
        assert "CWE-78" in cwes_of(r)
        assert any(f.get("interprocedural") for f in r["findings"])

    def test_c_multi_statement_flow(self, pipeline):
        code = ("void run(){ char buf[64]; char cmd[128];"
                " gets(buf); sprintf(cmd, \"ls %s\", buf); system(cmd); }")
        assert "CWE-78" in cwes_of(pipeline.run(code, "C"))

    def test_js_dom_xss(self, pipeline):
        code = ("function h(req){ const n = req.query.name;"
                " document.getElementById(\"o\").innerHTML = \"<p>\" + n + \"</p>\"; }")
        assert "CWE-79" in cwes_of(pipeline.run(code, "JavaScript"))

    @pytest.mark.parametrize("lang,code", [
        ("Java", "public class A { void h(HttpServletRequest r) throws Exception {"
                 " int id = Integer.parseInt(r.getParameter(\"u\"));"
                 " conn.createStatement().executeQuery(\"SELECT \" + id); } }"),
        ("C", "void run(){ char buf[64]; fgets(buf, sizeof(buf), stdin);"
              " int n = atoi(buf); printf(\"%d\", n); }"),
        ("JavaScript", "function h(req){ const n = encodeURIComponent(req.query.name);"
                       " document.getElementById(\"o\").innerHTML = n; }"),
    ])
    def test_sanitized_code_is_silent(self, pipeline, lang, code):
        """A validated or encoded value must not raise an injection finding."""
        found = cwes_of(pipeline.run(code, lang))
        assert not ({"CWE-89", "CWE-78", "CWE-79"} & found), \
            f"{lang}: false positive on sanitized input: {found}"


# ---------------------------------------------------------------------------
# Structural detectors added from real-benchmark diagnosis
# ---------------------------------------------------------------------------

class TestStructuralRules:
    def test_buffer_capacity_violation(self, pipeline):
        code = ("void f(char *source){ char *data = new char[50];"
                " strncpy(data, source, 100-1); }")
        assert {"CWE-121", "CWE-122"} & cwes_of(pipeline.run(code, "C++"))

    def test_unbounded_scanf(self, pipeline):
        code = "void f(){ char b[16]; scanf(\"%s\", b); }"
        assert "CWE-120" in cwes_of(pipeline.run(code, "C"))

    def test_bounded_scanf_is_silent(self, pipeline):
        code = "void f(){ char b[16]; scanf(\"%15s\", b); }"
        assert "CWE-120" not in cwes_of(pipeline.run(code, "C"))

    def test_weak_hash_java(self, pipeline):
        code = ("public class A { byte[] h(byte[] d) throws Exception {"
                " return MessageDigest.getInstance(\"MD5\").digest(d); } }")
        assert "CWE-327" in cwes_of(pipeline.run(code, "Java"))

    def test_cryptoapi_weak_algorithm(self, pipeline):
        code = ("void f(HCRYPTPROV p, HCRYPTHASH *h){"
                " CryptCreateHash(p, CALG_SHA1, 0, 0, h); }")
        assert {"CWE-327", "CWE-328"} & cwes_of(pipeline.run(code, "C"))

    def test_hardcoded_secret(self, pipeline):
        code = "function f(){ const api_key = \"sk_live_9f8a7b6c5d4e3f2a1b\"; }"
        assert "CWE-798" in cwes_of(pipeline.run(code, "JavaScript"))

    def test_placeholder_secret_is_silent(self, pipeline):
        code = "function f(){ const password = \"\"; const token = \"TODO\"; }"
        assert "CWE-798" not in cwes_of(pipeline.run(code, "JavaScript"))

    def test_division_by_constant_zero(self, pipeline):
        code = "int f(){ int z = 0; return 10 / z; }"
        assert "CWE-369" in cwes_of(pipeline.run(code, "C"))

    def test_comparison_is_not_a_division(self, pipeline):
        """`if (data != 0)` must never be read as division by zero."""
        code = "int f(int data){ if (data != 0) { return 1; } return 0; }"
        assert "CWE-369" not in cwes_of(pipeline.run(code, "C"))

    def test_unbounded_stream_extraction(self, pipeline):
        code = ("void bad()\n{\n"
                "    char charBuffer[10];\n"
                "    cin >> charBuffer;\n}")
        assert "CWE-676" in cwes_of(pipeline.run(code, "C++"))

    def test_stream_extraction_into_string_is_safe(self, pipeline):
        code = ("void ok()\n{\n"
                "    std::string s;\n"
                "    cin >> s;\n}")
        assert "CWE-676" not in cwes_of(pipeline.run(code, "C++"))

    def test_bounded_copy_within_capacity_is_silent(self, pipeline):
        """A copy that provably fits its destination is not an overflow."""
        code = ("void f()\n{\n"
                "    char *data = new char[100];\n"
                "    char source[100];\n"
                "    strncpy(data, source, 100-1);\n"
                "    delete [] data;\n}")
        found = cwes_of(pipeline.run(code, "C++"))
        assert not ({"CWE-120", "CWE-121", "CWE-122"} & found), found

    def test_infinite_loop(self, pipeline):
        code = "void f(){ while (1) { tick(); } }"
        assert "CWE-835" in cwes_of(pipeline.run(code, "C"))

    def test_loop_with_break_is_silent(self, pipeline):
        code = "void f(){ while (1) { if (done()) break; tick(); } }"
        assert "CWE-835" not in cwes_of(pipeline.run(code, "C"))


# ---------------------------------------------------------------------------
# Python path must not regress
# ---------------------------------------------------------------------------

class TestPythonEntryPoints:
    """
    A function nothing calls receives its arguments from outside, so a
    parameter that reaches a sink unsanitized is a real defect. Python must
    behave the same way the Tree-sitter languages do.
    """

    def test_parameter_reaching_sink_is_reported(self, pipeline):
        code = "import os\ndef f(u):\n    os.system(\"ls \" + u)\n"
        assert "CWE-78" in cwes_of(pipeline.run(code, "Python"))

    def test_sanitized_parameter_is_silent(self, pipeline):
        code = ("import os, shlex\n"
                "def f(u):\n"
                "    os.system(\"ls \" + shlex.quote(u))\n")
        assert "CWE-78" not in cwes_of(pipeline.run(code, "Python"))

    def test_internally_called_function_is_not_an_entry_point(self, pipeline):
        code = ("import os\n"
                "def helper(u):\n"
                "    os.system(u)\n"
                "def main():\n"
                "    helper(\"ls\")\n")
        assert "CWE-78" not in cwes_of(pipeline.run(code, "Python"))

    def test_subprocess_argv_list_is_safe(self, pipeline):
        """`subprocess.run([...], shell=False)` cannot be shell-injected."""
        code = ("import subprocess\n"
                "def r(host):\n"
                "    subprocess.run([\"ping\", host], shell=False)\n")
        assert "CWE-78" not in cwes_of(pipeline.run(code, "Python"))

    def test_subprocess_shell_true_is_reported(self, pipeline):
        code = ("import subprocess\n"
                "def r(host):\n"
                "    subprocess.run(\"ping \" + host, shell=True)\n")
        assert "CWE-78" in cwes_of(pipeline.run(code, "Python"))


def test_python_detectors_still_fire(pipeline):
    code = ("import os, hashlib, pickle\n"
            "def h(u):\n"
            "    q = \"SELECT * FROM t WHERE u=\" + u\n"
            "    cursor.execute(q)\n"
            "    os.system(\"ls \" + u)\n"
            "    eval(u)\n"
            "    pickle.loads(u)\n"
            "    hashlib.md5(u.encode())\n"
            "    x = 1 / 0\n")
    found = cwes_of(pipeline.run(code, "Python"))
    for cwe in ("CWE-89", "CWE-95", "CWE-502", "CWE-327", "CWE-369"):
        assert cwe in found, f"Python regression: {cwe} no longer detected ({found})"


# ---------------------------------------------------------------------------
# Reporting contract
# ---------------------------------------------------------------------------

def test_findings_are_enriched_and_exportable(pipeline):
    import json
    from nexus_engine.sarif_exporter import to_sarif_json

    code = ("public class A { void h(HttpServletRequest r) throws Exception {"
            " String u = r.getParameter(\"u\");"
            " conn.createStatement().executeQuery(\"SELECT \" + u); } }")
    r = pipeline.run(code, "Java")
    f = r["findings"][0]
    assert f["cwe"].startswith("CWE-")
    assert f.get("owasp"), "finding was not enriched with an OWASP category"
    assert 0 < f.get("confidence", 0) <= 1
    assert f.get("xai", {}).get("root_cause"), "no XAI explanation attached"

    sarif = json.loads(to_sarif_json(r["findings"], "A.java"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]


def test_latency_is_interactive(pipeline):
    for lang in LANGS:
        r = pipeline.run(SAMPLES[lang], lang)
        assert r["latency"]["total"] < 5.0, f"{lang} exceeded the 5 s budget"


def test_syntax_error_is_reported_not_raised(pipeline):
    r = pipeline.run("def broken(:\n  pass\n", "Python")
    assert r.get("error") and r["findings"] == []


class TestEvaluator:
    """The scorer must not manufacture agreement that is not there."""

    def test_equivalent_cwes_match(self):
        from nexus_engine.evaluator import cwe_matches
        # CWE-120 (classic overflow) and CWE-121 (stack overflow) name the
        # same defect at different levels of the MITRE hierarchy.
        assert cwe_matches("CWE-120", "CWE-121")
        assert cwe_matches("CWE-122", "CWE-120")
        assert cwe_matches("CWE-327", "CWE-328")

    def test_unrelated_cwes_do_not_match(self):
        from nexus_engine.evaluator import cwe_matches
        assert not cwe_matches("CWE-89", "CWE-120")
        assert not cwe_matches("CWE-79", "CWE-78")

    def test_per_cwe_does_not_match_across_cases(self):
        """
        A finding in one program must never satisfy ground truth in another;
        pooling findings before matching inflates TP and hides FN.
        """
        from nexus_engine.evaluator import per_cwe_breakdown
        case_a = ([{"line": 5, "cwe": "CWE-89"}], [{"line": 5, "cwe": "CWE-89"}], 20)
        case_b = ([], [{"line": 5, "cwe": "CWE-89"}], 20)   # missed entirely
        out = per_cwe_breakdown([case_a, case_b], line_tolerance=2)
        assert out["CWE-89"]["TP"] == 1
        assert out["CWE-89"]["FN"] == 1, "cross-case matching hid a false negative"
