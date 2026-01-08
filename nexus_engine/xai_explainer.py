"""
XAI Explainer (Explainable AI Layer)
====================================
The ONLY component that touches an LLM. Strict contract:

    The LLM NEVER detects bugs. Detection is 100% deterministic
    (graph theory + rules). The LLM only EXPLAINS verified findings:

        Explain -> Root Cause -> Educational Explanation
                -> Fix Suggestion -> Secure Code Example

Powered by Groq LPU (llama-3.1-8b-instant) for < 1s explanation latency.
Falls back to a deterministic template engine when no API key is set, so
the framework remains fully functional offline.
"""

import json
import os
import time

try:
    from groq import Groq
    from dotenv import load_dotenv
    load_dotenv()
    _key = os.getenv("GROQ_API_KEY")
    _client = Groq(api_key=_key) if _key else None
except Exception:                                     # pragma: no cover
    _client = None

MODEL = "llama-3.1-8b-instant"

# Deterministic fallback knowledge base (used offline / on API failure)
_TEMPLATES = {
    "CWE-89":  ("The SQL statement is concatenated with untrusted input, so the input is parsed "
                "as SQL grammar instead of data.",
                'Use parameterized queries.',
                'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'),
    "CWE-78":  ("Untrusted input becomes part of a shell command, so shell metacharacters "
                "(;, |, &&) let an attacker run arbitrary commands.",
                "Avoid the shell; pass an argument vector.",
                'subprocess.run(["ping", "-c", "1", host], shell=False)'),
    "CWE-22":  ("A user-controlled path can contain ../ sequences that escape the intended "
                "directory.",
                "Normalize and validate the path against a base directory.",
                'safe = os.path.basename(filename); open(os.path.join(BASE_DIR, safe))'),
    "CWE-95":  ("eval() executes any Python expression, so user input becomes executable code.",
                "Never eval user input; parse it instead.",
                "value = ast.literal_eval(user_input)  # literals only"),
    "CWE-94":  ("exec() runs arbitrary statements, giving full code execution.",
                "Remove exec; use explicit dispatch.",
                "actions = {'start': start_fn}; actions[cmd]()"),
    "CWE-798": ("Credentials in source code leak through version control and binaries.",
                "Move secrets to environment variables or a secret manager.",
                'API_KEY = os.environ["API_KEY"]'),
    "CWE-327": ("MD5/SHA-1 are collision-broken; attackers can forge matching digests.",
                "Use a modern hash (SHA-256+) or a password KDF.",
                "hashlib.sha256(data).hexdigest()  # or bcrypt/argon2 for passwords"),
    "CWE-369": ("The denominator can be zero on at least one execution path, raising "
                "ZeroDivisionError at runtime.",
                "Guard the division.",
                "result = x / d if d else 0"),
    "CWE-835": ("The loop condition never becomes false because no variable in it changes, "
                "so execution never terminates.",
                "Mutate the condition variable or add a break.",
                "while i < n:\n    ...\n    i += 1"),
    "CWE-502": ("Deserializing untrusted bytes can instantiate arbitrary objects and "
                "execute code (__reduce__).",
                "Use a safe format.",
                "data = json.loads(payload)  # or yaml.safe_load"),
    "CWE-563": ("The assigned value is never read, which usually signals a logic slip "
                "(wrong variable name) or leftover code.",
                "Delete the assignment or use the value.",
                "# remove the unused assignment"),
    "CWE-120": ("The copy has no bounds check, so input longer than the buffer overwrites "
                "adjacent memory.",
                "Use a bounded copy.",
                "strncpy(dst, src, sizeof(dst) - 1); dst[sizeof(dst)-1] = '\\0';"),
    "CWE-79":  ("Untrusted data is written into the DOM as HTML, so injected <script> runs.",
                "Escape or use textContent.",
                "element.textContent = userInput;"),
}
_DEFAULT = ("The detected construct violates a well-known secure-coding rule.",
            "Apply the referenced CWE mitigation.",
            "# see https://cwe.mitre.org/")


def _template_explain(finding: dict) -> dict:
    root, fix, example = _TEMPLATES.get(finding.get("cwe", ""), _DEFAULT)
    return {
        "root_cause": root,
        "education": f"{finding.get('message', '')}. {root} This class of defect is "
                     f"catalogued as {finding.get('cwe')} in the MITRE CWE taxonomy.",
        "fix_suggestion": finding.get("fix_hint") or fix,
        "secure_example": example,
        "explained_by": "deterministic-template",
    }


def explain_findings(findings: list[dict], code: str, use_llm: bool = True,
                     max_explain: int = 10) -> list[dict]:
    """Attach XAI explanations to verified findings. Mutates and returns findings."""
    lines = code.split("\n")
    for i, f in enumerate(findings):
        if i >= max_explain or not use_llm or _client is None:
            f["xai"] = _template_explain(f)
            continue
        line_no = f.get("line", 0)
        snippet = "\n".join(lines[max(0, line_no - 3): line_no + 2])
        pdg_slice = f.get("pdg_slice", {"slice_lines": [], "nodes": [], "edges": []})
        sys_prompt = (
            "You are the XAI (Explainable AI) module of a static analyzer. The bug below was "
            "ALREADY VERIFIED by deterministic graph analysis. You MUST NOT detect, suggest, "
            "rank, or mention any new bug. Treat the supplied PDG slice as the complete and "
            "only evidence: do not infer dependencies, source locations, paths, or APIs absent "
            "from it. Explain only the provided finding's deterministic source-to-sink trace and "
            "a remediation. Explain pedagogically for a student. "
            'Return ONLY JSON: {"root_cause": "...", "education": "...", '
            '"fix_suggestion": "...", "secure_example": "..."}'
        )
        user_prompt = (f"Verified bug: {f.get('message')}\nCWE: {f.get('cwe')}\n"
                       f"Sink criterion line {line_no}:\n```\n{snippet}\n```\n"
                       "Deterministic PDG backward slice (JSON):\n"
                       f"{json.dumps(pdg_slice, sort_keys=True)}")
        try:
            res = _client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "system", "content": sys_prompt},
                          {"role": "user", "content": user_prompt}],
                response_format={"type": "json_object"},
                temperature=0.2, max_tokens=400,
            )
            data = json.loads(res.choices[0].message.content)
            f["xai"] = {
                "root_cause": data.get("root_cause", ""),
                "education": data.get("education", ""),
                "fix_suggestion": data.get("fix_suggestion", ""),
                "secure_example": data.get("secure_example", ""),
                "explained_by": f"groq/{MODEL}",
            }
        except Exception as e:
            if "429" in str(e):
                time.sleep(2)
            f["xai"] = _template_explain(f)
    return findings
