"""
CWE -> OWASP Top-10 (2021) mapping and confidence model
=======================================================
Enriches every finding with:
  - OWASP Top-10 (2021) category
  - a confidence score derived from the detection method

Confidence model (deterministic, not learned):
  - Taint-verified source->sink flow ....... 0.95  (proven data flow)
  - Interprocedural taint flow ............. 0.90
  - AST pattern with structural guard ...... 0.85  (e.g. concat SQL, exec+var)
  - Simple signature/pattern match ......... 0.75
  - Metric-threshold finding ............... 0.70
Confidence is a transparency signal for the reviewer, never a detection gate.
"""

# CWE id -> OWASP 2021 category
CWE_TO_OWASP = {
    "CWE-89":  "A03:2021-Injection",
    "CWE-78":  "A03:2021-Injection",
    "CWE-94":  "A03:2021-Injection",
    "CWE-95":  "A03:2021-Injection",
    "CWE-79":  "A03:2021-Injection",           # XSS folded into Injection in 2021
    "CWE-77":  "A03:2021-Injection",
    "CWE-22":  "A01:2021-Broken Access Control",
    "CWE-601": "A01:2021-Broken Access Control",
    "CWE-798": "A07:2021-Identification and Authentication Failures",
    "CWE-259": "A07:2021-Identification and Authentication Failures",
    "CWE-327": "A02:2021-Cryptographic Failures",
    "CWE-328": "A02:2021-Cryptographic Failures",
    "CWE-338": "A02:2021-Cryptographic Failures",
    "CWE-502": "A08:2021-Software and Data Integrity Failures",
    "CWE-120": "A06:2021-Vulnerable and Outdated Components",  # memory-safety class
    "CWE-125": "A06:2021-Vulnerable and Outdated Components",
    "CWE-476": "A06:2021-Vulnerable and Outdated Components",
    "CWE-1336": "A03:2021-Injection",          # SSTI
    "CWE-611": "A05:2021-Security Misconfiguration",  # XXE
    "CWE-918": "A10:2021-Server-Side Request Forgery",  # SSRF
    "CWE-295": "A02:2021-Cryptographic Failures",
    # logic/quality classes -> not OWASP security categories
    "CWE-369": "N/A (logic defect)",
    "CWE-835": "N/A (logic defect)",
    "CWE-476-logic": "N/A (logic defect)",
    "CWE-561": "N/A (maintainability)",
    "CWE-563": "N/A (maintainability)",
    "CWE-1121": "N/A (maintainability)",
    "CWE-1188": "N/A (logic defect)",
    "CWE-390": "N/A (logic defect)",
}

# rule_id prefix / detection method -> base confidence
_CONFIDENCE_BY_RULE = {
    "SEC-TAINT": 0.95,
    "TAINT-": 0.95,
    "ML-TAINT-": 0.90,
    "SEC-CMDCONCAT": 0.85,
    "SEC-SQLBUILD": 0.85,
    "SEC-SECRET": 0.85,
    "SEC-UNSAFE": 0.80,
    "SEC-WEAKHASH": 0.80,
    "LOG-DIVZERO": 0.85,
    "LOG-INFLOOP": 0.80,
    "QUA-": 0.70,
    "ML-": 0.75,
}


def owasp_for(cwe: str) -> str:
    return CWE_TO_OWASP.get(cwe, "N/A")


def confidence_for(finding: dict) -> float:
    rid = finding.get("rule_id", "")
    # interprocedural taint flows carry an explicit flag
    if finding.get("interprocedural"):
        return 0.90
    for prefix, conf in _CONFIDENCE_BY_RULE.items():
        if rid.startswith(prefix):
            return conf
    return 0.75


def enrich(findings: list[dict]) -> list[dict]:
    """Attach owasp + confidence to each finding (idempotent)."""
    for f in findings:
        f["owasp"] = owasp_for(f.get("cwe", ""))
        f["confidence"] = round(confidence_for(f), 2)
    return findings
