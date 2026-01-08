"""
SARIF Exporter
==============
Exports findings as SARIF 2.1.0 (Static Analysis Results Interchange
Format, OASIS standard) — consumable by GitHub Code Scanning, VS Code
SARIF Viewer, Azure DevOps, etc.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json

SEVERITY_TO_LEVEL = {"CRITICAL": "error", "HIGH": "error",
                     "MEDIUM": "warning", "LOW": "note", "INFO": "note"}

TOOL_VERSION = "1.0.0"


def to_sarif(findings: list[dict], artifact_uri: str = "input.py") -> dict:
    rules_seen = {}
    results = []
    for f in findings:
        rid = f.get("rule_id", "NEXUS-000")
        if rid not in rules_seen:
            rules_seen[rid] = {
                "id": rid,
                "name": rid.replace("-", ""),
                "shortDescription": {"text": f.get("message", rid)[:120]},
                "helpUri": f"https://cwe.mitre.org/data/definitions/"
                           f"{f.get('cwe', 'CWE-0').replace('CWE-', '')}.html",
                "properties": {"cwe": f.get("cwe", ""), "category": f.get("category", ""),
                               "severity": f.get("severity", "")},
            }
        result = {
            "ruleId": rid,
            "level": SEVERITY_TO_LEVEL.get(f.get("severity", "MEDIUM"), "warning"),
            "message": {"text": f.get("message", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": {"startLine": max(1, int(f.get("line", 1) or 1))},
                }
            }],
            "properties": {
                "cwe": f.get("cwe", ""),
                "owasp": f.get("owasp", ""),
                "security-severity": str(round(f.get("confidence", 0.75) * 10, 1)),
                "confidence": f.get("confidence", ""),
                "evidence": f.get("evidence", ""),
                "fix_hint": f.get("fix_hint", ""),
            },
        }
        if f.get("xai"):
            result["properties"]["xai_root_cause"] = f["xai"].get("root_cause", "")
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
                   "Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "NexusReview",
                "organization": "NexusReview Research",
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/nexusreview",
                "rules": list(rules_seen.values()),
            }},
            "results": results,
        }],
    }


def to_sarif_json(findings: list[dict], artifact_uri: str = "input.py") -> str:
    return json.dumps(to_sarif(findings, artifact_uri), indent=2)
