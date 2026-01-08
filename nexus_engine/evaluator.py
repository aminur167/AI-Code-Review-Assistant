"""
Empirical Evaluation Engine
===========================
IEEE-standard benchmark evaluation against line-level ground truth.

Given ground-truth annotations [(line, cwe?)] and detected findings,
computes the confusion matrix with line-tolerance matching and derives:

    Precision, Recall, F1, Accuracy, MCC (Matthews Correlation
    Coefficient), FPR, FNR.

TN is defined at line granularity: analyzable SLOC that are neither
flagged nor buggy (standard practice for line-level static-analysis
benchmarks such as Juliet).
"""

import math
from dataclasses import dataclass, field

# CWE identifiers that name the same weakness at different levels of the MITRE
# hierarchy. A benchmark may label a stack overflow CWE-121 while a detector
# reports the parent class CWE-120; both are correct, and scoring them as a
# mismatch would count one finding as simultaneously a false positive and a
# false negative. Each group below is a set of mutually acceptable labels.
_CWE_EQUIVALENT = [
    # Buffer overflow: classic (120) / stack (121) / heap (122) / write-what-
    # where (787) / bounds (119) / unchecked input to buffer (680)
    {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-787", "CWE-680", "CWE-805"},
    # Dangerous function use (242 / 676) is the mechanism behind those copies
    {"CWE-242", "CWE-676"},
    # Weak crypto: broken algorithm (327) / reversible hash (328) / weak PRNG
    {"CWE-326", "CWE-327", "CWE-328"},
    # Injection families that benchmarks label inconsistently
    {"CWE-77", "CWE-78"},
    {"CWE-94", "CWE-95"},
    # Path traversal: relative (23) / absolute (36) / general (22)
    {"CWE-22", "CWE-23", "CWE-36"},
]

_CWE_ALIASES: dict[str, set] = {}
for _group in _CWE_EQUIVALENT:
    for _c in _group:
        _CWE_ALIASES[_c] = _group


def cwe_matches(found: str, expected: str) -> bool:
    """
    True when a reported CWE is an acceptable label for the expected one.

    Exact agreement always matches; otherwise the two must belong to the same
    equivalence group above. This keeps CWE-matched scoring meaningful without
    penalising a detector for choosing a different level of the same
    weakness taxonomy.
    """
    if not expected or not found:
        return True
    if found == expected:
        return True
    return found in _CWE_ALIASES.get(expected, set())


@dataclass
class EvalResult:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    matched_pairs: list = field(default_factory=list)
    unmatched_gt: list = field(default_factory=list)
    unmatched_findings: list = field(default_factory=list)

    # ---- derived metrics ----
    @property
    def precision(self):
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self):
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self):
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self):
        total = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / total if total else 0.0

    @property
    def mcc(self):
        num = self.tp * self.tn - self.fp * self.fn
        den = math.sqrt((self.tp + self.fp) * (self.tp + self.fn)
                        * (self.tn + self.fp) * (self.tn + self.fn))
        return num / den if den else 0.0

    @property
    def false_positive_rate(self):
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0

    @property
    def false_negative_rate(self):
        return self.fn / (self.fn + self.tp) if (self.fn + self.tp) else 0.0

    def to_dict(self):
        return {
            "TP": self.tp, "FP": self.fp, "FN": self.fn, "TN": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "mcc": round(self.mcc, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "matched": self.matched_pairs,
            "missed_ground_truth": self.unmatched_gt,
            "extra_findings": self.unmatched_findings,
        }


def evaluate(findings: list[dict], ground_truth: list[dict], sloc: int,
             line_tolerance: int = 1, match_cwe: bool = False) -> EvalResult:
    """
    findings     : [{line, cwe, message, ...}]
    ground_truth : [{"line": int, "cwe": "CWE-89" (optional)}]
    sloc         : source lines of code (for TN estimation)
    """
    res = EvalResult()
    remaining = list(ground_truth)
    info_free = [f for f in findings if f.get("severity") != "INFO" and f.get("line", 0) > 0]

    for f in info_free:
        match = None
        for gt in remaining:
            if abs(f.get("line", 0) - gt["line"]) <= line_tolerance:
                if match_cwe and gt.get("cwe") \
                        and not cwe_matches(f.get("cwe"), gt["cwe"]):
                    continue
                match = gt
                break
        if match:
            remaining.remove(match)
            res.tp += 1
            res.matched_pairs.append({"gt_line": match["line"], "found_line": f["line"],
                                      "cwe": f.get("cwe"), "rule": f.get("rule_id")})
        else:
            res.fp += 1
            res.unmatched_findings.append({"line": f.get("line"), "rule": f.get("rule_id"),
                                           "message": f.get("message", "")[:60]})
    res.fn = len(remaining)
    res.unmatched_gt = remaining
    res.tn = max(0, sloc - res.tp - res.fp - res.fn)
    return res


def per_cwe_breakdown(per_case_results: list, line_tolerance: int = 1) -> dict:
    """
    Precision/recall per CWE class (the paper's RQ2 table).

    Takes the *per-case* findings and ground truth, and matches them strictly
    within each case. Pooling every program's findings into one list before
    matching -- the obvious implementation -- lets a finding reported in one
    program satisfy a ground-truth annotation in a different program, which
    inflates true positives, hides false negatives, and can report a perfect
    score for a class the analyzer actually misses. Matching per case makes
    the breakdown consistent with the aggregate confusion matrix.

    ``per_case_results`` is a list of ``(findings, ground_truth, sloc)``.
    """
    cwes = set()
    for findings, gt, _ in per_case_results:
        cwes |= {g.get("cwe") for g in gt if g.get("cwe")}
        cwes |= {f.get("cwe") for f in findings if f.get("cwe")}

    # Report one row per *ground-truth* class. Rows are keyed by the label the
    # benchmark uses, and a finding counts toward that row when its CWE is an
    # accepted equivalent -- otherwise a detector reporting the parent class
    # CWE-120 for a CWE-121 case would produce an all-false-positive row for
    # CWE-120 and an all-false-negative row for CWE-121, describing one
    # taxonomy disagreement as two separate failures.
    gt_cwes = {g.get("cwe") for _, gt, _ in per_case_results
               for g in gt if g.get("cwe")}

    out = {}
    for cwe in sorted(cwes):
        if gt_cwes and cwe not in gt_cwes:
            continue
        agg = EvalResult()
        for findings, gt, sloc in per_case_results:
            f_sub = [f for f in findings if cwe_matches(f.get("cwe"), cwe)]
            g_sub = [g for g in gt if g.get("cwe") == cwe]
            if not f_sub and not g_sub:
                continue
            r = evaluate(f_sub, g_sub, sloc, line_tolerance)
            agg.tp += r.tp
            agg.fp += r.fp
            agg.fn += r.fn
        if not (agg.tp or agg.fp or agg.fn):
            continue
        out[cwe] = {"TP": agg.tp, "FP": agg.fp, "FN": agg.fn,
                    "precision": round(agg.precision, 3),
                    "recall": round(agg.recall, 3),
                    "f1": round(agg.f1, 3)}
    return out
