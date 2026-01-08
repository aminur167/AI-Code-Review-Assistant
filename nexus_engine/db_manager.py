"""
SQLite Persistence Layer
========================
Stores scan history and findings for longitudinal analysis and the
dashboard's History panel.
"""

import json
import sqlite3
from contextlib import contextmanager

DB_PATH = "nexus_research.db"


@contextmanager
def _conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with _conn() as conn:
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            language TEXT, loc INTEGER, sloc INTEGER,
            findings INTEGER, critical INTEGER, high INTEGER,
            quality_score REAL, complexity INTEGER,
            maintainability REAL, latency_total REAL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            rule_id TEXT, cwe TEXT, severity TEXT, category TEXT,
            line INTEGER, message TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS benchmark_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            dataset TEXT, files INTEGER,
            tp INTEGER, fp INTEGER, fn INTEGER, tn INTEGER,
            precision REAL, recall REAL, f1 REAL, mcc REAL,
            mean_latency REAL, details TEXT)""")


def log_scan(result: dict) -> int:
    sev = {}
    for f in result.get("findings", []):
        sev[f.get("severity")] = sev.get(f.get("severity"), 0) + 1
    with _conn() as conn:
        c = conn.cursor()
        c.execute("""INSERT INTO scans (language, loc, sloc, findings, critical, high,
                     quality_score, complexity, maintainability, latency_total)
                     VALUES (?,?,?,?,?,?,?,?,?,?)""",
                  (result.get("language"),
                   result.get("metrics", {}).get("loc", {}).get("total", 0),
                   result.get("metrics", {}).get("loc", {}).get("sloc", 0),
                   len(result.get("findings", [])),
                   sev.get("CRITICAL", 0), sev.get("HIGH", 0),
                   result.get("quality_score", 0),
                   result.get("metrics", {}).get("cyclomatic_complexity", 0),
                   result.get("metrics", {}).get("maintainability_index", 0),
                   result.get("latency", {}).get("total", 0)))
        scan_id = c.lastrowid
        for f in result.get("findings", []):
            c.execute("""INSERT INTO findings (scan_id, rule_id, cwe, severity,
                         category, line, message) VALUES (?,?,?,?,?,?,?)""",
                      (scan_id, f.get("rule_id"), f.get("cwe"), f.get("severity"),
                       f.get("category"), f.get("line"), f.get("message")))
        return scan_id


def log_benchmark(dataset: str, files: int, eval_dict: dict, mean_latency: float):
    with _conn() as conn:
        conn.cursor().execute(
            """INSERT INTO benchmark_runs (dataset, files, tp, fp, fn, tn,
               precision, recall, f1, mcc, mean_latency, details)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (dataset, files, eval_dict.get("TP", 0), eval_dict.get("FP", 0),
             eval_dict.get("FN", 0), eval_dict.get("TN", 0),
             eval_dict.get("precision", 0), eval_dict.get("recall", 0),
             eval_dict.get("f1_score", 0), eval_dict.get("mcc", 0),
             mean_latency, json.dumps(eval_dict, default=str)[:4000]))


def scan_history(limit: int = 50) -> list[dict]:
    with _conn() as conn:
        c = conn.cursor()
        c.execute("""SELECT id, timestamp, language, loc, findings, critical, high,
                     quality_score, maintainability, latency_total
                     FROM scans ORDER BY id DESC LIMIT ?""", (limit,))
        cols = ["id", "timestamp", "language", "loc", "findings", "critical",
                "high", "quality_score", "maintainability", "latency_total"]
        return [dict(zip(cols, row)) for row in c.fetchall()]
