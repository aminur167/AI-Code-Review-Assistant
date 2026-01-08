"""
Research Dataset Generator
==========================
Produces a large, diverse, line-accurately-labeled benchmark in the JSONL
format consumed by benchmark/harness.py. Each generated program is a
realistic vulnerable OR benign variant across the CWE classes NexusReview
targets. Ground-truth line numbers are computed exactly from the emitted
source, so the labels are always correct.

This is a *synthetic curated* benchmark (like the NIST Juliet philosophy:
matched good/bad pairs). To evaluate on an external suite instead, use
benchmark/adapters.py.

Usage:
    python -m benchmark.generate_dataset --out benchmark/data/nexus_bench.jsonl --n 200
"""

import argparse
import json
import random


# -------------------------------------------------------------------------
# Each template returns (code, ground_truth) where ground_truth is a list of
# {"line": int, "cwe": str}. Line numbers are 1-indexed into the returned
# code. Vulnerable templates carry >=1 gt entry; benign carry [].
# -------------------------------------------------------------------------

def _find_line(code: str, needle: str, occurrence: int = 1) -> int:
    hits = 0
    for i, line in enumerate(code.split("\n"), 1):
        if needle in line:
            hits += 1
            if hits == occurrence:
                return i
    return 1


# ---- CWE-89 : SQL Injection ---------------------------------------------
def sqli_vuln(rng):
    var = rng.choice(["user_id", "uid", "name", "email"])
    code = (f"import sqlite3\n"
            f"def lookup(conn, {var}):\n"
            f"    q = \"SELECT * FROM accounts WHERE k = \" + {var}\n"
            f"    conn.cursor().execute(q)\n"
            f"    return conn.cursor().fetchall()\n")
    return code, [{"line": _find_line(code, "execute(q)"), "cwe": "CWE-89"}]


def sqli_safe(rng):
    var = rng.choice(["user_id", "uid", "name"])
    code = (f"import sqlite3\n"
            f"def lookup(conn, {var}):\n"
            f"    conn.cursor().execute(\"SELECT * FROM accounts WHERE k = ?\", ({var},))\n"
            f"    return conn.cursor().fetchall()\n")
    return code, []


# ---- CWE-78 : OS Command Injection --------------------------------------
def cmdi_vuln(rng):
    style = rng.randint(0, 2)
    if style == 0:
        code = ("import os\n"
                "def ping(host):\n"
                "    target = host\n"
                "    os.system('ping ' + target)\n")
        return code, [{"line": _find_line(code, "os.system"), "cwe": "CWE-78"}]
    if style == 1:
        code = ("import os\n"
                "def run():\n"
                "    os.system(input('cmd> '))\n")
        return code, [{"line": _find_line(code, "os.system"), "cwe": "CWE-78"}]
    code = ("import subprocess\n"
            "def run(cmd):\n"
            "    subprocess.call(cmd, shell=True)\n")
    return code, [{"line": _find_line(code, "subprocess.call"), "cwe": "CWE-78"}]


def cmdi_safe(rng):
    code = ("import subprocess\n"
            "def ping(host):\n"
            "    subprocess.run(['ping', '-c', '1', host], shell=False)\n")
    return code, []


# ---- CWE-95/94 : Code Injection (eval/exec), incl. interprocedural ------
def codeinj_vuln(rng):
    if rng.random() < 0.5:
        code = ("def handle():\n"
                "    data = input('expr: ')\n"
                "    sink(data)\n"
                "def sink(x):\n"
                "    eval(x)\n")
        return code, [{"line": _find_line(code, "eval(x)"), "cwe": "CWE-95"}]
    code = ("def calc():\n"
            "    formula = input('f: ')\n"
            "    exec(formula)\n")
    return code, [{"line": _find_line(code, "exec("), "cwe": "CWE-94"}]


def codeinj_safe(rng):
    code = ("import ast\n"
            "def calc():\n"
            "    formula = input('f: ')\n"
            "    return ast.literal_eval(formula)\n")
    return code, []


# ---- CWE-22 : Path Traversal --------------------------------------------
def pathtrav_vuln(rng):
    code = ("def read_file():\n"
            "    name = input('file: ')\n"
            "    with open(name) as f:\n"
            "        return f.read()\n")
    return code, [{"line": _find_line(code, "open(name)"), "cwe": "CWE-22"}]


def pathtrav_safe(rng):
    code = ("import os\n"
            "BASE = '/data'\n"
            "def read_file():\n"
            "    name = os.path.basename(input('file: '))\n"
            "    with open(os.path.join(BASE, name)) as f:\n"
            "        return f.read()\n")
    return code, []


# ---- CWE-502 : Insecure Deserialization ---------------------------------
def deserial_vuln(rng):
    if rng.random() < 0.5:
        code = ("import pickle\n"
                "def load(blob):\n"
                "    return pickle.loads(blob)\n")
        return code, [{"line": _find_line(code, "pickle.loads"), "cwe": "CWE-502"}]
    code = ("import yaml\n"
            "def load(s):\n"
            "    return yaml.load(s)\n")
    return code, [{"line": _find_line(code, "yaml.load"), "cwe": "CWE-502"}]


def deserial_safe(rng):
    code = ("import json\n"
            "def load(s):\n"
            "    return json.loads(s)\n")
    return code, []


# ---- CWE-798 : Hardcoded Secret -----------------------------------------
def secret_vuln(rng):
    key = rng.choice(["password", "api_key", "secret_token", "auth_key"])
    val = "".join(rng.choice("abcdef0123456789") for _ in range(24))
    code = (f"{key} = \"{val}\"\n"
            f"def connect():\n"
            f"    return authenticate({key})\n"
            f"def authenticate(k):\n"
            f"    return k is not None\n")
    return code, [{"line": 1, "cwe": "CWE-798"}]


def secret_safe(rng):
    key = rng.choice(["password", "api_key"])
    code = (f"import os\n"
            f"{key} = os.environ.get('{key.upper()}')\n"
            f"def connect():\n"
            f"    return {key} is not None\n")
    return code, []


# ---- CWE-327 : Weak Hash -------------------------------------------------
def weakhash_vuln(rng):
    algo = rng.choice(["md5", "sha1"])
    code = (f"import hashlib\n"
            f"def digest(data):\n"
            f"    return hashlib.{algo}(data).hexdigest()\n")
    return code, [{"line": _find_line(code, algo), "cwe": "CWE-327"}]


def weakhash_safe(rng):
    code = ("import hashlib\n"
            "def digest(data):\n"
            "    return hashlib.sha256(data).hexdigest()\n")
    return code, []


# ---- CWE-369 : Division by Zero -----------------------------------------
def divzero_vuln(rng):
    if rng.random() < 0.5:
        code = ("def ratio(total):\n"
                "    count = 0\n"
                "    return total / count\n")
        return code, [{"line": _find_line(code, "total / count"), "cwe": "CWE-369"}]
    code = ("def scale(x):\n"
            "    return x / 0\n")
    return code, [{"line": _find_line(code, "x / 0"), "cwe": "CWE-369"}]


def divzero_safe(rng):
    code = ("def ratio(total, count):\n"
            "    if count == 0:\n"
            "        return 0\n"
            "    return total / count\n")
    return code, []


# ---- CWE-835 : Infinite Loop --------------------------------------------
def infloop_vuln(rng):
    if rng.random() < 0.5:
        code = ("def poll():\n"
                "    i = 0\n"
                "    while i < 100:\n"
                "        print(i)\n")
        return code, [{"line": _find_line(code, "while i"), "cwe": "CWE-835"}]
    code = ("def spin():\n"
            "    while True:\n"
            "        x = compute()\n")
    return code, [{"line": _find_line(code, "while True"), "cwe": "CWE-835"}]


def infloop_safe(rng):
    code = ("def poll():\n"
            "    i = 0\n"
            "    while i < 100:\n"
            "        print(i)\n"
            "        i += 1\n")
    return code, []


# ---- benign filler (clean utility code) ---------------------------------
def clean_util(rng):
    kind = rng.randint(0, 3)
    if kind == 0:
        code = ("def area(radius):\n"
                "    pi = 3.14159\n"
                "    return pi * radius * radius\n")
    elif kind == 1:
        code = ("def fib(n):\n"
                "    a, b = 0, 1\n"
                "    for _ in range(n):\n"
                "        a, b = b, a + b\n"
                "    return a\n")
    elif kind == 2:
        code = ("def normalize(values):\n"
                "    total = sum(values)\n"
                "    if total == 0:\n"
                "        return values\n"
                "    return [v / total for v in values]\n")
    else:
        code = ("def merge(a, b):\n"
                "    result = dict(a)\n"
                "    result.update(b)\n"
                "    return result\n")
    return code, []


VULN_TEMPLATES = [sqli_vuln, cmdi_vuln, codeinj_vuln, pathtrav_vuln,
                  deserial_vuln, secret_vuln, weakhash_vuln, divzero_vuln,
                  infloop_vuln]
SAFE_TEMPLATES = [sqli_safe, cmdi_safe, codeinj_safe, pathtrav_safe,
                  deserial_safe, secret_safe, weakhash_safe, divzero_safe,
                  infloop_safe, clean_util]


def generate(n: int, seed: int = 42, vuln_ratio: float = 0.55) -> list[dict]:
    rng = random.Random(seed)
    cases, counters = [], {}
    for _ in range(n):
        vulnerable = rng.random() < vuln_ratio
        tmpl = rng.choice(VULN_TEMPLATES if vulnerable else SAFE_TEMPLATES)
        code, gt = tmpl(rng)
        base = tmpl.__name__
        counters[base] = counters.get(base, 0) + 1
        cases.append({
            "id": f"{base}_{counters[base]:03d}",
            "language": "Python",
            "vulnerable": bool(gt),
            "ground_truth": gt,
            "code": code,
        })
    rng.shuffle(cases)
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="benchmark/data/nexus_bench.jsonl")
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--vuln-ratio", type=float, default=0.55)
    args = ap.parse_args()

    cases = generate(args.n, args.seed, args.vuln_ratio)
    from pathlib import Path
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for c in cases:
            fh.write(json.dumps(c) + "\n")

    vuln = sum(1 for c in cases if c["vulnerable"])
    cwe = {}
    for c in cases:
        for g in c["ground_truth"]:
            cwe[g["cwe"]] = cwe.get(g["cwe"], 0) + 1
    print(f"Wrote {len(cases)} cases to {args.out}")
    print(f"  vulnerable: {vuln}  benign: {len(cases) - vuln}")
    print(f"  CWE distribution: {dict(sorted(cwe.items()))}")


if __name__ == "__main__":
    main()
