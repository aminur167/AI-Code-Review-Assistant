"""
Universal Rule Set
==================
Deterministic, CWE-mapped detectors for C, C++, Java, and JavaScript that
operate on the Universal IR rather than on raw text.

These complement the universal taint analyzer: taint proves
source-to-sink flows, while the rules here catch defects that are *not*
data-flow shaped -- weak cryptography, hardcoded credentials, unbounded
copies, division by zero, non-terminating loops, and empty exception
handlers.

Every detector consumes parsed structure (statements, calls, arguments,
literals, CFG edges, constant environment). Matching against a real call
node -- rather than a regular expression over a line -- is what keeps the
false-positive rate low: ``system(cmd)`` is recognized as a call to
``system``, while the same characters inside a string literal or a comment
are not.
"""

from __future__ import annotations

import math
import re

from .universal_ir import UProgram, UStmt, _flatten

SECRET_NAME = re.compile(
    r"(password|passwd|\bpwd\b|\bpw\b|secret|api_?key|apikey|token|auth|"
    r"credential|private_?key|access_?key|secret_?key|connection_?string|"
    r"client_?secret|aws_?\w*key)", re.I)

# Placeholder values that are obviously not real credentials.
_PLACEHOLDER = re.compile(
    r"^(|none|null|nil|todo|changeme|xxx+|your_?\w*|<[^>]*>|\*+|\.\.\.|"
    r"example|test|dummy|placeholder|sample|foo|bar)$", re.I)

WEAK_HASHES = {"md5", "sha1", "sha-1", "md4", "md2"}
WEAK_CIPHERS = {"des", "3des", "rc2", "rc4", "blowfish"}

# Windows CryptoAPI selects the algorithm through a numeric identifier macro
# rather than a string, so the literal-based check cannot see it.
_WEAK_CRYPT_CONSTANTS = {
    "CALG_MD2": ("MD2", "CWE-328"), "CALG_MD4": ("MD4", "CWE-328"),
    "CALG_MD5": ("MD5", "CWE-328"), "CALG_SHA": ("SHA-1", "CWE-328"),
    "CALG_SHA1": ("SHA-1", "CWE-328"), "CALG_SHA_160": ("SHA-1", "CWE-328"),
    "CALG_DES": ("DES", "CWE-327"), "CALG_3DES": ("3DES", "CWE-327"),
    "CALG_3DES_112": ("2-key 3DES", "CWE-327"),
    "CALG_RC2": ("RC2", "CWE-327"), "CALG_RC4": ("RC4", "CWE-327"),
    "CALG_RC5": ("RC5", "CWE-327"), "CALG_SKIPJACK": ("Skipjack", "CWE-327"),
}

# CryptoAPI calls that consume the algorithm handle produced above; the flaw
# marker in Juliet sits on the *use*, not only on the selection.
_CRYPTOAPI_USES = {"CryptCreateHash", "CryptHashData", "CryptDeriveKey",
                   "CryptEncrypt", "CryptDecrypt", "CryptGetHashParam"}

# Unbounded C string/memory operations: no length parameter at all.
UNBOUNDED_COPY = {"strcpy": "strncpy", "strcat": "strncat",
                  "wcscpy": "wcsncpy", "wcscat": "wcsncat",
                  "sprintf": "snprintf", "gets": "fgets",
                  "vsprintf": "vsnprintf",
                  "scanf": "scanf with a field width",
                  "fscanf": "fscanf with a field width",
                  "sscanf": "sscanf with a field width",
                  "swscanf": "swscanf with a field width"}

WEAK_RANDOM = {"rand", "srand", "Math.random", "random"}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def _finding(rule_id, cwe, severity, category, line, message,
             evidence="", fix_hint=""):
    return {"rule_id": rule_id, "cwe": cwe, "severity": severity,
            "category": category, "line": line, "message": message,
            "evidence": evidence, "fix_hint": fix_hint}


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------

def _weak_crypto(program: UProgram, lines: list) -> list:
    """Weak hash or cipher selected by a literal algorithm name (CWE-327)."""
    out = []
    seen: set = set()
    for st in _all_stmts(program):
        for call in st.calls:
            for kind, val in [(a[0], a[1]) for a in call.args]:
                if kind != "const" or not isinstance(val, str):
                    continue
                if (st.lineno, val) in seen:
                    continue
                seen.add((st.lineno, val))
                low = val.strip().lower()
                algo = low.split("/")[0]
                if algo in WEAK_HASHES:
                    out.append(_finding(
                        "UNI-WEAKHASH", "CWE-327", "MEDIUM", "security", st.lineno,
                        f"Weak hash algorithm '{val}' is collision-prone and "
                        f"unsuitable for security use",
                        _src(lines, st.lineno),
                        "Use SHA-256 or stronger; for passwords use bcrypt, "
                        "scrypt, or Argon2."))
                elif algo in WEAK_CIPHERS:
                    out.append(_finding(
                        "UNI-WEAKCIPHER", "CWE-327", "MEDIUM", "security", st.lineno,
                        f"Weak cipher '{val}' should not protect sensitive data",
                        _src(lines, st.lineno),
                        "Use AES-256 in an authenticated mode such as GCM."))
                elif "ecb" in low and len(low) <= 24:
                    out.append(_finding(
                        "UNI-ECB", "CWE-327", "LOW", "security", st.lineno,
                        "ECB mode leaks plaintext structure across blocks",
                        _src(lines, st.lineno),
                        "Use an authenticated mode such as AES-GCM."))

    # Windows CryptoAPI: the algorithm arrives as a numeric identifier macro
    # (CALG_MD5, CALG_RC5), so it is matched by name among the call's uses
    # rather than among its string literals. Once a weak algorithm is selected
    # in a function, the CryptoAPI calls that consume it are reported too,
    # which is where the flaw is annotated.
    for fn in program.functions:
        weak_here = None
        for st in _flatten(fn.body):
            text = _src(lines, st.lineno)
            for const, (algo, cwe) in _WEAK_CRYPT_CONSTANTS.items():
                if re.search(r"\b" + const + r"\b", text):
                    weak_here = (algo, cwe)
                    if (st.lineno, const) in seen:
                        continue
                    seen.add((st.lineno, const))
                    out.append(_finding(
                        "UNI-WEAKCRYPTO", cwe,
                        "MEDIUM", "security", st.lineno,
                        f"Weak algorithm {algo} selected via {const}",
                        text,
                        "Use SHA-256 or stronger for hashing and AES-GCM for "
                        "encryption."))
                    break
            if weak_here is None:
                continue
            for call in st.calls:
                base = call.callee.split(".")[-1]
                if base not in _CRYPTOAPI_USES:
                    continue
                algo, cwe = weak_here
                if (st.lineno, base) in seen:
                    continue
                seen.add((st.lineno, base))
                out.append(_finding(
                    "UNI-WEAKCRYPTO", cwe, "MEDIUM", "security", st.lineno,
                    f"{base}() operates with the weak algorithm {algo}",
                    text,
                    "Use SHA-256 or stronger for hashing and AES-GCM for "
                    "encryption."))
    return out


def _hardcoded_secret(program: UProgram, lines: list) -> list:
    """
    Credential assigned from a string literal (CWE-798).

    A finding requires *both* a credential-shaped identifier and a literal
    that is not an obvious placeholder, which avoids flagging
    ``password = ""`` in configuration scaffolding.
    """
    out = []
    for st in _all_stmts(program):
        if st.literal_value is None or not isinstance(st.literal_value, str):
            continue
        value = st.literal_value
        if _PLACEHOLDER.match(value.strip()) or len(value) < 5:
            continue
        for var in st.defs:
            if not SECRET_NAME.search(var):
                continue
            ent = _entropy(value)
            out.append(_finding(
                "UNI-SECRET", "CWE-798", "HIGH", "security", st.lineno,
                f"Hardcoded credential in '{var}' "
                f"(literal length {len(value)}, entropy {ent:.2f})",
                _src(lines, st.lineno),
                "Load secrets from environment variables or a secrets manager; "
                "never commit them to source control."))
            break
    return out


def _unbounded_copy(program: UProgram, lines: list, language: str,
                    buffers: dict | None = None) -> list:
    """
    Unbounded or oversized copies in C/C++ (CWE-120, CWE-242).

    Two distinct defects are reported, and neither fires on the mere presence
    of the function name:

    ``gets()``
        Always a defect: the API cannot be called safely because it takes no
        destination size at all (CWE-242).

    ``strcpy`` / ``strcat`` / ``sprintf``
        Reported only when the copied source is *not* provably a fixed
        literal -- that is, when it comes from a parameter, an input routine,
        or another buffer. Juliet's remediated twins copy a compile-time
        constant string into an adequately sized buffer, which is safe, and
        flagging those would be a false positive.
    """
    if language not in ("C", "C++"):
        return []
    buffers = buffers or {}
    out = []
    for st in _all_stmts(program):
        for call in st.calls:
            fn = call.callee.split(".")[-1]
            if fn not in UNBOUNDED_COPY:
                continue
            safe = UNBOUNDED_COPY[fn]

            if fn == "gets":
                # gets() is simultaneously CWE-242 (an inherently dangerous
                # function) and the CWE-120 buffer overflow it causes.
                # CWE-120 is reported as the primary identifier because it
                # names the resulting weakness, with CWE-242 retained as a
                # secondary tag for reviewers filtering on banned APIs.
                f = _finding(
                    "UNI-DANGEROUS", "CWE-120", "CRITICAL", "security", st.lineno,
                    "gets() cannot be used safely: it performs an unbounded read "
                    "with no destination size, overflowing the buffer",
                    _src(lines, st.lineno),
                    "Use fgets() with an explicit buffer size.")
                f["secondary_cwe"] = "CWE-242"
                out.append(f)
                continue

            if fn in ("scanf", "fscanf", "sscanf", "swscanf"):
                # `%s` with no field width reads an unbounded token into a
                # fixed buffer; `%63s` is bounded and safe.
                fmt = next((a[1] for a in call.args
                            if a[0] == "const" and isinstance(a[1], str)), None)
                if fmt and re.search(r"%\*?s", fmt):
                    out.append(_finding(
                        "UNI-OVERFLOW", "CWE-120", "HIGH", "security", st.lineno,
                        f"{fn}() uses an unbounded \"%s\" conversion, which can "
                        f"overflow the destination buffer",
                        _src(lines, st.lineno),
                        'Specify a maximum field width, e.g. "%63s" for a '
                        "64-byte buffer."))
                continue

            src_args = call.args[1:] if len(call.args) > 1 else []
            if not src_args:
                continue
            # A copy whose every source operand is a compile-time constant
            # cannot overflow an adequately sized destination.
            if all(a[0] == "const" for a in src_args):
                continue
            # Both buffers have a known constant capacity and the source fits:
            # the copy is provably safe, so reporting it would be a false
            # alarm on exactly the code a fix produces.
            dest = call.args[0]
            dname = dest[1] if dest[0] == "name" else None
            sname = src_args[0][1] if src_args[0][0] == "name" else None
            if (dname in buffers and sname in buffers
                    and buffers[sname] <= buffers[dname]):
                continue
            out.append(_finding(
                "UNI-OVERFLOW", "CWE-120", "HIGH", "security", st.lineno,
                f"{fn}() writes a non-constant source into the destination "
                f"buffer without a length bound",
                _src(lines, st.lineno),
                f"Use {safe}() with an explicit destination size."))
    return out


_ALLOC_FUNCS = {"malloc", "calloc", "realloc", "alloca", "new"}

# Copy routines that take an explicit length as their third argument.
_BOUNDED_COPY_LEN_ARG = {"strncpy": 2, "strncat": 2, "memcpy": 2, "memmove": 2,
                         "snprintf": 1, "wcsncpy": 2, "wmemcpy": 2}


def _numeric_macros(lines: list) -> dict:
    """
    Object-like ``#define NAME <integer>`` directives.

    Buffer sizes in generated C and C++ are routinely written as macros
    (``char buf[CHAR_BUFFER_SIZE]``), and Tree-sitter parses before
    preprocessing, so the declared extent is an identifier rather than a
    literal. Without resolving these the buffer's capacity stays unknown and
    every size-dependent check silently declines to fire.
    """
    out: dict[str, int] = {}
    pat = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+"
                     r"\(?\s*(-?\d+)\s*\)?[ \t]*$")
    for raw in lines:
        m = pat.match(raw)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


def _buffer_capacities(program: UProgram, lines: list) -> dict:
    """
    Map each buffer variable to its allocated element count, where that count
    is a compile-time constant.

    Three declaration shapes are recognized:
    ``char buf[64]`` (array declarator), ``p = malloc(50)``, and
    ``p = new char[50]``. Sizes that are not constant are recorded as ``None``
    so callers can distinguish "unknown" from "unbounded".
    """
    caps: dict[str, dict] = {}
    macros = _numeric_macros(lines)
    for fn in program.functions:
        local: dict[str, int] = {}
        for st in _flatten(fn.body):
            node = st.node
            if node is None or not hasattr(node, "type"):
                continue
            text = _src(lines, st.lineno)

            # char buf[64];  /  char buf[CHAR_BUFFER_SIZE];
            # Only a *declaration* states a capacity. An indexed store such as
            # `data[0] = '\0'` matches the same shape but says nothing about
            # the buffer's size, and reading it as one would record a capacity
            # of zero and turn every later copy into a phantom overflow.
            m = re.match(r"^\s*(?:[A-Za-z_]\w*[\s\*&]+)+([A-Za-z_]\w*)\s*"
                         r"\[\s*([A-Za-z_]\w*|\d+)\s*\]", text)
            if m and st.kind == "decl" and m.group(1) in st.defs:
                extent = m.group(2)
                size = int(extent) if extent.isdigit() else macros.get(extent)
                if size:
                    local[m.group(1)] = size

            # data = new char[100];  /  data = new wchar_t[50];
            # Tree-sitter surfaces `new T[n]` as an anonymous call, so the
            # element count is read from the statement text. Without this the
            # buffer's capacity stays unknown and a perfectly sized copy is
            # mistaken for an overflow.
            mnew = re.search(r"=\s*new\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]", text)
            if mnew:
                for var in st.defs:
                    local[var] = int(mnew.group(2))

            # p = malloc(50) / ALLOCA(10) / new char[50]
            for call in st.calls:
                base = call.callee.split(".")[-1]
                if base.upper() not in {a.upper() for a in _ALLOC_FUNCS}:
                    continue
                size = None
                for a in call.args:
                    if a[0] == "const" and isinstance(a[1], (int, float)):
                        size = int(a[1])
                        break
                if size is None:
                    m2 = re.search(r"(?:malloc|alloca|ALLOCA|calloc)\s*\(\s*(\d+)",
                                   text, re.I)
                    if m2:
                        size = int(m2.group(1))
                if size is None or size <= 0:
                    continue
                # An allocation given in *bytes* but indexed through a wider
                # element type holds fewer elements than the byte count
                # suggests -- the CWE-131 "forgot sizeof" defect. Divide by
                # the element width when the size carries no sizeof().
                if "sizeof" not in text:
                    width = _element_width(text)
                    if width > 1:
                        size = max(1, size // width)
                for var in st.defs:
                    local[var] = size
            m3 = re.search(r"=\s*new\s+\w+\s*\[\s*(\d+)\s*\]", text)
            if m3:
                for var in st.defs:
                    local[var] = int(m3.group(1))
        if local:
            caps[fn.name] = local
    return caps


def _buffer_overflow_size(program: UProgram, lines: list, language: str) -> list:
    """
    Copy whose declared length exceeds the destination's allocated capacity
    (CWE-121 stack / CWE-122 heap buffer overflow).

    This is the defect Juliet's ``CWE805``/``CWE806`` families encode: a
    buffer is allocated with one size and then written with a larger constant
    length, for example ``data = new char[50]`` followed by
    ``strncpy(data, source, 100-1)``. Detecting it requires relating the
    allocation site to the copy site, which is why a bounded-copy call alone
    is not evidence of safety.
    """
    if language not in ("C", "C++"):
        return []
    caps = _buffer_capacities(program, lines)
    out = []
    for fn in program.functions:
        local = caps.get(fn.name, {})
        if not local:
            continue
        for st in _flatten(fn.body):
            text = _src(lines, st.lineno)
            for call in st.calls:
                base = call.callee.split(".")[-1]
                idx = _BOUNDED_COPY_LEN_ARG.get(base)
                if idx is None or len(call.args) <= idx:
                    continue
                dest = call.args[0]
                dname = dest[1] if dest[0] == "name" else None
                if dname is None and dest[0] == "expr":
                    dname = next((n for n in dest[1] if n in local), None)
                if dname not in local:
                    continue
                capacity = local[dname]

                length = _copy_length(call.args[idx], base, text)
                if length is None or length <= capacity:
                    continue
                # `sizeof(dest)` and `sizeof(dest)/sizeof(*dest)` are bounded
                # by the destination itself and can never overflow it.
                if re.search(r"sizeof\s*\(\s*\*?\s*" + re.escape(dname) + r"\s*\)", text):
                    continue

                cwe = "CWE-121" if capacity and not _is_heap(dname, program, lines) else "CWE-122"
                out.append(_finding(
                    "UNI-BUFSIZE", cwe, "HIGH", "security", st.lineno,
                    f"{base}() writes up to {length} bytes into '{dname}', which "
                    f"is allocated with only {capacity}",
                    text,
                    f"Bound the copy by the destination's own capacity "
                    f"(sizeof({dname}) or the allocation size)."))
    return out


_ELEMENT_WIDTH = {"char": 1, "unsigned char": 1, "signed char": 1,
                  "short": 2, "wchar_t": 2, "int": 4, "unsigned": 4,
                  "unsigned int": 4, "float": 4, "long": 4,
                  "double": 8, "int64_t": 8, "long long": 8, "size_t": 8}


def _element_width(text: str) -> int:
    """
    Width in bytes of the element type a buffer is cast to.

    ``(int *)ALLOCA(10)`` reserves ten bytes but is indexed as integers, so
    its true capacity is ``10 / sizeof(int)``. Recovering the cast type is
    what makes that discrepancy measurable.
    """
    m = re.search(r"\(\s*((?:unsigned\s+|signed\s+|long\s+)*\w+)\s*\*+\s*\)", text)
    if not m:
        return 1
    return _ELEMENT_WIDTH.get(m.group(1).strip(), 1)


def _loop_copy_overflow(program: UProgram, lines: list, language: str) -> list:
    """
    Element-wise copy loop whose bound is not the destination's capacity
    (CWE-121 / CWE-122).

    Juliet's ``CWE131``/``CWE805`` "loop" variants overflow without ever
    calling a copy routine::

        int * data = (int *)ALLOCA(10);      /* 10 *bytes*, not 10 ints */
        for (i = 0; i < 10; i++) data[i] = source[i];

    The defect is a mismatch between the loop's trip count and the allocated
    capacity of the buffer being written. We report a write ``dest[i]`` inside
    a counted loop when the destination has a known capacity and the loop
    bound is either a larger constant or derived from the *source* length
    rather than from the destination.
    """
    if language not in ("C", "C++"):
        return []
    caps = _buffer_capacities(program, lines)
    out = []
    for fn in program.functions:
        local = caps.get(fn.name, {})
        for st in _flatten(fn.body):
            if st.kind != "loop":
                continue
            header = _src(lines, st.lineno)
            bound = None
            m = re.search(r"<=?\s*(\d+)", header)
            if m:
                bound = int(m.group(1))
            len_driven = re.search(r"<=?\s*(\w*[Ll]en\w*|\w*[Ss]ize\w*|"
                                   r"strlen\s*\(|wcslen\s*\()", header)

            for inner in _flatten(st.body):
                text = _src(lines, inner.lineno)
                w = re.match(r"^\s*(\w+)\s*\[\s*(\w+)\s*\]\s*=", text)
                if not w:
                    continue
                dest = w.group(1)
                if dest not in local:
                    continue
                capacity = local[dest]
                if bound is not None and bound > capacity:
                    out.append(_finding(
                        "UNI-LOOPCOPY",
                        "CWE-122" if _is_heap(dest, program, lines) else "CWE-121",
                        "HIGH", "security", st.lineno,
                        f"Loop writes up to {bound} elements into '{dest}', which "
                        f"holds only {capacity}",
                        header,
                        f"Bound the loop by the capacity of '{dest}'."))
                elif len_driven:
                    # Only report a length-driven loop when the length is
                    # measured on a *different* buffer than the one written.
                    # `for (i = 0; i < strlen(dest); i++) dest[i] = ...` is
                    # bounded by its own destination and cannot overflow it.
                    measured = re.search(r"(?:strlen|wcslen)\s*\(\s*(\w+)", header)
                    src_var = measured.group(1) if measured else None
                    if src_var == dest:
                        continue
                    if src_var is None:
                        bound_var = len_driven.group(1)
                        if dest in bound_var:
                            continue
                    # The source's own capacity is known and fits: a copy
                    # bounded by its length cannot exceed the destination.
                    if src_var in local and local[src_var] <= capacity:
                        continue
                    out.append(_finding(
                        "UNI-LOOPCOPY",
                        "CWE-122" if _is_heap(dest, program, lines) else "CWE-121",
                        "HIGH", "security", st.lineno,
                        f"Loop copying into '{dest}' (capacity {capacity}) is bounded "
                        f"by the source length rather than the destination's size",
                        header,
                        f"Bound the loop by the capacity of '{dest}', not the source."))
    return out


def _copy_length(arg, base: str, text: str) -> int | None:
    """
    Constant length passed to a bounded copy, or ``None`` when it is not a
    compile-time constant.

    Juliet writes the bound as an expression (``100-1``, ``sizeof(dest)``),
    which Tree-sitter lowers to a composite argument rather than a literal, so
    the constant is recovered from the call text. Only additive arithmetic on
    literals is folded; anything else is reported as unknown rather than
    guessed, because an over-eager reading here would invent overflows.
    """
    if arg[0] == "const" and isinstance(arg[1], (int, float)):
        return int(arg[1])
    m = re.search(re.escape(base) + r"\s*\(([^;]*)\)", text)
    if not m:
        return None
    args = m.group(1).split(",")
    if not args:
        return None
    expr = args[-1].strip()
    if re.fullmatch(r"\d+", expr):
        return int(expr)
    m2 = re.fullmatch(r"(\d+)\s*([-+])\s*(\d+)", expr)
    if m2:
        a, op, b = int(m2.group(1)), m2.group(2), int(m2.group(3))
        return a - b if op == "-" else a + b
    return None


def _is_heap(var: str, program: UProgram, lines: list) -> bool:
    """True when the buffer was obtained from a heap allocator."""
    for fn in program.functions:
        for st in _flatten(fn.body):
            if var not in st.defs:
                continue
            for call in st.calls:
                if call.callee.split(".")[-1] in {"malloc", "calloc", "realloc"}:
                    return True
            if "new " in _src(lines, st.lineno):
                return True
    return False


def _stream_extraction(program: UProgram, lines: list, language: str,
                       buffers: dict) -> list:
    """
    Unbounded extraction from an input stream into a fixed-size array
    (CWE-676).

    ``cin >> charBuffer`` writes as many characters as the input supplies, with
    no field width, so a character array overflows exactly as it would with
    ``gets``. The construct is an operator rather than a call, so it is
    detected from the statement's uses: the stream object on one side and a
    known fixed-capacity buffer on the other. Extraction into ``std::string``
    or an arithmetic type is safe and is not reported.
    """
    if language not in ("C++",):
        return []
    out = []
    for st in _all_stmts(program):
        if not {"cin", "wcin", "std.cin"} & set(st.uses):
            continue
        text = _src(lines, st.lineno)
        if ">>" not in text:
            continue
        for var in st.uses:
            if var in ("cin", "wcin", "std.cin") or var not in buffers:
                continue
            out.append(_finding(
                "UNI-DANGEROUS", "CWE-676", "HIGH", "security", st.lineno,
                f"Unbounded stream extraction into the fixed-size buffer "
                f"'{var}' (capacity {buffers[var]})",
                text,
                "Extract into std::string, or set cin.width() to the buffer "
                "size before extracting."))
            break
    return out


def _literal_backed_buffers(fn, lines: list) -> set:
    """
    Buffers whose every write in this function is a string literal.

    ``strcpy(data, "fixedstringtest")`` makes ``data`` a compile-time constant
    for the rest of the function, so a later ``printf(data)`` cannot be
    attacker-controlled. Juliet's remediated format-string twins are built
    exactly this way: the sink is untouched and only the value written into
    the buffer changes. Recognising the pattern is what separates the fixed
    variant from the flawed one, which a rule keyed on ``printf(variable)``
    alone cannot do.

    A buffer is included only when *no* write to it is non-constant, so a
    single tainted assignment anywhere disqualifies it.
    """
    literal_backed: set = set()
    disqualified: set = set()
    aliases: dict = {}
    for st in _flatten(fn.body):
        # `data = dataBuffer` merely renames the storage; it neither
        # introduces a value nor disqualifies the buffer, so the alias is
        # recorded and resolved at the end.
        if st.kind in ("assign", "decl") and not st.calls \
                and len(st.defs) == 1 and len(st.uses) == 1:
            aliases[next(iter(st.defs))] = next(iter(st.uses))
            continue

        for call in st.calls:
            base = call.callee.split(".")[-1]
            if base not in _COPY_LIKE or not call.args:
                continue
            dest = call.args[0]
            dnames = ({dest[1]} if dest[0] == "name"
                      else (set(dest[1]) if dest[0] == "expr" else set()))
            srcs = call.args[1:]
            if srcs and all(a[0] == "const" for a in srcs):
                literal_backed |= dnames
            else:
                disqualified |= dnames

        # An assignment whose right-hand side is neither a literal nor a bare
        # alias introduces an unknown value.
        if st.kind in ("assign", "decl") and st.literal_value is None and st.uses:
            disqualified |= set(st.defs)

    # A buffer stays constant if the storage it aliases is constant.
    for name, target in aliases.items():
        if target in literal_backed and target not in disqualified:
            literal_backed.add(name)
        elif name in literal_backed and target not in disqualified:
            literal_backed.add(target)
    return literal_backed - disqualified


_COPY_LIKE = {"strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf",
              "wcscpy", "wcsncpy", "wcscat", "wcsncat", "memcpy", "strcpy_s"}


def _format_string(program: UProgram, lines: list, language: str) -> list:
    """printf-family call whose format argument is a variable (CWE-134)."""
    if language not in ("C", "C++"):
        return []
    out = []
    # Index of the format argument for each printf-family routine. Juliet
    # reaches these through uppercase macros (`#define SNPRINTF _snwprintf`),
    # which the IR resolves before the rule sees the callee.
    fmt_index = {"printf": 0, "wprintf": 0, "vprintf": 0, "vwprintf": 0,
                 "fprintf": 1, "fwprintf": 1, "vfprintf": 1,
                 "sprintf": 1, "swprintf": 1, "vsprintf": 1,
                 "snprintf": 2, "_snprintf": 2, "_snwprintf": 2,
                 "swprintf_s": 2, "syslog": 1}
    for func in program.functions:
        # Buffers written only from string literals are compile-time constants
        # and cannot carry an attacker-supplied format specifier.
        constant_buffers = _literal_backed_buffers(func, lines)
        for st in _flatten(func.body):
            for call in st.calls:
                fn = call.callee.split(".")[-1]
                if fn not in fmt_index:
                    continue
                idx = fmt_index[fn]
                if len(call.args) <= idx:
                    continue
                arg = call.args[idx]
                if arg[0] == "name" and arg[1] in constant_buffers:
                    continue
                # a non-constant format string that is also the *last*
                # argument means the caller passes data directly as the format
                if arg[0] == "name" and len(call.args) == idx + 1:
                    out.append(_finding(
                        "UNI-FMTSTR", "CWE-134", "HIGH", "security", st.lineno,
                        f"{fn}() uses a non-constant format string, allowing "
                        f"format-string attacks",
                        _src(lines, st.lineno),
                        f'Use {fn}("%s", value) so user data is never parsed '
                        f"as a format specifier."))
    return out


def _weak_random(program: UProgram, lines: list) -> list:
    """Non-cryptographic RNG used where security is implied (CWE-338)."""
    out = []
    for st in _all_stmts(program):
        for call in st.calls:
            name = call.callee
            short = name.split(".")[-1]
            if short not in WEAK_RANDOM and name not in WEAK_RANDOM:
                continue
            context = " ".join(sorted(st.defs)) + " " + _src(lines, st.lineno)
            if re.search(r"(token|key|secret|password|salt|nonce|session|"
                         r"otp|csrf|uuid|id)", context, re.I):
                out.append(_finding(
                    "UNI-WEAKRAND", "CWE-338", "MEDIUM", "security", st.lineno,
                    f"{short}() is not cryptographically secure but is used to "
                    f"generate a security-sensitive value",
                    _src(lines, st.lineno),
                    "Use a CSPRNG: /dev/urandom, SecureRandom, or crypto.randomBytes()."))
    return out


def _division_by_zero(program: UProgram, lines: list, constants: dict) -> list:
    """
    Division whose divisor is a literal zero, or a variable whose only
    reaching definition is the constant zero (CWE-369).
    """
    out = []
    per_fn = constants.get("per_function_constants", {})
    for fn in program.functions:
        env = per_fn.get(fn.name, {})
        for st in _flatten(fn.body):
            node = st.node
            if node is None or not hasattr(node, "type"):
                continue
            for div in _find_divisions(node):
                right = div.child_by_field_name("right")
                if right is None:
                    continue
                txt = _node_text(right, lines, st.lineno)
                if txt is None:
                    continue
                txt = txt.strip()
                if re.fullmatch(r"0+(\.0*)?", txt):
                    out.append(_finding(
                        "UNI-DIVZERO", "CWE-369", "HIGH", "logic", st.lineno,
                        "Division by the literal constant zero",
                        _src(lines, st.lineno),
                        "Guard the denominator before dividing."))
                elif txt in env and env[txt] == 0:
                    out.append(_finding(
                        "UNI-DIVZERO", "CWE-369", "HIGH", "logic", st.lineno,
                        f"Division by '{txt}', whose only reaching definition "
                        f"is the constant 0",
                        _src(lines, st.lineno),
                        "Guard the denominator before dividing."))
    return out


def _infinite_loop(program: UProgram, lines: list) -> list:
    """
    Loop with a constant-true condition and no exit statement (CWE-835).

    A ``while (true)`` that contains ``break``, ``return``, or ``throw`` is
    an idiomatic event loop and is deliberately not reported.
    """
    out = []
    for fn in program.functions:
        for st in _flatten(fn.body):
            if st.kind != "loop":
                continue
            cond = _loop_condition_text(st, lines)
            if cond is None or cond not in {"true", "1", ""}:
                continue
            if any(inner.kind in {"break", "return", "throw"}
                   for inner in _flatten(st.body)):
                continue
            out.append(_finding(
                "UNI-INFLOOP", "CWE-835", "HIGH", "logic", st.lineno,
                "Loop condition is constantly true and the body contains no "
                "break, return, or throw",
                _src(lines, st.lineno),
                "Add a terminating condition or an explicit break."))
    return out


def _empty_catch(program: UProgram, lines: list) -> list:
    """Exception handler that silently discards the error (CWE-390)."""
    out = []
    for fn in program.functions:
        for st in _flatten(fn.body):
            if st.kind != "try":
                continue
            for exc_name, hbody in st.handlers:
                real = [h for h in hbody
                        if not (h.kind == "simple" and h.text.startswith("catch "))]
                if not real:
                    out.append(_finding(
                        "UNI-EMPTYCATCH", "CWE-390", "LOW", "quality", st.lineno,
                        f"Exception handler for '{exc_name}' is empty; the error "
                        f"is silently discarded",
                        _src(lines, st.lineno),
                        "Log the exception or handle it explicitly."))
    return out


def _deserialization(program: UProgram, lines: list, language: str) -> list:
    """Unsafe deserialization entry points (CWE-502)."""
    out = []
    unsafe = {"readObject": "Java native deserialization",
              "readUnshared": "Java native deserialization",
              "readValue": "polymorphic JSON deserialization"}
    if language != "Java":
        return out
    for st in _all_stmts(program):
        for call in st.calls:
            short = call.callee.split(".")[-1]
            if short in unsafe:
                out.append(_finding(
                    "UNI-DESERIAL", "CWE-502", "HIGH", "security", st.lineno,
                    f"{unsafe[short]} via {short}() can instantiate arbitrary "
                    f"classes from untrusted bytes",
                    _src(lines, st.lineno),
                    "Avoid native deserialization of untrusted data; use a "
                    "schema-validated format and an allow-list of types."))
    return out


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _all_stmts(program: UProgram):
    for fn in program.functions:
        yield from _flatten(fn.body)
    yield from _flatten(program.toplevel)


def _src(lines: list, lineno: int) -> str:
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:100]
    return ""


def _find_divisions(node):
    """
    Yield binary expressions whose operator is division or modulo.

    The operator token must be checked explicitly: every comparison and
    arithmetic expression is also a ``binary_expression``, so accepting any
    operator would flag ``if (data != 0)`` as a division by zero.
    """
    stack = [node]
    while stack:
        n = stack.pop()
        if getattr(n, "type", "") in ("binary_expression", "assignment_expression",
                                      "augmented_assignment_expression"):
            op = n.child_by_field_name("operator")
            tok = None
            if op is not None:
                tok = _tok_text(op)
            else:
                for ch in n.children:
                    if not ch.is_named and ch.child_count == 0:
                        tok = _tok_text(ch)
                        break
            if tok in ("/", "%", "/=", "%="):
                yield n
        stack.extend(getattr(n, "children", []))


def _tok_text(node):
    """Operator token text, read from the node's own byte span."""
    try:
        return node.text.decode("utf8", "ignore")
    except Exception:
        return None


def _node_text(node, lines, fallback_line):
    """Best-effort source text for a CST node using the line cache."""
    try:
        start_row = node.start_point[0]
        end_row = node.end_point[0]
        if start_row != end_row or start_row >= len(lines):
            return None
        return lines[start_row][node.start_point[1]:node.end_point[1]]
    except Exception:
        return None


def _loop_condition_text(st: UStmt, lines: list) -> str | None:
    node = st.node
    if node is None or not hasattr(node, "child_by_field_name"):
        return None
    cond = node.child_by_field_name("condition")
    if cond is None:
        # `for (;;)` has no condition field at all
        text = _src(lines, st.lineno)
        if re.search(r"for\s*\(\s*;\s*;\s*\)", text):
            return "true"
        return None
    txt = _node_text(cond, lines, st.lineno)
    return txt.strip().strip("()") if txt else None


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def run_uir_rules(program: UProgram, code: str, language: str,
                  constants: dict | None = None) -> list:
    """Run every universal rule and return normalized findings."""
    lines = code.split("\n")
    constants = constants or {}
    findings: list = []
    caps = _buffer_capacities(program, lines) if language in ("C", "C++") else {}
    flat_caps = {v: n for fn in caps.values() for v, n in fn.items()}

    findings += _weak_crypto(program, lines)
    findings += _hardcoded_secret(program, lines)
    findings += _unbounded_copy(program, lines, language, flat_caps)
    findings += _buffer_overflow_size(program, lines, language)
    findings += _loop_copy_overflow(program, lines, language)
    findings += _stream_extraction(program, lines, language, flat_caps)
    findings += _format_string(program, lines, language)
    findings += _weak_random(program, lines)
    findings += _division_by_zero(program, lines, constants)
    findings += _infinite_loop(program, lines)
    findings += _empty_catch(program, lines)
    findings += _deserialization(program, lines, language)
    return findings
