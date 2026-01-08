"""
Universal Intermediate Representation (UIR)
===========================================
A language-neutral program model lowered from Tree-sitter concrete syntax
trees for C, C++, Java, and JavaScript (Python is lowered from the native
``ast`` module by the dedicated deep pipeline).

Motivation
----------
The deep analyses in this framework -- CFG construction, iterative data-flow
analysis, SSA construction, the PDG, and interprocedural taint analysis --
are all *graph algorithms over statements*. They do not care about surface
syntax; they only need, for every statement:

    * a source line,
    * the set of variables it defines,
    * the set of variables it uses,
    * the calls it performs (callee name + argument descriptors),
    * its structural role (branch, loop, return, jump, ...).

The UIR provides exactly that. By lowering four different concrete syntax
trees into one statement model, a *single* implementation of each analysis
serves all five languages, which is what makes full feature parity
(Table: capability matrix) achievable rather than four parallel
re-implementations.

Design
------
``UStmt``   -- one statement: line, kind, defs, uses, calls, children.
``UFunc``   -- one function/method: name, parameters, body (list of UStmt).
``UProgram``-- functions + top-level statements + class list.

Structured control flow is preserved as *nested* statements
(``kind='if'`` with ``then_body`` / ``else_body``; ``kind='loop'`` with
``body``), so the CFG builder can emit the same true/false/back/exception
edges it emits for Python.

Only genuine parse-tree facts are used; no regular expressions participate
in lowering.
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field
from enum import Enum

warnings.filterwarnings("ignore", category=FutureWarning, module="tree_sitter")

try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from tree_sitter import Parser
        from tree_sitter_languages import get_language
    TS_AVAILABLE = True
except Exception:                                        # pragma: no cover
    TS_AVAILABLE = False

LANG_MAP = {"C": "c", "C++": "cpp", "Java": "java", "JavaScript": "javascript"}

# ---------------------------------------------------------------------------
# Node-type vocabularies (tree-sitter grammar node names)
# ---------------------------------------------------------------------------

FUNC_NODES = {
    "function_definition",        # C / C++
    "method_declaration",         # Java
    "constructor_declaration",    # Java
    "function_declaration",       # JS
    "method_definition",          # JS class methods
    "generator_function_declaration",
}

CLASS_NODES = {"class_specifier", "struct_specifier", "class_declaration",
               "interface_declaration", "enum_declaration"}

# statements that terminate / divert control flow
RETURN_NODES = {"return_statement"}
BREAK_NODES = {"break_statement"}
CONTINUE_NODES = {"continue_statement"}
THROW_NODES = {"throw_statement"}

IF_NODES = {"if_statement"}
LOOP_NODES = {"for_statement", "while_statement", "do_statement",
              "enhanced_for_statement", "for_in_statement", "for_of_statement",
              "for_range_loop"}
SWITCH_NODES = {"switch_statement", "switch_expression"}
TRY_NODES = {"try_statement"}
BLOCK_NODES = {"compound_statement", "block", "statement_block",
               "constructor_body"}

CALL_NODES = {"call_expression", "method_invocation", "new_expression",
              "object_creation_expression"}

ASSIGN_NODES = {"assignment_expression", "augmented_assignment_expression"}
DECL_NODES = {"declaration", "local_variable_declaration", "variable_declaration",
              "lexical_declaration", "field_declaration"}

IDENT_NODES = {"identifier", "field_identifier", "type_identifier",
               "statement_identifier", "property_identifier",
               "shorthand_property_identifier"}

# operators counted for Halstead (grammar-level)
OPERATOR_NODES = {
    "binary_expression", "unary_expression", "assignment_expression",
    "augmented_assignment_expression", "update_expression",
    "conditional_expression", "ternary_expression", "cast_expression",
    "pointer_expression", "subscript_expression", "array_access",
    "field_expression", "field_access", "member_expression",
    "call_expression", "method_invocation", "new_expression",
    "object_creation_expression", "sizeof_expression",
    "instanceof_expression", "parenthesized_expression",
}
OPERAND_NODES = {
    "identifier", "field_identifier", "property_identifier", "type_identifier",
    "number_literal", "string_literal", "char_literal", "true", "false",
    "null", "null_literal", "decimal_integer_literal", "hex_integer_literal",
    "decimal_floating_point_literal", "string_fragment", "number",
    "this", "super",
}

_LITERAL_NODES = {"number_literal", "string_literal", "char_literal",
                  "decimal_integer_literal", "hex_integer_literal",
                  "decimal_floating_point_literal", "number", "string",
                  "true", "false", "null", "null_literal", "string_fragment"}

# Nodes that denote a *type* rather than a value; they must never contribute
# a variable definition or use (otherwise `String q = ...` would "define" the
# variable `String`).
_TYPE_NODES = {"type_identifier", "primitive_type", "sized_type_specifier",
               "modifiers", "storage_class_specifier", "type_qualifier",
               "generic_type", "scoped_type_identifier", "array_type",
               "type_arguments", "type_parameters", "integral_type",
               "floating_point_type", "boolean_type", "void_type",
               "struct_specifier", "union_specifier", "enum_specifier",
               "qualified_identifier", "template_type", "placeholder_type_specifier",
               "auto", "dependent_type", "decltype"}


# ---------------------------------------------------------------------------
# UIR data model
# ---------------------------------------------------------------------------

class StatementKind(str, Enum):
    """Closed vocabulary for the language-neutral statement model.

    The names deliberately express *semantic* roles rather than grammar
    production names.  Lowerers may retain richer internal distinctions (for
    example ``switch`` or ``throw``), but every such node is normalized to one
    of these roles before it reaches the graph passes.
    """

    ASSIGN = "assign"
    CALL = "call"
    BRANCH = "branch"
    LOOP = "loop"
    RETURN = "return"
    JUMP = "jump"
    HANDLER = "handler"


_CANONICAL_KIND = {
    "decl": StatementKind.ASSIGN.value,
    "assign": StatementKind.ASSIGN.value,
    "call": StatementKind.CALL.value,
    "simple": StatementKind.CALL.value,
    "if": StatementKind.BRANCH.value,
    "switch": StatementKind.BRANCH.value,
    "loop": StatementKind.LOOP.value,
    "return": StatementKind.RETURN.value,
    "break": StatementKind.JUMP.value,
    "continue": StatementKind.JUMP.value,
    "throw": StatementKind.JUMP.value,
    "label": StatementKind.JUMP.value,
    "try": StatementKind.HANDLER.value,
    "handler": StatementKind.HANDLER.value,
}

@dataclass
class UCall:
    """One call site lowered to a language-neutral descriptor."""
    callee: str                       # dotted/qualified callee name
    args: list = field(default_factory=list)   # [("name",v) | ("const",v) | ("expr",frozenset)]
    lineno: int = 0
    is_ctor: bool = False

    def as_dict(self):
        return {"callee": self.callee, "args": self.args, "lineno": self.lineno}


@dataclass
class UStmt:
    """
    A language-neutral statement.

    ``canonical_kind`` is one of :class:`StatementKind`: ``assign``,
    ``call``, ``branch``, ``loop``, ``return``, ``jump``, or ``handler``.
    ``kind`` retains the parser-level construct, while ``syntax_kind`` records
    that original value explicitly for serialization, so CFG
    construction can still distinguish, for example, ``break`` from
    ``continue`` and ``if`` from ``switch``.
    """
    lineno: int
    kind: str
    text: str = ""
    syntax_kind: str = field(default="", kw_only=True)
    defs: set = field(default_factory=set)
    uses: set = field(default_factory=set)
    calls: list = field(default_factory=list)      # list[UCall]
    # structured children
    test: "UStmt | None" = None
    then_body: list = field(default_factory=list)
    else_body: list = field(default_factory=list)
    body: list = field(default_factory=list)
    handlers: list = field(default_factory=list)   # list[(exc_name, body)]
    finalbody: list = field(default_factory=list)
    cases: list = field(default_factory=list)      # list[(label, body)] for switch
    literal_value: object = None                   # for constant propagation
    is_return: bool = False

    # compatibility with the Python-side Stmt used by CFG/DFG/taint
    node: object = field(repr=False, default=None)

    def __post_init__(self):
        self.syntax_kind = self.syntax_kind or self.kind

    @property
    def canonical_kind(self) -> str:
        """Semantic statement role consumed by language-independent clients."""
        return _CANONICAL_KIND.get(self.kind, self.kind)

    @property
    def call_dicts(self):
        return [c.as_dict() for c in self.calls]


@dataclass
class UFunc:
    name: str
    params: list = field(default_factory=list)     # parameter names, in order
    body: list = field(default_factory=list)       # list[UStmt]
    lineno: int = 0
    end_lineno: int = 0
    is_method: bool = False
    class_name: str | None = None
    returns_value: bool = False


@dataclass
class UProgram:
    language: str
    functions: list = field(default_factory=list)  # list[UFunc]
    toplevel: list = field(default_factory=list)   # list[UStmt]
    classes: list = field(default_factory=list)    # [{"name","lineno","methods"}]
    imports: list = field(default_factory=list)
    parse_ok: bool = False
    parse_error: str | None = None
    # Halstead raw streams (grammar-level, exact — not heuristic)
    operators: list = field(default_factory=list)
    operands: list = field(default_factory=list)
    literals: list = field(default_factory=list)
    loops: int = 0
    conditionals: int = 0
    total_calls: int = 0
    max_depth: int = 0
    error_nodes: int = 0

    def function_args(self) -> dict:
        return {f.name: list(f.params) for f in self.functions}


# ---------------------------------------------------------------------------
# Lowering
# ---------------------------------------------------------------------------

_PARSER_CACHE: dict = {}


def _parser_for(language: str):
    """Return a cached tree-sitter parser for a UIR language name."""
    if not TS_AVAILABLE or language not in LANG_MAP:
        return None
    key = LANG_MAP[language]
    if key in _PARSER_CACHE:
        return _PARSER_CACHE[key]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        parser = Parser()
        lang = get_language(key)
        try:
            parser.language = lang
        except (AttributeError, TypeError):              # older API
            parser.set_language(lang)
    _PARSER_CACHE[key] = parser
    return parser


class UIRLowering:
    """Lowers one tree-sitter CST into a :class:`UProgram`."""

    def __init__(self, code: str, language: str):
        self.code = code
        self.src = code.encode("utf8")
        self.language = language
        self.lines = code.split("\n")
        self.prog = UProgram(language=language)

    # -- helpers ---------------------------------------------------------
    def _text(self, node) -> str:
        return self.src[node.start_byte:node.end_byte].decode("utf8", "ignore")

    def _line(self, node) -> int:
        return node.start_point[0] + 1

    def _src_line(self, lineno: int) -> str:
        if 0 < lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()[:90]
        return ""

    # -- entry -----------------------------------------------------------
    def lower(self) -> UProgram:
        parser = _parser_for(self.language)
        if parser is None:
            self.prog.parse_error = "tree-sitter unavailable for " + self.language
            return self.prog
        if self.language in ("C", "C++"):
            self._collect_object_macros()
        try:
            tree = parser.parse(self.src)
        except Exception as exc:                          # pragma: no cover
            self.prog.parse_error = f"parse failure: {exc}"
            return self.prog

        root = tree.root_node
        self.prog.parse_ok = True
        self._collect_token_streams(root)
        self._walk_toplevel(root, self.prog.toplevel)
        return self.prog

    # -- C preprocessor object-like macros -------------------------------
    def _collect_object_macros(self):
        """
        Record object-like ``#define NAME REPLACEMENT`` pairs.

        Tree-sitter parses C and C++ *before* preprocessing, so a macro that
        aliases a variable -- ``#define COMMAND_ARG3 data`` -- makes the
        variable invisible at its use sites: the call argument reads as an
        opaque constant rather than as a use of ``data``. Resolving object-like
        macros to their replacement identifier restores the data-flow edge, so
        taint continues to follow the value into the sink.

        Only single-identifier replacements are recorded. Function-like macros
        and arbitrary token soup are deliberately left alone: substituting
        them without a full preprocessor risks inventing dependencies that the
        compiled program does not have.
        """
        macros: dict[str, str] = {}
        pattern = re.compile(
            r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+([A-Za-z_]\w*)[ \t]*$")
        for raw in self.lines:
            m = pattern.match(raw)
            if not m:
                continue
            name, value = m.group(1), m.group(2)
            if name == value:
                continue
            macros[name] = value
        # Resolve chains (A -> B -> data) without looping on cycles.
        for name in list(macros):
            seen = {name}
            value = macros[name]
            while value in macros and value not in seen:
                seen.add(value)
                value = macros[value]
            macros[name] = value
        self.macros = macros

    def _resolve(self, name: str) -> str:
        """Map an identifier through object-like macro definitions."""
        return getattr(self, "macros", {}).get(name, name)

    # -- Halstead / structural token streams -----------------------------
    def _collect_token_streams(self, root):
        """
        Walk the whole CST once and collect the exact operator and operand
        multisets, plus structural counters. Operators are grammar
        production names (plus the concrete operator token where present),
        operands are identifiers and literals -- this mirrors what the
        Python AST path does with typed ``ast`` nodes.
        """
        ops, opnds, lits = [], [], []
        loops = conds = calls = errors = 0
        max_depth = 0
        stack = [(root, 0)]
        while stack:
            node, depth = stack.pop()
            max_depth = max(max_depth, depth)
            t = node.type
            if t == "ERROR" or node.is_missing:
                errors += 1
            if t in OPERATOR_NODES:
                # use the concrete operator token when the grammar exposes it
                op_tok = None
                for ch in node.children:
                    if not ch.is_named and ch.child_count == 0:
                        tok = self._text(ch)
                        if tok and not tok.isalnum() and tok not in "();,{}[]":
                            op_tok = tok
                            break
                ops.append(op_tok or t)
            elif t in OPERAND_NODES:
                txt = self._text(node)
                opnds.append(txt)
                if t in _LITERAL_NODES:
                    lits.append(txt)
            if t in LOOP_NODES:
                loops += 1
                ops.append("loop")
            elif t in IF_NODES or t in SWITCH_NODES:
                conds += 1
                ops.append("branch")
            elif t == "catch_clause":
                conds += 1
                ops.append("catch")
            elif t in CALL_NODES:
                calls += 1
            elif t in RETURN_NODES:
                ops.append("return")
            for ch in node.children:
                stack.append((ch, depth + 1))
        self.prog.operators = ops
        self.prog.operands = opnds
        self.prog.literals = lits
        self.prog.loops = loops
        self.prog.conditionals = conds
        self.prog.total_calls = calls
        self.prog.max_depth = max_depth
        self.prog.error_nodes = errors

    # -- top level -------------------------------------------------------
    def _walk_toplevel(self, node, out: list, class_name: str | None = None):
        """Discover functions/classes; everything else becomes a UStmt."""
        for child in node.children:
            t = child.type
            if t in FUNC_NODES:
                self.prog.functions.append(self._lower_function(child, class_name))
            elif t in CLASS_NODES:
                cname = self._class_name(child)
                methods = []
                body = child.child_by_field_name("body") or child
                for gc in body.children:
                    if gc.type in FUNC_NODES:
                        methods.append(self._func_name(gc))
                self.prog.classes.append(
                    {"name": cname, "lineno": self._line(child), "methods": methods})
                self._walk_toplevel(body, out, cname)
            elif t in {"preproc_include", "import_declaration", "import_statement",
                       "package_declaration", "using_declaration"}:
                self.prog.imports.append(self._text(child).strip()[:100])
            elif t in BLOCK_NODES or t in {"declaration_list", "program",
                                           "translation_unit", "namespace_definition",
                                           "linkage_specification"}:
                self._walk_toplevel(child, out, class_name)
            elif child.is_named:
                # a genuine top-level statement (globals, expression stmts, ...)
                stmts = self._lower_stmt(child)
                out.extend(stmts)
                # JS arrow functions / function expressions assigned to a name
                self._harvest_nested_functions(child, class_name)

    def _harvest_nested_functions(self, node, class_name):
        """JS: `const f = (a) => {...}` and `var f = function(a){...}`."""
        if self.language != "JavaScript":
            return
        for ch in node.children:
            if ch.type in {"arrow_function", "function_expression", "function"}:
                name = self._js_binding_name(ch) or f"anon@L{self._line(ch)}"
                self.prog.functions.append(self._lower_function(ch, class_name, name))
            else:
                self._harvest_nested_functions(ch, class_name)

    def _js_binding_name(self, fnode):
        parent = fnode.parent
        while parent is not None and parent.type not in {
                "variable_declarator", "assignment_expression", "pair"}:
            parent = parent.parent
        if parent is None:
            return None
        target = parent.child_by_field_name("name") or parent.child_by_field_name("left") \
            or parent.child_by_field_name("key")
        return self._text(target) if target is not None else None

    def _class_name(self, node) -> str:
        n = node.child_by_field_name("name")
        if n is not None:
            return self._text(n)
        for ch in node.children:
            if ch.type in IDENT_NODES:
                return self._text(ch)
        return f"<class@L{self._line(node)}>"

    def _func_name(self, node) -> str:
        n = node.child_by_field_name("name")
        if n is not None:
            return self._text(n)
        decl = node.child_by_field_name("declarator")
        while decl is not None:
            if decl.type == "function_declarator":
                inner = decl.child_by_field_name("declarator")
                if inner is not None:
                    return self._text(inner).strip("*& ")
            nxt = decl.child_by_field_name("declarator")
            if nxt is None or nxt is decl:
                break
            decl = nxt
        for ch in node.children:
            if ch.type in IDENT_NODES:
                return self._text(ch)
        return f"<fn@L{self._line(node)}>"

    # -- functions -------------------------------------------------------
    def _lower_function(self, node, class_name=None, forced_name=None) -> UFunc:
        name = forced_name or self._func_name(node)
        params = self._params(node)
        body_node = node.child_by_field_name("body")
        body: list[UStmt] = []
        if body_node is not None:
            for ch in body_node.children:
                if ch.is_named:
                    body.extend(self._lower_stmt(ch))
        fn = UFunc(name=name, params=params, body=body,
                   lineno=self._line(node),
                   end_lineno=node.end_point[0] + 1,
                   is_method=class_name is not None,
                   class_name=class_name)
        fn.returns_value = any(self._returns_value(s) for s in _flatten(body))
        return fn

    @staticmethod
    def _returns_value(s: UStmt) -> bool:
        return s.kind == "return" and bool(s.uses or s.calls or s.literal_value is not None)

    def _params(self, node) -> list:
        """Extract parameter *names* in declaration order."""
        out = []
        plist = node.child_by_field_name("parameters")
        if plist is None:
            # C: parameters hang off the function_declarator
            decl = node.child_by_field_name("declarator")
            seen = set()
            while decl is not None and id(decl) not in seen:
                seen.add(id(decl))
                if decl.type == "function_declarator":
                    plist = decl.child_by_field_name("parameters")
                    break
                decl = decl.child_by_field_name("declarator")
        if plist is None:
            return out
        for ch in plist.children:
            if not ch.is_named:
                continue
            nm = self._param_name(ch)
            if nm:
                out.append(nm)
        return out

    def _param_name(self, node) -> str | None:
        """Innermost identifier of a parameter declaration."""
        if node.type in IDENT_NODES:
            return self._text(node)
        declarator = node.child_by_field_name("declarator")
        if declarator is not None:
            return self._param_name(declarator)
        nm = node.child_by_field_name("name")
        if nm is not None:
            return self._param_name(nm)
        pat = node.child_by_field_name("pattern")
        if pat is not None:
            return self._param_name(pat)
        # fall back: last identifier token inside (handles `char *buf`)
        last = None
        for ch in node.children:
            if ch.type in IDENT_NODES:
                last = ch
            elif ch.is_named:
                deep = self._param_name(ch)
                if deep:
                    last = None
                    return deep
        return self._text(last) if last is not None else None

    # -- statements ------------------------------------------------------
    def _lower_stmt(self, node) -> list:
        """Lower one CST node into zero or more UStmt (list keeps blocks flat)."""
        t = node.type
        line = self._line(node)

        if t in BLOCK_NODES:
            out = []
            for ch in node.children:
                if ch.is_named:
                    out.extend(self._lower_stmt(ch))
            return out

        if t in FUNC_NODES:
            # nested function: register it, emit a definition marker
            self.prog.functions.append(self._lower_function(node))
            return [UStmt(line, "simple", f"def {self._func_name(node)}(...)",
                          defs={self._func_name(node)})]

        if t in CLASS_NODES:
            cname = self._class_name(node)
            body = node.child_by_field_name("body") or node
            methods = []
            for gc in body.children:
                if gc.type in FUNC_NODES:
                    methods.append(self._func_name(gc))
                    self.prog.functions.append(self._lower_function(gc, cname))
            self.prog.classes.append({"name": cname, "lineno": line, "methods": methods})
            return []

        if t in IF_NODES:
            return [self._lower_if(node)]
        if t in LOOP_NODES:
            return [self._lower_loop(node)]
        if t in SWITCH_NODES:
            return [self._lower_switch(node)]
        if t in TRY_NODES:
            return [self._lower_try(node)]

        if t in RETURN_NODES:
            defs, uses, calls, lit = self._expr_facts(node)
            return [UStmt(line, "return", self._src_line(line), defs, uses, calls,
                          literal_value=lit, is_return=True, node=node)]
        if t in BREAK_NODES:
            return [UStmt(line, "break", self._src_line(line), node=node)]
        if t in CONTINUE_NODES:
            return [UStmt(line, "continue", self._src_line(line), node=node)]
        if t in THROW_NODES:
            defs, uses, calls, _ = self._expr_facts(node)
            return [UStmt(line, "throw", self._src_line(line), defs, uses, calls, node=node)]

        if t == "labeled_statement":
            out = []
            for ch in node.children:
                if ch.is_named and ch.type not in IDENT_NODES:
                    out.extend(self._lower_stmt(ch))
            return out

        # plain statement: declaration, expression statement, etc.
        defs, uses, calls, lit = self._expr_facts(node)
        kind = "decl" if t in DECL_NODES else ("assign" if defs else "simple")
        return [UStmt(line, kind, self._src_line(line), defs, uses, calls,
                      literal_value=lit, node=node)]

    def _lower_if(self, node) -> UStmt:
        line = self._line(node)
        cond = node.child_by_field_name("condition")
        defs, uses, calls, _ = self._expr_facts(cond) if cond is not None else (set(), set(), [], None)
        st = UStmt(line, "if", self._src_line(line), defs, uses, calls, node=node)
        cons = node.child_by_field_name("consequence")
        alt = node.child_by_field_name("alternative")
        if cons is not None:
            st.then_body = self._lower_stmt(cons)
        if alt is not None:
            # `else if` arrives as an else_clause wrapping another if_statement
            target = alt
            if alt.type in {"else_clause"}:
                named = [c for c in alt.children if c.is_named]
                target = named[0] if named else None
            if target is not None:
                st.else_body = self._lower_stmt(target)
        return st

    def _lower_loop(self, node) -> UStmt:
        line = self._line(node)
        defs, uses, calls = set(), set(), []
        for fname in ("condition", "initializer", "update", "left", "right",
                      "value", "object"):
            sub = node.child_by_field_name(fname)
            if sub is not None:
                d, u, c, _ = self._expr_facts(sub)
                defs |= d
                uses |= u
                calls.extend(c)
        # `for (int i = 0; ...)` / `for (String s : items)` header parts that
        # tree-sitter does not expose via named fields
        body_node = node.child_by_field_name("body")
        for ch in node.children:
            if ch.is_named and ch is not body_node and ch.type not in BLOCK_NODES:
                d, u, c, _ = self._expr_facts(ch)
                defs |= d
                uses |= u
                calls.extend(c)
        st = UStmt(line, "loop", self._src_line(line), defs, uses, calls, node=node)
        if body_node is not None:
            st.body = self._lower_stmt(body_node)
        elif node.type == "do_statement":
            for ch in node.children:
                if ch.type in BLOCK_NODES:
                    st.body = self._lower_stmt(ch)
        return st

    def _lower_switch(self, node) -> UStmt:
        line = self._line(node)
        cond = node.child_by_field_name("condition") or node.child_by_field_name("value")
        defs, uses, calls, _ = self._expr_facts(cond) if cond is not None else (set(), set(), [], None)
        st = UStmt(line, "switch", self._src_line(line), defs, uses, calls, node=node)
        body = node.child_by_field_name("body")
        if body is not None:
            current_label, current_body = "default", []
            for ch in body.children:
                if ch.type in {"case_statement", "switch_block_statement_group",
                               "switch_case", "switch_default"}:
                    label_node = ch.child_by_field_name("value")
                    label = self._text(label_node) if label_node is not None else "default"
                    cbody = []
                    for gc in ch.children:
                        if gc.is_named and gc is not label_node:
                            cbody.extend(self._lower_stmt(gc))
                    st.cases.append((label, cbody))
                elif ch.is_named:
                    current_body.extend(self._lower_stmt(ch))
            if current_body:
                st.cases.append((current_label, current_body))
        return st

    def _lower_try(self, node) -> UStmt:
        line = self._line(node)
        st = UStmt(line, "try", self._src_line(line), node=node)
        body = node.child_by_field_name("body")
        if body is not None:
            st.body = self._lower_stmt(body)
        for ch in node.children:
            if ch.type in {"catch_clause", "catch_formal_parameter"}:
                exc_name = "Exception"
                bound = None
                params = ch.child_by_field_name("parameters") or \
                    ch.child_by_field_name("parameter")
                if params is not None:
                    bound = self._param_name(params)
                    exc_name = self._text(params).strip("() ")[:40]
                hbody_node = ch.child_by_field_name("body")
                hbody = self._lower_stmt(hbody_node) if hbody_node is not None else []
                if bound:
                    hbody.insert(0, UStmt(self._line(ch), "simple",
                                          f"catch {exc_name}", defs={bound}))
                st.handlers.append((exc_name, hbody))
            elif ch.type in {"finally_clause"}:
                fbody = ch.child_by_field_name("body")
                if fbody is None:
                    named = [c for c in ch.children if c.is_named]
                    fbody = named[0] if named else None
                if fbody is not None:
                    st.finalbody = self._lower_stmt(fbody)
        return st

    # -- expression facts (defs / uses / calls / literal) -----------------
    def _expr_facts(self, node):
        """
        Compute (defs, uses, calls, literal_value) for an expression or simple
        statement subtree. Assignment targets and declarators become defs;
        every other identifier read becomes a use.
        """
        defs, uses = set(), set()
        calls: list[UCall] = []
        literal = None

        def walk(n, in_lhs=False):
            nonlocal literal
            t = n.type

            if t in ASSIGN_NODES:
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if left is not None:
                    self._targets(left, defs, uses)
                    if t == "augmented_assignment_expression":
                        # x += y reads x as well
                        self._targets(left, set(), uses)
                if right is not None:
                    walk(right)
                    lit = self._literal_of(right)
                    if lit is not None and left is not None and left.type in IDENT_NODES:
                        literal = lit
                return

            if t in {"init_declarator", "variable_declarator"}:
                nm = n.child_by_field_name("declarator") or n.child_by_field_name("name")
                val = n.child_by_field_name("value")
                if nm is not None:
                    self._targets(nm, defs, uses)
                if val is not None:
                    walk(val)
                    lit = self._literal_of(val)
                    if lit is not None:
                        literal = lit
                return

            if t in DECL_NODES:
                # The first named child of a declaration is its *type*, not a
                # variable; only declarators introduce definitions.
                type_node = n.child_by_field_name("type")
                for ch in n.children:
                    if ch is type_node:
                        continue
                    if ch.type in {"init_declarator", "variable_declarator"}:
                        walk(ch)
                    elif ch.type in {"pointer_declarator", "array_declarator",
                                     "reference_declarator", "function_declarator"}:
                        self._targets(ch, defs, uses)
                    elif ch.type in IDENT_NODES:
                        if ch.type != "type_identifier":
                            defs.add(self._text(ch))
                    elif ch.is_named and ch.type not in _TYPE_NODES:
                        walk(ch)
                return

            if t == "update_expression":                 # i++ / --i
                arg = n.child_by_field_name("argument")
                if arg is not None:
                    self._targets(arg, defs, uses)
                    self._targets(arg, set(), uses)
                return

            if t in CALL_NODES:
                calls.append(self._lower_call(n))
                # Java's `method_invocation` carries its receiver in an
                # `object` field on the call node itself, while C-family
                # grammars nest it inside the callee expression. Handle the
                # former here so fluent chains such as
                # `MessageDigest.getInstance("MD5").digest(d)` record the
                # inner call and the algorithm literal it selects.
                recv = n.child_by_field_name("object")
                if recv is not None:
                    walk(recv)
                fn = n.child_by_field_name("function") or n.child_by_field_name("constructor")
                if fn is not None and fn.type not in IDENT_NODES:
                    # The receiver of a method call is a use (obj.m()). It may
                    # itself be a call, as in the fluent style
                    # `MessageDigest.getInstance("MD5").digest(d)` -- walking it
                    # is what records the inner call and its literal argument.
                    obj = fn.child_by_field_name("object") or \
                        fn.child_by_field_name("argument")
                    if obj is not None:
                        walk(obj)
                args = n.child_by_field_name("arguments")
                if args is not None:
                    for ch in args.children:
                        if ch.is_named:
                            walk(ch)
                return

            if t == "pointer_expression":
                # `*p` reads (or writes) through p, so p itself is the
                # variable that carries the value -- this is what lets taint
                # follow `char *data = *dataPtr;`.
                arg = n.child_by_field_name("argument")
                if arg is not None:
                    walk(arg, in_lhs)
                return

            if t in {"field_expression", "field_access", "member_expression"} and not in_lhs:
                # `req.query.name` is a *read* of the dotted path and of its
                # base object; the trailing field name is not a variable.
                dotted = self._text(n).replace("->", ".")
                uses.add(dotted)
                base = n.child_by_field_name("argument") or n.child_by_field_name("object")
                while base is not None and base.type in {"field_expression", "field_access",
                                                         "member_expression"}:
                    uses.add(self._text(base).replace("->", "."))
                    nxt = base.child_by_field_name("argument") or \
                        base.child_by_field_name("object")
                    if nxt is None:
                        break
                    base = nxt
                if base is not None and base.type in IDENT_NODES:
                    uses.add(self._text(base))
                elif base is not None:
                    # A call receiver (fluent chaining) must still be lowered so
                    # its own callee and arguments are recorded.
                    walk(base)
                return

            if t in IDENT_NODES and t not in _TYPE_NODES:
                (defs if in_lhs else uses).add(self._resolve(self._text(n)))
                return

            if t in _LITERAL_NODES and literal is None and n.parent is not None \
                    and n.parent.type in {"return_statement", "expression_statement"}:
                literal = self._literal_of(n)

            for ch in n.children:
                if ch.is_named:
                    walk(ch, in_lhs)

        walk(node)
        uses -= defs & uses if False else set()          # keep both (x = x + 1)
        return defs, uses, calls, literal

    def _targets(self, node, defs: set, uses: set):
        """Record assignment/declaration targets: `a` defs a; `a[i]` defs a, uses i."""
        t = node.type
        if t in IDENT_NODES:
            defs.add(self._text(node))
            return
        if t in {"subscript_expression", "array_access"}:
            base = node.child_by_field_name("argument") or node.child_by_field_name("array")
            idx = node.child_by_field_name("index") or node.child_by_field_name("indices")
            if base is not None:
                self._targets(base, defs, uses)
            if idx is not None:
                for n2 in _descend(idx):
                    if n2.type in IDENT_NODES:
                        uses.add(self._text(n2))
            return
        if t in {"field_expression", "field_access", "member_expression"}:
            # obj.field = v  -> define the dotted name AND the base object
            defs.add(self._text(node))
            base = node.child_by_field_name("argument") or node.child_by_field_name("object")
            if base is not None and base.type in IDENT_NODES:
                defs.add(self._text(base))
            return
        if t in {"pointer_declarator", "array_declarator", "reference_declarator",
                 "parenthesized_declarator", "init_declarator", "variable_declarator"}:
            inner = node.child_by_field_name("declarator") or node.child_by_field_name("name")
            if inner is not None:
                self._targets(inner, defs, uses)
                return
        if t in {"pointer_expression", "parenthesized_expression"}:
            arg = node.child_by_field_name("argument")
            if arg is not None:
                self._targets(arg, defs, uses)
                return
        # generic fallback: first identifier is the target
        for ch in _descend(node):
            if ch.type in IDENT_NODES:
                defs.add(self._text(ch))
                return

    def _lower_call(self, node) -> UCall:
        fn = node.child_by_field_name("function") or \
            node.child_by_field_name("constructor") or \
            node.child_by_field_name("name")
        callee = self._callee_name(fn) if fn is not None else "<anon>"
        args = []
        alist = node.child_by_field_name("arguments")
        if alist is not None:
            for ch in alist.children:
                if not ch.is_named:
                    continue
                if ch.type in IDENT_NODES:
                    args.append(("name", self._resolve(self._text(ch))))
                elif ch.type in _LITERAL_NODES:
                    args.append(("const", self._literal_of(ch)))
                else:
                    names = frozenset(self._resolve(self._text(x))
                                      for x in _descend(ch)
                                      if x.type in IDENT_NODES)
                    args.append(("expr", names))
        return UCall(callee=callee, args=args, lineno=self._line(node),
                     is_ctor=node.type in {"new_expression", "object_creation_expression"})

    def _callee_name(self, fn) -> str:
        """Flatten a callee expression into a dotted, canonical name."""
        t = fn.type
        if t in IDENT_NODES:
            # `#define SYSTEM system` must resolve to the real API name so the
            # sink tables match the function actually invoked.
            return self._resolve(self._text(fn))
        if t in {"field_expression", "field_access", "member_expression",
                 "scoped_identifier", "qualified_identifier"}:
            return self._text(fn).replace("->", ".").replace("::", ".")
        return self._text(fn).replace("->", ".").replace("::", ".").strip()

    def _literal_of(self, node):
        """Return a Python value for a literal CST node, else None."""
        t = node.type
        txt = self._text(node)
        try:
            if t in {"number_literal", "decimal_integer_literal", "number",
                     "hex_integer_literal"}:
                s = txt.rstrip("uUlLfF")
                return int(s, 0) if not any(c in s for c in ".eE") else float(s)
            if t in {"decimal_floating_point_literal"}:
                return float(txt.rstrip("fFdD"))
            if t in {"string_literal", "char_literal", "string"}:
                return txt.strip("\"'`")
            if t in {"true"}:
                return True
            if t in {"false"}:
                return False
            if t in {"null", "null_literal"}:
                return None
        except (ValueError, TypeError):
            return None
        return None


def _descend(node):
    """Yield every descendant (including the node itself)."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _flatten(stmts):
    """Yield every UStmt in a body, descending into structured children."""
    for s in stmts:
        yield s
        yield from _flatten(s.then_body)
        yield from _flatten(s.else_body)
        yield from _flatten(s.body)
        for _, hb in s.handlers:
            yield from _flatten(hb)
        yield from _flatten(s.finalbody)
        for _, cb in s.cases:
            yield from _flatten(cb)


def lower_to_uir(code: str, language: str) -> UProgram:
    """Public entry point: source + language -> :class:`UProgram`."""
    return UIRLowering(code, language).lower()
