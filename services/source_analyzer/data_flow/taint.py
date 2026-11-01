"""Intra-procedural taint tracking over tree-sitter ASTs.

Deliberately simple and explainable: within one function, values derived
from user-controlled inputs are tracked through declarations, destructuring,
assignments, string building and method calls. Known sanitisers (numeric
conversion, allow-list ternaries, pg escaping helpers) stop propagation.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from tree_sitter import Node

from source_analyzer.structure.parser import FUNCTION_TYPES, line, pattern_names, text, unwrap

SANITISER_CALLS = {"Number", "parseInt", "parseFloat", "Boolean", "BigInt", "isNaN", "isFinite", "escapeLiteral",
                   "escapeIdentifier", "uuidValidate"}
SANITISER_MEMBERS = {"escapeLiteral", "escapeIdentifier", "literal", "ident", "toFixed", "length", "isInteger",
                     "isSafeInteger"}
SANITISER_OBJECTS = {"Math", "Number"}


@dataclass(frozen=True)
class Source:
    kind: str  # e.g. "URL query parameter", "request body", "route parameter", "parameter"
    name: str
    line: int
    expression: str
    param_index: int | None = None


@dataclass
class Taint:
    sources: tuple[Source, ...]
    steps: tuple[str, ...] = ()

    def merge(self, other: "Taint | None") -> "Taint":
        if other is None:
            return self
        sources = tuple(dict.fromkeys(self.sources + other.sources))[:5]
        steps = tuple(dict.fromkeys(self.steps + other.steps))[:12]
        return Taint(sources, steps)

    def step(self, description: str) -> "Taint":
        return Taint(self.sources, tuple(dict.fromkeys(self.steps + (description[:160],)))[:12])


def merge(*taints: Taint | None) -> Taint | None:
    out = None
    for t in taints:
        if t is not None:
            out = t if out is None else out.merge(t)
    return out


def classify_source(expr: str, base: str) -> str:
    lowered = expr.lower()
    if base == "context" or ".params" in lowered or lowered.startswith("params") or "{ params" in lowered:
        return "route parameter"
    if "searchparams" in lowered or ".query" in lowered:
        return "URL query parameter"
    if "formdata" in lowered:
        return "form data"
    if ".json(" in lowered or ".body" in lowered or ".text(" in lowered:
        return "request body"
    if "headers" in lowered:
        return "request header"
    if "cookies" in lowered:
        return "cookie"
    return "request data"


def _name_hint(node: Node) -> str:
    """Best-effort parameter name for messages, e.g. searchParams.get('q') -> q."""
    node = unwrap(node)
    if node is None:
        return ""
    if node.type == "call_expression":
        args = node.child_by_field_name("arguments")
        if args is not None and args.named_children and args.named_children[0].type == "string":
            return text(args.named_children[0]).strip("'\"`")[:60]
    if node.type == "member_expression":
        prop = node.child_by_field_name("property")
        return text(prop)[:60]
    return text(node)[:60]


@dataclass
class FunctionFacts:
    """Per-function results used by sink analysis."""

    env: dict[str, Taint] = field(default_factory=dict)
    defs: dict[str, list[Node]] = field(default_factory=dict)
    params: dict[str, int] = field(default_factory=dict)
    local_pool_vars: set[str] = field(default_factory=set)


class TaintEngine:
    def __init__(self, fn: Node, *, request_params: dict[int, str] | None = None, taint_params: bool = False,
                 is_pool_expr=None, extra_seed=None, extra_sanitisers=None):
        """request_params: {parameter index: base} where base is "request" or "context".
        taint_params: treat every parameter as a source (used for helper summaries).
        extra_seed: optional callable(node) -> Source | None, consulted before the normal
        type dispatch in taint_of(); used to recognise sources that are not function
        parameters, such as global browser state (location.search, document.referrer).
        extra_sanitisers: optional compiled regex; a call whose callee text matches it
        clears the taint. Class-specific: HTML escaping makes a value safe for a page,
        not for SQL, so only the XSS analysis passes one."""
        self.fn = fn
        self.facts = FunctionFacts()
        self.is_pool_expr = is_pool_expr or (lambda node, facts: False)
        self.extra_seed = extra_seed
        self.extra_sanitisers = extra_sanitisers
        for i, p in enumerate(_params(fn)):
            for name in pattern_names(p):
                self.facts.params[name] = i
        self.request_params = request_params or {}
        self.taint_params = taint_params
        self._seed()
        self._propagate()

    # --------------------------------------------------------------- seeding
    def _seed(self) -> None:
        for i, p in enumerate(_params(self.fn)):
            names = pattern_names(p)
            for name in names:
                base = self.request_params.get(i)
                if base:
                    kind = "route parameter" if base == "context" else "request"
                    self.facts.env[name] = Taint((Source(kind=kind, name=name, line=line(p), expression=text(p)[:120]),))
                elif self.taint_params:
                    self.facts.env[name] = Taint((Source(kind="parameter", name=name, line=line(p),
                                                         expression=text(p)[:120], param_index=i),))

    def _propagate(self) -> None:
        body = self.fn.child_by_field_name("body")
        if body is None:
            return
        bindings = list(_bindings(body))
        for _ in range(3):  # small fixed point for out-of-order assignments
            changed = False
            for target, value, kind in bindings:
                if kind == "decl" or kind == "assign":
                    names = pattern_names(target) if target.type != "identifier" else [text(target)]
                    for name in names:
                        if value is not None:
                            self.facts.defs.setdefault(name, [])
                            if value not in self.facts.defs[name]:
                                self.facts.defs[name].append(value)
                            if self.is_pool_expr(value, self.facts):
                                self.facts.local_pool_vars.add(name)
                    t = self.taint_of(value) if value is not None else None
                    if t is not None:
                        for name in names:
                            nt = t if target.type == "identifier" else Taint(
                                tuple(replace(src, name=name) if src.kind != "parameter" else src for src in t.sources),
                                t.steps,
                            ).step(f"destructured into {name}")
                            if self._set(name, nt.step(f"assigned to {name} (line {line(target)})")):
                                changed = True
                elif kind == "augment":
                    name = text(target)
                    self.facts.defs.setdefault(name, [])
                    if value not in self.facts.defs[name]:
                        self.facts.defs[name].append(value)
                    t = self.taint_of(value)
                    if t is not None and self._set(name, t.step(f"appended to {name} (line {line(target)})")):
                        changed = True
                elif kind == "for":
                    t = self.taint_of(value)
                    if t is not None:
                        for name in pattern_names(target):
                            if self._set(name, t.step(f"iterated into {name}")):
                                changed = True
            if not changed:
                break

    def _set(self, name: str, taint: Taint) -> bool:
        current = self.facts.env.get(name)
        if current is None:
            self.facts.env[name] = taint
            return True
        merged = current.merge(taint)
        if merged.sources != current.sources:
            self.facts.env[name] = merged
            return True
        return False

    # ------------------------------------------------------------- evaluation
    def taint_of(self, node: Node | None, depth: int = 0) -> Taint | None:
        if node is None or depth > 40:
            return None
        node = unwrap(node)
        if node is None:
            return None
        if self.extra_seed is not None:
            seeded = self.extra_seed(node)
            if seeded is not None:
                return Taint((seeded,))
        t = node.type
        if t in ("identifier", "shorthand_property_identifier"):
            return self.facts.env.get(text(node))
        if t in ("string", "number", "true", "false", "null", "undefined", "regex", "template_literal_type"):
            return None
        if t == "member_expression":
            obj = node.child_by_field_name("object")
            inner = self.taint_of(obj, depth + 1)
            if inner is None:
                return None
            return self._refine(inner, node)
        if t == "subscript_expression":
            return self.taint_of(node.child_by_field_name("object"), depth + 1)
        if t == "call_expression":
            return self._call_taint(node, depth)
        if t == "new_expression":
            args = node.child_by_field_name("arguments")
            return merge(*(self.taint_of(a, depth + 1) for a in (args.named_children if args else [])))
        if t == "template_string":
            subs = [c for c in node.named_children if c.type == "template_substitution"]
            found = merge(*(self.taint_of(s.named_children[0] if s.named_children else None, depth + 1) for s in subs))
            return found.step(f"inserted into a template string (line {line(node)})") if found else None
        if t == "binary_expression":
            op = text(node.child_by_field_name("operator"))
            if op in ("+",):
                left = self.taint_of(node.child_by_field_name("left"), depth + 1)
                right = self.taint_of(node.child_by_field_name("right"), depth + 1)
                found = merge(left, right)
                return found.step(f"concatenated into a string (line {line(node)})") if found else None
            if op in ("||", "??", "&&"):
                return merge(self.taint_of(node.child_by_field_name("left"), depth + 1),
                             self.taint_of(node.child_by_field_name("right"), depth + 1))
            return None  # comparisons, arithmetic produce booleans/numbers
        if t == "ternary_expression":
            if _is_allowlist_check(node.child_by_field_name("condition"), self.facts):
                return None
            return merge(self.taint_of(node.child_by_field_name("consequence"), depth + 1),
                         self.taint_of(node.child_by_field_name("alternative"), depth + 1))
        if t in ("array", "object"):
            parts = []
            for c in node.named_children:
                if c.type == "pair":
                    parts.append(self.taint_of(c.child_by_field_name("value"), depth + 1))
                elif c.type == "spread_element":
                    parts.append(self.taint_of(c.named_children[0] if c.named_children else None, depth + 1))
                else:
                    parts.append(self.taint_of(c, depth + 1))
            return merge(*parts)
        if t == "spread_element":
            return self.taint_of(node.named_children[0] if node.named_children else None, depth + 1)
        if t == "assignment_expression":
            return self.taint_of(node.child_by_field_name("right"), depth + 1)
        if t == "sequence_expression":
            return self.taint_of(node.named_children[-1] if node.named_children else None, depth + 1)
        return None

    def _refine(self, inner: Taint, node: Node) -> Taint:
        """While reading from the request/context object, label the input kind
        (query parameter, body, route parameter...) as precisely as possible."""
        refined = []
        changed = False
        for s in inner.sources:
            if s.kind in ("request", "request data", "route parameter"):
                base = "context" if s.kind == "route parameter" else "request"
                kind = classify_source(text(node), base)
                if kind != "request data" or s.kind == "request":
                    refined.append(Source(kind=kind, name=_name_hint(node), line=line(node), expression=text(node)[:160]))
                    changed = True
                    continue
            refined.append(s)
        return Taint(tuple(refined), inner.steps) if changed else inner

    def _call_taint(self, node: Node, depth: int) -> Taint | None:
        callee = unwrap(node.child_by_field_name("function"))
        args = node.child_by_field_name("arguments")
        arg_nodes = args.named_children if args is not None else []
        if callee is None:
            return None
        if callee.type == "identifier" and text(callee) in SANITISER_CALLS:
            return None
        if self.extra_sanitisers is not None and callee.type in ("identifier", "member_expression")                 and self.extra_sanitisers.search(text(callee)):
            return None
        if callee.type == "member_expression":
            obj = callee.child_by_field_name("object")
            prop = text(callee.child_by_field_name("property"))
            if prop in SANITISER_MEMBERS or text(obj) in SANITISER_OBJECTS:
                return None
            inner = self.taint_of(obj, depth + 1)
            if inner is not None:
                if prop in ("get", "getAll") and arg_nodes and arg_nodes[0].type == "string":
                    # searchParams.get("q") / formData.get("region"): name the input precisely.
                    key = text(arg_nodes[0]).strip("'\"`")[:60]
                    inner = Taint(tuple(replace(s, name=key, line=line(node), expression=text(node)[:160])
                                        if s.kind != "parameter" else s for s in inner.sources), inner.steps)
                refined = self._refine(inner, node)
                return refined if refined is not inner else inner.step(f".{prop}() on user input (line {line(node)})")
        # Unknown function called with user input: assume the result may still carry it.
        found = merge(*(self.taint_of(a, depth + 1) for a in arg_nodes))
        if found is not None and callee.type in ("identifier", "member_expression"):
            name = text(callee)[:60]
            if name in ("String", "decodeURIComponent", "decodeURI", "JSON.stringify", "unescape"):
                return found.step(f"converted with {name}()")
            return found.step(f"passed through {name}() (line {line(node)})")
        return found


def _params(fn: Node) -> list[Node]:
    from source_analyzer.structure.parser import params_of

    return params_of(fn)


def _bindings(body: Node):
    """Yield (target, value, kind) for all bindings in a function body, in order.
    Nested functions are included: closures commonly build queries too."""
    stack = [body]
    order = []
    while stack:
        n = stack.pop()
        order.append(n)
        stack.extend(reversed(n.children))
    for n in order:
        if n.type == "variable_declarator":
            name = n.child_by_field_name("name")
            if name is not None:
                yield name, n.child_by_field_name("value"), "decl"
        elif n.type == "assignment_expression":
            left = n.child_by_field_name("left")
            if left is not None and left.type in ("identifier", "object_pattern", "array_pattern"):
                yield left, n.child_by_field_name("right"), "assign"
        elif n.type == "augmented_assignment_expression":
            left = n.child_by_field_name("left")
            if left is not None and left.type == "identifier":
                yield left, n.child_by_field_name("right"), "augment"
        elif n.type == "for_in_statement":
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            if left is not None and right is not None:
                yield left, right, "for"


def _is_allowlist_check(cond: Node | None, facts: FunctionFacts) -> bool:
    """`[...].includes(x) ? x : 'default'` and `ALLOWED.has(x) ? ...` stop taint."""
    cond = unwrap(cond)
    if cond is None or cond.type != "call_expression":
        return False
    callee = cond.child_by_field_name("function")
    if callee is None or callee.type != "member_expression":
        return False
    if text(callee.child_by_field_name("property")) not in ("includes", "has", "indexOf"):
        return False
    obj = unwrap(callee.child_by_field_name("object"))
    if obj is None:
        return False
    if obj.type == "array":
        return all(c.type == "string" for c in obj.named_children)
    if obj.type == "identifier":
        for d in facts.defs.get(text(obj), []):
            d = unwrap(d)
            if d is not None and d.type == "array" and all(c.type == "string" for c in d.named_children):
                return True
            if d is not None and d.type == "new_expression" and "Set" in text(d.child_by_field_name("constructor")):
                return True
        return obj.type == "identifier" and text(obj).isupper()  # module-level constant allow-lists
    return False


def is_function(node: Node) -> bool:
    return node.type in FUNCTION_TYPES
