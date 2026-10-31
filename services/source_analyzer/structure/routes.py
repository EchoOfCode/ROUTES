"""Next.js route discovery from real source (not just file names).

App Router: ``app/**/route.{js,ts}`` files are inspected for exported HTTP
method handlers. Pages Router: ``pages/api/**`` files are inspected for a
default-exported handler and the ``req.method`` values it branches on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tree_sitter import Node

from source_analyzer.structure.parser import FUNCTION_TYPES, line, string_value, text, unwrap, walk

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
APP_ROUTE_RE = re.compile(r"^(?:(?P<prefix>.*?)/)?(?:src/)?app/(?P<path>(?:.+/)?)route\.(?:js|jsx|ts|tsx|mjs|cjs)$")
PAGES_API_RE = re.compile(r"^(?:(?P<prefix>.*?)/)?(?:src/)?pages/(?P<path>api(?:/.+)?)\.(?:js|jsx|ts|tsx|mjs|cjs)$")


@dataclass
class Handler:
    method: str  # HTTP method, or ANY for Pages Router handlers without explicit checks
    function: Node
    name: str
    line: int
    request_param_index: int = 0
    context_param_index: int | None = 1


@dataclass
class RouteFile:
    rel: str
    router: str  # "app" | "pages"
    endpoint: str
    handlers: list[Handler]


def endpoint_for(rel: str) -> tuple[str, str] | None:
    """Map a file path to (router, endpoint path)."""
    m = APP_ROUTE_RE.match(rel)
    if m:
        if m.group("prefix") and m.group("prefix").split("/")[-1] in ("node_modules", "test", "tests", "__tests__"):
            return None
        return "app", _clean_segments(m.group("path"))
    m = PAGES_API_RE.match(rel)
    if m:
        path = m.group("path")
        if path.endswith("/index") or path == "index":
            path = path[: -len("index")].rstrip("/")
        return "pages", _clean_segments(path)
    return None


def _clean_segments(path: str) -> str:
    segments = []
    for seg in path.strip("/").split("/"):
        if not seg:
            continue
        if seg.startswith("(") and seg.endswith(")"):
            continue  # route groups don't appear in URLs
        if seg.startswith("@"):
            continue  # parallel route slots
        segments.append(seg)
    return "/" + "/".join(segments)


def _exported_functions(root: Node) -> dict[str, Node]:
    """Exported name -> function node (declarations and const arrow functions)."""
    out: dict[str, Node] = {}
    local_functions: dict[str, Node] = {}
    for node in root.named_children:
        target = node.child_by_field_name("declaration") if node.type == "export_statement" else node
        if target is None:
            target = node
        if target.type in ("function_declaration", "generator_function_declaration"):
            name = text(target.child_by_field_name("name"))
            local_functions[name] = target
            if node.type == "export_statement":
                out["default" if _is_default(node) else name] = target
        elif target.type in ("lexical_declaration", "variable_declaration"):
            for decl in target.named_children:
                if decl.type != "variable_declarator":
                    continue
                value = unwrap(decl.child_by_field_name("value"))
                name = text(decl.child_by_field_name("name"))
                value = _unwrap_wrapper_call(value)
                if value is not None and value.type in FUNCTION_TYPES:
                    local_functions[name] = value
                    if node.type == "export_statement":
                        out[name] = value
        if node.type == "export_statement" and _is_default(node):
            value = unwrap(node.child_by_field_name("value"))
            value = _unwrap_wrapper_call(value)
            if value is not None and value.type in FUNCTION_TYPES:
                out["default"] = value
            elif value is not None and value.type == "identifier" and text(value) in local_functions:
                out["default"] = local_functions[text(value)]
        if node.type == "export_statement":
            clause = next((c for c in node.named_children if c.type == "export_clause"), None)
            if clause is not None:
                for spec in clause.named_children:
                    local = text(spec.child_by_field_name("name"))
                    alias = text(spec.child_by_field_name("alias")) or local
                    if local in local_functions:
                        out[alias] = local_functions[local]
    # CommonJS: module.exports = handler
    for node in root.named_children:
        if node.type == "expression_statement":
            expr = node.named_children[0] if node.named_children else None
            if expr is not None and expr.type == "assignment_expression" and text(expr.child_by_field_name("left")) in (
                "module.exports", "exports.default"):
                value = _unwrap_wrapper_call(unwrap(expr.child_by_field_name("right")))
                if value is not None and value.type in FUNCTION_TYPES:
                    out["default"] = value
                elif value is not None and value.type == "identifier" and text(value) in local_functions:
                    out["default"] = local_functions[text(value)]
    return out


def _unwrap_wrapper_call(value: Node | None) -> Node | None:
    """`export default withAuth(async (req, res) => {...})` -> the inner function."""
    if value is not None and value.type == "call_expression":
        args = value.child_by_field_name("arguments")
        for a in (args.named_children if args else []):
            if a.type in FUNCTION_TYPES:
                return a
    return value


def _is_default(export_node: Node) -> bool:
    return any(c.type == "default" or text(c) == "default" for c in export_node.children)


def _pages_methods(fn: Node) -> list[str]:
    methods = set()
    for n in walk(fn):
        if n.type == "binary_expression" and text(n.child_by_field_name("operator")) in ("===", "==", "!==", "!="):
            left, right = text(n.child_by_field_name("left")), n.child_by_field_name("right")
            if left.endswith(".method"):
                value = string_value(right)
                if value and value.upper() in HTTP_METHODS:
                    methods.add(value.upper())
        elif n.type == "switch_statement" and text(n.child_by_field_name("value")).strip("()").endswith(".method"):
            for case in walk(n):
                if case.type == "switch_case":
                    value = string_value(case.child_by_field_name("value"))
                    if value and value.upper() in HTTP_METHODS:
                        methods.add(value.upper())
    return sorted(methods) or ["ANY"]


def discover_route(rel: str, root: Node) -> RouteFile | None:
    mapped = endpoint_for(rel)
    if mapped is None:
        return None
    router, endpoint = mapped
    exported = _exported_functions(root)
    handlers: list[Handler] = []
    if router == "app":
        for method in HTTP_METHODS:
            fn = exported.get(method)
            if fn is not None:
                handlers.append(Handler(method=method, function=fn, name=method, line=line(fn)))
    else:
        fn = exported.get("default")
        if fn is not None:
            for method in _pages_methods(fn):
                handlers.append(Handler(method=method, function=fn, name="default export", line=line(fn),
                                        context_param_index=None))
    return RouteFile(rel=rel, router=router, endpoint=endpoint, handlers=handlers)
