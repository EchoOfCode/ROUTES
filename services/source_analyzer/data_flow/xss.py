"""Cross-site scripting analysis for Next.js (JS/TS).

Two independent, intra-procedural heuristics, in the same style as the SQLi
engine:
  1. DOM sinks: `el.innerHTML = <tainted>` / `document.write(<tainted>)`,
     where the tainted value comes from browser-controlled state (the URL,
     the referrer, window.name) or Next.js' `useSearchParams()`.
  2. Reflected response: an API route handler builds its response body by
     interpolating or concatenating request-controlled data directly,
     instead of returning it as JSON.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tree_sitter import Node

from source_analyzer.data_flow.taint import Source, Taint, TaintEngine
from source_analyzer.structure.parser import line, text, unwrap, walk
from source_analyzer.structure.routes import Handler, RouteFile

# HTML-output sanitisers: escaping / encoding helpers and the usual sanitiser libraries
# (escapeHtml, he.encode, DOMPurify.sanitize, sanitizeHtml, encodeURIComponent, ...).
# They make a value safe to put in a page; the SQL injection analysis does not use them.
XSS_SANITISERS = re.compile(r"(?i)(?:^|\.)(?!un)[\w$]*(?:escape|encode|sanitiz|sanitis|purify|xss)[\w$]*$")

_DOM_SOURCE_EXPR_RE = re.compile(
    r"^(window\.)?(location\.(search|hash|href|pathname)|document\.referrer|window\.name)$"
)


@dataclass
class XssFinding:
    rule: str  # "dom_sink" | "reflected_response"
    sink_label: str
    file: str
    line: int
    end_line: int
    snippet: str
    endpoint: str | None
    method: str | None
    taint: Taint


def _dom_source(node: Node) -> Source | None:
    if node.type == "call_expression":
        callee = unwrap(node.child_by_field_name("function"))
        if callee is not None and text(callee) == "useSearchParams":
            return Source(kind="URL query parameter", name="useSearchParams()", line=line(node),
                          expression=text(node)[:160])
        return None
    expr = text(node)
    if _DOM_SOURCE_EXPR_RE.match(expr):
        return Source(kind="URL/browser state", name=expr.rsplit(".", 1)[-1], line=line(node), expression=expr[:160])
    return None


def _builds_string(node: Node | None) -> bool:
    node = unwrap(node)
    if node is None:
        return False
    if node.type == "template_string":
        return any(c.type == "template_substitution" for c in node.named_children)
    if node.type == "binary_expression":
        return text(node.child_by_field_name("operator")) == "+"
    return False


class XssAnalyzer:
    def __init__(self, module_functions: dict[str, list[Node]], routes: list[RouteFile]):
        """module_functions: file -> its top-level function nodes (as already
        collected by SqliAnalyzer's module index, reused here)."""
        self.module_functions = module_functions
        self.routes = routes
        self.findings: list[XssFinding] = []

    def run(self) -> None:
        for rel, functions in self.module_functions.items():
            for fn in functions:
                self._scan_dom_sinks(rel, fn)
        for route in self.routes:
            for handler in route.handlers:
                self._scan_reflected_response(route, handler)

    # ------------------------------------------------------------- DOM sinks
    def _scan_dom_sinks(self, rel: str, fn: Node) -> None:
        engine = TaintEngine(fn, extra_seed=_dom_source, extra_sanitisers=XSS_SANITISERS)
        for node in walk(fn.child_by_field_name("body") or fn):
            if node.type == "assignment_expression":
                left = unwrap(node.child_by_field_name("left"))
                if left is not None and left.type == "member_expression" and \
                        text(left.child_by_field_name("property")) == "innerHTML":
                    taint = engine.taint_of(node.child_by_field_name("right"))
                    if taint is not None:
                        self._add(rel, node, "dom_sink", "An innerHTML assignment", taint, None, None)
            elif node.type == "call_expression":
                callee = unwrap(node.child_by_field_name("function"))
                if callee is not None and callee.type == "member_expression":
                    obj = text(callee.child_by_field_name("object"))
                    prop = text(callee.child_by_field_name("property"))
                    if obj == "document" and prop in ("write", "writeln"):
                        args = node.child_by_field_name("arguments")
                        arg = args.named_children[0] if args and args.named_children else None
                        taint = engine.taint_of(arg) if arg is not None else None
                        if taint is not None:
                            self._add(rel, node, "dom_sink", f"A document.{prop}() call", taint, None, None)

    # ------------------------------------------------------- reflected response
    def _scan_reflected_response(self, route: RouteFile, handler: Handler) -> None:
        fn = handler.function
        request_params = {handler.request_param_index: "request"}
        if handler.context_param_index is not None:
            request_params[handler.context_param_index] = "context"
        engine = TaintEngine(fn, request_params=request_params, extra_sanitisers=XSS_SANITISERS)
        for node in walk(fn.child_by_field_name("body") or fn):
            if node.type != "new_expression":
                continue
            ctor = text(node.child_by_field_name("constructor"))
            if ctor not in ("Response", "NextResponse"):
                continue
            args = node.child_by_field_name("arguments")
            arg0 = args.named_children[0] if args and args.named_children else None
            if arg0 is None or not _builds_string(arg0):
                continue
            taint = engine.taint_of(arg0)
            if taint is not None:
                self._add(route.rel, node, "reflected_response", "The response body", taint, route.endpoint,
                          handler.method)

    def _add(self, rel: str, node: Node, rule: str, sink_label: str, taint: Taint, endpoint: str | None,
             method: str | None) -> None:
        self.findings.append(XssFinding(
            rule=rule, sink_label=sink_label, file=rel, line=line(node), end_line=node.end_point[0] + 1,
            snippet=text(node)[:1000], endpoint=endpoint, method=method, taint=taint,
        ))
