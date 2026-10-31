"""Tree-sitter parsing helpers for JavaScript / TypeScript / TSX."""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

import tree_sitter_javascript as ts_javascript
import tree_sitter_typescript as ts_typescript
from tree_sitter import Language, Node, Parser


@lru_cache
def _language(kind: str) -> Language:
    if kind == "ts":
        return Language(ts_typescript.language_typescript())
    if kind == "tsx":
        return Language(ts_typescript.language_tsx())
    return Language(ts_javascript.language())


def language_for(path: str) -> str:
    lowered = path.lower()
    if lowered.endswith((".ts", ".mts", ".cts")):
        return "ts"
    if lowered.endswith(".tsx"):
        return "tsx"
    return "js"


def parse(path: str, source: bytes):
    parser = Parser(_language(language_for(path)))
    return parser.parse(source)


def text(node: Node | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", "replace")


def line(node: Node) -> int:
    return node.start_point[0] + 1


def walk(node: Node) -> Iterator[Node]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


WRAPPERS = {"parenthesized_expression", "as_expression", "non_null_expression", "satisfies_expression",
            "type_assertion", "await_expression"}


def unwrap(node: Node | None) -> Node | None:
    """Strip parentheses, TS assertions and await."""
    while node is not None and node.type in WRAPPERS:
        inner = [c for c in node.named_children if c.type not in ("type_annotation", "type_identifier",
                                                                   "predefined_type", "generic_type")]
        node = inner[0] if inner else None
    return node


def string_value(node: Node | None) -> str | None:
    node = unwrap(node)
    if node is None:
        return None
    if node.type == "string":
        return "".join(text(c) for c in node.named_children if c.type in ("string_fragment", "escape_sequence"))
    if node.type == "template_string" and not any(c.type == "template_substitution" for c in node.named_children):
        return text(node)[1:-1]
    return None


FUNCTION_TYPES = {"function_declaration", "function_expression", "arrow_function", "method_definition",
                  "generator_function_declaration", "function"}


def params_of(fn: Node) -> list[Node]:
    params = fn.child_by_field_name("parameters")
    if params is None:
        single = fn.child_by_field_name("parameter")
        return [single] if single is not None else []
    return [p for p in params.named_children if p.type not in ("comment",)]


def param_pattern(p: Node) -> Node:
    """TS wraps parameters as required_parameter/optional_parameter(pattern=...)."""
    if p.type in ("required_parameter", "optional_parameter"):
        inner = p.child_by_field_name("pattern")
        if inner is not None:
            return inner
    if p.type == "assignment_pattern":
        left = p.child_by_field_name("left")
        if left is not None:
            return left
    return p


def pattern_names(pattern: Node) -> list[str]:
    """All identifiers bound by a (possibly destructuring) pattern."""
    pattern = param_pattern(pattern)
    if pattern.type in ("identifier", "shorthand_property_identifier_pattern"):
        return [text(pattern)]
    names: list[str] = []
    if pattern.type in ("object_pattern", "array_pattern"):
        for child in pattern.named_children:
            if child.type == "pair_pattern":
                value = child.child_by_field_name("value")
                if value is not None:
                    names.extend(pattern_names(value))
            elif child.type == "object_assignment_pattern":
                left = child.child_by_field_name("left")
                if left is not None:
                    names.extend(pattern_names(left))
            elif child.type == "rest_pattern":
                names.extend(pattern_names(child.named_children[0]) if child.named_children else [])
            else:
                names.extend(pattern_names(child))
    elif pattern.type == "assignment_pattern":
        left = pattern.child_by_field_name("left")
        if left is not None:
            names.extend(pattern_names(left))
    return names
