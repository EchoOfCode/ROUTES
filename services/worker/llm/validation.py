"""Fix-response validation for LLM B's output.

Deliberately independent of source_analyzer.structure.parser: source_analyzer
is sandbox-only code, never installed in the worker's image, and the worker
is a different trust tier - this is its own small copy of the same
tree-sitter setup, not a shared import.

Validation criteria (the prompt says "with response validation" without
listing criteria - these are a judgment call, not a restated spec): the
candidate must still parse, must not add a new import/require beyond what
the original snapshot already had, and must not add a new network call
beyond what the original already had.
"""

from __future__ import annotations

from functools import lru_cache

import tree_sitter_javascript as ts_javascript
import tree_sitter_typescript as ts_typescript
from tree_sitter import Language, Node, Parser

_NETWORK_CALL_NAMES = {"fetch", "axios", "XMLHttpRequest", "http.request", "https.request", "http.get", "https.get"}


@lru_cache
def _language(kind: str) -> Language:
    if kind == "ts":
        return Language(ts_typescript.language_typescript())
    if kind == "tsx":
        return Language(ts_typescript.language_tsx())
    return Language(ts_javascript.language())


def _language_for(path: str) -> str:
    lowered = path.lower()
    if lowered.endswith((".ts", ".mts", ".cts")):
        return "ts"
    if lowered.endswith(".tsx"):
        return "tsx"
    return "js"


def _parse(path: str, source: bytes):
    return Parser(_language(_language_for(path))).parse(source)


def _text(node: Node | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", "replace")


def _walk(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _imported_specifiers(root: Node) -> set[str]:
    specs = set()
    for node in _walk(root):
        if node.type == "import_statement":
            source = node.child_by_field_name("source")
            if source is not None:
                specs.add(_text(source).strip("'\"`"))
        elif node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if callee is not None and _text(callee) == "require":
                args = node.child_by_field_name("arguments")
                if args is not None and args.named_children:
                    specs.add(_text(args.named_children[0]).strip("'\"`"))
    return specs


def _network_call_names(root: Node) -> set[str]:
    names = set()
    for node in _walk(root):
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            name = _text(callee)
            if name in _NETWORK_CALL_NAMES:
                names.add(name)
    return names


def validate_fix(file: str, original_code: str, candidate_code: str, *, forbid_new_dependencies: bool = True,
                  forbid_network_calls: bool = True) -> list[str]:
    """Returns a list of validation errors; empty means the candidate passed."""
    candidate_tree = _parse(file, candidate_code.encode())
    if candidate_tree.root_node.has_error:
        return ["Candidate code has a syntax error."]

    errors: list[str] = []
    original_tree = _parse(file, original_code.encode())
    if forbid_new_dependencies:
        new_imports = _imported_specifiers(candidate_tree.root_node) - _imported_specifiers(original_tree.root_node)
        if new_imports:
            errors.append(f"Candidate introduces new imports: {sorted(new_imports)}")
    if forbid_network_calls:
        new_calls = _network_call_names(candidate_tree.root_node) - _network_call_names(original_tree.root_node)
        if new_calls:
            errors.append(f"Candidate introduces new network calls: {sorted(new_calls)}")
    return errors
