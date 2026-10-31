"""SQL injection analysis for Next.js + pg.

Pipeline:
  1. Index every JS/TS module: imports, pg Pool/Client instances, and what
     each module exports (a pool, a query passthrough, or a helper that
     builds SQL from its parameters).
  2. For each route handler, seed taint from the request (and route context),
     propagate it, and inspect every pg query call.
  3. A finding is produced only when user-controlled data reaches the SQL
     *text* through interpolation/concatenation (or is the text). Constant
     SQL with a values array is recorded as a safe, parameterised interaction.
"""

from __future__ import annotations

import hashlib
import posixpath
from dataclasses import dataclass, field

from tree_sitter import Node

from source_analyzer.data_flow.taint import Taint, TaintEngine
from source_analyzer.structure.parser import (
    FUNCTION_TYPES,
    line,
    params_of,
    parse,
    pattern_names,
    string_value,
    text,
    unwrap,
    walk,
)
from source_analyzer.structure.routes import RouteFile, discover_route, endpoint_for

PG_MODULES = {"pg", "@neondatabase/serverless"}
PG_CLASSES = {"Pool", "Client"}
HEURISTIC_DB_NAMES = {"pool", "client", "db", "pg", "conn", "connection", "database", "sql", "pgpool", "dbpool"}
RESOLVE_EXTS = ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", "/index.ts", "/index.tsx", "/index.js", "/index.mjs")


@dataclass
class Export:
    kind: str  # "pool" | "query_fn" | "sql_helper" | "object"
    param_index: int | None = None
    members: dict[str, "Export"] = field(default_factory=dict)
    sink_line: int | None = None
    construction: str | None = None
    file: str | None = None
    function_name: str | None = None


@dataclass
class Module:
    rel: str
    root: Node
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)  # local -> (specifier, imported name)
    pg_class_names: set[str] = field(default_factory=set)
    pg_namespaces: set[str] = field(default_factory=set)
    pool_vars: set[str] = field(default_factory=set)
    functions: dict[str, Node] = field(default_factory=dict)
    exports: dict[str, Export] = field(default_factory=dict)
    imports_pg: bool = False


@dataclass
class Interaction:
    file: str
    line: int
    call: str
    client: str
    construction: str
    uses_user_input: bool
    endpoint: str | None
    method: str | None
    taint: Taint | None = None
    via_helper: str | None = None
    sink_file: str | None = None
    sink_line: int | None = None
    handler_line: int | None = None
    confidence: str = "high"


class SqliAnalyzer:
    def __init__(self, files: dict[str, bytes], *, tsconfig_paths: dict[str, list[str]] | None = None,
                 tsconfig_base: str = "."):
        self.sources = files
        self.paths = tsconfig_paths or {}
        self.base = tsconfig_base.strip("./") if tsconfig_base not in (".", "./") else ""
        self.modules: dict[str, Module] = {}
        self.parse_errors: list[str] = []
        self.interactions: list[Interaction] = []
        self.routes: list[RouteFile] = []
        self.input_sources: list[dict] = []

    # ------------------------------------------------------------------ index
    def run(self) -> None:
        for rel, src in self.sources.items():
            try:
                tree = parse(rel, src)
            except Exception:  # noqa: BLE001
                self.parse_errors.append(rel)
                continue
            if tree.root_node.has_error and tree.root_node.type == "ERROR":
                self.parse_errors.append(rel)
            self.modules[rel] = self._index(rel, tree.root_node)
        for _ in range(3):  # exports can depend on other modules' exports
            for mod in self.modules.values():
                self._compute_exports(mod)
        for rel, mod in self.modules.items():
            route = discover_route(rel, mod.root)
            if route is not None:
                self.routes.append(route)
                for handler in route.handlers:
                    self._analyse_handler(mod, route, handler)
        self._dedupe()

    def _index(self, rel: str, root: Node) -> Module:
        mod = Module(rel=rel, root=root)
        for node in root.named_children:
            if node.type == "import_statement":
                spec = string_value(node.child_by_field_name("source")) or ""
                clause = next((c for c in node.named_children if c.type == "import_clause"), None)
                for c in (clause.named_children if clause else []):
                    if c.type == "identifier":
                        mod.imports[text(c)] = (spec, "default")
                    elif c.type == "namespace_import":
                        ident = next((x for x in c.named_children if x.type == "identifier"), None)
                        if ident is not None:
                            mod.imports[text(ident)] = (spec, "*")
                    elif c.type == "named_imports":
                        for s in c.named_children:
                            if s.type == "import_specifier":
                                name = text(s.child_by_field_name("name"))
                                alias = text(s.child_by_field_name("alias")) or name
                                mod.imports[alias] = (spec, name)
            target = node.child_by_field_name("declaration") if node.type == "export_statement" else node
            target = target or node
            if target.type in ("lexical_declaration", "variable_declaration"):
                for decl in target.named_children:
                    if decl.type != "variable_declarator":
                        continue
                    name_node = decl.child_by_field_name("name")
                    value = unwrap(decl.child_by_field_name("value"))
                    if value is not None and value.type == "call_expression" and text(value.child_by_field_name("function")) == "require":
                        args = value.child_by_field_name("arguments")
                        spec = string_value(args.named_children[0]) if args and args.named_children else None
                        if spec:
                            if name_node.type == "identifier":
                                mod.imports[text(name_node)] = (spec, "*")
                            elif name_node.type == "object_pattern":
                                for n in pattern_names(name_node):
                                    mod.imports[n] = (spec, n)
                        continue
                    if value is not None and value.type in FUNCTION_TYPES and name_node.type == "identifier":
                        mod.functions[text(name_node)] = value
            if target.type in ("function_declaration",):
                mod.functions[text(target.child_by_field_name("name"))] = target
        for local, (spec, imported) in mod.imports.items():
            if spec in PG_MODULES:
                mod.imports_pg = True
                if imported in PG_CLASSES:
                    mod.pg_class_names.add(local)
                elif imported in ("default", "*"):
                    mod.pg_namespaces.add(local)
        # Module-level pool / client instances.
        for node in walk(root):
            if node.type == "variable_declarator" and self._creates_pg_client(mod, node.child_by_field_name("value")):
                name = node.child_by_field_name("name")
                if name is not None and name.type == "identifier":
                    mod.pool_vars.add(text(name))
            elif node.type == "assignment_expression" and self._creates_pg_client(mod, node.child_by_field_name("right")):
                left = node.child_by_field_name("left")
                if left is not None and left.type in ("identifier", "member_expression"):
                    mod.pool_vars.add(text(left).split(".")[-1] if left.type == "member_expression" else text(left))
        return mod

    def _creates_pg_client(self, mod: Module, value: Node | None) -> bool:
        if value is None:
            return False
        for n in walk(value):
            if n.type == "new_expression":
                ctor = text(n.child_by_field_name("constructor"))
                if ctor in mod.pg_class_names or any(ctor == f"{ns}.{c}" for ns in mod.pg_namespaces for c in PG_CLASSES):
                    return True
            if n.type in FUNCTION_TYPES:
                break  # a factory function is not itself an instance
        return False

    def _resolve(self, from_rel: str, spec: str) -> str | None:
        candidates: list[str] = []
        if spec.startswith("."):
            candidates.append(posixpath.normpath(posixpath.join(posixpath.dirname(from_rel), spec)))
        else:
            for pattern, targets in self.paths.items():
                if pattern.endswith("/*") and spec.startswith(pattern[:-1]):
                    rest = spec[len(pattern) - 1:]
                    for t in targets:
                        candidates.append(posixpath.normpath(posixpath.join(self.base, t.replace("*", rest))))
                elif pattern == spec:
                    candidates += [posixpath.normpath(posixpath.join(self.base, t)) for t in targets]
            if spec.startswith(("@/", "~/")) and not self.paths:
                candidates += [spec[2:], f"src/{spec[2:]}"]
        for cand in candidates:
            cand = cand.lstrip("./") if cand.startswith("./") else cand
            for ext in RESOLVE_EXTS:
                if cand + ext in self.modules:
                    return cand + ext
        return None

    def imported_export(self, mod: Module, local: str) -> Export | None:
        if local not in mod.imports:
            return None
        spec, imported = mod.imports[local]
        target = self._resolve(mod.rel, spec)
        if target is None:
            return None
        exports = self.modules[target].exports
        if imported == "*":
            return Export(kind="object", members=dict(exports))
        return exports.get(imported)

    # ---------------------------------------------------------------- exports
    def _compute_exports(self, mod: Module) -> None:
        local: dict[str, Export] = {}
        for name in mod.pool_vars:
            local[name] = Export(kind="pool", file=mod.rel)
        for name in list(mod.imports):
            exp = self.imported_export(mod, name)
            if exp is not None and exp.kind in ("pool", "query_fn", "sql_helper", "object"):
                local.setdefault(name, exp)
        for name, fn in mod.functions.items():
            summary = self._summarise_function(mod, fn, name)
            if summary is not None:
                local[name] = summary
        exports: dict[str, Export] = {}
        for node in mod.root.named_children:
            if node.type == "export_statement":
                decl = node.child_by_field_name("declaration")
                if decl is not None:
                    names = []
                    if decl.type in ("function_declaration",):
                        names = [text(decl.child_by_field_name("name"))]
                    elif decl.type in ("lexical_declaration", "variable_declaration"):
                        names = [text(d.child_by_field_name("name")) for d in decl.named_children
                                 if d.type == "variable_declarator"]
                    for n in names:
                        if n in local:
                            exports[n] = local[n]
                if any(c.type == "default" for c in node.children):
                    value = unwrap(node.child_by_field_name("value"))
                    exp = self._export_value(mod, value, local)
                    if exp is not None:
                        exports["default"] = exp
                clause = next((c for c in node.named_children if c.type == "export_clause"), None)
                for spec in (clause.named_children if clause else []):
                    n = text(spec.child_by_field_name("name"))
                    alias = text(spec.child_by_field_name("alias")) or n
                    if n in local:
                        exports[alias] = local[n]
            elif node.type == "expression_statement" and node.named_children:
                expr = node.named_children[0]
                if expr.type == "assignment_expression":
                    left = text(expr.child_by_field_name("left"))
                    value = unwrap(expr.child_by_field_name("right"))
                    if left == "module.exports":
                        exp = self._export_value(mod, value, local)
                        if exp is not None:
                            exports["default"] = exp
                            if exp.kind == "object":
                                exports.update(exp.members)
                    elif left.startswith(("module.exports.", "exports.")):
                        exp = self._export_value(mod, value, local)
                        if exp is not None:
                            exports[left.rsplit(".", 1)[-1]] = exp
        mod.exports = exports

    def _export_value(self, mod: Module, value: Node | None, local: dict[str, Export]) -> Export | None:
        if value is None:
            return None
        if value.type == "identifier":
            return local.get(text(value))
        if value.type in FUNCTION_TYPES:
            return self._summarise_function(mod, value, "default")
        if value.type == "object":
            members: dict[str, Export] = {}
            for c in value.named_children:
                if c.type == "shorthand_property_identifier" and text(c) in local:
                    members[text(c)] = local[text(c)]
                elif c.type == "pair":
                    key = text(c.child_by_field_name("key")).strip("'\"")
                    exp = self._export_value(mod, unwrap(c.child_by_field_name("value")), local)
                    if exp is not None:
                        members[key] = exp
                elif c.type == "method_definition":
                    exp = self._summarise_function(mod, c, text(c.child_by_field_name("name")))
                    if exp is not None:
                        members[text(c.child_by_field_name("name"))] = exp
            return Export(kind="object", members=members) if members else None
        if self._creates_pg_client(mod, value):
            return Export(kind="pool", file=mod.rel)
        return None

    def _summarise_function(self, mod: Module, fn: Node, name: str) -> Export | None:
        """Does a parameter of this function flow into SQL text?"""
        engine = TaintEngine(fn, taint_params=True, is_pool_expr=lambda v, f: self._is_pool_value(mod, v, f))
        best: Export | None = None
        for call in self._query_calls(mod, fn, engine):
            node, client, arg_index, via = call
            arg = _arg(node, arg_index)
            construction = self._construction(arg, engine)
            taint = engine.taint_of(arg)
            if taint is None:
                continue
            params = [s.param_index for s in taint.sources if s.kind == "parameter" and s.param_index is not None]
            if not params:
                continue
            if construction == "direct":
                return Export(kind="query_fn", param_index=params[0], file=mod.rel, function_name=name,
                              sink_line=line(node))
            if construction in ("interpolated", "concatenated"):
                best = Export(kind="sql_helper", param_index=params[0], file=mod.rel, function_name=name,
                              sink_line=line(node), construction=construction)
        return best

    # ------------------------------------------------------------------ sinks
    def _is_pool_value(self, mod: Module, value: Node | None, facts) -> bool:
        value = unwrap(value)
        if value is None:
            return False
        if self._creates_pg_client(mod, value):
            return True
        if value.type == "call_expression":  # const client = await pool.connect()
            callee = value.child_by_field_name("function")
            if callee is not None and callee.type == "member_expression" and text(callee.child_by_field_name("property")) == "connect":
                return self._is_pool_ref(mod, callee.child_by_field_name("object"), facts)
        return self._is_pool_ref(mod, value, facts)

    def _is_pool_ref(self, mod: Module, node: Node | None, facts) -> bool:
        node = unwrap(node)
        if node is None:
            return False
        name = text(node)
        if node.type == "identifier":
            if name in mod.pool_vars or (facts is not None and name in facts.local_pool_vars):
                return True
            exp = self.imported_export(mod, name)
            return exp is not None and exp.kind == "pool"
        if node.type == "member_expression":
            obj = unwrap(node.child_by_field_name("object"))
            prop = text(node.child_by_field_name("property"))
            if obj is not None and obj.type == "identifier":
                exp = self.imported_export(mod, text(obj))
                if exp is not None and exp.kind == "object" and exp.members.get(prop, Export("none")).kind == "pool":
                    return True
            return prop in mod.pool_vars
        return False

    def _query_calls(self, mod: Module, fn: Node, engine: TaintEngine):
        """Yield (call node, client description, index of SQL-text argument, helper export|None)."""
        facts = engine.facts
        for node in walk(fn.child_by_field_name("body") or fn):
            if node.type != "call_expression":
                continue
            callee = unwrap(node.child_by_field_name("function"))
            if callee is None:
                continue
            if callee.type == "member_expression":
                prop = text(callee.child_by_field_name("property"))
                obj = callee.child_by_field_name("object")
                obj_name = text(obj)
                if prop == "query":
                    if self._is_pool_ref(mod, obj, facts):
                        yield node, f"{obj_name}.query() (pg)", 0, None
                        continue
                    root_obj = unwrap(obj)
                    if root_obj is not None and root_obj.type == "identifier":
                        exp = self.imported_export(mod, obj_name)
                        if exp is not None and exp.kind == "object" and "query" in exp.members:
                            member = exp.members["query"]
                            if member.kind == "query_fn":
                                yield node, f"{obj_name}.query() (pg wrapper in {member.file})", member.param_index or 0, None
                                continue
                            if member.kind == "pool":
                                yield node, f"{obj_name}.query() (pg)", 0, None
                                continue
                    if (mod.imports_pg or self._project_uses_pg()) and obj_name.split(".")[-1].lower() in HEURISTIC_DB_NAMES:
                        yield node, f"{obj_name}.query() (assumed pg client)", 0, "heuristic"
                        continue
                # db.someHelper(...) where db is an imported namespace/object
                root_obj = unwrap(obj)
                if root_obj is not None and root_obj.type == "identifier":
                    exp = self.imported_export(mod, obj_name)
                    if exp is not None and exp.kind == "object":
                        member = exp.members.get(prop)
                        if member is not None and member.kind in ("query_fn", "sql_helper"):
                            yield node, f"{obj_name}.{prop}() ({member.file})", member.param_index or 0, member
                            continue
            elif callee.type == "identifier":
                name = text(callee)
                exp = self.imported_export(mod, name)
                if exp is None and name in mod.functions and mod.functions[name] is not fn:
                    exp = self._summarise_function(mod, mod.functions[name], name)
                if exp is not None and exp.kind in ("query_fn", "sql_helper"):
                    yield node, f"{name}() ({exp.file})", exp.param_index or 0, exp

    def _project_uses_pg(self) -> bool:
        return any(m.imports_pg for m in self.modules.values())

    def _construction(self, arg: Node | None, engine: TaintEngine, depth: int = 0) -> str:
        arg = unwrap(arg)
        if arg is None:
            return "missing"
        if depth > 6:
            return "dynamic"
        t = arg.type
        if t == "string":
            return "constant"
        if t == "template_string":
            return "interpolated" if any(c.type == "template_substitution" for c in arg.named_children) else "constant"
        if t == "binary_expression" and text(arg.child_by_field_name("operator")) == "+":
            return "concatenated"
        if t == "object":
            for c in arg.named_children:
                if c.type == "pair" and text(c.child_by_field_name("key")).strip("'\"") == "text":
                    return self._construction(c.child_by_field_name("value"), engine, depth + 1)
            return "dynamic"
        if t == "identifier":
            name = text(arg)
            defs = engine.facts.defs.get(name, [])
            if not defs:
                if name in engine.facts.params:
                    return "direct" if engine.taint_of(arg) is not None else "parameter"
                return "dynamic"
            kinds = {self._construction(d, engine, depth + 1) for d in defs}
            for k in ("concatenated", "interpolated", "direct", "dynamic", "parameter"):
                if k in kinds:
                    # x = 'SELECT ...'; x += userValue  -> concatenated
                    return k if not (k == "direct" and len(defs) > 1) else "concatenated"
            return "constant"
        if t in ("member_expression", "subscript_expression", "call_expression"):
            if t == "call_expression" and any(c.type == "template_string" for c in arg.children):
                return "tagged_template"  # sql`...` style libraries parameterise automatically
            return "direct" if engine.taint_of(arg) is not None else "dynamic"
        return "dynamic"

    # --------------------------------------------------------------- handlers
    def _analyse_handler(self, mod: Module, route: RouteFile, handler) -> None:
        fn = handler.function
        request_params = {handler.request_param_index: "request"}
        if handler.context_param_index is not None:
            request_params[handler.context_param_index] = "context"
        engine = TaintEngine(fn, request_params=request_params,
                             is_pool_expr=lambda v, f: self._is_pool_value(mod, v, f))
        for name, taint in engine.facts.env.items():
            for s in taint.sources:
                if s.kind not in ("request", "parameter") and len(self.input_sources) < 2000:
                    self.input_sources.append({"file": mod.rel, "line": s.line, "kind": s.kind, "name": s.name or name})
        for node, client, arg_index, via in self._query_calls(mod, fn, engine):
            arg = _arg(node, arg_index)
            taint = engine.taint_of(arg)
            if isinstance(via, Export) and via.kind == "sql_helper":
                # The helper interpolates its parameter into SQL: did the handler pass user input?
                construction = via.construction or "interpolated"
                interaction = Interaction(
                    file=mod.rel, line=line(node), call=text(node)[:200], client=client, construction=construction,
                    uses_user_input=taint is not None, endpoint=route.endpoint, method=handler.method, taint=taint,
                    via_helper=via.function_name, sink_file=via.file, sink_line=via.sink_line, handler_line=handler.line,
                    confidence="medium",
                )
            else:
                construction = self._construction(arg, engine)
                if construction == "constant" and _has_values_arg(node, arg_index):
                    construction = "parameterised"
                interaction = Interaction(
                    file=mod.rel, line=line(node), call=text(node)[:200], client=client, construction=construction,
                    uses_user_input=taint is not None, endpoint=route.endpoint, method=handler.method, taint=taint,
                    handler_line=handler.line, confidence="medium" if via == "heuristic" else "high",
                )
            self.interactions.append(interaction)

    def _dedupe(self) -> None:
        seen = {}
        for i in self.interactions:
            key = (i.file, i.line, i.method)
            if key not in seen:
                seen[key] = i
        self.interactions = list(seen.values())

    # ---------------------------------------------------------------- helpers
    def helper_sinks_without_tainted_callers(self) -> list[Export]:
        """SQL-building helpers never reached by traced user input (inconclusive)."""
        reached = {(i.sink_file, i.sink_line) for i in self.interactions if i.via_helper and i.uses_user_input}
        out = []
        for mod in self.modules.values():
            if endpoint_for(mod.rel) is not None:
                continue  # route handlers are analysed directly with request taint
            for exp in list(mod.exports.values()) + [m for e in mod.exports.values() for m in e.members.values()]:
                if exp.kind == "sql_helper" and exp.file == mod.rel and (exp.file, exp.sink_line) not in reached:
                    out.append(exp)
        unique = {(e.file, e.sink_line): e for e in out}
        return list(unique.values())


def _arg(call: Node, index: int) -> Node | None:
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    named = [a for a in args.named_children if a.type != "comment"]
    return named[index] if index < len(named) else None


def _has_values_arg(call: Node, text_index: int) -> bool:
    values = _arg(call, text_index + 1)
    if values is not None:
        return True
    first = unwrap(_arg(call, text_index))
    return first is not None and first.type == "object" and any(
        c.type == "pair" and text(c.child_by_field_name("key")).strip("'\"") == "values" for c in first.named_children
    )


def fingerprint(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:32]


def params_count(fn: Node) -> int:
    return len(params_of(fn))
