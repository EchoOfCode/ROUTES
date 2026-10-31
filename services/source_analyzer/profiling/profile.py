"""Repository profiling: languages, framework, dependencies, configuration.

Reads files as data only. Nothing from the repository is executed, and
secret *values* are never read out (environment variables are reported by
name only).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from source_analyzer.acquisition.archive import EXCLUDED_DIRS

LANGUAGE_BY_EXT = {
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".py": "Python", ".rb": "Ruby", ".php": "PHP", ".go": "Go", ".java": "Java", ".kt": "Kotlin", ".cs": "C#",
    ".rs": "Rust", ".swift": "Swift", ".scala": "Scala", ".ex": "Elixir", ".exs": "Elixir", ".vue": "Vue",
    ".svelte": "Svelte", ".dart": "Dart", ".c": "C", ".cpp": "C++", ".h": "C/C++ header",
}
JS_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
LOCKFILES = {"package-lock.json": "npm", "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm", "bun.lockb": "bun",
             "bun.lock": "bun", "npm-shrinkwrap.json": "npm"}
DB_LIBRARIES = {
    "pg": "PostgreSQL (pg)", "postgres": "PostgreSQL (postgres.js)", "@neondatabase/serverless": "PostgreSQL (Neon)",
    "@vercel/postgres": "PostgreSQL (Vercel Postgres)", "pg-promise": "PostgreSQL (pg-promise)",
    "mysql": "MySQL (mysql)", "mysql2": "MySQL (mysql2)", "mongodb": "MongoDB", "mongoose": "MongoDB (Mongoose)",
    "sqlite3": "SQLite", "better-sqlite3": "SQLite (better-sqlite3)", "@prisma/client": "Prisma ORM",
    "prisma": "Prisma ORM", "drizzle-orm": "Drizzle ORM", "knex": "Knex query builder", "sequelize": "Sequelize ORM",
    "typeorm": "TypeORM", "kysely": "Kysely", "redis": "Redis", "ioredis": "Redis (ioredis)",
    "@supabase/supabase-js": "Supabase", "firebase": "Firebase", "@planetscale/database": "MySQL (PlanetScale)",
    "mssql": "Microsoft SQL Server", "oracledb": "Oracle Database",
}
ENV_REF = re.compile(r"process\.env(?:\.([A-Z_][A-Z0-9_]{1,80})|\[\s*['\"]([A-Z_][A-Z0-9_]{1,80})['\"]\s*\])")
IMPORT_META_ENV = re.compile(r"import\.meta\.env\.([A-Z_][A-Z0-9_]{1,80})")
ENV_FILE_KEY = re.compile(r"^\s*(?:export\s+)?([A-Z_][A-Z0-9_]{1,80})\s*=", re.M)
MAX_SOURCE_FILE = 1024 * 1024


@dataclass
class RepoFile:
    rel: str
    path: Path
    size: int

    @property
    def ext(self) -> str:
        return Path(self.rel).suffix.lower()

    def read(self) -> str:
        return self.path.read_text("utf-8", errors="replace")


@dataclass
class Profile:
    root: Path
    files: list[RepoFile] = field(default_factory=list)
    languages: dict[str, int] = field(default_factory=dict)
    package_json: dict | None = None
    dependencies: list[dict] = field(default_factory=list)
    framework: str = "Unknown"
    framework_version: str | None = None
    runtime: str = "Unknown"
    package_manager: str | None = None
    lockfiles: list[str] = field(default_factory=list)
    typescript: bool = False
    router: str | None = None
    database_libraries: list[str] = field(default_factory=list)
    env_var_names: set[str] = field(default_factory=set)
    config_refs: list[dict] = field(default_factory=list)
    top_level_dirs: list[str] = field(default_factory=list)
    tsconfig_paths: dict[str, list[str]] = field(default_factory=dict)
    tsconfig_base: str = "."
    workspace_roots: list[str] = field(default_factory=list)
    support_status: str = "unsupported"
    support_reason: str = ""
    warnings: list[str] = field(default_factory=list)

    def dep_names(self) -> set[str]:
        return {d["name"] for d in self.dependencies}

    def js_files(self) -> list[RepoFile]:
        return [f for f in self.files if f.ext in JS_EXTS and f.size <= MAX_SOURCE_FILE]

    def as_dict(self) -> dict:
        return {
            "languages": self.languages, "framework": self.framework, "framework_version": self.framework_version,
            "runtime": self.runtime, "package_manager": self.package_manager, "lockfiles": self.lockfiles,
            "typescript": self.typescript, "router": self.router, "dependencies": self.dependencies[:2000],
            "database_libraries": self.database_libraries, "total_files": len(self.files),
            "analysed_files": len(self.js_files()), "top_level_dirs": self.top_level_dirs[:100],
        }


def _load_json(path: Path) -> dict | None:
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            return None
        data = json.loads(path.read_text("utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _strip_jsonc(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(^|[^:\"'])//[^\n]*", r"\1", text)
    return re.sub(r",(\s*[}\]])", r"\1", text)


def walk(root: Path) -> list[RepoFile]:
    out: list[RepoFile] = []
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for p in entries:
            if p.is_symlink():
                continue
            if p.is_dir():
                if p.name not in EXCLUDED_DIRS:
                    stack.append(p)
            elif p.is_file():
                out.append(RepoFile(rel=p.relative_to(root).as_posix(), path=p, size=p.stat().st_size))
    return out


def build_profile(root: Path) -> Profile:
    prof = Profile(root=root)
    prof.files = walk(root)
    prof.top_level_dirs = sorted({f.rel.split("/", 1)[0] for f in prof.files if "/" in f.rel})
    for f in prof.files:
        lang = LANGUAGE_BY_EXT.get(f.ext)
        if lang:
            prof.languages[lang] = prof.languages.get(lang, 0) + 1
        name = f.rel.rsplit("/", 1)[-1]
        if name in LOCKFILES and f.rel.count("/") <= 1:
            prof.lockfiles.append(f.rel)
            prof.package_manager = prof.package_manager or LOCKFILES[name]

    # package.json: root first, else a single app in a sub-directory (monorepo-lite).
    pkg_files = sorted((f for f in prof.files if f.rel.endswith("package.json") and f.rel.count("/") <= 2),
                       key=lambda f: f.rel.count("/"))
    for pf in pkg_files:
        data = _load_json(pf.path)
        if data is None:
            prof.warnings.append(f"{pf.rel} could not be parsed.")
            continue
        if prof.package_json is None:
            prof.package_json = data
        for section, dev in (("dependencies", False), ("devDependencies", True), ("peerDependencies", False)):
            deps = data.get(section) if isinstance(data.get(section), dict) else {}
            for name, version in deps.items():
                if isinstance(name, str) and name not in prof.dep_names() and len(prof.dependencies) < 2000:
                    prof.dependencies.append({"name": name[:200], "version": str(version)[:100], "dev": dev})
        if "workspaces" in data:
            prof.warnings.append("Workspace (monorepo) layout detected; only common app locations are analysed.")
        if pf.rel != "package.json":
            prof.workspace_roots.append(pf.rel.rsplit("/", 1)[0])

    deps = prof.dep_names()
    dep_versions = {d["name"]: d["version"] for d in prof.dependencies}
    prof.typescript = "typescript" in deps or prof.languages.get("TypeScript", 0) > 0
    next_configs = [f.rel for f in prof.files if re.search(r"(^|/)next\.config\.(js|mjs|cjs|ts|mts)$", f.rel)]
    if "next" in deps or next_configs:
        prof.framework = "Next.js"
        prof.framework_version = dep_versions.get("next")
        prof.runtime = "Node.js"
        for cfg in next_configs:
            prof.config_refs.append({"file": cfg, "line": None, "kind": "framework_config", "name": "Next.js configuration"})
    elif "nuxt" in deps:
        prof.framework, prof.runtime = "Nuxt", "Node.js"
    elif "@remix-run/node" in deps or "@remix-run/react" in deps:
        prof.framework, prof.runtime = "Remix", "Node.js"
    elif "@sveltejs/kit" in deps:
        prof.framework, prof.runtime = "SvelteKit", "Node.js"
    elif "express" in deps:
        prof.framework, prof.runtime = "Express", "Node.js"
    elif "fastify" in deps:
        prof.framework, prof.runtime = "Fastify", "Node.js"
    elif any(f.rel in ("manage.py",) for f in prof.files) or any(f.rel.endswith("requirements.txt") for f in prof.files):
        prof.framework = "Django" if any(f.rel == "manage.py" for f in prof.files) else "Unknown"
        prof.runtime = "Python"
    elif prof.package_json is not None:
        prof.runtime = "Node.js"
    if "bun" in (prof.package_manager or "") and prof.runtime == "Node.js":
        prof.warnings.append("Bun lockfile present; the project may run on Bun instead of Node.js.")

    prof.database_libraries = sorted({DB_LIBRARIES[d] for d in deps if d in DB_LIBRARIES})

    has_app_router = any(re.search(r"(^|/)(src/)?app/(.+/)?(page|route|layout)\.(js|jsx|ts|tsx)$", f.rel) for f in prof.files)
    has_pages_router = any(re.search(r"(^|/)(src/)?pages/.+\.(js|jsx|ts|tsx)$", f.rel) for f in prof.files)
    if prof.framework == "Next.js":
        prof.router = "app" if has_app_router and not has_pages_router else "pages" if has_pages_router and not has_app_router \
            else "app+pages" if has_app_router else None

    _tsconfig(prof)
    _env_names(prof)
    _support(prof)
    return prof


def _tsconfig(prof: Profile) -> None:
    for name in ("tsconfig.json", "jsconfig.json"):
        f = next((x for x in prof.files if x.rel == name), None)
        if f is None:
            continue
        prof.config_refs.append({"file": f.rel, "line": None, "kind": "typescript_config" if name.startswith("ts") else "javascript_config",
                                 "name": name})
        try:
            data = json.loads(_strip_jsonc(f.read()))
        except ValueError:
            prof.warnings.append(f"{name} could not be parsed; path aliases are not resolved.")
            return
        opts = data.get("compilerOptions") if isinstance(data, dict) else None
        if isinstance(opts, dict):
            prof.tsconfig_base = str(opts.get("baseUrl") or ".")
            paths = opts.get("paths")
            if isinstance(paths, dict):
                prof.tsconfig_paths = {k: [str(v) for v in vs][:5] for k, vs in paths.items() if isinstance(vs, list)}
        return


def _env_names(prof: Profile) -> None:
    for f in prof.files:
        name = f.rel.rsplit("/", 1)[-1]
        if name.startswith(".env") and f.size < 256 * 1024:
            keys = ENV_FILE_KEY.findall(f.read())
            for key in keys[:300]:
                prof.env_var_names.add(key)
            kind = "env_example" if name.endswith((".example", ".sample", ".template")) else "env_file"
            prof.config_refs.append({"file": f.rel, "line": None, "kind": kind, "name": f"{len(keys)} variable name(s)"})
            if kind == "env_file":
                prof.warnings.append(f"{f.rel} is committed to the repository; values were not read or stored.")
    for f in prof.js_files():
        text = f.read()
        for m in ENV_REF.finditer(text):
            prof.env_var_names.add(m.group(1) or m.group(2))
        for m in IMPORT_META_ENV.finditer(text):
            prof.env_var_names.add(m.group(1))
        if len(prof.env_var_names) > 500:
            break
    db_like = re.compile(r"(DATABASE|POSTGRES|PG|DB|MYSQL|MONGO|REDIS|SUPABASE)", re.I)
    for name in sorted(prof.env_var_names):
        if db_like.search(name):
            prof.config_refs.append({"file": "", "line": None, "kind": "database_env_var", "name": name})


def _support(prof: Profile) -> None:
    js_count = prof.languages.get("JavaScript", 0) + prof.languages.get("TypeScript", 0)
    deps = prof.dep_names()
    if js_count == 0:
        langs = ", ".join(sorted(prof.languages, key=lambda k: -prof.languages[k])[:3]) or "no recognised source files"
        prof.support_status = "unsupported"
        prof.support_reason = (f"Detailed analysis supports JavaScript/TypeScript Next.js projects using PostgreSQL (pg). "
                               f"This repository contains {langs}.")
    elif prof.framework != "Next.js":
        prof.support_status = "unsupported"
        prof.support_reason = (f"Detected {prof.framework if prof.framework != 'Unknown' else 'a JavaScript project without Next.js'}. "
                               "Detailed route and SQL injection analysis currently supports Next.js only; "
                               "general static rules still ran.")
    elif "pg" not in deps:
        prof.support_status = "partial"
        libs = ", ".join(prof.database_libraries) or "no recognised database library"
        prof.support_reason = (f"Next.js routes were analysed. SQL injection tracing supports the pg client only; "
                               f"this project uses {libs}.")
    else:
        prof.support_status = "supported"
        prof.support_reason = "Next.js with the pg PostgreSQL client: routes, database calls and data flow were analysed."
