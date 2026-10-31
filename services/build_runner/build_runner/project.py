"""Repository profiling for build-runs.

ROUTES never uses a Dockerfile, Compose file or CI configuration supplied by
the repository. It reads ``package.json`` and the lockfile and derives a
controlled build plan for the supported stack (Node.js + Next.js, npm
lockfile, optional PostgreSQL via ``pg``). Anything else is reported as
unsupported rather than guessed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from routes_shared.sourcefiles import BUILD_EXCLUDED_DIRS

NEXT_BIN = "node_modules/next/dist/bin/next"
DEV_MARKERS = re.compile(r"\bnext\s+dev\b|\bnodemon\b|--watch\b|\bvite\b(?!\s+preview)")
PORT_FLAG = re.compile(r"(?:^|\s)(?:-p|--port)(?:\s+|=)\S+")
ENV_REF = re.compile(r"process\.env(?:\.([A-Z_][A-Z0-9_]{0,99})|\[\s*['\"]([A-Z_][A-Z0-9_]{0,99})['\"]\s*\])")
ENV_FILE_KEY = re.compile(r"^\s*(?:export\s+)?([A-Z_][A-Z0-9_]{0,99})\s*=", re.M)
# psql meta-command reading an environment variable: \getenv <psql-var> <ENV_NAME>
SQL_GETENV = re.compile(r"^\s*\\getenv\s+\w+\s+([A-Za-z_][A-Za-z0-9_]{0,99})", re.M)
DB_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
ENV_DB_NAME = re.compile(r"^\s*(?:export\s+)?(?:POSTGRES_DB|PGDATABASE|DB_NAME|DATABASE_NAME)\s*=\s*[\"']?([A-Za-z_][A-Za-z0-9_]{0,62})",
                         re.M)
ENV_DB_URL = re.compile(r"^\s*(?:export\s+)?(?:DATABASE_URL|POSTGRES_URL)\s*=\s*[\"']?postgres(?:ql)?://[^/\s\"']*/"
                        r"([A-Za-z_][A-Za-z0-9_]{0,62})", re.M)
SQL_DB_REF = re.compile(r"\bON\s+DATABASE\s+\"?([A-Za-z_][A-Za-z0-9_]{0,62})", re.I)
SQL_DB_CREATE = re.compile(r"\bCREATE\s+DATABASE\s+\"?([A-Za-z_][A-Za-z0-9_]{0,62})", re.I)
COMPOSE_DB = re.compile(r"POSTGRES_DB\s*[:=]\s*[\"']?([A-Za-z_][A-Za-z0-9_]{0,62})")
SOURCE_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
OTHER_LOCKFILES = {"yarn.lock": "Yarn", "pnpm-lock.yaml": "pnpm", "bun.lockb": "Bun", "bun.lock": "Bun"}
# Configuration ROUTES deliberately does not use.
IGNORED_CONFIG = ("Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
                  ".npmrc", ".yarnrc", ".yarnrc.yml", "Procfile", ".devcontainer")
DATABASE_PACKAGES = {"pg", "postgres", "@vercel/postgres", "@neondatabase/serverless", "@prisma/client", "drizzle-orm",
                     "knex", "sequelize", "typeorm", "kysely", "slonik"}
SUPPORTED_DB_CLIENTS = {"pg"}
DB_ENV = {"DATABASE_URL", "POSTGRES_URL", "POSTGRES_PRISMA_URL", "POSTGRES_URL_NON_POOLING", "PGHOST", "PGPORT",
          "PGUSER", "PGPASSWORD", "PGDATABASE", "DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME"}
SCHEMA_FILES = ("schema.sql", "db/schema.sql", "database/schema.sql", "sql/schema.sql", "src/db/schema.sql",
                "db/init.sql", "init.sql")
MIGRATION_GLOBS = ("migrations/*.sql", "db/migrations/*.sql", "database/migrations/*.sql", "sql/migrations/*.sql",
                   "supabase/migrations/*.sql", "drizzle/*.sql", "prisma/migrations/*/migration.sql")
SEED_FILES = ("seed.sql", "db/seed.sql", "database/seed.sql", "sql/seed.sql", "db/seeds.sql")
LIFECYCLE = ("preinstall", "install", "postinstall")
MAX_SCAN_FILES = 5000


class Unsupported(Exception):
    """The project cannot be built and run reliably by ROUTES (yet)."""


@dataclass
class BuildPlan:
    root: Path
    name: str
    next_version: str
    lockfile: str
    install: list[str]
    build: list[str]
    build_label: str
    start: list[str]
    start_label: str
    notes: list[str] = field(default_factory=list)
    env_names: list[str] = field(default_factory=list)
    db_packages: list[str] = field(default_factory=list)
    schema_files: list[str] = field(default_factory=list)
    seed_files: list[str] = field(default_factory=list)
    db_name: str = "app"
    db_name_source: str = "default"
    ignored: list[str] = field(default_factory=list)
    root_scripts: list[str] = field(default_factory=list)

    @property
    def needs_database(self) -> bool:
        return bool(self.db_packages)

    def describe(self) -> dict:
        return {"name": self.name, "framework": "Next.js", "next_version": self.next_version, "package_manager": "npm",
                "lockfile": self.lockfile, "install_command": " ".join(self.install), "build_command": self.build_label,
                "start_command": self.start_label, "env_var_names": self.env_names[:200],
                "database_packages": self.db_packages, "database_name": self.db_name,
                "database_name_source": self.db_name_source, "ignored_configuration": self.ignored,
                "root_lifecycle_scripts": self.root_scripts, "notes": self.notes}


def _load_package(root: Path) -> dict:
    path = root / "package.json"
    if not path.is_file():
        raise Unsupported("No package.json at the repository root. Monorepos and non-Node projects are not supported yet.")
    try:
        data = json.loads(path.read_text("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise Unsupported("package.json is not valid JSON.") from exc
    if not isinstance(data, dict):
        raise Unsupported("package.json is not a JSON object.")
    return data


def _deps(pkg: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        section = pkg.get(key)
        if isinstance(section, dict):
            out.update({str(k): str(v) for k, v in section.items()})
    return out


def _source_files(root: Path):
    count = 0
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in BUILD_EXCLUDED_DIRS for part in rel.parts):
            continue
        if path.is_file() and not path.is_symlink() and path.suffix in SOURCE_SUFFIXES:
            count += 1
            if count > MAX_SCAN_FILES:
                return
            yield path


def env_names(root: Path) -> list[str]:
    names: set[str] = set()
    for path in _source_files(root):
        try:
            text = path.read_text("utf-8", "replace")[:500_000]
        except OSError:
            continue
        for a, b in ENV_REF.findall(text):
            names.add(a or b)
    for example in (".env.example", ".env.sample", ".env.template", ".env.local.example"):
        p = root / example
        if p.is_file() and not p.is_symlink():
            names.update(ENV_FILE_KEY.findall(p.read_text("utf-8", "replace")[:200_000]))
    return sorted(names)


def sql_env_names(root: Path, files: list[str]) -> list[str]:
    """Environment variables SQL files read with psql's \\getenv (they get placeholders)."""
    names: set[str] = set()
    for f in files:
        try:
            names.update(SQL_GETENV.findall((root / f).read_text("utf-8", "replace")[:2_000_000]))
        except OSError:
            continue
    return sorted(names)


def database_name(root: Path, files: list[str]) -> tuple[str, str]:
    """The database name the project expects. Files are only *read* for this hint;
    nothing in them is executed. Falls back to "app"."""
    def text(rel: str) -> str:
        p = root / rel
        try:
            return p.read_text("utf-8", "replace")[:500_000] if p.is_file() and not p.is_symlink() else ""
        except OSError:
            return ""

    created: set[str] = set()
    referenced: list[str] = []
    for f in files:
        sql = text(f)
        created.update(n.lower() for n in SQL_DB_CREATE.findall(sql))
        referenced += SQL_DB_REF.findall(sql)
    for name in referenced:
        if name.lower() not in created and name.lower() not in ("postgres", "template0", "template1"):
            return name, "referenced by the SQL schema"
    for example in (".env.example", ".env.sample", ".env.template", ".env.local.example"):
        body = text(example)
        for rx in (ENV_DB_NAME, ENV_DB_URL):
            m = rx.search(body)
            if m and m.group(1).lower() not in created | {"postgres", "template0", "template1"}:
                return m.group(1), example
    for compose in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        m = COMPOSE_DB.search(text(compose))
        if m and m.group(1).lower() not in created | {"postgres", "template0", "template1"}:
            return m.group(1), f"{compose} (read as a hint only)"
    return "app", "default"


def schema_files(root: Path) -> tuple[list[str], list[str]]:
    schema = [f for f in SCHEMA_FILES if (root / f).is_file() and not (root / f).is_symlink()]
    for pattern in MIGRATION_GLOBS:
        schema += sorted(p.relative_to(root).as_posix() for p in root.glob(pattern) if p.is_file() and not p.is_symlink())
    seeds = [f for f in SEED_FILES if (root / f).is_file() and not (root / f).is_symlink()]
    # Further seed files next to the schema (e.g. database/demo_seed.sql), after the standard ones.
    for pattern in ("db/*seed*.sql", "database/*seed*.sql", "sql/*seed*.sql"):
        seeds += sorted(p.relative_to(root).as_posix() for p in root.glob(pattern) if p.is_file() and not p.is_symlink())
    schema = list(dict.fromkeys(schema))
    return schema, [s for s in dict.fromkeys(seeds) if s not in schema]


def inspect(root: Path) -> BuildPlan:
    pkg = _load_package(root)
    for lock, tool in OTHER_LOCKFILES.items():
        if (root / lock).exists() and not (root / "package-lock.json").exists():
            raise Unsupported(f"The project uses {tool} ({lock}). ROUTES currently builds projects with an npm lockfile "
                              "(package-lock.json) only.")
    lockfile = next((n for n in ("package-lock.json", "npm-shrinkwrap.json") if (root / n).is_file()), None)
    if lockfile is None:
        raise Unsupported("No package-lock.json was found, so dependencies cannot be reconstructed reliably.")
    deps = _deps(pkg)
    if "next" not in deps:
        raise Unsupported("Only Next.js applications are supported for build-and-run verification at the moment.")
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    scripts = {str(k): str(v) for k, v in scripts.items()}
    notes: list[str] = []

    if "build" in scripts:
        build, build_label = ["npm", "run", "build"], f"npm run build ({scripts['build'][:200]})"
    else:
        build, build_label = ["node", NEXT_BIN, "build"], "next build (no build script defined)"
        notes.append("package.json has no build script; ROUTES runs `next build` directly.")

    start_script = scripts.get("start", "")
    if start_script and not DEV_MARKERS.search(start_script) and not PORT_FLAG.search(start_script):
        start, start_label = ["npm", "run", "start"], f"npm run start ({start_script[:200]})"
    else:
        start, start_label = ["node", NEXT_BIN, "start"], "next start"
        if not start_script:
            notes.append("package.json has no start script; ROUTES runs `next start`.")
        elif DEV_MARKERS.search(start_script):
            notes.append("The start script runs a development server; ROUTES uses the production `next start` instead.")
        else:
            notes.append("The start script sets its own port; ROUTES runs `next start` on the sandbox port instead.")

    db_packages = sorted(DATABASE_PACKAGES & set(deps))
    unsupported_db = [p for p in db_packages if p not in SUPPORTED_DB_CLIENTS]
    schema, seeds = schema_files(root)
    if db_packages and not schema:
        raise Unsupported("The application uses a database but no SQL schema or migration files were found "
                          f"(looked for {', '.join(SCHEMA_FILES[:4])}, migrations/*.sql, ...). The database cannot be "
                          "reconstructed reliably.")
    if unsupported_db:
        notes.append(f"Database libraries other than pg ({', '.join(unsupported_db)}) are not specifically supported; "
                     "only the SQL files found are applied.")

    db_name, db_source = database_name(root, schema + seeds) if db_packages else ("app", "default")
    ignored = [name for name in IGNORED_CONFIG if (root / name).exists()]
    if ignored:
        notes.append("Repository container/registry configuration is never used: " + ", ".join(ignored) + ".")
    return BuildPlan(
        root=root, name=str(pkg.get("name") or "application")[:100], next_version=deps.get("next", "")[:40],
        lockfile=lockfile, install=["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        build=build, build_label=build_label, start=start, start_label=start_label, notes=notes,
        env_names=sorted(set(env_names(root)) | set(sql_env_names(root, schema + seeds))), db_packages=db_packages,
        schema_files=schema, seed_files=seeds, ignored=ignored,
        db_name=db_name, db_name_source=db_source,
        root_scripts=[s for s in LIFECYCLE + ("prepare",) if s in scripts],
    )


def packages_with_install_scripts(root: Path, limit: int = 500) -> list[str]:
    """Installed dependencies that declare install-time scripts (which npm ci was told not to run)."""
    found: set[str] = set()

    def visit(pkg_dir: Path, name: str, depth: int) -> None:
        if len(found) >= limit or pkg_dir.is_symlink() or not pkg_dir.is_dir():
            return
        try:
            data = json.loads((pkg_dir / "package.json").read_text("utf-8"))
        except (ValueError, OSError, UnicodeDecodeError):
            data = {}
        scripts = data.get("scripts") if isinstance(data, dict) and isinstance(data.get("scripts"), dict) else {}
        if any(s in scripts for s in LIFECYCLE) or (pkg_dir / "binding.gyp").is_file():
            found.add(name)
        if depth < 8:
            walk(pkg_dir / "node_modules", depth + 1)

    def walk(nm: Path, depth: int) -> None:
        if not nm.is_dir() or nm.is_symlink():
            return
        for entry in sorted(nm.iterdir()):
            if entry.name.startswith("."):
                continue
            if entry.name.startswith("@") and entry.is_dir():
                for sub in sorted(entry.iterdir()):
                    visit(sub, f"{entry.name}/{sub.name}", depth)
            else:
                visit(entry, entry.name, depth)

    walk(root / "node_modules", 0)
    return sorted(found)


def count_packages(root: Path) -> int:
    nm = root / "node_modules"
    if not nm.is_dir():
        return 0
    total = 0
    for entry in nm.iterdir():
        if entry.name.startswith("@") and entry.is_dir():
            total += sum(1 for e in entry.iterdir() if (e / "package.json").is_file())
        elif (entry / "package.json").is_file():
            total += 1
    return total
