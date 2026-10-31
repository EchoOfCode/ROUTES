"""Prompt command parsing. Input is matched against a fixed command table and
never passed to a shell; anything else is rejected with a suggestion."""

from __future__ import annotations

import difflib
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Spec:
    name: str
    usage: str
    summary: str
    options: tuple[str, ...] = ()
    flags: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()


COMMANDS: tuple[Spec, ...] = (
    Spec("scan", "/scan <website-url> [--source <repo|folder|zip>] [--project <name>]",
         "Discover a website's pages, endpoints and technologies", ("--source", "--ref", "--project"), ("--private",)),
    Spec("analyze", "/analyze <github-url|folder|zip> [--url <website>] [--ref <branch>] [--private]",
         "Analyse source code statically (never executed)", ("--url", "--ref", "--project"), ("--private",),
         ("analyse",)),
    Spec("findings", "/findings [id] [--severity high]", "Findings of the latest assessment", ("--severity",)),
    Spec("history", "/history [project]", "Previous assessments (5 kept per project)"),
    Spec("report", "/report [markdown|html|json]", "Write a report of the latest assessment"),
    Spec("projects", "/projects", "List projects"),
    Spec("project", "/project add <source> --name <name> [--url <site>] | use <name> | show [name]",
         "Register, select or inspect a project", ("--name", "--url", "--ref"), ("--private",)),
    Spec("doctor", "/doctor", "Check Docker, the engine, SQLite and the analysis tools"),
    Spec("engine", "/engine up | status | stop", "Start, check or stop the local sandbox engine"),
    Spec("home", "/home", "Back to the start screen"),
    Spec("clear", "/clear", "Clear the screen"),
    Spec("help", "/help", "Show commands and keys", aliases=("?",)),
    Spec("exit", "/exit", "Leave ROUTES", aliases=("quit", "q")),
)
BY_NAME = {s.name: s for s in COMMANDS}
ALIASES = {a: s.name for s in COMMANDS for a in s.aliases}


class CommandError(ValueError):
    pass


@dataclass
class Command:
    name: str
    args: list[str] = field(default_factory=list)
    options: dict[str, str] = field(default_factory=dict)
    flags: set[str] = field(default_factory=set)


def tokenize(line: str) -> list[str]:
    """Split on whitespace; double or single quotes group words. Backslashes are
    kept literally so Windows paths work."""
    tokens, buf, quote, has = [], [], None, False
    for ch in line:
        if quote:
            if ch == quote:
                quote = None
            else:
                buf.append(ch)
        elif ch in "\"'":
            quote, has = ch, True
        elif ch.isspace():
            if buf or has:
                tokens.append("".join(buf))
            buf, has = [], False
        else:
            buf.append(ch)
    if quote:
        raise CommandError("Unclosed quote.")
    if buf or has:
        tokens.append("".join(buf))
    return tokens


def parse(line: str) -> Command:
    tokens = tokenize(line.strip())
    if not tokens:
        raise CommandError("")
    head = tokens[0].lstrip("/").lower()
    name = ALIASES.get(head, head)
    spec = BY_NAME.get(name)
    if spec is None:
        close = difflib.get_close_matches(name, [s.name for s in COMMANDS], n=1)
        hint = f" Did you mean /{close[0]}?" if close else " Type /help for the list."
        raise CommandError(f"Unknown command '{tokens[0]}'.{hint}")
    cmd = Command(name)
    rest = tokens[1:]
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok.startswith("--"):
            key = tok.split("=", 1)[0]
            if key in spec.flags:
                cmd.flags.add(key)
            elif key in spec.options:
                if "=" in tok:
                    cmd.options[key] = tok.split("=", 1)[1]
                elif i + 1 < len(rest):
                    i += 1
                    cmd.options[key] = rest[i]
                else:
                    raise CommandError(f"{key} needs a value.")
            elif key in ("--token", "--pat"):
                raise CommandError("Tokens are never accepted on the command line. Use --private and ROUTES will "
                                   "ask for it in a hidden field.")
            else:
                raise CommandError(f"Unknown option {key} for /{name}. Usage: {spec.usage}")
        else:
            cmd.args.append(tok)
        i += 1
    return cmd


# ------------------------------------------------------------- completion
def complete(value: str, *, projects: list[str] | None = None) -> str | None:
    """Return the completed prompt text for an inline suggestion, or None."""
    if not value or value.endswith("  "):
        return None
    try:
        tokens = tokenize(value)
    except CommandError:
        return None
    if not tokens:
        return None
    trailing_space = value[-1].isspace()
    if len(tokens) == 1 and not trailing_space:
        head = tokens[0]
        slash = head.startswith("/")
        word = head.lstrip("/").lower()
        for spec in COMMANDS:
            if spec.name.startswith(word) and spec.name != word:
                return ("/" if slash else "") + spec.name + value[len(head):]
        return None
    name = ALIASES.get(tokens[0].lstrip("/").lower(), tokens[0].lstrip("/").lower())
    spec = BY_NAME.get(name)
    if spec is None:
        return None
    current = "" if trailing_space else tokens[-1]
    base = value[: len(value) - len(current)]
    if current.startswith("--"):
        for opt in spec.options + spec.flags:
            if opt.startswith(current) and opt != current:
                return base + opt
        return None
    position = len(tokens) if trailing_space else len(tokens) - 1   # index of the word being completed
    previous = tokens[position - 1] if position >= 1 else ""

    def first(options) -> str | None:
        for option in options:
            if option.startswith(current) and option != current:
                return base + option
        return None

    choices = {"project": ("add", "use", "show"), "engine": ("up", "status", "stop"),
               "report": ("markdown", "html", "json")}
    if position == 1 and name in choices:
        return first(choices[name])
    if previous == "--severity":
        return first(("critical", "high", "medium", "low", "info"))
    if projects and current and (previous == "--project" or (name == "history" and position == 1)
                                 or (name == "project" and position == 2 and tokens[1] in ("use", "show"))):
        return first(projects)
    wants_path = (previous == "--source" or (name == "analyze" and position == 1)
                  or (name == "project" and position == 2 and tokens[1] == "add"))
    if wants_path and current and not current.startswith(("http", "--", "github.com")):
        path = _complete_path(current)
        if path:
            return base + path
    return None


def _complete_path(prefix: str) -> str | None:
    expanded = os.path.expanduser(prefix)
    directory, partial = os.path.split(expanded)
    try:
        entries = sorted(os.listdir(directory or "."))
    except OSError:
        return None
    for entry in entries:
        if entry.startswith(partial) and entry != partial and not entry.startswith("."):
            full = os.path.join(directory, entry) if directory else entry
            if prefix.startswith("~"):
                full = "~" + full[len(os.path.expanduser("~")):]
            if Path(os.path.expanduser(full)).is_dir():
                full += os.sep
            return full
    return None
