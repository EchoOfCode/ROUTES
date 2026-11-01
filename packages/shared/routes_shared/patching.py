"""Unified diffs for remediation: derive one from a replaced code region, and
apply one strictly to a temporary source tree.

`apply_unified_diff` is used where git is not available (the analyzer
sandbox rescanning a patched tree). It is deliberately strict: every context
and removed line must match exactly at the stated position; there is no fuzz
and no offset search, so a patch never lands somewhere it was not meant for.
Paths are validated by `routes_shared.buildrun.validate_patch` first.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path

from routes_shared.buildrun import PatchRejected, validate_patch

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def unified_diff(file: str, start_line: int, original: str, candidate: str) -> str:
    """A unified diff that replaces the region `original` (which starts at
    `start_line` of `file`) with `candidate`. Both sides are treated as
    newline-terminated, because a snapshot is a region inside the file."""
    original = original.rstrip("\n") + "\n"
    candidate = candidate.rstrip("\n") + "\n"
    lines = list(difflib.unified_diff(original.splitlines(keepends=True), candidate.splitlines(keepends=True),
                                      fromfile=f"a/{file}", tofile=f"b/{file}", n=3))
    offset = start_line - 1
    out = []
    for line in lines:
        m = _HUNK.match(line)
        if m:
            o_start, o_count, n_start, n_count = m.group(1), m.group(2), m.group(3), m.group(4)

            def shifted(start: str, count: str | None) -> str:
                n = int(start)
                if n > 0 or (count not in (None, "0")):
                    n += offset
                return f"{n}" + (f",{count}" if count is not None else "")
            line = f"@@ -{shifted(o_start, o_count)} +{shifted(n_start, n_count)} @@\n"
        out.append(line)
    return "".join(out)


def apply_unified_diff(root: Path, text: str) -> list[str]:
    """Apply a validated unified diff to files under `root`. Returns the files
    changed. Raises PatchRejected if any hunk does not match exactly; on
    failure no file is modified."""
    files = validate_patch(text)
    root = root.resolve()
    patches = _parse(text)
    results: dict[Path, str] = {}
    for rel, hunks in patches:
        path = (root / rel).resolve()
        if root not in path.parents:
            raise PatchRejected("The patch contains an unsafe path.")
        if not path.is_file():
            raise PatchRejected(f"{rel} does not exist in the source tree.")
        raw = path.read_bytes()
        if b"\x00" in raw:
            raise PatchRejected(f"{rel} is a binary file.")
        content = raw.decode("utf-8")
        crlf = "\r\n" in content
        lines = content.replace("\r\n", "\n").split("\n")
        trailing_newline = content.endswith("\n")
        if trailing_newline:
            lines = lines[:-1]
        shift = 0
        for old_start, old_lines, new_lines in hunks:
            at = old_start - 1 + shift if old_start > 0 else 0
            if lines[at:at + len(old_lines)] != old_lines:
                raise PatchRejected(f"The patch does not apply to {rel} at line {old_start}.")
            lines[at:at + len(old_lines)] = new_lines
            shift += len(new_lines) - len(old_lines)
        out = "\n".join(lines) + ("\n" if trailing_newline else "")
        results[path] = out.replace("\n", "\r\n") if crlf else out
    for path, content in results.items():
        path.write_bytes(content.encode("utf-8"))
    return files


def _parse(text: str) -> list[tuple[str, list[tuple[int, list[str], list[str]]]]]:
    patches: list[tuple[str, list]] = []
    current: list | None = None
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("+++ "):
            target = line[4:].split("\t")[0].strip()
            if target == "/dev/null":
                raise PatchRejected("Deleting files is not supported.")
            rel = target[2:] if target.startswith("b/") else target
            current = []
            patches.append((rel, current))
            i += 1
            continue
        m = _HUNK.match(line)
        if m and current is not None:
            old_start = int(m.group(1))
            old_count = int(m.group(2)) if m.group(2) is not None else 1
            new_count = int(m.group(4)) if m.group(4) is not None else 1
            old: list[str] = []
            new: list[str] = []
            i += 1
            while (len(old) < old_count or len(new) < new_count) and i < len(lines):
                body = lines[i]
                if body.startswith("\\"):
                    i += 1
                    continue
                tag, rest = body[:1], body[1:]
                if tag == " " or body == "":
                    old.append(rest)
                    new.append(rest)
                elif tag == "-":
                    old.append(rest)
                elif tag == "+":
                    new.append(rest)
                else:
                    raise PatchRejected("The patch has a malformed hunk.")
                i += 1
            if len(old) != old_count or len(new) != new_count:
                raise PatchRejected("The patch has a truncated hunk.")
            current.append((old_start, old, new))
            continue
        i += 1
    if not patches or not any(h for _, h in patches):
        raise PatchRejected("The patch contains no hunks.")
    return patches
