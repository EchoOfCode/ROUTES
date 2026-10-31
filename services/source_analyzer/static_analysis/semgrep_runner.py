"""Run the bundled Semgrep rules offline and normalise results into findings."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from routes_shared.fingerprint import fingerprint
from routes_shared.redaction import mask_string_literals, mask_value, redact_text

RULES = Path(__file__).parent / "rules"
TIMEOUT = 300


class SemgrepFailed(Exception):
    pass


def run_semgrep(root: Path) -> tuple[list[dict], list[str]]:
    cmd = [
        "semgrep", "scan", "--config", str(RULES), "--json", "--metrics=off", "--disable-version-check",
        "--no-git-ignore", "--timeout", "20", "--max-target-bytes", "1000000", "--jobs", "1", "--quiet",
        "--exclude", "node_modules", "--exclude", ".next", "--exclude", "dist", "--exclude", "build", str(root),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT, cwd=str(root), check=False,
                              env={"HOME": "/home/sandbox", "PATH": "/usr/local/bin:/usr/bin:/bin",
                                   "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"})
    except subprocess.TimeoutExpired as exc:
        raise SemgrepFailed("Static rules timed out.") from exc
    except FileNotFoundError as exc:
        raise SemgrepFailed("Semgrep is not installed in the analyzer image.") from exc
    if proc.returncode not in (0, 1):
        raise SemgrepFailed(f"Static rules failed to run (exit code {proc.returncode}).")
    try:
        data = json.loads(proc.stdout or b"{}")
    except ValueError as exc:
        raise SemgrepFailed("Static rule output could not be read.") from exc
    warnings = [f"Semgrep: {str(e.get('message', ''))[:200]}" for e in (data.get("errors") or [])[:5]]
    return [normalise(r, root) for r in data.get("results", [])][:500], warnings


SECRET_DEFAULTS = {
    "routes_type": "Hardcoded Secret",
    "routes_recommendation": "Remove the value from the code, rotate it with the provider, and load it at runtime "
                             "from an environment variable or a secrets manager.",
    "routes_severity": "high",
    "routes_confidence": "high",
    "cwe": "CWE-798",
    "secret": True,
}


def matched_lines(root: Path, rel: str, start: dict, end: dict) -> str:
    """Read the matched source span from disk.

    Semgrep >= 1.18 returns the literal string "requires login" in
    extra.lines, which would otherwise become every finding's snippet and
    collapse distinct findings of one rule in one file onto one fingerprint.
    """
    first = start.get("line")
    if not first:
        return ""
    try:
        lines = (root / rel).read_text("utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[first - 1:max(end.get("line") or first, first)])


def normalise(result: dict, root: Path) -> dict:
    meta = dict((result.get("extra") or {}).get("metadata") or {})
    if ".secrets." in result.get("check_id", ""):
        meta = {**SECRET_DEFAULTS, **meta}
    path = Path(result.get("path", ""))
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        rel = path.as_posix()
    start = result.get("start") or {}
    end = result.get("end") or {}
    # The snippet is real source now, so a hardcoded credential on the matched
    # line would otherwise leave the sandbox inside it.
    snippet = redact_text(mask_string_literals(matched_lines(root, rel, start, end)), max_length=200)
    evidence_value = ""
    if meta.get("secret"):
        # Never keep the secret itself: show at most its first four characters.
        try:
            raw = (root / rel).read_bytes()[start.get("offset", 0):end.get("offset", 0)].decode("utf-8", "replace")
        except OSError:
            raw = ""
        evidence_value = mask_value(raw.strip().strip("'\"")) if raw else "[redacted]"
    rule_id = result.get("check_id", "routes.unknown").split(".routes.", 1)[-1]
    if not rule_id.startswith("routes."):
        rule_id = "routes." + rule_id.split("routes.", 1)[-1]
    evidence = f"{meta.get('routes_title', 'Pattern match')} at {rel}:{start.get('line')}."
    if evidence_value:
        evidence += f" Value (hidden): {evidence_value}."
    return {
        "type": meta.get("routes_type", "Security Pattern"),
        "status": "potential",
        "severity": meta.get("routes_severity", "low"),
        "confidence": meta.get("routes_confidence", "low"),
        "title": meta.get("routes_title", "Security pattern detected"),
        "file": rel,
        "line": start.get("line"),
        "end_line": end.get("line"),
        "endpoint": None,
        "method": None,
        "rule_id": rule_id[:200],
        "plain_description": " ".join(str(meta.get("routes_plain", result.get("extra", {}).get("message", ""))).split()),
        "evidence_summary": evidence,
        "recommendation": " ".join(str(meta.get("routes_recommendation", "")).split()),
        "technical_details": {"engine": "semgrep", "rule": rule_id, "cwe": meta.get("cwe"), "snippet": snippet},
        "_fingerprint": fingerprint(rule_id, rel, snippet),
    }
