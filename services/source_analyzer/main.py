"""Source analysis sandbox entrypoint.

Acquire (GitHub via gateway import, or ZIP from a read-only mount) -> extract
safely into tmpfs -> profile -> structure -> static rules -> data flow ->
redact -> emit one JSON result. Repository code is never executed.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

from routes_shared.buildrun import PatchRejected
from routes_shared.patching import apply_unified_diff
from routes_shared.redaction import redact_structure, redact_text

from source_analyzer.acquisition.archive import ArchiveError, extract_tar_gz, extract_zip
from source_analyzer.acquisition.github import ImportFailed, download
from source_analyzer.events import emit, emit_result
from source_analyzer.profiling.matching import collect as collect_matching
from source_analyzer.profiling.profile import build_profile
from source_analyzer.static_analysis.headers import check_security_headers
from source_analyzer.static_analysis.semgrep_runner import SemgrepFailed, run_semgrep
from source_analyzer.vuln_classes import VULN_CLASSES, AnalysisContext
from source_analyzer.vuln_classes.base import snapshot_for

WORK = Path(os.environ.get("ROUTES_WORK_DIR", "/work"))


PATCH_FILE = Path("/input/patch.diff")


def acquire(kind: str, work: Path) -> tuple[Path, list[str], str | None, bool]:
    src = work / "src"
    src.mkdir(parents=True, exist_ok=True)
    emit("retrieving_source", "Retrieving source code")
    if kind == "github":
        url, token = os.environ.get("ROUTES_IMPORT_URL"), os.environ.get("ROUTES_PROXY_TOKEN")
        if not url or not token:
            raise ImportFailed("No repository import path was configured for this sandbox.")
        archive = work / "repo.tar.gz"
        size = download(url, token, archive)
        emit("extracting", f"Extracting repository archive ({size // 1024} KB)")
        report = extract_tar_gz(archive, src)
        archive.unlink(missing_ok=True)
    elif kind == "zip":
        archive = Path("/input/source.zip")
        if not archive.is_file():
            raise ArchiveError("The uploaded archive is no longer available. Upload it again.")
        emit("extracting", "Validating and extracting the ZIP archive")
        report = extract_zip(archive, src)
    else:
        raise ArchiveError("Unknown source type.")
    notes = []
    if report.skipped_links:
        notes.append(f"{report.skipped_links} symbolic link(s) or special file(s) were skipped.")
    if report.skipped_excluded:
        notes.append(f"{report.skipped_excluded} file(s) in dependency or build folders were excluded.")
    if report.files_written == 0:
        raise ArchiveError("The archive did not contain any analysable files.")
    emit("extracting", f"{report.files_written} files extracted", files=report.files_written)
    patched = False
    if PATCH_FILE.is_file():
        # Post-remediation rescan: apply the candidate patch to this temporary
        # copy, strictly (no fuzz), before analysing it.
        try:
            changed = apply_unified_diff(src, PATCH_FILE.read_text("utf-8"))
        except (PatchRejected, UnicodeDecodeError) as exc:
            raise ArchiveError(f"The candidate patch could not be applied: {exc}") from exc
        patched = True
        emit("extracting", f"Candidate patch applied to {len(changed)} file(s)")
    return src, notes, report.commit_sha, patched


# Rules whose finding *is* a committed secret value: the fix is rotating the
# secret, and a code snapshot of the finding would contain the secret itself.
SECRET_VALUE_RULES = frozenset({"routes.crypto.weak-jwt-secret", "routes.crypto.hardcoded-auth-secret",
                                "routes.config.public-env-secret"})


def analyse(root: Path, kind: str, target_host: str) -> dict:
    emit("profiling", "Profiling repository")
    profile = build_profile(root)
    warnings = list(profile.warnings)
    result: dict = {
        "source_kind": kind,
        "support_status": profile.support_status,
        "support_reason": profile.support_reason,
        "profile": profile.as_dict(),
        "env_var_names": sorted(profile.env_var_names)[:500],
        "config_refs": profile.config_refs[:2000],
        "routes": [],
        "db_interactions": [],
        "input_sources": [],
        "findings": [],
        "match_evidence": collect_matching(profile, target_host),
    }

    findings: list[dict] = []
    emit("running_static_rules", "Running static security rules")
    try:
        semgrep_findings, semgrep_warnings = run_semgrep(root)
        findings.extend(semgrep_findings)
        warnings.extend(semgrep_warnings)
    except SemgrepFailed as exc:
        warnings.append(str(exc))
        result["semgrep_failed"] = True
    else:
        emit("running_static_rules", f"Static rules reported {len(semgrep_findings)} potential issue(s)",
             static_matches=len(semgrep_findings))

    try:
        findings.extend(check_security_headers(profile))
    except Exception:  # noqa: BLE001
        warnings.append("The security-header check on next.config could not be completed.")

    js_files = profile.js_files()
    if profile.framework == "Next.js" and js_files:
        emit("analysing_structure", f"Parsing {len(js_files)} JavaScript/TypeScript files")
        sources = {f.rel: f.path.read_bytes() for f in js_files[:5000]}
        emit("tracing_data_flow", "Tracing user input to database queries")
        ctx = AnalysisContext(files=sources, tsconfig_paths=profile.tsconfig_paths,
                              tsconfig_base=profile.tsconfig_base, pg_declared="pg" in profile.dep_names())
        snapshot_failures = 0

        def snapshot_dict(snapshot) -> dict:
            # A snapshot is copied verbatim from the repository, so mask any
            # secret in it here, not only in main()'s final pass: no code
            # path may ever carry a raw secret value out of this function.
            return {"file": snapshot.file, "start_line": snapshot.start_line, "end_line": snapshot.end_line,
                    "code": redact_text(snapshot.code, max_length=1_000_000)}

        for vuln_class in VULN_CLASSES:
            plugin_findings = vuln_class.detect(ctx)
            for f in plugin_findings:
                try:
                    f["snapshot"] = snapshot_dict(vuln_class.build_snapshot(f, ctx))
                except Exception:  # noqa: BLE001
                    # The finding itself is still valid and reported; only
                    # the remediation-loop snapshot is unavailable for it.
                    f["snapshot"] = None
                    snapshot_failures += 1
            findings.extend(plugin_findings)
        # Semgrep-sourced findings have no plugin behind them, but a snapshot
        # is what makes a finding remediable at all (worker.fix_table has
        # deterministic fixes for several of these rules), so build one for
        # any that landed in a file this run already parsed.
        for f in findings:
            if "snapshot" in f or not f.get("file") or not f.get("line"):
                continue
            if f.get("rule_id", "").startswith("routes.secrets.") or f.get("rule_id") in SECRET_VALUE_RULES:
                # The fix for a committed secret is rotating it, not a code
                # rewrite, and its snapshot would be the secret itself.
                f["snapshot"] = None
                continue
            try:
                f["snapshot"] = snapshot_dict(snapshot_for(f, ctx))
            except Exception:  # noqa: BLE001
                f["snapshot"] = None

        if snapshot_failures:
            warnings.append(f"{snapshot_failures} finding(s) could not have a code snapshot built for them.")
        warnings.extend(ctx.warnings)

        analyzer = ctx.sqli_analyzer
        result["routes"] = [
            {"path": r.endpoint, "methods": sorted({h.method for h in r.handlers}), "file": r.rel,
             "line": r.handlers[0].line if r.handlers else None, "router": r.router,
             "handler": ", ".join(sorted({h.name for h in r.handlers})) or None}
            for r in analyzer.routes
        ]
        result["db_interactions"] = [
            {"file": i.sink_file or i.file, "line": i.sink_line or i.line, "call": i.call, "client": i.client,
             "query_construction": i.construction, "uses_user_input": i.uses_user_input, "endpoint": i.endpoint,
             "method": i.method}
            for i in analyzer.interactions
        ]
        result["input_sources"] = analyzer.input_sources[:2000]
        flows =sum(1 for f in findings if f.get("type") == "SQL Injection" and f.get("status") == "potential")
        emit("tracing_data_flow", f"{len(result['routes'])} route(s) traced, {flows} SQL injection flow(s) found",
             routes=len(result["routes"]), sqli_flows=flows)
    elif profile.support_status != "unsupported":
        warnings.append("No Next.js source files were found to analyse.")

    # One finding per location/rule.
    unique: dict[str, dict] = {}
    for f in findings:
        unique.setdefault(f.pop("_fingerprint", f"{f['rule_id']}:{f['file']}:{f['line']}"), f)
    result["findings"] = [{**f, "fingerprint": k} for k, f in unique.items()][:1000]
    result["warnings"] = warnings[:100]
    return result


def main() -> int:
    kind = os.environ.get("ROUTES_SOURCE_KIND", "")
    target_host = os.environ.get("ROUTES_TARGET_HOST", "")
    started = time.monotonic()
    try:
        root, notes, commit, patched = acquire(kind, WORK)
        result = analyse(root, kind, target_host)
        result["warnings"] = notes + result["warnings"]
        result["source_commit"] = commit
        result["patch_applied"] = patched
        result["duration_seconds"] = round(time.monotonic() - started, 1)
        # Defence in depth: nothing leaving the sandbox may contain a secret value.
        result = redact_structure(result, max_length=2000)
    except (ArchiveError, ImportFailed) as exc:
        result = {"fatal": True, "error": str(exc)[:500]}
    except Exception as exc:  # noqa: BLE001
        result = {"fatal": True, "error": f"Source analysis failed unexpectedly ({type(exc).__name__})."}
    finally:
        shutil.rmtree(WORK / "src", ignore_errors=True)
    emit_result(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
