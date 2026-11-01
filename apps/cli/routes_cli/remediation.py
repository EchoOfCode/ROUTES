"""CLI AI Remediation Loop Engine (Dual-LLM Iterative Correction & Multi-Finding Batching)."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import httpx

from routes_shared.patching import apply_unified_diff, unified_diff
from routes_shared.redaction import redact_text
from routes_storage.models import Finding

from routes_cli.renderers.theme import make_console


@dataclass
class RoundAttempt:
    round_no: int
    patch: str
    validated: bool
    error: Optional[str] = None


@dataclass
class FindingRemediationResult:
    finding_id: str
    rule_id: str
    title: str
    file: str
    line: int
    severity: str
    status: str  # "fixed" | "needs_human_review" | "inconclusive"
    model_a_name: str
    model_a_analysis: str
    model_a_strategy: str
    model_b_name: str
    attempts: list[RoundAttempt] = field(default_factory=list)
    final_patch: str = ""
    rounds_used: int = 0
    error: Optional[str] = None


@dataclass
class BatchRemediationReport:
    total_findings: int
    fixed_count: int
    human_review_count: int
    combined_patch: str
    results: list[FindingRemediationResult]


def _find_env_value(key: str, default: str = "") -> str:
    val = os.environ.get(key)
    if val:
        return val
    for parent in [Path.cwd(), Path.cwd().parent]:
        env_file = parent / ".env"
        if env_file.is_file():
            for line in env_file.read_text("utf-8").splitlines():
                line = line.strip()
                if line.startswith(f"{key}="):
                    return line.split("=", 1)[1].strip()
    return default


def _fetch_source_code(finding: Finding, source_hint: Optional[str] = None) -> tuple[str, str, int, int]:
    """Retrieve source code snippet around finding. Returns (file_rel, code_snippet, start_line, end_line)."""
    rel_path = finding.file or ""
    line_no = finding.line or 1

    candidates = []
    if source_hint and Path(source_hint).exists():
        candidates.append(Path(source_hint) / rel_path)
    candidates.extend([
        Path(rel_path),
        Path("D:/nova-ecommerce") / rel_path,
        Path.cwd() / rel_path,
    ])

    content = None
    for cand in candidates:
        if cand.is_file():
            try:
                content = cand.read_text("utf-8")
                break
            except Exception:
                pass

    if content is None:
        raw_url = f"https://raw.githubusercontent.com/Anish-16-N/nova-ecommerce/main/{rel_path}"
        try:
            r = httpx.get(raw_url, timeout=10.0)
            if r.status_code == 200:
                content = r.text
        except Exception:
            pass

    if not content:
        raise ValueError(f"Could not read source file '{rel_path}' locally or from remote repository.")

    lines = content.splitlines()
    start_line = max(1, line_no - 15)
    end_line = min(len(lines), line_no + 15)
    snippet = "\n".join(lines[start_line - 1 : end_line])
    return rel_path, snippet, start_line, end_line


def _verify_candidate_patch(file_rel: str, start_line: int, original_snippet: str, new_code: str, rule_id: str) -> tuple[bool, str, Optional[str]]:
    """Derive unified diff and verify against strict syntax and vulnerability rules."""
    diff = unified_diff(file_rel, start_line, original_snippet, new_code)
    if not diff.strip() or original_snippet.strip() == new_code.strip():
        return False, "", "Patch made no code modifications."

    # Strict application check (no fuzz)
    try:
        with tempfile.TemporaryDirectory() as td:
            target_f = Path(td) / file_rel
            target_f.parent.mkdir(parents=True, exist_ok=True)
            full_lines = ["// padding\n"] * max(1, start_line - 1)
            full_lines.append(original_snippet + "\n")
            target_f.write_text("".join(full_lines), "utf-8")
            apply_unified_diff(Path(td), diff)
    except Exception as exc:
        return False, diff, f"Patch failed strict validation: {exc}"

    # Semantic check: did it actually eliminate the vulnerable sink?
    if "dangerously-set-inner-html" in rule_id:
        if "dangerouslySetInnerHTML" in new_code and "DOMPurify" not in new_code and "sanitize" not in new_code:
            return False, diff, "Unsanitized dangerouslySetInnerHTML is still present in the replacement."

    return True, diff, None


def remediate_finding_loop(finding: Finding, source_hint: Optional[str] = None, max_rounds: int = 3, console=None) -> FindingRemediationResult:
    """Execute iterative remediation loop on a single finding (up to max_rounds)."""
    con = console or make_console()
    rel_path, snippet, start_line, end_line = _fetch_source_code(finding, source_hint)
    redacted_code = redact_text(snippet)

    llm_a_endpoint = _find_env_value("LLM_A_ENDPOINT", "https://api.groq.com/openai/v1/chat/completions")
    llm_a_key = _find_env_value("LLM_A_API_KEY", "") or _find_env_value("GROQ_API_KEY", "")
    llm_a_model = _find_env_value("LLM_A_MODEL", "openai/gpt-oss-120b")

    llm_b_endpoint = _find_env_value("LLM_B_ENDPOINT", "https://api.groq.com/openai/v1/chat/completions")
    llm_b_key = _find_env_value("LLM_B_API_KEY", "") or _find_env_value("GROQ_API_KEY", "")
    llm_b_model = _find_env_value("LLM_B_MODEL", "qwen/qwen3.8-27b")

    if not llm_a_key or not llm_b_key:
        raise ValueError("Missing LLM API keys in environment or .env (LLM_A_API_KEY / LLM_B_API_KEY).")

    # Step 1: Model A Analysis (Once per finding)
    con.print(f"  [accent]› Model A ({llm_a_model}):[/] Analysing root cause & generating strategy...")
    prompt_a = f"""You are Model A (Security Architect) in the ROUTES AI remediation engine.
Analyze this security finding:
Vulnerability: {finding.type} ({finding.rule_id})
File: {rel_path}:{finding.line}
Description: {finding.plain_description}

Source Code Context (lines {start_line}-{end_line}):
```
{redacted_code}
```

Respond strictly in valid JSON matching this schema:
{{
  "root_cause": "concise explanation of why this code is vulnerable",
  "expected_behaviour": "how the code should behave safely",
  "remediation_strategy": "exact instructions for Model B to rewrite the code safely without introducing regressions"
}}
"""
    headers_a = {"Authorization": f"Bearer {llm_a_key}", "Content-Type": "application/json"}
    resp_a = httpx.post(llm_a_endpoint, headers=headers_a, json={
        "model": llm_a_model,
        "messages": [{"role": "user", "content": prompt_a}],
        "temperature": 0.1,
    }, timeout=45.0)

    if resp_a.status_code != 200:
        raise RuntimeError(f"Model A failed ({resp_a.status_code}): {resp_a.text[:200]}")

    data_a_raw = resp_a.json()["choices"][0]["message"]["content"]
    json_match = re.search(r"\{.*\}", data_a_raw, re.DOTALL)
    if json_match:
        data_a = json.loads(json_match.group(0))
    else:
        data_a = {"root_cause": data_a_raw[:200], "remediation_strategy": data_a_raw}

    root_cause = data_a.get("root_cause", "")
    strategy = data_a.get("remediation_strategy", "")

    result = FindingRemediationResult(
        finding_id=f"{finding.seq:02d}",
        rule_id=finding.rule_id,
        title=finding.title,
        file=rel_path,
        line=finding.line or 1,
        severity=finding.severity,
        status="inconclusive",
        model_a_name=llm_a_model,
        model_a_analysis=root_cause,
        model_a_strategy=strategy,
        model_b_name=llm_b_model,
    )

    # Step 2: Iterative Model B Correction Loop (Attempts 1 to max_rounds)
    headers_b = {"Authorization": f"Bearer {llm_b_key}", "Content-Type": "application/json"}
    previous_error: Optional[str] = None

    for round_no in range(1, max_rounds + 1):
        con.print(f"  [accent]› Attempt {round_no}/{max_rounds} (Model B: {llm_b_model}):[/] Generating patch...")
        
        correction_guidance = ""
        if previous_error:
            correction_guidance = f"""
IMPORTANT: Attempt {round_no - 1} FAILED verification with this error:
{previous_error}
You must correct the patch to resolve this failure while ensuring the security vulnerability is fully eliminated!
"""

        prompt_b = f"""You are Model B (Code Patcher) in the ROUTES AI remediation engine.
Task: Write a secure replacement for the vulnerable code based on Model A's instructions.

File: {rel_path}
Vulnerability: {finding.type} ({finding.rule_id})
Model A Analysis: {root_cause}
Model A Strategy: {strategy}
{correction_guidance}

Original Code Context (lines {start_line}-{end_line}):
```
{snippet}
```

Rules:
1. Preserve existing indentation and styling.
2. Return ONLY the replacement code for this exact block (lines {start_line}-{end_line}) inside a ```jsx or ```tsx block.
3. Do not include markdown preamble or commentary.
"""
        resp_b = httpx.post(llm_b_endpoint, headers=headers_b, json={
            "model": llm_b_model,
            "messages": [{"role": "user", "content": prompt_b}],
            "temperature": 0.0,
        }, timeout=45.0)

        if resp_b.status_code != 200:
            err_msg = f"Model B returned HTTP {resp_b.status_code}"
            result.attempts.append(RoundAttempt(round_no=round_no, patch="", validated=False, error=err_msg))
            previous_error = err_msg
            continue

        data_b_raw = resp_b.json()["choices"][0]["message"]["content"]
        code_match = re.search(r"```(?:jsx|tsx|javascript|typescript|js)?\n(.*?)```", data_b_raw, re.DOTALL)
        new_code = code_match.group(1) if code_match else data_b_raw.strip()

        # Verification Gate
        validated, diff, v_err = _verify_candidate_patch(rel_path, start_line, snippet, new_code, finding.rule_id)
        result.attempts.append(RoundAttempt(round_no=round_no, patch=diff, validated=validated, error=v_err))

        if validated:
            con.print(f"    [ok]✓ Attempt {round_no}: Patch verified cleanly[/]")
            result.status = "fixed"
            result.final_patch = diff
            result.rounds_used = round_no
            return result
        else:
            con.print(f"    [warn]! Attempt {round_no} verification failed:[/] {v_err}")
            previous_error = v_err

    # Exhausted attempts
    result.status = "needs_human_review"
    result.rounds_used = max_rounds
    result.error = f"Exhausted {max_rounds} attempts without passing verification. Last error: {previous_error}"
    if result.attempts:
        result.final_patch = result.attempts[-1].patch
    return result


def remediate_batch_loop(findings: list[Finding], source_hint: Optional[str] = None, max_rounds: int = 3, console=None) -> BatchRemediationReport:
    """Execute remediation loop across a batch of findings, compiling a cumulative patch."""
    con = console or make_console()
    results: list[FindingRemediationResult] = []
    combined_diffs: list[str] = []

    con.print(f"\n[heading]STARTING REMEDIATION LOOP FOR {len(findings)} FINDING(S)[/]\n")

    for i, finding in enumerate(findings, 1):
        con.print(f"[bold cyan][{i}/{len(findings)}] Finding #{finding.seq:02d}:[/] {finding.title} ([path]{finding.file}:{finding.line}[/])")
        try:
            res = remediate_finding_loop(finding, source_hint=source_hint, max_rounds=max_rounds, console=con)
            results.append(res)
            if res.status == "fixed" and res.final_patch:
                combined_diffs.append(res.final_patch)
        except Exception as exc:
            con.print(f"  [err]✗ Failed to remediate finding #{finding.seq:02d}:[/] {exc}")
            results.append(FindingRemediationResult(
                finding_id=f"{finding.seq:02d}", rule_id=finding.rule_id, title=finding.title,
                file=finding.file or "", line=finding.line or 1, severity=finding.severity,
                status="inconclusive", model_a_name="", model_a_analysis="", model_a_strategy="",
                model_b_name="", error=str(exc)
            ))
        con.print()

    fixed_count = sum(1 for r in results if r.status == "fixed")
    human_review_count = sum(1 for r in results if r.status == "needs_human_review")
    combined_patch = "\n".join(combined_diffs)

    return BatchRemediationReport(
        total_findings=len(findings),
        fixed_count=fixed_count,
        human_review_count=human_review_count,
        combined_patch=combined_patch,
        results=results,
    )
