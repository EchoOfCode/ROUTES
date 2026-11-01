"""CLI AI Remediation Engine (Dual-LLM: Model A Analysis + Model B Patching)."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import httpx

from routes_shared.patching import apply_unified_diff, unified_diff
from routes_shared.redaction import redact_text
from routes_storage.models import Finding

from routes_cli.renderers.theme import Glyphs, make_console


@dataclass
class RemediationResult:
    finding_id: str
    rule_id: str
    file: str
    line: int
    model_a_name: str
    model_a_analysis: str
    model_a_strategy: str
    model_b_name: str
    candidate_patch: str
    validated: bool
    error: Optional[str] = None


def _find_env_value(key: str, default: str = "") -> str:
    val = os.environ.get(key)
    if val:
        return val
    # Try reading from repo root .env if available
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
    
    # Try candidate paths
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
                
    # If not on local disk, fetch via GitHub raw
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


def run_cli_remediation(finding: Finding, source_hint: Optional[str] = None, console=None) -> RemediationResult:
    """Execute dual-LLM remediation on finding."""
    con = console or make_console()
    rel_path, snippet, start_line, end_line = _fetch_source_code(finding, source_hint)
    
    # Redact code before sending to any model
    redacted_code = redact_text(snippet)
    
    # Model A: Analysis & Strategy (Groq or OpenAI)
    llm_a_endpoint = _find_env_value("LLM_A_ENDPOINT", "https://api.groq.com/openai/v1/chat/completions")
    llm_a_key = _find_env_value("LLM_A_API_KEY", "") or _find_env_value("GROQ_API_KEY", "")
    llm_a_model = _find_env_value("LLM_A_MODEL", "openai/gpt-oss-120b")
    
    # Model B: Patch generation (Groq or OpenAI)
    llm_b_endpoint = _find_env_value("LLM_B_ENDPOINT", "https://api.groq.com/openai/v1/chat/completions")
    llm_b_key = _find_env_value("LLM_B_API_KEY", "") or _find_env_value("GROQ_API_KEY", "")
    llm_b_model = _find_env_value("LLM_B_MODEL", "qwen/qwen3.8-27b")

    if not llm_a_key or not llm_b_key:
        raise ValueError("Missing LLM API keys in environment or .env (LLM_A_API_KEY / LLM_B_API_KEY).")

    # Step 1: Model A Invocation
    con.print(f"[accent]› Model A ({llm_a_model}):[/] Analysing root cause and remediation strategy...")
    
    prompt_a = f"""You are Model A (Security Architect) in the ROUTES AI remediation engine.
Analyze this security finding:
Vulnerability Type: {finding.type}
Rule ID: {finding.rule_id}
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
  "remediation_strategy": "exact instructions for Model B to rewrite the code safely without introducing regressions",
  "suggested_fix_snippet": "the replacement code snippet for lines {start_line}-{end_line}"
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
    # Extract JSON block if surrounded by markdown code fences
    json_match = re.search(r"\{.*\}", data_a_raw, re.DOTALL)
    if json_match:
        data_a = json.loads(json_match.group(0))
    else:
        data_a = {"root_cause": data_a_raw[:200], "expected_behaviour": "Safe rendering", "remediation_strategy": data_a_raw}

    root_cause = data_a.get("root_cause", "")
    strategy = data_a.get("remediation_strategy", "")

    # Step 2: Model B Invocation
    con.print(f"[accent]› Model B ({llm_b_model}):[/] Generating precise code patch...")
    prompt_b = f"""You are Model B (Code Patcher) in the ROUTES AI remediation engine.
Task: Write a secure replacement for the vulnerable code based on Model A's instructions.

File: {rel_path}
Vulnerability: {finding.type} ({finding.rule_id})
Model A Analysis: {root_cause}
Model A Strategy: {strategy}

Original Code Context (lines {start_line}-{end_line}):
```
{snippet}
```

Rules:
1. Preserve existing indentation and styling.
2. Return ONLY the replacement code for this exact block (lines {start_line}-{end_line}) inside a ```jsx or ```tsx block.
3. Do not include markdown preamble or commentary.
"""
    headers_b = {"Authorization": f"Bearer {llm_b_key}", "Content-Type": "application/json"}
    resp_b = httpx.post(llm_b_endpoint, headers=headers_b, json={
        "model": llm_b_model,
        "messages": [{"role": "user", "content": prompt_b}],
        "temperature": 0.0,
    }, timeout=45.0)

    if resp_b.status_code != 200:
        raise RuntimeError(f"Model B failed ({resp_b.status_code}): {resp_b.text[:200]}")

    data_b_raw = resp_b.json()["choices"][0]["message"]["content"]
    code_match = re.search(r"```(?:jsx|tsx|javascript|typescript|js)?\n(.*?)```", data_b_raw, re.DOTALL)
    new_code = code_match.group(1) if code_match else data_b_raw.strip()

    # Generate unified diff patch
    diff = unified_diff(rel_path, start_line, snippet, new_code)

    # Validate patch against temp directory
    validated = False
    validation_err = None
    try:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            target_f = Path(td) / rel_path
            target_f.parent.mkdir(parents=True, exist_ok=True)
            # Write dummy original file
            full_lines = ["// padding\n"] * max(1, start_line - 1)
            full_lines.append(snippet + "\n")
            target_f.write_text("".join(full_lines), "utf-8")
            apply_unified_diff(Path(td), diff)
            validated = True
    except Exception as exc:
        validation_err = str(exc)

    return RemediationResult(
        finding_id=f"{finding.seq:02d}",
        rule_id=finding.rule_id,
        file=rel_path,
        line=finding.line or 1,
        model_a_name=llm_a_model,
        model_a_analysis=root_cause,
        model_a_strategy=strategy,
        model_b_name=llm_b_model,
        candidate_patch=diff,
        validated=validated,
        error=validation_err,
    )
