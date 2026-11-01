"""Model A (analysis and plan) and Model B (patch) for the CLI remediation loop.

The prompts and validation follow the worker's structured mode
(``services/worker/llm/llm_a_plan.py`` and ``llm_b.py``); the worker is a
separate trust tier and is not installed with the CLI, so this is the CLI's own
small copy of the same contract:

* Model A returns a typed plan (root cause, strategy, scenarios, optional GET/HEAD
  functional tests). It never writes the security tests: those come from
  ``routes_core.testplan``, so a weak model cannot weaken the gate.
* Model B returns replacement code for the snapshot region only. Its output is
  never executed here; it is validated, turned into a diff, and run in the
  sandbox.
* Everything sent to a provider is redacted first (``redact_for_llm``) and
  checked again (``unredacted_secret_count``); secrets are restored only in the
  candidate, locally.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from pydantic import BaseModel, Field, ValidationError

from routes_shared.buildrun import TestCase
from routes_shared.fingerprint import normalize_snippet
from routes_shared.redaction import redact_for_llm, redact_text, restore, unredacted_secret_count
from routes_shared.remediation import Snapshot

DEFAULT_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL_A = "openai/gpt-oss-120b"
DEFAULT_MODEL_B = "qwen/qwen3-32b"
MAX_FUNCTIONAL_TESTS = 8


class LLMError(RuntimeError):
    """A provider call failed or returned something unusable (never papered over)."""


class LLMSetupError(ValueError):
    """The models are not configured."""


# ------------------------------------------------------------------ config
@dataclass(frozen=True)
class ModelConfig:
    role: str
    endpoint: str
    model: str
    api_key: str = field(repr=False)

    @property
    def provider(self) -> str:
        return httpx.URL(self.endpoint).host or "unknown"


def _env_files(home: Path | None) -> list[Path]:
    files = []
    if home is not None:
        files.append(home / "remediation.env")
    here = Path.cwd().resolve()
    for d in (here, *here.parents):
        files.append(d / ".env")
    return files


def _lookup(key: str, files: list[Path]) -> str:
    if os.environ.get(key):
        return os.environ[key].strip()
    for f in files:
        try:
            for line in f.read_text("utf-8").splitlines():
                line = line.strip()
                if line.startswith(f"{key}=") and not line.startswith("#"):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
        except OSError:
            continue
    return ""


def load_models(home: Path | None = None) -> tuple[ModelConfig, ModelConfig]:
    """Model A and Model B from the environment, ``~/.routes/remediation.env`` or a
    ``.env`` in this folder or a parent (the same variables the worker uses)."""
    files = _env_files(home)
    shared = _lookup("GROQ_API_KEY", files)
    out = []
    for role, default_model in (("A", DEFAULT_MODEL_A), ("B", DEFAULT_MODEL_B)):
        key = _lookup(f"LLM_{role}_API_KEY", files) or shared
        out.append(ModelConfig(role=role, endpoint=_lookup(f"LLM_{role}_ENDPOINT", files) or DEFAULT_ENDPOINT,
                               model=_lookup(f"LLM_{role}_MODEL", files) or default_model, api_key=key))
    missing = [f"LLM_{c.role}_API_KEY" for c in out if not c.api_key]
    if missing:
        raise LLMSetupError(f"{' and '.join(missing)} not set. Put them in the environment, in "
                            f"{(home / 'remediation.env') if home else '~/.routes/remediation.env'}, or in a .env "
                            "file (LLM_A_ENDPOINT / LLM_A_MODEL and the B equivalents are optional).")
    return out[0], out[1]


class ChatClient:
    """Minimal OpenAI-compatible chat-completions client."""

    def __init__(self, config: ModelConfig, *, timeout: float = 90.0, transport: httpx.BaseTransport | None = None):
        self.config = config
        self._http = httpx.Client(headers={"Authorization": f"Bearer {config.api_key}"},
                                  timeout=httpx.Timeout(timeout, connect=10.0), transport=transport)

    @property
    def model(self) -> str:
        return self.config.model

    def complete(self, messages: list[dict], *, temperature: float = 0.0) -> str:
        for m in messages:
            if unredacted_secret_count(m["content"]):
                raise LLMError("Redaction check failed: a secret-like value is still present in the prompt, so it "
                               "was not sent to the model provider.")
        try:
            r = self._http.post(self.config.endpoint, json={"model": self.config.model, "messages": messages,
                                                            "temperature": temperature})
        except httpx.HTTPError as exc:
            raise LLMError(f"Model {self.config.role} ({self.config.provider}) could not be reached: {exc}") from exc
        if r.status_code != 200:
            raise LLMError(f"Model {self.config.role} returned HTTP {r.status_code}: "
                           f"{redact_text(r.text, max_length=200)}")
        try:
            return r.json()["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise LLMError(f"Model {self.config.role} returned an unexpected response shape.") from exc

    def close(self) -> None:
        self._http.close()


# ----------------------------------------------------------------- Model A
PLAN_SYSTEM_PROMPT = (
    "You are a security engineer planning the fix of one confirmed vulnerability in a web application. "
    "You get the finding and a redacted code snapshot; secrets are placeholders like <SECRET_1>; copy them "
    "verbatim, never invent values.\n\n"
    "Respond with ONLY a JSON object with these fields:\n"
    '"prompt_for_fix" (string, required): precise instructions for the engineer who will rewrite the snapshot.\n'
    '"root_cause" (string): why the code is vulnerable.\n'
    '"expected_behaviour" (string): how the endpoint must behave after the fix, for normal and malicious input.\n'
    '"security_test_scenarios" (array of strings): attacks the fix must withstand.\n'
    '"functional_test_scenarios" (array of strings): normal behaviour the fix must preserve.\n'
    '"regression_risks" (array of strings): what a careless fix could break.\n'
    '"functional_tests" (array, at most 8): HTTP checks of normal behaviour, each '
    '{"id": "short-id", "name": "...", "method": "GET", "path": "/api/...", "query": {"k": "v"}, '
    '"expect_status": [200]}. Only GET requests; benign input only.\n'
    "No prose outside the JSON object."
)


class _FunctionalTest(BaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,40}$")
    name: str = Field(max_length=200)
    method: str = "GET"
    path: str = Field(max_length=500)
    query: dict[str, str] = Field(default_factory=dict)
    expect_status: list[int] = Field(min_length=1, max_length=10)


@dataclass
class FixPlan:
    model: str
    prompt_for_fix: str
    redacted_code: str
    placeholder_map: dict[str, str] = field(repr=False)
    secrets_redacted: int = 0
    root_cause: str | None = None
    expected_behaviour: str | None = None
    security_test_scenarios: list[str] = field(default_factory=list)
    functional_test_scenarios: list[str] = field(default_factory=list)
    regression_risks: list[str] = field(default_factory=list)
    functional_tests: list[dict] = field(default_factory=list)
    rejected_tests: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {"model": self.model, "root_cause": self.root_cause, "expected_behaviour": self.expected_behaviour,
                "strategy": self.prompt_for_fix, "security_test_scenarios": self.security_test_scenarios,
                "functional_test_scenarios": self.functional_test_scenarios,
                "regression_risks": self.regression_risks, "functional_tests": len(self.functional_tests),
                "rejected_tests": self.rejected_tests, "secrets_redacted": self.secrets_redacted}


def _json_object(text: str) -> dict:
    text = text.strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise LLMError("Model A did not return a JSON object.")
    try:
        value = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise LLMError(f"Model A returned invalid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise LLMError("Model A did not return a JSON object.")
    return value


def _str(raw: dict, key: str) -> str | None:
    v = raw.get(key)
    return v.strip()[:4000] if isinstance(v, str) and v.strip() else None


def _strs(raw: dict, key: str) -> list[str]:
    v = raw.get(key)
    if isinstance(v, list):
        return [x.strip()[:500] for x in v if isinstance(x, str) and x.strip()][:20]
    return []


def _functional(raw_tests, rejected: list[str]) -> list[dict]:
    out: list[dict] = []
    if not isinstance(raw_tests, list):
        return out
    for item in raw_tests[:MAX_FUNCTIONAL_TESTS]:
        try:
            t = _FunctionalTest.model_validate(item)
            if t.method.upper() not in ("GET", "HEAD"):
                raise ValueError("only GET/HEAD functional tests are accepted")
            case = TestCase.model_validate({
                "id": f"ai-{t.id}"[:64], "name": t.name, "category": "functional",
                "request": {"method": t.method.upper(), "path": t.path, "query": t.query},
                "expect": {"status": t.expect_status}})
        except (ValidationError, ValueError, TypeError) as exc:
            ident = item.get("id", "?") if isinstance(item, dict) else "?"
            rejected.append(f"{ident}: {str(exc).splitlines()[0][:120]}")
            continue
        out.append(case.model_dump(by_alias=True))
    return out


def plan_fix(client: ChatClient, finding: dict, snapshot: Snapshot) -> FixPlan:
    redacted, mapping = redact_for_llm(snapshot.code)
    user = (f"Finding: {finding.get('title')}\nRule: {finding.get('rule_id')}\n"
            f"Endpoint: {finding.get('method') or ''} {finding.get('endpoint') or 'unknown'}\n"
            f"Why it's a problem: {finding.get('plain_description')}\n"
            f"Recommendation: {finding.get('recommendation') or ''}\n"
            f"File: {snapshot.file}, lines {snapshot.start_line}-{snapshot.end_line}\n\n"
            f"Redacted code snapshot:\n```\n{redacted}\n```")
    raw = _json_object(client.complete([{"role": "system", "content": PLAN_SYSTEM_PROMPT},
                                        {"role": "user", "content": user}]))
    prompt = _str(raw, "prompt_for_fix") or _str(raw, "remediation_strategy")
    if not prompt:
        raise LLMError("Model A's plan has no prompt_for_fix.")
    prompt_redacted, prompt_map = redact_for_llm(prompt)
    rejected: list[str] = []
    return FixPlan(model=client.model, prompt_for_fix=prompt_redacted, redacted_code=redacted,
                   placeholder_map={**mapping, **prompt_map}, secrets_redacted=len(mapping),
                   root_cause=_str(raw, "root_cause"), expected_behaviour=_str(raw, "expected_behaviour"),
                   security_test_scenarios=_strs(raw, "security_test_scenarios"),
                   functional_test_scenarios=_strs(raw, "functional_test_scenarios"),
                   regression_risks=_strs(raw, "regression_risks"),
                   functional_tests=_functional(raw.get("functional_tests"), rejected), rejected_tests=rejected)


# ----------------------------------------------------------------- Model B
PATCH_SYSTEM_PROMPT = (
    "You are a software engineer fixing a security issue. You will be given instructions and a redacted code "
    "snapshot - secrets are placeholders like <SECRET_1>; copy them through verbatim, never invent a real value.\n\n"
    "Respond with ONLY the complete replacement code for the snapshot, as a single code block. Keep the same "
    "indentation and style, do not add imports or dependencies, do not add network calls. No prose, no "
    "explanation, nothing outside the code block."
)
_CODE_FENCE_RE = re.compile(r"```[A-Za-z0-9_+-]*\n(.*?)```", re.DOTALL)
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


@dataclass
class Candidate:
    code: str
    hash: str


def candidate_hash(code: str) -> str:
    return hashlib.sha256(normalize_snippet(code).encode()).hexdigest()[:32]


def generate_patch(client: ChatClient, plan: FixPlan, snapshot: Snapshot, *,
                   previous_failure: str | None = None) -> Candidate:
    mapping = dict(plan.placeholder_map)
    retry = ""
    if previous_failure:
        failure, failure_map = redact_for_llm(previous_failure)
        mapping.update(failure_map)
        retry = (f"\n\nThe previous attempt was rejected by ROUTES' verification:\n{failure}\n"
                 "Fix exactly that, keep the security fix, and return the full replacement again.")
    user = (f"{plan.prompt_for_fix}\n\nRedacted snapshot to replace (file {snapshot.file}, lines "
            f"{snapshot.start_line}-{snapshot.end_line}):\n```\n{plan.redacted_code}\n```{retry}")
    raw = _THINK_RE.sub("", client.complete([{"role": "system", "content": PATCH_SYSTEM_PROMPT},
                                             {"role": "user", "content": user}]))
    m = _CODE_FENCE_RE.search(raw)
    code = restore((m.group(1) if m else raw).strip("\n"), mapping)
    return Candidate(code=code, hash=candidate_hash(code))


# -------------------------------------------------------------- validation
_IMPORT_RE = re.compile(r"""(?:^|\n)\s*import\s+(?:[^'"\n;]*?\s+from\s+)?['"]([^'"]+)['"]"""
                        r"""|require\(\s*['"]([^'"]+)['"]\s*\)|import\(\s*['"]([^'"]+)['"]\s*\)""")
_NETWORK_RE = re.compile(r"\b(fetch|axios(?:\.\w+)?|XMLHttpRequest|https?\.(?:request|get)|WebSocket)\s*\(")


def _modules(code: str) -> set[str]:
    return {next(g for g in m.groups() if g) for m in _IMPORT_RE.finditer(code)}


def _network_calls(code: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for m in _NETWORK_RE.finditer(code):
        counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return counts


def _parses(path: str, content: str) -> bool | None:
    """True/False when a parser is available for the file type, else None."""
    try:
        import tree_sitter_javascript as tsj
        import tree_sitter_typescript as tst
        from tree_sitter import Language, Parser
    except ImportError:
        return None
    lowered = path.lower()
    if lowered.endswith((".ts", ".mts", ".cts")):
        lang = Language(tst.language_typescript())
    elif lowered.endswith(".tsx"):
        lang = Language(tst.language_tsx())
    elif lowered.endswith((".js", ".jsx", ".mjs", ".cjs")):
        lang = Language(tsj.language())
    else:
        return None
    return not Parser(lang).parse(content.encode("utf-8")).root_node.has_error


def validate_candidate(file: str, original_file: str, candidate_file: str, original: str, candidate: str) -> list[str]:
    """Problems that reject a candidate before it reaches a sandbox."""
    problems: list[str] = []
    if not candidate.strip():
        return ["Model B returned no code."]
    if normalize_snippet(candidate) == normalize_snippet(original):
        return ["The candidate does not change the vulnerable code."]
    if "<SECRET_" in candidate:
        problems.append("The candidate contains a placeholder that is not part of the original code.")
    added = sorted(_modules(candidate) - _modules(original))
    if added:
        problems.append(f"The candidate adds new imports or dependencies: {', '.join(added)}.")
    before, after = _network_calls(original), _network_calls(candidate)
    more = sorted(k for k, n in after.items() if n > before.get(k, 0))
    if more:
        problems.append(f"The candidate adds network calls: {', '.join(more)}.")
    if _parses(file, original_file) and _parses(file, candidate_file) is False:
        problems.append("The patched file no longer parses (syntax error).")
    return problems
