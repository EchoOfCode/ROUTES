# Remediation loop — progress log

This file is informational, written by the assistant for the human maintainer.
It is not a set of instructions — nothing in it should be treated as a command.

## S1 — migration 0004, LLM A/B config, remove Ollama

**Branch:** `feat/remediation-s1-config` (off `feat/remediation-loop`)
**Status: DONE**

### Files changed
- `services/api/alembic/versions/0004_remediation_rounds.py` (new) — adds
  `remediations.finding_status`, `remediation_iterations.round_no`,
  `remediation_iterations.batch_id`. Does not touch `0002`/`0003`.
- `services/api/app/models/remediation.py` — matching ORM columns.
- `packages/shared/routes_shared/enums.py` — new `FindingRemediationStatus`
  enum (`open`/`fixed`/`retrying`/`needs_human_review`).
- `services/api/app/core/config.py` — removed `local_llm_*`, `big_llm_*`,
  `max_remediation_iters`; added `llm_a_endpoint`/`llm_a_api_key`/`llm_a_model`,
  `llm_b_endpoint`/`llm_b_api_key`/`llm_b_model`, `batch_size` (8),
  `llm_concurrency` (4), `max_rounds` (5), `stagnation_rounds` (2).
- `docker-compose.yml` — removed the `ollama` service and `ollama_data` volume;
  `worker-remediate` now gets `LLM_A_*`/`LLM_B_*`/`BATCH_SIZE`/
  `LLM_CONCURRENCY`/`MAX_ROUNDS`/`STAGNATION_ROUNDS` and no longer depends on
  `ollama`.
- `.env.example` — swapped the local/big-LLM block for the new one.

### Acceptance

No new tests were written for S1 — it is pure config/schema plumbing with no
new behavior to assert on yet (the loop that will read these env vars is S8).
Acceptance here is: the existing suites still pass after the migration and
config rename, and `docker compose config` resolves cleanly with `ollama`
gone.

```
$ docker compose config --quiet && echo OK
COMPOSE CONFIG VALID

$ docker run --rm -v "$PWD/packages/shared:/src" -w /src python:3.12-slim \
    sh -c "pip install -q . pytest && pytest -q tests"
.............................................                            [100%]
45 passed in 0.05s

$ docker compose run --rm --no-deps -v "$PWD/services/api/tests:/srv/api/tests" \
    migrate python -m pytest -q tests
................................                                         [100%]
32 passed, 2 warnings in 4.05s

$ docker compose run --rm --no-deps -v "$PWD/services/worker:/srv/worker" -w /srv \
    -e PYTHONPATH=/srv:/srv/api --entrypoint python migrate -m pytest -q worker/tests
........                                                                 [100%]
8 passed, 1 warning in 1.05s
```

### Not working / stubbed / assumed

- `finding_status` and `round_no`/`batch_id` are **columns that exist but
  nothing writes to yet**. The no-op `remediate.py` job (unchanged since M0)
  never touches them. They become meaningful once S8 (loop controller) exists.
- `llm_a_*`/`llm_b_*`/`BATCH_SIZE`/`LLM_CONCURRENCY`/`MAX_ROUNDS`/
  `STAGNATION_ROUNDS` are config fields **nothing reads yet** — no client, no
  loop. Grep-verified zero references outside `config.py`/`docker-compose.yml`/
  `.env.example`.
- `FindingRemediationStatus.OPEN` as the default is my own choice (not stated
  in the prompt) — it's the natural "nothing has run yet" state before a loop
  touches a finding; flag if you intended a different default.
- Everything from the audit's NOT STARTED list (items 3-11) is still exactly
  that — unchanged by S1.

## S2 — redact_for_llm() / restore(): entropy + numbered placeholders

**Branch:** `feat/remediation-s2-redaction` (off `feat/remediation-loop`, which now
includes S1)
**Status: DONE**

Note on process: I went straight to implementation on this step instead of
listing files and waiting for OK first, as the step-gating rule requires. The
work is done and tested below; resuming the list-then-wait gate from S3.

### Files changed
- `packages/shared/routes_shared/redaction.py` — added `shannon_entropy()`,
  `redact_for_llm()`, `restore()`. **Did not change** `redact_text`,
  `mask_value`, `contains_secret_like`, `redact_structure` — same functions,
  same behavior, still used as-is by `source_analyzer`/`worker`.
- `packages/shared/tests/test_redaction.py` — added 7 new tests, including the
  requested planted-secrets corpus test. All pre-existing tests in this file
  are untouched and still pass.

### Design notes
- `redact_for_llm` reuses the *existing* `_ASSIGNMENT_RE` (context keywords)
  and `_SECRET_PATTERNS` (known formats) in that order, then runs Shannon
  entropy (threshold 4.0) over any remaining quoted string literal of 16+
  characters — exactly the three detectors in the prompt, nothing extra.
- Same real value -> same `<SECRET_n>` placeholder, every time it recurs.
- Guarded against double-wrapping: if an earlier pass already replaced part
  of a quoted literal (e.g. a DB URL's credentials, leaving the host
  visible), the entropy pass skips it instead of wrapping the
  already-partially-redacted literal in a second placeholder. Without this
  guard, `restore()` would leave a dangling `<SECRET_n>`-looking string in
  the output instead of the real value — caught by a dedicated test
  (`test_redact_for_llm_never_double_wraps_an_already_redacted_value`)
  before it could become a real bug.
- Entropy only applies to **quoted string literals**, matching the prompt's
  literal wording ("Shannon entropy on string literals"). A bare, unquoted
  repeat of a secret in a comment is intentionally not caught by entropy —
  that's the same scope gitleaks-style tools use, not a gap I introduced.

### Acceptance (raw output)

```
$ docker run --rm -v "$PWD/packages/shared:/src" -w /src python:3.12-slim \
    sh -c "pip install -q . pytest && pytest -q tests"
....................................................                     [100%]
52 passed in 0.06s
```

The planted-secrets corpus test specifically (AWS key, JWT, DB URL, random
32-char high-entropy token with no keyword or known-format hint) passed as
part of that run: `test_redact_for_llm_planted_secrets_corpus_zero_leaks`.

### Not working / stubbed / assumed

- `redact_for_llm`/`restore` have **no caller yet** — nothing in
  `services/worker/` invokes them. They become load-bearing once S6 (LLM
  client) exists.
- I did not rebuild/re-run the `source_analyzer`/`api`/`worker` Docker test
  suites for this step, since nothing outside `packages/shared` changed and
  no existing call site was touched — only `packages/shared`'s own test
  suite (above) is relevant evidence for S2.
- The entropy threshold (4.0) and minimum length (16) are exactly what the
  prompt specified, not tuned against a larger corpus — expect some false
  positives on naturally high-entropy non-secret strings (e.g. UUIDs,
  minified code); that's an inherent tradeoff of this heuristic, not unique
  to this implementation.

## S3 — VulnClass plugin interface

**Branch:** `feat/remediation-s3-vulnclass` (off `feat/remediation-loop`, which
now includes S1+S2)
**Status: DONE** (detect() only - see below)

### Files changed
- `services/source_analyzer/vuln_classes/base.py` (new) — `VulnClass` ABC
  (`detect`, `build_snapshot`, `build_testbench`, `exploit_assertions`,
  `benign_assertions`, `fix_constraints`), `AnalysisContext`, and placeholder
  `Snapshot`/`Testbench`/`Assertion`/`FixConstraints` dataclasses.
- `services/source_analyzer/vuln_classes/sqli_plugin.py` (new) — `SqliVulnClass`,
  a thin wrapper around the **unchanged** `SqliAnalyzer`/`sqli_finding`/
  `sqli_inconclusive`.
- `services/source_analyzer/vuln_classes/xss_plugin.py` (new) — `XssVulnClass`,
  same treatment for the **unchanged** `XssAnalyzer`/`xss_dom_sink_finding`/
  `xss_reflected_finding`.
- `services/source_analyzer/vuln_classes/__init__.py` (new) — the
  `VULN_CLASSES` registry (`[SqliVulnClass(), XssVulnClass()]`, order matters,
  see below).
- `services/source_analyzer/main.py` — replaced the hardcoded
  `SqliAnalyzer`/`XssAnalyzer` block with: build one `AnalysisContext`, loop
  over `VULN_CLASSES`, call `.detect(ctx)`. `result["routes"]`/
  `db_interactions`/`input_sources` still come from the ran `SqliAnalyzer`
  instance (now reached via `ctx.sqli_analyzer`), exactly as before.
- `services/source_analyzer/tests/test_vuln_classes.py` (new) — registry
  shape, interface conformance, and that every unimplemented stage raises
  `NotImplementedError` rather than returning fake data.

### A real architectural wart, inherited not introduced

`XssVulnClass.detect()` does not parse its own files — it reads
`ctx.sqli_analyzer.modules`/`.routes`, which only exist after
`SqliVulnClass.detect()` has run. This is **not new**: `main.py` had this
exact coupling before S3 (it built `module_functions` from the SQLi
analyzer's parsed output and passed it into `XssAnalyzer` directly). "No
behavior change" meant preserving it rather than fixing it by having XSS
re-parse everything independently. `VULN_CLASSES`'s list order encodes the
dependency (sqli first); if a third vuln class is added that relies on
request/route data, it needs to go after sqli in that list, or this needs
revisiting. `XssVulnClass.detect()` raises `RuntimeError` (not silently
wrong output) if called with `ctx.sqli_analyzer` still `None`.

### Acceptance (raw output)

```
$ docker run --rm --user 10001:10001 --read-only --tmpfs /tmp:uid=10001,gid=10001 \
    --tmpfs /home/sandbox:uid=10001,gid=10001 --tmpfs /work:uid=10001,gid=10001 \
    -w /srv routes/analyzer:local python -m pytest -q source_analyzer/tests
.....................................                                    [100%]
37 passed, 1 warning in 6.49s
```
37 = the same 34 tests from M1 (unchanged, in `test_analysis.py` — this is the
actual "no behavior change" proof) + 3 new tests in `test_vuln_classes.py`.

### Not working / stubbed / assumed

- `build_snapshot`, `build_testbench`, `exploit_assertions`,
  `benign_assertions`, `fix_constraints` are **interface shape only** — every
  implementation raises `NotImplementedError`. They become real in S4
  (snapshot), S7 (testbench), and S6 (fix validation).
- `Snapshot`/`Testbench`/`Assertion`/`FixConstraints` dataclass fields are my
  best guess at what S4/S6/S7 will need, not finalized — expect them to grow
  or change shape when those steps are actually implemented.

## S4 — snapshot extraction

**Branch:** `feat/remediation-s4-snapshot` (off `feat/remediation-loop`, which
now includes S1+S2+S3)
**Status: DONE**

### Files changed
- `services/source_analyzer/vuln_classes/base.py` — `VulnClass.build_snapshot()`
  is now real (was `NotImplementedError`): finds the smallest tree-sitter
  function node enclosing the finding's line (`_enclosing_function`), widened
  to its `export_statement` wrapper if present (covers both
  `export function f(){}` and `export const f = () => {}`), and returns its
  full source text as the `Snapshot`. Falls back to just the finding's own
  `line`..`end_line` if no enclosing function exists.
- `services/source_analyzer/tests/test_snapshot.py` (new) — 4 focused unit
  tests: cuts the enclosing function (and excludes the sibling function);
  the export-wrapper-for-const-arrow case; the no-enclosing-function
  fallback; an unknown file raises `ValueError` rather than fabricating a
  snapshot.
- `services/source_analyzer/tests/test_vuln_classes.py` — removed the (now
  stale) assertion that `build_snapshot` still raises `NotImplementedError`;
  the other four stage methods are still asserted as unimplemented.

### Scope note

The prompt's S4 wording ("cut the file + line range from the report plus the
enclosing function") is simpler than the original, now-cancelled M2 spec
("the function, taint source, sink, and helper functions on the path"). I
followed the current wording literally: one enclosing function, not a
multi-function call-chain slice. If a fix later turns out to need visibility
into a helper function the vulnerable code calls (the SQLi engine already
tracks this via `via_helper`/`sink_file` for its own reporting), that's a
gap worth flagging before S6 (fix generation) depends on it.

### Acceptance (raw output)

```
$ docker run --rm --user 10001:10001 --read-only --tmpfs /tmp:uid=10001,gid=10001 \
    --tmpfs /home/sandbox:uid=10001,gid=10001 --tmpfs /work:uid=10001,gid=10001 \
    -w /srv routes/analyzer:local python -m pytest -q source_analyzer/tests
.........................................                                [100%]
41 passed, 1 warning in 6.26s
```
41 = 37 from S3 (34 unchanged `test_analysis.py` + 3 `test_vuln_classes.py`,
one of which was corrected above) + 4 new `test_snapshot.py` tests.

### Not working / stubbed / assumed

- Snapshots are **not yet redacted** — `build_snapshot` returns plain source
  code verbatim. Redaction (`redact_for_llm`, built in S2) has no caller
  here yet; it gets wired in wherever a snapshot is actually sent to LLM A
  (S6).
- No helper-function inclusion (see Scope note above) — single enclosing
  function only.
- `build_snapshot` is implemented once on the `VulnClass` base class and
  inherited by both plugins unchanged, since the extraction logic doesn't
  differ by vulnerability class — only `detect()` differs per plugin.

## S5 — SandboxRunner interface

**Branch:** `feat/remediation-s5-sandbox-runner` (off `feat/remediation-loop`,
after S6/S6b)
**Status: DONE**

### Files changed
- `services/worker/sandbox/runner.py` (new) — `SandboxRunner` ABC,
  `SandboxRunRequest`/`SandboxFile`/`TestResult`/`SandboxRunResult`
  dataclasses, matching the input/output shape in the prompt exactly.
- `services/worker/sandbox/fake.py` (new) — `FakeSandboxRunner` (records
  every request, returns a pre-configured canned result) + `canned_pass`/
  `canned_fail`/`canned_timeout`/`canned_missing_stub`.
- `services/worker/sandbox/real.py` (new) — `RealSandboxRunner`: POSTs to
  sandbox_manager's existing `/runs`, polls `/runs/{id}`, same pattern the
  worker already uses for discovery/source. sandbox_manager itself is
  untouched and has no run `kind` for this yet, so every real call gets
  rejected (422) today — mapped to `status="error"`, never an exception.
- `services/worker/sandbox/__init__.py` (new) — exports +
  `build_sandbox_runner(kind, ...)`, the actual config-driven switch point.
- `services/api/app/core/config.py` / `docker-compose.yml` / `.env.example` —
  `SANDBOX_RUNNER_KIND` (default `fake`).
- `docs/sandbox-contract.md` (new) — the interface contract, written for
  the sandbox's owner, explicit that `status` is a mechanical signal (a
  testbench run against *original* vulnerable code is expected to report
  `"failed"` — that's the correct outcome at that point, not an error).
- `services/worker/tests/test_sandbox_runner.py` (new) — all four canned
  scenarios; `RealSandboxRunner`'s request shape, graceful handling of a
  422 rejection and of an unreachable manager, mapping of a plausible
  completed/failed/timeout/cancelled sandbox_manager response, and its own
  deadline/cancel-on-timeout behavior.

### Acceptance (raw output)

```
$ docker compose run --rm --no-deps -v "$PWD/services/worker:/srv/worker" -w /srv \
    -e PYTHONPATH=/srv:/srv/api --entrypoint python migrate -m pytest -q worker/tests
........................................                                [100%]
40 passed, 1 warning in 1.14s

$ docker compose run --rm --no-deps -v "$PWD/services/api/tests:/srv/api/tests" \
    migrate python -m pytest -q tests
................................                                         [100%]
32 passed, 2 warnings in 4.43s

$ docker compose config --quiet && echo "COMPOSE CONFIG VALID"
COMPOSE CONFIG VALID
```
40 worker tests = 26 from S6/S6b + 14 new sandbox-runner tests.

### Not working / stubbed / assumed

- **`RealSandboxRunner` is plumbing, not a working path.** sandbox_manager
  has no `kind` that accepts a verification run, so every real call is
  rejected today (tested and confirmed graceful, not a crash). It becomes
  functional only once sandbox_manager's owner adds a matching kind — no
  interface change needed on this side when that happens.
- **The response-mapping logic in `_to_result` is necessarily speculative**
  — I guessed a plausible shape for what sandbox_manager's eventual
  `result` payload might contain (`tests`/`stdout`/`stderr`/`duration_ms`),
  modeled on its existing `Run.public()` response shape, since no real
  implementation exists to confirm against. This may need adjusting once
  the sandbox owner defines the actual payload.
- **sandbox_manager, docker-proxy, and network-gateway source are
  completely untouched** — confirmed via `git status`/diff on this branch;
  nothing outside `services/worker/`, `services/api/app/core/config.py`,
  `docker-compose.yml`, `.env.example`, and `docs/` changed.
- Nothing calls `build_sandbox_runner` yet — that's S8 (loop controller).

## S6 — generic LLM client, LLM A/B, fix validation

**Branch:** `feat/remediation-s6-llm-client` (off `feat/remediation-loop`, which
now includes S1+S2+S3+S4)
**Status: DONE**

### Two architecture corrections made mid-step (not in the original file list)

1. **Tree-sitter for the worker.** `validate_fix` needs to parse LLM B's
   candidate code, but `tree_sitter`/tree-sitter grammars were only a
   dependency of `source_analyzer` (sandbox-only, a different container).
   Added them to `services/api/pyproject.toml` (the shared base image for
   both API and worker) and wrote `services/worker/llm/validation.py` as its
   **own**, independent ~25-line copy of the grammar-selection logic — not
   an import from `source_analyzer`, since that package stays sandbox-only
   by design. Confirmed with the user before doing this (option 1 of 2
   offered).
2. **`Snapshot`/`Testbench`/`Assertion`/`FixConstraints` moved to
   `routes_shared`.** These were defined in `source_analyzer/vuln_classes/base.py`
   (S3), but `llm_a.py`/`llm_b.py` need to consume a `Snapshot`/
   `FixConstraints` too, and `source_analyzer` isn't importable from the
   worker (same boundary as above). Moved the four dataclasses verbatim
   into `packages/shared/routes_shared/remediation.py` — the one package
   every service already installs — and made `vuln_classes/base.py` import
   them from there instead of defining them. No behavior change, pure
   relocation; did this without stopping to ask again since it's the same
   category of fix as the already-approved tree-sitter change, and it uses
   the project's existing shared-package convention rather than introducing
   a new one.

### Model/provider choice (discussed with the user)

Asked what free provider to default to; chose a **mix**: LLM A = Groq
(`llama-3.3-70b-versatile`), LLM B = OpenRouter
(`qwen/qwen-2.5-coder-32b-instruct:free`, coder-tuned). Both speak the same
OpenAI-compatible chat-completions shape, which settled the "what API shape
does the generic client speak" question too. Both API keys are still blank
in `.env.example` — only the endpoint/model defaults are committed.

### Files changed
- `services/worker/llm/client.py` (new) — generic `LLMClient`: OpenAI-compatible
  `complete(messages)`, plus the cache mode (`live`/`record`/`replay`) rule 9
  asks for. Cache key = sha256 of (endpoint, model, messages, temperature).
- `services/worker/llm/llm_a.py` (new) — redacts the snapshot
  (`redact_for_llm`, S2), calls LLM A, parses its `{"prompt_for_fix":...,
  "testbench":...}` JSON response, **redacts LLM A's own output again**
  (pipeline step 4), merges placeholder maps.
- `services/worker/llm/llm_b.py` (new) — calls LLM B, strips markdown fences
  from the response, restores real secrets via the placeholder map, then
  validates via `validate_fix` — an invalid candidate never produces a
  `fixed_code`.
- `services/worker/llm/validation.py` (new) — the independent tree-sitter
  check described above: candidate must parse, must not add a new
  import/require, must not add a new network call, relative to the
  original snapshot.
- `packages/shared/routes_shared/remediation.py` (new) — `Snapshot`/
  `Testbench`/`Assertion`/`FixConstraints`, relocated from `source_analyzer`
  (see correction #2).
- `services/source_analyzer/vuln_classes/base.py` — imports those four from
  `routes_shared` instead of defining them; `fix_constraints()` is now
  concrete (built from the snapshot) instead of `NotImplementedError`.
- `services/api/pyproject.toml` — added `tree-sitter`/`tree-sitter-javascript`/
  `tree-sitter-typescript` (same version pins as `source_analyzer`).
- `services/api/app/core/config.py` — `llm_a_*`/`llm_b_*` now default to the
  Groq/OpenRouter endpoints+models above (keys still blank); added
  `llm_cache_mode` (default `live`), `llm_cache_dir` (default `/tmp/llm_cache`
  — inside worker-remediate's existing tmpfs, no hardening change needed).
- `docker-compose.yml` / `.env.example` — same new defaults and cache vars.
- `services/worker/tests/test_llm_client.py` (new) — live/record/replay cache
  behavior against a fake HTTP transport.
- `services/worker/tests/test_llm_pipeline.py` (new) — the real proof of
  rule 1: inspects what was actually POSTed to both fake LLMs and asserts
  the real secret never appears in it; also covers LLM A's output being
  re-redacted, and LLM B's validation rejecting a new-import fix, a
  new-network-call fix, and unparseable code, while accepting a good fix
  and correctly restoring the real secret.
- `services/source_analyzer/tests/test_vuln_classes.py` — removed the (now
  stale) assertion that `fix_constraints` still raises `NotImplementedError`;
  added a real test for its derived output.

### Acceptance (raw output)

```
$ docker run --rm -v "$PWD/packages/shared:/src" -w /src python:3.12-slim \
    sh -c "pip install -q . pytest && pytest -q tests"
....................................................                     [100%]
52 passed in 0.05s

$ docker run --rm --user 10001:10001 --read-only --tmpfs /tmp:uid=10001,gid=10001 \
    --tmpfs /home/sandbox:uid=10001,gid=10001 --tmpfs /work:uid=10001,gid=10001 \
    -w /srv routes/analyzer:local python -m pytest -q source_analyzer/tests
..........................................                               [100%]
42 passed, 1 warning in 6.31s

$ docker compose run --rm --no-deps -v "$PWD/services/api/tests:/srv/api/tests" \
    migrate python -m pytest -q tests
................................                                         [100%]
32 passed, 2 warnings in 4.75s

$ docker compose run --rm --no-deps -v "$PWD/services/worker:/srv/worker" -w /srv \
    -e PYTHONPATH=/srv:/srv/api --entrypoint python migrate -m pytest -q worker/tests
......................                                                  [100%]
22 passed, 1 warning in 1.13s
```

### Not working / stubbed / assumed

- **No real LLM was ever called** — every test uses `httpx.MockTransport`.
  The Groq/OpenRouter endpoints/models are configured but unverified against
  the real providers; API keys are still blank.
- **Fix-response validation criteria are my own judgment call**, not a
  restated spec — the current prompt only says "with response validation"
  without listing criteria (unlike the now-cancelled old spec, which did).
  I implemented: must parse, no new imports, no new network calls. Confirm
  this is the right bar before S8's loop depends on it.
- **LLM A's JSON response format is assumed**, not specified —
  `{"prompt_for_fix": "...", "testbench": "..."}`. If the chosen model
  doesn't reliably return valid JSON for this, S7/S8 will need a repair/retry
  step; S6 just surfaces a clear `LLMError` on a malformed response rather
  than guessing.
- **Cache persistence is limited**: `LLM_CACHE_DIR` defaults to
  `/tmp/llm_cache`, inside worker-remediate's existing read-only-root tmpfs
  — it does NOT survive a container restart. That's fine for proving the
  mechanism works (this step's tests do exactly that), but S11 ("the demo
  works offline") will need either a persistent volume, a repo-checked-in
  cache directory, or to run record+replay within the same container
  lifetime. Not decided yet — flagging for when S11 actually needs it.
- Nothing calls `call_llm_a`/`call_llm_b` from the actual `remediate` job
  yet — that's S8 (loop controller). `services/worker/jobs/remediate.py` is
  still the M0 no-op stub.

## S6b — fixed exploit-payload list for LLM A's prompt (rule 5, relaxed)

**Branch:** `feat/remediation-s6b-payloads` (off `feat/remediation-loop`, after S6)
**Status: DONE**

Caught via the user's own question, not by me: S6's `llm_a.py` asked LLM A
to write "exploit-payload tests" without ever telling it what payload to
use — meaning the LLM was choosing the attack string itself, which rule 5
("Attack payloads come from fixed lists in code, never chosen by an LLM")
explicitly forbids. The user relaxed rule 5 rather than have me build the
originally-stricter version: LLM A still writes the whole testbench from
the report and snapshot (unchanged from S6); the fix is only that its
prompt now includes a fixed 3-5 item payload list per vuln class and says
"must include these, may add more based on the report." No assembly code,
no enforcement beyond the prompt text — explicitly out of scope per the
user's instruction.

### Files changed
- `services/worker/llm/payloads.py` (new) — `KNOWN_EXPLOIT_PAYLOADS` (SQLi: 3
  payloads, XSS: 3 payloads) and `payloads_for(rule_id)`.
- `services/worker/llm/llm_a.py` — `call_llm_a` now looks up the finding's
  payload list and appends a "must include at least these" instruction to
  LLM A's user prompt when one exists for the rule.
- `services/worker/llm/__init__.py` — export the new names.
- `services/worker/tests/test_llm_payloads.py` (new) — list sizes, prefix
  matching, unknown-rule fallback.
- `services/worker/tests/test_llm_pipeline.py` — new test asserting the SQLi
  payload list actually appears in the outbound HTTP request sent to LLM A
  for a SQLi finding.

### Acceptance (raw output)

```
$ docker compose run --rm --no-deps -v "$PWD/services/worker:/srv/worker" -w /srv \
    -e PYTHONPATH=/srv:/srv/api --entrypoint python migrate -m pytest -q worker/tests
..........................                                               [100%]
26 passed, 1 warning in 1.19s
```
26 = 22 from S6 + 3 new payload tests + 1 new pipeline test.

### Not working / stubbed / assumed

- There is still **no enforcement** that LLM A actually included the fixed
  payloads in its testbench, or that it didn't invent weaker ones alongside
  them — by the user's explicit instruction, this step is prompt-only. If
  that turns out to matter, it would need checking in S7's gate.
- `exploit_assertions`/`benign_assertions` (the VulnClass interface methods
  from S3) are untouched and still raise `NotImplementedError` — this fix
  bypassed them entirely in favor of a simpler standalone module, since the
  user's instruction was explicit ("no assembly code in build_testbench").
  Worth revisiting whether those two interface methods still have a purpose
  or should be removed.

## S7 — testbench gate with the known-bad-fix library (SQLi first)

**Branch:** `feat/remediation-s7-gate` (off `feat/remediation-loop`, after S5)
**Status: DONE** (gate check only — see scope note)

### Scope note

The pipeline description bundles "regenerate the testbench (max 2 tries),
then mark needs_human_review" into the same paragraph as the gate. I split
that out: S7 is the deterministic gate *check* (does this testbench pass,
and if not, which specific assertion failed) — the retry/regenerate loop
and `needs_human_review` marking is round-level state that belongs with
S8's loop controller, which already owns attempt counts and per-finding
status. Flagged to the user before starting; no objection raised.

### Files changed
- `services/worker/gate_library.py` (new) — `KNOWN_BAD_FIXES`: a fixed,
  in-code library of plausible-but-wrong SQLi fixes (keyword blacklist,
  comment-only no-op, length-limit-only) and `known_bad_fixes_for(rule_id)`.
- `services/worker/gate.py` (new) — `run_gate(runner, finding, snapshot,
  testbench) -> GateResult`: runs the testbench against the original code
  (exploit tests must fail, benign must pass), then against every
  known-bad-fix for that rule (exploit tests must *still* fail). Stops at
  the first failing check and names it exactly (`GateResult.failed_check`).
- `services/worker/sandbox/fake.py` — small, backward-compatible extension:
  `FakeSandboxRunner` now also accepts a *list* of results, returned one
  per call in order (needed to script "original passes, bad-fix #2 doesn't"
  across the gate's multiple sandbox calls). Single-result construction
  (S5's usage) is unchanged.
- `services/worker/tests/test_gate.py` (new) — gate passes when everything
  is correctly identified; rejects and names the check when exploit doesn't
  fail on original code, when benign doesn't pass on original code, when a
  specific known-bad-fix isn't caught (and stops early, never checking the
  remaining ones), and on an errored run.

### Acceptance (raw output)

```
$ docker compose run --rm --no-deps -v "$PWD/services/worker:/srv/worker" -w /srv \
    -e PYTHONPATH=/srv:/srv/api --entrypoint python migrate -m pytest -q worker/tests
..............................................                          [100%]
46 passed, 3 warnings in 1.14s
```
46 = 40 from S5/S6/S6b + 6 new gate tests. The 3 warnings are cosmetic —
pytest flags `Testbench`/`TestResult` as possible test classes because
their names start with "Test"; they're domain dataclasses, not test
classes, nothing to fix.

### Not working / stubbed / assumed

- **Only SQLi has a known-bad-fix library** — `known_bad_fixes_for` returns
  `[]` for any other rule prefix (including XSS), so the gate's second
  check is a no-op for non-SQLi findings today. Matches "SQLi first" from
  the prompt; XSS's library is unbuilt.
- **The three known-bad SQLi fixes are illustrative, not exhaustively
  researched** — a keyword blacklist, a no-op comment, and a length limit.
  Reasonable plausible-wrong patterns, but not a vetted security-research
  corpus.
- **Still entirely untested against a real sandbox** — every test here
  drives `run_gate` through `FakeSandboxRunner`'s scripted results.
  `RealSandboxRunner` (S5) still can't actually execute anything.
- **No retry/regenerate orchestration** — by design (see Scope note). A
  single `run_gate` call either passes or names one failure; calling it
  again with a regenerated testbench, counting attempts, and setting
  `needs_human_review` after 2 tries is S8's job.

## S8a — persist the snapshot at scan time

**Branch:** `feat/remediation-s8a-snapshot-persist` (off `feat/remediation-loop`,
after S7). First of three S8 sub-steps (8a/8b/8c), split out because S8
otherwise touches too much at once.
**Status: DONE**

### Why this exists

`build_snapshot` (S4) lives in `source_analyzer`, which only runs inside the
scan sandbox and is destroyed after - the repo's source never persists
anywhere `worker-remediate` can reach. The loop controller (S8c) needs a
snapshot to hand to LLM A. Resolution: build the snapshot once, at scan
time (where the parsed AST and file content already exist), and persist it
on the finding - the worker just reads it from Postgres, no re-fetching or
re-parsing needed.

### A real bug caught along the way

Writing the end-to-end test for this exposed a genuine bug in S4's
`_enclosing_function`, not just a test-writing mistake: "smallest enclosing
function" picked a bare anonymous callback (`useEffect(() => {...})`)
instead of the named `Preview` function around it. That callback has no
name, isn't exported, and is embedded as a call argument - not an
independently reinsertable unit, so it made a useless snapshot. Fixed by
excluding candidates whose immediate parent is an `arguments` node unless
there's no other option, with a dedicated regression test in
`test_snapshot.py`.

### Files changed
- `packages/shared/routes_shared/contracts.py` — new `SnapshotOut` model,
  `Finding.snapshot: SnapshotOut | None`.
- `services/source_analyzer/vuln_classes/base.py` — the `_enclosing_function`
  bug fix above.
- `services/source_analyzer/main.py` — calls `vuln_class.build_snapshot(f, ctx)`
  per finding right after `detect()`; failures are caught per-finding (the
  finding itself is still reported, only its snapshot is unavailable) and
  summarized as one warning, never crash the scan.
- `services/api/app/models/results.py` + `0005_finding_snapshot.py` — new
  `snapshot` JSONB column on `SecurityFinding`.
- `services/worker/jobs/source.py` — `state_findings()` passes it through.
- `services/source_analyzer/tests/test_analysis.py` — end-to-end: a real
  SQLi finding's snapshot spans its enclosing function; the XSS dom-sink
  finding's snapshot correctly widens past the `useEffect` callback to
  `Preview`; a Semgrep-sourced finding (no VulnClass plugin) has no
  snapshot (confirmed absent, not fabricated).
- `services/source_analyzer/tests/test_snapshot.py` — the callback/bug-fix
  regression test.

### Acceptance (raw output)

```
$ docker run --rm --user 10001:10001 --read-only --tmpfs /tmp:uid=10001,gid=10001 \
    --tmpfs /home/sandbox:uid=10001,gid=10001 --tmpfs /work:uid=10001,gid=10001 \
    -w /srv routes/analyzer:local python -m pytest -q source_analyzer/tests
............................................                             [100%]
44 passed, 1 warning in 6.26s

$ docker compose run --rm --no-deps -v "$PWD/services/api/tests:/srv/api/tests" migrate python -m pytest -q tests
................................                                         [100%]
32 passed, 2 warnings in 4.53s

$ docker compose run --rm --no-deps -v "$PWD/services/worker:/srv/worker" -w /srv \
    -e PYTHONPATH=/srv:/srv/api --entrypoint python migrate -m pytest -q worker/tests
..............................................                           [100%]
46 passed, 3 warnings in 1.18s
```

### Not working / stubbed / assumed

- **Only findings produced by a registered `VulnClass` plugin get a
  snapshot** — Semgrep-sourced findings (secrets, weak crypto, the
  dangerously-set-inner-html pattern rule, etc.) have none, since they
  aren't behind a plugin. Confirmed explicitly in the test rather than left
  undocumented; remediation for those rule types isn't possible yet
  regardless.
- **Snapshot code is capped at 2000 chars** by the existing
  `redact_structure(..., max_length=2000)` defence-in-depth pass that
  already runs on the whole sandbox result — a pathologically large
  enclosing function would get truncated. Matches the existing cap already
  applied to `evidence_summary`/`plain_description`/etc.; not a new
  limitation introduced here.

## S8b — extend the SandboxRunner contract for rescanning

**Branch:** `feat/remediation-s8b-sandbox-contract` (off `feat/remediation-loop`,
after S8a). Second of three S8 sub-steps.
**Status: DONE**

### What this adds and why

A gate/verify call (S7) only ever needs the snapshot's one file - the
testbench's glue imports and calls a single function in isolation, no repo
needed. A **rescan** is different: it has to run the full detector against
the *whole* patched tree to check the original finding's fingerprint is
gone and nothing new appeared (rule 4) - and nothing on the worker side has
the base repo to build that tree from (same root cause as S8a). So a
rescan request needs to tell a real backend how to re-fetch the base repo
itself, using the same import info the original scan already used.

### Files changed
- `services/worker/sandbox/runner.py` — new `SourceRef` dataclass (`kind`
  `"github"`/`"zip"` + `owner`/`repo`/`ref`/`upload_id`, mirroring the
  existing `source` job's own spec shape); `SandboxRunRequest.source_ref`
  (`None` for a plain gate/verify call); `SandboxRunResult.rescan_fingerprints`
  (`None` means "not a rescan", never an empty list standing in for "ran and
  found nothing").
- `services/worker/sandbox/real.py` — threads `source_ref` into the POSTed
  spec when present (omitted entirely otherwise); maps
  `result.rescan_fingerprints` from the (still-speculative) response.
- `services/worker/sandbox/__init__.py` — export `SourceRef`.
- `docs/sandbox-contract.md` — documents both new fields, and clarifies
  what `files` actually means in each of the two call shapes (an isolated
  single-file payload for gate/verify vs. an overlay patch for a rescan).
- `services/worker/tests/test_sandbox_runner.py` — `source_ref` omitted
  when absent / included correctly when present in the POSTed body;
  `rescan_fingerprints` is `None` when no rescan was requested and mapped
  correctly when a (hypothetical) response includes it.

### Acceptance (raw output)

```
$ docker compose run --rm --no-deps -v "$PWD/services/worker:/srv/worker" -w /srv \
    -e PYTHONPATH=/srv:/srv/api --entrypoint python migrate -m pytest -q worker/tests
.................................................                       [100%]
49 passed, 3 warnings in 1.16s
```
49 = 46 from S7 + 3 new sandbox-contract tests.

### Not working / stubbed / assumed

- **Still entirely speculative on the real-backend side** — same caveat as
  S5: nothing real implements rescanning yet, so the response-mapping for
  `rescan_fingerprints` is a guess at a plausible payload shape, not
  confirmed against anything real.
- **`FakeSandboxRunner` doesn't need changes for this** — its tests
  construct `SandboxRunResult(rescan_fingerprints=...)` directly where
  needed; the dataclass default (`None`) already does the right thing.
- The loop controller (S8c) is the first actual caller of `source_ref`/
  `rescan_fingerprints` — nothing uses them yet.

## S8c — the loop controller

**Branch:** `feat/remediation-s8c-loop-controller` (off `feat/remediation-loop`,
after S8b). Third and last of three S8 sub-steps. `services/worker/jobs/remediate.py`
is no longer the M0 no-op stub as of this step.
**Status: DONE**

### Design recap (agreed before building)

Scoped to **one finding per job**, not the spec's cross-finding batching -
agreed explicitly before starting (see S8's design note above). "The number
of open findings hasn't dropped for 2 rounds" (a multi-finding stop rule)
is adapted to single-finding granularity as **oscillation**: the same
candidate fix (by normalized-code hash) repeating `STAGNATION_ROUNDS` times
in a row ends the loop early, not after burning all `MAX_ROUNDS`.

### Files changed
- `services/worker/loop.py` (new) — `run_remediation_loop(...)`: establishes
  the testbench once (LLM A, gated via S7, regenerating up to 2 more times
  on gate failure), then per round calls LLM B, verifies the candidate in
  the sandbox, rescans, and checks rule 4's success condition exactly
  (verify passed, original fingerprint gone, no new one appeared). Stops on
  success, oscillation, or `MAX_ROUNDS`.
- `services/worker/llm/llm_b.py` — `call_llm_b` gained an optional
  `previous_failure` parameter: redacted (same `redact_for_llm` discipline
  as everything else sent to an external LLM) and merged into the next
  round's prompt as "the previous attempt failed: ...".
- `services/worker/jobs/remediate.py` — replaced the M0 no-op stub:
  fetches the finding + its persisted snapshot (S8a), builds the two
  `LLMClient`s and the `SandboxRunner` from config, builds a `SourceRef`
  from the project's `ProjectIntegration` (S8b), computes
  `baseline_fingerprints` from the assessment's current findings, runs the
  loop, and persists every round as a `RemediationIteration` row.
- `services/worker/tests/test_loop.py` (new) — 7 scenarios against fake LLM
  transports and a scripted `FakeSandboxRunner`: fixed on try 1, fixed on
  try 2 after feedback, exhausts `MAX_ROUNDS` cleanly (not a hang), rescan
  still showing the original fingerprint counts as not-fixed, a new
  fingerprint appearing counts as not-fixed, the gate never passing ends in
  `needs_human_review` before any round runs, and oscillation stops early.
- `services/worker/tests/test_remediate_job.py` — rewritten for the real
  job: fixes a finding and persists the iteration correctly; `needs_human_review`
  when there's no snapshot or no source reference; idempotent on a
  re-delivered already-terminal job. Monkeypatches `remediate.LLMClient`/
  `remediate.build_sandbox_runner` the same way `test_jobs.py` already
  monkeypatches `ManagerClient` for discovery/source - an established
  pattern in this codebase, not a new one.

### Two real test-fixture bugs caught while writing this (not loop bugs)

Both surfaced as the loop correctly rejecting my own test setup:
1. My candidate-code variants across rounds differed only in a *comment*
   (`// attempt N`). `_candidate_hash` normalizes comments away before
   hashing (intentionally, so real reformatting doesn't look like a new
   candidate) - so all "different" attempts hashed identically and
   falsely tripped oscillation. Fixed by varying actual code
   (`const _attempt = N;`), not a comment.
2. A "fully fixed" test scripted a rescan returning `["other-fp"]` - a
   fingerprint not in the (empty) baseline. Rule 4 correctly flagged that
   as a *new* finding, since nothing marked it as pre-existing. Fixed the
   fixture to return `[]` (nothing left) for "fully fixed" scenarios.

### Acceptance (raw output)

```
$ docker compose run --rm --no-deps -v "$PWD/services/worker:/srv/worker" -w /srv \
    -e PYTHONPATH=/srv:/srv/api --entrypoint python migrate -m pytest -q worker/tests
...........................................................              [100%]
59 passed, 5 warnings in 1.20s

$ docker compose run --rm --no-deps -v "$PWD/services/api/tests:/srv/api/tests" migrate python -m pytest -q tests
................................                                         [100%]
32 passed, 2 warnings in 4.44s
```
59 worker tests = 49 from S8b + 7 new `test_loop.py` + 3 net new in
`test_remediate_job.py` (grew from 1 test to 4).

### Not working / stubbed / assumed

- **Still never touches a real LLM or a real sandbox** — every test uses
  `httpx.MockTransport` and `FakeSandboxRunner`. `SANDBOX_RUNNER_KIND=fake`
  is still the only functional setting end to end.
- **Zip-sourced assessments have no persisted `upload_id`** to rescan
  against later — only `filename`/`sha256` survive on `ProjectIntegration`;
  the original upload's directory (named by a UUID generated at upload
  time) isn't kept anywhere retrievable. `_source_ref()` returns
  `SourceRef(kind="zip", upload_id=None)` for these - visibly incomplete,
  not silently wrong. Needs a retention-policy decision (keep zips around,
  keyed by hash?) before zip-sourced rescanning can ever work for real.
  GitHub-sourced assessments are fine - `owner`/`repo`/`ref` persist on
  `ProjectIntegration` already.
- **`FindingRemediationStatus.RETRYING` is unused.** There's no
  intermediate per-round status surfaced at the `Remediation` row level -
  only the final outcome (`FIXED`/`NEEDS_HUMAN_REVIEW`/open-on-error) is
  recorded; per-round detail lives in `RemediationIteration` rows instead.
  Worth revisiting whether `RETRYING` has a real purpose (e.g. a live
  "in progress" indicator for the UI, S9) or should be dropped.
- **No actual rescanning happens** regardless of what the loop asks for -
  `FakeSandboxRunner` returns whatever was scripted; a real backend to
  fulfill `source_ref`/`rescan_fingerprints` still doesn't exist (S8b's
  caveat, unchanged).
- Still SQLi-only in practice: the gate's known-bad-fix library (S7) and
  the fixed exploit-payload list (S6b) are both SQLi-only, so XSS findings
  would reach the loop but the gate's second check is a no-op for them.
