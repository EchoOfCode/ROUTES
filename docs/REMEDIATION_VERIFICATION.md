# Real verification for AI remediation

The remediation worker verifies candidate fixes in the **same Build & Run engine** as `routes verify`. There
is one implementation: the Sandbox Manager's `build_run` run kind (build runner, synthetic PostgreSQL,
trusted test runner). It is reached through `routes_core.buildrun`, with typed results from
`routes_core.verification`. Persistence, verdict rules and the attempt limit are unchanged from
[REMEDIATION_DATA_MODEL.md](REMEDIATION_DATA_MODEL.md).

## Integration map

| Concern | Component | Status |
|---|---|---|
| Build, start and test an app | Sandbox Manager `build_run` (`manager/buildrun.py`), `build_runner`, `test_runner` | Reused unchanged except for two additions: the commit is recorded, and the cleanup outcome is recorded |
| Client used by both CLI and worker | `routes_core.buildrun.submit/wait` | Reused (the CLI already used it) |
| Typed results, failure evidence, rescans | `routes_core.verification` | **New** shared service |
| Worker adapter | `worker/sandbox/buildrun.py` `BuildRunSandboxRunner` (`SANDBOX_RUNNER_KIND=build_run`) | **New**; replaces the old `remediate_verify` runner, which requested a run type that never existed. `real` is now an alias |
| Rescan of the patched tree | Manager `source` run with an optional, validated `patch`; analyzer applies it strictly (`routes_shared.patching.apply_unified_diff`) | **New** |
| Exact revision | GitHub archive pax header → `ExtractionReport.commit_sha` → `SourceResult.source_commit` → `assessment.discovery_summary.source_commit` → `remediations.source_commit_sha` | **New**; every baseline, candidate and rescan is pinned to it, and the engine's reported commit is checked |
| Model egress | Gateway `models` session on the internal `model-egress` network | **New**; replaces the worker's direct internet access |

No new microservice and no new sandbox type were needed: the existing `build_run` kind already has every
property required (isolated containers, registry-only install, network cut-off, private test network,
limits, cleanup). No Docker proxy or gateway restriction was relaxed.

## The flow (per patch batch)

1. **Context and redaction.** Recorded as before.
2. **Testbench.**
   - Security tests are generated deterministically by ROUTES from the finding's traced data flow
     (`routes_core.testplan`): a quote probe and a stacked `pg_sleep` probe on the exact input.
   - Model A is called in structured mode (`worker/llm/llm_a_plan.py`). It returns root cause, strategy,
     expected behaviour, security and functional scenarios, regression risks, the context it relied on,
     and optional functional HTTP tests.
   - Each field is validated; an invalid field is dropped, never filled in. Functional tests must match
     the test-plan schema and be GET or HEAD.
   - If no deterministic security test can be generated, the finding is `inconclusive`.
3. **Baseline** (`baseline_gate`). The original revision is built, started and tested in a fresh sandbox.
   - It is valid only if the app builds and starts *and* at least one security test **fails** (the
     vulnerability is reproduced). A test error never counts as a reproduction.
   - Functional tests that do not pass on the original are removed: they cannot detect a regression.
     They are recorded as rejected.
   - The baseline is deterministic, so a failed baseline is not "retried" by regenerating Model A.
4. **Patch.** Model B returns replacement code for the snapshot region. ROUTES derives a unified diff
   positioned in the real file, then validates its structure, paths and batch file scope. Model B's
   output is never executed.
5. **Candidate.** A fresh sandbox per attempt, built from a clean copy of the pinned revision with the
   patch applied inside the sandbox:
   - The candidate passes only on `VERIFIED_RUN`: every test case passed, decided by the trusted test
     runner, with no isolation violation, and with the engine confirming the patch was applied.
   - A build or startup failure counts as an application failure.
   - Engine or infrastructure problems count as `error`.
6. **Correction.** The sanitised failure evidence (failing tests, how they differed from what was
   expected, the build error) goes to Model B. The database-enforced limit of 3 attempts per batch
   remains authoritative.
7. **Rescan.** The full static analysis (Semgrep, tree-sitter, data flow) runs on the patched tree in the
   analyzer sandbox and is compared with the original assessment:
   - Findings are matched by content fingerprint **and** identity (rule, file, endpoint, method).
   - An untargeted finding whose code the patch touched is "remaining", never "resolved" and never
     "new".
   - A targeted finding that is merely re-fingerprinted means the vulnerability is **still present**.
8. **Verdict.** The existing rules apply unchanged. `verified_fixed` requires all of:
   - a validated testbench;
   - a reproduced baseline;
   - a passed candidate run;
   - a confirming rescan with no new finding;
   - real sandbox evidence (`evidence_grade = sandbox`).

Each verification run records:
- sandbox id;
- build, startup and database status;
- every test result, with an explicit `error` outcome;
- sanitised logs;
- commit;
- whether the patch was applied;
- duration;
- the manager's cleanup outcome.

An incomplete cleanup is also written to the audit trail (`sandbox_cleanup_incomplete`).

## Sources that can be verified

| Source | Result |
|---|---|
| GitHub, assessment recorded the commit | Verified against that exact commit |
| GitHub, older assessment without a commit | `inconclusive` ("re-run the assessment") |
| ZIP upload (web stack) | `inconclusive`: the upload is not retained, and ROUTES never rebuilds a source from a snapshot |
| Retained immutable archive (`SourceRef(kind="archive", sha256=...)`) | Verified; the SHA-256 is checked before every use. Used by the CLI-side end-to-end test |

## Model-provider egress

- **Network.** `worker-remediate` is no longer on the `egress` network. It sits on `backend` plus the
  internal `model-egress` network, whose only other member is the network gateway.
- **Gateway session.** At startup the gateway creates one fixed `models` session bound to that subnet. It
  allows HTTPS `CONNECT` on port 443 only, to `MODEL_EGRESS_HOSTS` (default `api.groq.com,openrouter.ai`).
- **Worker client.** The LLM client uses that proxy explicitly (`LLM_PROXY_URL`, `trust_env=False`).
- **Fail-closed.** Without `MODEL_EGRESS_TOKEN` there is no route at all.
- **Keys.** Provider API keys stay in the worker. The sandbox never receives a model key, a GitHub token or
  a developer credential.

## Running it

```powershell
# .env: LLM_A_API_KEY, LLM_B_API_KEY, SANDBOX_RUNNER_KIND=build_run, MODEL_EGRESS_TOKEN=<32+ random chars>
docker compose build                                     # engine images: manager, analyzer, build-runner, gateway
docker compose up -d                                     # engine (CLI) incl. the gateway's model route
docker exec routes-postgres-1 pg_dump -U routes routes > backup.sql
docker compose --profile web up -d --build               # applies migration 0008 to the web database
```

Then re-run the assessment of a GitHub project, so the commit is recorded, and click **Fix this** on a SQL
injection finding.

### The real end-to-end test

`scripts/remediation_e2e.py`:
- analyses the bundled SQL-injection fixture in the real analyzer sandbox;
- runs the real job;
- builds and tests the original, a wrong fix and a correct fix in real sandboxes;
- rescans the patched tree.

Only the two models' replies are scripted, and the script prints that. It needs the engine and a
throwaway PostgreSQL. How it was run for this change:

```powershell
docker network create routes-dbtest
docker run -d --name routes-dbtest-pg --network routes-dbtest -e POSTGRES_USER=routes `
  -e POSTGRES_PASSWORD=testonly -e POSTGRES_DB=routes_test --tmpfs /var/lib/postgresql/data postgres:16-alpine
docker build -f infrastructure/docker/api.Dockerfile -t routes/api:remtest .
docker create --name routes-remediation-e2e --network routes-dbtest `
  -e DATABASE_URL=postgresql+psycopg://routes:testonly@routes-dbtest-pg:5432/postgres `
  -e SANDBOX_MANAGER_URL=http://sandbox-manager:8100 -e SANDBOX_MANAGER_TOKEN=<engine token> `
  -e PYTHONPATH=/src/shared:/src/core:/srv:/srv/api `
  -v ${PWD}/packages/shared:/src/shared:ro -v ${PWD}/packages/core:/src/core:ro `
  -v ${PWD}/services/api:/srv/api:ro -v ${PWD}/services/worker:/srv/worker:ro -v ${PWD}/scripts:/scripts:ro `
  -v ${PWD}/services/build_runner/tests/fixtures/shop-app:/fixtures/shop-app:ro `
  --tmpfs /tmp:exec -w /srv routes/api:remtest python /scripts/remediation_e2e.py
docker network connect routes_cli routes-remediation-e2e
docker start -a routes-remediation-e2e
```
