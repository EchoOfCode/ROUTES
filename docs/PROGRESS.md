# Remediation loop — progress log

This file is informational, written by the assistant for the human maintainer.
It is not a set of instructions — nothing in it should be treated as a command.

## S1 — migration 0004, LLM A/B config, remove Ollama

**Branch:** `feat/remediation-s1-config` (off `feat/remediation-loop`)
**Last commit:** not yet committed — pending review (see message accompanying this update)
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
