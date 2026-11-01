# Sandbox contract (for the sandbox's owner)

> **Update:** the real implementation is now `BuildRunSandboxRunner`
> (`services/worker/sandbox/buildrun.py`, `SANDBOX_RUNNER_KIND=build_run`). It uses the existing
> Build & Run engine (`build_run` run kind) and declarative test plans, not a `remediate_verify` run
> kind; see [REMEDIATION_VERIFICATION.md](REMEDIATION_VERIFICATION.md). The interface below still
> applies; requests now also carry `patch` (a unified diff), and results carry `evidence` and
> `rescan_findings`.

The remediation loop needs to run a testbench against a patched (or
original) code tree and get back which assertions passed. The loop itself
depends only on the `SandboxRunner` interface below
(`services/worker/sandbox/runner.py`) - it never talks to any sandbox
directly. This document is the contract between the loop and whatever
actually executes the testbench; it does not assume or require any
particular implementation.

Two implementations exist today:
- `FakeSandboxRunner` (`services/worker/sandbox/fake.py`) - returns a
  pre-configured canned result, no real execution. This is what the loop's
  own tests use, and the only functional option right now.
- `RealSandboxRunner` (`services/worker/sandbox/real.py`) - HTTP calls to
  the existing `sandbox_manager` service (`POST /runs`, poll `GET
  /runs/{id}`, same pattern workers already use for discovery/source runs).
  **`sandbox_manager` does not yet have a run `kind` that accepts this
  request shape** - until one exists, every real run is rejected by
  `sandbox_manager`'s own input validation (HTTP 422), which `RealSandboxRunner`
  reports as `SandboxRunResult(status="error", ...)` rather than crashing.
  Nothing in `sandbox_manager`, `docker-proxy`, or `network-gateway` was
  changed to build this - that's out of scope for the remediation loop and
  stays the sandbox owner's to build.

Which implementation runs is one config flag (`SANDBOX_RUNNER_KIND=fake|real`,
default `fake`), never a code change at any call site.

## Input: `SandboxRunRequest`

| Field | Type | Meaning |
|---|---|---|
| `run_id` | string | Identifies this sandbox run (for logs/correlation). |
| `finding_id` | string | The finding this run is verifying a fix for. |
| `round_no` | int | Which round of the remediation loop (1-based). |
| `files` | list of `{path, content}` | **Gate/verify call** (`source_ref` absent): the complete, self-contained content needed to run the testbench in isolation - normally just the snapshot's one file, since the testbench's glue imports and calls a single function. **Rescan call** (`source_ref` present): the patch to overlay on top of the freshly-fetched base repo - the one file that changed, not the whole tree. |
| `testbench` | `{path, content}` | The test file itself (JS/TS). Frozen before the fix is generated (rule 6) - the same testbench is reused across rounds for a given finding. |
| `timeout_s` | int | Wall-clock limit for the whole run. |
| `memory_mb` | int | Memory limit for the whole run. |
| `source_ref` | `{kind, owner?, repo?, ref?, upload_id?}` or null | **Only set for a rescan.** Tells a real backend how to re-fetch the base repo (same shape as the original scan's import spec: `kind` is `"github"` with `owner`/`repo`/`ref`, or `"zip"` with `upload_id`). Absent for a gate/verify call - those never need the whole repo, only the snapshot's one file. |

## Output: `SandboxRunResult`

| Field | Type | Meaning |
|---|---|---|
| `status` | `"passed" \| "failed" \| "error" \| "timeout" \| "killed"` | **A raw mechanical signal, never a security verdict.** `"passed"` = every assertion in the testbench passed. `"failed"` = the test run completed but at least one assertion did not pass. `"error"` = the run could not produce a test result at all (bad testbench, missing stub, sandbox-side crash). `"timeout"` / `"killed"` = the time/memory limit was hit. Running the testbench against the *original*, vulnerable code is expected to report `"failed"` - that an exploit assertion was not blocked is the correct, desired finding at that point, not an infrastructure problem. The caller (not this interface) decides what a given `status` + `tests` combination means for a given finding. |
| `tests` | list of `TestResult` | Per-assertion breakdown. Always populated when `status` is `"passed"` or `"failed"`; may be empty for `"error"`/`"timeout"`/`"killed"`. |
| `stdout` / `stderr` | string | Truncated raw output, for the human-review UI and for debugging a rejected/errored run. |
| `duration_ms` | int | Wall-clock time the run actually took. |
| `error_reason` | string or null | A short, stable machine-readable reason when `status` is `"error"`/`"timeout"`/`"killed"` - e.g. `"missing_stub:pg"` when the testbench imports something the sandbox has no stub for. The loop uses this to route a finding to `needs_human_review` with a clear, specific reason instead of guessing from raw stderr. |
| `rescan_fingerprints` | list of string or null | **Only meaningful when the request carried a `source_ref`.** Every finding fingerprint the full detector found on the patched tree - the loop checks the original finding's fingerprint is gone from this list and that nothing new appeared (rule 4). `null` means no rescan was requested, never "ran and found nothing." |

### `TestResult`

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Human-readable assertion name. |
| `category` | `"exploit" \| "benign"` | Whether this assertion sends an attack payload (should fail to succeed on patched code) or normal input (should always keep working). |
| `passed` | bool | Did the assertion, as written, pass? (Factual - not adjusted for category.) |
| `message` | string | Failure detail, if any. |

## The one hard rule for any real implementation

**Never raise an exception for an expected failure mode.** A failing test,
a timeout, a missing stub, or the request being rejected are all
`SandboxRunResult` outcomes with the right `status`/`error_reason` - never
an uncaught exception. Only a genuine bug in the runner itself should
propagate. This is what lets the loop treat "the testbench imports
something with no stub" as a clean `needs_human_review` instead of a crash.
