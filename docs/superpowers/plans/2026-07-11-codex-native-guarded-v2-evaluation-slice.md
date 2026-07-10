# Codex-native Guarded V2 Evaluation Slice Implementation Plan

> **For Codex:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task-by-task. Use `superpowers:test-driven-development` for every behavior change. Do not skip task review or the final whole-branch review.

**Goal:** Build a narrow, evaluation-only V2 path that cannot turn missing semantic work into a clean review, while truthfully describing the selected Codex worker as guarded and unconfined.

**Architecture:** A new Python package owns an explicit two-dot Git target, immutable content-addressed artifacts, a hash-chained event ledger, strict reviewer/verifier schemas, one correctness reviewer, one procedurally separate verifier per candidate, and a deterministic completion gate. A fake backend makes the complete protocol testable. A Codex CLI adapter can diagnose the current host and build the intended launch specification, but this slice always blocks live semantic dispatch because no host-owned complete capability-inventory oracle exists. V1 remains untouched.

**Tech Stack:** Python 3.11+, standard library, `jsonschema>=4.20,<5`, `unittest`, Git CLI, optional bundled Codex CLI for an opt-in host smoke.

---

## Global Constraints

These bind every task and every task review.

1. The selected worker machine value is exactly `codex_native_guarded`; its display value is `Codex-native guarded worker (no hard confinement)`.
2. Every accepted synthetic evaluation records these values inside `assurance_contract_under_test`; every live diagnostic records the same current limitations as diagnostic state:
   - `worker_boundary=guarded_unconfined`
   - `hard_worker_confinement=not_provided`
   - `packet_only_read=not_guaranteed`
   - `residual_tool_surface=unknown`
   - `residual_tool_inventory=unavailable`
   - `accepted_tool_calls=none_observed` only for an accepted synthetic attempt after zero observed **tool-call** events; a pre-dispatch live diagnostic uses `not_applicable_no_dispatch`
   - `telemetry_scope=observed_events_only`
   - `worker_child_environment=not_verified` until the new host-owned preflight passes; a passing preflight may report `allowlist_preflight_passed` but still cannot overcome the inventory block
   - `backend_stateless_attestation=unavailable`
   - `target_execution=not_requested`
3. Never call the selected worker `controlled`, `isolated`, `confined`, `sandboxed`, `packet-only`, `no-tools`, `no-network`, or `attested` without an explicit negation/limitation. Target-command assurance is a separate future concern.
4. The exact complete-result banner is reserved for a future authoritative live result:

   `Review process complete under the Codex-native guarded worker profile. Hard worker confinement was not provided. “Clean” means no confirmed findings under the completed review contract; it is not a worker-security claim.`

   Diagnostic output replaces `Review process complete` with `Review process incomplete` or `Review process blocked` and retains the rest of the limitation. Synthetic evaluation output must not emit this banner at all.
5. Worker assurance is orthogonal to `completeness` and `verdict`. A complete guarded result may be `clean`, `findings`, or `manual_review_required`; a failed task is `incomplete/not_available`, never an empty result.
6. Scope is exactly one clean tracked two-dot target: explicit `--base`, explicit `--head`, both resolved once to full SHAs, one correctness reviewer, and one new process/thread verifier per candidate.
7. Defer dirty/staged/unstaged/untracked overlays, PR/GitHub behavior, target-code execution, resume, multiple reviewer lenses, adjudication, semantic dedupe, publication, V1 compatibility, and production skill promotion.
8. Do not modify `SKILL.md`, `README.md`, `agents/openai.yaml`, existing `config/`, existing `scripts/`, existing schemas/prompts/templates/examples, or existing V1 tests in this slice.
9. Do not use `--ask-for-approval`; it is not a supported `codex exec` flag on the qualified CLI. Do not invent `store=false`, parent-lineage attestation, or complete tool telemetry.
10. The Codex launch posture uses only flags proven present: `--ephemeral`, `--ignore-user-config`, `--ignore-rules`, `--skip-git-repo-check`, `--strict-config`, `-s read-only`, `-C`, `--output-schema`, `--json`, `--output-last-message`, `-c 'web_search="disabled"'`, an explicit model, and the qualified feature disables.
11. Known-observed worker introspection is not a canonical inventory. This slice has no host-owned oracle that can enumerate every effective host, nested, connector, or GitHub capability, so `CodexCliBackend.run()` must block before the semantic subprocess even if a JSON record claims completeness. A data record alone can never self-authorize live dispatch.
12. Implement a host-owned synthetic environment preflight through the same process-construction helper: begin from an empty child environment, add only a sealed allowlist, inject fake secrets only into the adapter parent, spawn a trusted canary plus descendant, and prove non-allowlisted keys are absent. This evidence is not model-authored and is not borrowed from the target-command sandbox. Even a passing environment preflight does not overcome the missing inventory oracle in this slice.
13. A worker-authored capability, lineage, tool inventory, or assurance field is rejected. Trusted run manifests are adapter-authored.
14. Any observed tool-call event rejects the attempt whether the call succeeded or failed. The rejection does not claim the access was prevented or undone.
15. Strict schemas use Draft 2020-12 and `additionalProperties: false` at every object boundary. Blank, fenced, partial, malformed, or schema-invalid output rejects the entire task.
16. The reviewer proposes candidates only; it cannot assign a terminal disposition. Each candidate receives exactly one verifier result from a distinct task ID, process launch ID, and observed CLI thread ID.
17. All canonical JSON is UTF-8, sorted keys, compact separators, and a final newline. Hashes are lowercase SHA-256 over canonical bytes.
18. Artifact writes use staging, fsync, and atomic rename. The event ledger is adapter-only, append+fsync, and hash-chained. Hash or ledger corruption blocks gating and rendering.
19. This slice produces no canonical code-review report. Every synthetic evaluation says `profile=evaluation_slice_v2`, `release_ready=false`, and `authoritative_review=false`. A diagnostic report must not contain `clean`, `Pass`, `no issues`, or `No confirmed findings` as a verdict claim.
20. Use `subprocess` with argv arrays and `shell=False`. No network, external writes, GitHub operations, target commands, or repository mutation are part of this slice.
21. The fake backend is a synthetic protocol test harness, not a semantic reviewer. It can produce only non-authoritative evaluation artifacts. It must never create canonical `report.md`, emit the complete-review banner, or claim the target is clean.
22. Every changed path belongs to exactly one complete partition: reviewer-covered atoms or adapter-owned manual dispositions. Binary, submodule, sensitive-path, materially redacted, and otherwise unreviewable content can never disappear from the partition or permit a clean simulated verdict.
23. Known-sensitive material is classified and redacted before packet persistence. Worker output and every accepted sink are scanned before writing; unsafe output is rejected/quarantined without persisting the raw value. This is sink containment, not ambient worker secrecy.

## Deferred Work

- Target permission-profile runner and its live preflight.
- Dirty/untracked overlays and local working-tree review.
- PR resolution, GitHub payloads, grants, and publication.
- Deep/max coverage, impact mapping, multiple lenses, adjudication, and semantic dedupe.
- Resume/recovery across interrupted sessions.
- `SKILL.md`, README, agent metadata, and installed-skill promotion.
- Paired V1/V2 longitudinal scoring and release acceptance.

## Task 1: Add the V2 package, strict contracts, and prompts

**Files:**

- Create: `pyproject.toml`
- Create: `src/local_ultra_review/__init__.py`
- Create: `src/local_ultra_review/contracts.py`
- Create: `src/local_ultra_review/resources/__init__.py`
- Create: `src/local_ultra_review/resources/schemas/reviewer-result.schema.json`
- Create: `src/local_ultra_review/resources/schemas/verifier-result.schema.json`
- Create: `src/local_ultra_review/resources/schemas/qualification-record.schema.json`
- Create: `src/local_ultra_review/resources/schemas/evaluation-completion.schema.json`
- Create: `src/local_ultra_review/resources/prompts/reviewer-correctness.md`
- Create: `src/local_ultra_review/resources/prompts/verifier.md`
- Create: `tests/test_v2_contracts.py`

### Required interfaces

`pyproject.toml`:

- Python `>=3.11`.
- Only runtime dependency: `jsonschema>=4.20,<5`.
- `src` package layout.
- Console script: `local-ultra-review-v2 = local_ultra_review.orchestrator:main` (the module arrives in Task 4).
- Package JSON/Markdown resources in wheels and editable installs; load them only through `importlib.resources`.

`contracts.py`:

```python
SCHEMA_VERSION = "2.0-evaluation-slice"

class ContractError(ValueError): ...

def canonical_json_bytes(value: object) -> bytes: ...
def sha256_json(value: object) -> str: ...
def load_schema(name: str) -> dict: ...
def validate_payload(schema_name: str, value: object) -> None: ...
def reject_worker_authority_fields(value: object) -> None: ...
```

- Schema/prompt lookup uses `importlib.resources.files("local_ultra_review.resources")`, never the caller's current directory.
- `reject_worker_authority_fields` recursively rejects these worker-supplied keys anywhere: `assurance`, `capability`, `capabilities`, `worker_profile`, `worker_boundary`, `hard_worker_confinement`, `context_lineage`, `parent_context_id`, `residual_tool_surface`, `tool_inventory`, `tools`, `telemetry_scope`.

Reviewer payload:

```json
{
  "schema_version": "2.0-evaluation-slice",
  "task_id": "reviewer-...",
  "packet_hash": "64 lowercase hex",
  "status": "completed",
  "coverage": {
    "reviewed_atom_ids": ["atom-..."],
    "notes": "nonempty"
  },
  "candidates": [
    {
      "severity": "Important",
      "file": "relative/path.py",
      "line": 12,
      "title": "concise",
      "failure_scenario": "concrete",
      "evidence": ["specific evidence"],
      "why_diff": "causality"
    }
  ]
}
```

- Candidate properties `status`, `verification`, `disposition`, `confirmed`, and `final_severity` are forbidden by strict schema.
- A completed reviewer envelope with `candidates=[]` is valid only when coverage is nonempty and later matches the sealed atom set.

Verifier payload:

```json
{
  "schema_version": "2.0-evaluation-slice",
  "task_id": "verifier-...",
  "packet_hash": "64 lowercase hex",
  "candidate_hash": "64 lowercase hex",
  "status": "completed",
  "disposition": "confirmed",
  "final_severity": "Important",
  "provenance": "introduced by ...",
  "best_fix": "ownership-boundary fix",
  "refactor_judgment": "bounded judgment",
  "proof": ["specific proof"],
  "residual_risk": "remaining uncertainty"
}
```

- Dispositions: `confirmed`, `false_positive`, `pre_existing`, `needs_manual_review`.
- `final_severity` is required and `Important|Nit` only for `confirmed`; it must be absent for all other dispositions.

Qualification/diagnostic record fields are strict and exact: `record_kind=diagnostic_evidence`, `profile=codex_native_guarded`, CLI version and three policy/binary SHA-256 values, `residual_tool_surface=unknown`, `residual_tool_inventory=unavailable`, `canonical_inventory_oracle=unavailable`, `inventory_scope=known_observed_partial`, `inventory_source=worker_observed_only`, sorted unique known-observed exposures, observation method, RFC3339 UTC qualification/expiry timestamps, guarded mitigation/preflight states, `telemetry_scope=observed_events_only`, `live_dispatch_authorized=false`, and a unique blocker list containing `canonical_inventory_oracle_unavailable`. A data record never authorizes live dispatch.

The evaluation-completion schema is explicitly non-authoritative. It uses `authority=synthetic_evaluation`, `authoritative_review=false`, `execution_backend=fake_evaluation`, `protocol_completeness=complete`, and `simulated_review_verdict=clean|findings|manual_review_required`. Its guarded-profile fields are named `assurance_contract_under_test`, not `assurance`. It cannot satisfy a canonical review-result schema and cannot be rendered as `report.md`.

### TDD sequence

1. Write tests for canonical JSON stability, strict additional-property rejection, terminal candidate-field rejection, confirmed/non-confirmed verifier conditionals, recursive worker-authority rejection, qualification limitations, and the non-authoritative evaluation-completion constants.
2. Run `python -m unittest tests.test_v2_contracts -v`; capture the expected import/schema RED.
3. Add only the package/contracts/packaged schemas/prompts required for GREEN. Build a wheel into a temporary directory, install it into a temporary venv, and prove schema/prompt lookup works outside the checkout.
4. Re-run the focused test, then `python -m unittest discover -s tests -v`.
5. Commit: `Build strict V2 review contracts`.

## Task 2: Seal the Git target and immutable artifact history

**Files:**

- Create: `src/local_ultra_review/git_target.py`
- Create: `src/local_ultra_review/redaction.py`
- Create: `src/local_ultra_review/store.py`
- Create: `tests/test_v2_core.py`

### Required interfaces

`git_target.py`:

```python
@dataclass(frozen=True)
class SealedTarget:
    repository_root: Path
    base_sha: str
    head_sha: str
    redacted_diff_text: str
    safe_diff_hash: str
    changed_paths: tuple[str, ...]
    coverage_atoms: tuple[dict, ...]
    manual_dispositions: tuple[dict, ...]
    target_identity_hash: str

def seal_two_dot_target(repo: Path, base: str, head: str) -> SealedTarget: ...
def build_review_packet(target: SealedTarget) -> dict: ...
```

- Resolve both refs with `git rev-parse --verify <ref>^{commit}` exactly once.
- Reject a non-repository, equal SHAs, dirty index/worktree, untracked files, submodule dirt in the checkout, empty diff, absolute/escaping paths, and undecodable path metadata. Do not silently reject or omit an otherwise valid mixed binary/special diff: classify it into a manual partition.
- Use `git diff --raw -z --no-renames <base_sha>..<head_sha --`, `git diff --numstat -z --no-renames ...`, and `git diff --no-ext-diff --no-textconv --no-renames ...`. Parse delete/add as separate paths; never enable heuristic rename detection.
- Every raw changed path creates one deterministic path-metadata atom containing status and old/new modes. Every textual hunk creates one additional hunk atom. Therefore mode-only and empty-file changes still have an atom.
- Binary, submodule, sensitive-path, unparseable, or materially redacted atoms receive adapter-owned manual dispositions. Reviewer-covered and manual atom sets are disjoint and their exact union is every atom. A mixed text+binary target can continue only as `manual_review_required`, never simulated clean.
- `target_identity_hash` includes repository identity, base/head SHAs, the **redacted** safe-diff hash, changed-path metadata, every atom, every redaction/manual disposition, and redaction-ruleset hash. It excludes session path, wall clock, session ID, worker/model/backend inputs, raw-diff hash, blob IDs for sensitive paths, and raw sensitive bytes. The fixed commit SHAs seal the original Git objects without persisting a standalone secret-derived digest. Task 4 builds the broader `review_identity_hash`.
- The packet contains fixed SHAs, only the redacted/withheld diff representation, changed-path metadata, reviewable atoms, manual dispositions, profile, and an untrusted-content warning. It contains no local repository path or raw sensitive value.

`redaction.py`:

```python
class SensitiveMaterialError(ValueError): ...

@dataclass(frozen=True)
class RedactionResult:
    safe_diff_text: str
    manual_dispositions: tuple[dict, ...]
    ruleset_hash: str

def classify_and_redact_diff(raw_diff: bytes, path_records: tuple[dict, ...]) -> RedactionResult: ...
def assert_safe_sink(value: object) -> None: ...
```

- High-confidence detectors cover private-key blocks, common provider/token prefixes, and secret/password/token/API-key assignments with non-placeholder values. Sensitive path classes include `.env*`, private-key/certificate-key files, credential/token stores, and local database files.
- A sensitive path is represented only by safe path metadata, reason code, and a withheld-content marker. For an inline secret, replace the value with a deterministic location/ordinal marker that is not derived from the secret value, and mark the affected hunk manual. Never persist the raw diff, a raw matched value, blob ID, or standalone digest of sensitive bytes.
- `assert_safe_sink` scans packets, plan/artifact/event payloads, accepted worker payloads, evaluation reports, diagnostics, and materialized views before any write. Unsafe worker output is rejected in memory; any diagnostic uses a reason code/hash only.
- Sink containment tests use synthetic provider-shaped canaries and assert their bytes and standalone canary-derived hashes are absent from packet, plan, ledger, artifact, event, report, and recovery output. Do not infer ambient non-access.

`store.py`:

```python
class IntegrityError(RuntimeError): ...

class ArtifactStore:
    @classmethod
    def create(cls, session_root: Path, plan: dict) -> "ArtifactStore": ...
    def write_artifact(self, artifact_type: str, payload: dict, producer: dict) -> dict: ...
    def append_event(self, event_type: str, payload: dict) -> dict: ...
    def verify(self) -> None: ...
    def read_artifacts(self, artifact_type: str) -> list[dict]: ...
```

- Create a staging directory beside the final session directory, write canonical `plan.json`, fsync file and directory, write genesis event, and atomically promote. Existing final session directory is an error.
- Plan has `plan_integrity_hash` over all plan fields except itself. It includes session ID/root/time. Task 4 supplies a review identity that combines the target identity with all semantic worker inputs.
- Artifact envelope is adapter-authored and includes artifact/schema/session/plan/review identity, producer task/attempt/thread/process IDs, input hashes, payload hash, timestamp, and envelope hash.
- Artifact filename is content-addressed and immutable; collision with different bytes is an integrity error. Every planned payload passes `assert_safe_sink` before staging.
- Ledger records `sequence`, previous hash, event type, payload hash, timestamp, and event hash. Verify the full chain and all artifact/plan hashes on every gate/render read.

### TDD sequence

1. Add tests creating three-commit temporary repos: requested head is commit 2 while repository HEAD is commit 3; assert only commit 2 is sealed.
2. Add tests for dirty/untracked rejection; `--no-renames` delete/add behavior; path and hunk atom stability; mixed text+binary; mode-only; empty-file; symlink/submodule; sensitive-path and inline-secret redaction; exact reviewed/manual partition; path-free/sensitive-free packets; target identity stability; atomic exclusive creation; content-addressed artifacts; sink-scan rejection; and plan/ledger/artifact tamper failure.
3. Run `python -m unittest tests.test_v2_core -v`; capture RED.
4. Implement minimal Git and store behavior; no worker logic.
5. Run focused and full suites.
6. Commit: `Seal V2 targets and artifacts`.

## Task 3: Implement fake and guarded Codex worker backends

**Files:**

- Create: `src/local_ultra_review/backend.py`
- Create: `tests/test_v2_backend.py`

### Required interfaces

```python
@dataclass(frozen=True)
class WorkerTask:
    task_id: str
    role: Literal["reviewer", "verifier"]
    packet: dict
    packet_hash: str
    prompt_text: str
    output_schema_name: str
    timeout_seconds: int

@dataclass(frozen=True)
class ScriptedAttempt:
    expected_role: Literal["reviewer", "verifier"]
    raw_events: tuple[dict, ...]
    last_message_template: bytes
    process_launch_id: str
    return_code: int = 0
    timed_out: bool = False

@dataclass(frozen=True)
class WorkerAttempt:
    payload: dict
    thread_id: str
    process_launch_id: str
    manifest: dict

class WorkerProtocolError(RuntimeError): ...
class WorkerUnavailable(RuntimeError): ...

class WorkerBackend(Protocol):
    def readiness(self) -> dict: ...
    def semantic_identity(self) -> dict: ...
    def run(self, task: WorkerTask, attempt_dir: Path) -> WorkerAttempt: ...

class FakeBackend:
    def __init__(self, *, scenario_id: str, attempts: Sequence[ScriptedAttempt]): ...
    def readiness(self) -> dict: ...
    def semantic_identity(self) -> dict: ...
    def run(self, task: WorkerTask, attempt_dir: Path) -> WorkerAttempt: ...

class CodexCliBackend:
    def __init__(self, *, codex_path: Path, model: str, qualification_record: Path,
                 parent_environment: Mapping[str, str] | None = None): ...
    def readiness(self) -> dict: ...
    def semantic_identity(self) -> dict: ...
    def build_launch_spec(self, task: WorkerTask, attempt_dir: Path) -> dict: ...
    def preflight_worker_environment(self, scratch_dir: Path) -> dict: ...
    def run(self, task: WorkerTask, attempt_dir: Path) -> WorkerAttempt: ...
```

### Guarded backend contract

- Compute the CLI binary hash, `codex --version`, launch-policy hash, and environment-policy hash for a trusted diagnostic. Validate the adapter-owned record and expiry, but never treat the record as a capability oracle.
- Known-observed inventory is deliberately partial. Record its exact sorted values and hash with `inventory_scope=known_observed_partial`, `residual_tool_surface=unknown`, and `residual_tool_inventory=unavailable`; never render it as exhaustive.
- Child environment keys are exactly the available subset of `PATH`, `HOME`, `CODEX_HOME`, `LANG`, `LC_ALL`, `TERM`, plus adapter-set `TMPDIR`. Remove every other parent variable. Manifest records key names/hash, never values. Tests inject `LOCAL_ULTRA_REVIEW_FAKE_SECRET=EVAL_ONLY_...` and prove it does not reach the fake CLI.
- `build_launch_spec()` creates the exact hypothetical semantic argv, stdin, and scrubbed environment, but `run()` raises `WorkerUnavailable` with a structured blocked diagnostic before launching it. No record supplied to this slice can turn that gate on.
- `preflight_worker_environment()` may launch only a trusted synthetic canary through the shared process-construction helper. It starts from an empty child environment, validates parent-secret exclusion and descendant inheritance, and records host-owned evidence. It is not a semantic invocation.
- Required argv, in stable order:
  - `codex exec --ephemeral --ignore-user-config --ignore-rules --skip-git-repo-check --strict-config`
  - `-s read-only`
  - `-c web_search="disabled"`
  - each of these exact disables: `shell_tool`, `unified_exec`, `code_mode_host`, `apps`, `browser_use`, `browser_use_external`, `browser_use_full_cdp_access`, `computer_use`, `plugins`, `remote_plugin`, `image_generation`, `multi_agent`, `goals`, `workspace_dependencies`, `tool_suggest`, `tool_call_mcp_elicitation`
  - `-C <attempt packet directory>`
  - `--model <sealed model>`
  - `--output-schema <task schema>`
  - `--json --output-last-message <attempt scratch/result.json> -`
- Do not add `--ask-for-approval`, target-command permission profiles, or network claims.
- `last_message_template` may contain only the adapter-defined placeholders `{{TASK_ID}}`, `{{PACKET_HASH}}`, and `{{CANDIDATE_HASH}}`. `FakeBackend` binds them after review identity/task creation and before validation. Any unknown or unresolved placeholder rejects the attempt.
- The shared fake-attempt acceptance path consumes `ScriptedAttempt`, checks the expected role, timeout, return code, and launch evidence, binds the task-specific placeholders, parses events, requires exactly one nonempty thread ID and a schema-valid raw payload, detects only observed event evidence, and rejects tool/command/MCP/function/apply-patch markers. Its manifest always says `telemetry_scope=observed_events_only`.
- Reject blank/fenced/partial/malformed output, packet/task mismatch, worker authority fields, unsafe sensitive bytes, missing/repeated thread IDs, timeout/nonzero status, or any observed tool call in fake protocol evaluations.
- Adapter-authored fake manifests contain task/attempt/packet hashes, process launch ID, synthetic thread ID, observed event count, observed tool-call count, all conservative assurance limitations, `authority=synthetic_evaluation`, `execution_backend=fake_evaluation`, and `target_execution=not_requested`.
- `FakeBackend.semantic_identity()` includes backend/protocol version, scenario ID, expected role sequence, and a canonical hash of the **unbound attempt templates** (including literal placeholder tokens). It excludes actual task/packet/candidate IDs, which do not exist yet. The hash of each bound attempt is recorded later in its adapter manifest, artifact input hashes, and ledger event, not fed back into review identity. `CodexCliBackend.semantic_identity()` includes adapter version, model, CLI version/binary hash, launch/environment policy hashes, diagnostic-record hash, inventory status, and qualification state. Task 4 includes the appropriate semantic identity object in review identity.
- `FakeBackend.readiness()` returns a synthetic-only ready state with no live authority. `CodexCliBackend.readiness()` includes the independent environment-preflight result but always returns live semantic dispatch blocked in this slice because canonical inventory remains unavailable.

`FakeBackend` is test/evaluation-only. It still runs the same schema, identity, authority-field, secret-sink, and observed-tool gates, but no `WorkerAttempt` it returns can acquire live authority.

### TDD sequence

1. Test every live Codex path blocks with zero semantic subprocess calls, including a syntactically valid record that claims a complete inventory.
2. Test exact hypothetical argv and feature disables, absence of unsupported flags, parent-secret stripping, empty-base child environment, trusted canary descendant inheritance, environment-policy hash matching, and host-owned diagnostic fields.
3. Test valid structured result, blank/fenced/malformed result, worker authority forgery, missing/duplicate thread, timeout/nonzero exit, and observed `view_image`/collaboration/tool events.
4. Run `python -m unittest tests.test_v2_backend -v`; capture RED.
5. Implement the shared acceptance path, fake backend, then guarded CLI adapter.
6. Run focused and full suites.
7. Commit: `Add guarded V2 worker backends`.

## Task 4: Orchestrate reviewer and fresh verifier accounting

**Files:**

- Create: `src/local_ultra_review/orchestrator.py`
- Create: `tests/test_v2_orchestrator.py`

### Required interfaces

```python
@dataclass(frozen=True)
class EvaluationRequest:
    repo: Path
    base: str
    head: str
    model: str
    session_root: Path

@dataclass(frozen=True)
class EvaluationOutcome:
    evaluation_completion: dict | None
    evaluation_report_path: Path | None
    diagnostic_path: Path | None
    recovery_diagnostic_path: Path | None

def evaluate(request: EvaluationRequest, backend: WorkerBackend) -> EvaluationOutcome: ...
```

- `evaluate` is the only phase-transition owner: backend readiness -> seal target -> create plan/store -> packet -> reviewer -> verifier(s) -> synthetic evaluation gate. It must not call V1 scripts. A blocked Codex backend performs no semantic invocation and creates only a diagnostic.
- Plan fixes exactly `profile=evaluation_slice_v2`, `authority=synthetic_evaluation` for fake runs, one `correctness` role, prompt/schema/redaction hashes, backend semantic identity, model, adapter/protocol/run-manifest versions, target identity, and `release_ready=false`.
- `review_identity_hash` is the canonical hash of all semantic inputs: target identity; selected profile; schema/prompt/redaction versions and hashes; backend kind/version; model; adapter/CLI binary and version when applicable; launch/environment/inventory/qualification states and policy hashes; and fake script hash for synthetic runs. It excludes session ID/path/time only. No task ID is derived before this identity exists.
- Reviewer task ID is a stable hash of review identity plus role. Reviewer packet hash binds the complete packet. Accepted reviewer coverage must equal the sealed **reviewable** atom set exactly: no missing or unknown atoms.
- More precisely, reviewer coverage must equal the reviewable atom set exactly, while adapter manual dispositions must equal the manual atom set exactly. The two sets must be disjoint and their union must equal every changed-path/hunk atom.
- Candidate hash is adapter-computed from the strict candidate payload. A verifier task/packet is created for each candidate. Its task ID is a stable hash of review identity plus candidate hash plus `verifier`.
- Reviewer and verifier must have distinct task IDs, process launch IDs, and thread IDs. Verifier threads must also be pairwise distinct. Reuse/missing evidence rejects the affected result and makes the run incomplete.
- Each raw candidate has exactly one terminal verifier disposition. Candidate count, verifier count, and canonical disposition count reconcile exactly.
- Exact duplicate candidates may merge only after verification by identical canonical root-cause key; final severity is monotonic (`Important` wins). No semantic/model dedupe in this slice.
- Material redaction/manual content, uncovered atom, worker failure, schema error, observed tool call, thread/process reuse, pending candidate, or integrity failure can never become a simulated clean verdict.
- A successful fake run creates a schema-valid `evaluation_completion` with `authority=synthetic_evaluation`, `authoritative_review=false`, `protocol_completeness=complete`, and a `simulated_review_verdict`. It is an orchestration evaluation, not a code-review completion.
- A normal failure after session creation writes a sanitized adapter-authored diagnostic artifact only after `store.verify()` passes. An integrity failure must not write through the damaged store; it atomically writes a clearly non-authoritative recovery diagnostic to a sibling path outside canonical session state and exits via the integrity path.
- Gate calls `store.verify()` immediately before accepting an evaluation completion and records the exact accepted artifact hashes. No code path in this slice can create a canonical live-review completion.

### TDD sequence

1. Test a valid empty fake reviewer result with exact reviewable coverage and no manual atoms produces `protocol_completeness=complete`, `simulated_review_verdict=clean`, and `authoritative_review=false`—never a canonical review result.
2. Test prompt-only/no payload, malformed payload, partial coverage, unknown coverage, candidate without verifier, verifier thread/process reuse, verifier packet mismatch, and observed-tool rejection all produce incomplete/not-available.
3. Test one confirmed candidate flows with all proof fields; false positive and pre-existing are accounted but not findings; adapter/manual or verifier needs-manual yields simulated manual-review-required.
4. Test order-independent exact duplicate merge and Important severity retention.
5. Test candidate/verifier counts and accepted artifact hashes reconcile; tampering between worker and gate blocks.
6. Run `python -m unittest tests.test_v2_orchestrator -v`; capture RED.
7. Implement the minimal orchestration/gate path.
8. Run focused and full suites.
9. Commit: `Gate V2 reviewer and verifier work`.

## Task 5: Render non-authoritative evaluation and diagnostic reports without false-clean language

**Files:**

- Create: `src/local_ultra_review/render.py`
- Modify: `src/local_ultra_review/orchestrator.py`
- Extend: `tests/test_v2_orchestrator.py`

### Required interfaces

```python
def render_evaluation_report(*, plan: dict, completion: dict, artifacts: list[dict]) -> str: ...
def render_diagnostic_report(*, plan: dict | None, state: str, reasons: list[str],
                             assurance_state: dict) -> str: ...
def write_recovery_diagnostic(*, sibling_path: Path, reason_codes: list[str]) -> Path: ...
```

- Evaluation rendering is allowed only after store verification and a schema-valid synthetic evaluation-completion artifact.
- The first heading and front matter say **Synthetic protocol evaluation — not a code-review result**, `authority=synthetic_evaluation`, `authoritative_review=false`, `profile=evaluation_slice_v2`, and `release_ready=false`. It states that even a simulated `clean` fixture makes no claim that the target is clean.
- The exact complete-review banner is forbidden in fake/evaluation output. `evaluation-report.md` may show `simulated_review_verdict`, confirmed fixture findings, and manual fixture items only when every label remains explicitly synthetic.
- Diagnostic rendering states the actual incomplete/blocked state, reason codes, and current guarded limitations (`residual_tool_surface=unknown`, `worker_child_environment=not_verified`). It must not contain false-clean phrases as outcome claims.
- Renderer rejects missing/mismatched synthetic authority, selected-profile positive hard claims, completion/artifact hash mismatch, unsafe sensitive bytes, or any attempt to materialize fake output as `report.md`.
- First persist rendered bytes as a content-addressed `evaluation_report` or `diagnostic_report` artifact and commit its ledger event. Verify the store, then atomically materialize the non-authoritative view as `evaluation-report.md` or `diagnostic.md`. A materialized view is never the authority and is reproducible from the committed artifact.
- `write_recovery_diagnostic` is used only after integrity failure, writes outside the session directory with staging+fsync+atomic rename, contains only stable reason codes (no unsafe-payload digest), makes no target/result claims, and labels itself non-authoritative because canonical state could not be verified.

### TDD sequence

1. Add snapshot-like assertions for synthetic clean/findings/manual fixture evaluations, normal incomplete/blocked diagnostics, and integrity recovery diagnostics.
2. Prove fake output can never create `report.md`, the exact complete-review banner, `authoritative_review=true`, or an unqualified claim that the target is clean. Prove prompt-only, failed worker, bad authority, hard-claim wording, manual item, unsafe output, and tampered inputs fail closed.
3. Assert every evaluation report has `release_ready=false`, `authority=synthetic_evaluation`, a prominent non-review disclaimer, and separate `target_execution=not_requested` inside `assurance_contract_under_test`.
4. Run the focused orchestrator tests; capture RED.
5. Implement rendering and wire it after the gate.
6. Run focused and full suites.
7. Commit: `Render truthful guarded V2 reports`.

## Task 6: Add the evaluation CLI and end-to-end proof

**Files:**

- Modify: `src/local_ultra_review/orchestrator.py`
- Create: `tests/test_v2_e2e.py`
- Create: `tests/test_v2_live.py`

### CLI

```text
local-ultra-review-v2 evaluate \
  --repo <path> \
  --base <ref> \
  --head <ref> \
  --model <explicit-model-id> \
  --session-root <new-path> \
  --codex-path <path> \
  --qualification-record <adapter-owned-diagnostic-json>
```

- Every listed argument is required. There is no implicit HEAD/default branch/model/session. The current Codex path exits with a blocked diagnostic before semantic dispatch because the complete host inventory oracle is unavailable.
- Only subcommand is `evaluate`. Reject overlay, PR, posting, check, resume, mode, and network flags rather than ignoring them.
- Exit codes: `0` synthetic protocol evaluation completed (not a review verdict), `2` input/contract error before session, `3` incomplete/blocked diagnostic, `4` integrity invariant failure.
- Print only the absolute `evaluation-report.md`, `diagnostic.md`, or sibling recovery-diagnostic path plus a one-line authority/status label; semantic details live in artifacts.

### End-to-end tests

1. Temporary two-commit repo plus `FakeBackend`, valid empty reviewer envelope: synthetic protocol completion with simulated clean fixture, prominent non-review disclaimer, no complete-review banner, no `report.md`, and all hashes verified.
2. Seeded regression plus fake reviewer and fresh verifier: one synthetic confirmed Important fixture finding appears with all proof fields and remains non-authoritative.
3. V1 false-clean shape: backend only prepares a prompt/no result. Assert exit/status incomplete, only `diagnostic.md`, no `report.md`, no target-clean claim.
4. Mixed text+binary, mode-only, sensitive path, inline provider-shaped secret, observed tool event, malformed output, reused thread, candidate without verifier, manual item, and artifact tamper each produce their exact reviewed/manual/incomplete/integrity outcome. Assert canary bytes are absent from every surviving file.
5. CLI argument and exit-code tests prove the Codex adapter returns blocked/diagnostic with zero fake semantic executable calls; separately test the trusted environment canary and exact hypothetical flags.
6. `tests/test_v2_live.py` is an opt-in **diagnostic-only** test when `LOCAL_ULTRA_REVIEW_RUN_LIVE_CODEX_DIAGNOSTIC=1` and explicit paths/model/record are supplied. It verifies version/hash/config observations and the pre-dispatch block. It must never issue a live semantic request in this slice.
7. TDD order is mandatory: write all Task 6 CLI/E2E/install tests first; run `python -m unittest tests.test_v2_e2e -v` and capture the expected RED; implement the CLI/materialized-view/install support; then rerun focused GREEN and the full suite.
8. Build a wheel to a temporary directory, install it into a fresh temporary venv with `uv`, change cwd outside the checkout, and prove the console command and packaged schemas/prompts resolve. Then run:

   ```bash
   python -m unittest tests.test_v2_e2e -v
   python -m unittest discover -s tests -v
   /Library/Frameworks/Python.framework/Versions/3.12/bin/python3 \
     /Users/kiedis/.codex/skills/.system/skill-creator/scripts/quick_validate.py .
   ```

   The V2 suite must pass. The final validator is expected to remain RED because V1 `SKILL.md` metadata promotion is explicitly deferred; record the exact failure as known deferred work, not as a V2 test failure.
9. Confirm `git diff 18b3dff..HEAD -- SKILL.md README.md agents/openai.yaml config scripts prompts schemas` is empty; all new V2 resources live under the package.
10. Commit: `Prove the guarded V2 evaluation slice`.

## Final Verification and Review

After all six task reviews approve:

1. Run the entire isolated-environment suite with Python 3.11+ and `jsonschema>=4.20,<5`.
2. Run an opt-in fake-Codex process smoke exercising exact argv/environment/JSONL parsing.
3. Run only the live Codex **diagnostic** smoke when explicitly enabled. Expected result is `blocked/not_available` with zero semantic dispatch because the canonical inventory oracle is not implemented; do not weaken the gate.
4. Verify no existing V1 file changed and no output/session artifact is tracked.
5. Use `superpowers:requesting-code-review` for a whole-branch review of merge-base through HEAD. Fix every Critical/Important finding and re-review.
6. Use `superpowers:finishing-a-development-branch` to present the completed evaluation slice. Do not merge, publish, install, or promote it without separate user authorization.

## Slice Acceptance

The slice is complete only when:

- deterministic prompt-only/no-result input cannot render a synthetic success or any target-clean claim;
- valid structured empty fake review plus exact coverage can complete the synthetic protocol evaluation, but creates only `evaluation-report.md`, never the complete-review banner or canonical `report.md`;
- every candidate has one procedurally separate verifier or the run is incomplete;
- every changed path/hunk belongs to the exact reviewed/manual partition; binary, mode-only, sensitive, and redacted material cannot disappear or yield a simulated clean result;
- known-sensitive canary bytes are absent from every accepted packet, event, artifact, report, diagnostic, recovery output, and materialized view;
- observed tool events, schema/identity/integrity failures, and qualification/env-policy drift fail closed;
- the fake backend proves the complete protocol end to end;
- the guarded CLI backend exists, diagnoses current evidence, and blocks every live semantic dispatch in this slice, including when a record merely claims completeness;
- V1 is byte-for-byte unchanged; and
- every fake result is explicitly `authority=synthetic_evaluation`, `authoritative_review=false`, `evaluation_slice_v2`, and `release_ready=false`, not a promoted Local Ultra Review V2 release or a code-review verdict.
