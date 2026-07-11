"""Guarded V2 synthetic reviewer/verifier orchestration.

Task 4 owns only in-memory outcomes and canonical Store artifacts. Rendering and the
CLI deliberately arrive in later tasks.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import unicodedata
import uuid

from .backend import (
    RUN_MANIFEST_VERSION,
    WORKER_ENVIRONMENT_POLICY_SHA256,
    ENVIRONMENT_ALLOWLIST,
    WorkerAttempt,
    WorkerBackend,
    WorkerProtocolError,
    WorkerTask,
    WorkerUnavailable,
    validate_run_manifest,
)
from .completion_projection import (
    build_reviewer_task_record,
    build_verifier_task_record,
    completion_source_hashes,
    derive_completion_payload,
    review_candidate_hash,
    validate_role_task_record,
    validate_target_packet,
)
from .contracts import (
    ContractError,
    ORCHESTRATION_CONTRACT_VERSION,
    SCHEMA_VERSION,
    is_required_evidence_sentinel,
    prompt_contracts,
    review_identity_hash,
    schema_contracts,
    sha256_json,
    validate_payload,
    validate_semantic_plan,
)
from .git_target import TargetError, build_review_packet, seal_two_dot_target
from .redaction import (
    SensitiveMaterialError,
    assert_safe_sink,
    redaction_contract,
)
from .store import ArtifactStore, IntegrityError


DIAGNOSTIC_CONTRACT_VERSION = "evaluation-diagnostic-v1"

_HASH = re.compile(r"^[0-9a-f]{64}$")
_FAKE_READINESS_FIELDS = {
    "ready",
    "mode",
    "authority",
    "execution_backend",
    "live_dispatch_authorized",
    "live_dispatch_blockers",
    "consumption_state",
}
_CODEX_READINESS_FIELDS = {
    "ready",
    "diagnostic_ready",
    "profile",
    "worker_boundary",
    "hard_worker_confinement",
    "canonical_inventory_oracle",
    "inventory_scope",
    "residual_tool_surface",
    "residual_tool_inventory",
    "qualification_state",
    "cli_version",
    "version_probe_executed",
    "object_bound_executable_binding",
    "cli_binary_identity_scope",
    "environment_preflight",
    "live_dispatch_authorized",
    "live_dispatch_blockers",
}
_PRE_SESSION_FIELDS = {
    "schema_version",
    "diagnostic_contract_version",
    "diagnostic_kind",
    "status",
    "authority",
    "authoritative_review",
    "release_ready",
    "failure_phase",
    "reason_codes",
    "target_sealed",
    "store_created",
    "semantic_subprocess_launched",
    "completion_created",
    "backend_readiness",
}
_POST_STORE_FIELDS = {
    "schema_version",
    "diagnostic_contract_version",
    "diagnostic_kind",
    "status",
    "profile",
    "authority",
    "authoritative_review",
    "release_ready",
    "protocol_completeness",
    "result_state",
    "target_execution",
    "completion_created",
    "failure_phase",
    "reason_codes",
    "assurance_state",
}
_POST_STORE_PHASES = {
    "reviewer_dispatch",
    "reviewer_acceptance",
    "verifier_dispatch",
    "verifier_acceptance",
    "completion_gate",
}
_POST_STORE_REASONS = {
    "worker_unavailable",
    "scripted_attempts_exhausted",
    "worker_attempt_rejected",
    "semantic_contract_rejected",
    "coverage_accounting_failed",
    "scripted_attempts_leftover",
    "scripted_attempt_accounting_mismatch",
    "completion_projection_rejected",
}
_BINDING_REASONS = {
    "request_backend_model_mismatch",
    "synthetic_consumption_state_unavailable",
    "backend_semantic_identity_invalid",
}
_CODEX_BLOCKERS = {
    "canonical_inventory_oracle_unavailable",
    "object_bound_version_probe_unavailable",
    "qualification_record_unavailable",
    "qualification_record_invalid",
    "qualification_record_expired",
    "qualification_record_mismatch",
    "cli_binary_inspection_failed",
}
_FAKE_BLOCKERS = {
    "fake_backend_has_no_live_authority",
    "fake_backend_not_pristine",
    "fake_backend_scenario_invalid",
}
_RECOVERY_REASONS = {
    "store_creation_integrity_failed",
    "canonical_store_verification_failed",
    "artifact_commit_state_uncertain",
    "canonical_readback_integrity_failed",
    "terminal_commit_state_uncertain",
}
_ASSURANCE_STATE = {
    "worker_boundary": "guarded_unconfined",
    "hard_worker_confinement": "not_provided",
    "packet_only_read": "not_guaranteed",
    "residual_tool_surface": "unknown",
    "residual_tool_inventory": "unavailable",
    "worker_child_environment": "not_verified",
    "filesystem_write_mitigation": "not_verified",
    "nested_web_search": "not_verified",
    "backend_stateless_attestation": "unavailable",
    "target_execution": "not_requested",
}


class EvaluationInputError(ValueError):
    """Raised when a request cannot name one new explicit evaluation session."""


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
    diagnostic: dict | None
    recovery_reason_codes: tuple[str, ...]
    evaluation_report_path: Path | None
    diagnostic_path: Path | None
    recovery_diagnostic_path: Path | None

    def __post_init__(self) -> None:
        if not isinstance(self.recovery_reason_codes, tuple):
            raise ValueError("integrity recovery reason codes must be a tuple")
        channels = sum(
            (
                self.evaluation_completion is not None,
                self.diagnostic is not None,
                bool(self.recovery_reason_codes),
            )
        )
        if channels != 1:
            raise ValueError("evaluation outcome must contain exactly one result channel")
        if any(
            path is not None
            for path in (
                self.evaluation_report_path,
                self.diagnostic_path,
                self.recovery_diagnostic_path,
            )
        ):
            raise ValueError("Task 4 outcomes cannot contain materialized paths")
        if self.evaluation_completion is not None and not isinstance(
            self.evaluation_completion, dict
        ):
            raise ValueError("evaluation completion must be an object")
        if self.evaluation_completion is not None:
            try:
                validate_payload("evaluation-completion", self.evaluation_completion)
            except ContractError as error:
                raise ValueError("evaluation completion contract is invalid") from error
        if self.diagnostic is not None:
            validate_evaluation_diagnostic(self.diagnostic)
        if self.recovery_reason_codes:
            if (
                self.recovery_reason_codes
                != tuple(sorted(set(self.recovery_reason_codes)))
                or any(code not in _RECOVERY_REASONS for code in self.recovery_reason_codes)
            ):
                raise ValueError("integrity recovery reason codes are invalid")


def _sorted_unique_strings(value: object, *, allowlist: set[str], label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or value != sorted(set(value))
        or any(not isinstance(item, str) or item not in allowlist for item in value)
    ):
        raise ValueError(f"{label} must be sorted unique allowlisted strings")
    return value


def _nonnegative_count(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _validate_consumption_state(value: object) -> dict:
    if not isinstance(value, Mapping) or set(value) != {
        "total_attempts",
        "consumed_attempts",
        "remaining_attempts",
    }:
        raise ValueError("consumption state fields do not match the contract")
    state = {
        key: _nonnegative_count(value[key], f"consumption {key}")
        for key in ("total_attempts", "consumed_attempts", "remaining_attempts")
    }
    if state["total_attempts"] != state["consumed_attempts"] + state["remaining_attempts"]:
        raise ValueError("consumption state equation does not reconcile")
    return state


def _validate_fake_readiness(value: Mapping[str, object]) -> None:
    if set(value) != _FAKE_READINESS_FIELDS:
        raise ValueError("Fake readiness fields do not match the contract")
    fixed = {
        "mode": "synthetic_evaluation_only",
        "authority": "synthetic_evaluation",
        "execution_backend": "fake_evaluation",
    }
    if any(value[key] != expected for key, expected in fixed.items()):
        raise ValueError("Fake readiness identity/authority mismatch")
    if value["live_dispatch_authorized"] is not False:
        raise ValueError("Fake readiness cannot authorize live dispatch")
    if not isinstance(value["ready"], bool):
        raise ValueError("Fake readiness ready state must be boolean")
    blockers = _sorted_unique_strings(
        value["live_dispatch_blockers"],
        allowlist=_FAKE_BLOCKERS,
        label="Fake readiness blockers",
    )
    if "fake_backend_has_no_live_authority" not in blockers:
        raise ValueError("Fake readiness must retain its no-live-authority blocker")
    state = _validate_consumption_state(value["consumption_state"])
    extras = set(blockers) - {"fake_backend_has_no_live_authority"}
    if value["ready"] and (extras or state["consumed_attempts"] != 0):
        raise ValueError("ready Fake snapshot must be pristine and scenario-valid")
    if ("fake_backend_not_pristine" in extras) != (
        state["consumed_attempts"] > 0
    ):
        raise ValueError("Fake not-pristine blocker/evidence mismatch")
    if not value["ready"] and not extras:
        # Retained for the allowlisted conservative fallback diagnostic.
        return


def _validate_environment_preflight(value: object) -> None:
    if not isinstance(value, Mapping):
        raise ValueError("Codex environment preflight must be an object")
    not_run = {
        "status",
        "evidence_owner",
        "semantic_invocation",
        "worker_environment_policy_sha256",
        "environment_values_recorded",
    }
    if set(value) == not_run:
        if (
            value["status"] != "not_run"
            or value["evidence_owner"] != "adapter_host"
            or value["semantic_invocation"] is not False
            or value["environment_values_recorded"] is not False
            or value["worker_environment_policy_sha256"]
            != WORKER_ENVIRONMENT_POLICY_SHA256
        ):
            raise ValueError("Codex not-run environment preflight is invalid")
        return
    full = {
        "status",
        "evidence_owner",
        "diagnostic_kind",
        "semantic_invocation",
        "target_execution",
        "base_environment",
        "child_environment_keys",
        "descendant_environment_keys",
        "host_runtime_added_keys",
        "child_environment_keys_sha256",
        "worker_environment_policy_sha256",
        "parent_nonallowlisted_keys_excluded",
        "descendant_inheritance_matched",
        "environment_values_recorded",
        "error_code",
    }
    if set(value) != full:
        raise ValueError("Codex environment preflight fields do not match the contract")
    if (
        value["status"] not in {"passed", "failed"}
        or value["evidence_owner"] != "adapter_host"
        or value["diagnostic_kind"] != "trusted_worker_environment_canary"
        or value["semantic_invocation"] is not False
        or value["target_execution"] != "not_requested"
        or value["base_environment"] != "empty"
        or value["environment_values_recorded"] is not False
        or not isinstance(value["parent_nonallowlisted_keys_excluded"], bool)
        or not isinstance(value["descendant_inheritance_matched"], bool)
        or value["error_code"] not in {
            None,
            "canary_nonzero",
            "canary_timeout",
            "canary_invalid_result",
        }
    ):
        raise ValueError("Codex environment preflight fixed state is invalid")
    for field in (
        "child_environment_keys",
        "descendant_environment_keys",
        "host_runtime_added_keys",
    ):
        items = value[field]
        if (
            not isinstance(items, list)
            or items != sorted(set(items))
            or any(not isinstance(item, str) or not item for item in items)
        ):
            raise ValueError(f"Codex preflight {field} must be sorted unique strings")
    policy_keys = set(ENVIRONMENT_ALLOWLIST) | {"TMPDIR"}
    if any(
        not set(value[field]).issubset(policy_keys)
        for field in ("child_environment_keys", "descendant_environment_keys")
    ):
        raise ValueError("Codex environment preflight contains a non-policy key")
    if (
        value["child_environment_keys_sha256"]
        != sha256_json(value["child_environment_keys"])
        or value["worker_environment_policy_sha256"]
        != WORKER_ENVIRONMENT_POLICY_SHA256
    ):
        raise ValueError("Codex environment preflight hashes are invalid")
    passed = (
        value["error_code"] is None
        and value["parent_nonallowlisted_keys_excluded"] is True
        and value["descendant_inheritance_matched"] is True
        and value["child_environment_keys"] == value["descendant_environment_keys"]
        and "TMPDIR" in value["child_environment_keys"]
    )
    if (value["status"] == "passed") != passed:
        raise ValueError("Codex environment preflight status does not match evidence")


def _validate_codex_readiness(value: Mapping[str, object]) -> None:
    if set(value) != _CODEX_READINESS_FIELDS:
        raise ValueError("Codex readiness fields do not match the contract")
    fixed = {
        "profile": "codex_native_guarded",
        "worker_boundary": "guarded_unconfined",
        "hard_worker_confinement": "not_provided",
        "canonical_inventory_oracle": "unavailable",
        "inventory_scope": "known_observed_partial",
        "residual_tool_surface": "unknown",
        "residual_tool_inventory": "unavailable",
        "cli_version": None,
        "object_bound_executable_binding": "unavailable",
    }
    if any(value[key] != expected for key, expected in fixed.items()):
        raise ValueError("Codex guarded readiness fixed state is invalid")
    if any(
        value[key] is not False
        for key in (
            "ready",
            "diagnostic_ready",
            "version_probe_executed",
            "live_dispatch_authorized",
        )
    ):
        raise ValueError("Codex guarded readiness boolean state is invalid")
    if value["qualification_state"] not in {
        "record_unavailable",
        "invalid_record",
        "expired_record",
        "diagnostic_mismatch",
        "not_evaluable_without_object_bound_version_probe",
    }:
        raise ValueError("Codex qualification state is invalid")
    if value["cli_binary_identity_scope"] not in {
        "unavailable",
        "unexecuted_nofollow_file_object",
    }:
        raise ValueError("Codex CLI binary identity scope is invalid")
    blockers = _sorted_unique_strings(
        value["live_dispatch_blockers"],
        allowlist=_CODEX_BLOCKERS,
        label="Codex readiness blockers",
    )
    if not {
        "canonical_inventory_oracle_unavailable",
        "object_bound_version_probe_unavailable",
    }.issubset(blockers):
        raise ValueError("Codex readiness omits a permanent live-dispatch blocker")
    expected_qualification = {
        "record_unavailable": "qualification_record_unavailable",
        "invalid_record": "qualification_record_invalid",
        "expired_record": "qualification_record_expired",
        "diagnostic_mismatch": "qualification_record_mismatch",
        "not_evaluable_without_object_bound_version_probe": (
            "object_bound_version_probe_unavailable"
        ),
    }[value["qualification_state"]]
    expected_blockers = {
        "canonical_inventory_oracle_unavailable",
        "object_bound_version_probe_unavailable",
        expected_qualification,
    }
    if value["cli_binary_identity_scope"] == "unavailable":
        expected_blockers.add("cli_binary_inspection_failed")
    if blockers != sorted(expected_blockers):
        raise ValueError("Codex readiness blockers are not the exact state projection")
    _validate_environment_preflight(value["environment_preflight"])


def _readiness_kind(value: object) -> str:
    if not isinstance(value, Mapping):
        raise ValueError("backend readiness must be an object")
    if set(value) == _FAKE_READINESS_FIELDS:
        _validate_fake_readiness(value)
        return "fake"
    if set(value) == _CODEX_READINESS_FIELDS:
        _validate_codex_readiness(value)
        return "codex"
    raise ValueError("backend readiness is not an exact Fake or Codex snapshot")


def _reject_result_wording(value: object) -> None:
    if isinstance(value, Mapping):
        if "simulated_review_verdict" in value:
            raise ValueError("diagnostic cannot contain a simulated verdict")
        for key, child in value.items():
            _reject_result_wording(key)
            _reject_result_wording(child)
    elif isinstance(value, list):
        for child in value:
            _reject_result_wording(child)
    elif isinstance(value, str):
        lowered = " ".join(unicodedata.normalize("NFKC", value).casefold().split())
        if (
            re.search(r"\bclean\b", lowered)
            or re.search(r"\bpass\b", lowered)
            or re.search(r"\bno\s+issues\b", lowered)
            or re.search(r"\bno\s+confirmed\s+findings\b", lowered)
        ):
            raise ValueError("diagnostic contains forbidden result wording")


def validate_evaluation_diagnostic(value: object) -> None:
    """Validate one exact non-authoritative Task 4 diagnostic payload."""

    try:
        assert_safe_sink(value)
    except SensitiveMaterialError as error:
        raise ValueError("diagnostic failed the safe-sink gate") from error
    _reject_result_wording(value)
    if not isinstance(value, Mapping):
        raise ValueError("diagnostic must be an object")
    common = {
        "schema_version": SCHEMA_VERSION,
        "diagnostic_contract_version": DIAGNOSTIC_CONTRACT_VERSION,
        "authority": "non_authoritative_diagnostic",
    }
    if any(value.get(key) != expected for key, expected in common.items()):
        raise ValueError("diagnostic common authority/version state is invalid")
    if any(
        value.get(key) is not False
        for key in ("authoritative_review", "release_ready", "completion_created")
    ):
        raise ValueError("diagnostic common boolean state is invalid")

    kind = value.get("diagnostic_kind")
    if kind == "pre_session_blocked":
        if set(value) != _PRE_SESSION_FIELDS or value.get("status") != "blocked":
            raise ValueError("pre-session diagnostic fields/status mismatch")
        if any(
            value.get(key) is not False
            for key in (
                "target_sealed",
                "store_created",
                "semantic_subprocess_launched",
                "completion_created",
            )
        ):
            raise ValueError("pre-session diagnostic claims forbidden phase progress")
        phase = value.get("failure_phase")
        if phase not in {"backend_readiness", "backend_binding"}:
            raise ValueError("pre-session diagnostic failure phase is invalid")
        readiness_kind = _readiness_kind(value.get("backend_readiness"))
        reasons = value.get("reason_codes")
        if phase == "backend_binding":
            _sorted_unique_strings(
                reasons, allowlist=_BINDING_REASONS, label="backend binding reasons"
            )
            if len(reasons) != 1:
                raise ValueError("backend binding diagnostic requires one reason")
            if readiness_kind != "fake" or value["backend_readiness"]["ready"] is not True:
                raise ValueError("backend binding diagnostic requires a ready Fake snapshot")
            return
        readiness = value["backend_readiness"]
        if readiness_kind == "codex":
            expected = readiness["live_dispatch_blockers"]
        else:
            if readiness["ready"] is not False:
                raise ValueError("readiness diagnostic cannot contain a ready Fake")
            expected = sorted(
                set(readiness["live_dispatch_blockers"])
                - {"fake_backend_has_no_live_authority"}
            ) or ["fake_backend_not_ready"]
        allowed = _CODEX_BLOCKERS if readiness_kind == "codex" else {
            "fake_backend_not_pristine",
            "fake_backend_scenario_invalid",
            "fake_backend_not_ready",
        }
        _sorted_unique_strings(reasons, allowlist=allowed, label="readiness reasons")
        if reasons != expected:
            raise ValueError("diagnostic reasons do not exactly project readiness blockers")
        return

    if kind == "post_store_incomplete":
        if set(value) != _POST_STORE_FIELDS:
            raise ValueError("post-Store diagnostic fields mismatch")
        fixed = {
            "status": "incomplete",
            "profile": "evaluation_slice_v2",
            "protocol_completeness": "incomplete",
            "result_state": "not_available",
            "target_execution": "not_requested",
        }
        if any(value.get(key) != expected for key, expected in fixed.items()):
            raise ValueError("post-Store diagnostic fixed state is invalid")
        if value.get("failure_phase") not in _POST_STORE_PHASES:
            raise ValueError("post-Store diagnostic failure phase is invalid")
        _sorted_unique_strings(
            value.get("reason_codes"),
            allowlist=_POST_STORE_REASONS,
            label="post-Store reasons",
        )
        if value.get("assurance_state") != _ASSURANCE_STATE:
            raise ValueError("post-Store assurance state is not exact")
        return
    raise ValueError("diagnostic kind is invalid")


def _outcome_completion(payload: dict) -> EvaluationOutcome:
    return EvaluationOutcome(payload, None, (), None, None, None)


def _outcome_diagnostic(payload: dict) -> EvaluationOutcome:
    validate_evaluation_diagnostic(payload)
    return EvaluationOutcome(None, deepcopy(payload), (), None, None, None)


def _outcome_recovery(code: str) -> EvaluationOutcome:
    return EvaluationOutcome(None, None, (code,), None, None, None)


def _validate_request(request: object) -> EvaluationRequest:
    if not isinstance(request, EvaluationRequest):
        raise EvaluationInputError("request must be an EvaluationRequest")
    if not isinstance(request.repo, Path) or not isinstance(request.session_root, Path):
        raise EvaluationInputError("repository and session root must be Path values")
    for field in ("base", "head", "model"):
        value = getattr(request, field)
        if not isinstance(value, str) or not value.strip():
            raise EvaluationInputError(f"{field} must be a nonempty string")
    if request.base == request.head:
        raise EvaluationInputError("base and head must name different revisions")
    session_root = request.session_root.expanduser().resolve()
    try:
        assert_safe_sink({"model": request.model, "session_root": str(session_root)})
    except SensitiveMaterialError as error:
        raise EvaluationInputError("request contains unsafe persisted input") from error
    if os.path.lexists(session_root):
        raise EvaluationInputError("session root must not already exist")
    return request


def _pre_session_diagnostic(
    readiness: dict, *, phase: str, reason_codes: list[str]
) -> EvaluationOutcome:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "diagnostic_contract_version": DIAGNOSTIC_CONTRACT_VERSION,
        "diagnostic_kind": "pre_session_blocked",
        "status": "blocked",
        "authority": "non_authoritative_diagnostic",
        "authoritative_review": False,
        "release_ready": False,
        "failure_phase": phase,
        "reason_codes": sorted(set(reason_codes)),
        "target_sealed": False,
        "store_created": False,
        "semantic_subprocess_launched": False,
        "completion_created": False,
        "backend_readiness": deepcopy(readiness),
    }
    return _outcome_diagnostic(payload)


def _post_store_payload(*, phase: str, reason_codes: list[str]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "diagnostic_contract_version": DIAGNOSTIC_CONTRACT_VERSION,
        "diagnostic_kind": "post_store_incomplete",
        "status": "incomplete",
        "profile": "evaluation_slice_v2",
        "authority": "non_authoritative_diagnostic",
        "authoritative_review": False,
        "release_ready": False,
        "protocol_completeness": "incomplete",
        "result_state": "not_available",
        "target_execution": "not_requested",
        "completion_created": False,
        "failure_phase": phase,
        "reason_codes": sorted(set(reason_codes)),
        "assurance_state": dict(_ASSURANCE_STATE),
    }


def _adapter_producer(operation_id: str, input_hashes: list[str]) -> dict:
    if (
        len(input_hashes) != len(set(input_hashes))
        or any(
            not isinstance(value, str) or _HASH.fullmatch(value) is None
            for value in input_hashes
        )
    ):
        raise ContractError("adapter producer inputs must be unique SHA-256 values")
    return {
        "producer_kind": "adapter_operation",
        "operation_id": operation_id,
        "input_hashes": sorted(input_hashes),
    }


def _normal_failure(
    store: ArtifactStore,
    *,
    phase: str,
    reason_codes: list[str],
    semantic_prefix_hashes: list[str],
) -> EvaluationOutcome:
    try:
        store.verify()
    except (IntegrityError, OSError):
        return _outcome_recovery("canonical_store_verification_failed")
    payload = _post_store_payload(phase=phase, reason_codes=reason_codes)
    validate_evaluation_diagnostic(payload)
    producer = _adapter_producer(
        "adapter-evaluation-diagnostic", semantic_prefix_hashes
    )
    try:
        written = store.write_artifact("diagnostic", payload, producer)
    except (IntegrityError, OSError):
        return _outcome_recovery("terminal_commit_state_uncertain")
    try:
        store.verify()
    except (IntegrityError, OSError):
        return _outcome_recovery("canonical_store_verification_failed")
    try:
        diagnostics = _read_exact_artifacts(store, "diagnostic", [written])
    except (IntegrityError, OSError):
        return _outcome_recovery("canonical_readback_integrity_failed")
    if len(diagnostics) != 1 or diagnostics[0].get("payload") != payload:
        return _outcome_recovery("canonical_readback_integrity_failed")
    return _outcome_diagnostic(diagnostics[0]["payload"])


def _semantic_plan(
    *, model: str, readiness: dict, semantic_identity: dict
) -> dict:
    return {
        "profile": "evaluation_slice_v2",
        "authority": "synthetic_evaluation",
        "execution_backend": "fake_evaluation",
        "release_ready": False,
        "roles": ["correctness"],
        "model": model,
        "schema_contracts": schema_contracts(),
        "prompt_contracts": prompt_contracts(),
        "redaction_contract": redaction_contract(),
        "fake_readiness": deepcopy(readiness),
        "fake_semantic_identity": deepcopy(semantic_identity),
        "orchestration_contract_version": ORCHESTRATION_CONTRACT_VERSION,
        "run_manifest_version": RUN_MANIFEST_VERSION,
    }


def _worker_wrapper_and_producer(
    attempt: object,
    *,
    task: WorkerTask,
    task_record: dict,
    seen_execution: dict[str, set[str]],
) -> tuple[dict, dict]:
    if not isinstance(attempt, WorkerAttempt):
        raise WorkerProtocolError("backend returned no complete worker attempt")
    if not isinstance(attempt.payload, dict) or not isinstance(attempt.manifest, dict):
        raise WorkerProtocolError("worker attempt payload/manifest must be objects")
    if (
        attempt.thread_id != attempt.manifest.get("thread_id")
        or attempt.process_launch_id != attempt.manifest.get("process_launch_id")
    ):
        raise WorkerProtocolError("worker attempt identity does not match its manifest")
    validate_run_manifest(attempt.manifest)
    validate_payload(f"{task.role}-result", attempt.payload)
    if not (
        attempt.payload.get("task_id")
        == attempt.manifest.get("task_id")
        == task.task_id
        == task_record["task_id"]
        and attempt.payload.get("packet_hash")
        == attempt.manifest.get("packet_hash")
        == task.packet_hash
        == task_record["packet_hash"]
        and attempt.manifest.get("task_hash") == task_record["task_hash"]
    ):
        raise WorkerProtocolError("worker attempt does not bind its role task")
    if task.role == "verifier" and (
        attempt.payload.get("candidate_hash") != task.packet.get("candidate_hash")
    ):
        raise WorkerProtocolError("verifier result does not bind its candidate")
    for field in ("task_id", "attempt_hash", "thread_id", "process_launch_id"):
        value = attempt.manifest.get(field)
        if (
            not isinstance(value, str)
            or not value.strip()
            or is_required_evidence_sentinel(value)
            or value in seen_execution[field]
        ):
            raise WorkerProtocolError(f"worker {field} evidence is missing or reused")
    wrapper = {
        "result": deepcopy(attempt.payload),
        "adapter_manifest": deepcopy(attempt.manifest),
    }
    producer = {
        "producer_kind": "worker_attempt",
        "task_id": attempt.manifest["task_id"],
        "attempt_hash": attempt.manifest["attempt_hash"],
        "thread_id": attempt.manifest["thread_id"],
        "process_launch_id": attempt.manifest["process_launch_id"],
        "input_hashes": sorted([task_record["task_hash"], task_record["packet_hash"]]),
    }
    assert_safe_sink({"wrapper": wrapper, "producer": producer})
    for field in seen_execution:
        seen_execution[field].add(attempt.manifest[field])
    return wrapper, producer


def _run_role(
    backend: WorkerBackend,
    *,
    task: WorkerTask,
    task_record: dict,
    attempt_dir: Path,
    seen_execution: dict[str, set[str]],
) -> tuple[dict, dict]:
    result = backend.run(task, attempt_dir)
    return _worker_wrapper_and_producer(
        result,
        task=task,
        task_record=task_record,
        seen_execution=seen_execution,
    )


def _read_exact_artifacts(
    store: ArtifactStore, artifact_type: str, expected_envelopes: list[dict]
) -> list[dict]:
    values = store.read_artifacts(artifact_type)
    if not isinstance(values, list) or any(
        not isinstance(value, dict) for value in values
    ):
        raise IntegrityError(f"canonical {artifact_type} readback shape is invalid")
    try:
        expected_by_hash = {
            value["envelope_hash"]: value for value in expected_envelopes
        }
        actual_by_hash = {value["envelope_hash"]: value for value in values}
    except (KeyError, TypeError) as error:
        raise IntegrityError(
            f"canonical {artifact_type} readback envelope is malformed"
        ) from error
    if (
        len(expected_by_hash) != len(expected_envelopes)
        or len(actual_by_hash) != len(values)
        or set(actual_by_hash) != set(expected_by_hash)
        or any(
            not isinstance(envelope_hash, str)
            or _HASH.fullmatch(envelope_hash) is None
            or actual_by_hash[envelope_hash] != expected_by_hash[envelope_hash]
            for envelope_hash in expected_by_hash
        )
    ):
        raise IntegrityError(f"canonical {artifact_type} readback does not match writes")
    return values


def evaluate(request: EvaluationRequest, backend: WorkerBackend) -> EvaluationOutcome:
    """Run one synthetic evaluation protocol and return no materialized view."""

    request = _validate_request(request)
    try:
        readiness = deepcopy(backend.readiness())
        assert_safe_sink(readiness)
        readiness_kind = _readiness_kind(readiness)
    except (ContractError, SensitiveMaterialError, ValueError) as error:
        raise WorkerProtocolError("backend readiness contract is invalid") from error
    if readiness_kind == "codex" or readiness.get("ready") is not True:
        if readiness_kind == "codex":
            reasons = list(readiness["live_dispatch_blockers"])
        else:
            reasons = sorted(
                set(readiness["live_dispatch_blockers"])
                - {"fake_backend_has_no_live_authority"}
            ) or ["fake_backend_not_ready"]
        return _pre_session_diagnostic(
            readiness, phase="backend_readiness", reason_codes=reasons
        )

    try:
        backend_model = backend.model
    except AttributeError:
        backend_model = None
    if backend_model != request.model:
        return _pre_session_diagnostic(
            readiness,
            phase="backend_binding",
            reason_codes=["request_backend_model_mismatch"],
        )
    consumption_oracle = getattr(backend, "consumption_state", None)
    if not callable(consumption_oracle):
        return _pre_session_diagnostic(
            readiness,
            phase="backend_binding",
            reason_codes=["synthetic_consumption_state_unavailable"],
        )

    # This capture intentionally precedes target sealing so a malformed backend
    # identity remains a truthful pre-session failure with target_sealed=false.
    try:
        semantic_identity = deepcopy(backend.semantic_identity())
        assert_safe_sink(semantic_identity)
        semantic_plan = _semantic_plan(
            model=request.model,
            readiness=readiness,
            semantic_identity=semantic_identity,
        )
        validate_semantic_plan(semantic_plan)
    except (ContractError, SensitiveMaterialError, WorkerProtocolError, WorkerUnavailable):
        return _pre_session_diagnostic(
            readiness,
            phase="backend_binding",
            reason_codes=["backend_semantic_identity_invalid"],
        )

    try:
        target = seal_two_dot_target(request.repo, request.base, request.head)
        target_packet = build_review_packet(target)
        validate_target_packet(
            target_packet, target_identity_hash=target.target_identity_hash
        )
        target_packet_payload_hash = sha256_json(target_packet)
    except (TargetError, ContractError, SensitiveMaterialError) as error:
        raise EvaluationInputError("target cannot be sealed for evaluation") from error

    session_root = request.session_root.expanduser().resolve()
    review_hash = review_identity_hash(target.target_identity_hash, semantic_plan)
    plan_core = {
        "schema_version": SCHEMA_VERSION,
        "session_id": f"session-{uuid.uuid4().hex}",
        "session_root": str(session_root),
        "created_at": datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        "review_identity_hash": review_hash,
        "target_identity_hash": target.target_identity_hash,
        "target_packet_payload_hash": target_packet_payload_hash,
        "semantic_plan": semantic_plan,
    }
    try:
        assert_safe_sink(plan_core)
    except SensitiveMaterialError as error:
        raise EvaluationInputError("session plan contains unsafe persisted input") from error
    plan = {**plan_core, "plan_integrity_hash": sha256_json(plan_core)}
    try:
        store = ArtifactStore.create(session_root, plan)
    except (IntegrityError, OSError):
        return _outcome_recovery("store_creation_integrity_failed")

    semantic_prefix_hashes: list[str] = []
    try:
        target_envelope = store.write_artifact(
            "target_packet",
            target_packet,
            _adapter_producer(
                "adapter-target-packet", [target.target_identity_hash]
            ),
        )
    except (IntegrityError, OSError):
        return _outcome_recovery("artifact_commit_state_uncertain")
    semantic_prefix_hashes.append(target_envelope["envelope_hash"])

    reviewer_packet_written: list[dict] = []
    reviewer_result_written: list[dict] = []
    verifier_packet_written: list[dict] = []
    verifier_result_written: list[dict] = []
    seen_execution = {
        field: set()
        for field in ("task_id", "attempt_hash", "thread_id", "process_launch_id")
    }

    if target_packet["reviewable_atom_ids"]:
        try:
            reviewer_record = build_reviewer_task_record(
                plan=plan,
                target_packet=target_packet,
                target_packet_payload_hash=target_envelope["payload_hash"],
                timeout_seconds=300,
            )
            reviewer_task = validate_role_task_record(
                reviewer_record,
                plan=plan,
                target_packet=target_packet,
                target_packet_payload_hash=target_envelope["payload_hash"],
            )
        except ContractError:
            return _normal_failure(
                store,
                phase="reviewer_acceptance",
                reason_codes=["semantic_contract_rejected"],
                semantic_prefix_hashes=semantic_prefix_hashes,
            )
        try:
            reviewer_packet_envelope = store.write_artifact(
                "reviewer_packet",
                reviewer_record,
                _adapter_producer(
                    "adapter-reviewer-packet", [target_envelope["envelope_hash"]]
                ),
            )
        except (IntegrityError, OSError):
            return _outcome_recovery("artifact_commit_state_uncertain")
        reviewer_packet_written.append(reviewer_packet_envelope)
        semantic_prefix_hashes.append(reviewer_packet_envelope["envelope_hash"])

        try:
            reviewer_wrapper, reviewer_producer = _run_role(
                backend,
                task=reviewer_task,
                task_record=reviewer_record,
                attempt_dir=session_root.parent
                / f".{plan['session_id']}-attempt-reviewer",
                seen_execution=seen_execution,
            )
        except WorkerUnavailable as error:
            worker_diagnostic = (
                error.diagnostic if isinstance(error.diagnostic, Mapping) else {}
            )
            reason = (
                "scripted_attempts_exhausted"
                if worker_diagnostic.get("reason") == "scripted_attempts_exhausted"
                else "worker_unavailable"
            )
            return _normal_failure(
                store,
                phase="reviewer_dispatch",
                reason_codes=[reason],
                semantic_prefix_hashes=semantic_prefix_hashes,
            )
        except (WorkerProtocolError, ContractError, SensitiveMaterialError):
            return _normal_failure(
                store,
                phase="reviewer_acceptance",
                reason_codes=["worker_attempt_rejected"],
                semantic_prefix_hashes=semantic_prefix_hashes,
            )
        try:
            reviewer_result_envelope = store.write_artifact(
                "reviewer_result", reviewer_wrapper, reviewer_producer
            )
        except (IntegrityError, OSError):
            return _outcome_recovery("artifact_commit_state_uncertain")
        reviewer_result_written.append(reviewer_result_envelope)
        semantic_prefix_hashes.append(reviewer_result_envelope["envelope_hash"])

        try:
            canonical_reviewer_results = _read_exact_artifacts(
                store,
                "reviewer_result",
                [reviewer_result_envelope],
            )
        except (IntegrityError, OSError):
            return _outcome_recovery("canonical_readback_integrity_failed")
        reviewer_result = canonical_reviewer_results[0]["payload"]["result"]
        if reviewer_result["coverage"]["reviewed_atom_ids"] != target_packet[
            "reviewable_atom_ids"
        ]:
            return _normal_failure(
                store,
                phase="reviewer_acceptance",
                reason_codes=["coverage_accounting_failed"],
                semantic_prefix_hashes=semantic_prefix_hashes,
            )

        duplicate_counts: dict[str, int] = {}
        for candidate_index, candidate_payload in enumerate(
            reviewer_result["candidates"]
        ):
            try:
                candidate_hash = review_candidate_hash(candidate_payload)
                duplicate_ordinal = duplicate_counts.get(candidate_hash, 0)
                duplicate_counts[candidate_hash] = duplicate_ordinal + 1
                verifier_record = build_verifier_task_record(
                    plan=plan,
                    target_packet=target_packet,
                    target_packet_payload_hash=target_envelope["payload_hash"],
                    candidate=candidate_payload,
                    duplicate_ordinal=duplicate_ordinal,
                    timeout_seconds=300,
                )
                verifier_task = validate_role_task_record(
                    verifier_record,
                    plan=plan,
                    target_packet=target_packet,
                    target_packet_payload_hash=target_envelope["payload_hash"],
                )
            except ContractError:
                return _normal_failure(
                    store,
                    phase="verifier_acceptance",
                    reason_codes=["semantic_contract_rejected"],
                    semantic_prefix_hashes=semantic_prefix_hashes,
                )
            try:
                verifier_packet_envelope = store.write_artifact(
                    "verifier_packet",
                    verifier_record,
                    _adapter_producer(
                        f"adapter-verifier-packet-{verifier_record['task_id']}",
                        [
                            target_envelope["envelope_hash"],
                            reviewer_result_envelope["envelope_hash"],
                        ],
                    ),
                )
            except (IntegrityError, OSError):
                return _outcome_recovery("artifact_commit_state_uncertain")
            verifier_packet_written.append(verifier_packet_envelope)
            semantic_prefix_hashes.append(verifier_packet_envelope["envelope_hash"])

            try:
                verifier_wrapper, verifier_producer = _run_role(
                    backend,
                    task=verifier_task,
                    task_record=verifier_record,
                    attempt_dir=session_root.parent
                    / f".{plan['session_id']}-attempt-verifier-{candidate_index}",
                    seen_execution=seen_execution,
                )
            except WorkerUnavailable as error:
                worker_diagnostic = (
                    error.diagnostic if isinstance(error.diagnostic, Mapping) else {}
                )
                reason = (
                    "scripted_attempts_exhausted"
                    if worker_diagnostic.get("reason") == "scripted_attempts_exhausted"
                    else "worker_unavailable"
                )
                return _normal_failure(
                    store,
                    phase="verifier_dispatch",
                    reason_codes=[reason],
                    semantic_prefix_hashes=semantic_prefix_hashes,
                )
            except (WorkerProtocolError, ContractError, SensitiveMaterialError):
                return _normal_failure(
                    store,
                    phase="verifier_acceptance",
                    reason_codes=["worker_attempt_rejected"],
                    semantic_prefix_hashes=semantic_prefix_hashes,
                )
            try:
                verifier_result_envelope = store.write_artifact(
                    "verifier_result", verifier_wrapper, verifier_producer
                )
            except (IntegrityError, OSError):
                return _outcome_recovery("artifact_commit_state_uncertain")
            verifier_result_written.append(verifier_result_envelope)
            semantic_prefix_hashes.append(verifier_result_envelope["envelope_hash"])

    try:
        store.verify()
    except (IntegrityError, OSError):
        return _outcome_recovery("canonical_store_verification_failed")
    try:
        canonical_targets = _read_exact_artifacts(
            store, "target_packet", [target_envelope]
        )
        canonical_reviewer_packets = _read_exact_artifacts(
            store,
            "reviewer_packet",
            reviewer_packet_written,
        )
        canonical_reviewer_results = _read_exact_artifacts(
            store,
            "reviewer_result",
            reviewer_result_written,
        )
        canonical_verifier_packets = _read_exact_artifacts(
            store,
            "verifier_packet",
            verifier_packet_written,
        )
        canonical_verifier_results = _read_exact_artifacts(
            store,
            "verifier_result",
            verifier_result_written,
        )
    except (IntegrityError, OSError):
        return _outcome_recovery("canonical_readback_integrity_failed")

    expected_attempts = 0
    if target_packet["reviewable_atom_ids"]:
        persisted_candidates = canonical_reviewer_results[0]["payload"]["result"][
            "candidates"
        ]
        expected_attempts = 1 + len(persisted_candidates)
    try:
        state = _validate_consumption_state(deepcopy(consumption_oracle()))
    except (ContractError, SensitiveMaterialError, TypeError, ValueError):
        return _normal_failure(
            store,
            phase="completion_gate",
            reason_codes=["scripted_attempt_accounting_mismatch"],
            semantic_prefix_hashes=semantic_prefix_hashes,
        )
    expected_state = {
        "total_attempts": expected_attempts,
        "consumed_attempts": expected_attempts,
        "remaining_attempts": 0,
    }
    if state != expected_state:
        reason = (
            "scripted_attempts_leftover"
            if state["remaining_attempts"] > 0
            else "scripted_attempt_accounting_mismatch"
        )
        return _normal_failure(
            store,
            phase="completion_gate",
            reason_codes=[reason],
            semantic_prefix_hashes=semantic_prefix_hashes,
        )

    # No backend.run reference is permitted below the exact consumption gate.
    try:
        completion = derive_completion_payload(
            plan=plan,
            target_packet_envelope=canonical_targets[0],
            reviewer_packet_envelopes=canonical_reviewer_packets,
            verifier_packet_envelopes=canonical_verifier_packets,
            reviewer_result_envelopes=canonical_reviewer_results,
            verifier_result_envelopes=canonical_verifier_results,
        )
        sources = completion_source_hashes(
            target_packet_envelope=canonical_targets[0],
            reviewer_packet_envelopes=canonical_reviewer_packets,
            verifier_packet_envelopes=canonical_verifier_packets,
            reviewer_result_envelopes=canonical_reviewer_results,
            verifier_result_envelopes=canonical_verifier_results,
        )
        validate_payload("evaluation-completion", completion)
    except ContractError:
        return _normal_failure(
            store,
            phase="completion_gate",
            reason_codes=["completion_projection_rejected"],
            semantic_prefix_hashes=semantic_prefix_hashes,
        )
    try:
        completion_envelope = store.write_artifact(
            "evaluation_completion",
            completion,
            _adapter_producer("adapter-evaluation-completion", sources),
        )
    except (IntegrityError, OSError):
        return _outcome_recovery("terminal_commit_state_uncertain")
    try:
        store.verify()
    except (IntegrityError, OSError):
        return _outcome_recovery("canonical_store_verification_failed")
    try:
        completions = _read_exact_artifacts(
            store, "evaluation_completion", [completion_envelope]
        )
    except (IntegrityError, OSError):
        return _outcome_recovery("canonical_readback_integrity_failed")
    if len(completions) != 1 or completions[0].get("payload") != completion:
        return _outcome_recovery("canonical_readback_integrity_failed")
    return _outcome_completion(deepcopy(completions[0]["payload"]))
