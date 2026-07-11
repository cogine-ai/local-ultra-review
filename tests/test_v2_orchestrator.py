from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from local_ultra_review.backend import (  # noqa: E402
    LAUNCH_POLICY_SHA256,
    FAKE_BACKEND_VERSION,
    PROTOCOL_VERSION,
    REVIEWED_ATOM_IDS_PLACEHOLDER,
    RUN_MANIFEST_VERSION,
    WORKER_ENVIRONMENT_POLICY_SHA256,
    CodexCliBackend,
    FakeBackend,
    ScriptedAttempt,
    WorkerProtocolError,
    WorkerAttempt,
    WorkerUnavailable,
)
from local_ultra_review import backend as backend_module  # noqa: E402
from local_ultra_review import orchestrator as orchestrator_module  # noqa: E402
from local_ultra_review import render as render_module  # noqa: E402
from local_ultra_review.completion_projection import review_candidate_hash  # noqa: E402
from local_ultra_review.contracts import (  # noqa: E402
    ALL_MANUAL_ASSURANCE,
    DIAGNOSTIC_CONTRACT_VERSION,
    INCOMPLETE_DIAGNOSTIC_BANNER,
    SCHEMA_VERSION,
    SYNTHETIC_ATTEMPT_ASSURANCE,
    adapter_manual_item_hash,
    canonical_json_bytes,
    post_store_diagnostic_assurance,
    pre_session_diagnostic_assurance,
    validate_payload,
    verifier_manual_item_hash,
    sha256_json,
)
from local_ultra_review.git_target import (  # noqa: E402
    build_review_packet,
    seal_two_dot_target,
)
from local_ultra_review.orchestrator import (  # noqa: E402
    EvaluationInputError,
    EvaluationOutcome,
    EvaluationRequest,
    evaluate,
    validate_evaluation_diagnostic,
)
from local_ultra_review.render import (  # noqa: E402
    MaterializationError,
    RenderError,
    render_diagnostic_report,
    render_evaluation_report,
    write_recovery_diagnostic,
)
from local_ultra_review.store import ArtifactStore, IntegrityError  # noqa: E402


def run(argv: list[str], cwd: Path) -> str:
    return subprocess.run(
        argv, cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


class GitRepo:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True)
        run(["git", "init", "-q"], root)
        run(["git", "config", "user.name", "V2 Orchestrator Test"], root)
        run(["git", "config", "user.email", "v2-orchestrator@example.invalid"], root)

    def write_text(self, path: str, value: str) -> None:
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(value, encoding="utf-8")

    def write_bytes(self, path: str, value: bytes) -> None:
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(value)

    def commit(self, message: str) -> str:
        run(["git", "add", "-A"], self.root)
        run(["git", "commit", "-qm", message], self.root)
        return run(["git", "rev-parse", "HEAD"], self.root).strip()


def reviewer_template(atom_ids: object, candidates: list[dict]) -> bytes:
    return json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "task_id": "{{TASK_ID}}",
            "packet_hash": "{{PACKET_HASH}}",
            "status": "completed",
            "coverage": {
                "reviewed_atom_ids": atom_ids,
                "notes": "Reviewed every sealed reviewable atom.",
            },
            "candidates": candidates,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def verifier_template(
    disposition: str,
    *,
    final_severity: str | None = None,
    proof: str = "The candidate was independently checked.",
) -> bytes:
    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "task_id": "{{TASK_ID}}",
        "packet_hash": "{{PACKET_HASH}}",
        "candidate_hash": "{{CANDIDATE_HASH}}",
        "status": "completed",
        "disposition": disposition,
        "provenance": "Compared against the sealed two-dot diff.",
        "best_fix": "Restore the local boundary check.",
        "refactor_judgment": "A focused correction is sufficient.",
        "proof": [proof],
        "residual_risk": "Unrelated runtime paths were not executed.",
    }
    if final_severity is not None:
        payload["final_severity"] = final_severity
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def attempt(
    role: str,
    template: bytes,
    index: int,
    *,
    thread_id: str | None = None,
    process_launch_id: str | None = None,
) -> ScriptedAttempt:
    return ScriptedAttempt(
        expected_role=role,  # type: ignore[arg-type]
        raw_events=(
            {
                "type": "thread.started",
                "thread_id": thread_id or f"thread-{index}",
            },
            {"type": "turn.completed", "usage": {"input_tokens": 1}},
        ),
        last_message_template=template,
        process_launch_id=process_launch_id or f"process-{index}",
    )


def candidate(label: str = "A", *, severity: str = "Important") -> dict:
    return {
        "severity": severity,
        "file": "app.py",
        "line": 1,
        "title": f"Candidate {label}",
        "failure_scenario": f"The changed branch exposes failure {label}.",
        "evidence": [f"Evidence for candidate {label}."],
        "why_diff": f"The two-dot diff introduces condition {label}.",
    }


class EvaluationFixture:
    def __init__(self, test: unittest.TestCase, *, kind: str = "regular") -> None:
        temporary = tempfile.TemporaryDirectory()
        test.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = GitRepo(self.root / "repo")
        if kind == "regular":
            self.repo.write_text("app.py", "VALUE = 1\n")
            self.base = self.repo.commit("base")
            self.repo.write_text("app.py", "VALUE = 2\n")
            self.head = self.repo.commit("head")
        elif kind == "manual":
            self.repo.write_bytes("asset.bin", b"\x00before")
            self.base = self.repo.commit("base")
            self.repo.write_bytes("asset.bin", b"\x00after")
            self.head = self.repo.commit("head")
        elif kind == "mixed":
            self.repo.write_text("app.py", "VALUE = 1\n")
            self.repo.write_bytes("asset.bin", b"\x00before")
            self.base = self.repo.commit("base")
            self.repo.write_text("app.py", "VALUE = 2\n")
            self.repo.write_bytes("asset.bin", b"\x00after")
            self.head = self.repo.commit("head")
        elif kind == "executable":
            self.execution_canary = self.root / "target-executed"
            self.repo.write_text("run-me.sh", "#!/bin/sh\nexit 0\n")
            os.chmod(self.repo.root / "run-me.sh", 0o755)
            self.base = self.repo.commit("base")
            self.repo.write_text("run-me.sh", "#!/bin/sh\ntouch ../target-executed\n")
            self.head = self.repo.commit("head")
        else:
            raise AssertionError(f"unknown fixture kind: {kind}")
        target = seal_two_dot_target(self.repo.root, self.base, self.head)
        self.packet = build_review_packet(target)
        self.session_root = self.root / "session"

    def request(self, *, model: str = "synthetic-model") -> EvaluationRequest:
        return EvaluationRequest(
            repo=self.repo.root,
            base=self.base,
            head=self.head,
            model=model,
            session_root=self.session_root,
        )

    def backend(
        self,
        candidates: list[dict],
        dispositions: list[tuple[str, str | None]],
        *,
        coverage: list[str] | None = None,
        extra_attempts: tuple[ScriptedAttempt, ...] = (),
    ) -> FakeBackend:
        attempts = [
            attempt(
                "reviewer",
                reviewer_template(
                    coverage
                    if coverage is not None
                    else REVIEWED_ATOM_IDS_PLACEHOLDER,
                    candidates,
                ),
                0,
            )
        ]
        for index, (disposition, severity) in enumerate(dispositions, start=1):
            attempts.append(
                attempt(
                    "verifier",
                    verifier_template(disposition, final_severity=severity),
                    index,
                )
            )
        attempts.extend(extra_attempts)
        return FakeBackend(scenario_id="orchestrator-fixture", attempts=attempts)


def fake_readiness(*, ready: bool = False) -> dict:
    return {
        "ready": ready,
        "mode": "synthetic_evaluation_only",
        "authority": "synthetic_evaluation",
        "execution_backend": "fake_evaluation",
        "live_dispatch_authorized": False,
        "live_dispatch_blockers": [
            "fake_backend_has_no_live_authority",
            *([] if ready else ["fake_backend_not_pristine"]),
        ],
        "consumption_state": {
            "total_attempts": 1,
            "consumed_attempts": 0 if ready else 1,
            "remaining_attempts": 1 if ready else 0,
        },
    }


def codex_readiness(*, canary: bool = False) -> dict:
    environment_preflight = {
        "status": "not_run",
        "evidence_owner": "adapter_host",
        "semantic_invocation": False,
        "worker_environment_policy_sha256": WORKER_ENVIRONMENT_POLICY_SHA256,
        "environment_values_recorded": False,
    }
    if canary:
        keys = ["HOME", "PATH", "TMPDIR"]
        environment_preflight = {
            "status": "passed",
            "evidence_owner": "adapter_host",
            "diagnostic_kind": "trusted_worker_environment_canary",
            "semantic_invocation": False,
            "target_execution": "not_requested",
            "base_environment": "empty",
            "child_environment_keys": keys,
            "descendant_environment_keys": keys,
            "host_runtime_added_keys": [],
            "child_environment_keys_sha256": __import__(
                "local_ultra_review.contracts", fromlist=["sha256_json"]
            ).sha256_json(keys),
            "worker_environment_policy_sha256": WORKER_ENVIRONMENT_POLICY_SHA256,
            "parent_nonallowlisted_keys_excluded": True,
            "parent_environment_values_matched": True,
            "descendant_inheritance_matched": True,
            "descendant_environment_values_matched": True,
            "environment_values_recorded": False,
            "error_code": None,
        }
    return {
        "ready": False,
        "diagnostic_ready": False,
        "profile": "codex_native_guarded",
        "worker_boundary": "guarded_unconfined",
        "hard_worker_confinement": "not_provided",
        "canonical_inventory_oracle": "unavailable",
        "inventory_scope": "known_observed_partial",
        "residual_tool_surface": "unknown",
        "residual_tool_inventory": "unavailable",
        "qualification_state": "not_evaluable_without_object_bound_version_probe",
        "cli_version": None,
        "version_probe_executed": False,
        "object_bound_executable_binding": "unavailable",
        "cli_binary_identity_scope": "unexecuted_nofollow_file_object",
        "environment_preflight": environment_preflight,
        "live_dispatch_authorized": False,
        "live_dispatch_blockers": [
            "canonical_inventory_oracle_unavailable",
            "object_bound_version_probe_unavailable",
        ],
    }


def pre_session_diagnostic(readiness: dict, reasons: list[str]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "diagnostic_contract_version": DIAGNOSTIC_CONTRACT_VERSION,
        "diagnostic_kind": "pre_session_blocked",
        "status": "blocked",
        "authority": "non_authoritative_diagnostic",
        "authoritative_review": False,
        "release_ready": False,
        "failure_phase": "backend_readiness",
        "reason_codes": reasons,
        "target_sealed": False,
        "store_created": False,
        "semantic_subprocess_launched": False,
        "completion_created": False,
        "backend_readiness": readiness,
    }


def post_store_diagnostic(
    reason: str = "worker_attempt_rejected",
    *,
    phase: str = "reviewer_acceptance",
) -> dict:
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
        "reason_codes": [reason],
        "assurance_state": post_store_diagnostic_assurance(),
    }


class FakeCodex:
    def __init__(self, root: Path) -> None:
        self.path = root / "fake-codex"
        self.version_probe = root / "version-probe-ran"
        self.semantic_probe = root / "semantic-probe-ran"
        self.path.write_text(
            "#!/bin/sh\n"
            f"touch {str(self.semantic_probe)!r}\n"
            "exit 91\n",
            encoding="utf-8",
        )
        self.path.chmod(self.path.stat().st_mode | stat.S_IXUSR)


def real_codex_backend(root: Path) -> tuple[FakeCodex, CodexCliBackend]:
    fake = FakeCodex(root)
    record = {
        "schema_version": SCHEMA_VERSION,
        "record_kind": "diagnostic_evidence",
        "profile": "codex_native_guarded",
        "worker_boundary": "guarded_unconfined",
        "hard_worker_confinement": "not_provided",
        "cli_version": "codex-cli fixture",
        "cli_binary_sha256": hashlib.sha256(fake.path.read_bytes()).hexdigest(),
        "launch_policy_sha256": LAUNCH_POLICY_SHA256,
        "worker_environment_policy_sha256": WORKER_ENVIRONMENT_POLICY_SHA256,
        "residual_tool_surface": "unknown",
        "residual_tool_inventory": "unavailable",
        "canonical_inventory_oracle": "unavailable",
        "inventory_scope": "known_observed_partial",
        "inventory_source": "worker_observed_only",
        "known_observed_exposures": ["exec_command"],
        "observation_method": "Observed structured worker events only.",
        "qualified_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "telemetry_scope": "observed_events_only",
        "filesystem_write_mitigation": "not_verified",
        "nested_web_search": "not_verified",
        "worker_environment_preflight_state": "not_verified",
        "live_dispatch_authorized": False,
        "live_dispatch_blockers": ["canonical_inventory_oracle_unavailable"],
    }
    record_path = root / "qualification.json"
    record_path.write_bytes(canonical_json_bytes(record))
    backend = CodexCliBackend(
        codex_path=fake.path,
        model="sealed-model",
        qualification_record=record_path,
        parent_environment={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": "C.UTF-8",
            "ORCHESTRATOR_TEST_SECRET": "must-not-inherit",
        },
    )
    return fake, backend


class DiagnosticContractTests(unittest.TestCase):
    def test_exact_fake_codex_and_post_store_diagnostics_validate(self) -> None:
        validate_evaluation_diagnostic(
            pre_session_diagnostic(fake_readiness(), ["fake_backend_not_pristine"])
        )
        validate_evaluation_diagnostic(
            pre_session_diagnostic(
                codex_readiness(),
                [
                    "canonical_inventory_oracle_unavailable",
                    "object_bound_version_probe_unavailable",
                ],
            )
        )
        validate_evaluation_diagnostic(
            pre_session_diagnostic(
                codex_readiness(canary=True),
                [
                    "canonical_inventory_oracle_unavailable",
                    "object_bound_version_probe_unavailable",
                ],
            )
        )
        validate_evaluation_diagnostic(post_store_diagnostic())

    def test_diagnostic_rejects_shape_reason_readiness_and_false_result_claims(self) -> None:
        base = post_store_diagnostic()
        mutations = []
        extra = copy.deepcopy(base)
        extra["extra"] = True
        mutations.append(extra)
        unsorted = copy.deepcopy(base)
        unsorted["reason_codes"] = ["worker_unavailable", "coverage_accounting_failed"]
        mutations.append(unsorted)
        false_claim = copy.deepcopy(base)
        false_claim["message"] = "No confirmed findings"
        mutations.append(false_claim)
        false_verdict = copy.deepcopy(base)
        false_verdict["simulated_review_verdict"] = "clean"
        mutations.append(false_verdict)
        bad_readiness = pre_session_diagnostic(
            fake_readiness(), ["fake_backend_not_pristine"]
        )
        bad_readiness["backend_readiness"]["live_dispatch_authorized"] = True
        mutations.append(bad_readiness)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_evaluation_diagnostic(value)

    def test_post_store_phase_reason_matrix_is_exact(self) -> None:
        matrix = {
            "reviewer_dispatch": {
                "worker_unavailable",
                "scripted_attempts_exhausted",
            },
            "reviewer_acceptance": {
                "worker_attempt_rejected",
                "semantic_contract_rejected",
                "coverage_accounting_failed",
            },
            "verifier_dispatch": {
                "worker_unavailable",
                "scripted_attempts_exhausted",
            },
            "verifier_acceptance": {
                "worker_attempt_rejected",
                "semantic_contract_rejected",
            },
            "completion_gate": {
                "scripted_attempts_leftover",
                "scripted_attempt_accounting_mismatch",
                "completion_projection_rejected",
            },
        }
        for phase, reasons in matrix.items():
            for reason in reasons:
                with self.subTest(valid=(phase, reason)):
                    validate_evaluation_diagnostic(
                        post_store_diagnostic(reason, phase=phase)
                    )

        phases = tuple(matrix)
        for phase, reasons in matrix.items():
            foreign_reason = next(
                reason
                for other_phase in phases
                if other_phase != phase
                for reason in matrix[other_phase]
                if reason not in reasons
            )
            with self.subTest(invalid=(phase, foreign_reason)), self.assertRaises(
                ValueError
            ):
                validate_evaluation_diagnostic(
                    post_store_diagnostic(foreign_reason, phase=phase)
                )

    def test_outcome_requires_exactly_one_channel_and_exact_absolute_path(self) -> None:
        diagnostic = post_store_diagnostic()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        diagnostic_path = root / "diagnostic.md"
        recovery_path = root / "recovery-diagnostic.md"
        diagnostic_path.write_text("diagnostic", encoding="utf-8")
        recovery_path.write_text("recovery", encoding="utf-8")
        EvaluationOutcome(None, diagnostic, (), None, diagnostic_path, None)
        EvaluationOutcome(
            None,
            None,
            ("canonical_store_verification_failed",),
            None,
            None,
            recovery_path,
        )
        invalid = (
            (None, None, (), None, None, None),
            ({"result": "synthetic"}, None, (), None, None, None),
            ({}, diagnostic, (), None, None, None),
            (None, None, ("unknown",), None, None, None),
            (None, diagnostic, (), None, None, None),
            (None, diagnostic, (), root / "evaluation-report.md", None, None),
            (None, diagnostic, (), None, Path("diagnostic.md"), None),
            (None, diagnostic, (), None, root / "report.md", None),
            (None, diagnostic, (), None, root / "missing" / "diagnostic.md", None),
            (
                None,
                None,
                ("canonical_store_verification_failed",),
                None,
                None,
                root / "diagnostic.md",
            ),
        )
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(ValueError):
                EvaluationOutcome(*args)

        directory_path = root / "directory" / "diagnostic.md"
        directory_path.mkdir(parents=True)
        with self.assertRaises(ValueError):
            EvaluationOutcome(None, diagnostic, (), None, directory_path, None)

        symlink_root = root / "symlink"
        symlink_root.mkdir()
        symlink_path = symlink_root / "diagnostic.md"
        symlink_path.symlink_to(diagnostic_path)
        with self.assertRaises(ValueError):
            EvaluationOutcome(None, diagnostic, (), None, symlink_path, None)

        for codes in (
            (
                "terminal_commit_state_uncertain",
                "artifact_commit_state_uncertain",
            ),
            (
                "canonical_readback_integrity_failed",
                "canonical_readback_integrity_failed",
            ),
        ):
            with self.subTest(codes=codes), self.assertRaises(ValueError):
                EvaluationOutcome(None, None, codes, None, None, recovery_path)
        with self.assertRaises(ValueError):
            EvaluationOutcome(  # type: ignore[arg-type]
                None, diagnostic, [], None, diagnostic_path, None
            )

    def test_public_validation_rejects_unhashable_list_elements_as_value_errors(self) -> None:
        malformed_reasons = post_store_diagnostic()
        malformed_reasons["reason_codes"] = [{}]
        with self.assertRaises(ValueError):
            validate_evaluation_diagnostic(malformed_reasons)

        malformed_environment = pre_session_diagnostic(
            codex_readiness(canary=True),
            [
                "canonical_inventory_oracle_unavailable",
                "object_bound_version_probe_unavailable",
            ],
        )
        malformed_environment["backend_readiness"]["environment_preflight"][
            "child_environment_keys"
        ] = [{}]
        with self.assertRaises(ValueError):
            validate_evaluation_diagnostic(malformed_environment)

        with self.assertRaises(ValueError):
            EvaluationOutcome(
                None,
                None,
                ({},),  # type: ignore[arg-type]
                None,
                None,
                None,
            )

    def test_diagnostic_nested_mutations_and_false_wording_are_rejected(self) -> None:
        mutations: list[dict] = []
        missing = post_store_diagnostic()
        del missing["result_state"]
        mutations.append(missing)

        nested_extra = post_store_diagnostic()
        nested_extra["assurance_state"]["extra"] = "unknown"
        mutations.append(nested_extra)

        equation = pre_session_diagnostic(
            fake_readiness(), ["fake_backend_not_pristine"]
        )
        equation["backend_readiness"]["consumption_state"]["remaining_attempts"] = 1
        mutations.append(equation)

        reason_mismatch = pre_session_diagnostic(
            fake_readiness(), ["fake_backend_scenario_invalid"]
        )
        mutations.append(reason_mismatch)

        codex_fixed = pre_session_diagnostic(
            codex_readiness(),
            [
                "canonical_inventory_oracle_unavailable",
                "object_bound_version_probe_unavailable",
            ],
        )
        codex_fixed["backend_readiness"]["diagnostic_ready"] = True
        mutations.append(codex_fixed)

        canary_error = pre_session_diagnostic(
            codex_readiness(canary=True),
            [
                "canonical_inventory_oracle_unavailable",
                "object_bound_version_probe_unavailable",
            ],
        )
        canary_error["backend_readiness"]["environment_preflight"][
            "error_code"
        ] = "canary_timeout"
        mutations.append(canary_error)

        false_wording = pre_session_diagnostic(
            codex_readiness(canary=True),
            [
                "canonical_inventory_oracle_unavailable",
                "object_bound_version_probe_unavailable",
            ],
        )
        false_wording["backend_readiness"]["environment_preflight"][
            "host_runtime_added_keys"
        ] = ["No confirmed findings"]
        mutations.append(false_wording)

        fullwidth_pass = pre_session_diagnostic(
            codex_readiness(canary=True),
            [
                "canonical_inventory_oracle_unavailable",
                "object_bound_version_probe_unavailable",
            ],
        )
        fullwidth_pass["backend_readiness"]["environment_preflight"][
            "host_runtime_added_keys"
        ] = ["ＰＡＳＳ"]
        mutations.append(fullwidth_pass)

        fake_bool_zero = pre_session_diagnostic(
            fake_readiness(), ["fake_backend_not_pristine"]
        )
        fake_bool_zero["backend_readiness"]["live_dispatch_authorized"] = 0
        mutations.append(fake_bool_zero)

        diagnostic_bool_zero = post_store_diagnostic()
        diagnostic_bool_zero["authoritative_review"] = 0
        mutations.append(diagnostic_bool_zero)

        binding_not_ready = pre_session_diagnostic(
            fake_readiness(), ["fake_backend_not_pristine"]
        )
        binding_not_ready["failure_phase"] = "backend_binding"
        binding_not_ready["reason_codes"] = ["request_backend_model_mismatch"]
        mutations.append(binding_not_ready)

        readiness_ready = pre_session_diagnostic(
            fake_readiness(ready=True), ["fake_backend_not_ready"]
        )
        mutations.append(readiness_ready)

        consumed_without_blocker = pre_session_diagnostic(
            fake_readiness(), ["fake_backend_not_pristine"]
        )
        consumed_without_blocker["backend_readiness"][
            "live_dispatch_blockers"
        ] = ["fake_backend_has_no_live_authority", "fake_backend_scenario_invalid"]
        consumed_without_blocker["reason_codes"] = ["fake_backend_scenario_invalid"]
        mutations.append(consumed_without_blocker)

        codex_extra_blocker = pre_session_diagnostic(
            codex_readiness(),
            [
                "canonical_inventory_oracle_unavailable",
                "object_bound_version_probe_unavailable",
                "qualification_record_invalid",
            ],
        )
        codex_extra_blocker["backend_readiness"]["live_dispatch_blockers"] = [
            "canonical_inventory_oracle_unavailable",
            "object_bound_version_probe_unavailable",
            "qualification_record_invalid",
        ]
        mutations.append(codex_extra_blocker)

        wrong_policy = pre_session_diagnostic(
            codex_readiness(),
            [
                "canonical_inventory_oracle_unavailable",
                "object_bound_version_probe_unavailable",
            ],
        )
        wrong_policy["backend_readiness"]["environment_preflight"][
            "worker_environment_policy_sha256"
        ] = "a" * 64
        mutations.append(wrong_policy)

        forged_canary = pre_session_diagnostic(
            codex_readiness(canary=True),
            [
                "canonical_inventory_oracle_unavailable",
                "object_bound_version_probe_unavailable",
            ],
        )
        forged_preflight = forged_canary["backend_readiness"]["environment_preflight"]
        forged_preflight["child_environment_keys"] = ["UNRELATED_PARENT_VALUE"]
        forged_preflight["descendant_environment_keys"] = ["UNRELATED_PARENT_VALUE"]
        forged_preflight["child_environment_keys_sha256"] = sha256_json(
            ["UNRELATED_PARENT_VALUE"]
        )
        mutations.append(forged_canary)

        impossible_scope = pre_session_diagnostic(
            codex_readiness(),
            [
                "canonical_inventory_oracle_unavailable",
                "cli_binary_inspection_failed",
                "object_bound_version_probe_unavailable",
            ],
        )
        impossible_scope["backend_readiness"][
            "cli_binary_identity_scope"
        ] = "unavailable"
        impossible_scope["backend_readiness"]["live_dispatch_blockers"] = [
            "canonical_inventory_oracle_unavailable",
            "cli_binary_inspection_failed",
            "object_bound_version_probe_unavailable",
        ]
        mutations.append(impossible_scope)

        for value in mutations:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_evaluation_diagnostic(value)

    def test_pre_session_diagnostic_owns_a_deep_readiness_snapshot(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        snapshot = fake_readiness()

        class ReusedBackend:
            model = "synthetic-model"

            def readiness(self):
                return snapshot

            def semantic_identity(self):
                raise AssertionError("not ready backend must not expose identity")

            def run(self, task, attempt_dir):
                raise AssertionError("not ready backend must not run")

        outcome = evaluate(
            EvaluationRequest(
                repo=root / "unused",
                base="base",
                head="head",
                model="synthetic-model",
                session_root=root / "session",
            ),
            ReusedBackend(),
        )
        snapshot["live_dispatch_blockers"].append("fake_backend_scenario_invalid")
        snapshot["consumption_state"]["consumed_attempts"] = 99
        self.assertEqual(
            outcome.diagnostic["reason_codes"], ["fake_backend_not_pristine"]
        )
        self.assertEqual(
            outcome.diagnostic["backend_readiness"]["consumption_state"],
            {"total_attempts": 1, "consumed_attempts": 1, "remaining_attempts": 0},
        )

    def test_malformed_backend_readiness_is_protocol_error_not_input_error(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)

        class MalformedReadiness:
            model = "synthetic-model"

            def readiness(self):
                return {"ready": True}

            def semantic_identity(self):
                raise AssertionError("malformed readiness must stop first")

            def run(self, task, attempt_dir):
                raise AssertionError("malformed readiness must not run")

        request = EvaluationRequest(
            repo=root / "unused",
            base="base",
            head="head",
            model="synthetic-model",
            session_root=root / "session",
        )
        with (
            mock.patch(
                "local_ultra_review.orchestrator.seal_two_dot_target"
            ) as seal,
            self.assertRaisesRegex(WorkerProtocolError, "readiness contract"),
        ):
            evaluate(request, MalformedReadiness())
        seal.assert_not_called()
        self.assertFalse((root / "session").exists())

    def test_unhashable_backend_readiness_is_wrapped_as_worker_protocol_error(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        malformed = fake_readiness()
        malformed["live_dispatch_blockers"] = [{}]

        class MalformedReadiness:
            model = "synthetic-model"

            def readiness(self):
                return malformed

        request = EvaluationRequest(
            repo=root / "unused",
            base="base",
            head="head",
            model="synthetic-model",
            session_root=root / "session",
        )
        with self.assertRaisesRegex(WorkerProtocolError, "readiness contract"):
            evaluate(request, MalformedReadiness())
        self.assertFalse((root / "session").exists())


class EvaluationFlowTests(unittest.TestCase):
    def test_actual_codex_and_passing_canary_block_before_target_or_store(self) -> None:
        for run_canary in (False, True):
            with self.subTest(run_canary=run_canary):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                root = Path(temporary.name)
                fake, backend = real_codex_backend(root)
                if run_canary:
                    def exact_canary(argv, *, environment, cwd, timeout_seconds):
                        del cwd, timeout_seconds
                        keys = sorted(environment)
                        value_digest = hashlib.sha256(
                            json.dumps(
                                dict(environment),
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ).hexdigest()
                        observed = {
                            "parent_keys": keys,
                            "raw_parent_keys": keys,
                            "descendant_keys": keys,
                            "raw_descendant_keys": keys,
                            "parent_values_sha256": value_digest,
                            "descendant_values_sha256": value_digest,
                            "descendant_return_code": 0,
                        }
                        return subprocess.CompletedProcess(
                            argv,
                            0,
                            stdout=json.dumps(
                                observed,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8"),
                            stderr=b"",
                        )

                    with mock.patch.object(
                        backend_module, "_run_process", side_effect=exact_canary
                    ):
                        evidence = backend.preflight_worker_environment(root / "canary")
                    self.assertEqual(evidence["status"], "passed")
                    evidence["status"] = "failed"
                    evidence["child_environment_keys"].append("CALLER_MUTATION")
                    readiness_alias = backend.readiness()
                    readiness_alias["environment_preflight"][
                        "descendant_environment_keys"
                    ].append("SECOND_CALLER_MUTATION")
                request = EvaluationRequest(
                    repo=root / "repository-is-never-opened",
                    base="base-ref",
                    head="head-ref",
                    model="sealed-model",
                    session_root=root / "session",
                )
                with (
                    mock.patch.object(
                        backend, "readiness", wraps=backend.readiness
                    ) as readiness,
                    mock.patch.object(
                        backend, "semantic_identity", wraps=backend.semantic_identity
                    ) as semantic_identity,
                    mock.patch.object(backend, "run", wraps=backend.run) as worker_run,
                    mock.patch(
                        "local_ultra_review.orchestrator.seal_two_dot_target"
                    ) as seal,
                    mock.patch(
                        "local_ultra_review.orchestrator.ArtifactStore.create"
                    ) as create_store,
                ):
                    outcome = evaluate(request, backend)

                readiness.assert_called_once_with()
                semantic_identity.assert_not_called()
                worker_run.assert_not_called()
                seal.assert_not_called()
                create_store.assert_not_called()
                self.assertEqual(
                    outcome.diagnostic["reason_codes"],
                    [
                        "canonical_inventory_oracle_unavailable",
                        "object_bound_version_probe_unavailable",
                    ],
                )
                snapshot = outcome.diagnostic["backend_readiness"]
                self.assertFalse(snapshot["ready"])
                self.assertFalse(snapshot["diagnostic_ready"])
                self.assertIsNone(snapshot["cli_version"])
                self.assertFalse(snapshot["version_probe_executed"])
                self.assertEqual(
                    snapshot["object_bound_executable_binding"], "unavailable"
                )
                self.assertFalse(snapshot["live_dispatch_authorized"])
                if run_canary:
                    self.assertEqual(
                        snapshot["environment_preflight"]["status"], "passed"
                    )
                    self.assertNotIn(
                        "CALLER_MUTATION",
                        snapshot["environment_preflight"]["child_environment_keys"],
                    )
                    self.assertNotIn(
                        "SECOND_CALLER_MUTATION",
                        snapshot["environment_preflight"][
                            "descendant_environment_keys"
                        ],
                    )
                self.assertFalse((root / "session").exists())
                self.assertFalse(fake.semantic_probe.exists())

    def test_clean_and_all_manual_complete_with_truthful_reports(self) -> None:
        clean = EvaluationFixture(self)
        clean_outcome = evaluate(clean.request(), clean.backend([], []))
        completion = clean_outcome.evaluation_completion
        assert completion is not None
        validate_payload("evaluation-completion", completion)
        self.assertEqual(completion["simulated_review_verdict"], "clean")
        self.assertFalse(completion["authoritative_review"])
        self.assertEqual(completion["protocol_completeness"], "complete")
        self.assertEqual(
            completion["assurance_contract_under_test"],
            dict(SYNTHETIC_ATTEMPT_ASSURANCE),
        )
        self.assertEqual(
            clean_outcome.evaluation_report_path,
            (clean.session_root.parent / "evaluation-report.md").resolve(),
        )
        self.assertIsNone(clean_outcome.diagnostic_path)
        self.assertIsNone(clean_outcome.recovery_diagnostic_path)
        store = ArtifactStore(clean.session_root)
        self.assertEqual(len(store.read_artifacts("evaluation_completion")), 1)
        self.assertEqual(len(store.read_artifacts("evaluation_report")), 1)
        self.assertFalse((clean.session_root / "report.md").exists())

        manual = EvaluationFixture(self, kind="manual")
        backend = FakeBackend(scenario_id="all-manual", attempts=[])
        with mock.patch.object(backend, "run", wraps=backend.run) as run_worker:
            manual_outcome = evaluate(manual.request(), backend)
        run_worker.assert_not_called()
        manual_completion = manual_outcome.evaluation_completion
        assert manual_completion is not None
        self.assertEqual(
            manual_completion["simulated_review_verdict"], "manual_review_required"
        )
        self.assertEqual(
            manual_completion["assurance_contract_under_test"],
            dict(ALL_MANUAL_ASSURANCE),
        )
        self.assertEqual(
            manual_outcome.evaluation_report_path,
            (manual.session_root.parent / "evaluation-report.md").resolve(),
        )
        self.assertEqual(backend.consumption_state(), {
            "total_attempts": 0,
            "consumed_attempts": 0,
            "remaining_attempts": 0,
        })

    def test_each_verifier_disposition_projects_exact_accounting(self) -> None:
        cases = (
            ("confirmed", "Important", "findings", "confirmed_candidate_dispositions"),
            ("false_positive", None, "clean", "false_positive"),
            ("pre_existing", None, "clean", "pre_existing"),
            ("needs_manual_review", None, "manual_review_required", "needs_manual_review"),
        )
        for disposition, severity, verdict, count_field in cases:
            with self.subTest(disposition=disposition):
                fixture = EvaluationFixture(self)
                finding = candidate(disposition)
                outcome = evaluate(
                    fixture.request(),
                    fixture.backend([finding], [(disposition, severity)]),
                )
                completion = outcome.evaluation_completion
                assert completion is not None
                self.assertEqual(completion["simulated_review_verdict"], verdict)
                self.assertEqual(completion["accounting"][count_field], 1)
                self.assertEqual(completion["accounting"]["raw_candidates"], 1)
                self.assertEqual(completion["accounting"]["verifier_results"], 1)
                self.assertEqual(len(completion["verifier_artifact_hashes"]), 1)
                self.assertEqual(
                    completion["accepted_artifact_hashes"],
                    sorted([
                        completion["reviewer_artifact_hash"],
                        *completion["verifier_artifact_hashes"],
                    ]),
                )
                if disposition == "needs_manual_review":
                    manual_record = completion["manual_item_records"][0]
                    disposition_record = completion["verifier_disposition_records"][0]
                    expected_manual_hash = verifier_manual_item_hash(
                        disposition_record["candidate_hash"],
                        disposition_record["duplicate_ordinal"],
                        disposition_record["verifier_result_envelope_hash"],
                    )
                    self.assertEqual(
                        manual_record["manual_item_hash"], expected_manual_hash
                    )
                    self.assertEqual(
                        completion["manual_item_hashes"], [expected_manual_hash]
                    )

    def test_duplicate_confirmed_instances_keep_ordinals_and_merge_important(self) -> None:
        fixture = EvaluationFixture(self)
        same_root_nit = candidate("duplicate", severity="Nit")
        same_root_important = {**same_root_nit, "severity": "Important"}
        outcome = evaluate(
            fixture.request(),
            fixture.backend(
                [same_root_nit, same_root_important],
                [("confirmed", "Nit"), ("confirmed", "Important")],
            ),
        )
        completion = outcome.evaluation_completion
        assert completion is not None
        self.assertEqual(completion["accounting"]["raw_candidates"], 2)
        self.assertEqual(completion["accounting"]["confirmed_candidate_dispositions"], 2)
        self.assertEqual(completion["accounting"]["canonical_findings"], 1)
        record = completion["canonical_finding_records"][0]
        self.assertEqual(record["merged_final_severity"], "Important")
        self.assertEqual(
            [item["duplicate_ordinal"] for item in record["confirmed_instances"]],
            [0, 0],
        )
        # Severity is part of candidate identity; exact duplicate ordinals are tested separately.
        exact_fixture = EvaluationFixture(self)
        exact = candidate("exact", severity="Nit")
        exact_completion = evaluate(
            exact_fixture.request(),
            exact_fixture.backend(
                [exact, copy.deepcopy(exact)],
                [("confirmed", "Nit"), ("confirmed", "Important")],
            ),
        ).evaluation_completion
        assert exact_completion is not None
        self.assertEqual(
            [item["duplicate_ordinal"] for item in exact_completion["verifier_disposition_records"]],
            [0, 1],
        )
        verifier_packets = ArtifactStore(exact_fixture.session_root).read_artifacts(
            "verifier_packet"
        )
        self.assertEqual(len({item["payload"]["task_id"] for item in verifier_packets}), 2)
        self.assertEqual(len({item["payload"]["packet_hash"] for item in verifier_packets}), 2)

    def test_adapter_manual_content_forces_manual_verdict_with_worker_evidence(self) -> None:
        fixture = EvaluationFixture(self, kind="mixed")
        outcome = evaluate(fixture.request(), fixture.backend([], []))
        completion = outcome.evaluation_completion
        assert completion is not None
        self.assertEqual(completion["simulated_review_verdict"], "manual_review_required")
        self.assertGreater(completion["accounting"]["adapter_manual_items"], 0)
        self.assertEqual(
            completion["coverage"]["reviewed_atoms"]
            + completion["coverage"]["manual_atoms"],
            completion["coverage"]["total_atoms"],
        )
        self.assertTrue(
            all(
                item["domain"] == "adapter_manual_disposition"
                for item in completion["manual_item_records"]
            )
        )
        expected_adapter_hashes = sorted(
            adapter_manual_item_hash(record["disposition"])
            for record in completion["manual_item_records"]
        )
        self.assertEqual(completion["manual_item_hashes"], expected_adapter_hashes)

    def test_exact_producer_lineage_and_final_consumption_gate_order(self) -> None:
        fixture = EvaluationFixture(self)
        candidates = [candidate("lineage-a"), candidate("lineage-b")]
        backend = fixture.backend(
            candidates,
            [("confirmed", "Important"), ("false_positive", None)],
        )
        events: list[tuple[str, object]] = []
        real_readiness = backend.readiness
        real_identity = backend.semantic_identity
        real_consumption = backend.consumption_state
        real_run = backend.run

        def readiness():
            events.append(("readiness", None))
            return real_readiness()

        def identity():
            events.append(("semantic_identity", None))
            return real_identity()

        def consumption():
            state = real_consumption()
            events.append(("consumption", copy.deepcopy(state)))
            return state

        def run_worker(task, attempt_dir):
            events.append(("run", task.role))
            return real_run(task, attempt_dir)

        with (
            mock.patch.object(backend, "readiness", side_effect=readiness),
            mock.patch.object(backend, "semantic_identity", side_effect=identity),
            mock.patch.object(backend, "consumption_state", side_effect=consumption),
            mock.patch.object(backend, "run", side_effect=run_worker),
        ):
            outcome = evaluate(fixture.request(), backend)

        completion = outcome.evaluation_completion
        assert completion is not None
        self.assertEqual(
            [value for name, value in events if name == "run"],
            ["reviewer", "verifier", "verifier"],
        )
        self.assertEqual(
            events[-1],
            (
                "consumption",
                {"total_attempts": 3, "consumed_attempts": 3, "remaining_attempts": 0},
            ),
        )
        self.assertEqual(sum(name == "semantic_identity" for name, _ in events), 1)
        final_consumption_index = len(events) - 1
        self.assertFalse(
            any(name == "run" for name, _ in events[final_consumption_index + 1 :])
        )

        store = ArtifactStore(fixture.session_root)
        target = store.read_artifacts("target_packet")[0]
        reviewer_packet = store.read_artifacts("reviewer_packet")[0]
        reviewer_result = store.read_artifacts("reviewer_result")[0]
        verifier_packets = store.read_artifacts("verifier_packet")
        verifier_results = store.read_artifacts("verifier_result")
        completion_envelope = store.read_artifacts("evaluation_completion")[0]

        self.assertEqual(
            target["producer"],
            {
                "producer_kind": "adapter_operation",
                "operation_id": "adapter-target-packet",
                "input_hashes": [target["payload"]["target_identity_hash"]],
            },
        )
        self.assertEqual(target["input_hashes"], target["producer"]["input_hashes"])
        self.assertEqual(
            reviewer_packet["producer"],
            {
                "producer_kind": "adapter_operation",
                "operation_id": "adapter-reviewer-packet",
                "input_hashes": [target["envelope_hash"]],
            },
        )
        reviewer_manifest = reviewer_result["payload"]["adapter_manifest"]
        reviewer_record = reviewer_packet["payload"]
        self.assertEqual(
            reviewer_result["producer"],
            {
                "producer_kind": "worker_attempt",
                "task_id": reviewer_manifest["task_id"],
                "attempt_hash": reviewer_manifest["attempt_hash"],
                "thread_id": reviewer_manifest["thread_id"],
                "process_launch_id": reviewer_manifest["process_launch_id"],
                "input_hashes": sorted(
                    [reviewer_record["task_hash"], reviewer_record["packet_hash"]]
                ),
            },
        )

        result_by_task = {
            value["payload"]["result"]["task_id"]: value
            for value in verifier_results
        }
        for packet in verifier_packets:
            task_id = packet["payload"]["task_id"]
            self.assertEqual(
                packet["producer"],
                {
                    "producer_kind": "adapter_operation",
                    "operation_id": f"adapter-verifier-packet-{task_id}",
                    "input_hashes": sorted(
                        [target["envelope_hash"], reviewer_result["envelope_hash"]]
                    ),
                },
            )
            result = result_by_task[task_id]
            manifest = result["payload"]["adapter_manifest"]
            self.assertEqual(
                result["producer"]["input_hashes"],
                sorted([packet["payload"]["task_hash"], packet["payload"]["packet_hash"]]),
            )
            self.assertEqual(result["producer"]["attempt_hash"], manifest["attempt_hash"])
            self.assertEqual(result["producer"]["thread_id"], manifest["thread_id"])
            self.assertEqual(
                result["producer"]["process_launch_id"],
                manifest["process_launch_id"],
            )

        semantic_envelopes = [
            target,
            reviewer_packet,
            reviewer_result,
            *verifier_packets,
            *verifier_results,
        ]
        expected_sources = sorted(value["envelope_hash"] for value in semantic_envelopes)
        self.assertEqual(completion_envelope["input_hashes"], expected_sources)
        self.assertEqual(
            completion_envelope["producer"],
            {
                "producer_kind": "adapter_operation",
                "operation_id": "adapter-evaluation-completion",
                "input_hashes": expected_sources,
            },
        )
        accepted_results = sorted(
            [reviewer_result["envelope_hash"]]
            + [value["envelope_hash"] for value in verifier_results]
        )
        self.assertEqual(completion["accepted_artifact_hashes"], accepted_results)
        self.assertNotIn(target["envelope_hash"], completion["accepted_artifact_hashes"])
        self.assertNotIn(
            completion_envelope["envelope_hash"], completion["accepted_artifact_hashes"]
        )
        self.assertEqual(len(store.read_artifacts("evaluation_report")), 1)
        self.assertEqual(store.read_artifacts("diagnostic_report"), [])

    def test_partial_and_unknown_coverage_are_incomplete_not_clean(self) -> None:
        for coverage in (["atom-not-sealed"], []):
            with self.subTest(coverage=coverage):
                fixture = EvaluationFixture(self)
                if not coverage:
                    # The reviewer schema itself rejects an empty reviewed set.
                    template = reviewer_template([], [])
                    backend = FakeBackend(
                        scenario_id="coverage-empty",
                        attempts=[attempt("reviewer", template, 0)],
                    )
                else:
                    backend = fixture.backend([], [], coverage=coverage)
                outcome = evaluate(fixture.request(), backend)
                self.assertIsNone(outcome.evaluation_completion)
                self.assertEqual(outcome.diagnostic["status"], "incomplete")
                self.assertIn(
                    outcome.diagnostic["reason_codes"][0],
                    {"coverage_accounting_failed", "worker_attempt_rejected"},
                )
                self.assertNotIn(
                    "simulated_review_verdict", outcome.diagnostic
                )

        partial_fixture = EvaluationFixture(self)
        self.assertGreater(len(partial_fixture.packet["reviewable_atom_ids"]), 1)
        partial_delegate = partial_fixture.backend([], [])

        class PartialCoverageBackend:
            model = "synthetic-model"

            def readiness(self):
                return partial_delegate.readiness()

            def consumption_state(self):
                return partial_delegate.consumption_state()

            def semantic_identity(self):
                return partial_delegate.semantic_identity()

            def run(self, task, attempt_dir):
                accepted = partial_delegate.run(task, attempt_dir)
                payload = copy.deepcopy(accepted.payload)
                payload["coverage"]["reviewed_atom_ids"] = payload["coverage"][
                    "reviewed_atom_ids"
                ][:1]
                return WorkerAttempt(
                    payload=payload,
                    thread_id=accepted.thread_id,
                    process_launch_id=accepted.process_launch_id,
                    manifest=copy.deepcopy(accepted.manifest),
                )

        partial = evaluate(partial_fixture.request(), PartialCoverageBackend())
        self.assertEqual(
            partial.diagnostic["reason_codes"], ["coverage_accounting_failed"]
        )
        self.assertEqual(partial.diagnostic["failure_phase"], "reviewer_acceptance")
        self.assertEqual(
            ArtifactStore(partial_fixture.session_root).read_artifacts(
                "evaluation_completion"
            ),
            [],
        )

    def test_real_fake_early_rejections_never_seal_or_create_store(self) -> None:
        valid = reviewer_template(REVIEWED_ATOM_IDS_PLACEHOLDER, [])
        identity_misuse = valid.replace(
            b"Reviewed every sealed reviewable atom.", ("a" * 64).encode("ascii")
        )
        cases = (
            (
                "malformed-json",
                ScriptedAttempt(
                    expected_role="reviewer",
                    raw_events=(
                        {"type": "thread.started", "thread_id": "thread-malformed"},
                    ),
                    last_message_template=b'{"task_id":"{{TASK_ID}}",',
                    process_launch_id="process-malformed",
                ),
            ),
            (
                "observed-tool",
                ScriptedAttempt(
                    expected_role="reviewer",
                    raw_events=(
                        {"type": "thread.started", "thread_id": "thread-tool"},
                        {"type": "tool", "name": "forbidden"},
                    ),
                    last_message_template=valid,
                    process_launch_id="process-tool",
                ),
            ),
            (
                "identity-misuse",
                attempt("reviewer", identity_misuse, 0),
            ),
        )
        for name, scripted in cases:
            with self.subTest(name=name):
                fixture = EvaluationFixture(self)
                backend = FakeBackend(
                    scenario_id=f"early-{name}", attempts=[scripted]
                )
                with (
                    mock.patch.object(backend, "run", wraps=backend.run) as worker_run,
                    mock.patch.object(
                        orchestrator_module, "seal_two_dot_target"
                    ) as seal,
                    mock.patch.object(
                        orchestrator_module.ArtifactStore, "create"
                    ) as create_store,
                ):
                    outcome = evaluate(fixture.request(), backend)
                self.assertEqual(
                    outcome.diagnostic["reason_codes"],
                    ["fake_backend_scenario_invalid"],
                )
                worker_run.assert_not_called()
                seal.assert_not_called()
                create_store.assert_not_called()
                self.assertFalse(fixture.session_root.exists())

    def test_real_fake_prompt_only_and_reused_execution_fail_post_store(self) -> None:
        prompt_only_fixture = EvaluationFixture(self)
        prompt_only = json.dumps(
            {
                "task_id": "{{TASK_ID}}",
                "packet_hash": "{{PACKET_HASH}}",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        prompt_backend = FakeBackend(
            scenario_id="prompt-only",
            attempts=[attempt("reviewer", prompt_only, 0)],
        )
        with mock.patch.object(
            prompt_backend, "run", wraps=prompt_backend.run
        ) as prompt_run:
            prompt_outcome = evaluate(prompt_only_fixture.request(), prompt_backend)
        self.assertEqual(
            prompt_outcome.diagnostic["reason_codes"], ["worker_attempt_rejected"]
        )
        self.assertEqual(prompt_outcome.diagnostic["failure_phase"], "reviewer_acceptance")
        self.assertEqual(prompt_run.call_count, 1)
        prompt_store = ArtifactStore(prompt_only_fixture.session_root)
        self.assertEqual(len(prompt_store.read_artifacts("target_packet")), 1)
        self.assertEqual(len(prompt_store.read_artifacts("reviewer_packet")), 1)
        self.assertEqual(prompt_store.read_artifacts("reviewer_result"), [])
        self.assertEqual(prompt_store.read_artifacts("evaluation_completion"), [])

        reuse_fixture = EvaluationFixture(self)
        raw_candidate = candidate("reuse")
        reuse_backend = FakeBackend(
            scenario_id="reuse-evidence",
            attempts=[
                attempt(
                    "reviewer",
                    reviewer_template(REVIEWED_ATOM_IDS_PLACEHOLDER, [raw_candidate]),
                    0,
                ),
                attempt(
                    "verifier",
                    verifier_template("false_positive"),
                    1,
                    thread_id="thread-0",
                    process_launch_id="process-0",
                ),
            ],
        )
        with mock.patch.object(
            reuse_backend, "run", wraps=reuse_backend.run
        ) as reuse_run:
            reuse_outcome = evaluate(reuse_fixture.request(), reuse_backend)
        self.assertEqual(
            reuse_outcome.diagnostic["reason_codes"], ["worker_attempt_rejected"]
        )
        self.assertEqual(reuse_outcome.diagnostic["failure_phase"], "verifier_acceptance")
        self.assertEqual(reuse_run.call_count, 2)
        self.assertEqual(
            reuse_backend.consumption_state(),
            {"total_attempts": 2, "consumed_attempts": 2, "remaining_attempts": 0},
        )
        reuse_store = ArtifactStore(reuse_fixture.session_root)
        self.assertEqual(len(reuse_store.read_artifacts("reviewer_result")), 1)
        self.assertEqual(len(reuse_store.read_artifacts("verifier_packet")), 1)
        self.assertEqual(reuse_store.read_artifacts("verifier_result"), [])
        self.assertEqual(reuse_store.read_artifacts("evaluation_completion"), [])

    def test_nonconforming_backend_packet_and_candidate_mismatch_are_rejected(self) -> None:
        for mismatch_role in ("reviewer", "verifier"):
            with self.subTest(mismatch_role=mismatch_role):
                fixture = EvaluationFixture(self)
                raw_candidate = candidate("mismatch")
                delegate = fixture.backend(
                    [] if mismatch_role == "reviewer" else [raw_candidate],
                    []
                    if mismatch_role == "reviewer"
                    else [("false_positive", None)],
                )

                class NonconformingBackend:
                    model = "synthetic-model"

                    def readiness(self):
                        return delegate.readiness()

                    def consumption_state(self):
                        return delegate.consumption_state()

                    def semantic_identity(self):
                        return delegate.semantic_identity()

                    def run(self, task, attempt_dir):
                        accepted = delegate.run(task, attempt_dir)
                        if task.role != mismatch_role:
                            return accepted
                        payload = copy.deepcopy(accepted.payload)
                        if mismatch_role == "reviewer":
                            payload["packet_hash"] = "a" * 64
                        else:
                            payload["candidate_hash"] = "a" * 64
                        return WorkerAttempt(
                            payload=payload,
                            thread_id=accepted.thread_id,
                            process_launch_id=accepted.process_launch_id,
                            manifest=copy.deepcopy(accepted.manifest),
                        )

                outcome = evaluate(fixture.request(), NonconformingBackend())
                self.assertEqual(
                    outcome.diagnostic["reason_codes"], ["worker_attempt_rejected"]
                )
                self.assertEqual(
                    outcome.diagnostic["failure_phase"],
                    f"{mismatch_role}_acceptance",
                )
                self.assertEqual(
                    ArtifactStore(fixture.session_root).read_artifacts(
                        "evaluation_completion"
                    ),
                    [],
                )

    def test_missing_and_extra_attempts_are_incomplete_with_exact_consumption(self) -> None:
        finding = candidate("missing")
        missing = EvaluationFixture(self)
        missing_backend = missing.backend([finding], [])
        missing_outcome = evaluate(missing.request(), missing_backend)
        self.assertEqual(
            missing_outcome.diagnostic["reason_codes"],
            ["scripted_attempts_exhausted"],
        )
        self.assertEqual(ArtifactStore(missing.session_root).read_artifacts(
            "evaluation_completion"
        ), [])
        missing_store = ArtifactStore(missing.session_root)
        late_prefix = sorted(
            envelope["envelope_hash"]
            for artifact_type in (
                "target_packet",
                "reviewer_packet",
                "reviewer_result",
                "verifier_packet",
                "verifier_result",
            )
            for envelope in missing_store.read_artifacts(artifact_type)
        )
        late_diagnostic = missing_store.read_artifacts("diagnostic")[0]
        self.assertEqual(late_diagnostic["input_hashes"], late_prefix)
        self.assertEqual(late_diagnostic["producer"]["input_hashes"], late_prefix)

        extra = EvaluationFixture(self)
        unused = attempt(
            "verifier",
            verifier_template("false_positive"),
            1,
        )
        extra_backend = extra.backend([], [], extra_attempts=(unused,))
        extra_outcome = evaluate(extra.request(), extra_backend)
        self.assertEqual(
            extra_outcome.diagnostic["reason_codes"],
            ["scripted_attempts_leftover"],
        )
        self.assertEqual(extra_backend.consumption_state(), {
            "total_attempts": 2,
            "consumed_attempts": 1,
            "remaining_attempts": 1,
        })
        self.assertEqual(ArtifactStore(extra.session_root).read_artifacts(
            "evaluation_completion"
        ), [])

    def test_malformed_and_lying_consumption_oracles_reject_completion(self) -> None:
        states = (
            {"total_attempts": 1, "consumed_attempts": 1},
            {"total_attempts": 1, "consumed_attempts": 1, "remaining_attempts": 1},
            {"total_attempts": 0, "consumed_attempts": 0, "remaining_attempts": 0},
        )
        for state in states:
            with self.subTest(state=state):
                fixture = EvaluationFixture(self)
                delegate = fixture.backend([], [])
                events: list[str] = []

                class OracleWrapper:
                    model = "synthetic-model"

                    def readiness(self):
                        return delegate.readiness()

                    def semantic_identity(self):
                        return delegate.semantic_identity()

                    def consumption_state(self):
                        events.append("consumption")
                        return copy.deepcopy(state)

                    def run(self, task, attempt_dir):
                        events.append("run")
                        return delegate.run(task, attempt_dir)

                outcome = evaluate(fixture.request(), OracleWrapper())
                self.assertEqual(
                    outcome.diagnostic["reason_codes"],
                    ["scripted_attempt_accounting_mismatch"],
                )
                self.assertEqual(events, ["run", "consumption"])
                self.assertEqual(
                    ArtifactStore(fixture.session_root).read_artifacts(
                        "evaluation_completion"
                    ),
                    [],
                )

    def test_consumption_oracle_contract_exceptions_are_sanitized_only(self) -> None:
        known = (
            WorkerUnavailable("oracle unavailable", diagnostic={"private": "detail"}),
            WorkerProtocolError("oracle protocol private detail"),
        )
        for error in known:
            with self.subTest(known=type(error).__name__):
                fixture = EvaluationFixture(self)
                delegate = fixture.backend([], [])

                class KnownOracleFailure:
                    model = "synthetic-model"

                    def readiness(self):
                        return delegate.readiness()

                    def semantic_identity(self):
                        return delegate.semantic_identity()

                    def consumption_state(self):
                        raise error

                    def run(self, task, attempt_dir):
                        return delegate.run(task, attempt_dir)

                outcome = evaluate(fixture.request(), KnownOracleFailure())
                self.assertEqual(
                    outcome.diagnostic["reason_codes"],
                    ["scripted_attempt_accounting_mismatch"],
                )
                self.assertNotIn("private", json.dumps(outcome.diagnostic))

        programming = (
            RuntimeError("oracle programming error"),
            AttributeError("oracle attribute programming error"),
        )
        for error in programming:
            with self.subTest(programming=type(error).__name__):
                fixture = EvaluationFixture(self)
                delegate = fixture.backend([], [])

                class ProgrammingOracleFailure:
                    model = "synthetic-model"

                    def readiness(self):
                        return delegate.readiness()

                    def semantic_identity(self):
                        return delegate.semantic_identity()

                    def consumption_state(self):
                        raise error

                    def run(self, task, attempt_dir):
                        return delegate.run(task, attempt_dir)

                with self.assertRaises(type(error)):
                    evaluate(fixture.request(), ProgrammingOracleFailure())

    def test_model_missing_consumption_reused_fake_and_bad_identity_short_circuit(self) -> None:
        fixture = EvaluationFixture(self)
        base_backend = fixture.backend([], [])

        mismatch = evaluate(fixture.request(model="other-model"), base_backend)
        self.assertEqual(
            mismatch.diagnostic["reason_codes"], ["request_backend_model_mismatch"]
        )
        self.assertFalse(fixture.session_root.exists())

        class MissingConsumption:
            model = "synthetic-model"

            def readiness(self):
                return base_backend.readiness()

            def semantic_identity(self):
                raise AssertionError("semantic identity must not be called")

            def run(self, task, attempt_dir):
                raise AssertionError("worker must not run")

        missing_fixture = EvaluationFixture(self)
        missing_outcome = evaluate(missing_fixture.request(), MissingConsumption())
        self.assertEqual(
            missing_outcome.diagnostic["reason_codes"],
            ["synthetic_consumption_state_unavailable"],
        )
        self.assertFalse(missing_fixture.session_root.exists())

        missing_model_fixture = EvaluationFixture(self)
        missing_model_delegate = missing_model_fixture.backend([], [])

        class MissingModel:
            def readiness(self):
                return missing_model_delegate.readiness()

            def consumption_state(self):
                raise AssertionError("model binding must stop before consumption")

        missing_model = evaluate(missing_model_fixture.request(), MissingModel())
        self.assertEqual(
            missing_model.diagnostic["reason_codes"],
            ["request_backend_model_mismatch"],
        )
        self.assertFalse(missing_model_fixture.session_root.exists())

        descriptor_fixture = EvaluationFixture(self)
        descriptor_delegate = descriptor_fixture.backend([], [])

        class ModelDescriptorProgrammingError:
            @property
            def model(self):
                raise AttributeError("internal model descriptor error")

            def readiness(self):
                return descriptor_delegate.readiness()

            def consumption_state(self):
                raise AssertionError("model descriptor must stop before consumption")

        with self.assertRaisesRegex(AttributeError, "model descriptor error"):
            evaluate(descriptor_fixture.request(), ModelDescriptorProgrammingError())
        self.assertFalse(descriptor_fixture.session_root.exists())

        consumption_descriptor_fixture = EvaluationFixture(self)
        consumption_descriptor_delegate = consumption_descriptor_fixture.backend([], [])

        class ConsumptionDescriptorProgrammingError:
            model = "synthetic-model"

            @property
            def consumption_state(self):
                raise AttributeError("internal consumption descriptor error")

            def readiness(self):
                return consumption_descriptor_delegate.readiness()

        with self.assertRaisesRegex(AttributeError, "consumption descriptor error"):
            evaluate(
                consumption_descriptor_fixture.request(),
                ConsumptionDescriptorProgrammingError(),
            )
        self.assertFalse(consumption_descriptor_fixture.session_root.exists())

        reused_fixture = EvaluationFixture(self)
        reused_backend = reused_fixture.backend([], [])
        target = seal_two_dot_target(
            reused_fixture.repo.root, reused_fixture.base, reused_fixture.head
        )
        # Consume the one attempt with a structurally valid standalone role task by
        # letting a throwaway evaluation own it.
        throwaway = EvaluationFixture(self)
        evaluate(throwaway.request(), throwaway.backend([], []))
        reused_backend._next_attempt = 1  # exercise public readiness short-circuit
        reused_outcome = evaluate(reused_fixture.request(), reused_backend)
        self.assertEqual(
            reused_outcome.diagnostic["reason_codes"], ["fake_backend_not_pristine"]
        )
        self.assertFalse(reused_fixture.session_root.exists())
        self.assertTrue(target.target_identity_hash)

        identity_fixture = EvaluationFixture(self)
        identity_delegate = identity_fixture.backend([], [])

        class BadIdentity:
            model = "synthetic-model"

            def readiness(self):
                return identity_delegate.readiness()

            def consumption_state(self):
                return identity_delegate.consumption_state()

            def semantic_identity(self):
                value = identity_delegate.semantic_identity()
                value["backend_version"] = "wrong"
                return value

            def run(self, task, attempt_dir):
                raise AssertionError("worker must not run")

        bad = evaluate(identity_fixture.request(), BadIdentity())
        self.assertEqual(
            bad.diagnostic["reason_codes"], ["backend_semantic_identity_invalid"]
        )
        self.assertFalse(identity_fixture.session_root.exists())

        attribute_fixture = EvaluationFixture(self)
        attribute_delegate = attribute_fixture.backend([], [])

        class IdentityProgrammingError:
            model = "synthetic-model"

            def readiness(self):
                return attribute_delegate.readiness()

            def consumption_state(self):
                return attribute_delegate.consumption_state()

            def semantic_identity(self):
                raise AttributeError("internal identity programming error")

            def run(self, task, attempt_dir):
                raise AssertionError("identity programming error must stop before run")

        with self.assertRaisesRegex(AttributeError, "identity programming error"):
            evaluate(attribute_fixture.request(), IdentityProgrammingError())
        self.assertFalse(attribute_fixture.session_root.exists())

    def test_worker_rejection_becomes_sanitized_post_store_diagnostic(self) -> None:
        fixture = EvaluationFixture(self)
        delegate = fixture.backend([], [])

        class RejectingBackend:
            model = "synthetic-model"

            def readiness(self):
                return delegate.readiness()

            def consumption_state(self):
                return delegate.consumption_state()

            def semantic_identity(self):
                return delegate.semantic_identity()

            def run(self, task, attempt_dir):
                raise WorkerProtocolError("observed forbidden tool call with private detail")

        outcome = evaluate(fixture.request(), RejectingBackend())
        self.assertEqual(
            outcome.diagnostic["reason_codes"], ["worker_attempt_rejected"]
        )
        self.assertNotIn("private detail", json.dumps(outcome.diagnostic))
        store = ArtifactStore(fixture.session_root)
        diagnostics = store.read_artifacts("diagnostic")
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0]["payload"], outcome.diagnostic)
        prefix_hashes = sorted(
            envelope["envelope_hash"]
            for artifact_type in ("target_packet", "reviewer_packet")
            for envelope in store.read_artifacts(artifact_type)
        )
        self.assertEqual(diagnostics[0]["input_hashes"], prefix_hashes)

    def test_invalid_request_is_input_error_without_mutation(self) -> None:
        fixture = EvaluationFixture(self)
        invalid = EvaluationRequest(
            repo=fixture.repo.root,
            base=fixture.base,
            head=fixture.base,
            model="synthetic-model",
            session_root=fixture.session_root,
        )
        with self.assertRaises(EvaluationInputError):
            evaluate(invalid, fixture.backend([], []))
        self.assertFalse(fixture.session_root.exists())

    def test_invalid_request_types_and_existing_root_do_not_call_readiness(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        existing = root / "existing"
        existing.mkdir()
        backend = mock.Mock()
        invalid_requests = (
            EvaluationRequest(  # type: ignore[arg-type]
                repo="not-a-Path",
                base="base",
                head="head",
                model="model",
                session_root=root / "session-a",
            ),
            EvaluationRequest(
                repo=root,
                base="",
                head="head",
                model="model",
                session_root=root / "session-b",
            ),
            EvaluationRequest(
                repo=root,
                base="base",
                head="head",
                model="model",
                session_root=existing,
            ),
            EvaluationRequest(
                repo=root,
                base="base",
                head="head",
                model="password = super-secret-password",
                session_root=root / "session-c",
            ),
        )
        for request in invalid_requests:
            with self.subTest(request=request), self.assertRaises(EvaluationInputError):
                evaluate(request, backend)
        backend.readiness.assert_not_called()

    def test_invalid_ref_and_dirty_target_are_input_errors_before_store(self) -> None:
        invalid_ref = EvaluationFixture(self)
        invalid_request = EvaluationRequest(
            repo=invalid_ref.repo.root,
            base="missing-ref",
            head=invalid_ref.head,
            model="synthetic-model",
            session_root=invalid_ref.session_root,
        )
        with self.assertRaises(EvaluationInputError):
            evaluate(invalid_request, invalid_ref.backend([], []))
        self.assertFalse(invalid_ref.session_root.exists())

        dirty = EvaluationFixture(self)
        dirty_backend = dirty.backend([], [])
        dirty.repo.write_text("untracked.txt", "dirty\n")
        with self.assertRaises(EvaluationInputError):
            evaluate(dirty.request(), dirty_backend)
        self.assertFalse(dirty.session_root.exists())

    def test_ready_call_order_captures_identity_before_target_seal(self) -> None:
        fixture = EvaluationFixture(self, kind="manual")
        backend = FakeBackend(scenario_id="call-order", attempts=[])
        events: list[str] = []
        real_readiness = backend.readiness
        real_identity = backend.semantic_identity
        real_seal = orchestrator_module.seal_two_dot_target

        def readiness():
            events.append("readiness")
            return real_readiness()

        def identity():
            events.append("semantic_identity")
            return real_identity()

        def seal(*args, **kwargs):
            events.append("seal_target")
            return real_seal(*args, **kwargs)

        with (
            mock.patch.object(backend, "readiness", side_effect=readiness),
            mock.patch.object(backend, "semantic_identity", side_effect=identity),
            mock.patch.object(
                orchestrator_module, "seal_two_dot_target", side_effect=seal
            ),
        ):
            outcome = evaluate(fixture.request(), backend)
        self.assertIsNotNone(outcome.evaluation_completion)
        self.assertEqual(events, ["readiness", "semantic_identity", "seal_target"])

    def test_store_integrity_failures_return_only_stable_recovery_codes(self) -> None:
        for exception in (
            IntegrityError("create integrity private detail"),
            OSError("create OS private detail"),
        ):
            with self.subTest(create_exception=type(exception).__name__):
                create_fixture = EvaluationFixture(self, kind="manual")
                with mock.patch.object(
                    orchestrator_module.ArtifactStore,
                    "create",
                    side_effect=exception,
                ):
                    create_outcome = evaluate(
                        create_fixture.request(),
                        FakeBackend(scenario_id="create-failure", attempts=[]),
                    )
                self.assertEqual(
                    create_outcome.recovery_reason_codes,
                    ("store_creation_integrity_failed",),
                )
                self.assertIsNone(create_outcome.diagnostic)
                self.assertFalse(create_fixture.session_root.exists())

        original_create = ArtifactStore.create

        class StoreProxy:
            def __init__(self, real: ArtifactStore, mode: str, state: dict) -> None:
                self.real = real
                self.mode = mode
                self.state = state
                self.log: list[str] = []
                self.write_count = 0

            def _fault(self) -> None:
                self.state["faulted"] = True

            def write_artifact(self, artifact_type, payload, producer):
                self.log.append(f"write:{artifact_type}")
                self.write_count += 1
                envelope = self.real.write_artifact(artifact_type, payload, producer)
                if self.mode == "semantic_write" and self.write_count == 1:
                    self._fault()
                    raise OSError("semantic post-commit private detail")
                if self.mode == "semantic_result_write" and artifact_type == "reviewer_result":
                    self._fault()
                    raise OSError("result post-commit private detail")
                if self.mode == "terminal_write" and artifact_type == "evaluation_completion":
                    self._fault()
                    raise OSError("terminal post-commit private detail")
                if self.mode == "diagnostic_terminal" and artifact_type == "diagnostic":
                    self._fault()
                    raise OSError("diagnostic post-commit private detail")
                if self.mode.startswith("tamper_") and artifact_type == "target_packet":
                    if self.mode == "tamper_plan":
                        (self.real.session_root / "plan.json").write_bytes(b"{}\n")
                    elif self.mode == "tamper_ledger":
                        (self.real.session_root / "ledger.jsonl").write_bytes(b"{}\n")
                    else:
                        artifact_path = next(
                            (self.real.session_root / "artifacts" / "target_packet").glob(
                                "*.json"
                            )
                        )
                        artifact_path.write_bytes(b"{}\n")
                return envelope

            def verify(self):
                self.log.append("verify")
                if self.mode.startswith("tamper_"):
                    self._fault()
                return self.real.verify()

            def read_artifacts(self, artifact_type):
                self.log.append(f"read:{artifact_type}")
                if self.mode == "readback":
                    self._fault()
                    raise OSError("readback private detail")
                if self.mode == "readback_empty":
                    self._fault()
                    return []
                if (
                    self.mode == "completion_readback_empty"
                    and artifact_type == "evaluation_completion"
                ):
                    self._fault()
                    return []
                return self.real.read_artifacts(artifact_type)

        cases = (
            ("semantic_write", "artifact_commit_state_uncertain"),
            ("semantic_result_write", "artifact_commit_state_uncertain"),
            ("tamper_plan", "canonical_store_verification_failed"),
            ("tamper_ledger", "canonical_store_verification_failed"),
            ("tamper_artifact", "canonical_store_verification_failed"),
            ("readback", "canonical_readback_integrity_failed"),
            ("readback_empty", "canonical_readback_integrity_failed"),
            ("completion_readback_empty", "canonical_readback_integrity_failed"),
            ("terminal_write", "terminal_commit_state_uncertain"),
            ("diagnostic_terminal", "terminal_commit_state_uncertain"),
        )
        for mode, expected_code in cases:
            with self.subTest(mode=mode):
                fixture = EvaluationFixture(
                    self,
                    kind="regular" if mode == "semantic_result_write" else "manual",
                )
                state = {"faulted": False}
                holder: dict[str, StoreProxy] = {}

                def create_proxy(session_root, plan):
                    proxy = StoreProxy(original_create(session_root, plan), mode, state)
                    holder["proxy"] = proxy
                    return proxy

                original_hash = orchestrator_module.sha256_json

                def guarded_hash(value):
                    if state["faulted"]:
                        raise AssertionError("orchestrator hashed after integrity outcome")
                    return original_hash(value)

                with (
                    mock.patch.object(
                        orchestrator_module.ArtifactStore,
                        "create",
                        side_effect=create_proxy,
                    ),
                    mock.patch.object(
                        orchestrator_module,
                        "sha256_json",
                        side_effect=guarded_hash,
                    ),
                ):
                    if mode == "semantic_result_write":
                        backend = fixture.backend([], [])
                    else:
                        backend = FakeBackend(
                            scenario_id=f"integrity-{mode}",
                            attempts=(
                                [
                                    attempt(
                                        "reviewer",
                                        reviewer_template(["atom-unbound-fixture"], []),
                                        0,
                                    )
                                ]
                                if mode == "diagnostic_terminal"
                                else []
                            ),
                        )
                    outcome = evaluate(fixture.request(), backend)

                self.assertEqual(outcome.recovery_reason_codes, (expected_code,))
                self.assertIsNone(outcome.evaluation_completion)
                self.assertIsNone(outcome.diagnostic)
                proxy = holder["proxy"]
                fault_index = next(
                    index
                    for index, item in enumerate(proxy.log)
                    if (
                        (mode == "semantic_write" and item == "write:target_packet")
                        or (
                            mode == "semantic_result_write"
                            and item == "write:reviewer_result"
                        )
                        or (mode.startswith("tamper_") and item == "verify")
                        or (
                            mode
                            in {
                                "readback",
                                "readback_empty",
                                "completion_readback_empty",
                            }
                            and item.startswith("read:")
                            and (
                                mode != "completion_readback_empty"
                                or item == "read:evaluation_completion"
                            )
                        )
                        or (
                            mode == "terminal_write"
                            and item == "write:evaluation_completion"
                        )
                        or (
                            mode == "diagnostic_terminal"
                            and item == "write:diagnostic"
                        )
                    )
                )
                self.assertEqual(fault_index, len(proxy.log) - 1)
                if mode != "diagnostic_terminal":
                    self.assertFalse(
                        (fixture.session_root / "artifacts" / "diagnostic").exists()
                    )
                self.assertFalse(
                    (fixture.session_root / "artifacts" / "evaluation_report").exists()
                )

    def test_unknown_store_exception_propagates(self) -> None:
        fixture = EvaluationFixture(self, kind="manual")
        with mock.patch.object(
            orchestrator_module.ArtifactStore,
            "create",
            side_effect=RuntimeError("programming error"),
        ):
            with self.assertRaisesRegex(RuntimeError, "programming error"):
                evaluate(
                    fixture.request(),
                    FakeBackend(scenario_id="unknown-store-error", attempts=[]),
                )

        projection_fixture = EvaluationFixture(self, kind="manual")
        with mock.patch.object(
            orchestrator_module,
            "derive_completion_payload",
            side_effect=RuntimeError("projection programming error"),
        ):
            with self.assertRaisesRegex(RuntimeError, "projection programming error"):
                evaluate(
                    projection_fixture.request(),
                    FakeBackend(scenario_id="unknown-projection-error", attempts=[]),
                )

    def test_task4_never_calls_v1_network_or_target_execution(self) -> None:
        fixture = EvaluationFixture(self, kind="executable")
        real_subprocess_run = subprocess.run
        commands: list[list[str]] = []

        def git_only(argv, *args, **kwargs):
            if (
                not isinstance(argv, (list, tuple))
                or not argv
                or Path(argv[0]).name != "git"
            ):
                raise AssertionError(f"Task 4 attempted a non-Git subprocess: {argv!r}")
            commands.append(list(argv))
            return real_subprocess_run(argv, *args, **kwargs)

        with (
            mock.patch("subprocess.run", side_effect=git_only),
            mock.patch.object(
                socket,
                "socket",
                side_effect=AssertionError("Task 4 attempted a network socket"),
            ),
            mock.patch.object(
                os,
                "system",
                side_effect=AssertionError("Task 4 attempted a shell/V1 command"),
            ),
        ):
            outcome = evaluate(fixture.request(), fixture.backend([], []))
        self.assertIsNotNone(outcome.evaluation_completion)
        self.assertTrue(commands)
        self.assertTrue(
            all(
                Path(command[0]).is_absolute()
                and Path(command[0]).name == "git"
                for command in commands
            )
        )
        argv_text = json.dumps(commands)
        self.assertNotIn("local_review_session.py", argv_text)
        for v1_script in (
            "run-reviewers.py",
            "verify-findings.py",
            "dedupe-rank.py",
            "render-report.py",
        ):
            self.assertNotIn(v1_script, argv_text)
        self.assertNotIn("curl", argv_text)
        self.assertNotIn("wget", argv_text)
        self.assertFalse(fixture.execution_canary.exists())
        self.assertFalse((fixture.session_root / "diagnostic.md").exists())
        self.assertFalse((fixture.session_root / "recovery-diagnostic.md").exists())

    def test_task5_materializes_truthful_exclusive_views(self) -> None:
        clean = EvaluationFixture(self)
        clean_outcome = evaluate(clean.request(), clean.backend([], []))
        expected_evaluation = (clean.session_root.parent / "evaluation-report.md").resolve()
        self.assertEqual(clean_outcome.evaluation_report_path, expected_evaluation)
        self.assertIsNone(clean_outcome.diagnostic_path)
        self.assertIsNone(clean_outcome.recovery_diagnostic_path)
        text = expected_evaluation.read_text(encoding="utf-8")
        self.assertIn("# Synthetic protocol evaluation — not a code-review result", text)
        self.assertIn("authority: synthetic_evaluation", text)
        self.assertIn("authoritative_review: false", text)
        self.assertIn("profile: evaluation_slice_v2", text)
        self.assertIn("release_ready: false", text)
        self.assertIn("simulated_review_verdict: `clean`", text)
        self.assertIn("makes no claim that the target is clean", text)
        self.assertIn("target_execution: `not_requested`", text)
        self.assertIn(
            "worker_profile_display: `Codex-native guarded worker (no hard confinement)`",
            text,
        )
        self.assertNotIn("# Local Ultra Review Report", text)
        self.assertNotIn("authoritative_review=true", text)
        self.assertFalse((clean.session_root.parent / "report.md").exists())
        self.assertFalse((clean.session_root / "evaluation-report.md").exists())
        self.assertEqual(
            {path.name for path in clean.session_root.iterdir()},
            {"plan.json", "ledger.jsonl", "artifacts"},
        )
        store = ArtifactStore(clean.session_root)
        reports = store.read_artifacts("evaluation_report")
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["payload"]["content"], text)

        primer = EvaluationFixture(self)
        blocked_backend = primer.backend([], [])
        evaluate(primer.request(), blocked_backend)
        blocked = EvaluationFixture(self)
        blocked_request = EvaluationRequest(
            repo=blocked.repo.root,
            base=blocked.base,
            head=blocked.head,
            model="synthetic-model",
            session_root=blocked.root / "new-parent" / "session",
        )
        blocked_outcome = evaluate(blocked_request, blocked_backend)
        expected_diagnostic = (
            blocked_request.session_root.parent / "diagnostic.md"
        ).resolve()
        self.assertEqual(blocked_outcome.diagnostic_path, expected_diagnostic)
        self.assertIsNone(blocked_outcome.evaluation_report_path)
        diagnostic_text = expected_diagnostic.read_text(encoding="utf-8")
        self.assertIn("# Synthetic protocol diagnostic — not a code-review result", diagnostic_text)
        self.assertIn("state: `blocked`", diagnostic_text)
        self.assertIn("residual_tool_surface: `unknown`", diagnostic_text)
        self.assertIn("worker_child_environment: `not_verified`", diagnostic_text)
        self.assertIn(
            "Review process blocked under the Codex-native guarded worker profile. "
            "Hard worker confinement was not provided. “Clean” means no confirmed "
            "findings under the completed review contract; it is not a worker-security claim.",
            diagnostic_text,
        )
        self.assertIn("accepted_tool_calls: `not_applicable_no_dispatch`", diagnostic_text)
        self.assertIn("telemetry_scope: `not_applicable_no_dispatch`", diagnostic_text)
        self.assertIn(
            "worker_profile_display: `Codex-native guarded worker (no hard confinement)`",
            diagnostic_text,
        )
        self.assertNotIn("Review process complete", diagnostic_text)
        self.assertNotIn("simulated_review_verdict", diagnostic_text)
        self.assertFalse(blocked_request.session_root.exists())

    def test_task5_all_manual_report_says_no_worker_was_dispatched(self) -> None:
        fixture = EvaluationFixture(self, kind="manual")
        outcome = evaluate(
            fixture.request(), FakeBackend(scenario_id="task5-all-manual", attempts=[])
        )
        assert outcome.evaluation_report_path is not None
        text = outcome.evaluation_report_path.read_text(encoding="utf-8")
        self.assertIn("No worker was dispatched for this all-manual fixture.", text)
        self.assertNotIn("zero tool calls", text.casefold())

    def test_task5_findings_and_manual_items_stay_explicitly_synthetic(self) -> None:
        findings = EvaluationFixture(self)
        findings_outcome = evaluate(
            findings.request(),
            findings.backend([candidate("rendered")], [("confirmed", "Important")]),
        )
        assert findings_outcome.evaluation_report_path is not None
        findings_text = findings_outcome.evaluation_report_path.read_text(encoding="utf-8")
        self.assertIn("simulated_review_verdict: `findings`", findings_text)
        self.assertIn("### Synthetic fixture finding 1", findings_text)
        self.assertIn("synthetic_title: `Candidate rendered`", findings_text)
        self.assertIn("synthetic_severity: `Important`", findings_text)

        manual = EvaluationFixture(self, kind="manual")
        manual_outcome = evaluate(
            manual.request(), FakeBackend(scenario_id="render-manual", attempts=[])
        )
        assert manual_outcome.evaluation_report_path is not None
        manual_text = manual_outcome.evaluation_report_path.read_text(encoding="utf-8")
        self.assertIn("simulated_review_verdict: `manual_review_required`", manual_text)
        self.assertIn("### Synthetic fixture manual item 1", manual_text)
        self.assertIn("synthetic_manual_domain: `adapter_manual_disposition`", manual_text)
        self.assertNotIn("No worker calls were observed", manual_text)

    def test_task5_post_store_failure_persists_then_materializes_diagnostic(self) -> None:
        fixture = EvaluationFixture(self)
        outcome = evaluate(
            fixture.request(),
            FakeBackend(scenario_id="render-worker-failure", attempts=[]),
        )
        assert outcome.diagnostic is not None
        self.assertEqual(outcome.diagnostic["status"], "incomplete")
        self.assertEqual(outcome.diagnostic["reason_codes"], ["scripted_attempts_exhausted"])
        expected = (fixture.session_root.parent / "diagnostic.md").resolve()
        self.assertEqual(outcome.diagnostic_path, expected)
        self.assertIsNone(outcome.evaluation_report_path)
        text = expected.read_text(encoding="utf-8")
        self.assertIn("state: `incomplete`", text)
        self.assertIn("- `scripted_attempts_exhausted`", text)
        self.assertIn(INCOMPLETE_DIAGNOSTIC_BANNER, text)
        self.assertIn("accepted_tool_calls: `not_available_incomplete`", text)
        self.assertIn("telemetry_scope: `not_available_incomplete`", text)
        self.assertNotIn("Review process complete", text)
        without_contract_banner = text.replace(INCOMPLETE_DIAGNOSTIC_BANNER, "")
        self.assertNotRegex(
            without_contract_banner.casefold(),
            r"\b(no issues|no confirmed findings|pass)\b",
        )
        store = ArtifactStore(fixture.session_root)
        self.assertEqual(len(store.read_artifacts("diagnostic")), 1)
        reports = store.read_artifacts("diagnostic_report")
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["payload"]["content"], text)

    def test_task5_renderer_rejects_bad_authority_hard_claims_and_tampered_inputs(self) -> None:
        fixture = EvaluationFixture(self)
        outcome = evaluate(fixture.request(), fixture.backend([], []))
        assert outcome.evaluation_completion is not None
        store = ArtifactStore(fixture.session_root)
        plan = store._plan
        artifacts = [
            *store.read_artifacts("reviewer_result"),
            *store.read_artifacts("verifier_result"),
        ]
        expected = render_evaluation_report(
            plan=plan,
            completion=outcome.evaluation_completion,
            artifacts=artifacts,
        )
        assert outcome.evaluation_report_path is not None
        self.assertEqual(expected, outcome.evaluation_report_path.read_text(encoding="utf-8"))

        mutations: list[tuple[dict, dict, list[dict]]] = []
        bad_authority = copy.deepcopy(outcome.evaluation_completion)
        bad_authority["authority"] = "canonical_review"
        mutations.append((plan, bad_authority, artifacts))
        hard_claim = copy.deepcopy(outcome.evaluation_completion)
        hard_claim["assurance_contract_under_test"]["hard_worker_confinement"] = "provided"
        mutations.append((plan, hard_claim, artifacts))
        bad_plan = copy.deepcopy(plan)
        bad_plan["semantic_plan"]["release_ready"] = True
        mutations.append((bad_plan, outcome.evaluation_completion, artifacts))
        bad_hashes = copy.deepcopy(outcome.evaluation_completion)
        bad_hashes["accepted_artifact_hashes"] = []
        mutations.append((plan, bad_hashes, artifacts))
        tampered_artifacts = copy.deepcopy(artifacts)
        tampered_artifacts[0]["payload"]["result"]["coverage"]["notes"] = (
            "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        mutations.append((plan, outcome.evaluation_completion, tampered_artifacts))
        for mutation_plan, mutation_completion, mutation_artifacts in mutations:
            with self.subTest(mutation=mutation_completion.get("authority")), self.assertRaises(
                RenderError
            ):
                render_evaluation_report(
                    plan=mutation_plan,
                    completion=mutation_completion,
                    artifacts=mutation_artifacts,
                )

    def test_task5_diagnostic_renderer_rejects_result_claims_and_bad_assurance(self) -> None:
        assurance = pre_session_diagnostic_assurance()
        text = render_diagnostic_report(
            plan=None,
            state="blocked",
            reasons=["canonical_inventory_oracle_unavailable"],
            assurance_state=assurance,
        )
        self.assertIn("pre_session: true", text)
        self.assertNotIn("target_identity", text)
        self.assertNotIn("simulated_review_verdict", text)
        with self.assertRaises(RenderError):
            render_diagnostic_report(
                plan=None,
                state="clean",
                reasons=["no_issues"],
                assurance_state=assurance,
            )
        assurance["worker_child_environment"] = "verified"
        with self.assertRaises(RenderError):
            render_diagnostic_report(
                plan=None,
                state="blocked",
                reasons=["worker_unavailable"],
                assurance_state=assurance,
            )

    def test_task5_recovery_writer_is_atomic_restricted_and_sanitized(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        destination = root / "recovery-diagnostic.md"
        first = write_recovery_diagnostic(
            sibling_path=destination,
            reason_codes=["canonical_store_verification_failed"],
        )
        self.assertEqual(first, destination)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        first_text = destination.read_text(encoding="utf-8")
        self.assertIn("canonical state could not be verified", first_text)
        self.assertNotIn("target", first_text.casefold())
        self.assertNotIn("private", first_text)
        write_recovery_diagnostic(
            sibling_path=destination,
            reason_codes=["artifact_commit_state_uncertain"],
        )
        self.assertIn("artifact_commit_state_uncertain", destination.read_text())
        self.assertFalse(any(root.glob(".*.tmp-*")))

        for forbidden in ("report.md", "other.md"):
            with self.subTest(forbidden=forbidden), self.assertRaises(MaterializationError):
                write_recovery_diagnostic(
                    sibling_path=root / forbidden,
                    reason_codes=["canonical_store_verification_failed"],
                )

        symlink_root = root / "symlink-case"
        symlink_root.mkdir()
        symlink_target = symlink_root / "outside.txt"
        symlink_target.write_text("untouched", encoding="utf-8")
        symlink = symlink_root / "recovery-diagnostic.md"
        symlink.symlink_to(symlink_target)
        with self.assertRaisesRegex(
            MaterializationError, "materialized view could not be written"
        ):
            write_recovery_diagnostic(
                sibling_path=symlink,
                reason_codes=["canonical_store_verification_failed"],
            )
        self.assertEqual(symlink_target.read_text(), "untouched")

        ancestor_root = root / "ancestor-case"
        outside_root = root / "outside-case"
        ancestor_root.mkdir()
        outside_root.mkdir()
        (ancestor_root / "link").symlink_to(outside_root, target_is_directory=True)
        with self.assertRaises(MaterializationError):
            write_recovery_diagnostic(
                sibling_path=ancestor_root
                / "link"
                / "new"
                / "recovery-diagnostic.md",
                reason_codes=["canonical_store_verification_failed"],
            )
        self.assertFalse((outside_root / "new").exists())

    def test_task5_materializer_holds_parent_directory_against_symlink_swap(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        parent = root / "parent"
        moved = root / "moved-parent"
        outside = root / "outside"
        parent.mkdir()
        outside.mkdir()
        destination = parent / "recovery-diagnostic.md"
        real_open = render_module.os.open
        swapped = False

        def swap_before_temporary_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if (
                not swapped
                and dir_fd is not None
                and isinstance(path, str)
                and path.startswith(".recovery-diagnostic.md.tmp-")
            ):
                parent.rename(moved)
                parent.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(render_module.os, "open", side_effect=swap_before_temporary_open):
            with self.assertRaisesRegex(
                MaterializationError, "^materialized view could not be written$"
            ):
                write_recovery_diagnostic(
                    sibling_path=destination,
                    reason_codes=["canonical_store_verification_failed"],
                )
        self.assertTrue(swapped)
        self.assertFalse((outside / "recovery-diagnostic.md").exists())
        self.assertFalse(any(moved.glob(".recovery-diagnostic.md.tmp-*")))

    def test_task5_materialization_io_failure_never_returns_a_path(self) -> None:
        fixture = EvaluationFixture(self, kind="manual")
        with mock.patch(
            "local_ultra_review.render.os.replace",
            side_effect=OSError("private destination detail"),
        ):
            with self.assertRaisesRegex(
                MaterializationError, "^materialized view could not be written$"
            ):
                evaluate(
                    fixture.request(),
                    FakeBackend(scenario_id="materialization-failure", attempts=[]),
                )
        self.assertFalse((fixture.session_root.parent / "evaluation-report.md").exists())
        self.assertFalse(any(fixture.session_root.parent.glob(".*.tmp-*")))


if __name__ == "__main__":
    unittest.main()
