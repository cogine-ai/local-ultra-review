from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from local_ultra_review.backend import (  # noqa: E402
    CodexCliBackend,
    DISABLED_FEATURES,
    ENVIRONMENT_ALLOWLIST,
    FakeBackend,
    LAUNCH_POLICY_SHA256,
    ScriptedAttempt,
    WORKER_ENVIRONMENT_POLICY_SHA256,
    WorkerProtocolError,
    WorkerUnavailable,
    WorkerTask,
)
from local_ultra_review.contracts import (  # noqa: E402
    SCHEMA_VERSION,
    canonical_json_bytes,
    load_schema,
    sha256_json,
)


HEX_A = "a" * 64
HEX_B = "b" * 64
TOKEN = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def reviewer_packet() -> dict:
    return {"reviewable_atom_ids": ["atom-1"], "sealed": True}


def reviewer_task(*, task_id: str = "reviewer-correctness-1") -> WorkerTask:
    packet = reviewer_packet()
    return WorkerTask(
        task_id=task_id,
        role="reviewer",
        packet=packet,
        packet_hash=sha256_json(packet),
        prompt_text="Review the sealed packet.",
        output_schema_name="reviewer-result",
        timeout_seconds=30,
    )


def reviewer_payload_template(**updates: object) -> bytes:
    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "task_id": "{{TASK_ID}}",
        "packet_hash": "{{PACKET_HASH}}",
        "status": "completed",
        "coverage": {
            "reviewed_atom_ids": ["atom-1"],
            "notes": "Reviewed the sealed atom.",
        },
        "candidates": [],
    }
    payload.update(updates)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def verifier_task() -> WorkerTask:
    packet = {"candidate_hash": HEX_B, "sealed": True}
    return WorkerTask(
        task_id="verifier-1",
        role="verifier",
        packet=packet,
        packet_hash=sha256_json(packet),
        prompt_text="Verify the sealed candidate.",
        output_schema_name="verifier-result.schema.json",
        timeout_seconds=30,
    )


def verifier_payload_template() -> bytes:
    return json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "task_id": "{{TASK_ID}}",
            "packet_hash": "{{PACKET_HASH}}",
            "candidate_hash": "{{CANDIDATE_HASH}}",
            "status": "completed",
            "disposition": "confirmed",
            "final_severity": "Important",
            "provenance": "Introduced by this diff.",
            "best_fix": "Restore the boundary check.",
            "refactor_judgment": "A local fix is sufficient.",
            "proof": ["The changed branch is reachable."],
            "residual_risk": "Concurrent retries were not exercised.",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def scripted_attempt(
    *,
    role: str = "reviewer",
    template: bytes | None = None,
    events: tuple[dict, ...] | None = None,
    process_launch_id: str = "process-1",
    return_code: int = 0,
    timed_out: bool = False,
) -> ScriptedAttempt:
    if template is None:
        template = reviewer_payload_template()
    if events is None:
        events = (
            {"type": "thread.started", "thread_id": "thread-1"},
            {"type": "turn.completed", "usage": {"input_tokens": 1}},
        )
    return ScriptedAttempt(
        expected_role=role,  # type: ignore[arg-type]
        raw_events=events,
        last_message_template=template,
        process_launch_id=process_launch_id,
        return_code=return_code,
        timed_out=timed_out,
    )


class FakeCodex:
    def __init__(self, root: Path) -> None:
        self.path = root / "fake-codex"
        capture_dir = root / "captures"
        capture_dir.mkdir()
        self.version_environment_path = capture_dir / "version-environment.json"
        self.semantic_launch_path = capture_dir / "semantic-launched"
        source = f"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

if sys.argv[1:] == [\"--version\"]:
    Path({str(self.version_environment_path)!r}).write_text(
        json.dumps(dict(os.environ), sort_keys=True), encoding=\"utf-8\"
    )
    print(\"codex-cli 9.9.9\")
    raise SystemExit(0)

Path({str(self.semantic_launch_path)!r}).write_text(
    json.dumps(sys.argv[1:]), encoding=\"utf-8\"
)
raise SystemExit(91)
"""
        self.path.write_text(source, encoding="utf-8")
        self.path.chmod(self.path.stat().st_mode | stat.S_IXUSR)


def qualification_payload(fake_codex: FakeCodex, **updates: object) -> dict:
    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "record_kind": "diagnostic_evidence",
        "profile": "codex_native_guarded",
        "worker_boundary": "guarded_unconfined",
        "hard_worker_confinement": "not_provided",
        "cli_version": "codex-cli 9.9.9",
        "cli_binary_sha256": hashlib.sha256(fake_codex.path.read_bytes()).hexdigest(),
        "launch_policy_sha256": LAUNCH_POLICY_SHA256,
        "worker_environment_policy_sha256": WORKER_ENVIRONMENT_POLICY_SHA256,
        "residual_tool_surface": "unknown",
        "residual_tool_inventory": "unavailable",
        "canonical_inventory_oracle": "unavailable",
        "inventory_scope": "known_observed_partial",
        "inventory_source": "worker_observed_only",
        "known_observed_exposures": ["exec_command", "view_image"],
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
    payload.update(updates)
    return payload


def write_qualification(root: Path, fake_codex: FakeCodex, **updates: object) -> Path:
    path = root / "qualification.json"
    path.write_bytes(canonical_json_bytes(qualification_payload(fake_codex, **updates)))
    return path


def parent_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C.UTF-8",
        "LOCAL_ULTRA_REVIEW_FAKE_SECRET": "EVAL_ONLY_DO_NOT_LEAK_123456",
        "UNRELATED_PARENT_VALUE": "must-not-pass",
    }


class FakeBackendTests(unittest.TestCase):
    def run_attempt(
        self, attempt: ScriptedAttempt, task: WorkerTask | None = None
    ):
        backend = FakeBackend(scenario_id="fixture", attempts=[attempt])
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return backend.run(task or reviewer_task(), Path(temporary.name))

    def test_valid_reviewer_and_verifier_results_bind_only_known_placeholders(self) -> None:
        reviewer = self.run_attempt(scripted_attempt())
        verifier = self.run_attempt(
            scripted_attempt(
                role="verifier",
                template=verifier_payload_template(),
                events=({"type": "thread.started", "thread_id": "thread-v"},),
            ),
            verifier_task(),
        )

        self.assertEqual(reviewer.payload["task_id"], "reviewer-correctness-1")
        self.assertEqual(verifier.payload["candidate_hash"], HEX_B)
        self.assertEqual(reviewer.thread_id, "thread-1")
        self.assertEqual(reviewer.manifest["authority"], "synthetic_evaluation")
        self.assertEqual(reviewer.manifest["execution_backend"], "fake_evaluation")
        self.assertEqual(reviewer.manifest["observed_event_count"], 2)
        self.assertEqual(reviewer.manifest["observed_tool_call_count"], 0)
        self.assertEqual(reviewer.manifest["telemetry_scope"], "observed_events_only")
        self.assertEqual(reviewer.manifest["target_execution"], "not_requested")

    def test_semantic_identity_hashes_unbound_templates_without_task_feedback(self) -> None:
        attempts = [scripted_attempt(), scripted_attempt(role="verifier", template=verifier_payload_template())]
        backend = FakeBackend(scenario_id="stable-fixture", attempts=attempts)
        before = backend.semantic_identity()

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        backend.run(reviewer_task(task_id="reviewer-another-id"), Path(temporary.name))
        after = backend.semantic_identity()

        self.assertEqual(before, after)
        self.assertEqual(before["expected_role_sequence"], ["reviewer", "verifier"])
        self.assertNotIn("reviewer-another-id", json.dumps(before))
        self.assertIn("unbound_attempt_templates_sha256", before)

    def test_semantic_identity_rejects_sensitive_scenario_or_launch_evidence(self) -> None:
        backends = (
            FakeBackend(scenario_id=TOKEN, attempts=[]),
            FakeBackend(
                scenario_id="fixture",
                attempts=[scripted_attempt(process_launch_id=TOKEN)],
            ),
        )
        for backend in backends:
            with self.subTest(backend=backend), self.assertRaises(WorkerProtocolError):
                backend.semantic_identity()

    def test_scenario_and_process_identity_shapes_reject_before_semantic_hash(self) -> None:
        reviewer = reviewer_task()
        backends = (
            FakeBackend(scenario_id=reviewer.task_id, attempts=[]),
            FakeBackend(scenario_id=reviewer.packet_hash, attempts=[]),
            FakeBackend(
                scenario_id="fixture",
                attempts=[scripted_attempt(process_launch_id=reviewer.task_id)],
            ),
            FakeBackend(
                scenario_id="fixture",
                attempts=[scripted_attempt(process_launch_id=reviewer.packet_hash)],
            ),
        )
        for backend in backends:
            with self.subTest(backend=backend), mock.patch(
                "local_ultra_review.backend.sha256_json"
            ) as hash_json:
                with self.assertRaises(WorkerProtocolError):
                    backend.semantic_identity()
                hash_json.assert_not_called()

    def test_invalid_or_sensitive_attempt_metadata_is_rejected_before_any_hash(self) -> None:
        task = reviewer_task()
        attempts = (
            scripted_attempt(role="owner"),
            scripted_attempt(role=TOKEN),
            scripted_attempt(process_launch_id=TOKEN),
        )
        for attempt in attempts:
            with self.subTest(path="identity", attempt=attempt):
                backend = FakeBackend(scenario_id="fixture", attempts=[attempt])
                with mock.patch("local_ultra_review.backend.sha256_json") as hash_json:
                    with self.assertRaises(WorkerProtocolError):
                        backend.semantic_identity()
                hash_json.assert_not_called()

            with self.subTest(path="run", attempt=attempt):
                backend = FakeBackend(scenario_id="fixture", attempts=[attempt])
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                with mock.patch("local_ultra_review.backend.sha256_json") as hash_json:
                    with self.assertRaises(WorkerProtocolError):
                        backend.run(task, Path(temporary.name))
                hash_json.assert_not_called()

    def test_unbound_identity_shape_is_rejected_everywhere_before_semantic_hash(self) -> None:
        reviewer = reviewer_task()
        verifier = verifier_task()
        reviewer_templates = (
            reviewer_payload_template(
                coverage={
                    "reviewed_atom_ids": ["atom-1"],
                    "notes": f"hidden {reviewer.task_id}",
                }
            ),
            reviewer_payload_template(
                coverage={
                    "reviewed_atom_ids": ["atom-1"],
                    "notes": f"hidden {reviewer.packet_hash}",
                }
            ),
        )
        verifier_templates = (
            verifier_payload_template().replace(
                b'"proof":[',
                f'"proof":["hidden {verifier.packet_hash}",'.encode(),
            ),
            verifier_payload_template().replace(
                b'"proof":[',
                f'"proof":["hidden {HEX_B}",'.encode(),
            ),
        )
        attempts = [scripted_attempt(template=template) for template in reviewer_templates]
        attempts.extend(
            scripted_attempt(role="verifier", template=template)
            for template in verifier_templates
        )
        attempts.append(
            scripted_attempt(
                events=(
                    {
                        "type": "thread.started",
                        "thread_id": "thread-1",
                        "note": reviewer.task_id,
                    },
                )
            )
        )
        for attempt in attempts:
            backend = FakeBackend(scenario_id="fixture", attempts=[attempt])
            with self.subTest(attempt=attempt), mock.patch(
                "local_ultra_review.backend.sha256_json"
            ) as hash_json:
                with self.assertRaises(WorkerProtocolError):
                    backend.semantic_identity()
                hash_json.assert_not_called()

    def test_run_rejects_opaque_task_identity_across_all_non_identity_evidence(self) -> None:
        packet = reviewer_packet()
        task = WorkerTask(
            task_id="opaque-task-identity",
            role="reviewer",
            packet=packet,
            packet_hash=sha256_json(packet),
            prompt_text="Review the sealed packet.",
            output_schema_name="reviewer-result",
            timeout_seconds=30,
        )
        hidden_template = reviewer_payload_template(
            coverage={
                "reviewed_atom_ids": ["atom-1"],
                "notes": f"hidden {task.task_id}",
            }
        )
        cases = (
            FakeBackend(scenario_id=task.task_id, attempts=[scripted_attempt()]),
            FakeBackend(
                scenario_id="fixture",
                attempts=[scripted_attempt(process_launch_id=task.task_id)],
            ),
            FakeBackend(
                scenario_id="fixture",
                attempts=[
                    scripted_attempt(
                        events=(
                            {
                                "type": "thread.started",
                                "thread_id": "thread-1",
                                "kind": task.task_id,
                            },
                        )
                    )
                ],
            ),
            FakeBackend(
                scenario_id="fixture",
                attempts=[scripted_attempt(template=hidden_template)],
            ),
        )
        for backend in cases:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            with self.subTest(backend=backend), mock.patch(
                "local_ultra_review.backend.validate_payload"
            ) as validate:
                with self.assertRaises(WorkerProtocolError):
                    backend.run(task, Path(temporary.name))
                validate.assert_not_called()

    def test_run_rejects_identity_placeholders_outside_dedicated_fields_after_binding(self) -> None:
        reviewer = reviewer_task()
        verifier = verifier_task()
        cases = (
            (
                reviewer,
                scripted_attempt(
                    template=reviewer_payload_template(
                        coverage={
                            "reviewed_atom_ids": ["atom-1"],
                            "notes": "hidden {{TASK_ID}}",
                        }
                    )
                ),
            ),
            (
                verifier,
                scripted_attempt(
                    role="verifier",
                    template=verifier_payload_template().replace(
                        b'"proof":[',
                        b'"proof":["hidden {{CANDIDATE_HASH}}",',
                    ),
                ),
            ),
        )
        for task, attempt in cases:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            backend = FakeBackend(scenario_id="fixture", attempts=[attempt])
            with self.subTest(role=task.role), mock.patch(
                "local_ultra_review.backend.validate_payload"
            ) as validate:
                with self.assertRaises(WorkerProtocolError):
                    backend.run(task, Path(temporary.name))
                validate.assert_not_called()

    def test_readiness_is_synthetic_only_and_has_no_live_authority(self) -> None:
        readiness = FakeBackend(scenario_id="fixture", attempts=[]).readiness()
        self.assertTrue(readiness["ready"])
        self.assertFalse(readiness["live_dispatch_authorized"])
        self.assertEqual(readiness["authority"], "synthetic_evaluation")

    def test_unknown_or_unresolved_placeholders_are_rejected(self) -> None:
        for template in (
            reviewer_payload_template().replace(b"{{TASK_ID}}", b"{{UNKNOWN}}"),
            reviewer_payload_template().replace(b"{{TASK_ID}}", b"{{CANDIDATE_HASH}}"),
            reviewer_payload_template() + b"{{",
        ):
            with self.subTest(template=template), self.assertRaises(WorkerProtocolError):
                self.run_attempt(scripted_attempt(template=template))

    def test_identity_fields_require_role_specific_unbound_placeholders(self) -> None:
        reviewer = reviewer_task()
        reviewer_cases = (
            reviewer_payload_template().replace(
                b"{{TASK_ID}}", reviewer.task_id.encode()
            ),
            reviewer_payload_template().replace(
                b"{{PACKET_HASH}}", reviewer.packet_hash.encode()
            ),
            reviewer_payload_template(
                task_id=reviewer.task_id,
                coverage={
                    "reviewed_atom_ids": ["atom-1"],
                    "notes": "{{TASK_ID}}",
                },
            ),
        )
        for template in reviewer_cases:
            with self.subTest(role="reviewer", template=template), self.assertRaises(
                WorkerProtocolError
            ):
                self.run_attempt(scripted_attempt(template=template), reviewer)

        verifier = verifier_task()
        verifier_cases = (
            verifier_payload_template().replace(
                b"{{TASK_ID}}", verifier.task_id.encode()
            ),
            verifier_payload_template().replace(
                b"{{PACKET_HASH}}", verifier.packet_hash.encode()
            ),
            verifier_payload_template().replace(b"{{CANDIDATE_HASH}}", HEX_B.encode()),
            verifier_payload_template()
            .replace(b"{{CANDIDATE_HASH}}", HEX_B.encode())
            .replace(b'"proof":[', b'"proof":["{{CANDIDATE_HASH}}",'),
        )
        for template in verifier_cases:
            with self.subTest(role="verifier", template=template), self.assertRaises(
                WorkerProtocolError
            ):
                self.run_attempt(
                    scripted_attempt(role="verifier", template=template), verifier
                )

    def test_blank_fenced_malformed_partial_and_duplicate_key_output_are_rejected(self) -> None:
        valid = reviewer_payload_template()
        cases = (
            b"   \n",
            b"```json\n" + valid + b"\n```",
            b'{"schema_version":',
            valid + b" trailing",
            valid.replace(
                b'"status":"completed"',
                b'"status":"completed","status":"completed"',
            ),
        )
        for template in cases:
            with self.subTest(template=template), self.assertRaises(WorkerProtocolError):
                self.run_attempt(scripted_attempt(template=template))

    def test_role_task_packet_candidate_and_schema_mismatches_are_rejected(self) -> None:
        wrong_task = reviewer_payload_template(task_id="reviewer-other")
        wrong_packet = reviewer_payload_template(packet_hash=HEX_A)
        wrong_candidate = verifier_payload_template().replace(
            b"{{CANDIDATE_HASH}}", HEX_A.encode()
        )
        cases = (
            (scripted_attempt(role="verifier"), reviewer_task()),
            (scripted_attempt(template=wrong_task), reviewer_task()),
            (scripted_attempt(template=wrong_packet), reviewer_task()),
            (
                scripted_attempt(role="verifier", template=wrong_candidate),
                verifier_task(),
            ),
        )
        bad_schema_task = reviewer_task()
        bad_schema_task = WorkerTask(
            **{**bad_schema_task.__dict__, "output_schema_name": "verifier-result"}
        )
        cases += ((scripted_attempt(), bad_schema_task),)
        for attempt, task in cases:
            with self.subTest(attempt=attempt, task=task), self.assertRaises(WorkerProtocolError):
                self.run_attempt(attempt, task)

    def test_worker_authority_and_sensitive_output_are_rejected(self) -> None:
        authority = reviewer_payload_template(assurance={"sandboxed": True})
        sensitive = reviewer_payload_template(
            coverage={
                "reviewed_atom_ids": ["atom-1"],
                "notes": f"API_TOKEN={TOKEN}",
            }
        )
        for template in (authority, sensitive):
            with self.subTest(template=template), self.assertRaises(WorkerProtocolError):
                self.run_attempt(scripted_attempt(template=template))

    def test_missing_repeated_or_reused_thread_ids_are_rejected(self) -> None:
        event_cases = (
            ({"type": "turn.completed"},),
            ({"type": "thread.started", "thread_id": ""},),
            (
                {"type": "thread.started", "thread_id": "thread-1"},
                {"type": "turn.started", "thread_id": "thread-1"},
            ),
        )
        for events in event_cases:
            with self.subTest(events=events), self.assertRaises(WorkerProtocolError):
                self.run_attempt(scripted_attempt(events=events))

        backend = FakeBackend(
            scenario_id="reuse",
            attempts=[scripted_attempt(), scripted_attempt(process_launch_id="process-2")],
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        backend.run(reviewer_task(), Path(temporary.name) / "one")
        with self.assertRaises(WorkerProtocolError):
            backend.run(reviewer_task(task_id="reviewer-2"), Path(temporary.name) / "two")

    def test_timeout_nonzero_status_and_missing_or_reused_launch_evidence_are_rejected(self) -> None:
        for attempt in (
            scripted_attempt(timed_out=True),
            scripted_attempt(return_code=7),
            scripted_attempt(process_launch_id=""),
        ):
            with self.subTest(attempt=attempt), self.assertRaises(WorkerProtocolError):
                self.run_attempt(attempt)

        backend = FakeBackend(
            scenario_id="launch-reuse",
            attempts=[
                scripted_attempt(),
                scripted_attempt(
                    events=({"type": "thread.started", "thread_id": "thread-2"},)
                ),
            ],
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        backend.run(reviewer_task(), Path(temporary.name) / "one")
        with self.assertRaises(WorkerProtocolError):
            backend.run(reviewer_task(task_id="reviewer-2"), Path(temporary.name) / "two")

    def test_events_outside_the_exact_harmless_structural_contract_reject(self) -> None:
        invalid_events = (
            {"type": "tool"},
            {"type": "command"},
            {"type": "function"},
            {"type": "mcp"},
            {"type": "file_edit_call"},
            {"type": "web_fetch"},
            {"type": "custom_unknown_event"},
            {"type": "turn.started", "kind": "unknown"},
            {"type": "turn.started", "event": "unknown"},
            {"type": "turn.started", "action": "unknown"},
            {"type": "turn.completed", "payload": {}},
            {
                "type": "item.completed",
                "item": {"type": "reasoning", "text": "safe", "action": "unknown"},
            },
            {
                "type": "item.completed",
                "item": {"type": "reasoning", "nested": {}},
            },
            {"type": "usage", "input_tokens": 1, "payload": []},
            {"type": "usage", "input_tokens": "1"},
        )
        for invalid_event in invalid_events:
            events = (
                {"type": "thread.started", "thread_id": "thread-1"},
                invalid_event,
            )
            with self.subTest(event=invalid_event), self.assertRaises(
                WorkerProtocolError
            ):
                self.run_attempt(scripted_attempt(events=events))

    def test_explicit_harmless_lifecycle_message_and_reasoning_events_are_accepted(self) -> None:
        events = (
            {"type": "thread.started", "thread_id": "thread-harmless"},
            {"type": "turn.started"},
            {
                "type": "item.completed",
                "item": {
                    "type": "reasoning",
                    "text": "Free text may mention tool, web_fetch, or command.",
                },
            },
            {
                "type": "item.completed",
                "item": {"type": "agent_message", "text": "Structured result follows."},
            },
            {"type": "turn.completed", "usage": {"input_tokens": 1}},
            {"type": "message", "text": "Free text may say apply_patch."},
            {"type": "usage", "input_tokens": 1, "total_tokens": 2},
        )

        result = self.run_attempt(scripted_attempt(events=events))

        self.assertEqual(result.manifest["observed_event_count"], 7)
        self.assertEqual(result.manifest["observed_tool_call_count"], 0)


class CodexCliBackendTests(unittest.TestCase):
    def make_backend(
        self, *, record_updates: dict[str, object] | None = None
    ) -> tuple[tempfile.TemporaryDirectory[str], FakeCodex, Path, CodexCliBackend]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fake_codex = FakeCodex(root)
        record = write_qualification(root, fake_codex, **(record_updates or {}))
        backend = CodexCliBackend(
            codex_path=fake_codex.path,
            model="sealed-model-id",
            qualification_record=record,
            parent_environment=parent_environment(),
        )
        return temporary, fake_codex, record, backend

    def test_exact_hypothetical_argv_materializes_packet_and_packaged_schema(self) -> None:
        _temporary, fake_codex, _record, backend = self.make_backend()
        attempt_root = fake_codex.path.parent / "attempt-1"
        task = reviewer_task()

        spec = backend.build_launch_spec(task, attempt_root)

        packet_dir = (attempt_root / "packet").resolve()
        schema_path = (attempt_root / "scratch" / "output-schema.json").resolve()
        result_path = (attempt_root / "scratch" / "result.json").resolve()
        expected = [
            str(fake_codex.path.resolve()),
            "exec",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
            "--strict-config",
            "-s",
            "read-only",
            "-c",
            'web_search="disabled"',
        ]
        for feature in DISABLED_FEATURES:
            expected.extend(["--disable", feature])
        expected.extend(
            [
                "-C",
                str(packet_dir),
                "--model",
                "sealed-model-id",
                "--output-schema",
                str(schema_path),
                "--json",
                "--output-last-message",
                str(result_path),
                "-",
            ]
        )

        self.assertEqual(spec["argv"], expected)
        self.assertEqual(spec["stdin"], task.prompt_text)
        self.assertEqual((packet_dir / "packet.json").read_bytes(), canonical_json_bytes(task.packet))
        self.assertEqual(schema_path.read_bytes(), canonical_json_bytes(load_schema("reviewer-result")))
        self.assertTrue(result_path.is_file())
        self.assertFalse(result_path.is_symlink())
        self.assertEqual(result_path.read_bytes(), b"")
        self.assertNotIn("--ask-for-approval", spec["argv"])
        self.assertNotIn("store=false", " ".join(spec["argv"]))
        self.assertEqual(
            sorted(spec["environment"]),
            sorted({"PATH", "HOME", "LANG", "TMPDIR"}),
        )
        self.assertNotIn("LOCAL_ULTRA_REVIEW_FAKE_SECRET", spec["environment"])
        self.assertNotIn("UNRELATED_PARENT_VALUE", spec["environment"])
        self.assertEqual(
            spec["environment_manifest"]["worker_environment_policy_sha256"],
            WORKER_ENVIRONMENT_POLICY_SHA256,
        )
        self.assertNotIn(
            "EVAL_ONLY_DO_NOT_LEAK_123456",
            json.dumps(spec["environment_manifest"], sort_keys=True),
        )

    def test_launch_materialization_rejects_symlinked_parents_and_destinations(self) -> None:
        _temporary, fake_codex, _record, backend = self.make_backend()
        root = fake_codex.path.parent
        victim_file = root / "victim.json"
        victim_file.write_text("victim", encoding="utf-8")
        cases: list[tuple[str, Path]] = []

        real_attempt = root / "real-attempt"
        real_attempt.mkdir()
        linked_attempt = root / "linked-attempt"
        linked_attempt.symlink_to(real_attempt, target_is_directory=True)
        cases.append(("attempt", linked_attempt))

        real_parent = root / "real-parent"
        real_parent.mkdir()
        linked_parent = root / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        cases.append(("attempt-parent", linked_parent / "attempt"))

        for name in ("packet-parent", "scratch-parent"):
            attempt = root / name
            attempt.mkdir()
            target = root / f"{name}-target"
            target.mkdir()
            child = "packet" if name == "packet-parent" else "scratch"
            (attempt / child).symlink_to(target, target_is_directory=True)
            cases.append((name, attempt))

        destinations = {
            "packet-destination": ("packet", "packet.json"),
            "schema-destination": ("scratch", "output-schema.json"),
            "result-destination": ("scratch", "result.json"),
        }
        for name, (parent, filename) in destinations.items():
            attempt = root / name
            (attempt / parent).mkdir(parents=True)
            (attempt / parent / filename).symlink_to(victim_file)
            cases.append((name, attempt))

        for name, attempt in cases:
            with self.subTest(name=name), self.assertRaises(WorkerProtocolError):
                backend.build_launch_spec(reviewer_task(), attempt)

        self.assertEqual(victim_file.read_text(encoding="utf-8"), "victim")

    def test_object_bound_hash_never_executes_an_unbound_version_probe(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fake_codex = FakeCodex(root)
        expected_hash = hashlib.sha256(fake_codex.path.read_bytes()).hexdigest()
        record = write_qualification(root, fake_codex)
        with mock.patch("local_ultra_review.backend._run_process") as run_process:
            backend = CodexCliBackend(
                codex_path=fake_codex.path,
                model="sealed-model-id",
                qualification_record=record,
                parent_environment=parent_environment(),
            )

        run_process.assert_not_called()
        identity = backend.semantic_identity()
        readiness = backend.readiness()
        self.assertFalse(fake_codex.version_environment_path.exists())
        self.assertEqual(identity["cli_binary_sha256"], expected_hash)
        self.assertIsNone(identity["cli_version"])
        self.assertFalse(identity["version_probe_executed"])
        self.assertEqual(
            identity["object_bound_executable_binding"], "unavailable"
        )
        self.assertEqual(
            identity["cli_binary_identity_scope"],
            "unexecuted_nofollow_file_object",
        )
        self.assertEqual(
            identity["cli_diagnostic_state"],
            "object_bound_version_probe_unavailable",
        )
        self.assertEqual(
            identity["qualification_state"],
            "not_evaluable_without_object_bound_version_probe",
        )
        self.assertFalse(readiness["version_probe_executed"])
        self.assertEqual(readiness["object_bound_executable_binding"], "unavailable")
        self.assertIn(
            "object_bound_version_probe_unavailable",
            readiness["live_dispatch_blockers"],
        )

    def test_preflight_trusted_canary_proves_descendant_inheritance_without_values(self) -> None:
        _temporary, fake_codex, _record, backend = self.make_backend()

        evidence = backend.preflight_worker_environment(fake_codex.path.parent / "preflight")

        expected_keys = sorted({"PATH", "HOME", "LANG", "TMPDIR"})
        self.assertEqual(evidence["status"], "passed")
        self.assertEqual(evidence["evidence_owner"], "adapter_host")
        self.assertFalse(evidence["semantic_invocation"])
        self.assertEqual(evidence["base_environment"], "empty")
        self.assertEqual(evidence["child_environment_keys"], expected_keys)
        self.assertEqual(evidence["descendant_environment_keys"], expected_keys)
        self.assertTrue(evidence["parent_nonallowlisted_keys_excluded"])
        self.assertTrue(evidence["descendant_inheritance_matched"])
        self.assertEqual(
            evidence["worker_environment_policy_sha256"],
            WORKER_ENVIRONMENT_POLICY_SHA256,
        )
        self.assertEqual(
            evidence["child_environment_keys_sha256"], sha256_json(expected_keys)
        )
        rendered = json.dumps(evidence, sort_keys=True)
        self.assertNotIn("EVAL_ONLY_DO_NOT_LEAK_123456", rendered)
        self.assertNotIn("must-not-pass", rendered)

        readiness = backend.readiness()
        self.assertEqual(readiness["environment_preflight"], evidence)
        self.assertFalse(readiness["live_dispatch_authorized"])

    def test_matching_record_cannot_qualify_without_object_bound_version_probe(self) -> None:
        _temporary, _fake_codex, record, backend = self.make_backend()

        identity = backend.semantic_identity()
        readiness = backend.readiness()

        self.assertEqual(identity["adapter_version"], "codex-cli-guarded-1")
        self.assertEqual(identity["model"], "sealed-model-id")
        self.assertEqual(identity["launch_policy_sha256"], LAUNCH_POLICY_SHA256)
        self.assertEqual(
            identity["worker_environment_policy_sha256"],
            WORKER_ENVIRONMENT_POLICY_SHA256,
        )
        self.assertEqual(
            identity["diagnostic_record_sha256"],
            hashlib.sha256(record.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            identity["qualification_state"],
            "not_evaluable_without_object_bound_version_probe",
        )
        inventory = identity["inventory"]
        self.assertEqual(inventory["inventory_scope"], "known_observed_partial")
        self.assertEqual(inventory["residual_tool_surface"], "unknown")
        self.assertEqual(inventory["residual_tool_inventory"], "unavailable")
        self.assertEqual(inventory["inventory_source"], "unavailable")
        self.assertEqual(inventory["known_observed_exposures"], [])
        self.assertIsNone(inventory["known_observed_exposures_sha256"])
        self.assertFalse(readiness["ready"])
        self.assertIn(
            "canonical_inventory_oracle_unavailable",
            readiness["live_dispatch_blockers"],
        )

    def test_schema_valid_records_remain_not_evaluable_and_never_supply_inventory(self) -> None:
        cases = (
            ({"expires_at": "2026-02-01T00:00:00Z"}, "expired_record"),
            ({"launch_policy_sha256": HEX_A}, "diagnostic_mismatch"),
            ({"worker_environment_policy_sha256": HEX_A}, "diagnostic_mismatch"),
            ({"cli_binary_sha256": HEX_A}, "diagnostic_mismatch"),
            (
                {"cli_version": "codex-cli other"},
                "not_evaluable_without_object_bound_version_probe",
            ),
        )
        for updates, expected_state in cases:
            with self.subTest(updates=updates):
                _temporary, _fake_codex, _record, backend = self.make_backend(
                    record_updates=updates
                )
                state = backend.semantic_identity()["qualification_state"]
                inventory = backend.semantic_identity()["inventory"]
                self.assertEqual(state, expected_state)
                self.assertEqual(inventory["known_observed_exposures"], [])
                self.assertIsNone(inventory["known_observed_exposures_sha256"])
                self.assertEqual(inventory["inventory_source"], "unavailable")
                self.assertFalse(backend.readiness()["live_dispatch_authorized"])

    def test_run_blocks_before_every_semantic_subprocess_with_structured_diagnostic(self) -> None:
        _temporary, fake_codex, _record, backend = self.make_backend()

        with mock.patch("local_ultra_review.backend.subprocess.run") as run_process:
            with self.assertRaises(WorkerUnavailable) as raised:
                backend.run(reviewer_task(), fake_codex.path.parent / "blocked-attempt")

        run_process.assert_not_called()
        self.assertFalse(fake_codex.semantic_launch_path.exists())
        diagnostic = raised.exception.diagnostic
        self.assertEqual(diagnostic["status"], "blocked")
        self.assertEqual(
            diagnostic["reason"], "canonical_inventory_oracle_unavailable"
        )
        self.assertFalse(diagnostic["live_dispatch_authorized"])
        self.assertFalse(diagnostic["semantic_subprocess_launched"])
        self.assertEqual(diagnostic["accepted_tool_calls"], "not_applicable_no_dispatch")
        self.assertEqual(diagnostic["target_execution"], "not_requested")

    def test_record_claiming_complete_inventory_cannot_turn_gate_on(self) -> None:
        _temporary, fake_codex, _record, backend = self.make_backend(
            record_updates={
                "canonical_inventory_oracle": "available",
                "inventory_scope": "complete",
                "residual_tool_surface": "none",
                "residual_tool_inventory": "complete",
                "live_dispatch_authorized": True,
            }
        )

        with mock.patch("local_ultra_review.backend.subprocess.run") as run_process:
            with self.assertRaises(WorkerUnavailable) as raised:
                backend.run(reviewer_task(), fake_codex.path.parent / "blocked-attempt")

        run_process.assert_not_called()
        self.assertFalse(fake_codex.semantic_launch_path.exists())
        self.assertEqual(
            backend.semantic_identity()["qualification_state"], "invalid_record"
        )
        self.assertIn(
            "qualification_record_invalid",
            raised.exception.diagnostic["live_dispatch_blockers"],
        )

    def test_mismatched_record_cannot_lend_mitigation_claims_to_blocked_diagnostic(self) -> None:
        _temporary, fake_codex, _record, backend = self.make_backend(
            record_updates={
                "launch_policy_sha256": HEX_A,
                "filesystem_write_mitigation": "read_only_preflight_passed",
                "nested_web_search": "disabled_and_observed_absent",
            }
        )

        with self.assertRaises(WorkerUnavailable) as raised:
            backend.run(reviewer_task(), fake_codex.path.parent / "blocked-attempt")

        self.assertEqual(
            raised.exception.diagnostic["qualification_state"],
            "diagnostic_mismatch",
        )
        self.assertEqual(
            raised.exception.diagnostic["filesystem_write_mitigation"], "not_verified"
        )
        self.assertEqual(raised.exception.diagnostic["nested_web_search"], "not_verified")


if __name__ == "__main__":
    unittest.main()
