from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from local_ultra_review import orchestrator as orchestrator_module  # noqa: E402
from local_ultra_review.backend import (  # noqa: E402
    FakeBackend,
    REVIEWED_ATOM_IDS_PLACEHOLDER,
    ScriptedAttempt,
)
from local_ultra_review.orchestrator import (  # noqa: E402
    EvaluationRequest,
    evaluate,
)
from local_ultra_review.render import MaterializationError, RenderError  # noqa: E402
from local_ultra_review.store import ArtifactStore  # noqa: E402
from tests.test_v2_backend import FakeCodex, write_qualification  # noqa: E402
from tests.test_v2_orchestrator import (  # noqa: E402
    EvaluationFixture,
    attempt,
    candidate,
    reviewer_template,
    verifier_template,
)


COMPLETE_REVIEW_BANNER = (
    "Review process complete under the Codex-native guarded worker profile."
)
SECRET = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
FINE_GRAINED_PAT = "github_pat_" + "B" * 40
COMPOUND_SECRET = "compound-secret-value-1234567890abcdef"


def surviving_output_bytes(root: Path, session_root: Path) -> bytes:
    paths = []
    if session_root.exists():
        paths.extend(path for path in session_root.rglob("*") if path.is_file())
    paths.extend(
        path
        for path in (
            root / "evaluation-report.md",
            root / "diagnostic.md",
            root / "recovery-diagnostic.md",
        )
        if path.is_file()
    )
    return b"\n".join(path.read_bytes() for path in paths)


class EvaluationEndToEndTests(unittest.TestCase):
    def test_clean_fake_evaluation_is_non_authoritative_and_fully_verified(self) -> None:
        fixture = EvaluationFixture(self)
        outcome = evaluate(fixture.request(), fixture.backend([], []))

        self.assertEqual(outcome.evaluation_completion["simulated_review_verdict"], "clean")
        self.assertFalse(outcome.evaluation_completion["authoritative_review"])
        self.assertFalse(outcome.evaluation_completion["release_ready"])
        report_path = outcome.evaluation_report_path
        assert report_path is not None
        report = report_path.read_text(encoding="utf-8")
        self.assertIn("# Synthetic protocol evaluation — not a code-review result", report)
        self.assertIn("makes no claim that the target is clean", report)
        self.assertNotIn(COMPLETE_REVIEW_BANNER, report)
        self.assertFalse((fixture.root / "report.md").exists())
        store = ArtifactStore(fixture.session_root)
        store.verify()
        completion = store.read_artifacts("evaluation_completion")
        reports = store.read_artifacts("evaluation_report")
        self.assertEqual(len(completion), 1)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["input_hashes"], [completion[0]["envelope_hash"]])

    def test_confirmed_important_report_contains_every_synthetic_proof_field(self) -> None:
        fixture = EvaluationFixture(self)
        outcome = evaluate(
            fixture.request(),
            fixture.backend([candidate("seeded")], [("confirmed", "Important")]),
        )

        self.assertEqual(outcome.evaluation_completion["simulated_review_verdict"], "findings")
        report_path = outcome.evaluation_report_path
        assert report_path is not None
        report = report_path.read_text(encoding="utf-8")
        for marker in (
            "synthetic_title: `Candidate seeded`",
            "synthetic_severity: `Important`",
            "synthetic_evidence:",
            "synthetic_evidence_item: `Evidence for candidate seeded.`",
            "synthetic_why_diff:",
            "synthetic_why_diff: `The two-dot diff introduces condition seeded.`",
            "synthetic_confirmed_instances:",
            "synthetic_candidate_hash:",
            "synthetic_duplicate_ordinal:",
            "synthetic_verifier_result_envelope_hash:",
            "synthetic_proof:",
            "synthetic_proof_item: `The candidate was independently checked.`",
            "synthetic_provenance:",
            "synthetic_provenance_item: `Compared against the sealed two-dot diff.`",
            "synthetic_best_fix:",
            "synthetic_best_fix_item: `Restore the local boundary check.`",
            "synthetic_refactor_judgment:",
            "synthetic_refactor_judgment_item: `A focused correction is sufficient.`",
            "synthetic_residual_risk:",
            "synthetic_residual_risk_item: `Unrelated runtime paths were not executed.`",
            "synthetic_canonical_finding_hash:",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, report)
        self.assertNotIn(COMPLETE_REVIEW_BANNER, report)
        ArtifactStore(fixture.session_root).verify()

    def test_prompt_only_missing_verifier_and_observed_tool_never_render_success(self) -> None:
        prompt_fixture = EvaluationFixture(self)
        prompt_only = json.dumps(
            {"task_id": "{{TASK_ID}}", "packet_hash": "{{PACKET_HASH}}"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        prompt_outcome = evaluate(
            prompt_fixture.request(),
            FakeBackend(
                scenario_id="e2e-prompt-only",
                attempts=[attempt("reviewer", prompt_only, 0)],
            ),
        )
        self.assertEqual(prompt_outcome.diagnostic["reason_codes"], ["worker_attempt_rejected"])
        self.assertEqual(prompt_outcome.diagnostic_path.name, "diagnostic.md")
        self.assertFalse((prompt_fixture.root / "evaluation-report.md").exists())
        self.assertNotIn(
            "target is clean",
            prompt_outcome.diagnostic_path.read_text(encoding="utf-8").casefold(),
        )

        missing_fixture = EvaluationFixture(self)
        missing_outcome = evaluate(
            missing_fixture.request(),
            missing_fixture.backend([candidate("missing-verifier")], []),
        )
        self.assertEqual(
            missing_outcome.diagnostic["reason_codes"], ["scripted_attempts_exhausted"]
        )
        self.assertFalse((missing_fixture.root / "evaluation-report.md").exists())

        tool_fixture = EvaluationFixture(self)
        valid = reviewer_template(REVIEWED_ATOM_IDS_PLACEHOLDER, [])
        tool_attempt = ScriptedAttempt(
            expected_role="reviewer",
            raw_events=(
                {"type": "thread.started", "thread_id": "thread-tool-e2e"},
                {"type": "tool", "name": "forbidden"},
            ),
            last_message_template=valid,
            process_launch_id="process-tool-e2e",
        )
        tool_outcome = evaluate(
            tool_fixture.request(),
            FakeBackend(scenario_id="e2e-tool", attempts=[tool_attempt]),
        )
        self.assertEqual(
            tool_outcome.diagnostic["reason_codes"], ["fake_backend_scenario_invalid"]
        )
        self.assertFalse(tool_fixture.session_root.exists())
        self.assertEqual(tool_outcome.diagnostic_path.name, "diagnostic.md")

        malformed_fixture = EvaluationFixture(self)
        malformed_attempt = ScriptedAttempt(
            expected_role="reviewer",
            raw_events=(
                {"type": "thread.started", "thread_id": "thread-malformed-e2e"},
            ),
            last_message_template=b'{"task_id":"{{TASK_ID}}",',
            process_launch_id="process-malformed-e2e",
        )
        malformed_outcome = evaluate(
            malformed_fixture.request(),
            FakeBackend(scenario_id="e2e-malformed", attempts=[malformed_attempt]),
        )
        self.assertEqual(
            malformed_outcome.diagnostic["reason_codes"],
            ["fake_backend_scenario_invalid"],
        )
        self.assertFalse(malformed_fixture.session_root.exists())

        reused_fixture = EvaluationFixture(self)
        reused_candidate = candidate("reused-thread")
        reused_backend = FakeBackend(
            scenario_id="e2e-reused-thread",
            attempts=[
                attempt(
                    "reviewer",
                    reviewer_template(
                        REVIEWED_ATOM_IDS_PLACEHOLDER, [reused_candidate]
                    ),
                    0,
                    thread_id="shared-thread-e2e",
                ),
                attempt(
                    "verifier",
                    verifier_template("confirmed", final_severity="Important"),
                    1,
                    thread_id="shared-thread-e2e",
                ),
            ],
        )
        reused_outcome = evaluate(reused_fixture.request(), reused_backend)
        self.assertEqual(
            reused_outcome.diagnostic["reason_codes"], ["worker_attempt_rejected"]
        )
        self.assertEqual(reused_outcome.diagnostic["failure_phase"], "verifier_acceptance")
        self.assertFalse((reused_fixture.root / "evaluation-report.md").exists())

    def test_mixed_binary_sensitive_and_manual_outputs_contain_no_secret(self) -> None:
        fixture = EvaluationFixture(self, kind="mixed")
        fixture.repo.write_text(".env.production", f"API_TOKEN={SECRET}\n")
        fixture.repo.write_text(
            "config.py",
            "\n".join(
                (
                    f'PROVIDER_TOKEN = "{SECRET}"',
                    f'AWS_SECRET_ACCESS_KEY = "{COMPOUND_SECRET}"',
                    f'credential = "{FINE_GRAINED_PAT}"',
                    "",
                )
            ),
        )
        head = fixture.repo.commit("sensitive head")
        request = EvaluationRequest(
            repo=fixture.repo.root,
            base=fixture.base,
            head=head,
            model="synthetic-model",
            session_root=fixture.session_root,
        )
        outcome = evaluate(request, fixture.backend([], []))

        self.assertEqual(
            outcome.evaluation_completion["simulated_review_verdict"],
            "manual_review_required",
        )
        store = ArtifactStore(fixture.session_root)
        store.verify()
        target_packet = store.read_artifacts("target_packet")[0]["payload"]
        dispositions = target_packet["manual_dispositions"]
        self.assertEqual(
            {(item["path"], item["reason"]) for item in dispositions},
            {
                (".env.production", "sensitive_path"),
                ("asset.bin", "binary_content"),
                ("config.py", "sensitive_content_redacted"),
            },
        )
        all_atom_ids = {item["atom_id"] for item in target_packet["coverage_atoms"]}
        reviewed_atom_ids = set(target_packet["reviewable_atom_ids"])
        manual_atom_ids = {
            atom_id
            for disposition in dispositions
            for atom_id in disposition["atom_ids"]
        }
        self.assertFalse(reviewed_atom_ids & manual_atom_ids)
        self.assertEqual(reviewed_atom_ids | manual_atom_ids, all_atom_ids)
        self.assertEqual(
            outcome.evaluation_completion["coverage"]["manual_atoms"],
            len(manual_atom_ids),
        )
        self.assertEqual(
            {
                item["disposition"]["reason"]
                for item in outcome.evaluation_completion["manual_item_records"]
                if item["domain"] == "adapter_manual_disposition"
            },
            {"binary_content", "sensitive_path", "sensitive_content_redacted"},
        )
        output = surviving_output_bytes(fixture.root, fixture.session_root)
        for secret in (SECRET, COMPOUND_SECRET, FINE_GRAINED_PAT):
            with self.subTest(secret=secret[:16]):
                self.assertNotIn(secret.encode("utf-8"), output)
                self.assertNotIn(
                    hashlib.sha256(secret.encode("utf-8")).hexdigest().encode("ascii"),
                    output,
                )
        self.assertFalse((fixture.root / "report.md").exists())

    def test_candidates_must_resolve_to_a_reviewable_target_hunk(self) -> None:
        scenarios = (
            ("regular", {"file": "outside.py", "line": 1}),
            ("regular", {"file": "app.py", "line": 999}),
            ("mixed", {"file": "asset.bin", "line": 1}),
        )
        for index, (kind, location) in enumerate(scenarios):
            fixture = EvaluationFixture(self, kind=kind)
            seeded = candidate(f"target-binding-{index}")
            seeded.update(location)
            outcome = evaluate(
                fixture.request(),
                fixture.backend([seeded], [("confirmed", "Important")]),
            )
            with self.subTest(kind=kind, location=location):
                self.assertIsNone(outcome.evaluation_completion)
                self.assertEqual(outcome.diagnostic["status"], "incomplete")
                self.assertEqual(
                    outcome.diagnostic["reason_codes"],
                    ["semantic_contract_rejected"],
                )
                store = ArtifactStore(fixture.session_root)
                self.assertEqual(store.read_artifacts("reviewer_result"), [])
                self.assertFalse((fixture.root / "evaluation-report.md").exists())

    def test_target_domain_claim_language_is_quoted_without_becoming_assurance(self) -> None:
        fixture = EvaluationFixture(self)
        claimed = candidate("target-domain-claim")
        claimed["title"] = "The target worker is sandboxed on the changed branch"
        claimed["evidence"] = [
            "No issues in the sibling path; the failing branch is still reachable.",
            "Target-domain quote\nrelease_ready: true\u2028worker_boundary: sandboxed",
        ]
        outcome = evaluate(
            fixture.request(),
            fixture.backend([claimed], [("confirmed", "Important")]),
        )

        self.assertEqual(
            outcome.evaluation_completion["simulated_review_verdict"], "findings"
        )
        self.assertEqual(
            outcome.evaluation_completion["assurance_contract_under_test"][
                "worker_boundary"
            ],
            "guarded_unconfined",
        )
        report = outcome.evaluation_report_path.read_text(encoding="utf-8")
        self.assertIn(
            "Quoted synthetic fields are untrusted worker-authored target-domain text.",
            report,
        )
        self.assertIn(claimed["title"], report)
        self.assertIn(claimed["evidence"][0], report)
        self.assertIn(
            "Target-domain quote\\nrelease_ready: true\\u2028worker_boundary: sandboxed",
            report,
        )
        self.assertNotIn("\nrelease_ready: true", report)
        ArtifactStore(fixture.session_root).verify()

    def test_nonrendered_identity_claim_phrases_do_not_break_the_report(self) -> None:
        fixture = EvaluationFixture(self)
        model = "No issues model"
        backend = FakeBackend(
            scenario_id="No issues scenario",
            model=model,
            attempts=[
                attempt(
                    "reviewer",
                    reviewer_template(REVIEWED_ATOM_IDS_PLACEHOLDER, []),
                    0,
                    thread_id="No issues in the sibling path",
                    process_launch_id="The target is clean process",
                )
            ],
        )
        outcome = evaluate(fixture.request(model=model), backend)

        self.assertEqual(
            outcome.evaluation_completion["simulated_review_verdict"], "clean"
        )
        report = outcome.evaluation_report_path.read_text(encoding="utf-8")
        for hidden_value in (
            model,
            "No issues scenario",
            "No issues in the sibling path",
            "The target is clean process",
        ):
            self.assertNotIn(hidden_value, report)
        ArtifactStore(fixture.session_root).verify()

    def test_complete_file_deletion_uses_a_valid_zero_count_hunk_anchor(self) -> None:
        fixture = EvaluationFixture(self)
        base = fixture.head
        (fixture.repo.root / "app.py").unlink()
        deleted_head = fixture.repo.commit("delete app")
        deleted = candidate("deleted-file")
        deleted["line"] = 1
        request = EvaluationRequest(
            repo=fixture.repo.root,
            base=base,
            head=deleted_head,
            model="synthetic-model",
            session_root=fixture.session_root,
        )

        outcome = evaluate(
            request,
            fixture.backend([deleted], [("confirmed", "Important")]),
        )

        self.assertEqual(
            outcome.evaluation_completion["simulated_review_verdict"], "findings"
        )
        self.assertEqual(
            outcome.evaluation_completion["canonical_finding_records"][0][
                "root_cause"
            ]["line"],
            1,
        )
        ArtifactStore(fixture.session_root).verify()

    def test_renderer_rejection_occurs_before_completion_terminal(self) -> None:
        fixture = EvaluationFixture(self)
        with mock.patch.object(
            orchestrator_module,
            "render_evaluation_report",
            side_effect=RenderError("synthetic precommit renderer rejection"),
        ):
            outcome = evaluate(fixture.request(), fixture.backend([], []))

        self.assertIsNone(outcome.evaluation_completion)
        self.assertEqual(outcome.diagnostic["failure_phase"], "completion_gate")
        self.assertEqual(
            outcome.diagnostic["reason_codes"], ["completion_projection_rejected"]
        )
        store = ArtifactStore(fixture.session_root)
        self.assertEqual(store.read_artifacts("evaluation_completion"), [])
        self.assertEqual(store.read_artifacts("evaluation_report"), [])
        self.assertEqual(len(store.read_artifacts("diagnostic")), 1)

    def test_mode_only_target_is_all_manual_and_dispatches_no_worker(self) -> None:
        fixture = EvaluationFixture(self)
        base = fixture.head
        source = fixture.repo.root / "app.py"
        os.chmod(source, 0o755)
        head = fixture.repo.commit("mode-only head")
        request = EvaluationRequest(
            repo=fixture.repo.root,
            base=base,
            head=head,
            model="synthetic-model",
            session_root=fixture.session_root,
        )
        backend = FakeBackend(scenario_id="e2e-mode-only", attempts=[])
        with mock.patch.object(backend, "run", wraps=backend.run) as run_worker:
            outcome = evaluate(request, backend)
        run_worker.assert_not_called()
        self.assertEqual(
            outcome.evaluation_completion["simulated_review_verdict"],
            "manual_review_required",
        )
        self.assertGreater(outcome.evaluation_completion["coverage"]["manual_atoms"], 0)
        self.assertIn(
            "No worker was dispatched for this all-manual fixture.",
            outcome.evaluation_report_path.read_text(encoding="utf-8"),
        )

    def test_canonical_tamper_returns_only_integrity_recovery_view(self) -> None:
        fixture = EvaluationFixture(self, kind="manual")
        real_create = ArtifactStore.create

        class TamperBeforeGate:
            def __init__(self, real: ArtifactStore) -> None:
                self.real = real
                self.tampered = False

            def write_artifact(self, artifact_type, payload, producer):
                return self.real.write_artifact(artifact_type, payload, producer)

            def read_artifacts(self, artifact_type):
                return self.real.read_artifacts(artifact_type)

            def verify(self):
                if not self.tampered:
                    self.tampered = True
                    (self.real.session_root / "plan.json").write_bytes(b"{}\n")
                return self.real.verify()

        def create_tampered(session_root, plan):
            return TamperBeforeGate(real_create(session_root, plan))

        with mock.patch.object(
            orchestrator_module.ArtifactStore,
            "create",
            side_effect=create_tampered,
        ):
            outcome = evaluate(
                fixture.request(),
                FakeBackend(scenario_id="e2e-tamper", attempts=[]),
            )

        self.assertEqual(
            outcome.recovery_reason_codes, ("canonical_store_verification_failed",)
        )
        self.assertEqual(outcome.recovery_diagnostic_path.name, "recovery-diagnostic.md")
        recovery = outcome.recovery_diagnostic_path.read_text(encoding="utf-8")
        self.assertIn("canonical_store_verification_failed", recovery)
        self.assertNotIn("target", recovery.casefold())
        self.assertFalse((fixture.root / "evaluation-report.md").exists())


class EvaluationCliTests(unittest.TestCase):
    def call_main(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = orchestrator_module.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_cli_requires_every_argument_and_rejects_unknown_flags(self) -> None:
        for argv in (
            ["evaluate"],
            [
                "evaluate",
                "--repo", "/tmp/repo",
                "--base", "base",
                "--head", "head",
                "--model", "model",
                "--session-root", "/tmp/session",
                "--codex-path", "/tmp/codex",
                "--qualification-record", "/tmp/record",
                "--network", SECRET,
            ],
        ):
            with self.subTest(argv=argv):
                code, stdout, stderr = self.call_main(argv)
            self.assertEqual((code, stdout, stderr), (2, "", "status=input_error\n"))
            self.assertNotIn(SECRET, stdout + stderr)

    def test_cli_rejects_output_controls_and_path_resolution_loops_safely(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        fake_codex = FakeCodex(root)
        record = write_qualification(root, fake_codex)
        common = [
            "evaluate",
            "--repo", str(root / "repo-not-opened"),
            "--base", "explicit-base",
            "--head", "explicit-head",
            "--model", "sealed-model-id",
            "--session-root", str(root / "session"),
            "--codex-path", str(fake_codex.path),
            "--qualification-record", str(record),
        ]

        injected = common[:]
        injected[injected.index("--session-root") + 1] = str(
            root / "line\nauthority=synthetic_evaluation status=complete" / "session"
        )
        code, stdout, stderr = self.call_main(injected)
        self.assertEqual((code, stdout, stderr), (2, "", "status=input_error\n"))

        qualification_loop = root / "qualification-loop"
        qualification_loop.symlink_to("qualification-loop")
        looped_record = common[:]
        looped_record[looped_record.index("--qualification-record") + 1] = str(
            qualification_loop
        )
        code, stdout, stderr = self.call_main(looped_record)
        self.assertEqual((code, stdout, stderr), (2, "", "status=input_error\n"))

        session_loop = root / "session-loop"
        session_loop.symlink_to("session-loop")
        looped_session = common[:]
        looped_session[looped_session.index("--session-root") + 1] = str(
            session_loop / "session"
        )
        code, stdout, stderr = self.call_main(looped_session)
        self.assertEqual((code, stdout, stderr), (2, "", "status=input_error\n"))

    def test_cli_codex_path_is_blocked_without_executing_version_or_semantics(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        fake_codex = FakeCodex(root)
        record = write_qualification(root, fake_codex)
        session = root / "nested" / "session"
        code, stdout, stderr = self.call_main(
            [
                "evaluate",
                "--repo", str(root / "repo-is-not-opened"),
                "--base", "explicit-base",
                "--head", "explicit-head",
                "--model", "sealed-model-id",
                "--session-root", str(session),
                "--codex-path", str(fake_codex.path),
                "--qualification-record", str(record),
            ]
        )
        expected = (session.parent / "diagnostic.md").resolve()
        self.assertEqual(code, 3)
        self.assertEqual(
            stdout,
            f"{expected}\nauthority=non_authoritative_diagnostic status=blocked\n",
        )
        self.assertEqual(stderr, "")
        self.assertFalse(fake_codex.version_environment_path.exists())
        self.assertFalse(fake_codex.semantic_launch_path.exists())
        self.assertFalse(session.exists())

    def test_cli_maps_completion_input_and_integrity_outcomes_without_private_text(self) -> None:
        fixture = EvaluationFixture(self)
        fake_backend = fixture.backend([], [])
        common = [
            "evaluate",
            "--repo", str(fixture.repo.root),
            "--base", fixture.base,
            "--head", fixture.head,
            "--model", "synthetic-model",
            "--session-root", str(fixture.session_root),
            "--codex-path", str(fixture.root / "unused-codex"),
            "--qualification-record", str(fixture.root / "unused-record"),
        ]
        with mock.patch.object(
            orchestrator_module, "CodexCliBackend", return_value=fake_backend
        ):
            code, stdout, stderr = self.call_main(common)
        self.assertEqual(code, 0)
        self.assertEqual(
            stdout,
            f"{(fixture.root / 'evaluation-report.md').resolve()}\n"
            "authority=synthetic_evaluation status=complete\n",
        )
        self.assertEqual(stderr, "")

        input_fixture = EvaluationFixture(self)
        input_args = [
            *common[:],
        ]
        input_args[input_args.index("--repo") + 1] = str(input_fixture.repo.root)
        input_args[input_args.index("--base") + 1] = input_fixture.base
        input_args[input_args.index("--head") + 1] = input_fixture.base
        input_args[input_args.index("--session-root") + 1] = str(input_fixture.session_root)
        with mock.patch.object(
            orchestrator_module,
            "CodexCliBackend",
            return_value=input_fixture.backend([], []),
        ):
            code, stdout, stderr = self.call_main(input_args)
        self.assertEqual((code, stdout, stderr), (2, "", "status=input_error\n"))

        integrity_fixture = EvaluationFixture(self)
        integrity_args = common[:]
        integrity_args[integrity_args.index("--repo") + 1] = str(integrity_fixture.repo.root)
        integrity_args[integrity_args.index("--base") + 1] = integrity_fixture.base
        integrity_args[integrity_args.index("--head") + 1] = integrity_fixture.head
        integrity_args[integrity_args.index("--session-root") + 1] = str(
            integrity_fixture.session_root
        )
        with (
            mock.patch.object(
                orchestrator_module,
                "CodexCliBackend",
                return_value=integrity_fixture.backend([], []),
            ),
            mock.patch.object(
                orchestrator_module,
                "evaluate",
                side_effect=MaterializationError("private destination detail"),
            ),
        ):
            code, stdout, stderr = self.call_main(integrity_args)
        self.assertEqual((code, stdout, stderr), (4, "", "status=integrity_failure\n"))

    def test_cli_emits_exact_recovery_outcome_after_canonical_tamper(self) -> None:
        fixture = EvaluationFixture(self, kind="manual")
        backend = FakeBackend(scenario_id="cli-recovery", attempts=[])
        real_create = ArtifactStore.create

        class TamperBeforeGate:
            def __init__(self, real: ArtifactStore) -> None:
                self.real = real
                self.tampered = False

            def write_artifact(self, artifact_type, payload, producer):
                return self.real.write_artifact(artifact_type, payload, producer)

            def read_artifacts(self, artifact_type):
                return self.real.read_artifacts(artifact_type)

            def verify(self):
                if not self.tampered:
                    self.tampered = True
                    (self.real.session_root / "plan.json").write_bytes(b"{}\n")
                return self.real.verify()

        def create_tampered(session_root, plan):
            return TamperBeforeGate(real_create(session_root, plan))

        argv = [
            "evaluate",
            "--repo", str(fixture.repo.root),
            "--base", fixture.base,
            "--head", fixture.head,
            "--model", "synthetic-model",
            "--session-root", str(fixture.session_root),
            "--codex-path", str(fixture.root / "unused-codex"),
            "--qualification-record", str(fixture.root / "unused-record"),
        ]
        with (
            mock.patch.object(orchestrator_module, "CodexCliBackend", return_value=backend),
            mock.patch.object(
                orchestrator_module.ArtifactStore,
                "create",
                side_effect=create_tampered,
            ),
        ):
            code, stdout, stderr = self.call_main(argv)

        expected = (fixture.root / "recovery-diagnostic.md").resolve()
        self.assertEqual(code, 4)
        self.assertEqual(
            stdout,
            f"{expected}\nauthority=non_authoritative status=integrity_failure\n",
        )
        self.assertEqual(stderr, "")

    def test_wheel_and_editable_console_and_resources_work_from_foreign_cwd(self) -> None:
        uv = shutil.which("uv")
        self.assertIsNotNone(uv, "Task 6 distribution proof requires uv")
        assert uv is not None
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        source = root / "source"
        source.mkdir()
        shutil.copy2(ROOT / "pyproject.toml", source / "pyproject.toml")
        shutil.copytree(ROOT / "src", source / "src")
        dist = root / "dist"
        subprocess.run(
            [uv, "build", "--wheel", "--out-dir", str(dist), str(source)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        wheel = next(dist.glob("*.whl"))
        fake_codex = FakeCodex(root)
        record = write_qualification(root, fake_codex)
        for label, install_arguments in (
            ("wheel", [str(wheel)]),
            ("editable", ["-e", str(source)]),
        ):
            with self.subTest(install=label):
                mode_root = root / label
                mode_root.mkdir()
                venv = mode_root / "venv"
                subprocess.run(
                    [uv, "venv", "--python", sys.executable, str(venv)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                binary_root = venv / ("Scripts" if os.name == "nt" else "bin")
                installed_python = binary_root / (
                    "python.exe" if os.name == "nt" else "python"
                )
                subprocess.run(
                    [
                        uv,
                        "pip",
                        "install",
                        "--python",
                        str(installed_python),
                        *install_arguments,
                    ],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                foreign_cwd = mode_root / "foreign-cwd"
                foreign_cwd.mkdir()
                resource_probe = subprocess.run(
                    [
                        str(installed_python),
                        "-c",
                        (
                            "from local_ultra_review.contracts import load_schema, prompt_contracts; "
                            "assert load_schema('reviewer-result')['type'] == 'object'; "
                            "assert set(prompt_contracts()) == {'reviewer-correctness', 'verifier'}"
                        ),
                    ],
                    cwd=foreign_cwd,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(
                    (
                        resource_probe.returncode,
                        resource_probe.stdout,
                        resource_probe.stderr,
                    ),
                    (0, "", ""),
                )

                console = binary_root / (
                    "local-ultra-review-v2.exe"
                    if os.name == "nt"
                    else "local-ultra-review-v2"
                )
                session = mode_root / "installed-session"
                installed_run = subprocess.run(
                    [
                        str(console),
                        "evaluate",
                        "--repo",
                        str(root / "repo-not-opened"),
                        "--base",
                        "explicit-base",
                        "--head",
                        "explicit-head",
                        "--model",
                        "sealed-model-id",
                        "--session-root",
                        str(session),
                        "--codex-path",
                        str(fake_codex.path),
                        "--qualification-record",
                        str(record),
                    ],
                    cwd=foreign_cwd,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                expected = (session.parent / "diagnostic.md").resolve()
                self.assertEqual(installed_run.returncode, 3)
                self.assertEqual(
                    installed_run.stdout,
                    f"{expected}\nauthority=non_authoritative_diagnostic status=blocked\n",
                )
                self.assertEqual(installed_run.stderr, "")
                self.assertFalse(session.exists())
        self.assertFalse(fake_codex.version_environment_path.exists())
        self.assertFalse(fake_codex.semantic_launch_path.exists())


if __name__ == "__main__":
    unittest.main()
