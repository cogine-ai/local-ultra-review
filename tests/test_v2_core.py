from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from local_ultra_review import store as store_module  # noqa: E402
from local_ultra_review.backend import (  # noqa: E402
    FAKE_BACKEND_VERSION,
    PROTOCOL_VERSION,
    RUN_MANIFEST_VERSION,
)
from local_ultra_review.contracts import (  # noqa: E402
    ALL_MANUAL_ASSURANCE,
    ORCHESTRATION_CONTRACT_VERSION,
    SCHEMA_VERSION,
    SYNTHETIC_ATTEMPT_ASSURANCE,
    adapter_manual_item_hash,
    canonical_json_bytes,
    prompt_contracts,
    review_identity_hash,
    schema_contracts,
    sha256_json,
)
from local_ultra_review.git_target import (  # noqa: E402
    TargetError,
    build_review_packet,
    seal_two_dot_target,
)
from local_ultra_review.redaction import (  # noqa: E402
    SensitiveMaterialError,
    assert_safe_sink,
    redaction_contract,
)
from local_ultra_review.store import ArtifactStore, IntegrityError  # noqa: E402


TOKEN = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def run(argv: list[str], cwd: Path, *, text: bool = True) -> str | bytes:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=text,
    )
    return completed.stdout


class GitRepo:
    def __init__(self, root: Path) -> None:
        self.root = root
        run(["git", "init", "-q"], root)
        run(["git", "config", "user.name", "V2 Test"], root)
        run(["git", "config", "user.email", "v2@example.invalid"], root)

    def write_text(self, name: str, value: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def write_bytes(self, name: str, value: bytes) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)

    def commit(self, message: str) -> str:
        run(["git", "add", "-A"], self.root)
        run(["git", "commit", "-qm", message], self.root)
        return str(run(["git", "rev-parse", "HEAD"], self.root)).strip()


class GitTargetTests(unittest.TestCase):
    def make_repo(self) -> tuple[tempfile.TemporaryDirectory[str], GitRepo]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, GitRepo(Path(temporary.name))

    def test_two_dot_target_pins_requested_upper_bound(self) -> None:
        temporary, repo = self.make_repo()
        self.addCleanup(temporary.cleanup)
        repo.write_text("app.py", "VALUE = 1\n")
        base = repo.commit("base")
        repo.write_text("app.py", "VALUE = 2\n")
        requested_head = repo.commit("requested")
        repo.write_text("app.py", "VALUE = 3\n")
        repo.commit("later")

        target = seal_two_dot_target(repo.root, base, requested_head)
        packet = build_review_packet(target)

        self.assertEqual(target.base_sha, base)
        self.assertEqual(target.head_sha, requested_head)
        self.assertIn("VALUE = 2", target.redacted_diff_text)
        self.assertNotIn("VALUE = 3", target.redacted_diff_text)
        self.assertNotIn(str(repo.root), json.dumps(packet))
        self.assertEqual(packet["target_identity_hash"], target.target_identity_hash)

    def test_dirty_or_untracked_checkout_is_rejected(self) -> None:
        temporary, repo = self.make_repo()
        self.addCleanup(temporary.cleanup)
        repo.write_text("app.py", "VALUE = 1\n")
        base = repo.commit("base")
        repo.write_text("app.py", "VALUE = 2\n")
        head = repo.commit("head")

        repo.write_text("app.py", "dirty\n")
        with self.assertRaisesRegex(TargetError, "clean"):
            seal_two_dot_target(repo.root, base, head)
        run(["git", "restore", "app.py"], repo.root)
        repo.write_text("untracked.txt", "x\n")
        with self.assertRaisesRegex(TargetError, "clean"):
            seal_two_dot_target(repo.root, base, head)

    def test_no_rename_detection_keeps_delete_and_add_paths(self) -> None:
        temporary, repo = self.make_repo()
        self.addCleanup(temporary.cleanup)
        repo.write_text("old.txt", "same content\n")
        base = repo.commit("base")
        os.rename(repo.root / "old.txt", repo.root / "new.txt")
        head = repo.commit("move")

        target = seal_two_dot_target(repo.root, base, head)

        self.assertEqual(target.changed_paths, ("new.txt", "old.txt"))
        metadata_paths = {
            atom["path"] for atom in target.coverage_atoms if atom["kind"] == "path_metadata"
        }
        self.assertEqual(metadata_paths, {"new.txt", "old.txt"})

    def test_literal_pathspec_name_is_not_silently_omitted(self) -> None:
        temporary, repo = self.make_repo()
        self.addCleanup(temporary.cleanup)
        path = ":(literal)magic.txt"
        repo.write_text(path, "before\n")
        base = repo.commit("base")
        repo.write_text(path, "after\n")
        head = repo.commit("head")

        target = seal_two_dot_target(repo.root, base, head)

        self.assertIn("after", target.redacted_diff_text)
        self.assertTrue(
            any(
                atom["path"] == path and atom["kind"] == "text_hunk"
                for atom in target.coverage_atoms
            )
        )

    def test_every_path_and_hunk_is_in_exact_reviewed_or_manual_partition(self) -> None:
        temporary, repo = self.make_repo()
        self.addCleanup(temporary.cleanup)
        repo.write_text("app.py", "VALUE = 1\n")
        repo.write_text("mode.sh", "#!/bin/sh\nexit 0\n")
        base = repo.commit("base")
        repo.write_text("app.py", "VALUE = 2\n")
        repo.write_bytes("image.bin", b"\x00\x01\x02binary")
        repo.write_text("empty.txt", "")
        os.chmod(repo.root / "mode.sh", stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        head = repo.commit("mixed")

        target = seal_two_dot_target(repo.root, base, head)
        packet = build_review_packet(target)
        all_atoms = {atom["atom_id"] for atom in target.coverage_atoms}
        reviewed = set(packet["reviewable_atom_ids"])
        manual = {
            atom_id
            for disposition in target.manual_dispositions
            for atom_id in disposition["atom_ids"]
        }

        self.assertFalse(reviewed & manual)
        self.assertEqual(reviewed | manual, all_atoms)
        self.assertIn("image.bin", target.changed_paths)
        self.assertTrue(
            any(item["path"] == "image.bin" and item["reason"] == "binary_content" for item in target.manual_dispositions)
        )
        self.assertTrue(
            any(atom["path"] == "empty.txt" and atom["kind"] == "path_metadata" for atom in target.coverage_atoms)
        )
        self.assertTrue(
            any(atom["path"] == "mode.sh" and atom["kind"] == "path_metadata" for atom in target.coverage_atoms)
        )

    def test_symlink_and_gitlink_are_manual_not_omitted(self) -> None:
        temporary, repo = self.make_repo()
        self.addCleanup(temporary.cleanup)
        submodule_temporary = tempfile.TemporaryDirectory()
        self.addCleanup(submodule_temporary.cleanup)
        submodule = GitRepo(Path(submodule_temporary.name))
        submodule.write_text("module.txt", "module\n")
        submodule.commit("module base")
        repo.write_text("base.txt", "base\n")
        base = repo.commit("base")
        os.symlink("base.txt", repo.root / "link.txt")
        run(
            [
                "git",
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                str(submodule.root),
                "vendor/sub",
            ],
            repo.root,
        )
        head = repo.commit("special")

        target = seal_two_dot_target(repo.root, base, head)

        reasons = {(item["path"], item["reason"]) for item in target.manual_dispositions}
        self.assertIn(("link.txt", "special_file"), reasons)
        self.assertIn(("vendor/sub", "submodule_gitlink"), reasons)

    def test_sensitive_paths_and_inline_secrets_are_redacted_and_manual(self) -> None:
        temporary, repo = self.make_repo()
        self.addCleanup(temporary.cleanup)
        repo.write_text("app.py", "VALUE = 1\n")
        base = repo.commit("base")
        repo.write_text(".env.production", f"API_TOKEN={TOKEN}\n")
        repo.write_text("app.py", f'VALUE = 2\nAPI_KEY = "{TOKEN}"\n')
        head = repo.commit("secret")

        target = seal_two_dot_target(repo.root, base, head)
        packet_text = json.dumps(build_review_packet(target), sort_keys=True)
        token_hash = hashlib.sha256(TOKEN.encode()).hexdigest()
        inline_secret_blob_id = str(
            run(["git", "rev-parse", "--short", f"{head}:app.py"], repo.root)
        ).strip()

        self.assertNotIn(TOKEN, target.redacted_diff_text)
        self.assertNotIn(TOKEN, packet_text)
        self.assertNotIn(token_hash, packet_text)
        self.assertNotIn(inline_secret_blob_id, packet_text)
        self.assertIn("[WITHHELD:sensitive_path]", target.redacted_diff_text)
        self.assertIn("[REDACTED:", target.redacted_diff_text)
        self.assertTrue(any(item["reason"] == "sensitive_path" for item in target.manual_dispositions))
        self.assertTrue(any(item["reason"] == "sensitive_content_redacted" for item in target.manual_dispositions))

    def test_envrc_and_quoted_json_secret_assignment_are_contained(self) -> None:
        temporary, repo = self.make_repo()
        self.addCleanup(temporary.cleanup)
        repo.write_text("config.json", "{}\n")
        base = repo.commit("base")
        repo.write_text(".envrc", "PASSWORD=environment-secret-value\n")
        repo.write_text("config.json", '{"password": "super-secret-password"}\n')
        head = repo.commit("secret forms")

        target = seal_two_dot_target(repo.root, base, head)
        packet_text = json.dumps(build_review_packet(target), sort_keys=True)

        self.assertNotIn("environment-secret-value", packet_text)
        self.assertNotIn("super-secret-password", packet_text)
        self.assertIn("[WITHHELD:sensitive_path]", target.redacted_diff_text)
        self.assertIn("[REDACTED:secret_assignment:", target.redacted_diff_text)
        self.assertIn(
            (".envrc", "sensitive_path"),
            {(item["path"], item["reason"]) for item in target.manual_dispositions},
        )

    def test_private_key_redaction_claims_every_spanned_hunk(self) -> None:
        temporary, repo = self.make_repo()
        self.addCleanup(temporary.cleanup)
        repo.write_text("key_material.txt", "".join(f"line {index}\n" for index in range(1, 21)))
        base = repo.commit("base")
        lines = [f"line {index}\n" for index in range(1, 21)]
        lines[0] = "-----BEGIN PRIVATE KEY-----\n"
        lines[-1] = "-----END PRIVATE KEY-----\n"
        repo.write_text("key_material.txt", "".join(lines))
        head = repo.commit("two hunk key")

        target = seal_two_dot_target(repo.root, base, head)
        packet = build_review_packet(target)
        hunk_ids = {
            atom["atom_id"]
            for atom in target.coverage_atoms
            if atom["path"] == "key_material.txt" and atom["kind"] == "text_hunk"
        }
        manual_hunk_ids = {
            atom_id
            for disposition in target.manual_dispositions
            for atom_id in disposition["atom_ids"]
            if atom_id in hunk_ids
        }
        metadata_id = next(
            atom["atom_id"]
            for atom in target.coverage_atoms
            if atom["path"] == "key_material.txt" and atom["kind"] == "path_metadata"
        )

        self.assertEqual(len(hunk_ids), 2)
        self.assertEqual(manual_hunk_ids, hunk_ids)
        self.assertIn(metadata_id, packet["reviewable_atom_ids"])

    def test_target_identity_is_stable_and_excludes_local_path(self) -> None:
        temporary, repo = self.make_repo()
        self.addCleanup(temporary.cleanup)
        repo.write_text("app.py", "VALUE = 1\n")
        base = repo.commit("base")
        repo.write_text("app.py", "VALUE = 2\n")
        head = repo.commit("head")

        first = seal_two_dot_target(repo.root, base, head)
        second = seal_two_dot_target(repo.root, base, head)

        self.assertEqual(first.target_identity_hash, second.target_identity_hash)
        self.assertEqual(first.safe_diff_hash, second.safe_diff_hash)
        self.assertNotIn(str(repo.root), json.dumps(build_review_packet(first)))

    def test_ambient_diff_config_and_later_attributes_do_not_change_target(self) -> None:
        temporary, repo = self.make_repo()
        self.addCleanup(temporary.cleanup)
        repo.write_text("app.py", "VALUE = 1\n")
        base = repo.commit("base")
        repo.write_text("app.py", "VALUE = 2\n")
        requested_head = repo.commit("requested")
        expected = seal_two_dot_target(repo.root, base, requested_head)

        run(["git", "config", "diff.noprefix", "true"], repo.root)
        run(["git", "config", "diff.algorithm", "histogram"], repo.root)
        git_dir = Path(str(run(["git", "rev-parse", "--git-dir"], repo.root)).strip())
        if not git_dir.is_absolute():
            git_dir = repo.root / git_dir
        (git_dir / "info").mkdir(exist_ok=True)
        (git_dir / "info/attributes").write_text("app.py -diff\n", encoding="utf-8")
        repo.write_text(".gitattributes", "app.py -diff\n")
        repo.write_text("app.py", "VALUE = 3\n")
        repo.commit("later attributes")

        actual = seal_two_dot_target(repo.root, base, requested_head)
        self.assertEqual(actual.safe_diff_hash, expected.safe_diff_hash)
        self.assertEqual(actual.coverage_atoms, expected.coverage_atoms)
        self.assertEqual(actual.manual_dispositions, expected.manual_dispositions)
        self.assertEqual(actual.target_identity_hash, expected.target_identity_hash)

    def test_submodule_ignore_all_cannot_hide_dirty_submodule(self) -> None:
        temporary, repo = self.make_repo()
        self.addCleanup(temporary.cleanup)
        submodule_temporary = tempfile.TemporaryDirectory()
        self.addCleanup(submodule_temporary.cleanup)
        submodule = GitRepo(Path(submodule_temporary.name))
        submodule.write_text("module.txt", "module\n")
        submodule.commit("module base")
        repo.write_text("app.py", "VALUE = 1\n")
        base = repo.commit("base")
        run(
            [
                "git",
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                str(submodule.root),
                "vendor/sub",
            ],
            repo.root,
        )
        repo.write_text("app.py", "VALUE = 2\n")
        head = repo.commit("head")
        run(["git", "config", "submodule.vendor/sub.ignore", "all"], repo.root)
        (repo.root / "vendor/sub/module.txt").write_text("dirty\n", encoding="utf-8")

        with self.assertRaisesRegex(TargetError, "clean"):
            seal_two_dot_target(repo.root, base, head)

    def test_explicit_credential_store_paths_are_withheld(self) -> None:
        temporary, repo = self.make_repo()
        self.addCleanup(temporary.cleanup)
        repo.write_text("app.py", "VALUE = 1\n")
        base = repo.commit("base")
        repo.write_text(".git-credentials", "https://user:passphrase@example.com\n")
        repo.write_text(".aws/credentials", "[default]\naws_secret_access_key = plain credential\n")
        head = repo.commit("credentials")

        target = seal_two_dot_target(repo.root, base, head)
        packet = json.dumps(build_review_packet(target), sort_keys=True)
        self.assertNotIn("passphrase", packet)
        self.assertNotIn("plain credential", packet)
        self.assertEqual(
            {
                item["path"]
                for item in target.manual_dispositions
                if item["reason"] == "sensitive_path"
            },
            {".aws/credentials", ".git-credentials"},
        )


class RedactionTests(unittest.TestCase):
    def test_safe_sink_rejects_provider_token_assignment_and_private_key(self) -> None:
        unsafe_values = [
            {"token": TOKEN},
            "password = super-secret-password",
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
        ]
        for value in unsafe_values:
            with self.subTest(value=value):
                with self.assertRaises(SensitiveMaterialError):
                    assert_safe_sink(value)

        assert_safe_sink({"token_state": "redacted", "message": "safe"})

    def test_sink_scans_mapping_keys_and_quoted_secrets_with_spaces(self) -> None:
        for value in (
            {TOKEN: "ordinary value"},
            'password = "correct horse battery, staple"',
            {'password': "correct horse battery, staple"},
        ):
            with self.subTest(value=value):
                with self.assertRaises(SensitiveMaterialError):
                    assert_safe_sink(value)

    def test_quoted_secret_with_spaces_is_redacted_from_packet(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        repo = GitRepo(Path(temporary.name))
        repo.write_text("app.py", "VALUE = 1\n")
        base = repo.commit("base")
        repo.write_text("app.py", 'password = "correct horse battery, staple"\n')
        head = repo.commit("secret")

        target = seal_two_dot_target(repo.root, base, head)
        packet = json.dumps(build_review_packet(target), sort_keys=True)
        self.assertNotIn("correct horse battery", packet)
        self.assertIn("[REDACTED:secret_assignment:", target.redacted_diff_text)
        self.assertTrue(
            any(item["reason"] == "sensitive_content_redacted" for item in target.manual_dispositions)
        )

    def test_json_escaped_quotes_do_not_truncate_secret_redaction(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        repo = GitRepo(Path(temporary.name))
        repo.write_text("config.json", "{}\n")
        base = repo.commit("base")
        raw_secret = 'correct horse, "battery" staple'
        repo.write_text("config.json", json.dumps({"password": raw_secret}) + "\n")
        head = repo.commit("secret")

        target = seal_two_dot_target(repo.root, base, head)
        packet = json.dumps(build_review_packet(target), sort_keys=True)
        self.assertNotIn("battery", packet)
        self.assertNotIn("staple", packet)
        self.assertIn("[REDACTED:secret_assignment:", target.redacted_diff_text)
        with self.assertRaises(SensitiveMaterialError):
            assert_safe_sink(json.dumps({"password": raw_secret}))


def semantic_plan_for(*, total_attempts: int = 1) -> dict:
    roles = (
        []
        if total_attempts == 0
        else ["reviewer", *(["verifier"] * (total_attempts - 1))]
    )
    return {
        "profile": "evaluation_slice_v2",
        "authority": "synthetic_evaluation",
        "execution_backend": "fake_evaluation",
        "release_ready": False,
        "roles": ["correctness"],
        "model": "synthetic-model",
        "schema_contracts": schema_contracts(),
        "prompt_contracts": prompt_contracts(),
        "redaction_contract": redaction_contract(),
        "fake_readiness": {
            "ready": True,
            "mode": "synthetic_evaluation_only",
            "authority": "synthetic_evaluation",
            "execution_backend": "fake_evaluation",
            "live_dispatch_authorized": False,
            "live_dispatch_blockers": ["fake_backend_has_no_live_authority"],
            "consumption_state": {
                "total_attempts": total_attempts,
                "consumed_attempts": 0,
                "remaining_attempts": total_attempts,
            },
        },
        "fake_semantic_identity": {
            "backend": "fake_evaluation",
            "backend_version": FAKE_BACKEND_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "run_manifest_version": RUN_MANIFEST_VERSION,
            "scenario_id": "store-fixture",
            "total_attempts": total_attempts,
            "expected_role_sequence": roles,
            "unbound_attempt_templates_sha256": (
                sha256_json([]) if total_attempts == 0 else "f" * 64
            ),
        },
        "orchestration_contract_version": ORCHESTRATION_CONTRACT_VERSION,
        "run_manifest_version": RUN_MANIFEST_VERSION,
    }


def plan_for(session_root: Path, *, total_attempts: int = 1) -> dict:
    semantic_plan = semantic_plan_for(total_attempts=total_attempts)
    target_identity_hash = "b" * 64
    plan_without_hash = {
        "schema_version": SCHEMA_VERSION,
        "session_id": "session-001",
        "session_root": str(session_root),
        "created_at": "2026-07-11T00:00:00Z",
        "review_identity_hash": review_identity_hash(target_identity_hash, semantic_plan),
        "target_identity_hash": target_identity_hash,
        "semantic_plan": semantic_plan,
    }
    return {**plan_without_hash, "plan_integrity_hash": sha256_json(plan_without_hash)}


def producer() -> dict:
    return {
        "producer_kind": "worker_attempt",
        "task_id": "reviewer-001",
        "attempt_hash": "e" * 64,
        "thread_id": "thread-001",
        "process_launch_id": "process-001",
        "input_hashes": sorted(["c" * 64, "d" * 64]),
    }


def adapter_producer(operation_id: str = "adapter-target-packet") -> dict:
    return {
        "producer_kind": "adapter_operation",
        "operation_id": operation_id,
        "input_hashes": [],
    }


def reviewer_wrapper() -> dict:
    result = {
        "schema_version": SCHEMA_VERSION,
        "task_id": "reviewer-001",
        "packet_hash": "d" * 64,
        "status": "completed",
        "coverage": {"reviewed_atom_ids": ["atom-1"], "notes": "Reviewed."},
        "candidates": [],
    }
    manifest = {
        "adapter_version": FAKE_BACKEND_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "run_manifest_version": RUN_MANIFEST_VERSION,
        "authority": "synthetic_evaluation",
        "execution_backend": "fake_evaluation",
        "task_id": "reviewer-001",
        "task_hash": "c" * 64,
        "attempt_hash": "e" * 64,
        "packet_hash": "d" * 64,
        "process_launch_id": "process-001",
        "thread_id": "thread-001",
        "synthetic_thread_id": "thread-001",
        "observed_event_count": 2,
        "observed_tool_call_count": 0,
        **SYNTHETIC_ATTEMPT_ASSURANCE,
    }
    return {"result": result, "adapter_manifest": manifest}


def all_manual_completion(plan: dict) -> dict:
    disposition = {
        "path": "asset.bin",
        "reason": "binary_content",
        "atom_ids": ["atom-1"],
        "disposition_id": "manual-" + "a" * 64,
    }
    item_hash = adapter_manual_item_hash(disposition)
    return {
        "schema_version": SCHEMA_VERSION,
        "authority": "synthetic_evaluation",
        "authoritative_review": False,
        "execution_backend": "fake_evaluation",
        "profile": "evaluation_slice_v2",
        "release_ready": False,
        "session_id": plan["session_id"],
        "plan_integrity_hash": plan["plan_integrity_hash"],
        "review_identity_hash": plan["review_identity_hash"],
        "protocol_completeness": "complete",
        "simulated_review_verdict": "manual_review_required",
        "reviewer_execution_state": "not_applicable_no_reviewable_atoms",
        "worker_dispatch_state": "not_applicable_no_reviewable_atoms",
        "coverage": {"total_atoms": 1, "reviewed_atoms": 0, "manual_atoms": 1},
        "accounting": {
            "raw_candidates": 0,
            "verifier_results": 0,
            "confirmed_candidate_dispositions": 0,
            "canonical_findings": 0,
            "false_positive": 0,
            "pre_existing": 0,
            "needs_manual_review": 0,
            "adapter_manual_items": 1,
        },
        "reviewer_artifact_hash": None,
        "verifier_artifact_hashes": [],
        "canonical_finding_hashes": [],
        "canonical_finding_records": [],
        "manual_item_hashes": [item_hash],
        "manual_item_records": [
            {
                "domain": "adapter_manual_disposition",
                "disposition": disposition,
                "manual_item_hash": item_hash,
            }
        ],
        "accepted_artifact_hashes": [],
        "assurance_contract_under_test": dict(ALL_MANUAL_ASSURANCE),
    }


def completed_completion(plan: dict, reviewer_envelope_hash: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "authority": "synthetic_evaluation",
        "authoritative_review": False,
        "execution_backend": "fake_evaluation",
        "profile": "evaluation_slice_v2",
        "release_ready": False,
        "session_id": plan["session_id"],
        "plan_integrity_hash": plan["plan_integrity_hash"],
        "review_identity_hash": plan["review_identity_hash"],
        "protocol_completeness": "complete",
        "simulated_review_verdict": "clean",
        "reviewer_execution_state": "completed",
        "worker_dispatch_state": "synthetic_attempts_accepted",
        "coverage": {"total_atoms": 1, "reviewed_atoms": 1, "manual_atoms": 0},
        "accounting": {
            "raw_candidates": 0,
            "verifier_results": 0,
            "confirmed_candidate_dispositions": 0,
            "canonical_findings": 0,
            "false_positive": 0,
            "pre_existing": 0,
            "needs_manual_review": 0,
            "adapter_manual_items": 0,
        },
        "reviewer_artifact_hash": reviewer_envelope_hash,
        "verifier_artifact_hashes": [],
        "canonical_finding_hashes": [],
        "canonical_finding_records": [],
        "manual_item_hashes": [],
        "manual_item_records": [],
        "accepted_artifact_hashes": [reviewer_envelope_hash],
        "assurance_contract_under_test": dict(SYNTHETIC_ATTEMPT_ASSURANCE),
    }


class ArtifactStoreTests(unittest.TestCase):
    def make_store(
        self, *, total_attempts: int = 1
    ) -> tuple[tempfile.TemporaryDirectory[str], ArtifactStore, Path]:
        temporary = tempfile.TemporaryDirectory()
        session = Path(temporary.name) / "session"
        store = ArtifactStore.create(
            session, plan_for(session, total_attempts=total_attempts)
        )
        return temporary, store, session

    def test_create_is_atomic_exclusive_and_has_genesis(self) -> None:
        temporary, store, session = self.make_store()
        self.addCleanup(temporary.cleanup)

        self.assertTrue((session / "plan.json").is_file())
        self.assertTrue((session / "ledger.jsonl").is_file())
        self.assertTrue((session / "plan.json").read_bytes().endswith(b"\n"))
        self.assertTrue((session / "ledger.jsonl").read_bytes().endswith(b"\n"))
        self.assertFalse(any(session.parent.glob(f".{session.name}.staging-*")))
        store.verify()
        with self.assertRaises(IntegrityError):
            ArtifactStore.create(session, plan_for(session))

    def test_plan_binds_exact_semantic_plan_to_review_identity(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for mutation in ("semantic", "review_identity"):
            session = root / mutation
            plan = plan_for(session)
            if mutation == "semantic":
                plan["semantic_plan"]["model"] = "different-model"
            else:
                plan["review_identity_hash"] = "a" * 64
            core = {key: value for key, value in plan.items() if key != "plan_integrity_hash"}
            plan["plan_integrity_hash"] = sha256_json(core)
            with self.subTest(mutation=mutation), self.assertRaises(IntegrityError):
                ArtifactStore.create(session, plan)

        first_root = root / "first"
        second_root = root / "second"
        first = plan_for(first_root)
        second = plan_for(second_root)
        second["session_id"] = "session-002"
        second["created_at"] = "2026-07-11T00:01:00Z"
        second_core = {
            key: value for key, value in second.items() if key != "plan_integrity_hash"
        }
        second["plan_integrity_hash"] = sha256_json(second_core)
        self.assertEqual(first["review_identity_hash"], second["review_identity_hash"])
        self.assertNotEqual(first["plan_integrity_hash"], second["plan_integrity_hash"])

    def test_exact_artifact_registry_and_producer_tag_union(self) -> None:
        temporary, store, _session = self.make_store(total_attempts=0)
        self.addCleanup(temporary.cleanup)
        adapter_types = (
            "target_packet",
            "reviewer_packet",
            "verifier_packet",
            "diagnostic",
            "evaluation_report",
            "diagnostic_report",
            "evaluation_completion",
        )
        for index, artifact_type in enumerate(adapter_types):
            payload = (
                all_manual_completion(store._plan)
                if artifact_type == "evaluation_completion"
                else {"safe": artifact_type}
            )
            store.write_artifact(
                artifact_type,
                payload,
                adapter_producer(f"adapter-{index}-{artifact_type}"),
            )

        with self.assertRaises(IntegrityError):
            store.write_artifact("unknown_type", {"safe": True}, adapter_producer())
        with self.assertRaises(IntegrityError):
            store.write_artifact("target_packet", {"safe": True}, producer())
        with self.assertRaises(IntegrityError):
            store.write_artifact("reviewer_result", reviewer_wrapper(), adapter_producer())

        for invalid in (
            {"producer_kind": "adapter_operation", "operation_id": "none", "input_hashes": []},
            {**producer(), "thread_id": "not_applicable"},
            {**producer(), "extra": True},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(IntegrityError):
                store.write_artifact("reviewer_result", reviewer_wrapper(), invalid)

    def test_worker_wrapper_is_exact_and_cross_reconciled_before_persistence(self) -> None:
        mutations = (
            lambda wrapper, producer_value: wrapper.update(extra=True),
            lambda wrapper, producer_value: wrapper["adapter_manifest"].__setitem__("extra", True),
            lambda wrapper, producer_value: wrapper["result"].__setitem__("task_id", "reviewer-other"),
            lambda wrapper, producer_value: wrapper["result"].__setitem__("packet_hash", "a" * 64),
            lambda wrapper, producer_value: wrapper["adapter_manifest"].__setitem__("task_id", "reviewer-other"),
            lambda wrapper, producer_value: wrapper["adapter_manifest"].__setitem__("attempt_hash", "a" * 64),
            lambda wrapper, producer_value: wrapper["adapter_manifest"].__setitem__("packet_hash", "a" * 64),
            lambda wrapper, producer_value: wrapper["adapter_manifest"].__setitem__("process_launch_id", "process-other"),
            lambda wrapper, producer_value: wrapper["adapter_manifest"].__setitem__("thread_id", "thread-other"),
            lambda wrapper, producer_value: wrapper["adapter_manifest"].__setitem__("synthetic_thread_id", "thread-other"),
            lambda wrapper, producer_value: wrapper["adapter_manifest"].__setitem__("adapter_version", "wrong"),
            lambda wrapper, producer_value: wrapper["adapter_manifest"].__setitem__("protocol_version", "wrong"),
            lambda wrapper, producer_value: wrapper["adapter_manifest"].__setitem__("run_manifest_version", "wrong"),
            lambda wrapper, producer_value: wrapper["adapter_manifest"].__setitem__("authority", "canonical_review"),
            lambda wrapper, producer_value: wrapper["adapter_manifest"].__setitem__("execution_backend", "codex_exec"),
            lambda wrapper, producer_value: wrapper["adapter_manifest"].__setitem__("accepted_tool_calls", "not_applicable_no_dispatch"),
            lambda wrapper, producer_value: producer_value.__setitem__("input_hashes", ["d" * 64]),
        )
        for index, mutate in enumerate(mutations):
            temporary, store, session = self.make_store()
            wrapper = reviewer_wrapper()
            producer_value = producer()
            mutate(wrapper, producer_value)
            before = {
                path.relative_to(session): path.read_bytes()
                for path in session.rglob("*")
                if path.is_file()
            }
            try:
                with self.subTest(index=index), self.assertRaises(IntegrityError):
                    store.write_artifact("reviewer_result", wrapper, producer_value)
                after = {
                    path.relative_to(session): path.read_bytes()
                    for path in session.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(after, before)
            finally:
                temporary.cleanup()

    def test_completion_binds_plan_attempt_count_and_persisted_worker_results(self) -> None:
        temporary, store, _session = self.make_store(total_attempts=1)
        self.addCleanup(temporary.cleanup)
        reviewer = store.write_artifact(
            "reviewer_result", reviewer_wrapper(), producer()
        )
        completion = completed_completion(store._plan, reviewer["envelope_hash"])
        envelope = store.write_artifact(
            "evaluation_completion",
            completion,
            adapter_producer("adapter-completion"),
        )
        self.assertEqual(envelope["payload"], completion)
        store.verify()

        report = store.write_artifact(
            "evaluation_report",
            {"view": "synthetic evaluation"},
            adapter_producer("adapter-evaluation-report"),
        )
        self.assertEqual(report["artifact_type"], "evaluation_report")
        store.verify()
        with self.assertRaises(IntegrityError):
            store.write_artifact(
                "evaluation_completion",
                completion,
                adapter_producer("adapter-second-completion"),
            )
        with self.assertRaises(IntegrityError):
            store.write_artifact("reviewer_result", reviewer_wrapper(), producer())
        with self.assertRaises(IntegrityError):
            store.write_artifact(
                "diagnostic",
                {"status": "late"},
                adapter_producer("adapter-late-diagnostic"),
            )

    def test_schema_valid_completion_with_store_mismatch_is_rejected_before_write(self) -> None:
        cases = ("session", "plan", "review", "reviewer_hash", "attempt_count")
        for case in cases:
            total_attempts = 2 if case == "attempt_count" else 1
            temporary, store, session = self.make_store(total_attempts=total_attempts)
            reviewer = store.write_artifact(
                "reviewer_result", reviewer_wrapper(), producer()
            )
            completion = completed_completion(store._plan, reviewer["envelope_hash"])
            if case == "session":
                completion["session_id"] = "different-session"
            elif case == "plan":
                completion["plan_integrity_hash"] = "a" * 64
            elif case == "review":
                completion["review_identity_hash"] = "a" * 64
            elif case == "reviewer_hash":
                completion["reviewer_artifact_hash"] = "a" * 64
                completion["accepted_artifact_hashes"] = ["a" * 64]
            before = {
                path.relative_to(session): path.read_bytes()
                for path in session.rglob("*")
                if path.is_file()
            }
            try:
                with self.subTest(case=case), self.assertRaises(IntegrityError):
                    store.write_artifact(
                        "evaluation_completion",
                        completion,
                        adapter_producer(f"adapter-invalid-{case}"),
                    )
                after = {
                    path.relative_to(session): path.read_bytes()
                    for path in session.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(after, before)
            finally:
                temporary.cleanup()

    def test_all_manual_completion_requires_zero_sealed_attempts_and_no_worker_results(self) -> None:
        temporary, store, _session = self.make_store(total_attempts=0)
        self.addCleanup(temporary.cleanup)
        store.write_artifact(
            "evaluation_completion",
            all_manual_completion(store._plan),
            adapter_producer("adapter-all-manual-completion"),
        )
        store.verify()

        temporary_bad, bad_store, _bad_session = self.make_store(total_attempts=1)
        try:
            with self.assertRaises(IntegrityError):
                bad_store.write_artifact(
                    "evaluation_completion",
                    all_manual_completion(bad_store._plan),
                    adapter_producer("adapter-invalid-all-manual"),
                )
        finally:
            temporary_bad.cleanup()

    def test_directory_publication_never_replaces_existing_destination(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source = root / "staging"
        destination = root / "session"
        source.mkdir()
        (source / "source-marker").write_text("source", encoding="utf-8")
        destination.mkdir()
        (destination / "destination-marker").write_text("destination", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            store_module._rename_directory_exclusive(source, destination)

        self.assertTrue((source / "source-marker").is_file())
        self.assertTrue((destination / "destination-marker").is_file())

    def test_short_writes_are_completed_and_zero_write_fails_before_publish(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        session = root / "session"
        real_write = os.write

        def short_write(descriptor: int, data: bytes | bytearray | memoryview) -> int:
            raw = bytes(data)
            return real_write(descriptor, raw[: max(1, len(raw) // 3)])

        with mock.patch.object(store_module.os, "write", side_effect=short_write):
            store = ArtifactStore.create(session, plan_for(session))
            store.write_artifact("reviewer_result", reviewer_wrapper(), producer())
        store.verify()

        failed_session = root / "failed-session"
        with mock.patch.object(store_module.os, "write", return_value=0):
            with self.assertRaises(IntegrityError):
                ArtifactStore.create(failed_session, plan_for(failed_session))
        self.assertFalse(failed_session.exists())

    def test_artifact_is_content_addressed_readable_and_verified(self) -> None:
        temporary, store, session = self.make_store()
        self.addCleanup(temporary.cleanup)

        envelope = store.write_artifact("reviewer_result", reviewer_wrapper(), producer())

        artifact_path = session / "artifacts" / "reviewer_result" / f'{envelope["envelope_hash"]}.json'
        self.assertTrue(artifact_path.is_file())
        self.assertEqual(store.read_artifacts("reviewer_result"), [envelope])
        store.verify()

    def test_sink_rejection_writes_no_secret_or_secret_hash(self) -> None:
        temporary, store, session = self.make_store()
        self.addCleanup(temporary.cleanup)
        before = sorted(path.relative_to(session) for path in session.rglob("*") if path.is_file())

        with self.assertRaises(SensitiveMaterialError):
            store.write_artifact("target_packet", {"token": TOKEN}, adapter_producer())

        after = sorted(path.relative_to(session) for path in session.rglob("*") if path.is_file())
        surviving = b"".join(path.read_bytes() for path in session.rglob("*") if path.is_file())
        self.assertEqual(after, before)
        self.assertNotIn(TOKEN.encode(), surviving)
        self.assertNotIn(hashlib.sha256(TOKEN.encode()).hexdigest().encode(), surviving)

    def test_secret_producer_metadata_is_rejected_before_hashing(self) -> None:
        temporary, store, session = self.make_store()
        self.addCleanup(temporary.cleanup)
        before = {
            path.relative_to(session): path.read_bytes()
            for path in session.rglob("*")
            if path.is_file()
        }
        hashed_values: list[object] = []
        real_hash = store_module.sha256_json

        def capture_hash(value: object) -> str:
            hashed_values.append(copy.deepcopy(value))
            return real_hash(value)

        unsafe_producer = adapter_producer()
        unsafe_producer["operation_id"] = TOKEN
        with mock.patch.object(store_module, "sha256_json", side_effect=capture_hash):
            with self.assertRaises(SensitiveMaterialError):
                store.write_artifact("target_packet", {"status": "completed"}, unsafe_producer)

        after = {
            path.relative_to(session): path.read_bytes()
            for path in session.rglob("*")
            if path.is_file()
        }
        self.assertEqual(after, before)
        self.assertNotIn(TOKEN, json.dumps(hashed_values, sort_keys=True))

    def test_reserved_artifact_event_cannot_corrupt_the_ledger(self) -> None:
        temporary, store, session = self.make_store()
        self.addCleanup(temporary.cleanup)
        ledger = session / "ledger.jsonl"
        before = ledger.read_bytes()

        with self.assertRaises(IntegrityError):
            store.append_event(
                "artifact_committed",
                {"artifact_type": "reviewer_result", "envelope_hash": "d" * 64},
            )

        self.assertEqual(ledger.read_bytes(), before)
        store.verify()

    def test_artifact_type_is_reconciled_across_ledger_envelope_and_path(self) -> None:
        for target in ("ledger", "path"):
            with self.subTest(target=target):
                temporary, store, session = self.make_store()
                envelope = store.write_artifact(
                    "reviewer_result", reviewer_wrapper(), producer()
                )
                artifact_path = (
                    session
                    / "artifacts"
                    / "reviewer_result"
                    / f'{envelope["envelope_hash"]}.json'
                )
                if target == "ledger":
                    ledger_path = session / "ledger.jsonl"
                    records = [json.loads(line) for line in ledger_path.read_bytes().splitlines()]
                    record = records[-1]
                    record["payload"]["artifact_type"] = "worker_result"
                    record["payload_hash"] = sha256_json(record["payload"])
                    event_core = {
                        key: value for key, value in record.items() if key != "event_hash"
                    }
                    record["event_hash"] = sha256_json(event_core)
                    ledger_path.write_bytes(
                        b"".join(canonical_json_bytes(item) for item in records)
                    )
                else:
                    moved_directory = session / "artifacts" / "worker_result"
                    moved_directory.mkdir()
                    artifact_path.rename(moved_directory / artifact_path.name)
                try:
                    with self.assertRaises(IntegrityError):
                        store.verify()
                finally:
                    temporary.cleanup()

    def test_rehashed_artifact_still_requires_strict_matching_producer_inputs(self) -> None:
        temporary, store, session = self.make_store()
        self.addCleanup(temporary.cleanup)
        envelope = store.write_artifact(
            "reviewer_result", reviewer_wrapper(), producer()
        )
        old_path = (
            session
            / "artifacts"
            / "reviewer_result"
            / f'{envelope["envelope_hash"]}.json'
        )
        mutated = copy.deepcopy(envelope)
        mutated["input_hashes"] = ["d" * 64]
        core = {key: value for key, value in mutated.items() if key != "envelope_hash"}
        mutated["envelope_hash"] = sha256_json(core)
        new_path = old_path.with_name(f'{mutated["envelope_hash"]}.json')
        new_path.write_bytes(canonical_json_bytes(mutated))
        old_path.unlink()

        ledger_path = session / "ledger.jsonl"
        records = [json.loads(line) for line in ledger_path.read_bytes().splitlines()]
        records[-1]["payload"]["envelope_hash"] = mutated["envelope_hash"]
        records[-1]["payload_hash"] = sha256_json(records[-1]["payload"])
        event_core = {
            key: value for key, value in records[-1].items() if key != "event_hash"
        }
        records[-1]["event_hash"] = sha256_json(event_core)
        ledger_path.write_bytes(b"".join(canonical_json_bytes(item) for item in records))

        with self.assertRaises(IntegrityError):
            store.verify()

    def test_rehashed_persisted_wrapper_still_reconciles_manifest_evidence(self) -> None:
        temporary, store, session = self.make_store()
        self.addCleanup(temporary.cleanup)
        envelope = store.write_artifact(
            "reviewer_result", reviewer_wrapper(), producer()
        )
        old_path = (
            session
            / "artifacts"
            / "reviewer_result"
            / f'{envelope["envelope_hash"]}.json'
        )
        mutated = copy.deepcopy(envelope)
        mutated["payload"]["adapter_manifest"]["thread_id"] = "thread-tampered"
        mutated["payload_hash"] = sha256_json(mutated["payload"])
        core = {key: value for key, value in mutated.items() if key != "envelope_hash"}
        mutated["envelope_hash"] = sha256_json(core)
        new_path = old_path.with_name(f'{mutated["envelope_hash"]}.json')
        new_path.write_bytes(canonical_json_bytes(mutated))
        old_path.unlink()

        ledger_path = session / "ledger.jsonl"
        records = [json.loads(line) for line in ledger_path.read_bytes().splitlines()]
        records[-1]["payload"]["envelope_hash"] = mutated["envelope_hash"]
        records[-1]["payload_hash"] = sha256_json(records[-1]["payload"])
        event_core = {
            key: value for key, value in records[-1].items() if key != "event_hash"
        }
        records[-1]["event_hash"] = sha256_json(event_core)
        ledger_path.write_bytes(b"".join(canonical_json_bytes(item) for item in records))

        with self.assertRaises(IntegrityError):
            store.verify()

    def test_unexpected_root_file_directory_or_symlink_fails_verification(self) -> None:
        for kind in ("file", "directory", "symlink"):
            with self.subTest(kind=kind):
                temporary, store, session = self.make_store()
                unexpected = session / "unexpected"
                if kind == "file":
                    unexpected.write_text("extra", encoding="utf-8")
                elif kind == "directory":
                    unexpected.mkdir()
                else:
                    unexpected.symlink_to(session / "plan.json")
                try:
                    with self.assertRaises(IntegrityError):
                        store.verify()
                finally:
                    temporary.cleanup()

    def test_missing_artifact_root_and_torn_ledger_fail_closed(self) -> None:
        for target in ("artifacts", "ledger"):
            with self.subTest(target=target):
                temporary, store, session = self.make_store()
                if target == "artifacts":
                    (session / "artifacts").rmdir()
                else:
                    ledger = session / "ledger.jsonl"
                    ledger.write_bytes(ledger.read_bytes()[:-1])
                try:
                    with self.assertRaises(IntegrityError):
                        store.verify()
                finally:
                    temporary.cleanup()

    def test_plan_artifact_and_ledger_tampering_each_fail_verification(self) -> None:
        for target in ("plan", "artifact", "ledger"):
            with self.subTest(target=target):
                temporary, store, session = self.make_store()
                envelope = store.write_artifact("reviewer_result", reviewer_wrapper(), producer())
                if target == "plan":
                    path = session / "plan.json"
                    value = json.loads(path.read_text())
                    value["session_id"] = "tampered"
                    path.write_text(json.dumps(value), encoding="utf-8")
                elif target == "artifact":
                    path = session / "artifacts" / "reviewer_result" / f'{envelope["envelope_hash"]}.json'
                    value = json.loads(path.read_text())
                    value["payload"]["result"]["status"] = "tampered"
                    path.write_text(json.dumps(value), encoding="utf-8")
                else:
                    path = session / "ledger.jsonl"
                    lines = path.read_text().splitlines()
                    record = json.loads(lines[-1])
                    record["event_type"] = "tampered"
                    lines[-1] = json.dumps(record)
                    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                try:
                    with self.assertRaises(IntegrityError):
                        store.verify()
                finally:
                    temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
