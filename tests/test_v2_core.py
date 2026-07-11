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
from local_ultra_review.contracts import (  # noqa: E402
    SCHEMA_VERSION,
    canonical_json_bytes,
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


def plan_for(session_root: Path) -> dict:
    plan_without_hash = {
        "schema_version": SCHEMA_VERSION,
        "session_id": "session-001",
        "session_root": str(session_root),
        "created_at": "2026-07-11T00:00:00Z",
        "review_identity_hash": "a" * 64,
        "target_identity_hash": "b" * 64,
    }
    return {**plan_without_hash, "plan_integrity_hash": sha256_json(plan_without_hash)}


def producer() -> dict:
    return {
        "task_id": "reviewer-001",
        "attempt_id": "attempt-001",
        "thread_id": "thread-001",
        "process_launch_id": "process-001",
        "input_hashes": ["c" * 64],
    }


class ArtifactStoreTests(unittest.TestCase):
    def make_store(self) -> tuple[tempfile.TemporaryDirectory[str], ArtifactStore, Path]:
        temporary = tempfile.TemporaryDirectory()
        session = Path(temporary.name) / "session"
        store = ArtifactStore.create(session, plan_for(session))
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

    def test_artifact_is_content_addressed_readable_and_verified(self) -> None:
        temporary, store, session = self.make_store()
        self.addCleanup(temporary.cleanup)

        envelope = store.write_artifact("reviewer_result", {"status": "completed"}, producer())

        artifact_path = session / "artifacts" / "reviewer_result" / f'{envelope["envelope_hash"]}.json'
        self.assertTrue(artifact_path.is_file())
        self.assertEqual(store.read_artifacts("reviewer_result"), [envelope])
        store.verify()

    def test_sink_rejection_writes_no_secret_or_secret_hash(self) -> None:
        temporary, store, session = self.make_store()
        self.addCleanup(temporary.cleanup)
        before = sorted(path.relative_to(session) for path in session.rglob("*") if path.is_file())

        with self.assertRaises(SensitiveMaterialError):
            store.write_artifact("worker_result", {"token": TOKEN}, producer())

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

        unsafe_producer = producer()
        unsafe_producer["task_id"] = TOKEN
        with mock.patch.object(store_module, "sha256_json", side_effect=capture_hash):
            with self.assertRaises(SensitiveMaterialError):
                store.write_artifact("worker_result", {"status": "completed"}, unsafe_producer)

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
                    "reviewer_result", {"status": "completed"}, producer()
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
                envelope = store.write_artifact("reviewer_result", {"status": "completed"}, producer())
                if target == "plan":
                    path = session / "plan.json"
                    value = json.loads(path.read_text())
                    value["session_id"] = "tampered"
                    path.write_text(json.dumps(value), encoding="utf-8")
                elif target == "artifact":
                    path = session / "artifacts" / "reviewer_result" / f'{envelope["envelope_hash"]}.json'
                    value = json.loads(path.read_text())
                    value["payload"]["status"] = "tampered"
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
