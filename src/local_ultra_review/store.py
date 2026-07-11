"""Fail-closed, content-addressed artifact storage for the V2 slice."""

from __future__ import annotations

from copy import deepcopy
import ctypes
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import re
import sys
import uuid

from .backend import (
    WorkerProtocolError,
    validate_run_manifest,
)
from .contracts import (
    ContractError,
    SCHEMA_VERSION,
    canonical_json_bytes,
    review_identity_hash,
    sha256_json,
    validate_payload,
    validate_semantic_plan,
)
from .redaction import assert_safe_sink


class IntegrityError(RuntimeError):
    """Raised when canonical session state is missing, torn, or tampered."""


_HASH = re.compile(r"^[0-9a-f]{64}$")
_ZERO_HASH = "0" * 64
_PLAN_FIELDS = {
    "schema_version",
    "session_id",
    "session_root",
    "created_at",
    "review_identity_hash",
    "target_identity_hash",
    "semantic_plan",
    "plan_integrity_hash",
}
_ADAPTER_ARTIFACT_TYPES = {
    "target_packet",
    "reviewer_packet",
    "verifier_packet",
    "evaluation_completion",
    "diagnostic",
    "evaluation_report",
    "diagnostic_report",
}
_WORKER_ARTIFACT_TYPES = {"reviewer_result", "verifier_result"}
_ARTIFACT_TYPES = _ADAPTER_ARTIFACT_TYPES | _WORKER_ARTIFACT_TYPES
_SENTINEL_EVIDENCE = {
    "none",
    "not_applicable",
    "not-applicable",
    "n/a",
    "unknown",
    "unavailable",
    "adapter",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(descriptor, view[offset:])
        except OSError as error:
            raise IntegrityError(f"write failed: {error}") from error
        if written <= 0:
            raise IntegrityError("write made no forward progress")
        offset += written


def _write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_directory_exclusive(source: Path, destination: Path) -> None:
    """Atomically publish a directory without replacing any destination."""

    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    libc = ctypes.CDLL(None, use_errno=True)
    result: int
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        renamex = libc.renamex_np
        renamex.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex.restype = ctypes.c_int
        result = renamex(source_bytes, destination_bytes, 0x00000004)
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        renameat2 = libc.renameat2
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(-100, source_bytes, -100, destination_bytes, 0x00000001)
    elif os.name == "nt":
        os.rename(source, destination)
        return
    else:
        raise IntegrityError("atomic no-replace directory publication is unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error_number, os.strerror(error_number), str(destination))
    raise OSError(error_number, os.strerror(error_number), str(destination))


def _write_atomic(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        _write_new(temporary, data)
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise IntegrityError(f"immutable file already exists: {path.name}") from error
        _fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()
            _fsync_directory(path.parent)


def _load_canonical_json(path: Path) -> dict:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IntegrityError(f"cannot read canonical JSON {path.name}: {error}") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise IntegrityError(f"non-canonical JSON: {path.name}")
    return value


def _validate_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise IntegrityError(f"invalid {label}")
    return value


def _event(sequence: int, previous_hash: str, event_type: str, payload: dict) -> dict:
    core = {
        "sequence": sequence,
        "previous_hash": previous_hash,
        "event_type": event_type,
        "payload": payload,
        "payload_hash": sha256_json(payload),
        "created_at": _now(),
    }
    return {**core, "event_hash": sha256_json(core)}


def _validate_plan(plan: dict, session_root: Path) -> str:
    assert_safe_sink(plan)
    if set(plan) != _PLAN_FIELDS:
        raise IntegrityError("plan fields do not match the slice contract")
    if plan.get("schema_version") != SCHEMA_VERSION:
        raise IntegrityError("plan schema version mismatch")
    if any(not isinstance(plan.get(key), str) or not plan[key] for key in ("session_id", "created_at")):
        raise IntegrityError("plan identity/time fields must be nonempty strings")
    if not isinstance(plan.get("session_root"), str):
        raise IntegrityError("plan session root must be a string")
    if Path(plan["session_root"]).expanduser().resolve() != session_root:
        raise IntegrityError("plan session root mismatch")
    provided_hash = _validate_hash(plan.get("plan_integrity_hash"), "plan hash")
    core = {key: value for key, value in plan.items() if key != "plan_integrity_hash"}
    if sha256_json(core) != provided_hash:
        raise IntegrityError("plan integrity hash mismatch")
    provided_review_identity = _validate_hash(
        plan.get("review_identity_hash"), "review identity hash"
    )
    target_identity = _validate_hash(plan.get("target_identity_hash"), "target identity hash")
    try:
        validate_semantic_plan(plan.get("semantic_plan"))
        computed_review_identity = review_identity_hash(
            target_identity, plan["semantic_plan"]
        )
    except ContractError as error:
        raise IntegrityError(f"semantic plan is invalid: {error}") from error
    if provided_review_identity != computed_review_identity:
        raise IntegrityError("review identity does not bind target and semantic plan")
    return provided_hash


def _validate_producer(producer: object) -> list[str]:
    if not isinstance(producer, dict):
        raise IntegrityError("producer must be an object")
    assert_safe_sink(producer)
    kind = producer.get("producer_kind")
    if kind == "worker_attempt":
        required = {
            "producer_kind",
            "task_id",
            "attempt_hash",
            "thread_id",
            "process_launch_id",
            "input_hashes",
        }
        if set(producer) != required:
            raise IntegrityError("worker producer fields do not match contract")
        for key in ("task_id", "thread_id", "process_launch_id"):
            child = producer[key]
            if (
                not isinstance(child, str)
                or not child.strip()
                or child.strip().lower() in _SENTINEL_EVIDENCE
            ):
                raise IntegrityError(f"invalid worker producer {key}")
        _validate_hash(producer["attempt_hash"], "producer attempt hash")
    elif kind == "adapter_operation":
        required = {"producer_kind", "operation_id", "input_hashes"}
        if set(producer) != required:
            raise IntegrityError("adapter producer fields do not match contract")
        operation_id = producer["operation_id"]
        if (
            not isinstance(operation_id, str)
            or not operation_id.strip()
            or operation_id.strip().lower() in _SENTINEL_EVIDENCE
        ):
            raise IntegrityError("invalid adapter producer operation ID")
    else:
        raise IntegrityError("producer kind is invalid")
    input_hashes = producer["input_hashes"]
    if (
        not isinstance(input_hashes, list)
        or input_hashes != sorted(set(input_hashes))
        or any(not isinstance(value, str) or not _HASH.fullmatch(value) for value in input_hashes)
    ):
        raise IntegrityError("producer input hashes must be sorted unique SHA-256 values")
    return list(input_hashes)


def _validate_artifact_contract(
    artifact_type: object, payload: object, producer: object
) -> list[str]:
    """Reconcile artifact type, tagged producer, and persisted worker wrapper."""

    assert_safe_sink({
        "artifact_type": artifact_type,
        "payload": payload,
        "producer": producer,
    })
    if not isinstance(artifact_type, str) or artifact_type not in _ARTIFACT_TYPES:
        raise IntegrityError("artifact type is outside the exact slice registry")
    if not isinstance(payload, dict):
        raise IntegrityError("artifact payload must be an object")
    input_hashes = _validate_producer(producer)
    producer_kind = producer["producer_kind"]
    if artifact_type in _ADAPTER_ARTIFACT_TYPES:
        if producer_kind != "adapter_operation":
            raise IntegrityError("adapter artifact requires adapter producer")
        if artifact_type == "evaluation_completion":
            try:
                validate_payload("evaluation-completion", payload)
            except ContractError as error:
                raise IntegrityError(f"evaluation completion contract failed: {error}") from error
        return input_hashes

    if producer_kind != "worker_attempt":
        raise IntegrityError("worker result artifact requires worker producer")
    if set(payload) != {"result", "adapter_manifest"}:
        raise IntegrityError("worker result wrapper fields do not match contract")
    result = payload["result"]
    manifest = payload["adapter_manifest"]
    schema_name = artifact_type.removesuffix("_result") + "-result"
    try:
        validate_payload(schema_name, result)
        validate_run_manifest(manifest)
    except (ContractError, WorkerProtocolError) as error:
        raise IntegrityError(f"worker result wrapper contract failed: {error}") from error
    if not isinstance(result, dict) or not isinstance(manifest, dict):
        raise IntegrityError("worker result and manifest must be objects")
    expected_role = "reviewer" if artifact_type == "reviewer_result" else "verifier"
    task_id = result.get("task_id")
    if not isinstance(task_id, str) or not task_id.startswith(f"{expected_role}-"):
        raise IntegrityError("worker result task role mismatch")
    if not (
        producer["task_id"] == manifest["task_id"] == task_id
        and producer["attempt_hash"] == manifest["attempt_hash"]
        and producer["thread_id"] == manifest["thread_id"] == manifest["synthetic_thread_id"]
        and producer["process_launch_id"] == manifest["process_launch_id"]
        and result.get("packet_hash") == manifest["packet_hash"]
    ):
        raise IntegrityError("worker producer, manifest, and result identity mismatch")
    expected_inputs = sorted([manifest["task_hash"], manifest["packet_hash"]])
    if input_hashes != expected_inputs:
        raise IntegrityError("worker producer inputs must be exactly task and packet hashes")
    return input_hashes


def _validate_completion_store_binding(
    payload: dict,
    plan: dict,
    worker_hashes: dict[str, set[str]],
) -> None:
    """Bind a completion to this plan and the canonical persisted worker envelopes."""

    assert_safe_sink(
        {"payload": payload, "plan": plan, "worker_hashes": worker_hashes}
    )
    if (
        payload.get("session_id") != plan["session_id"]
        or payload.get("plan_integrity_hash") != plan["plan_integrity_hash"]
        or payload.get("review_identity_hash") != plan["review_identity_hash"]
    ):
        raise IntegrityError("evaluation completion identity does not match the Store plan")
    reviewer_hashes = worker_hashes.get("reviewer_result", set())
    verifier_hashes = worker_hashes.get("verifier_result", set())
    if payload["reviewer_execution_state"] == "completed":
        if reviewer_hashes != {payload["reviewer_artifact_hash"]}:
            raise IntegrityError("completion reviewer hash does not match persisted result")
        if verifier_hashes != set(payload["verifier_artifact_hashes"]):
            raise IntegrityError("completion verifier hashes do not match persisted results")
        expected_attempts = 1 + payload["accounting"]["raw_candidates"]
    else:
        if reviewer_hashes or verifier_hashes:
            raise IntegrityError("all-manual completion cannot coexist with worker results")
        expected_attempts = 0
    semantic_total = plan["semantic_plan"]["fake_semantic_identity"]["total_attempts"]
    if semantic_total != expected_attempts:
        raise IntegrityError("completion dispatch count does not match sealed Fake attempts")


class ArtifactStore:
    """Single-writer session store with a verified hash-chain ledger."""

    def __init__(self, session_root: Path) -> None:
        self.session_root = Path(session_root).resolve()

    @classmethod
    def create(cls, session_root: Path, plan: dict) -> "ArtifactStore":
        final = Path(session_root).expanduser().resolve()
        if os.path.lexists(final):
            raise IntegrityError("session root already exists")
        if not isinstance(plan, dict):
            raise IntegrityError("plan must be an object")
        assert_safe_sink(plan)
        plan_copy = deepcopy(plan)
        provided_hash = _validate_plan(plan_copy, final)

        final.parent.mkdir(parents=True, exist_ok=True)
        lock_path = final.parent / f".{final.name}.create.lock"
        try:
            lock_descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as error:
            raise IntegrityError("session creation is already in progress") from error
        os.close(lock_descriptor)
        staging = final.parent / f".{final.name}.staging-{uuid.uuid4().hex}"
        try:
            _fsync_directory(final.parent)
            if os.path.lexists(final):
                raise IntegrityError("session root already exists")
            staging.mkdir(mode=0o700)
            (staging / "artifacts").mkdir(mode=0o700)
            _write_new(staging / "plan.json", canonical_json_bytes(plan_copy))
            genesis = _event(
                0,
                _ZERO_HASH,
                "genesis",
                {"plan_integrity_hash": provided_hash},
            )
            _write_new(staging / "ledger.jsonl", canonical_json_bytes(genesis))
            _fsync_directory(staging / "artifacts")
            _fsync_directory(staging)
            if os.path.lexists(final):
                raise IntegrityError("session root already exists")
            _rename_directory_exclusive(staging, final)
            _fsync_directory(final.parent)
        except Exception:
            if staging.exists():
                for child in sorted(staging.rglob("*"), reverse=True):
                    if child.is_file() or child.is_symlink():
                        child.unlink()
                    elif child.is_dir():
                        child.rmdir()
                staging.rmdir()
            raise
        finally:
            if lock_path.exists():
                lock_path.unlink()
                _fsync_directory(final.parent)
        store = cls(final)
        store.verify()
        return store

    @property
    def _plan(self) -> dict:
        return _load_canonical_json(self.session_root / "plan.json")

    def _read_ledger(self) -> list[dict]:
        path = self.session_root / "ledger.jsonl"
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise IntegrityError(f"cannot read ledger: {error}") from error
        if not raw or not raw.endswith(b"\n"):
            raise IntegrityError("ledger is empty or torn")
        records: list[dict] = []
        for line in raw.splitlines(keepends=True):
            try:
                record = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise IntegrityError("ledger contains invalid JSON") from error
            if not isinstance(record, dict) or canonical_json_bytes(record) != line:
                raise IntegrityError("ledger record is not canonical")
            records.append(record)
        return records

    def _verify_ledger(self, plan: dict) -> tuple[list[dict], set[tuple[str, str]]]:
        records = self._read_ledger()
        previous = _ZERO_HASH
        committed: set[tuple[str, str]] = set()
        for sequence, record in enumerate(records):
            expected_fields = {
                "sequence",
                "previous_hash",
                "event_type",
                "payload",
                "payload_hash",
                "created_at",
                "event_hash",
            }
            if set(record) != expected_fields:
                raise IntegrityError("ledger fields do not match contract")
            if record["sequence"] != sequence or record["previous_hash"] != previous:
                raise IntegrityError("ledger sequence or previous hash mismatch")
            if not isinstance(record["event_type"], str) or not isinstance(record["payload"], dict):
                raise IntegrityError("ledger event type or payload is invalid")
            assert_safe_sink(record["event_type"])
            assert_safe_sink(record["payload"])
            if record["payload_hash"] != sha256_json(record["payload"]):
                raise IntegrityError("ledger payload hash mismatch")
            core = {key: value for key, value in record.items() if key != "event_hash"}
            if record["event_hash"] != sha256_json(core):
                raise IntegrityError("ledger event hash mismatch")
            previous = _validate_hash(record["event_hash"], "event hash")
            if sequence == 0:
                if record["event_type"] != "genesis" or record["payload"] != {
                    "plan_integrity_hash": plan["plan_integrity_hash"]
                }:
                    raise IntegrityError("invalid genesis event")
            elif record["event_type"] == "artifact_committed":
                if set(record["payload"]) != {"artifact_type", "envelope_hash"}:
                    raise IntegrityError("artifact commit payload does not match contract")
                artifact_type = record["payload"].get("artifact_type")
                if not isinstance(artifact_type, str) or artifact_type not in _ARTIFACT_TYPES:
                    raise IntegrityError("committed artifact type is invalid")
                envelope_hash = _validate_hash(
                    record["payload"].get("envelope_hash"), "committed envelope hash"
                )
                commit_identity = (artifact_type, envelope_hash)
                if commit_identity in committed:
                    raise IntegrityError("artifact committed more than once")
                committed.add(commit_identity)
            elif record["event_type"] == "genesis":
                raise IntegrityError("genesis event may only appear first")
        return records, committed

    def _artifact_files(self) -> list[Path]:
        root = self.session_root / "artifacts"
        if not root.is_dir() or root.is_symlink():
            raise IntegrityError("artifact root is missing or invalid")
        try:
            files: list[Path] = []
            for directory in root.iterdir():
                if (
                    directory.is_symlink()
                    or not directory.is_dir()
                    or directory.name not in _ARTIFACT_TYPES
                ):
                    raise IntegrityError("unexpected artifact-store entry")
                for path in directory.iterdir():
                    if path.is_symlink() or not path.is_file() or path.suffix != ".json":
                        raise IntegrityError("unexpected artifact-store file")
                    files.append(path)
            files.sort()
        except OSError as error:
            raise IntegrityError(f"cannot enumerate artifacts: {error}") from error
        return files

    def verify(self) -> None:
        if self.session_root.is_symlink() or not self.session_root.is_dir():
            raise IntegrityError("session root is missing")
        try:
            root_entries = {entry.name: entry for entry in self.session_root.iterdir()}
        except OSError as error:
            raise IntegrityError(f"cannot enumerate session root: {error}") from error
        if set(root_entries) != {"plan.json", "ledger.jsonl", "artifacts"}:
            raise IntegrityError("session root inventory does not match contract")
        if (
            root_entries["plan.json"].is_symlink()
            or not root_entries["plan.json"].is_file()
            or root_entries["ledger.jsonl"].is_symlink()
            or not root_entries["ledger.jsonl"].is_file()
            or root_entries["artifacts"].is_symlink()
            or not root_entries["artifacts"].is_dir()
        ):
            raise IntegrityError("session root entry type does not match contract")
        plan = self._plan
        _validate_plan(plan, self.session_root)
        _records, committed = self._verify_ledger(plan)

        observed: set[tuple[str, str]] = set()
        worker_hashes: dict[str, set[str]] = {
            "reviewer_result": set(),
            "verifier_result": set(),
        }
        completion_payloads: list[dict] = []
        for path in self._artifact_files():
            envelope = _load_canonical_json(path)
            assert_safe_sink(envelope)
            expected_fields = {
                "artifact_type",
                "schema_version",
                "session_id",
                "plan_integrity_hash",
                "review_identity_hash",
                "producer",
                "input_hashes",
                "payload",
                "payload_hash",
                "created_at",
                "envelope_hash",
            }
            if set(envelope) != expected_fields:
                raise IntegrityError("artifact envelope fields do not match contract")
            artifact_type = envelope.get("artifact_type")
            input_hashes = _validate_artifact_contract(
                artifact_type,
                envelope.get("payload"),
                envelope.get("producer"),
            )
            envelope_hash = _validate_hash(envelope.get("envelope_hash"), "envelope hash")
            if path.stem != envelope_hash:
                raise IntegrityError("artifact filename/hash mismatch")
            core_envelope = {key: value for key, value in envelope.items() if key != "envelope_hash"}
            if sha256_json(core_envelope) != envelope_hash:
                raise IntegrityError("artifact envelope hash mismatch")
            if envelope.get("payload_hash") != sha256_json(envelope.get("payload")):
                raise IntegrityError("artifact payload hash mismatch")
            if envelope.get("input_hashes") != input_hashes:
                raise IntegrityError("artifact producer/input hashes disagree")
            if (
                envelope.get("schema_version") != SCHEMA_VERSION
                or envelope.get("session_id") != plan["session_id"]
                or envelope.get("plan_integrity_hash") != plan["plan_integrity_hash"]
                or envelope.get("review_identity_hash") != plan["review_identity_hash"]
            ):
                raise IntegrityError("artifact identity mismatch")
            if artifact_type != path.parent.name:
                raise IntegrityError("artifact type/path mismatch")
            artifact_identity = (artifact_type, envelope_hash)
            if artifact_identity in observed:
                raise IntegrityError("duplicate artifact envelope")
            observed.add(artifact_identity)
            if artifact_type in _WORKER_ARTIFACT_TYPES:
                worker_hashes[artifact_type].add(envelope_hash)
            elif artifact_type == "evaluation_completion":
                completion_payloads.append(envelope["payload"])
        if observed != committed:
            raise IntegrityError("artifact files and commit ledger disagree")
        if len(completion_payloads) > 1:
            raise IntegrityError("a session may contain at most one evaluation completion")
        if completion_payloads:
            _validate_completion_store_binding(
                completion_payloads[0], plan, worker_hashes
            )

    def _append_event_unchecked(
        self, event_type: str, payload: dict, *, allow_reserved: bool = False
    ) -> dict:
        if not isinstance(event_type, str) or not event_type:
            raise IntegrityError("event type must be nonempty")
        assert_safe_sink(event_type)
        if event_type in {"genesis", "artifact_committed"} and not allow_reserved:
            raise IntegrityError("reserved event type is adapter-owned")
        if not isinstance(payload, dict):
            raise IntegrityError("event payload must be an object")
        assert_safe_sink(payload)
        records = self._read_ledger()
        previous = records[-1]["event_hash"]
        record = _event(len(records), previous, event_type, deepcopy(payload))
        descriptor = os.open(self.session_root / "ledger.jsonl", os.O_WRONLY | os.O_APPEND)
        try:
            _write_all(descriptor, canonical_json_bytes(record))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(self.session_root)
        return record

    def append_event(self, event_type: str, payload: dict) -> dict:
        assert_safe_sink({"event_type": event_type, "payload": payload})
        self.verify()
        record = self._append_event_unchecked(event_type, payload)
        self.verify()
        return record

    def write_artifact(self, artifact_type: str, payload: dict, producer: dict) -> dict:
        assert_safe_sink(
            {"artifact_type": artifact_type, "payload": payload, "producer": producer}
        )
        input_hashes = _validate_artifact_contract(artifact_type, payload, producer)
        self.verify()
        plan = self._plan
        completion_directory = self.session_root / "artifacts" / "evaluation_completion"
        if (
            completion_directory.exists()
            and any(completion_directory.glob("*.json"))
            and artifact_type != "evaluation_report"
        ):
            raise IntegrityError("evaluation completion is terminal for the session")
        worker_hashes = {
            worker_type: {
                path.stem
                for path in (
                    self.session_root / "artifacts" / worker_type
                ).glob("*.json")
            }
            for worker_type in _WORKER_ARTIFACT_TYPES
        }
        if artifact_type == "evaluation_completion":
            _validate_completion_store_binding(payload, plan, worker_hashes)
        core = {
            "artifact_type": artifact_type,
            "schema_version": SCHEMA_VERSION,
            "session_id": plan["session_id"],
            "plan_integrity_hash": plan["plan_integrity_hash"],
            "review_identity_hash": plan["review_identity_hash"],
            "producer": deepcopy(producer),
            "input_hashes": list(input_hashes),
            "payload": deepcopy(payload),
            "payload_hash": sha256_json(payload),
            "created_at": _now(),
        }
        envelope = {**core, "envelope_hash": sha256_json(core)}
        assert_safe_sink(envelope)

        artifact_directory = self.session_root / "artifacts" / artifact_type
        artifact_directory.mkdir(mode=0o700, exist_ok=True)
        _fsync_directory(artifact_directory.parent)
        destination = artifact_directory / f'{envelope["envelope_hash"]}.json'
        if destination.exists():
            if destination.read_bytes() != canonical_json_bytes(envelope):
                raise IntegrityError("content-address collision")
            raise IntegrityError("artifact envelope already exists")
        _write_atomic(destination, canonical_json_bytes(envelope))
        self._append_event_unchecked(
            "artifact_committed",
            {"artifact_type": artifact_type, "envelope_hash": envelope["envelope_hash"]},
            allow_reserved=True,
        )
        self.verify()
        return deepcopy(envelope)

    def read_artifacts(self, artifact_type: str) -> list[dict]:
        self.verify()
        if not isinstance(artifact_type, str) or artifact_type not in _ARTIFACT_TYPES:
            raise IntegrityError("invalid artifact type")
        directory = self.session_root / "artifacts" / artifact_type
        if not directory.exists():
            return []
        return [_load_canonical_json(path) for path in sorted(directory.glob("*.json"))]
