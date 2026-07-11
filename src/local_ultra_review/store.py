"""Fail-closed, content-addressed artifact storage for the V2 slice."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import uuid

from .contracts import SCHEMA_VERSION, canonical_json_bytes, sha256_json
from .redaction import assert_safe_sink


class IntegrityError(RuntimeError):
    """Raised when canonical session state is missing, torn, or tampered."""


_HASH = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_TYPE = re.compile(r"^[a-z][a-z0-9_]*$")
_ZERO_HASH = "0" * 64
_PLAN_FIELDS = {
    "schema_version",
    "session_id",
    "session_root",
    "created_at",
    "review_identity_hash",
    "target_identity_hash",
    "plan_integrity_hash",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


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
    _validate_hash(plan.get("review_identity_hash"), "review identity hash")
    _validate_hash(plan.get("target_identity_hash"), "target identity hash")
    return provided_hash


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
            os.rename(staging, final)
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
                if not isinstance(artifact_type, str) or not _ARTIFACT_TYPE.fullmatch(artifact_type):
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
                    or not _ARTIFACT_TYPE.fullmatch(directory.name)
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
        if not self.session_root.is_dir():
            raise IntegrityError("session root is missing")
        plan = self._plan
        _validate_plan(plan, self.session_root)
        _records, committed = self._verify_ledger(plan)

        observed: set[tuple[str, str]] = set()
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
            envelope_hash = _validate_hash(envelope.get("envelope_hash"), "envelope hash")
            if path.stem != envelope_hash:
                raise IntegrityError("artifact filename/hash mismatch")
            core_envelope = {key: value for key, value in envelope.items() if key != "envelope_hash"}
            if sha256_json(core_envelope) != envelope_hash:
                raise IntegrityError("artifact envelope hash mismatch")
            if envelope.get("payload_hash") != sha256_json(envelope.get("payload")):
                raise IntegrityError("artifact payload hash mismatch")
            if (
                envelope.get("schema_version") != SCHEMA_VERSION
                or envelope.get("session_id") != plan["session_id"]
                or envelope.get("plan_integrity_hash") != plan["plan_integrity_hash"]
                or envelope.get("review_identity_hash") != plan["review_identity_hash"]
            ):
                raise IntegrityError("artifact identity mismatch")
            artifact_type = envelope.get("artifact_type")
            if artifact_type != path.parent.name:
                raise IntegrityError("artifact type/path mismatch")
            artifact_identity = (artifact_type, envelope_hash)
            if artifact_identity in observed:
                raise IntegrityError("duplicate artifact envelope")
            observed.add(artifact_identity)
        if observed != committed:
            raise IntegrityError("artifact files and commit ledger disagree")

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
            with os.fdopen(descriptor, "ab", closefd=False) as handle:
                handle.write(canonical_json_bytes(record))
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)
        _fsync_directory(self.session_root)
        return record

    def append_event(self, event_type: str, payload: dict) -> dict:
        self.verify()
        record = self._append_event_unchecked(event_type, payload)
        self.verify()
        return record

    def write_artifact(self, artifact_type: str, payload: dict, producer: dict) -> dict:
        self.verify()
        if not isinstance(artifact_type, str) or not _ARTIFACT_TYPE.fullmatch(artifact_type):
            raise IntegrityError("invalid artifact type")
        if not isinstance(payload, dict) or not isinstance(producer, dict):
            raise IntegrityError("payload and producer must be objects")
        assert_safe_sink(payload)
        assert_safe_sink(producer)
        required_producer = {
            "task_id",
            "attempt_id",
            "thread_id",
            "process_launch_id",
            "input_hashes",
        }
        if set(producer) != required_producer:
            raise IntegrityError("producer fields do not match contract")
        for key in required_producer - {"input_hashes"}:
            if not isinstance(producer[key], str) or not producer[key]:
                raise IntegrityError(f"invalid producer {key}")
        input_hashes = producer["input_hashes"]
        if (
            not isinstance(input_hashes, list)
            or input_hashes != sorted(set(input_hashes))
            or any(not isinstance(value, str) or not _HASH.fullmatch(value) for value in input_hashes)
        ):
            raise IntegrityError("producer input hashes must be sorted unique SHA-256 values")
        plan = self._plan
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
        if not isinstance(artifact_type, str) or not _ARTIFACT_TYPE.fullmatch(artifact_type):
            raise IntegrityError("invalid artifact type")
        directory = self.session_root / "artifacts" / artifact_type
        if not directory.exists():
            return []
        return [_load_canonical_json(path) for path in sorted(directory.glob("*.json"))]
