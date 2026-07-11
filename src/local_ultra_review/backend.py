"""Synthetic and guarded worker backends for the V2 evaluation slice."""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Literal, Protocol

from .contracts import (
    ContractError,
    canonical_json_bytes,
    is_required_evidence_sentinel,
    load_schema,
    reject_worker_authority_fields,
    sha256_json,
    synthetic_attempt_assurance,
    validate_payload,
)
from .redaction import SensitiveMaterialError, assert_safe_sink


PROTOCOL_VERSION = "v2-worker-protocol-1"
FAKE_BACKEND_VERSION = "fake-backend-1"
RUN_MANIFEST_VERSION = "run-manifest-v1"
_CODEX_ADAPTER_VERSION = "codex-cli-guarded-1"
_PLACEHOLDER = re.compile(rb"\{\{[^{}]*\}\}")
_ALLOWED_PLACEHOLDERS = {
    b"{{TASK_ID}}",
    b"{{PACKET_HASH}}",
    b"{{CANDIDATE_HASH}}",
}
_USAGE_FIELDS = {
    "cached_input_tokens",
    "input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
    "total_tokens",
}
_ITEM_EVENT_TYPES = {"item.started", "item.completed"}
_ITEM_CONTENT_TYPES = {"agent_message", "reasoning"}
_DIRECT_TEXT_EVENT_TYPES = {"agent_message", "message", "reasoning"}
_TASK_IDENTITY_SHAPE = re.compile(
    r"(?<![A-Za-z0-9_])(?:reviewer|verifier)-[A-Za-z0-9._:/-]+"
)
_HASH_IDENTITY_SHAPE = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")

DISABLED_FEATURES = (
    "shell_tool",
    "unified_exec",
    "code_mode_host",
    "apps",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "computer_use",
    "plugins",
    "remote_plugin",
    "image_generation",
    "multi_agent",
    "goals",
    "workspace_dependencies",
    "tool_suggest",
    "tool_call_mcp_elicitation",
)
ENVIRONMENT_ALLOWLIST = ("PATH", "HOME", "CODEX_HOME", "LANG", "LC_ALL", "TERM")
_LAUNCH_POLICY = {
    "version": "codex-native-guarded-launch-1",
    "base_arguments": [
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
    ],
    "disabled_features": list(DISABLED_FEATURES),
    "dynamic_arguments": [
        "-C",
        "--model",
        "--output-schema",
        "--json",
        "--output-last-message",
        "-",
    ],
    "semantic_dispatch": "blocked_without_canonical_inventory_oracle",
}
_WORKER_ENVIRONMENT_POLICY = {
    "version": "empty-base-allowlist-1",
    "base_environment": "empty",
    "inherited_keys": list(ENVIRONMENT_ALLOWLIST),
    "adapter_set_keys": ["TMPDIR"],
    "environment_values_recorded": False,
}
LAUNCH_POLICY_SHA256 = sha256_json(_LAUNCH_POLICY)
WORKER_ENVIRONMENT_POLICY_SHA256 = sha256_json(_WORKER_ENVIRONMENT_POLICY)

_DESCENDANT_CANARY_SOURCE = """
import json
import os
import sys

expected_keys = json.loads(sys.argv[1])
raw_keys = sorted(os.environ.keys())
for key in tuple(os.environ):
    if key not in expected_keys:
        del os.environ[key]
print(json.dumps({
    "keys": sorted(os.environ.keys()),
    "raw_keys": raw_keys,
}, sort_keys=True, separators=(",", ":")))
"""
_PARENT_CANARY_SOURCE = f"""
import json
import os
import subprocess
import sys

expected_keys = json.loads(sys.argv[1])
raw_parent_keys = sorted(os.environ.keys())
for key in tuple(os.environ):
    if key not in expected_keys:
        del os.environ[key]
completed = subprocess.run(
    [
        sys.executable,
        "-I",
        "-c",
        {_DESCENDANT_CANARY_SOURCE!r},
        json.dumps(expected_keys, separators=(",", ":")),
    ],
    check=False,
    capture_output=True,
    text=True,
    shell=False,
)
descendant = json.loads(completed.stdout) if completed.returncode == 0 else {{}}
print(json.dumps({{
    "parent_keys": sorted(os.environ.keys()),
    "raw_parent_keys": raw_parent_keys,
    "descendant_keys": descendant.get("keys", []),
    "raw_descendant_keys": descendant.get("raw_keys", []),
    "descendant_return_code": completed.returncode,
}}, sort_keys=True, separators=(",", ":")))
"""


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


class WorkerProtocolError(RuntimeError):
    """Raised when worker evidence cannot be accepted as one complete attempt."""


class WorkerUnavailable(RuntimeError):
    """Raised when a worker cannot be dispatched under the selected policy."""

    def __init__(self, message: str, *, diagnostic: dict | None = None) -> None:
        super().__init__(message)
        self.diagnostic = diagnostic or {"status": "blocked", "reason": message}


class WorkerBackend(Protocol):
    @property
    def model(self) -> str: ...

    def readiness(self) -> dict: ...

    def semantic_identity(self) -> dict: ...

    def run(self, task: WorkerTask, attempt_dir: Path) -> WorkerAttempt: ...


class _FrozenDict(dict):
    """Private JSON-object snapshot that rejects later in-process mutation."""

    def _immutable(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("scripted attempt snapshot is immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable
    __ior__ = _immutable

    def __deepcopy__(self, memo: dict[int, object]) -> "_FrozenDict":
        del memo
        return self


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return _FrozenDict({key: _freeze_json(child) for key, child in value.items()})
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(_freeze_json(child) for child in value)
    return value


def _snapshot_attempt(value: object) -> object:
    copied = deepcopy(value)
    if not isinstance(copied, ScriptedAttempt):
        return copied
    return ScriptedAttempt(
        expected_role=copied.expected_role,
        raw_events=tuple(_freeze_json(event) for event in copied.raw_events),  # type: ignore[arg-type]
        last_message_template=bytes(copied.last_message_template),
        process_launch_id=copied.process_launch_id,
        return_code=copied.return_code,
        timed_out=copied.timed_out,
    )


def _numeric_usage(value: object) -> bool:
    return (
        isinstance(value, Mapping)
        and bool(value)
        and set(value).issubset(_USAGE_FIELDS)
        and all(
            isinstance(count, int) and not isinstance(count, bool) and count >= 0
            for count in value.values()
        )
    )


def _event_matches_harmless_contract(event: object) -> bool:
    if not isinstance(event, Mapping):
        return False
    event_type = event.get("type")
    if not isinstance(event_type, str):
        return False
    keys = set(event)
    if event_type == "thread.started":
        return (
            keys == {"type", "thread_id"}
            and isinstance(event.get("thread_id"), str)
            and bool(event["thread_id"].strip())
        )
    if event_type == "turn.started":
        return keys == {"type"}
    if event_type == "turn.completed":
        if keys == {"type"}:
            return True
        return keys == {"type", "usage"} and _numeric_usage(event.get("usage"))
    if event_type in _ITEM_EVENT_TYPES:
        if keys != {"type", "item"}:
            return False
        item = event.get("item")
        if not isinstance(item, Mapping) or set(item) not in (
            {"type"},
            {"type", "text"},
        ):
            return False
        if item.get("type") not in _ITEM_CONTENT_TYPES:
            return False
        return "text" not in item or isinstance(item.get("text"), str)
    if event_type in _DIRECT_TEXT_EVENT_TYPES:
        if keys not in ({"type"}, {"type", "text"}):
            return False
        return "text" not in event or isinstance(event.get("text"), str)
    if event_type == "usage":
        return "type" in keys and _numeric_usage(
            {key: value for key, value in event.items() if key != "type"}
        )
    return False


def _event_observes_tool_call(event: object) -> bool:
    return not _event_matches_harmless_contract(event)


def _thread_id_occurrences(value: object) -> list[object]:
    occurrences: list[object] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key == "thread_id":
                occurrences.append(child)
            occurrences.extend(_thread_id_occurrences(child))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            occurrences.extend(_thread_id_occurrences(child))
    return occurrences


def _json_without_duplicate_keys(raw: bytes) -> object:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise WorkerProtocolError("worker result is not UTF-8") from error
    if not text.strip():
        raise WorkerProtocolError("worker result is blank")
    if text.lstrip().startswith("```"):
        raise WorkerProtocolError("worker result must not be fenced")

    def pairs_hook(pairs: list[tuple[str, object]]) -> dict:
        value: dict[str, object] = {}
        for key, child in pairs:
            if key in value:
                raise WorkerProtocolError(f"worker result repeats JSON key: {key}")
            value[key] = child
        return value

    try:
        return json.loads(text, object_pairs_hook=pairs_hook)
    except WorkerProtocolError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise WorkerProtocolError("worker result is malformed or partial JSON") from error


def _schema_key(name: str) -> str:
    suffix = ".schema.json"
    return name[: -len(suffix)] if name.endswith(suffix) else name


def _validate_task(task: WorkerTask) -> None:
    if task.role not in {"reviewer", "verifier"}:
        raise WorkerProtocolError("worker task role is invalid")
    if (
        not isinstance(task.task_id, str)
        or not task.task_id
        or is_required_evidence_sentinel(task.task_id)
    ):
        raise WorkerProtocolError("worker task ID is missing")
    if not isinstance(task.packet, dict):
        raise WorkerProtocolError("worker packet must be an object")
    try:
        assert_safe_sink(task.task_id)
        assert_safe_sink(task.packet_hash)
        assert_safe_sink(task.packet)
        assert_safe_sink(task.prompt_text)
        assert_safe_sink(task.output_schema_name)
        computed_packet_hash = sha256_json(task.packet)
    except (ContractError, SensitiveMaterialError) as error:
        raise WorkerProtocolError("worker task is not safe canonical input") from error
    if task.packet_hash != computed_packet_hash:
        raise WorkerProtocolError("worker task packet hash mismatch")
    if not isinstance(task.timeout_seconds, int) or isinstance(task.timeout_seconds, bool):
        raise WorkerProtocolError("worker timeout must be a positive integer")
    if task.timeout_seconds <= 0:
        raise WorkerProtocolError("worker timeout must be a positive integer")
    if _schema_key(task.output_schema_name) != f"{task.role}-result":
        raise WorkerProtocolError("worker task role and output schema mismatch")


def _bind_template(template: bytes, task: WorkerTask) -> bytes:
    placeholders = set(_PLACEHOLDER.findall(template))
    unknown = placeholders - _ALLOWED_PLACEHOLDERS
    if unknown:
        raise WorkerProtocolError("scripted attempt contains an unknown placeholder")

    bindings = {
        b"{{TASK_ID}}": task.task_id.encode("utf-8"),
        b"{{PACKET_HASH}}": task.packet_hash.encode("ascii"),
    }
    if b"{{CANDIDATE_HASH}}" in placeholders:
        candidate_hash = task.packet.get("candidate_hash")
        if task.role != "verifier" or not isinstance(candidate_hash, str):
            raise WorkerProtocolError("candidate placeholder has no sealed verifier binding")
        bindings[b"{{CANDIDATE_HASH}}"] = candidate_hash.encode("ascii")

    bound = template
    for placeholder, replacement in bindings.items():
        bound = bound.replace(placeholder, replacement)
    if b"{{" in bound or b"}}" in bound:
        raise WorkerProtocolError("scripted attempt contains an unresolved placeholder")
    return bound


def _validate_unbound_template(template: bytes, role: str) -> dict:
    placeholders = set(_PLACEHOLDER.findall(template))
    unknown = placeholders - _ALLOWED_PLACEHOLDERS
    if unknown:
        raise WorkerProtocolError("scripted attempt contains an unknown placeholder")
    remainder = template
    for placeholder in _ALLOWED_PLACEHOLDERS:
        remainder = remainder.replace(placeholder, b"")
    if b"{{" in remainder or b"}}" in remainder:
        raise WorkerProtocolError("scripted attempt contains an unresolved placeholder")
    payload = _json_without_duplicate_keys(template)
    if not isinstance(payload, dict):
        raise WorkerProtocolError("scripted last-message template must be one JSON object")
    required = {
        "task_id": "{{TASK_ID}}",
        "packet_hash": "{{PACKET_HASH}}",
    }
    if role == "verifier":
        required["candidate_hash"] = "{{CANDIDATE_HASH}}"
    for field, placeholder in required.items():
        if payload.get(field) != placeholder:
            raise WorkerProtocolError(
                f"scripted attempt {field} must use its unbound adapter placeholder"
            )
    return payload


def _walk_identity_strings(value: object):
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str):
                yield key
            yield from _walk_identity_strings(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            yield from _walk_identity_strings(child)
    elif isinstance(value, str):
        yield value


def _reject_generic_identity_shapes(value: object) -> None:
    for text in _walk_identity_strings(value):
        if text in {"{{TASK_ID}}", "{{PACKET_HASH}}", "{{CANDIDATE_HASH}}"}:
            continue
        if _TASK_IDENTITY_SHAPE.search(text) or _HASH_IDENTITY_SHAPE.search(text):
            raise WorkerProtocolError(
                "scripted attempt embeds a task or packet identity outside its placeholder"
            )


def _reject_task_identity_feedback(
    payload: Mapping[str, object],
    raw_events: object,
    task: WorkerTask,
    *,
    scenario_id: str,
    process_launch_id: str,
) -> None:
    dedicated_fields = {"task_id", "packet_hash"}
    identities = [task.task_id, task.packet_hash]
    if task.role == "verifier":
        dedicated_fields.add("candidate_hash")
        candidate_hash = task.packet.get("candidate_hash")
        if isinstance(candidate_hash, str) and candidate_hash:
            identities.append(candidate_hash)
    non_identity_payload = {
        key: child for key, child in payload.items() if key not in dedicated_fields
    }
    for value in (
        scenario_id,
        process_launch_id,
        non_identity_payload,
        raw_events,
    ):
        for text in _walk_identity_strings(value):
            if any(identity in text for identity in identities):
                raise WorkerProtocolError(
                    "scripted attempt feeds the active task identity into non-identity evidence"
                )


def _validate_scripted_attempt_before_hash(attempt: object) -> ScriptedAttempt:
    if not isinstance(attempt, ScriptedAttempt):
        raise WorkerProtocolError("scripted attempt has an invalid type")
    try:
        assert_safe_sink(attempt.expected_role)
        assert_safe_sink(attempt.process_launch_id)
        assert_safe_sink(attempt.raw_events)
        assert_safe_sink(attempt.last_message_template)
    except SensitiveMaterialError as error:
        raise WorkerProtocolError("scripted attempt contains unsafe sensitive material") from error
    if attempt.expected_role not in {"reviewer", "verifier"}:
        raise WorkerProtocolError("scripted attempt expected role is invalid")
    if (
        not isinstance(attempt.process_launch_id, str)
        or not attempt.process_launch_id.strip()
        or is_required_evidence_sentinel(attempt.process_launch_id)
    ):
        raise WorkerProtocolError("scripted attempt has no process launch evidence")
    if not isinstance(attempt.raw_events, tuple) or any(
        not isinstance(event, dict) for event in attempt.raw_events
    ):
        raise WorkerProtocolError("scripted attempt events must be object records")
    if any(not _event_matches_harmless_contract(event) for event in attempt.raw_events):
        raise WorkerProtocolError("scripted attempt events violate the harmless contract")
    thread_ids = _thread_id_occurrences(attempt.raw_events)
    if (
        len(thread_ids) != 1
        or not isinstance(thread_ids[0], str)
        or is_required_evidence_sentinel(thread_ids[0])
    ):
        raise WorkerProtocolError("scripted attempt requires one real thread ID")
    if not isinstance(attempt.last_message_template, bytes):
        raise WorkerProtocolError("scripted last-message template must be bytes")
    if not isinstance(attempt.return_code, int) or isinstance(attempt.return_code, bool):
        raise WorkerProtocolError("scripted attempt return code is invalid")
    if not isinstance(attempt.timed_out, bool):
        raise WorkerProtocolError("scripted attempt timeout evidence is invalid")
    payload = _validate_unbound_template(
        attempt.last_message_template, attempt.expected_role
    )
    dedicated_fields = {"task_id", "packet_hash"}
    if attempt.expected_role == "verifier":
        dedicated_fields.add("candidate_hash")
    _reject_generic_identity_shapes(
        {key: child for key, child in payload.items() if key not in dedicated_fields}
    )
    _reject_generic_identity_shapes(attempt.raw_events)
    _reject_generic_identity_shapes(attempt.process_launch_id)
    return attempt


def _attempt_hash(attempt: ScriptedAttempt, bound_message: bytes) -> str:
    return sha256_json(
        {
            "expected_role": attempt.expected_role,
            "raw_events": attempt.raw_events,
            "last_message_base64": base64.b64encode(bound_message).decode("ascii"),
            "process_launch_id": attempt.process_launch_id,
            "return_code": attempt.return_code,
            "timed_out": attempt.timed_out,
        }
    )


def _task_hash(task: WorkerTask) -> str:
    return sha256_json(
        {
            "task_id": task.task_id,
            "role": task.role,
            "packet_hash": task.packet_hash,
            "prompt_text": task.prompt_text,
            "output_schema_name": task.output_schema_name,
            "timeout_seconds": task.timeout_seconds,
        }
    )


def worker_task_hash(task: WorkerTask) -> str:
    """Validate and hash one adapter-owned worker task."""

    _validate_task(task)
    return _task_hash(task)


_RUN_MANIFEST_BASE_FIELDS = {
    "adapter_version",
    "protocol_version",
    "run_manifest_version",
    "authority",
    "execution_backend",
    "task_id",
    "task_hash",
    "attempt_hash",
    "packet_hash",
    "process_launch_id",
    "thread_id",
    "synthetic_thread_id",
    "observed_event_count",
    "observed_tool_call_count",
}


def validate_run_manifest(value: object) -> None:
    """Validate exact persisted adapter evidence for one synthetic worker attempt."""

    try:
        assert_safe_sink(value)
    except SensitiveMaterialError as error:
        raise WorkerProtocolError("run manifest contains unsafe sensitive material") from error
    expected_assurance = synthetic_attempt_assurance()
    if not isinstance(value, Mapping) or set(value) != _RUN_MANIFEST_BASE_FIELDS | set(
        expected_assurance
    ):
        raise WorkerProtocolError("run manifest fields do not match the contract")
    if (
        value["adapter_version"] != FAKE_BACKEND_VERSION
        or value["protocol_version"] != PROTOCOL_VERSION
        or value["run_manifest_version"] != RUN_MANIFEST_VERSION
        or value["authority"] != "synthetic_evaluation"
        or value["execution_backend"] != "fake_evaluation"
    ):
        raise WorkerProtocolError("run manifest identity/version mismatch")
    for key in ("task_id", "process_launch_id", "thread_id", "synthetic_thread_id"):
        child = value[key]
        if (
            not isinstance(child, str)
            or not child.strip()
            or is_required_evidence_sentinel(child)
        ):
            raise WorkerProtocolError(f"run manifest {key} is invalid")
    if value["synthetic_thread_id"] != value["thread_id"]:
        raise WorkerProtocolError("run manifest synthetic/thread identity mismatch")
    for key in ("task_hash", "attempt_hash", "packet_hash"):
        if not isinstance(value[key], str) or re.fullmatch(r"[0-9a-f]{64}", value[key]) is None:
            raise WorkerProtocolError(f"run manifest {key} is invalid")
    for key in ("observed_event_count", "observed_tool_call_count"):
        if (
            not isinstance(value[key], int)
            or isinstance(value[key], bool)
            or value[key] < 0
        ):
            raise WorkerProtocolError(f"run manifest {key} is invalid")
    if value["observed_tool_call_count"] != 0:
        raise WorkerProtocolError("run manifest observed a forbidden tool call")
    if {key: value[key] for key in expected_assurance} != expected_assurance:
        raise WorkerProtocolError("run manifest assurance does not match the exact tuple")


def _accept_scripted_attempt(
    task: WorkerTask,
    attempt: ScriptedAttempt,
    *,
    scenario_id: str,
    seen_thread_ids: set[str],
    seen_process_launch_ids: set[str],
) -> WorkerAttempt:
    try:
        assert_safe_sink(scenario_id)
    except SensitiveMaterialError as error:
        raise WorkerProtocolError("fake scenario contains unsafe sensitive material") from error
    _reject_generic_identity_shapes(scenario_id)
    _validate_scripted_attempt_before_hash(attempt)
    _validate_task(task)
    unbound_payload = _json_without_duplicate_keys(attempt.last_message_template)
    if not isinstance(unbound_payload, dict):
        raise WorkerProtocolError("scripted last-message template must be one JSON object")
    _reject_task_identity_feedback(
        unbound_payload,
        attempt.raw_events,
        task,
        scenario_id=scenario_id,
        process_launch_id=attempt.process_launch_id,
    )
    if attempt.expected_role != task.role:
        raise WorkerProtocolError("scripted attempt role mismatch")
    if attempt.timed_out:
        raise WorkerProtocolError("scripted attempt timed out")
    if attempt.return_code != 0:
        raise WorkerProtocolError("scripted attempt returned a nonzero status")
    if attempt.process_launch_id in seen_process_launch_ids:
        raise WorkerProtocolError("scripted attempt reused a process launch ID")

    observed_tool_calls = sum(
        1 for event in attempt.raw_events if _event_observes_tool_call(event)
    )
    if observed_tool_calls:
        raise WorkerProtocolError("scripted attempt observed a forbidden tool call")

    thread_occurrences = _thread_id_occurrences(attempt.raw_events)
    if len(thread_occurrences) != 1:
        raise WorkerProtocolError("scripted attempt must contain exactly one thread ID")
    thread_id = thread_occurrences[0]
    if (
        not isinstance(thread_id, str)
        or not thread_id.strip()
        or is_required_evidence_sentinel(thread_id)
    ):
        raise WorkerProtocolError("scripted attempt thread ID is empty")
    if thread_id in seen_thread_ids:
        raise WorkerProtocolError("scripted attempt reused a thread ID")

    bound = _bind_template(attempt.last_message_template, task)
    try:
        assert_safe_sink(bound)
        payload = _json_without_duplicate_keys(bound)
        if not isinstance(payload, dict):
            raise WorkerProtocolError("worker result must be one JSON object")
        _reject_task_identity_feedback(
            payload,
            attempt.raw_events,
            task,
            scenario_id=scenario_id,
            process_launch_id=attempt.process_launch_id,
        )
        reject_worker_authority_fields(payload)
        validate_payload(task.output_schema_name, payload)
        assert_safe_sink(payload)
    except WorkerProtocolError:
        raise
    except (ContractError, SensitiveMaterialError) as error:
        raise WorkerProtocolError("worker result failed acceptance gates") from error

    if payload.get("task_id") != task.task_id:
        raise WorkerProtocolError("worker result task ID mismatch")
    if payload.get("packet_hash") != task.packet_hash:
        raise WorkerProtocolError("worker result packet hash mismatch")
    if task.role == "verifier":
        candidate_hash = task.packet.get("candidate_hash")
        if payload.get("candidate_hash") != candidate_hash:
            raise WorkerProtocolError("worker result candidate hash mismatch")

    try:
        bound_attempt_hash = _attempt_hash(attempt, bound)
        task_hash = _task_hash(task)
    except ContractError as error:
        raise WorkerProtocolError("scripted evidence is not canonical JSON") from error
    manifest = {
        "adapter_version": FAKE_BACKEND_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "run_manifest_version": RUN_MANIFEST_VERSION,
        "authority": "synthetic_evaluation",
        "execution_backend": "fake_evaluation",
        "task_id": task.task_id,
        "task_hash": task_hash,
        "attempt_hash": bound_attempt_hash,
        "packet_hash": task.packet_hash,
        "process_launch_id": attempt.process_launch_id,
        "thread_id": thread_id,
        "synthetic_thread_id": thread_id,
        "observed_event_count": len(attempt.raw_events),
        "observed_tool_call_count": 0,
        **synthetic_attempt_assurance(),
    }
    try:
        assert_safe_sink(manifest)
        validate_run_manifest(manifest)
    except SensitiveMaterialError as error:
        raise WorkerProtocolError("adapter manifest failed the safe-sink gate") from error

    seen_thread_ids.add(thread_id)
    seen_process_launch_ids.add(attempt.process_launch_id)
    return WorkerAttempt(payload, thread_id, attempt.process_launch_id, manifest)


class FakeBackend:
    """Deterministic protocol harness with permanently synthetic authority."""

    def __init__(
        self,
        *,
        scenario_id: str,
        attempts: Sequence[ScriptedAttempt],
        model: str = "synthetic-model",
    ) -> None:
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("scenario ID must be a nonempty string")
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a nonempty string")
        self._scenario_id = scenario_id
        self._model = model
        self._attempts = tuple(_snapshot_attempt(attempt) for attempt in tuple(attempts))
        self._next_attempt = 0
        self._seen_thread_ids: set[str] = set()
        self._seen_process_launch_ids: set[str] = set()

    @property
    def model(self) -> str:
        """Return the sealed model requested by this synthetic scenario."""

        return self._model

    def consumption_state(self) -> dict:
        """Return a fresh dispatch-accounting snapshot."""

        total = len(self._attempts)
        consumed = self._next_attempt
        return {
            "total_attempts": total,
            "consumed_attempts": consumed,
            "remaining_attempts": total - consumed,
        }

    def readiness(self) -> dict:
        state = self.consumption_state()
        pristine = state["consumed_attempts"] == 0
        valid = True
        try:
            assert_safe_sink(self._scenario_id)
            assert_safe_sink(self._model)
            _reject_generic_identity_shapes(self._scenario_id)
            for attempt in self._attempts:
                _validate_scripted_attempt_before_hash(attempt)
            roles = [attempt.expected_role for attempt in self._attempts]
            expected_roles = (
                []
                if not roles
                else ["reviewer", *(["verifier"] * (len(roles) - 1))]
            )
            if roles != expected_roles:
                valid = False
        except (AttributeError, WorkerProtocolError, SensitiveMaterialError):
            valid = False
        return {
            "ready": pristine and valid,
            "mode": "synthetic_evaluation_only",
            "authority": "synthetic_evaluation",
            "execution_backend": "fake_evaluation",
            "live_dispatch_authorized": False,
            "live_dispatch_blockers": [
                "fake_backend_has_no_live_authority",
                *([] if pristine else ["fake_backend_not_pristine"]),
                *([] if valid else ["fake_backend_scenario_invalid"]),
            ],
            "consumption_state": state,
        }

    def semantic_identity(self) -> dict:
        state = self.consumption_state()
        if state["consumed_attempts"] != 0:
            raise WorkerUnavailable(
                "fake backend is not pristine",
                diagnostic={
                    "status": "blocked",
                    "reason": "fake_backend_not_pristine",
                    "authority": "synthetic_evaluation",
                    "live_dispatch_authorized": False,
                    "consumption_state": state,
                },
            )
        templates = []
        try:
            assert_safe_sink(self._scenario_id)
            _reject_generic_identity_shapes(self._scenario_id)
            for attempt in self._attempts:
                _validate_scripted_attempt_before_hash(attempt)
                templates.append(
                    {
                        "expected_role": attempt.expected_role,
                        "raw_events": attempt.raw_events,
                        "last_message_template_base64": base64.b64encode(
                            attempt.last_message_template
                        ).decode("ascii"),
                        "process_launch_id": attempt.process_launch_id,
                        "return_code": attempt.return_code,
                        "timed_out": attempt.timed_out,
                    }
                )
            roles = [attempt.expected_role for attempt in self._attempts]
            expected_roles = (
                []
                if not roles
                else ["reviewer", *(["verifier"] * (len(roles) - 1))]
            )
            if roles != expected_roles:
                raise WorkerProtocolError(
                    "scripted attempts must be one reviewer followed by verifiers"
                )
            templates_hash = sha256_json(templates)
        except (AttributeError, ContractError, SensitiveMaterialError) as error:
            raise WorkerProtocolError("scripted attempt templates are unsafe or invalid") from error
        return {
            "backend": "fake_evaluation",
            "backend_version": FAKE_BACKEND_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "run_manifest_version": RUN_MANIFEST_VERSION,
            "scenario_id": self._scenario_id,
            "total_attempts": len(self._attempts),
            "expected_role_sequence": roles,
            "unbound_attempt_templates_sha256": templates_hash,
        }

    def run(self, task: WorkerTask, attempt_dir: Path) -> WorkerAttempt:
        del attempt_dir
        if self._next_attempt >= len(self._attempts):
            raise WorkerUnavailable(
                "no scripted attempt remains",
                diagnostic={
                    "status": "blocked",
                    "reason": "scripted_attempts_exhausted",
                    "authority": "synthetic_evaluation",
                    "live_dispatch_authorized": False,
                },
            )
        attempt = self._attempts[self._next_attempt]
        self._next_attempt += 1
        return _accept_scripted_attempt(
            task,
            attempt,
            scenario_id=self._scenario_id,
            seen_thread_ids=self._seen_thread_ids,
            seen_process_launch_ids=self._seen_process_launch_ids,
        )


def _run_process(
    argv: Sequence[str],
    *,
    environment: Mapping[str, str],
    cwd: Path,
    stdin: bytes | None = None,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[bytes]:
    """Construct a subprocess only for adapter-owned diagnostic programs."""

    return subprocess.run(
        list(argv),
        cwd=str(cwd),
        env=dict(environment),
        input=stdin,
        capture_output=True,
        check=False,
        shell=False,
        timeout=timeout_seconds,
    )


def _lexical_absolute_path(path: Path) -> Path:
    expanded = Path(path).expanduser()
    if ".." in expanded.parts:
        raise WorkerProtocolError("adapter path must not contain parent traversal")
    absolute = Path(os.path.abspath(os.fspath(expanded)))
    # macOS exposes root-owned compatibility aliases such as /var -> /private/var.
    # Canonicalize only that first, root-owned component; every caller-controlled
    # component below it is still opened one-by-one with O_NOFOLLOW.
    if len(absolute.parts) > 1:
        first_component = Path(absolute.anchor) / absolute.parts[1]
        try:
            first_metadata = os.lstat(first_component)
        except OSError:
            first_metadata = None
        if (
            first_metadata is not None
            and stat.S_ISLNK(first_metadata.st_mode)
            and first_metadata.st_uid == 0
        ):
            trusted_target = Path(os.path.realpath(first_component))
            absolute = trusted_target.joinpath(*absolute.parts[2:])
    return absolute


def _directory_open_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        raise WorkerProtocolError("no-follow directory traversal is unavailable")
    return (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )


def _open_directory_chain(path: Path) -> int:
    absolute = _lexical_absolute_path(path)
    flags = _directory_open_flags()
    try:
        descriptor = os.open(absolute.anchor, flags)
    except OSError as error:
        raise WorkerProtocolError("cannot open attempt path anchor safely") from error
    try:
        for component in absolute.parts[1:]:
            if component in {"", ".", ".."}:
                raise WorkerProtocolError("attempt path component is invalid")
            try:
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as error:
                raise WorkerProtocolError(
                    "attempt path contains a symlink or non-directory component"
                ) from error
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_child_directory(parent_descriptor: int, name: str) -> int:
    if not name or "/" in name or name in {".", ".."}:
        raise WorkerProtocolError("attempt child directory name is invalid")
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
    except FileExistsError:
        pass
    try:
        return os.open(name, _directory_open_flags(), dir_fd=parent_descriptor)
    except OSError as error:
        raise WorkerProtocolError(
            "attempt child path is a symlink or non-directory"
        ) from error


def _read_descriptor(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _materialize_exact_at(directory_descriptor: int, name: str, data: bytes) -> None:
    if not name or "/" in name or name in {".", ".."}:
        raise WorkerProtocolError("attempt materialization name is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise WorkerProtocolError("no-follow file materialization is unavailable")
    flags = os.O_RDWR | nofollow | getattr(os, "O_CLOEXEC", 0)
    created = False
    try:
        descriptor = os.open(
            name,
            flags | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_descriptor,
        )
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(name, flags, dir_fd=directory_descriptor)
        except OSError as error:
            raise WorkerProtocolError(
                f"attempt materialization destination is unsafe: {name}"
            ) from error
    except OSError as error:
        raise WorkerProtocolError(
            f"cannot reserve attempt materialization: {name}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise WorkerProtocolError(
                f"attempt materialization destination is not a private regular file: {name}"
            )
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise WorkerProtocolError(
                f"attempt materialization destination permissions are unsafe: {name}"
            )
        if not created:
            if _read_descriptor(descriptor) != data:
                raise WorkerProtocolError(f"attempt materialization conflicts at {name}")
            return
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise WorkerProtocolError("attempt materialization made no progress")
            offset += written
        os.fsync(descriptor)
        os.fsync(directory_descriptor)
    except Exception:
        if created:
            try:
                os.unlink(name, dir_fd=directory_descriptor)
                os.fsync(directory_descriptor)
            except OSError:
                pass
        raise
    finally:
        os.close(descriptor)


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _hash_nofollow_executable_object(path: Path) -> str:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise OSError("no-follow executable inspection is unavailable")
    path_metadata = os.lstat(path)
    if not stat.S_ISREG(path_metadata.st_mode):
        raise OSError("CLI binary is not a regular file")
    if not path_metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise OSError("CLI binary is not executable")
    descriptor = os.open(
        path,
        os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        descriptor_metadata = os.fstat(descriptor)
        if _stat_identity(descriptor_metadata) != _stat_identity(path_metadata):
            raise OSError("CLI binary changed before hashing")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        if _stat_identity(os.fstat(descriptor)) != _stat_identity(descriptor_metadata):
            raise OSError("CLI file object changed while hashing")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _utc_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp is not timezone-aware")
    return parsed.astimezone(timezone.utc)


class CodexCliBackend:
    """Host diagnostic adapter whose live semantic gate is permanently closed."""

    def __init__(
        self,
        *,
        codex_path: Path,
        model: str,
        qualification_record: Path,
        parent_environment: Mapping[str, str] | None = None,
    ) -> None:
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a nonempty sealed identifier")
        try:
            assert_safe_sink(model)
        except SensitiveMaterialError as error:
            raise ValueError("model identifier contains unsafe sensitive material") from error
        self._codex_path = _lexical_absolute_path(Path(codex_path))
        self._model = model
        self._qualification_record_path = Path(qualification_record).expanduser().resolve()
        source_environment = os.environ if parent_environment is None else parent_environment
        self._parent_environment = {
            str(key): str(value)
            for key, value in source_environment.items()
            if isinstance(key, str) and isinstance(value, str)
        }
        self._environment_preflight: dict | None = None
        self._cli_binary_sha256: str | None = None
        self._cli_binary_identity_scope = "unavailable"
        self._cli_version: str | None = None
        self._cli_diagnostic_state = "unavailable"
        self._inspect_cli()
        self._diagnostic_record_sha256: str | None = None
        self._qualification_state = "record_unavailable"
        self._load_qualification_record()

    @property
    def model(self) -> str:
        """Return the sealed diagnostic model identifier."""

        return self._model

    def _child_environment(self, tmpdir: Path) -> dict[str, str]:
        environment: dict[str, str] = {}
        for key in ENVIRONMENT_ALLOWLIST:
            if key in self._parent_environment:
                environment[key] = self._parent_environment[key]
        environment["TMPDIR"] = str(tmpdir.resolve())
        return environment

    @staticmethod
    def _environment_manifest(environment: Mapping[str, str]) -> dict:
        keys = sorted(environment)
        return {
            "base_environment": "empty",
            "inherited_key_allowlist": list(ENVIRONMENT_ALLOWLIST),
            "adapter_set_keys": ["TMPDIR"],
            "child_environment_keys": keys,
            "child_environment_keys_sha256": sha256_json(keys),
            "worker_environment_policy_sha256": WORKER_ENVIRONMENT_POLICY_SHA256,
            "environment_values_recorded": False,
        }

    def _inspect_cli(self) -> None:
        try:
            self._cli_binary_sha256 = _hash_nofollow_executable_object(
                self._codex_path
            )
            self._cli_binary_identity_scope = "unexecuted_nofollow_file_object"
            self._cli_version = None
            self._cli_diagnostic_state = "object_bound_version_probe_unavailable"
        except OSError:
            self._cli_diagnostic_state = "binary_inspection_failed"

    def _load_qualification_record(self) -> None:
        try:
            raw = self._qualification_record_path.read_bytes()
            assert_safe_sink(raw)
            self._diagnostic_record_sha256 = hashlib.sha256(raw).hexdigest()
            payload = _json_without_duplicate_keys(raw)
            if not isinstance(payload, dict):
                raise ContractError("qualification record must be an object")
            validate_payload("qualification-record", payload)
        except (OSError, ContractError, SensitiveMaterialError, WorkerProtocolError):
            self._qualification_state = "invalid_record"
            return

        now = datetime.now(timezone.utc)
        try:
            qualified_at = _utc_timestamp(payload["qualified_at"])
            expires_at = _utc_timestamp(payload["expires_at"])
        except (KeyError, TypeError, ValueError):
            self._qualification_state = "invalid_record"
            return
        if qualified_at > now or expires_at <= now:
            self._qualification_state = "expired_record"
            return
        expected = {
            "cli_binary_sha256": self._cli_binary_sha256,
            "launch_policy_sha256": LAUNCH_POLICY_SHA256,
            "worker_environment_policy_sha256": WORKER_ENVIRONMENT_POLICY_SHA256,
        }
        if any(payload.get(key) != value for key, value in expected.items()):
            self._qualification_state = "diagnostic_mismatch"
            return
        self._qualification_state = (
            "not_evaluable_without_object_bound_version_probe"
        )

    def _qualification_blockers(self) -> list[str]:
        blocker_by_state = {
            "record_unavailable": "qualification_record_unavailable",
            "invalid_record": "qualification_record_invalid",
            "expired_record": "qualification_record_expired",
            "diagnostic_mismatch": "qualification_record_mismatch",
            "not_evaluable_without_object_bound_version_probe": (
                "object_bound_version_probe_unavailable"
            ),
        }
        blocker = blocker_by_state.get(self._qualification_state)
        return [blocker] if blocker else []

    def readiness(self) -> dict:
        blockers = [
            "canonical_inventory_oracle_unavailable",
            "object_bound_version_probe_unavailable",
            *self._qualification_blockers(),
        ]
        if self._cli_diagnostic_state == "binary_inspection_failed":
            blockers.append("cli_binary_inspection_failed")
        blockers = sorted(set(blockers))
        environment_preflight = self._environment_preflight or {
            "status": "not_run",
            "evidence_owner": "adapter_host",
            "semantic_invocation": False,
            "worker_environment_policy_sha256": WORKER_ENVIRONMENT_POLICY_SHA256,
            "environment_values_recorded": False,
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
            "qualification_state": self._qualification_state,
            "cli_version": None,
            "version_probe_executed": False,
            "object_bound_executable_binding": "unavailable",
            "cli_binary_identity_scope": self._cli_binary_identity_scope,
            "environment_preflight": environment_preflight,
            "live_dispatch_authorized": False,
            "live_dispatch_blockers": blockers,
        }

    def semantic_identity(self) -> dict:
        inventory = {
            "inventory_scope": "known_observed_partial",
            "inventory_source": "unavailable",
            "residual_tool_surface": "unknown",
            "residual_tool_inventory": "unavailable",
            "canonical_inventory_oracle": "unavailable",
            "known_observed_exposures": [],
            "known_observed_exposures_sha256": None,
        }
        return {
            "backend": "codex_cli_guarded",
            "adapter_version": _CODEX_ADAPTER_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "model": self._model,
            "cli_version": self._cli_version,
            "cli_binary_sha256": self._cli_binary_sha256,
            "cli_diagnostic_state": self._cli_diagnostic_state,
            "version_probe_executed": False,
            "object_bound_executable_binding": "unavailable",
            "cli_binary_identity_scope": self._cli_binary_identity_scope,
            "launch_policy_sha256": LAUNCH_POLICY_SHA256,
            "worker_environment_policy_sha256": WORKER_ENVIRONMENT_POLICY_SHA256,
            "diagnostic_record_sha256": self._diagnostic_record_sha256,
            "qualification_state": self._qualification_state,
            "inventory": inventory,
            "live_dispatch_authorized": False,
        }

    def build_launch_spec(self, task: WorkerTask, attempt_dir: Path) -> dict:
        _validate_task(task)
        attempt_root = _lexical_absolute_path(Path(attempt_dir))
        packet_dir = attempt_root / "packet"
        scratch_dir = attempt_root / "scratch"
        tmpdir = scratch_dir / "tmp"

        try:
            schema = load_schema(task.output_schema_name)
            packet_bytes = canonical_json_bytes(task.packet)
            schema_bytes = canonical_json_bytes(schema)
            assert_safe_sink(packet_bytes)
        except (ContractError, SensitiveMaterialError) as error:
            raise WorkerProtocolError("cannot materialize worker task inputs") from error
        packet_path = packet_dir / "packet.json"
        schema_path = scratch_dir / "output-schema.json"
        result_path = scratch_dir / "result.json"
        descriptors: list[int] = []
        try:
            attempt_descriptor = _open_directory_chain(attempt_root)
            descriptors.append(attempt_descriptor)
            packet_descriptor = _open_child_directory(attempt_descriptor, "packet")
            descriptors.append(packet_descriptor)
            scratch_descriptor = _open_child_directory(attempt_descriptor, "scratch")
            descriptors.append(scratch_descriptor)
            tmp_descriptor = _open_child_directory(scratch_descriptor, "tmp")
            descriptors.append(tmp_descriptor)
            _materialize_exact_at(packet_descriptor, "packet.json", packet_bytes)
            _materialize_exact_at(scratch_descriptor, "output-schema.json", schema_bytes)
            _materialize_exact_at(scratch_descriptor, "result.json", b"")
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

        environment = self._child_environment(tmpdir)
        argv = [
            str(self._codex_path),
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
            argv.extend(["--disable", feature])
        argv.extend(
            [
                "-C",
                str(packet_dir),
                "--model",
                self._model,
                "--output-schema",
                str(schema_path),
                "--json",
                "--output-last-message",
                str(result_path),
                "-",
            ]
        )
        return {
            "argv": argv,
            "stdin": task.prompt_text,
            "environment": environment,
            "environment_manifest": self._environment_manifest(environment),
            "packet_path": str(packet_path),
            "schema_path": str(schema_path),
            "result_path": str(result_path),
            "semantic_dispatch_authorized": False,
        }

    def preflight_worker_environment(self, scratch_dir: Path) -> dict:
        scratch = Path(scratch_dir).expanduser().resolve()
        scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmpdir = scratch / "tmp"
        tmpdir.mkdir(mode=0o700, exist_ok=True)
        environment = self._child_environment(tmpdir)
        expected_keys = sorted(environment)
        parent_keys: list[str] = []
        raw_parent_keys: list[str] = []
        descendant_keys: list[str] = []
        raw_descendant_keys: list[str] = []
        error_code: str | None = None
        descendant_return_code: int | None = None
        try:
            completed = _run_process(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    _PARENT_CANARY_SOURCE,
                    json.dumps(expected_keys, separators=(",", ":")),
                ],
                environment=environment,
                cwd=scratch,
                timeout_seconds=10,
            )
            if completed.returncode != 0:
                error_code = "canary_nonzero"
            else:
                observed = json.loads(completed.stdout.decode("utf-8"))
                if not isinstance(observed, dict):
                    raise ValueError("canary result is not an object")
                parent_keys = observed.get("parent_keys", [])
                raw_parent_keys = observed.get("raw_parent_keys", [])
                descendant_keys = observed.get("descendant_keys", [])
                raw_descendant_keys = observed.get("raw_descendant_keys", [])
                descendant_return_code = observed.get("descendant_return_code")
                if not (
                    isinstance(parent_keys, list)
                    and all(isinstance(key, str) for key in parent_keys)
                    and isinstance(raw_parent_keys, list)
                    and all(isinstance(key, str) for key in raw_parent_keys)
                    and isinstance(descendant_keys, list)
                    and all(isinstance(key, str) for key in descendant_keys)
                    and isinstance(raw_descendant_keys, list)
                    and all(isinstance(key, str) for key in raw_descendant_keys)
                    and isinstance(descendant_return_code, int)
                ):
                    raise ValueError("canary result fields are invalid")
        except subprocess.TimeoutExpired:
            error_code = "canary_timeout"
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            error_code = "canary_invalid_result"

        forbidden_parent_keys = set(self._parent_environment) - set(
            ENVIRONMENT_ALLOWLIST
        ) - {"TMPDIR"}
        nonallowlisted_excluded = not bool(
            forbidden_parent_keys & (set(raw_parent_keys) | set(raw_descendant_keys))
        )
        host_runtime_added_keys = sorted(
            (set(raw_parent_keys) | set(raw_descendant_keys)) - set(expected_keys)
        )
        descendant_matched = (
            descendant_return_code == 0
            and parent_keys == expected_keys
            and descendant_keys == expected_keys
        )
        passed = (
            error_code is None
            and parent_keys == expected_keys
            and nonallowlisted_excluded
            and descendant_matched
        )
        evidence = {
            "status": "passed" if passed else "failed",
            "evidence_owner": "adapter_host",
            "diagnostic_kind": "trusted_worker_environment_canary",
            "semantic_invocation": False,
            "target_execution": "not_requested",
            "base_environment": "empty",
            "child_environment_keys": parent_keys,
            "descendant_environment_keys": descendant_keys,
            "host_runtime_added_keys": host_runtime_added_keys,
            "child_environment_keys_sha256": sha256_json(parent_keys),
            "worker_environment_policy_sha256": WORKER_ENVIRONMENT_POLICY_SHA256,
            "parent_nonallowlisted_keys_excluded": nonallowlisted_excluded,
            "descendant_inheritance_matched": descendant_matched,
            "environment_values_recorded": False,
            "error_code": error_code,
        }
        try:
            assert_safe_sink(evidence)
        except SensitiveMaterialError as error:
            raise WorkerUnavailable("environment preflight evidence was unsafe") from error
        self._environment_preflight = evidence
        return evidence

    def run(self, task: WorkerTask, attempt_dir: Path) -> WorkerAttempt:
        del task, attempt_dir
        readiness = self.readiness()
        preflight_state = readiness["environment_preflight"]["status"]
        diagnostic = {
            "status": "blocked",
            "reason": "canonical_inventory_oracle_unavailable",
            "profile": "codex_native_guarded",
            "worker_boundary": "guarded_unconfined",
            "hard_worker_confinement": "not_provided",
            "packet_only_read": "not_guaranteed",
            "residual_tool_surface": "unknown",
            "residual_tool_inventory": "unavailable",
            "accepted_tool_calls": "not_applicable_no_dispatch",
            "telemetry_scope": "not_applicable_no_dispatch",
            "worker_child_environment": (
                "allowlist_preflight_passed" if preflight_state == "passed" else "not_verified"
            ),
            "filesystem_write_mitigation": "not_verified",
            "nested_web_search": "not_verified",
            "broader_network_denial": "not_guaranteed",
            "connector_github_denial": "not_guaranteed",
            "ambient_secret_non_access": "not_guaranteed",
            "backend_stateless_attestation": "unavailable",
            "target_execution": "not_requested",
            "qualification_state": self._qualification_state,
            "cli_version": None,
            "version_probe_executed": False,
            "object_bound_executable_binding": "unavailable",
            "cli_binary_identity_scope": self._cli_binary_identity_scope,
            "launch_policy_sha256": LAUNCH_POLICY_SHA256,
            "worker_environment_policy_sha256": WORKER_ENVIRONMENT_POLICY_SHA256,
            "canonical_inventory_oracle": "unavailable",
            "live_dispatch_authorized": False,
            "live_dispatch_blockers": readiness["live_dispatch_blockers"],
            "semantic_subprocess_launched": False,
        }
        raise WorkerUnavailable(
            "live Codex semantic dispatch is blocked: canonical inventory oracle unavailable",
            diagnostic=diagnostic,
        )
