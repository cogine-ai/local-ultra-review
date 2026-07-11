"""Synthetic and guarded worker backends for the V2 evaluation slice."""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Literal, Protocol

from .contracts import (
    ContractError,
    canonical_json_bytes,
    load_schema,
    reject_worker_authority_fields,
    sha256_json,
    validate_payload,
)
from .redaction import SensitiveMaterialError, assert_safe_sink


_PROTOCOL_VERSION = "v2-worker-protocol-1"
_FAKE_BACKEND_VERSION = "fake-backend-1"
_CODEX_ADAPTER_VERSION = "codex-cli-guarded-1"
_PLACEHOLDER = re.compile(rb"\{\{[^{}]*\}\}")
_ALLOWED_PLACEHOLDERS = {
    b"{{TASK_ID}}",
    b"{{PACKET_HASH}}",
    b"{{CANDIDATE_HASH}}",
}
_EVENT_MARKER_KEYS = {
    "type",
    "name",
    "tool",
    "tool_name",
    "function",
    "function_name",
    "method",
}
_STRUCTURAL_TOOL_KEYS = {
    "apply_patch",
    "command",
    "function",
    "mcp",
    "tool",
    "tool_name",
}
_EXACT_TOOL_MARKERS = {
    "apply_patch",
    "browser_use",
    "code_mode_host",
    "collaboration",
    "computer_use",
    "exec_command",
    "function_call",
    "image_generation",
    "mcp_call",
    "remote_plugin",
    "shell_tool",
    "tool_call",
    "unified_exec",
    "view_image",
}

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
    def readiness(self) -> dict: ...

    def semantic_identity(self) -> dict: ...

    def run(self, task: WorkerTask, attempt_dir: Path) -> WorkerAttempt: ...


def _normalized_marker(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _marker_is_tool_call(marker: str) -> bool:
    if marker in _EXACT_TOOL_MARKERS:
        return True
    return (
        marker.startswith(("collaboration_", "command_", "function_", "mcp_", "tool_"))
        or marker.endswith(("_command", "_function_call", "_mcp_call", "_tool_call"))
        or "apply_patch" in marker
    )


def _event_observes_tool_call(event: object) -> bool:
    if isinstance(event, Mapping):
        for key, value in event.items():
            normalized_key = _normalized_marker(str(key))
            if normalized_key in _STRUCTURAL_TOOL_KEYS or (
                _marker_is_tool_call(normalized_key)
                and normalized_key not in _EVENT_MARKER_KEYS
            ):
                return True
            if (
                normalized_key in _EVENT_MARKER_KEYS
                and isinstance(value, str)
                and _marker_is_tool_call(_normalized_marker(value))
            ):
                return True
            if _event_observes_tool_call(value):
                return True
    elif isinstance(event, Sequence) and not isinstance(event, (str, bytes, bytearray)):
        return any(_event_observes_tool_call(item) for item in event)
    return False


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
    if not isinstance(task.task_id, str) or not task.task_id:
        raise WorkerProtocolError("worker task ID is missing")
    if not isinstance(task.packet, dict):
        raise WorkerProtocolError("worker packet must be an object")
    try:
        assert_safe_sink(task.packet)
        assert_safe_sink(task.prompt_text)
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
    if not isinstance(template, bytes):
        raise WorkerProtocolError("scripted last-message template must be bytes")
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


def _accept_scripted_attempt(
    task: WorkerTask,
    attempt: ScriptedAttempt,
    *,
    seen_thread_ids: set[str],
    seen_process_launch_ids: set[str],
) -> WorkerAttempt:
    _validate_task(task)
    if attempt.expected_role != task.role:
        raise WorkerProtocolError("scripted attempt role mismatch")
    if attempt.timed_out:
        raise WorkerProtocolError("scripted attempt timed out")
    if attempt.return_code != 0:
        raise WorkerProtocolError("scripted attempt returned a nonzero status")
    if not isinstance(attempt.process_launch_id, str) or not attempt.process_launch_id.strip():
        raise WorkerProtocolError("scripted attempt has no process launch evidence")
    if attempt.process_launch_id in seen_process_launch_ids:
        raise WorkerProtocolError("scripted attempt reused a process launch ID")
    if not isinstance(attempt.raw_events, tuple) or any(
        not isinstance(event, dict) for event in attempt.raw_events
    ):
        raise WorkerProtocolError("scripted attempt events must be object records")

    try:
        assert_safe_sink(attempt.raw_events)
        assert_safe_sink(attempt.last_message_template)
    except SensitiveMaterialError as error:
        raise WorkerProtocolError("scripted attempt contains unsafe sensitive material") from error

    observed_tool_calls = sum(
        1 for event in attempt.raw_events if _event_observes_tool_call(event)
    )
    if observed_tool_calls:
        raise WorkerProtocolError("scripted attempt observed a forbidden tool call")

    thread_occurrences = _thread_id_occurrences(attempt.raw_events)
    if len(thread_occurrences) != 1:
        raise WorkerProtocolError("scripted attempt must contain exactly one thread ID")
    thread_id = thread_occurrences[0]
    if not isinstance(thread_id, str) or not thread_id.strip():
        raise WorkerProtocolError("scripted attempt thread ID is empty")
    if thread_id in seen_thread_ids:
        raise WorkerProtocolError("scripted attempt reused a thread ID")

    bound = _bind_template(attempt.last_message_template, task)
    try:
        assert_safe_sink(bound)
        payload = _json_without_duplicate_keys(bound)
        if not isinstance(payload, dict):
            raise WorkerProtocolError("worker result must be one JSON object")
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
        "adapter_version": _FAKE_BACKEND_VERSION,
        "protocol_version": _PROTOCOL_VERSION,
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
        "worker_profile": "codex_native_guarded",
        "worker_boundary": "guarded_unconfined",
        "hard_worker_confinement": "not_provided",
        "input_discipline": "adapter_packet_minimized",
        "packet_only_read": "not_guaranteed",
        "residual_tool_surface": "unknown",
        "residual_tool_inventory": "unavailable",
        "accepted_tool_calls": "none_observed",
        "telemetry_scope": "observed_events_only",
        "worker_child_environment": "not_verified",
        "filesystem_write_mitigation": "not_verified",
        "nested_web_search": "not_verified",
        "broader_network_denial": "not_guaranteed",
        "connector_github_denial": "not_guaranteed",
        "ambient_secret_non_access": "not_guaranteed",
        "context_lineage": "fresh_process_inferred",
        "backend_stateless_attestation": "unavailable",
        "target_execution": "not_requested",
    }
    try:
        assert_safe_sink(manifest)
    except SensitiveMaterialError as error:
        raise WorkerProtocolError("adapter manifest failed the safe-sink gate") from error

    seen_thread_ids.add(thread_id)
    seen_process_launch_ids.add(attempt.process_launch_id)
    return WorkerAttempt(payload, thread_id, attempt.process_launch_id, manifest)


class FakeBackend:
    """Deterministic protocol harness with permanently synthetic authority."""

    def __init__(self, *, scenario_id: str, attempts: Sequence[ScriptedAttempt]) -> None:
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("scenario ID must be a nonempty string")
        self._scenario_id = scenario_id
        self._attempts = tuple(attempts)
        self._next_attempt = 0
        self._seen_thread_ids: set[str] = set()
        self._seen_process_launch_ids: set[str] = set()

    def readiness(self) -> dict:
        return {
            "ready": True,
            "mode": "synthetic_evaluation_only",
            "authority": "synthetic_evaluation",
            "execution_backend": "fake_evaluation",
            "live_dispatch_authorized": False,
            "live_dispatch_blockers": ["fake_backend_has_no_live_authority"],
        }

    def semantic_identity(self) -> dict:
        templates = []
        try:
            assert_safe_sink(self._scenario_id)
            for attempt in self._attempts:
                assert_safe_sink(attempt.raw_events)
                assert_safe_sink(attempt.last_message_template)
                assert_safe_sink(attempt.process_launch_id)
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
            templates_hash = sha256_json(templates)
        except (AttributeError, ContractError, SensitiveMaterialError) as error:
            raise WorkerProtocolError("scripted attempt templates are unsafe or invalid") from error
        return {
            "backend": "fake_evaluation",
            "backend_version": _FAKE_BACKEND_VERSION,
            "protocol_version": _PROTOCOL_VERSION,
            "scenario_id": self._scenario_id,
            "expected_role_sequence": [
                attempt.expected_role for attempt in self._attempts
            ],
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


def _materialize_exact(path: Path, data: bytes) -> None:
    if path.exists():
        if not path.is_file() or path.is_symlink() or path.read_bytes() != data:
            raise WorkerProtocolError(f"attempt materialization conflicts at {path.name}")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise WorkerProtocolError("attempt materialization made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
        self._codex_path = Path(codex_path).expanduser().resolve()
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
        self._cli_version: str | None = None
        self._cli_diagnostic_state = "unavailable"
        self._inspect_cli()
        self._diagnostic_record_sha256: str | None = None
        self._qualification_payload: dict | None = None
        self._qualification_state = "record_unavailable"
        self._load_qualification_record()

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
            if not self._codex_path.is_file() or not os.access(self._codex_path, os.X_OK):
                self._cli_diagnostic_state = "binary_unavailable"
                return
            self._cli_binary_sha256 = hashlib.sha256(
                self._codex_path.read_bytes()
            ).hexdigest()
            with tempfile.TemporaryDirectory(prefix="local-ultra-review-codex-version-") as root:
                scratch = Path(root).resolve()
                tmpdir = scratch / "tmp"
                tmpdir.mkdir(mode=0o700)
                completed = _run_process(
                    [str(self._codex_path), "--version"],
                    environment=self._child_environment(tmpdir),
                    cwd=scratch,
                    timeout_seconds=10,
                )
            if completed.returncode != 0:
                self._cli_diagnostic_state = "version_probe_nonzero"
                return
            raw_version = completed.stdout if completed.stdout.strip() else completed.stderr
            version = raw_version.decode("utf-8").strip()
            if not version or "\n" in version:
                self._cli_diagnostic_state = "version_probe_invalid"
                return
            assert_safe_sink(version)
            self._cli_version = version
            self._cli_diagnostic_state = "validated"
        except subprocess.TimeoutExpired:
            self._cli_diagnostic_state = "version_probe_timeout"
        except (OSError, UnicodeDecodeError, SensitiveMaterialError):
            self._cli_diagnostic_state = "version_probe_failed"

    def _load_qualification_record(self) -> None:
        try:
            raw = self._qualification_record_path.read_bytes()
            assert_safe_sink(raw)
            self._diagnostic_record_sha256 = hashlib.sha256(raw).hexdigest()
            payload = _json_without_duplicate_keys(raw)
            if not isinstance(payload, dict):
                raise ContractError("qualification record must be an object")
            validate_payload("qualification-record", payload)
            self._qualification_payload = payload
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
            "cli_version": self._cli_version,
            "cli_binary_sha256": self._cli_binary_sha256,
            "launch_policy_sha256": LAUNCH_POLICY_SHA256,
            "worker_environment_policy_sha256": WORKER_ENVIRONMENT_POLICY_SHA256,
        }
        if self._cli_diagnostic_state != "validated" or any(
            payload.get(key) != value for key, value in expected.items()
        ):
            self._qualification_state = "diagnostic_mismatch"
            return
        self._qualification_state = "valid_diagnostic"

    def _qualification_blockers(self) -> list[str]:
        blocker_by_state = {
            "record_unavailable": "qualification_record_unavailable",
            "invalid_record": "qualification_record_invalid",
            "expired_record": "qualification_record_expired",
            "diagnostic_mismatch": "qualification_record_mismatch",
        }
        blocker = blocker_by_state.get(self._qualification_state)
        return [blocker] if blocker else []

    def readiness(self) -> dict:
        blockers = [
            "canonical_inventory_oracle_unavailable",
            *self._qualification_blockers(),
        ]
        if self._cli_diagnostic_state != "validated":
            blockers.append("cli_diagnostic_unavailable")
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
            "diagnostic_ready": self._cli_diagnostic_state == "validated",
            "profile": "codex_native_guarded",
            "worker_boundary": "guarded_unconfined",
            "hard_worker_confinement": "not_provided",
            "canonical_inventory_oracle": "unavailable",
            "inventory_scope": "known_observed_partial",
            "residual_tool_surface": "unknown",
            "residual_tool_inventory": "unavailable",
            "qualification_state": self._qualification_state,
            "environment_preflight": environment_preflight,
            "live_dispatch_authorized": False,
            "live_dispatch_blockers": blockers,
        }

    def semantic_identity(self) -> dict:
        exposures: list[str] = []
        if self._qualification_payload is not None:
            observed = self._qualification_payload.get("known_observed_exposures")
            if isinstance(observed, list) and all(isinstance(item, str) for item in observed):
                exposures = list(observed)
        inventory = {
            "inventory_scope": "known_observed_partial",
            "residual_tool_surface": "unknown",
            "residual_tool_inventory": "unavailable",
            "canonical_inventory_oracle": "unavailable",
            "known_observed_exposures": exposures,
            "known_observed_exposures_sha256": sha256_json(exposures),
        }
        return {
            "backend": "codex_cli_guarded",
            "adapter_version": _CODEX_ADAPTER_VERSION,
            "protocol_version": _PROTOCOL_VERSION,
            "model": self._model,
            "cli_version": self._cli_version,
            "cli_binary_sha256": self._cli_binary_sha256,
            "cli_diagnostic_state": self._cli_diagnostic_state,
            "launch_policy_sha256": LAUNCH_POLICY_SHA256,
            "worker_environment_policy_sha256": WORKER_ENVIRONMENT_POLICY_SHA256,
            "diagnostic_record_sha256": self._diagnostic_record_sha256,
            "qualification_state": self._qualification_state,
            "inventory": inventory,
            "live_dispatch_authorized": False,
        }

    def build_launch_spec(self, task: WorkerTask, attempt_dir: Path) -> dict:
        _validate_task(task)
        attempt_root = Path(attempt_dir).expanduser().resolve()
        packet_dir = attempt_root / "packet"
        scratch_dir = attempt_root / "scratch"
        tmpdir = scratch_dir / "tmp"
        for directory in (attempt_root, packet_dir, scratch_dir, tmpdir):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not directory.is_dir() or directory.is_symlink():
                raise WorkerProtocolError("attempt path is not a trusted directory")

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
        _materialize_exact(packet_path, packet_bytes)
        _materialize_exact(schema_path, schema_bytes)

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
        qualification = (
            self._qualification_payload
            if self._qualification_state == "valid_diagnostic"
            else {}
        )
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
            "telemetry_scope": "observed_events_only",
            "worker_child_environment": (
                "allowlist_preflight_passed" if preflight_state == "passed" else "not_verified"
            ),
            "filesystem_write_mitigation": qualification.get(
                "filesystem_write_mitigation", "not_verified"
            ),
            "nested_web_search": qualification.get("nested_web_search", "not_verified"),
            "broader_network_denial": "not_guaranteed",
            "connector_github_denial": "not_guaranteed",
            "ambient_secret_non_access": "not_guaranteed",
            "backend_stateless_attestation": "unavailable",
            "target_execution": "not_requested",
            "qualification_state": self._qualification_state,
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
