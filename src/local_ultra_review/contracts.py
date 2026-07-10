"""Strict JSON contracts and deterministic hashing for the V2 evaluation slice."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime
import hashlib
from importlib import resources
import json
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_VERSION = "2.0-evaluation-slice"

_RESOURCE_PACKAGE = "local_ultra_review.resources"
_SCHEMA_FILES = {
    "reviewer-result": "reviewer-result.schema.json",
    "verifier-result": "verifier-result.schema.json",
    "qualification-record": "qualification-record.schema.json",
    "evaluation-completion": "evaluation-completion.schema.json",
}
_WORKER_AUTHORITY_FIELDS = frozenset(
    {
        "assurance",
        "capability",
        "capabilities",
        "worker_profile",
        "worker_boundary",
        "hard_worker_confinement",
        "context_lineage",
        "parent_context_id",
        "residual_tool_surface",
        "tool_inventory",
        "tools",
        "telemetry_scope",
    }
)


class ContractError(ValueError):
    """Raised when a value violates a V2 contract."""


def canonical_json_bytes(value: object) -> bytes:
    """Serialize a JSON value deterministically as compact UTF-8 bytes."""

    try:
        serialized = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise ContractError(f"value is not valid canonical JSON: {error}") from error
    return serialized.encode("utf-8")


def sha256_json(value: object) -> str:
    """Return the lowercase SHA-256 digest of a canonical JSON value."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _schema_key(name: str) -> str:
    if not isinstance(name, str) or not name:
        raise ContractError("schema name must be a nonempty string")
    suffix = ".schema.json"
    key = name[: -len(suffix)] if name.endswith(suffix) else name
    if key not in _SCHEMA_FILES:
        raise ContractError(f"unknown schema: {name!r}")
    return key


def load_schema(name: str) -> dict:
    """Load a packaged schema without consulting the caller's working directory."""

    key = _schema_key(name)
    resource = resources.files(_RESOURCE_PACKAGE).joinpath(
        "schemas", _SCHEMA_FILES[key]
    )
    try:
        value = json.loads(resource.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError) as error:
        raise ContractError(f"cannot load packaged schema {key!r}: {error}") from error
    if not isinstance(value, dict):
        raise ContractError(f"packaged schema {key!r} is not a JSON object")
    try:
        Draft202012Validator.check_schema(value)
    except Exception as error:
        raise ContractError(f"packaged schema {key!r} is invalid: {error}") from error
    return deepcopy(value)


def _json_path(error_path: Sequence[object]) -> str:
    path = "$"
    for component in error_path:
        if isinstance(component, int):
            path += f"[{component}]"
        else:
            path += f".{component}"
    return path


def _validate_qualification_semantics(value: Mapping[str, Any]) -> None:
    exposures = value["known_observed_exposures"]
    if exposures != sorted(exposures):
        raise ContractError("$.known_observed_exposures must be sorted")

    qualified_at = datetime.fromisoformat(value["qualified_at"].replace("Z", "+00:00"))
    expires_at = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
    if expires_at <= qualified_at:
        raise ContractError("$.expires_at must be later than $.qualified_at")


def _validate_evaluation_completion_semantics(value: Mapping[str, Any]) -> None:
    coverage = value["coverage"]
    if coverage["reviewed_atoms"] + coverage["manual_atoms"] != coverage["total_atoms"]:
        raise ContractError("evaluation coverage must account for every atom exactly once")

    accounting = value["accounting"]
    verifier_hashes = value["verifier_artifact_hashes"]
    if not (
        accounting["verifier_results"]
        == accounting["raw_candidates"]
        == len(verifier_hashes)
    ):
        raise ContractError("verifier results, raw candidates, and verifier hashes must match")

    dispositions = (
        accounting["confirmed_findings"]
        + accounting["false_positive"]
        + accounting["pre_existing"]
        + accounting["needs_manual_review"]
    )
    if dispositions != accounting["raw_candidates"]:
        raise ContractError("candidate dispositions must sum to raw candidates")
    if len(value["canonical_finding_hashes"]) != accounting["confirmed_findings"]:
        raise ContractError("canonical finding hashes must match confirmed findings")

    manual_count = accounting["needs_manual_review"] + accounting["adapter_manual_items"]
    if len(value["manual_item_hashes"]) != manual_count:
        raise ContractError("manual item hashes must match all manual items")

    expected_accepted = {value["reviewer_artifact_hash"], *verifier_hashes}
    if set(value["accepted_artifact_hashes"]) != expected_accepted:
        raise ContractError("accepted artifact hashes must be exactly reviewer plus verifiers")

    for field in (
        "verifier_artifact_hashes",
        "canonical_finding_hashes",
        "manual_item_hashes",
        "accepted_artifact_hashes",
    ):
        hashes = value[field]
        if hashes != sorted(hashes):
            raise ContractError(f"$.{field} must be sorted")

    verdict = value["simulated_review_verdict"]
    confirmed = accounting["confirmed_findings"]
    if verdict == "clean" and (confirmed != 0 or manual_count != 0):
        raise ContractError("clean verdict requires no confirmed or manual items")
    if verdict == "findings" and (confirmed < 1 or manual_count != 0):
        raise ContractError("findings verdict requires confirmed findings and no manual items")
    if verdict == "manual_review_required" and manual_count < 1:
        raise ContractError("manual-review verdict requires at least one manual item")


def validate_payload(schema_name: str, value: object) -> None:
    """Validate a payload against its strict schema and cross-field invariants."""

    key = _schema_key(schema_name)
    schema = load_schema(key)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(
        validator.iter_errors(value),
        key=lambda error: (tuple(str(part) for part in error.absolute_path), error.message),
    )
    if errors:
        error = errors[0]
        raise ContractError(f"{_json_path(error.absolute_path)}: {error.message}") from error

    if key == "qualification-record":
        _validate_qualification_semantics(value)  # type: ignore[arg-type]
    elif key == "evaluation-completion":
        _validate_evaluation_completion_semantics(value)  # type: ignore[arg-type]


def reject_worker_authority_fields(value: object) -> None:
    """Reject worker-supplied authority claims at any nesting depth."""

    def walk(node: object, path: str) -> None:
        if isinstance(node, Mapping):
            for key, child in node.items():
                child_path = f"{path}.{key}"
                if key in _WORKER_AUTHORITY_FIELDS:
                    raise ContractError(f"worker authority field is forbidden: {child_path}")
                walk(child, child_path)
        elif isinstance(node, Sequence) and not isinstance(node, (str, bytes, bytearray)):
            for index, child in enumerate(node):
                walk(child, f"{path}[{index}]")

    walk(value, "$")
