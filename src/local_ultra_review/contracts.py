"""Strict JSON contracts and deterministic hashing for the V2 evaluation slice."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime
import hashlib
from importlib import resources
import json
from pathlib import PurePosixPath
import re
from types import MappingProxyType
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_VERSION = "2.0-evaluation-slice"
ORCHESTRATION_CONTRACT_VERSION = "v2-orchestration-contract-1"

_SYNTHETIC_ATTEMPT_ASSURANCE_ITEMS = (
    ("worker_profile", "codex_native_guarded"),
    ("worker_boundary", "guarded_unconfined"),
    ("hard_worker_confinement", "not_provided"),
    ("input_discipline", "adapter_packet_minimized"),
    ("packet_only_read", "not_guaranteed"),
    ("residual_tool_surface", "unknown"),
    ("residual_tool_inventory", "unavailable"),
    ("accepted_tool_calls", "none_observed"),
    ("telemetry_scope", "observed_events_only"),
    ("worker_child_environment", "not_verified"),
    ("filesystem_write_mitigation", "not_verified"),
    ("nested_web_search", "not_verified"),
    ("broader_network_denial", "not_guaranteed"),
    ("connector_github_denial", "not_guaranteed"),
    ("ambient_secret_non_access", "not_guaranteed"),
    ("context_lineage", "fresh_process_inferred"),
    ("backend_stateless_attestation", "unavailable"),
    ("target_execution", "not_requested"),
)
_ALL_MANUAL_ASSURANCE_ITEMS = tuple(
    (key, "not_applicable_no_dispatch")
    if key in {"accepted_tool_calls", "telemetry_scope", "context_lineage"}
    else (key, value)
    for key, value in _SYNTHETIC_ATTEMPT_ASSURANCE_ITEMS
)
SYNTHETIC_ATTEMPT_ASSURANCE = MappingProxyType(
    dict(_SYNTHETIC_ATTEMPT_ASSURANCE_ITEMS)
)
ALL_MANUAL_ASSURANCE = MappingProxyType(dict(_ALL_MANUAL_ASSURANCE_ITEMS))

_PROMPT_VERSIONS = {
    "reviewer-correctness": "reviewer-correctness-v1",
    "verifier": "verifier-v1",
}
_HASH = re.compile(r"^[0-9a-f]{64}$")

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
    return f"{serialized}\n".encode("utf-8")


def sha256_json(value: object) -> str:
    """Return the lowercase SHA-256 digest of a canonical JSON value."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _safe_untrusted(value: object) -> None:
    """Apply the accepted-sink gate without creating an import cycle."""

    from .redaction import SensitiveMaterialError, assert_safe_sink

    try:
        assert_safe_sink(value)
    except SensitiveMaterialError as error:
        raise ContractError("known-sensitive value is forbidden before hashing") from error


def schema_contracts() -> dict:
    """Return fresh public metadata for semantic result schemas only."""

    return {
        name: {
            "schema_version": SCHEMA_VERSION,
            "sha256": sha256_json(load_schema(name)),
        }
        for name in ("reviewer-result", "verifier-result", "evaluation-completion")
    }


def prompt_contracts() -> dict:
    """Return fresh prompt versions and hashes over packaged raw bytes."""

    prompt_root = resources.files(_RESOURCE_PACKAGE).joinpath("prompts")
    contracts: dict[str, dict[str, str]] = {}
    for name, version in _PROMPT_VERSIONS.items():
        try:
            raw = prompt_root.joinpath(f"{name}.md").read_bytes()
        except OSError as error:
            raise ContractError(f"cannot load packaged prompt {name!r}: {error}") from error
        contracts[name] = {
            "version": version,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    return contracts


def synthetic_attempt_assurance() -> dict:
    """Return the exact conservative assurance for accepted synthetic attempts."""

    return dict(_SYNTHETIC_ATTEMPT_ASSURANCE_ITEMS)


def all_manual_assurance() -> dict:
    """Return the exact assurance for a target requiring no worker dispatch."""

    return dict(_ALL_MANUAL_ASSURANCE_ITEMS)


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


def validate_semantic_plan(value: object) -> None:
    """Validate the complete, session-independent synthetic semantic plan."""

    _safe_untrusted(value)
    if not isinstance(value, Mapping):
        raise ContractError("semantic plan must be an object")
    exact_fields = {
        "profile",
        "authority",
        "execution_backend",
        "release_ready",
        "roles",
        "model",
        "schema_contracts",
        "prompt_contracts",
        "redaction_contract",
        "fake_readiness",
        "fake_semantic_identity",
        "orchestration_contract_version",
        "run_manifest_version",
    }
    if set(value) != exact_fields:
        raise ContractError("semantic plan fields do not match the V2 contract")
    fixed = {
        "profile": "evaluation_slice_v2",
        "authority": "synthetic_evaluation",
        "execution_backend": "fake_evaluation",
        "release_ready": False,
        "roles": ["correctness"],
        "orchestration_contract_version": ORCHESTRATION_CONTRACT_VERSION,
    }
    for key, expected in fixed.items():
        if value[key] != expected:
            raise ContractError(f"semantic plan {key} mismatch")
    if not isinstance(value["model"], str) or not value["model"].strip():
        raise ContractError("semantic plan model must be nonempty")
    if value["schema_contracts"] != schema_contracts():
        raise ContractError("semantic plan schema contracts mismatch")
    if value["prompt_contracts"] != prompt_contracts():
        raise ContractError("semantic plan prompt contracts mismatch")
    from .redaction import redaction_contract

    if value["redaction_contract"] != redaction_contract():
        raise ContractError("semantic plan redaction contract mismatch")

    readiness = value["fake_readiness"]
    readiness_fields = {
        "ready",
        "mode",
        "authority",
        "execution_backend",
        "live_dispatch_authorized",
        "live_dispatch_blockers",
        "consumption_state",
    }
    if not isinstance(readiness, Mapping) or set(readiness) != readiness_fields:
        raise ContractError("fake readiness fields do not match the contract")
    if {
        key: readiness[key]
        for key in readiness_fields - {"consumption_state"}
    } != {
        "ready": True,
        "mode": "synthetic_evaluation_only",
        "authority": "synthetic_evaluation",
        "execution_backend": "fake_evaluation",
        "live_dispatch_authorized": False,
        "live_dispatch_blockers": ["fake_backend_has_no_live_authority"],
    }:
        raise ContractError("fake readiness is not pristine synthetic-only state")
    state = readiness["consumption_state"]
    if not isinstance(state, Mapping) or set(state) != {
        "total_attempts",
        "consumed_attempts",
        "remaining_attempts",
    }:
        raise ContractError("fake consumption state fields mismatch")
    if any(
        not isinstance(state[key], int)
        or isinstance(state[key], bool)
        or state[key] < 0
        for key in state
    ):
        raise ContractError("fake consumption counts must be nonnegative integers")
    if state["consumed_attempts"] != 0 or state["remaining_attempts"] != state["total_attempts"]:
        raise ContractError("fake backend must be pristine in the semantic plan")

    identity = value["fake_semantic_identity"]
    identity_fields = {
        "backend",
        "backend_version",
        "protocol_version",
        "run_manifest_version",
        "scenario_id",
        "total_attempts",
        "expected_role_sequence",
        "unbound_attempt_templates_sha256",
    }
    if not isinstance(identity, Mapping) or set(identity) != identity_fields:
        raise ContractError("fake semantic identity fields do not match the contract")
    from .backend import FAKE_BACKEND_VERSION, PROTOCOL_VERSION, RUN_MANIFEST_VERSION

    if (
        identity["backend"] != "fake_evaluation"
        or identity["backend_version"] != FAKE_BACKEND_VERSION
        or identity["protocol_version"] != PROTOCOL_VERSION
        or identity["run_manifest_version"] != RUN_MANIFEST_VERSION
        or value["run_manifest_version"] != RUN_MANIFEST_VERSION
    ):
        raise ContractError("fake semantic identity version mismatch")
    if not isinstance(identity["scenario_id"], str) or not identity["scenario_id"].strip():
        raise ContractError("fake scenario ID must be nonempty")
    roles = identity["expected_role_sequence"]
    total_attempts = identity["total_attempts"]
    if (
        not isinstance(total_attempts, int)
        or isinstance(total_attempts, bool)
        or total_attempts < 0
    ):
        raise ContractError("fake total attempt count is invalid")
    expected_roles = (
        []
        if total_attempts == 0
        else ["reviewer", *(["verifier"] * (total_attempts - 1))]
    )
    if (
        not isinstance(roles, list)
        or roles != expected_roles
        or total_attempts != len(roles)
        or total_attempts != state["total_attempts"]
    ):
        raise ContractError("fake attempt count and role sequence mismatch")
    if not isinstance(identity["unbound_attempt_templates_sha256"], str) or not _HASH.fullmatch(
        identity["unbound_attempt_templates_sha256"]
    ):
        raise ContractError("fake template hash is invalid")
    if total_attempts == 0 and identity["unbound_attempt_templates_sha256"] != sha256_json([]):
        raise ContractError("empty fake scenario template hash mismatch")


def review_identity_hash(target_identity_hash: str, semantic_plan: dict) -> str:
    """Bind target identity to every session-independent semantic input."""

    core = {
        "target_identity_hash": target_identity_hash,
        "semantic_plan": semantic_plan,
    }
    _safe_untrusted(core)
    if not isinstance(target_identity_hash, str) or not _HASH.fullmatch(target_identity_hash):
        raise ContractError("target identity hash is invalid")
    validate_semantic_plan(semantic_plan)
    return sha256_json(core)


def adapter_manual_item_hash(disposition: dict) -> str:
    """Hash one complete adapter-owned manual disposition in its own domain."""

    _safe_untrusted(disposition)
    if not isinstance(disposition, Mapping) or set(disposition) != {
        "path",
        "reason",
        "atom_ids",
        "disposition_id",
    }:
        raise ContractError("adapter manual disposition fields mismatch")
    if any(
        not isinstance(disposition[key], str) or not disposition[key]
        for key in ("path", "reason", "disposition_id")
    ):
        raise ContractError("adapter manual disposition strings must be nonempty")
    atoms = disposition["atom_ids"]
    if (
        not isinstance(atoms, list)
        or not atoms
        or atoms != sorted(set(atoms))
        or any(not isinstance(atom, str) or not atom.startswith("atom-") for atom in atoms)
    ):
        raise ContractError("adapter manual atom IDs must be sorted unique values")
    return sha256_json(
        {"domain": "adapter_manual_disposition_v1", "disposition": disposition}
    )


def verifier_manual_item_hash(
    candidate_hash: str,
    duplicate_ordinal: int,
    verifier_result_envelope_hash: str,
) -> str:
    """Hash one ordinal-bound verifier manual disposition in its own domain."""

    core = {
        "domain": "verifier_needs_manual_review_v1",
        "candidate_hash": candidate_hash,
        "duplicate_ordinal": duplicate_ordinal,
        "verifier_result_envelope_hash": verifier_result_envelope_hash,
    }
    _safe_untrusted(core)
    if (
        not isinstance(candidate_hash, str)
        or not _HASH.fullmatch(candidate_hash)
        or not isinstance(verifier_result_envelope_hash, str)
        or not _HASH.fullmatch(verifier_result_envelope_hash)
        or not isinstance(duplicate_ordinal, int)
        or isinstance(duplicate_ordinal, bool)
        or duplicate_ordinal < 0
    ):
        raise ContractError("verifier manual item identity is invalid")
    return sha256_json(core)


_ROOT_CAUSE_FIELDS = {
    "file",
    "line",
    "title",
    "failure_scenario",
    "evidence",
    "why_diff",
}
_CANONICAL_FINDING_FIELDS = {
    "root_cause",
    "merged_final_severity",
    "confirmed_instances",
    "proof",
    "provenance",
    "best_fix",
    "refactor_judgment",
    "residual_risk",
}


def _validate_canonical_finding_core(value: object) -> Mapping[str, Any]:
    _safe_untrusted(value)
    if not isinstance(value, Mapping) or set(value) != _CANONICAL_FINDING_FIELDS:
        raise ContractError("canonical finding fields mismatch")
    root = value["root_cause"]
    if not isinstance(root, Mapping) or set(root) != _ROOT_CAUSE_FIELDS:
        raise ContractError("canonical root-cause fields mismatch")
    if (
        not isinstance(root["file"], str)
        or not root["file"]
        or PurePosixPath(root["file"]).is_absolute()
        or ".." in PurePosixPath(root["file"]).parts
        or not isinstance(root["line"], int)
        or isinstance(root["line"], bool)
        or root["line"] < 1
        or any(
            not isinstance(root[key], str) or not root[key]
            for key in ("title", "failure_scenario", "why_diff")
        )
        or not isinstance(root["evidence"], list)
        or not root["evidence"]
        or len(set(root["evidence"])) != len(root["evidence"])
        or any(not isinstance(item, str) or not item for item in root["evidence"])
    ):
        raise ContractError("canonical root-cause payload is invalid")
    if value["merged_final_severity"] not in {"Important", "Nit"}:
        raise ContractError("canonical merged severity is invalid")
    instances = value["confirmed_instances"]
    instance_fields = {
        "candidate_hash",
        "duplicate_ordinal",
        "verifier_result_envelope_hash",
        "final_severity",
    }
    if not isinstance(instances, list) or not instances:
        raise ContractError("canonical finding requires confirmed instances")
    identities: list[tuple[str, int, str]] = []
    for instance in instances:
        if not isinstance(instance, Mapping) or set(instance) != instance_fields:
            raise ContractError("confirmed instance fields mismatch")
        identity = (
            instance["candidate_hash"],
            instance["duplicate_ordinal"],
            instance["verifier_result_envelope_hash"],
        )
        if (
            not isinstance(identity[0], str)
            or not _HASH.fullmatch(identity[0])
            or not isinstance(identity[1], int)
            or isinstance(identity[1], bool)
            or identity[1] < 0
            or not isinstance(identity[2], str)
            or not _HASH.fullmatch(identity[2])
            or instance["final_severity"] not in {"Important", "Nit"}
        ):
            raise ContractError("confirmed instance identity is invalid")
        identities.append(identity)
    if identities != sorted(set(identities)):
        raise ContractError("confirmed instances must be sorted and unique")
    expected_severity = (
        "Important"
        if any(instance["final_severity"] == "Important" for instance in instances)
        else "Nit"
    )
    if value["merged_final_severity"] != expected_severity:
        raise ContractError("canonical merged severity must retain Important")
    for field in ("proof", "provenance", "best_fix", "refactor_judgment", "residual_risk"):
        items = value[field]
        if (
            not isinstance(items, list)
            or not items
            or items != sorted(set(items))
            or any(not isinstance(item, str) or not item for item in items)
        ):
            raise ContractError(f"canonical {field} values must be sorted unique strings")
    return value


def canonical_finding_hash(finding: dict) -> str:
    """Hash the complete canonical finding, including severity and merged proof."""

    core = _validate_canonical_finding_core(finding)
    return sha256_json({"domain": "canonical_finding_v1", "finding": core})


def _validate_evaluation_completion_semantics(value: Mapping[str, Any]) -> None:
    _safe_untrusted(value)
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
        accounting["confirmed_candidate_dispositions"]
        + accounting["false_positive"]
        + accounting["pre_existing"]
        + accounting["needs_manual_review"]
    )
    if dispositions != accounting["raw_candidates"]:
        raise ContractError("candidate dispositions must sum to raw candidates")
    confirmed = accounting["confirmed_candidate_dispositions"]
    canonical_count = accounting["canonical_findings"]
    if (confirmed == 0) != (canonical_count == 0):
        raise ContractError("confirmed dispositions and canonical findings must agree on emptiness")
    if confirmed > 0 and not (1 <= canonical_count <= confirmed):
        raise ContractError("canonical findings must group all confirmed dispositions")

    canonical_records = value["canonical_finding_records"]
    if len(canonical_records) != canonical_count:
        raise ContractError("canonical finding records must match canonical finding count")
    canonical_hashes: list[str] = []
    confirmed_memberships: list[tuple[str, int, str]] = []
    canonical_root_keys: list[bytes] = []
    for record in canonical_records:
        if not isinstance(record, Mapping) or set(record) != _CANONICAL_FINDING_FIELDS | {
            "canonical_finding_hash"
        }:
            raise ContractError("canonical finding record fields mismatch")
        core = {
            key: deepcopy(child)
            for key, child in record.items()
            if key != "canonical_finding_hash"
        }
        computed = canonical_finding_hash(core)
        if record["canonical_finding_hash"] != computed:
            raise ContractError("canonical finding record hash mismatch")
        canonical_hashes.append(computed)
        canonical_root_keys.append(canonical_json_bytes(record["root_cause"]))
        for instance in record["confirmed_instances"]:
            identity = (
                instance["candidate_hash"],
                instance["duplicate_ordinal"],
                instance["verifier_result_envelope_hash"],
            )
            if identity[2] not in verifier_hashes:
                raise ContractError("canonical finding references an unaccepted verifier result")
            confirmed_memberships.append(identity)
    if len(confirmed_memberships) != confirmed or len(set(confirmed_memberships)) != confirmed:
        raise ContractError("each confirmed candidate instance must belong to exactly one group")
    if len(set(canonical_root_keys)) != len(canonical_root_keys):
        raise ContractError("one severity-free root cause may appear in only one canonical group")
    if value["canonical_finding_hashes"] != sorted(canonical_hashes):
        raise ContractError("canonical finding hashes must be the exact record projection")

    manual_count = accounting["needs_manual_review"] + accounting["adapter_manual_items"]
    manual_records = value["manual_item_records"]
    if len(manual_records) != manual_count:
        raise ContractError("manual item records must match all manual items")
    manual_hashes: list[str] = []
    adapter_count = 0
    verifier_manual_count = 0
    verifier_manual_identities: set[tuple[str, int, str]] = set()
    adapter_manual_atoms: set[str] = set()
    for record in manual_records:
        if not isinstance(record, Mapping):
            raise ContractError("manual item record must be an object")
        domain = record.get("domain")
        if domain == "adapter_manual_disposition":
            if set(record) != {"domain", "disposition", "manual_item_hash"}:
                raise ContractError("adapter manual item fields mismatch")
            computed = adapter_manual_item_hash(record["disposition"])
            atoms = set(record["disposition"]["atom_ids"])
            if adapter_manual_atoms & atoms:
                raise ContractError("adapter manual dispositions overlap atom coverage")
            adapter_manual_atoms.update(atoms)
            adapter_count += 1
        elif domain == "verifier_needs_manual_review":
            if set(record) != {
                "domain",
                "candidate_hash",
                "duplicate_ordinal",
                "verifier_result_envelope_hash",
                "manual_item_hash",
            }:
                raise ContractError("verifier manual item fields mismatch")
            computed = verifier_manual_item_hash(
                record["candidate_hash"],
                record["duplicate_ordinal"],
                record["verifier_result_envelope_hash"],
            )
            identity = (
                record["candidate_hash"],
                record["duplicate_ordinal"],
                record["verifier_result_envelope_hash"],
            )
            if identity in verifier_manual_identities:
                raise ContractError("verifier manual item instance is duplicated")
            verifier_manual_identities.add(identity)
            if record["verifier_result_envelope_hash"] not in verifier_hashes:
                raise ContractError("manual item references an unaccepted verifier result")
            verifier_manual_count += 1
        else:
            raise ContractError("manual item hash domain is invalid")
        if record["manual_item_hash"] != computed:
            raise ContractError("manual item record hash mismatch")
        manual_hashes.append(computed)
    if adapter_count != accounting["adapter_manual_items"]:
        raise ContractError("adapter manual disposition count mismatch")
    if verifier_manual_count != accounting["needs_manual_review"]:
        raise ContractError("verifier manual disposition count mismatch")
    if len(adapter_manual_atoms) != coverage["manual_atoms"]:
        raise ContractError("adapter manual dispositions must cover every manual atom exactly once")
    if value["manual_item_hashes"] != sorted(manual_hashes):
        raise ContractError("manual item hashes must be the exact record projection")

    all_instance_pairs = [
        (candidate_hash, duplicate_ordinal)
        for candidate_hash, duplicate_ordinal, _envelope_hash in confirmed_memberships
    ] + [
        (candidate_hash, duplicate_ordinal)
        for candidate_hash, duplicate_ordinal, _envelope_hash in verifier_manual_identities
    ]
    all_terminal_envelopes = [
        envelope_hash for _candidate_hash, _ordinal, envelope_hash in confirmed_memberships
    ] + [
        envelope_hash
        for _candidate_hash, _ordinal, envelope_hash in verifier_manual_identities
    ]
    if len(all_instance_pairs) != len(set(all_instance_pairs)):
        raise ContractError("candidate/ordinal instance belongs to more than one terminal domain")
    if len(all_terminal_envelopes) != len(set(all_terminal_envelopes)):
        raise ContractError("verifier result belongs to more than one terminal domain")
    unreferenced_verifiers = set(verifier_hashes) - set(all_terminal_envelopes)
    if len(unreferenced_verifiers) != accounting["false_positive"] + accounting["pre_existing"]:
        raise ContractError("verifier result references do not reconcile terminal dispositions")

    reviewer_state = value["reviewer_execution_state"]
    dispatch_state = value["worker_dispatch_state"]
    reviewer_hash = value["reviewer_artifact_hash"]
    completed_branch = coverage["reviewed_atoms"] > 0
    if completed_branch:
        if (
            reviewer_state != "completed"
            or dispatch_state != "synthetic_attempts_accepted"
            or not isinstance(reviewer_hash, str)
            or not _HASH.fullmatch(reviewer_hash)
        ):
            raise ContractError("reviewed atoms require one accepted reviewer execution")
        expected_assurance = synthetic_attempt_assurance()
        expected_accepted = sorted([reviewer_hash, *verifier_hashes])
    else:
        if (
            reviewer_state != "not_applicable_no_reviewable_atoms"
            or dispatch_state != "not_applicable_no_reviewable_atoms"
            or reviewer_hash is not None
            or coverage["manual_atoms"] != coverage["total_atoms"]
        ):
            raise ContractError("all-manual target must not claim reviewer execution")
        if any(
            accounting[key] != 0
            for key in (
                "raw_candidates",
                "verifier_results",
                "confirmed_candidate_dispositions",
                "canonical_findings",
                "false_positive",
                "pre_existing",
                "needs_manual_review",
            )
        ):
            raise ContractError("all-manual target cannot contain worker accounting")
        if verifier_hashes or canonical_records or value["canonical_finding_hashes"]:
            raise ContractError("all-manual target cannot contain worker findings")
        if accounting["adapter_manual_items"] < 1:
            raise ContractError("all-manual target requires an adapter manual disposition")
        expected_assurance = all_manual_assurance()
        expected_accepted = []
    if value["accepted_artifact_hashes"] != expected_accepted:
        raise ContractError("accepted artifact hashes must be exactly reviewer plus verifiers")
    if value["assurance_contract_under_test"] != expected_assurance:
        raise ContractError("completion assurance tuple does not match its dispatch branch")

    for field in (
        "verifier_artifact_hashes",
        "canonical_finding_hashes",
        "manual_item_hashes",
        "accepted_artifact_hashes",
    ):
        hashes = value[field]
        if hashes != sorted(hashes):
            raise ContractError(f"$.{field} must be sorted")

    expected_verdict = (
        "manual_review_required"
        if manual_count > 0
        else "findings"
        if canonical_count > 0
        else "clean"
    )
    if value["simulated_review_verdict"] != expected_verdict:
        raise ContractError("simulated verdict does not match exact accounting")


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
