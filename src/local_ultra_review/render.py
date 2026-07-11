"""Truthful, non-authoritative report rendering for the guarded V2 slice."""

from __future__ import annotations

from collections.abc import Mapping
import html
import hashlib
import os
from pathlib import Path
import re
import stat
import unicodedata
import uuid

from .backend import WorkerProtocolError, validate_run_manifest
from .contracts import (
    ContractError,
    SCHEMA_VERSION,
    review_identity_hash,
    sha256_json,
    validate_payload,
    validate_semantic_plan,
)
from .redaction import SensitiveMaterialError, assert_safe_sink


class RenderError(ValueError):
    """Raised when inputs cannot support a truthful non-authoritative report."""


class MaterializationError(RuntimeError):
    """Raised when a non-authoritative view cannot be safely materialized."""


REPORT_CONTRACT_VERSION = "guarded-report-v1"
MARKDOWN_MEDIA_TYPE = "text/markdown; charset=utf-8"

_HASH = re.compile(r"^[0-9a-f]{64}$")
_PLAN_FIELDS = {
    "schema_version",
    "session_id",
    "session_root",
    "created_at",
    "review_identity_hash",
    "target_identity_hash",
    "target_packet_payload_hash",
    "semantic_plan",
    "plan_integrity_hash",
}
_ENVELOPE_FIELDS = {
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
_REPORT_FIELDS = {
    "report_contract_version",
    "document_kind",
    "media_type",
    "content_sha256",
    "content",
}
_REPORT_BASENAMES = {
    "evaluation_report": "evaluation-report.md",
    "diagnostic_report": "diagnostic.md",
}
_RECOVERY_BASENAME = "recovery-diagnostic.md"
_RECOVERY_REASONS = {
    "store_creation_integrity_failed",
    "canonical_store_verification_failed",
    "artifact_commit_state_uncertain",
    "canonical_readback_integrity_failed",
    "terminal_commit_state_uncertain",
}
_BLOCKED_REASONS = {
    "canonical_inventory_oracle_unavailable",
    "object_bound_version_probe_unavailable",
    "qualification_record_unavailable",
    "qualification_record_invalid",
    "qualification_record_expired",
    "qualification_record_mismatch",
    "cli_binary_inspection_failed",
    "fake_backend_not_pristine",
    "fake_backend_scenario_invalid",
    "fake_backend_not_ready",
    "request_backend_model_mismatch",
    "synthetic_consumption_state_unavailable",
    "backend_semantic_identity_invalid",
}
_INCOMPLETE_REASONS = {
    "worker_unavailable",
    "scripted_attempts_exhausted",
    "worker_attempt_rejected",
    "semantic_contract_rejected",
    "coverage_accounting_failed",
    "scripted_attempts_leftover",
    "scripted_attempt_accounting_mismatch",
    "completion_projection_rejected",
}
_DIAGNOSTIC_ASSURANCE = {
    "worker_boundary": "guarded_unconfined",
    "hard_worker_confinement": "not_provided",
    "packet_only_read": "not_guaranteed",
    "residual_tool_surface": "unknown",
    "residual_tool_inventory": "unavailable",
    "worker_child_environment": "not_verified",
    "filesystem_write_mitigation": "not_verified",
    "nested_web_search": "not_verified",
    "backend_stateless_attestation": "unavailable",
    "target_execution": "not_requested",
}
_HARD_CLAIM_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"#\s*local\s+ultra\s+review\s+report",
        r"authoritative_review\s*[:=]\s*true",
        r"release_ready\s*[:=]\s*true",
        r"(?<![A-Za-z0-9_])authority\s*[:=]\s*(?!synthetic_evaluation\b|non_authoritative_diagnostic\b)\S+",
        r"(?<![A-Za-z0-9_])profile\s*[:=]\s*(?!evaluation_slice_v2\b)\S+",
        r"(?<![A-Za-z0-9_])document_kind\s*[:=]\s*(?:report|canonical_report|code_review_report)",
        r"worker_boundary\s*[:=]\s*(?:sandboxed|confined|isolated)",
        r"hard_worker_confinement\s*[:=]\s*provided",
        r"packet_only_read\s*[:=]\s*(?:guaranteed|verified)",
        r"residual_tool_surface\s*[:=]\s*(?:none|no_tools)",
        r"worker_child_environment\s*[:=]\s*verified",
        r"filesystem_write_mitigation\s*[:=]\s*verified",
        r"nested_web_search\s*[:=]\s*(?:denied|disabled|verified)",
        r"broader_network_denial\s*[:=]\s*(?:guaranteed|verified)",
        r"connector_github_denial\s*[:=]\s*(?:guaranteed|verified)",
        r"ambient_secret_non_access\s*[:=]\s*(?:guaranteed|verified)",
        r"\bworker(?:\s+boundary)?\s+(?:is\s+)?(?:sandboxed|isolated|confined|controlled|attested|packet[-_ ]only)\b",
        r"\b(?:sandboxed|isolated|confined|controlled|attested|packet[-_ ]only)\s+worker\b",
        r"\b(?:tool[- ]free|no[- ]tools?)\b",
        r"\bnetwork(?:\s+access)?\s+(?:is\s+)?(?:denied|disabled|blocked)\b",
        r"\bnetwork[- ]free\b",
        r"\bno[- ]network\b(?!\s+guarantee)",
    )
)
_FALSE_CLEAN_PATTERN = re.compile(
    r"(?:\btarget\s+is\s+clean\b|\bno\s+issues\b|"
    r"\bno\s+confirmed\s+findings\b|\breview\s+passed\b)",
    re.IGNORECASE,
)


def _raise_render(message: str, error: Exception | None = None) -> None:
    if error is None:
        raise RenderError(message)
    raise RenderError(message) from error


def _safe(value: object, label: str) -> None:
    try:
        assert_safe_sink(value)
    except SensitiveMaterialError as error:
        _raise_render(f"{label} contains unsafe material", error)


def _hash(value: object) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _json_hash(value: object, label: str) -> str:
    try:
        return sha256_json(value)
    except ContractError as error:
        _raise_render(f"{label} is not canonical JSON", error)


def _content_bytes(content: str) -> bytes:
    try:
        return content.encode("utf-8")
    except UnicodeEncodeError as error:
        _raise_render("report content is not valid UTF-8", error)


def _validate_plan(plan: object) -> dict:
    _safe(plan, "plan")
    if not isinstance(plan, dict) or set(plan) != _PLAN_FIELDS:
        _raise_render("plan does not match the exact V2 contract")
    if plan.get("schema_version") != SCHEMA_VERSION:
        _raise_render("plan schema version mismatch")
    if any(
        not isinstance(plan.get(key), str) or not plan[key]
        for key in ("session_id", "created_at")
    ):
        _raise_render("plan identity fields are invalid")
    session_root = plan.get("session_root")
    if not isinstance(session_root, str) or not Path(session_root).is_absolute():
        _raise_render("plan session root is invalid")
    if any(
        not _hash(plan.get(key))
        for key in (
            "review_identity_hash",
            "target_identity_hash",
            "target_packet_payload_hash",
            "plan_integrity_hash",
        )
    ):
        _raise_render("plan hash field is invalid")
    core = {key: value for key, value in plan.items() if key != "plan_integrity_hash"}
    if _json_hash(core, "plan") != plan["plan_integrity_hash"]:
        _raise_render("plan integrity hash mismatch")
    try:
        validate_semantic_plan(plan["semantic_plan"])
        expected_identity = review_identity_hash(
            plan["target_identity_hash"], plan["semantic_plan"]
        )
    except ContractError as error:
        _raise_render("plan semantic contract failed", error)
    if expected_identity != plan["review_identity_hash"]:
        _raise_render("plan review identity mismatch")
    return plan


def _validate_worker_envelope(envelope: object, plan: dict) -> str:
    _safe(envelope, "worker artifact")
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_FIELDS:
        _raise_render("worker artifact envelope fields mismatch")
    artifact_type = envelope.get("artifact_type")
    if artifact_type not in {"reviewer_result", "verifier_result"}:
        _raise_render("report accepts only worker result envelopes")
    if (
        envelope.get("schema_version") != SCHEMA_VERSION
        or envelope.get("session_id") != plan["session_id"]
        or envelope.get("plan_integrity_hash") != plan["plan_integrity_hash"]
        or envelope.get("review_identity_hash") != plan["review_identity_hash"]
    ):
        _raise_render("worker artifact identity mismatch")
    if not isinstance(envelope.get("created_at"), str) or not envelope["created_at"]:
        _raise_render("worker artifact timestamp is invalid")
    payload = envelope.get("payload")
    producer = envelope.get("producer")
    input_hashes = envelope.get("input_hashes")
    if not isinstance(payload, dict) or set(payload) != {"result", "adapter_manifest"}:
        _raise_render("worker artifact wrapper fields mismatch")
    if not isinstance(producer, dict) or set(producer) != {
        "producer_kind",
        "task_id",
        "attempt_hash",
        "thread_id",
        "process_launch_id",
        "input_hashes",
    }:
        _raise_render("worker artifact producer fields mismatch")
    if producer.get("producer_kind") != "worker_attempt":
        _raise_render("worker artifact producer kind mismatch")
    result = payload.get("result")
    manifest = payload.get("adapter_manifest")
    role = "reviewer" if artifact_type == "reviewer_result" else "verifier"
    try:
        validate_payload(f"{role}-result", result)
        validate_run_manifest(manifest)
    except (ContractError, WorkerProtocolError) as error:
        _raise_render("worker artifact contract failed", error)
    if not isinstance(result, dict) or not isinstance(manifest, dict):
        _raise_render("worker artifact payload is invalid")
    task_id = result.get("task_id")
    if not isinstance(task_id, str) or not task_id.startswith(f"{role}-"):
        _raise_render("worker artifact role mismatch")
    expected_inputs = sorted([manifest["task_hash"], manifest["packet_hash"]])
    if (
        producer.get("task_id") != manifest["task_id"]
        or manifest["task_id"] != task_id
        or producer.get("attempt_hash") != manifest["attempt_hash"]
        or producer.get("thread_id") != manifest["thread_id"]
        or manifest["thread_id"] != manifest["synthetic_thread_id"]
        or producer.get("process_launch_id") != manifest["process_launch_id"]
        or result.get("packet_hash") != manifest["packet_hash"]
        or producer.get("input_hashes") != expected_inputs
        or input_hashes != expected_inputs
    ):
        _raise_render("worker artifact lineage mismatch")
    if envelope.get("payload_hash") != _json_hash(payload, "worker payload"):
        _raise_render("worker artifact payload hash mismatch")
    core = {key: value for key, value in envelope.items() if key != "envelope_hash"}
    envelope_hash = envelope.get("envelope_hash")
    if not _hash(envelope_hash) or _json_hash(core, "worker envelope") != envelope_hash:
        _raise_render("worker artifact envelope hash mismatch")
    return envelope_hash


def _reject_claim_text(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            _reject_claim_text(key)
            _reject_claim_text(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_claim_text(child)
    elif isinstance(value, str):
        normalized = _normalized_claim_text(value)
        if _FALSE_CLEAN_PATTERN.search(normalized) or _contains_hard_claim(normalized):
            _raise_render("input contains a forbidden review or assurance claim")


def _inline(value: object) -> str:
    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
    delimiter = "`" * (longest + 1)
    return f"{delimiter}{text}{delimiter}"


def _append_synthetic_values(lines: list[str], label: str, values: list[str]) -> None:
    lines.append(f"- synthetic_{label}:")
    lines.extend(
        f"  - synthetic_{label}_item: {_inline(value)}" for value in values
    )


def _normalized_claim_text(content: str) -> str:
    normalized = unicodedata.normalize("NFKC", html.unescape(content))
    for _iteration in range(3):
        normalized = re.sub(
            r"!?\[([^\]]*)\]\[[^\]]*\]", r"\1", normalized
        )
        normalized = re.sub(
            r"!?\[([^\]]*)\]\([^)]*\)", r"\1", normalized
        )
    normalized = re.sub(r"<!--.*?-->", "", normalized, flags=re.DOTALL)
    for _iteration in range(3):
        normalized = re.sub(
            r"<(?P<removed>del|s|script|style|template)\b[^>]*>.*?</(?P=removed)\s*>",
            "",
            normalized,
            flags=re.IGNORECASE | re.DOTALL,
        )
        normalized = re.sub(
            r"<(?P<hidden_tag>[A-Za-z][\w:-]*)\b(?=[^>]*\bhidden\b)[^>]*>.*?</(?P=hidden_tag)\s*>",
            "",
            normalized,
            flags=re.IGNORECASE | re.DOTALL,
        )
        normalized = re.sub(
            r"<(?P<styled_tag>[A-Za-z][\w:-]*)\b(?=[^>]*\bstyle\s*=[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden))[^>]*>.*?</(?P=styled_tag)\s*>",
            "",
            normalized,
            flags=re.IGNORECASE | re.DOTALL,
        )
        normalized = re.sub(r"~~.*?~~", "", normalized, flags=re.DOTALL)
    normalized = re.sub(r"<[^>]*>", "", normalized, flags=re.DOTALL)
    normalized = re.sub(r"\\(.)", r"\1", normalized, flags=re.DOTALL)
    normalized = re.sub(r"[`*~]", "", normalized)
    normalized = re.sub(r"(?<!\w)_{1,3}(?=\w)", "", normalized)
    normalized = re.sub(r"(?<=\w)_{1,3}(?!\w)", "", normalized)
    without_format_controls = "".join(
        ""
        if unicodedata.category(character) == "Cf"
        or "\ufe00" <= character <= "\ufe0f"
        or "\U000e0100" <= character <= "\U000e01ef"
        else character
        for character in normalized
    )
    return re.sub(r"\s+", " ", without_format_controls)


def _contains_hard_claim(content: str) -> bool:
    normalized = _normalized_claim_text(content)
    return any(pattern.search(normalized) for pattern in _HARD_CLAIM_PATTERNS)


def _contains_false_clean_claim(content: str) -> bool:
    checked = _normalized_claim_text(
        content.replace(
            "makes no claim that the target is clean", "synthetic disclaimer"
        )
    )
    return _FALSE_CLEAN_PATTERN.search(checked) is not None


def _evaluation_markers_valid(content: str) -> bool:
    required = (
        "document_kind: evaluation_report",
        "authority: synthetic_evaluation",
        "authoritative_review: false",
        "profile: evaluation_slice_v2",
        "release_ready: false",
        "# Synthetic protocol evaluation — not a code-review result",
        "makes no claim that the target is clean",
        "target_execution: `not_requested`",
    )
    return content.startswith(
        "---\ntitle: Synthetic protocol evaluation — not a code-review result\n"
    ) and all(marker in content for marker in required)


def _diagnostic_markers_valid(content: str) -> bool:
    required = (
        "document_kind: diagnostic_report",
        "authority: non_authoritative_diagnostic",
        "authoritative_review: false",
        "profile: evaluation_slice_v2",
        "release_ready: false",
        "# Synthetic protocol diagnostic — not a code-review result",
        "residual_tool_surface: `unknown`",
        "worker_child_environment: `not_verified`",
    )
    return content.startswith(
        "---\ntitle: Synthetic protocol diagnostic — not a code-review result\n"
    ) and all(marker in content for marker in required)


def render_evaluation_report(
    *, plan: dict, completion: dict, artifacts: list[dict]
) -> str:
    """Render one truthful synthetic evaluation from verified canonical inputs."""

    checked_plan = _validate_plan(plan)
    _safe(completion, "completion")
    _safe(artifacts, "worker artifacts")
    if not isinstance(completion, dict) or not isinstance(artifacts, list):
        _raise_render("evaluation report inputs have invalid types")
    try:
        validate_payload("evaluation-completion", completion)
    except ContractError as error:
        _raise_render("evaluation completion contract failed", error)
    if (
        completion.get("session_id") != checked_plan["session_id"]
        or completion.get("plan_integrity_hash") != checked_plan["plan_integrity_hash"]
        or completion.get("review_identity_hash") != checked_plan["review_identity_hash"]
    ):
        _raise_render("evaluation completion does not bind the plan")
    _reject_claim_text(checked_plan)
    _reject_claim_text(completion)
    _reject_claim_text(artifacts)
    artifact_hashes = [_validate_worker_envelope(item, checked_plan) for item in artifacts]
    if len(artifact_hashes) != len(set(artifact_hashes)):
        _raise_render("evaluation artifacts contain duplicate envelopes")
    if sorted(artifact_hashes) != completion["accepted_artifact_hashes"]:
        _raise_render("evaluation artifact hashes do not match completion")
    reviewer_hashes = sorted(
        item["envelope_hash"]
        for item in artifacts
        if item["artifact_type"] == "reviewer_result"
    )
    verifier_hashes = sorted(
        item["envelope_hash"]
        for item in artifacts
        if item["artifact_type"] == "verifier_result"
    )
    expected_reviewer_hashes = (
        []
        if completion["reviewer_artifact_hash"] is None
        else [completion["reviewer_artifact_hash"]]
    )
    if (
        reviewer_hashes != expected_reviewer_hashes
        or verifier_hashes != completion["verifier_artifact_hashes"]
    ):
        _raise_render("evaluation artifact roles do not match completion")

    assurance = completion["assurance_contract_under_test"]
    coverage = completion["coverage"]
    accounting = completion["accounting"]
    lines = [
        "---",
        "title: Synthetic protocol evaluation — not a code-review result",
        "document_kind: evaluation_report",
        "authority: synthetic_evaluation",
        "authoritative_review: false",
        "profile: evaluation_slice_v2",
        "release_ready: false",
        "---",
        "",
        "# Synthetic protocol evaluation — not a code-review result",
        "",
        "This is a non-authoritative protocol fixture. It makes no claim that the target is clean, including when the simulated verdict is `clean`.",
        "",
        "## Synthetic fixture state",
        "",
        f"- simulated_review_verdict: {_inline(completion['simulated_review_verdict'])}",
        f"- protocol_completeness: {_inline(completion['protocol_completeness'])}",
        f"- synthetic_total_atoms: {_inline(coverage['total_atoms'])}",
        f"- synthetic_reviewed_atoms: {_inline(coverage['reviewed_atoms'])}",
        f"- synthetic_manual_atoms: {_inline(coverage['manual_atoms'])}",
        f"- synthetic_canonical_findings: {_inline(accounting['canonical_findings'])}",
        "",
        "## Assurance contract under test",
        "",
    ]
    for key in sorted(assurance):
        lines.append(f"- {key}: {_inline(assurance[key])}")
    if completion["worker_dispatch_state"] == "not_applicable_no_reviewable_atoms":
        lines.extend(
            ["", "No worker was dispatched for this all-manual fixture."]
        )

    for index, record in enumerate(completion["canonical_finding_records"], start=1):
        root = record["root_cause"]
        lines.extend(
            [
                "",
                f"### Synthetic fixture finding {index}",
                "",
                f"- synthetic_title: {_inline(root['title'])}",
                f"- synthetic_severity: {_inline(record['merged_final_severity'])}",
                f"- synthetic_location: {_inline(str(root['file']) + ':' + str(root['line']))}",
                f"- synthetic_failure_scenario: {_inline(root['failure_scenario'])}",
                f"- synthetic_why_diff: {_inline(root['why_diff'])}",
            ]
        )
        _append_synthetic_values(lines, "evidence", root["evidence"])
        lines.append("- synthetic_confirmed_instances:")
        for instance in record["confirmed_instances"]:
            lines.extend(
                [
                    "  - synthetic_confirmed_instance:",
                    f"    - synthetic_candidate_hash: {_inline(instance['candidate_hash'])}",
                    f"    - synthetic_duplicate_ordinal: {_inline(instance['duplicate_ordinal'])}",
                    "    - synthetic_verifier_result_envelope_hash: "
                    + _inline(instance["verifier_result_envelope_hash"]),
                    f"    - synthetic_instance_final_severity: {_inline(instance['final_severity'])}",
                ]
            )
        for label in (
            "proof",
            "provenance",
            "best_fix",
            "refactor_judgment",
            "residual_risk",
        ):
            _append_synthetic_values(lines, label, record[label])
        lines.append(
            "- synthetic_canonical_finding_hash: "
            + _inline(record["canonical_finding_hash"])
        )

    if completion["verifier_disposition_records"]:
        lines.extend(["", "## Synthetic fixture verifier dispositions", ""])
        for index, disposition in enumerate(
            completion["verifier_disposition_records"], start=1
        ):
            lines.extend(
                [
                    f"### Synthetic fixture verifier disposition {index}",
                    "",
                    f"- synthetic_candidate_hash: {_inline(disposition['candidate_hash'])}",
                    f"- synthetic_duplicate_ordinal: {_inline(disposition['duplicate_ordinal'])}",
                    "- synthetic_verifier_result_envelope_hash: "
                    + _inline(disposition["verifier_result_envelope_hash"]),
                    f"- synthetic_disposition: {_inline(disposition['disposition'])}",
                    "- synthetic_final_severity: "
                    + _inline(
                        "null"
                        if disposition["final_severity"] is None
                        else disposition["final_severity"]
                    ),
                ]
            )
    for index, record in enumerate(completion["manual_item_records"], start=1):
        lines.extend(
            [
                "",
                f"### Synthetic fixture manual item {index}",
                "",
                f"- synthetic_manual_domain: {_inline(record['domain'])}",
                f"- synthetic_manual_item_hash: {_inline(record['manual_item_hash'])}",
            ]
        )
        if record["domain"] == "adapter_manual_disposition":
            disposition = record["disposition"]
            lines.extend(
                [
                    f"- synthetic_manual_path: {_inline(disposition['path'])}",
                    f"- synthetic_manual_reason: {_inline(disposition['reason'])}",
                    f"- synthetic_manual_disposition_id: {_inline(disposition['disposition_id'])}",
                    "- synthetic_manual_atom_ids:",
                    *(
                        f"  - synthetic_manual_atom_id: {_inline(atom_id)}"
                        for atom_id in disposition["atom_ids"]
                    ),
                ]
            )
        else:
            lines.extend(
                [
                    f"- synthetic_candidate_hash: {_inline(record['candidate_hash'])}",
                    f"- synthetic_duplicate_ordinal: {_inline(record['duplicate_ordinal'])}",
                    "- synthetic_verifier_result_envelope_hash: "
                    + _inline(record["verifier_result_envelope_hash"]),
                ]
            )
    content = "\n".join(lines) + "\n"
    _safe(content, "rendered evaluation")
    if not _evaluation_markers_valid(content):
        _raise_render("rendered evaluation is missing truthful fixed markers")
    if _contains_hard_claim(content):
        _raise_render("rendered evaluation contains a forbidden hard claim")
    if _contains_false_clean_claim(content):
        _raise_render("rendered evaluation contains forbidden outcome wording")
    return content


def _validate_reason_list(
    reasons: object, *, allowlist: set[str], label: str
) -> list[str]:
    if (
        not isinstance(reasons, list)
        or not reasons
        or any(not isinstance(reason, str) for reason in reasons)
        or reasons != sorted(set(reasons))
        or any(reason not in allowlist for reason in reasons)
    ):
        _raise_render(f"{label} are invalid")
    _safe(reasons, label)
    return reasons


def render_diagnostic_report(
    *,
    plan: dict | None,
    state: str,
    reasons: list[str],
    assurance_state: dict,
) -> str:
    """Render a blocked/incomplete diagnostic without review-result language."""

    if plan is None:
        if state != "blocked":
            _raise_render("pre-session diagnostic state must be blocked")
        checked_plan = None
        checked_reasons = _validate_reason_list(
            reasons, allowlist=_BLOCKED_REASONS, label="blocked diagnostic reasons"
        )
    else:
        checked_plan = _validate_plan(plan)
        if state != "incomplete":
            _raise_render("post-Store diagnostic state must be incomplete")
        checked_reasons = _validate_reason_list(
            reasons,
            allowlist=_INCOMPLETE_REASONS,
            label="incomplete diagnostic reasons",
        )
    _safe(assurance_state, "diagnostic assurance")
    if not isinstance(assurance_state, dict) or assurance_state != _DIAGNOSTIC_ASSURANCE:
        _raise_render("diagnostic assurance state is not the exact guarded tuple")
    _reject_claim_text(checked_reasons)
    _reject_claim_text(assurance_state)

    lines = [
        "---",
        "title: Synthetic protocol diagnostic — not a code-review result",
        "document_kind: diagnostic_report",
        "authority: non_authoritative_diagnostic",
        "authoritative_review: false",
        "profile: evaluation_slice_v2",
        "release_ready: false",
        "---",
        "",
        "# Synthetic protocol diagnostic — not a code-review result",
        "",
        "This non-authoritative view records an incomplete protocol state. It provides no code-review result.",
        "",
        f"- state: {_inline(state)}",
        f"- pre_session: {'true' if checked_plan is None else 'false'}",
        "- residual_tool_surface: `unknown`",
        "- worker_child_environment: `not_verified`",
        "",
        "## Stable reason codes",
        "",
        *(f"- {_inline(reason)}" for reason in checked_reasons),
        "",
        "## Current guarded limitations",
        "",
    ]
    for key in sorted(assurance_state):
        lines.append(f"- {key}: {_inline(assurance_state[key])}")
    content = "\n".join(lines) + "\n"
    _safe(content, "rendered diagnostic")
    if not _diagnostic_markers_valid(content):
        _raise_render("rendered diagnostic is missing truthful fixed markers")
    if _contains_false_clean_claim(content) or _contains_hard_claim(content):
        _raise_render("rendered diagnostic contains forbidden outcome wording")
    return content


def validate_report_artifact_payload(artifact_type: object, payload: object) -> None:
    """Validate the exact content-addressed payload stored for one report view."""

    if artifact_type not in _REPORT_BASENAMES:
        _raise_render("report artifact type is invalid")
    _safe(payload, "report artifact")
    if not isinstance(payload, dict) or set(payload) != _REPORT_FIELDS:
        _raise_render("report artifact payload fields mismatch")
    if (
        payload.get("report_contract_version") != REPORT_CONTRACT_VERSION
        or payload.get("document_kind") != artifact_type
        or payload.get("media_type") != MARKDOWN_MEDIA_TYPE
        or not isinstance(payload.get("content"), str)
    ):
        _raise_render("report artifact fixed fields mismatch")
    content = payload["content"]
    expected_hash = hashlib.sha256(_content_bytes(content)).hexdigest()
    if payload.get("content_sha256") != expected_hash:
        _raise_render("report artifact content hash mismatch")
    markers_valid = (
        _evaluation_markers_valid(content)
        if artifact_type == "evaluation_report"
        else _diagnostic_markers_valid(content)
    )
    if not markers_valid:
        _raise_render("report artifact truthful markers mismatch")
    if _contains_hard_claim(content):
        _raise_render("report artifact contains a forbidden hard claim")
    if _contains_false_clean_claim(content):
        _raise_render("report artifact contains forbidden outcome wording")


def make_report_payload(document_kind: str, content: str) -> dict:
    """Build the exact content-addressed Store payload for rendered Markdown."""

    if document_kind not in _REPORT_BASENAMES or not isinstance(content, str):
        _raise_render("report payload inputs are invalid")
    payload = {
        "report_contract_version": REPORT_CONTRACT_VERSION,
        "document_kind": document_kind,
        "media_type": MARKDOWN_MEDIA_TYPE,
        "content_sha256": hashlib.sha256(_content_bytes(content)).hexdigest(),
        "content": content,
    }
    validate_report_artifact_payload(document_kind, payload)
    return payload


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("write made no progress")
        offset += written


def _open_parent_directory(parent: Path) -> int:
    """Open/create one absolute parent without ever following a symlink component."""

    if not parent.is_absolute() or any(part in {"", ".", ".."} for part in parent.parts[1:]):
        raise ValueError("invalid materialization parent")
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("no-follow directory operations are unavailable")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC

    descriptor = os.open(parent.anchor, directory_flags)
    try:
        for component in parent.parts[1:]:
            try:
                child = os.open(component, directory_flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=descriptor)
                child = os.open(component, directory_flags, dir_fd=descriptor)
            child_stat = os.fstat(child)
            if not stat.S_ISDIR(child_stat.st_mode):
                os.close(child)
                raise ValueError("materialization parent component is not a directory")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _parent_path_matches_descriptor(parent: Path, descriptor: int) -> bool:
    try:
        path_stat = os.stat(parent, follow_symlinks=False)
        descriptor_stat = os.fstat(descriptor)
    except OSError:
        return False
    return (
        stat.S_ISDIR(path_stat.st_mode)
        and path_stat.st_dev == descriptor_stat.st_dev
        and path_stat.st_ino == descriptor_stat.st_ino
    )


def _materialize(path: Path, content: str, *, allowed_basename: str) -> Path:
    parent_descriptor: int | None = None
    temporary_name: str | None = None
    try:
        if not isinstance(path, Path) or not isinstance(content, str):
            raise ValueError("invalid materialization inputs")
        normalized = Path(os.path.normpath(os.fspath(path)))
        if (
            not path.is_absolute()
            or path != normalized
            or path.name != allowed_basename
        ):
            raise ValueError("invalid materialization destination")
        _safe(content, "materialized view")
        parent_descriptor = _open_parent_directory(path.parent)
        if not _parent_path_matches_descriptor(path.parent, parent_descriptor):
            raise ValueError("materialization parent identity mismatch")

        try:
            destination_stat = os.stat(
                path.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
        except FileNotFoundError:
            destination_stat = None
        if destination_stat is not None:
            if not stat.S_ISREG(destination_stat.st_mode):
                raise ValueError("destination is not a regular file")
        temporary_name = f".{path.name}.tmp-{uuid.uuid4().hex}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        content_bytes = _content_bytes(content)
        descriptor = os.open(
            temporary_name, flags, 0o600, dir_fd=parent_descriptor
        )
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, content_bytes)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if not _parent_path_matches_descriptor(path.parent, parent_descriptor):
            raise OSError("materialization parent changed before publication")
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_name = None
        os.fsync(parent_descriptor)
        if not hasattr(os, "O_NONBLOCK"):
            raise OSError("nonblocking readback is unavailable")
        read_flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            read_flags |= os.O_CLOEXEC
        read_descriptor = os.open(
            path.name, read_flags, dir_fd=parent_descriptor
        )
        try:
            destination_stat = os.fstat(read_descriptor)
            if (
                not stat.S_ISREG(destination_stat.st_mode)
                or stat.S_IMODE(destination_stat.st_mode) != 0o600
            ):
                raise OSError("materialized file type or mode mismatch")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(read_descriptor, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
            if b"".join(chunks) != content_bytes:
                raise OSError("materialized bytes mismatch")
        finally:
            os.close(read_descriptor)
        if not _parent_path_matches_descriptor(path.parent, parent_descriptor):
            raise OSError("materialization parent changed after publication")
        return path
    except Exception as error:
        if temporary_name is not None and parent_descriptor is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except OSError:
                pass
        raise MaterializationError("materialized view could not be written") from error
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def materialize_non_authoritative_view(
    *, sibling_path: Path, content: str, document_kind: str
) -> Path:
    """Atomically replace one exact non-authoritative evaluation/diagnostic view."""

    if document_kind not in _REPORT_BASENAMES:
        raise MaterializationError("materialized view could not be written")
    try:
        payload = make_report_payload(document_kind, content)
    except RenderError as error:
        raise MaterializationError("materialized view could not be written") from error
    return _materialize(
        sibling_path,
        payload["content"],
        allowed_basename=_REPORT_BASENAMES[document_kind],
    )


def write_recovery_diagnostic(
    *, sibling_path: Path, reason_codes: list[str]
) -> Path:
    """Write a reason-code-only view after canonical integrity was lost."""

    try:
        checked = _validate_reason_list(
            reason_codes, allowlist=_RECOVERY_REASONS, label="recovery reason codes"
        )
        lines = [
            "# Integrity recovery diagnostic — non-authoritative",
            "",
            "This view is non-authoritative because canonical state could not be verified.",
            "It contains only stable recovery codes and no interpretation of unverified bytes.",
            "",
            "## Stable recovery reason codes",
            "",
            *(f"- {_inline(reason)}" for reason in checked),
            "",
        ]
        content = "\n".join(lines)
        _safe(content, "recovery diagnostic")
    except RenderError as error:
        raise MaterializationError("materialized view could not be written") from error
    return _materialize(
        sibling_path, content, allowed_basename=_RECOVERY_BASENAME
    )
