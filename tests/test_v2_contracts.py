from __future__ import annotations

import copy
import hashlib
import importlib.resources
import os
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from local_ultra_review.contracts import (  # noqa: E402
    ALL_MANUAL_ASSURANCE,
    ContractError,
    ORCHESTRATION_CONTRACT_VERSION,
    SCHEMA_VERSION,
    SYNTHETIC_ATTEMPT_ASSURANCE,
    adapter_manual_item_hash,
    canonical_json_bytes,
    canonical_finding_hash,
    load_schema,
    prompt_contracts,
    reject_worker_authority_fields,
    review_identity_hash,
    schema_contracts,
    sha256_json,
    validate_semantic_plan,
    validate_payload,
    verifier_manual_item_hash,
)
from local_ultra_review.backend import (  # noqa: E402
    FAKE_BACKEND_VERSION,
    PROTOCOL_VERSION,
    RUN_MANIFEST_VERSION,
)
from local_ultra_review.redaction import (  # noqa: E402
    REDACTION_VERSION,
    RULESET_HASH,
    redaction_contract,
)


HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64
HEX_D = "d" * 64
HEX_E = "e" * 64
TOKEN = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def reviewer_payload(*, with_candidate: bool = True) -> dict:
    candidates = []
    if with_candidate:
        candidates.append(
            {
                "severity": "Important",
                "file": "src/example.py",
                "line": 12,
                "title": "State can be lost",
                "failure_scenario": "A retry overwrites the prior state.",
                "evidence": ["The retry branch assigns before it reads."],
                "why_diff": "The changed assignment reverses the ordering.",
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "task_id": "reviewer-correctness-1",
        "packet_hash": HEX_A,
        "status": "completed",
        "coverage": {
            "reviewed_atom_ids": ["atom-1"],
            "notes": "Reviewed the sealed atom.",
        },
        "candidates": candidates,
    }


def verifier_payload(*, disposition: str = "confirmed") -> dict:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "task_id": "verifier-1",
        "packet_hash": HEX_A,
        "candidate_hash": HEX_B,
        "status": "completed",
        "disposition": disposition,
        "provenance": "Introduced by the changed retry branch.",
        "best_fix": "Restore ownership at the retry boundary.",
        "refactor_judgment": "A local ownership fix is sufficient.",
        "proof": ["The failing branch is reachable after one retry."],
        "residual_risk": "Concurrency beyond one retry was not exercised.",
    }
    if disposition == "confirmed":
        payload["final_severity"] = "Important"
    return payload


def qualification_payload() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "record_kind": "diagnostic_evidence",
        "profile": "codex_native_guarded",
        "worker_boundary": "guarded_unconfined",
        "hard_worker_confinement": "not_provided",
        "cli_version": "0.144.0-alpha.4",
        "cli_binary_sha256": HEX_A,
        "launch_policy_sha256": HEX_B,
        "worker_environment_policy_sha256": HEX_C,
        "residual_tool_surface": "unknown",
        "residual_tool_inventory": "unavailable",
        "canonical_inventory_oracle": "unavailable",
        "inventory_scope": "known_observed_partial",
        "inventory_source": "worker_observed_only",
        "known_observed_exposures": ["exec_command", "web_search"],
        "observation_method": "Observed structured worker events.",
        "qualified_at": "2026-07-11T01:00:00Z",
        "expires_at": "2026-07-11T02:00:00Z",
        "telemetry_scope": "observed_events_only",
        "filesystem_write_mitigation": "read_only_preflight_passed",
        "nested_web_search": "disabled_and_observed_absent",
        "worker_environment_preflight_state": "allowlist_preflight_passed",
        "live_dispatch_authorized": False,
        "live_dispatch_blockers": ["canonical_inventory_oracle_unavailable"],
    }


def assurance_contract_under_test() -> dict:
    return dict(SYNTHETIC_ATTEMPT_ASSURANCE)


def canonical_finding_record() -> dict:
    payload = {
        "root_cause": {
            "file": "src/example.py",
            "line": 12,
            "title": "State can be lost",
            "failure_scenario": "A retry overwrites the prior state.",
            "evidence": ["The retry branch assigns before it reads."],
            "why_diff": "The changed assignment reverses the ordering.",
        },
        "merged_final_severity": "Important",
        "confirmed_instances": [
            {
                "candidate_hash": HEX_D,
                "duplicate_ordinal": 0,
                "verifier_result_envelope_hash": HEX_E,
                "final_severity": "Important",
            }
        ],
        "proof": ["The failing branch is reachable after one retry."],
        "provenance": ["Introduced by the changed retry branch."],
        "best_fix": ["Restore ownership at the retry boundary."],
        "refactor_judgment": ["A local ownership fix is sufficient."],
        "residual_risk": ["Concurrency beyond one retry was not exercised."],
    }
    return {**payload, "canonical_finding_hash": canonical_finding_hash(payload)}


def evaluation_completion_payload() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "authority": "synthetic_evaluation",
        "authoritative_review": False,
        "execution_backend": "fake_evaluation",
        "profile": "evaluation_slice_v2",
        "release_ready": False,
        "session_id": "session-1",
        "plan_integrity_hash": HEX_A,
        "review_identity_hash": HEX_B,
        "protocol_completeness": "complete",
        "simulated_review_verdict": "clean",
        "reviewer_execution_state": "completed",
        "worker_dispatch_state": "synthetic_attempts_accepted",
        "coverage": {
            "total_atoms": 1,
            "reviewed_atoms": 1,
            "manual_atoms": 0,
        },
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
        "reviewer_artifact_hash": HEX_C,
        "verifier_artifact_hashes": [],
        "canonical_finding_hashes": [],
        "canonical_finding_records": [],
        "manual_item_hashes": [],
        "manual_item_records": [],
        "accepted_artifact_hashes": [HEX_C],
        "assurance_contract_under_test": assurance_contract_under_test(),
    }


class CanonicalJsonTests(unittest.TestCase):
    def test_canonical_json_is_stable_compact_sorted_utf8(self) -> None:
        left = {"z": [3, 2, 1], "accent": "café", "nested": {"b": 2, "a": 1}}
        right = {"nested": {"a": 1, "b": 2}, "accent": "café", "z": [3, 2, 1]}

        expected = '{"accent":"café","nested":{"a":1,"b":2},"z":[3,2,1]}\n'.encode()
        self.assertEqual(canonical_json_bytes(left), expected)
        self.assertEqual(canonical_json_bytes(left), canonical_json_bytes(right))
        self.assertTrue(canonical_json_bytes(left).endswith(b"}\n"))
        self.assertFalse(canonical_json_bytes(left).endswith(b"\n\n"))
        self.assertEqual(
            sha256_json(left),
            "886dcb58bd5e38016b9bee35612a1c31e8259c6c9c4261e15dac66150269874b",
        )

    def test_non_json_values_raise_contract_error(self) -> None:
        with self.assertRaises(ContractError):
            canonical_json_bytes({"not-json": {1, 2}})


class ReviewerContractTests(unittest.TestCase):
    def test_valid_payload_and_empty_candidate_completion(self) -> None:
        validate_payload("reviewer-result", reviewer_payload())
        validate_payload("reviewer-result.schema.json", reviewer_payload(with_candidate=False))

    def test_additional_properties_are_rejected_at_every_level(self) -> None:
        mutations = []

        top_level = reviewer_payload()
        top_level["extra"] = True
        mutations.append(top_level)

        coverage = reviewer_payload()
        coverage["coverage"]["extra"] = True
        mutations.append(coverage)

        candidate = reviewer_payload()
        candidate["candidates"][0]["extra"] = True
        mutations.append(candidate)

        for payload in mutations:
            with self.subTest(payload=payload), self.assertRaises(ContractError):
                validate_payload("reviewer-result", payload)

    def test_terminal_candidate_fields_are_rejected(self) -> None:
        for field in (
            "status",
            "verification",
            "disposition",
            "confirmed",
            "final_severity",
        ):
            payload = reviewer_payload()
            payload["candidates"][0][field] = "worker-supplied"
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_payload("reviewer-result", payload)


class VerifierContractTests(unittest.TestCase):
    def test_confirmed_requires_bounded_final_severity(self) -> None:
        validate_payload("verifier-result", verifier_payload())

        missing = verifier_payload()
        del missing["final_severity"]
        with self.assertRaises(ContractError):
            validate_payload("verifier-result", missing)

        invalid = verifier_payload()
        invalid["final_severity"] = "Critical"
        with self.assertRaises(ContractError):
            validate_payload("verifier-result", invalid)

    def test_non_confirmed_dispositions_forbid_final_severity(self) -> None:
        for disposition in ("false_positive", "pre_existing", "needs_manual_review"):
            payload = verifier_payload(disposition=disposition)
            validate_payload("verifier-result", payload)

            payload["final_severity"] = "Nit"
            with self.subTest(disposition=disposition), self.assertRaises(ContractError):
                validate_payload("verifier-result", payload)


class WorkerAuthorityTests(unittest.TestCase):
    def test_forbidden_authority_fields_are_rejected_recursively(self) -> None:
        for field in (
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
        ):
            payload = {"safe": [{"nested": {field: "claimed"}}]}
            with self.subTest(field=field), self.assertRaises(ContractError):
                reject_worker_authority_fields(payload)

    def test_authority_words_as_values_are_not_rejected(self) -> None:
        reject_worker_authority_fields(
            {"notes": ["worker_profile", {"safe": "telemetry_scope"}]}
        )


class QualificationContractTests(unittest.TestCase):
    def test_diagnostic_record_is_valid_but_never_authorizes_dispatch(self) -> None:
        validate_payload("qualification-record", qualification_payload())

        authorized = qualification_payload()
        authorized["live_dispatch_authorized"] = True
        with self.assertRaises(ContractError):
            validate_payload("qualification-record", authorized)

        no_oracle_blocker = qualification_payload()
        no_oracle_blocker["live_dispatch_blockers"] = ["some_other_blocker"]
        with self.assertRaises(ContractError):
            validate_payload("qualification-record", no_oracle_blocker)

    def test_diagnostic_record_requires_exact_worker_boundary(self) -> None:
        schema = load_schema("qualification-record")
        self.assertEqual(
            schema["properties"]["worker_boundary"],
            {"const": "guarded_unconfined"},
        )
        self.assertEqual(
            schema["properties"]["hard_worker_confinement"],
            {"const": "not_provided"},
        )
        self.assertIn("worker_boundary", schema["required"])
        self.assertIn("hard_worker_confinement", schema["required"])

        for field in ("worker_boundary", "hard_worker_confinement"):
            missing = qualification_payload()
            del missing[field]
            with self.subTest(field=field, case="missing"), self.assertRaises(ContractError):
                validate_payload("qualification-record", missing)

        invalid_boundary = qualification_payload()
        invalid_boundary["worker_boundary"] = "unconfined"
        with self.assertRaises(ContractError):
            validate_payload("qualification-record", invalid_boundary)

        invalid_confinement = qualification_payload()
        invalid_confinement["hard_worker_confinement"] = "provided"
        with self.assertRaises(ContractError):
            validate_payload("qualification-record", invalid_confinement)

    def test_exposures_must_be_sorted_unique_nonempty_strings(self) -> None:
        unsorted_payload = qualification_payload()
        unsorted_payload["known_observed_exposures"] = ["web_search", "exec_command"]
        with self.assertRaises(ContractError):
            validate_payload("qualification-record", unsorted_payload)

        duplicate_payload = qualification_payload()
        duplicate_payload["known_observed_exposures"] = ["exec_command", "exec_command"]
        with self.assertRaises(ContractError):
            validate_payload("qualification-record", duplicate_payload)

        empty_item = qualification_payload()
        empty_item["known_observed_exposures"] = [""]
        with self.assertRaises(ContractError):
            validate_payload("qualification-record", empty_item)

    def test_qualification_timestamps_are_utc_and_expiry_is_later(self) -> None:
        offset_timestamp = qualification_payload()
        offset_timestamp["qualified_at"] = "2026-07-11T09:00:00+08:00"
        with self.assertRaises(ContractError):
            validate_payload("qualification-record", offset_timestamp)

        backwards = qualification_payload()
        backwards["expires_at"] = backwards["qualified_at"]
        with self.assertRaises(ContractError):
            validate_payload("qualification-record", backwards)


class EvaluationCompletionContractTests(unittest.TestCase):
    def test_completion_is_explicitly_synthetic_and_non_authoritative(self) -> None:
        validate_payload("evaluation-completion", evaluation_completion_payload())

        constant_mutations = {
            "authority": "canonical_review",
            "authoritative_review": True,
            "execution_backend": "codex_exec",
            "profile": "codex_native_guarded",
            "release_ready": True,
            "protocol_completeness": "partial",
        }
        for field, value in constant_mutations.items():
            payload = evaluation_completion_payload()
            payload[field] = value
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_payload("evaluation-completion", payload)

    def test_canonical_assurance_key_is_forbidden(self) -> None:
        payload = evaluation_completion_payload()
        payload["assurance"] = payload.pop("assurance_contract_under_test")
        with self.assertRaises(ContractError):
            validate_payload("evaluation-completion", payload)

    def test_cross_field_accounting_and_verdict_are_strict(self) -> None:
        bad_coverage = evaluation_completion_payload()
        bad_coverage["coverage"]["reviewed_atoms"] = 0
        with self.assertRaises(ContractError):
            validate_payload("evaluation-completion", bad_coverage)

        bad_counts = evaluation_completion_payload()
        bad_counts["accounting"]["raw_candidates"] = 1
        with self.assertRaises(ContractError):
            validate_payload("evaluation-completion", bad_counts)

        bad_accepted = evaluation_completion_payload()
        bad_accepted["accepted_artifact_hashes"] = [HEX_D]
        with self.assertRaises(ContractError):
            validate_payload("evaluation-completion", bad_accepted)

        bad_verdict = evaluation_completion_payload()
        bad_verdict["simulated_review_verdict"] = "findings"
        with self.assertRaises(ContractError):
            validate_payload("evaluation-completion", bad_verdict)

    def test_hash_arrays_must_be_sorted_and_manual_counts_must_match(self) -> None:
        payload = evaluation_completion_payload()
        payload["coverage"] = {"total_atoms": 2, "reviewed_atoms": 1, "manual_atoms": 1}
        payload["accounting"]["adapter_manual_items"] = 1
        disposition = {
            "path": "secret.env",
            "reason": "sensitive_path",
            "atom_ids": ["atom-1"],
            "disposition_id": "manual-" + HEX_D,
        }
        manual_hash = adapter_manual_item_hash(disposition)
        payload["manual_item_hashes"] = [manual_hash]
        payload["manual_item_records"] = [
            {
                "domain": "adapter_manual_disposition",
                "disposition": disposition,
                "manual_item_hash": manual_hash,
            }
        ]
        payload["accepted_artifact_hashes"] = [HEX_C]
        payload["simulated_review_verdict"] = "manual_review_required"
        validate_payload("evaluation-completion", payload)

        unsorted_hashes = copy.deepcopy(payload)
        unsorted_hashes["manual_item_hashes"] = [HEX_E, HEX_D]
        unsorted_hashes["accounting"]["adapter_manual_items"] = 2
        with self.assertRaises(ContractError):
            validate_payload("evaluation-completion", unsorted_hashes)

    def test_completed_and_all_manual_branches_are_bidirectional(self) -> None:
        completed = evaluation_completion_payload()
        for mutation in (
            {"reviewer_execution_state": "not_applicable_no_reviewable_atoms"},
            {"worker_dispatch_state": "not_applicable_no_reviewable_atoms"},
            {"reviewer_artifact_hash": None},
        ):
            payload = copy.deepcopy(completed)
            payload.update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ContractError):
                validate_payload("evaluation-completion", payload)

        disposition = {
            "path": "asset.bin",
            "reason": "binary_content",
            "atom_ids": ["atom-1", "atom-2"],
            "disposition_id": "manual-" + HEX_A,
        }
        item_hash = adapter_manual_item_hash(disposition)
        all_manual = evaluation_completion_payload()
        all_manual.update(
            {
                "reviewer_execution_state": "not_applicable_no_reviewable_atoms",
                "worker_dispatch_state": "not_applicable_no_reviewable_atoms",
                "reviewer_artifact_hash": None,
                "verifier_artifact_hashes": [],
                "accepted_artifact_hashes": [],
                "manual_item_hashes": [item_hash],
                "manual_item_records": [
                    {
                        "domain": "adapter_manual_disposition",
                        "disposition": disposition,
                        "manual_item_hash": item_hash,
                    }
                ],
                "assurance_contract_under_test": dict(ALL_MANUAL_ASSURANCE),
                "simulated_review_verdict": "manual_review_required",
            }
        )
        all_manual["coverage"] = {"total_atoms": 2, "reviewed_atoms": 0, "manual_atoms": 2}
        all_manual["accounting"]["adapter_manual_items"] = 1
        validate_payload("evaluation-completion", all_manual)

        for path, value in (
            (("accounting", "raw_candidates"), 1),
            (("accounting", "canonical_findings"), 1),
            (("coverage", "reviewed_atoms"), 1),
        ):
            mutated = copy.deepcopy(all_manual)
            mutated[path[0]][path[1]] = value
            with self.subTest(path=path), self.assertRaises(ContractError):
                validate_payload("evaluation-completion", mutated)

    def test_raw_canonical_membership_hashes_and_verdict_equations_are_exact(self) -> None:
        record = canonical_finding_record()
        payload = evaluation_completion_payload()
        payload["accounting"].update(
            {
                "raw_candidates": 1,
                "verifier_results": 1,
                "confirmed_candidate_dispositions": 1,
                "canonical_findings": 1,
            }
        )
        payload["verifier_artifact_hashes"] = [HEX_E]
        payload["canonical_finding_records"] = [record]
        payload["canonical_finding_hashes"] = [record["canonical_finding_hash"]]
        payload["accepted_artifact_hashes"] = sorted([HEX_C, HEX_E])
        payload["simulated_review_verdict"] = "findings"
        validate_payload("evaluation-completion", payload)

        mutations = []
        wrong_count = copy.deepcopy(payload)
        wrong_count["accounting"]["canonical_findings"] = 0
        mutations.append(wrong_count)
        duplicate_membership = copy.deepcopy(payload)
        duplicate_membership["canonical_finding_records"].append(copy.deepcopy(record))
        duplicate_membership["canonical_finding_hashes"] = [record["canonical_finding_hash"]]
        mutations.append(duplicate_membership)
        changed_proof = copy.deepcopy(payload)
        changed_proof["canonical_finding_records"][0]["proof"] = ["different proof"]
        mutations.append(changed_proof)
        severity_downgrade = copy.deepcopy(payload)
        severity_downgrade["canonical_finding_records"][0]["merged_final_severity"] = "Nit"
        severity_core = {
            key: value
            for key, value in severity_downgrade["canonical_finding_records"][0].items()
            if key != "canonical_finding_hash"
        }
        with self.assertRaises(ContractError):
            canonical_finding_hash(severity_core)
        wrong_verdict = copy.deepcopy(payload)
        wrong_verdict["simulated_review_verdict"] = "clean"
        mutations.append(wrong_verdict)
        for mutated in mutations:
            with self.subTest(mutated=mutated), self.assertRaises(ContractError):
                validate_payload("evaluation-completion", mutated)

    def test_manual_hash_domains_bind_complete_distinct_instances(self) -> None:
        disposition = {
            "path": "asset.bin",
            "reason": "binary_content",
            "atom_ids": ["atom-1"],
            "disposition_id": "manual-" + HEX_A,
        }
        adapter_hash = adapter_manual_item_hash(disposition)
        verifier_zero = verifier_manual_item_hash(HEX_B, 0, HEX_D)
        verifier_one = verifier_manual_item_hash(HEX_B, 1, HEX_E)
        self.assertNotEqual(adapter_hash, verifier_zero)
        self.assertNotEqual(verifier_zero, verifier_one)
        changed = copy.deepcopy(disposition)
        changed["reason"] = "special_file"
        self.assertNotEqual(adapter_hash, adapter_manual_item_hash(changed))

    def test_mixed_adapter_and_duplicate_verifier_manual_records_are_exact(self) -> None:
        disposition = {
            "path": "asset.bin",
            "reason": "binary_content",
            "atom_ids": ["atom-manual"],
            "disposition_id": "manual-" + HEX_A,
        }
        records = [
            {
                "domain": "adapter_manual_disposition",
                "disposition": disposition,
                "manual_item_hash": adapter_manual_item_hash(disposition),
            },
            {
                "domain": "verifier_needs_manual_review",
                "candidate_hash": HEX_B,
                "duplicate_ordinal": 0,
                "verifier_result_envelope_hash": HEX_D,
                "manual_item_hash": verifier_manual_item_hash(HEX_B, 0, HEX_D),
            },
            {
                "domain": "verifier_needs_manual_review",
                "candidate_hash": HEX_B,
                "duplicate_ordinal": 1,
                "verifier_result_envelope_hash": HEX_E,
                "manual_item_hash": verifier_manual_item_hash(HEX_B, 1, HEX_E),
            },
        ]
        payload = evaluation_completion_payload()
        payload["coverage"] = {"total_atoms": 2, "reviewed_atoms": 1, "manual_atoms": 1}
        payload["accounting"].update(
            {
                "raw_candidates": 2,
                "verifier_results": 2,
                "needs_manual_review": 2,
                "adapter_manual_items": 1,
            }
        )
        payload["verifier_artifact_hashes"] = [HEX_D, HEX_E]
        payload["accepted_artifact_hashes"] = sorted([HEX_C, HEX_D, HEX_E])
        payload["manual_item_records"] = records
        payload["manual_item_hashes"] = sorted(
            record["manual_item_hash"] for record in records
        )
        payload["simulated_review_verdict"] = "manual_review_required"
        validate_payload("evaluation-completion", payload)

        mutations = []
        missing = copy.deepcopy(payload)
        missing["manual_item_records"].pop()
        mutations.append(missing)
        arbitrary = copy.deepcopy(payload)
        arbitrary["manual_item_hashes"][0] = HEX_A
        arbitrary["manual_item_hashes"].sort()
        mutations.append(arbitrary)
        cross_spliced = copy.deepcopy(payload)
        first_hash = cross_spliced["manual_item_records"][0]["manual_item_hash"]
        cross_spliced["manual_item_records"][0]["manual_item_hash"] = (
            cross_spliced["manual_item_records"][1]["manual_item_hash"]
        )
        cross_spliced["manual_item_records"][1]["manual_item_hash"] = first_hash
        mutations.append(cross_spliced)
        duplicated = copy.deepcopy(payload)
        duplicated["manual_item_records"][2] = copy.deepcopy(
            duplicated["manual_item_records"][1]
        )
        duplicated["manual_item_hashes"] = sorted(
            {record["manual_item_hash"] for record in duplicated["manual_item_records"]}
        )
        mutations.append(duplicated)
        unaccepted = copy.deepcopy(payload)
        unaccepted["manual_item_records"][1]["verifier_result_envelope_hash"] = HEX_A
        unaccepted["manual_item_records"][1]["manual_item_hash"] = (
            verifier_manual_item_hash(HEX_B, 0, HEX_A)
        )
        unaccepted["manual_item_hashes"] = sorted(
            record["manual_item_hash"] for record in unaccepted["manual_item_records"]
        )
        mutations.append(unaccepted)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ContractError):
                validate_payload("evaluation-completion", mutation)

    def test_canonical_root_and_instance_memberships_are_globally_unique(self) -> None:
        first = canonical_finding_record()
        second = copy.deepcopy(first)
        second["confirmed_instances"] = [
            {
                "candidate_hash": HEX_A,
                "duplicate_ordinal": 1,
                "verifier_result_envelope_hash": HEX_D,
                "final_severity": "Nit",
            }
        ]
        second["merged_final_severity"] = "Nit"
        core = {key: value for key, value in second.items() if key != "canonical_finding_hash"}
        second["canonical_finding_hash"] = canonical_finding_hash(core)
        payload = evaluation_completion_payload()
        payload["accounting"].update(
            {
                "raw_candidates": 2,
                "verifier_results": 2,
                "confirmed_candidate_dispositions": 2,
                "canonical_findings": 2,
            }
        )
        payload["verifier_artifact_hashes"] = [HEX_D, HEX_E]
        payload["canonical_finding_records"] = [first, second]
        payload["canonical_finding_hashes"] = sorted(
            [first["canonical_finding_hash"], second["canonical_finding_hash"]]
        )
        payload["accepted_artifact_hashes"] = sorted([HEX_C, HEX_D, HEX_E])
        payload["simulated_review_verdict"] = "findings"
        with self.assertRaises(ContractError):
            validate_payload("evaluation-completion", payload)


class SemanticPlanContractTests(unittest.TestCase):
    def semantic_plan(self) -> dict:
        readiness = {
            "ready": True,
            "mode": "synthetic_evaluation_only",
            "authority": "synthetic_evaluation",
            "execution_backend": "fake_evaluation",
            "live_dispatch_authorized": False,
            "live_dispatch_blockers": ["fake_backend_has_no_live_authority"],
            "consumption_state": {
                "total_attempts": 0,
                "consumed_attempts": 0,
                "remaining_attempts": 0,
            },
        }
        identity = {
            "backend": "fake_evaluation",
            "backend_version": FAKE_BACKEND_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "run_manifest_version": RUN_MANIFEST_VERSION,
            "scenario_id": "all-manual",
            "total_attempts": 0,
            "expected_role_sequence": [],
            "unbound_attempt_templates_sha256": sha256_json([]),
        }
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
            "fake_readiness": readiness,
            "fake_semantic_identity": identity,
            "orchestration_contract_version": ORCHESTRATION_CONTRACT_VERSION,
            "run_manifest_version": RUN_MANIFEST_VERSION,
        }

    def test_exact_metadata_and_resource_hash_algorithms_work_from_foreign_cwd(self) -> None:
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            os.chdir(temporary)
            try:
                schemas = schema_contracts()
                prompts = prompt_contracts()
            finally:
                os.chdir(original)
        self.assertEqual(set(schemas), {"reviewer-result", "verifier-result", "evaluation-completion"})
        for name, contract in schemas.items():
            self.assertEqual(contract["schema_version"], SCHEMA_VERSION)
            self.assertEqual(contract["sha256"], sha256_json(load_schema(name)))
        self.assertEqual(set(prompts), {"reviewer-correctness", "verifier"})
        prompt_root = importlib.resources.files("local_ultra_review.resources").joinpath("prompts")
        for name, contract in prompts.items():
            self.assertEqual(set(contract), {"version", "sha256"})
            self.assertEqual(
                contract["sha256"],
                hashlib.sha256(prompt_root.joinpath(f"{name}.md").read_bytes()).hexdigest(),
            )
        self.assertEqual(
            redaction_contract(),
            {"version": REDACTION_VERSION, "ruleset_sha256": RULESET_HASH},
        )
        schemas["reviewer-result"]["sha256"] = HEX_A
        prompts["verifier"]["version"] = "mutated"
        redaction_contract()["version"] = "mutated"
        self.assertNotEqual(schema_contracts()["reviewer-result"]["sha256"], HEX_A)
        self.assertNotEqual(prompt_contracts()["verifier"]["version"], "mutated")
        self.assertEqual(redaction_contract()["version"], REDACTION_VERSION)

    def test_semantic_plan_exactness_and_review_identity_binding(self) -> None:
        semantic_plan = self.semantic_plan()
        validate_semantic_plan(semantic_plan)
        target_hash = HEX_A
        expected = sha256_json(
            {"target_identity_hash": target_hash, "semantic_plan": semantic_plan}
        )
        self.assertEqual(review_identity_hash(target_hash, semantic_plan), expected)

        for mutation in (
            lambda value: value.update(extra=True),
            lambda value: value.__setitem__("run_manifest_version", "wrong"),
            lambda value: value["fake_semantic_identity"].__setitem__("total_attempts", 1),
            lambda value: value["fake_readiness"]["consumption_state"].__setitem__("consumed_attempts", 1),
        ):
            invalid = copy.deepcopy(semantic_plan)
            mutation(invalid)
            with self.subTest(invalid=invalid), self.assertRaises(ContractError):
                validate_semantic_plan(invalid)

        two_attempts = copy.deepcopy(semantic_plan)
        two_attempts["fake_readiness"]["consumption_state"].update(
            total_attempts=2, remaining_attempts=2
        )
        two_attempts["fake_semantic_identity"].update(
            total_attempts=2,
            expected_role_sequence=["reviewer", "verifier"],
        )
        validate_semantic_plan(two_attempts)
        two_attempts["fake_semantic_identity"]["expected_role_sequence"] = [
            "reviewer",
            "reviewer",
        ]
        with self.assertRaises(ContractError):
            validate_semantic_plan(two_attempts)

    def test_untrusted_hash_inputs_are_safe_scanned_before_sha256(self) -> None:
        semantic_plan = self.semantic_plan()
        unsafe_plan = copy.deepcopy(semantic_plan)
        unsafe_plan["model"] = TOKEN
        disposition = {
            "path": TOKEN,
            "reason": "sensitive_path",
            "atom_ids": ["atom-1"],
            "disposition_id": "manual-" + HEX_A,
        }
        finding = {key: value for key, value in canonical_finding_record().items() if key != "canonical_finding_hash"}
        finding["proof"] = [TOKEN]
        calls = (
            lambda: review_identity_hash(HEX_A, unsafe_plan),
            lambda: adapter_manual_item_hash(disposition),
            lambda: verifier_manual_item_hash(TOKEN, 0, HEX_A),
            lambda: canonical_finding_hash(finding),
        )
        for call in calls:
            with self.subTest(call=call), mock.patch(
                "local_ultra_review.contracts.sha256_json"
            ) as hash_json:
                with self.assertRaises(ContractError):
                    call()
                hash_json.assert_not_called()


class PackagedResourceTests(unittest.TestCase):
    def test_schema_and_prompt_lookup_do_not_depend_on_cwd(self) -> None:
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary_directory:
            os.chdir(temporary_directory)
            try:
                self.assertEqual(load_schema("reviewer-result")["type"], "object")
                prompt = (
                    importlib.resources.files("local_ultra_review.resources")
                    .joinpath("prompts", "reviewer-correctness.md")
                    .read_text(encoding="utf-8")
                )
            finally:
                os.chdir(original_cwd)
        self.assertIn("reviewer-result.schema.json", prompt)

    def test_pyproject_declares_runtime_and_packaged_resources(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["requires-python"], ">=3.11")
        self.assertEqual(project["project"]["dependencies"], ["jsonschema>=4.20,<5"])
        self.assertEqual(
            project["project"]["scripts"]["local-ultra-review-v2"],
            "local_ultra_review.orchestrator:main",
        )
        package_data = project["tool"]["setuptools"]["package-data"]["local_ultra_review.resources"]
        self.assertIn("schemas/*.json", package_data)
        self.assertIn("prompts/*.md", package_data)


if __name__ == "__main__":
    unittest.main()
