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


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from local_ultra_review.contracts import (  # noqa: E402
    ContractError,
    SCHEMA_VERSION,
    canonical_json_bytes,
    load_schema,
    reject_worker_authority_fields,
    sha256_json,
    validate_payload,
)


HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64
HEX_D = "d" * 64
HEX_E = "e" * 64


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
    return {
        "worker_profile": "codex_native_guarded",
        "worker_boundary": "guarded_unconfined",
        "hard_worker_confinement": "not_provided",
        "input_discipline": "adapter_packet_minimized",
        "packet_only_read": "not_guaranteed",
        "residual_tool_surface": "unknown",
        "residual_tool_inventory": "unavailable",
        "accepted_tool_calls": "none_observed",
        "telemetry_scope": "observed_events_only",
        "worker_child_environment": "allowlist_preflight_passed",
        "filesystem_write_mitigation": "read_only_preflight_passed",
        "nested_web_search": "disabled_and_observed_absent",
        "broader_network_denial": "not_guaranteed",
        "connector_github_denial": "not_guaranteed",
        "ambient_secret_non_access": "not_guaranteed",
        "context_lineage": "fresh_process_inferred",
        "backend_stateless_attestation": "unavailable",
        "target_execution": "not_requested",
    }


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
        "coverage": {
            "total_atoms": 1,
            "reviewed_atoms": 1,
            "manual_atoms": 0,
        },
        "accounting": {
            "raw_candidates": 0,
            "verifier_results": 0,
            "confirmed_findings": 0,
            "false_positive": 0,
            "pre_existing": 0,
            "needs_manual_review": 0,
            "adapter_manual_items": 0,
        },
        "reviewer_artifact_hash": HEX_C,
        "verifier_artifact_hashes": [],
        "canonical_finding_hashes": [],
        "manual_item_hashes": [],
        "accepted_artifact_hashes": [HEX_C],
        "assurance_contract_under_test": assurance_contract_under_test(),
    }


class CanonicalJsonTests(unittest.TestCase):
    def test_canonical_json_is_stable_compact_sorted_utf8(self) -> None:
        left = {"z": [3, 2, 1], "accent": "café", "nested": {"b": 2, "a": 1}}
        right = {"nested": {"a": 1, "b": 2}, "accent": "café", "z": [3, 2, 1]}

        expected = '{"accent":"café","nested":{"a":1,"b":2},"z":[3,2,1]}'.encode()
        self.assertEqual(canonical_json_bytes(left), expected)
        self.assertEqual(canonical_json_bytes(left), canonical_json_bytes(right))
        self.assertEqual(sha256_json(left), hashlib.sha256(expected).hexdigest())

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
        payload["manual_item_hashes"] = [HEX_D]
        payload["accepted_artifact_hashes"] = [HEX_C]
        payload["simulated_review_verdict"] = "manual_review_required"
        validate_payload("evaluation-completion", payload)

        unsorted_hashes = copy.deepcopy(payload)
        unsorted_hashes["manual_item_hashes"] = [HEX_E, HEX_D]
        unsorted_hashes["accounting"]["adapter_manual_items"] = 2
        with self.assertRaises(ContractError):
            validate_payload("evaluation-completion", unsorted_hashes)


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
