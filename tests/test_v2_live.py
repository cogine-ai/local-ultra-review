from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from local_ultra_review import backend as backend_module  # noqa: E402
from local_ultra_review.backend import CodexCliBackend  # noqa: E402
from local_ultra_review.orchestrator import EvaluationRequest, evaluate  # noqa: E402


LIVE_ENABLED = os.environ.get("LOCAL_ULTRA_REVIEW_RUN_LIVE_CODEX_DIAGNOSTIC") == "1"


@unittest.skipUnless(
    LIVE_ENABLED,
    "set LOCAL_ULTRA_REVIEW_RUN_LIVE_CODEX_DIAGNOSTIC=1 for diagnostic-only smoke",
)
class LiveCodexDiagnosticTests(unittest.TestCase):
    def required_path(self, name: str) -> Path:
        value = os.environ.get(name)
        self.assertTrue(value, f"{name} is required when live diagnostic smoke is enabled")
        return Path(value).expanduser().resolve()

    def test_live_adapter_remains_blocked_without_version_or_semantic_execution(self) -> None:
        codex_path = self.required_path("LOCAL_ULTRA_REVIEW_LIVE_CODEX_PATH")
        record = self.required_path("LOCAL_ULTRA_REVIEW_LIVE_QUALIFICATION_RECORD")
        model = os.environ.get("LOCAL_ULTRA_REVIEW_LIVE_MODEL")
        self.assertTrue(
            model,
            "LOCAL_ULTRA_REVIEW_LIVE_MODEL is required when live diagnostic smoke is enabled",
        )
        expected_hash = hashlib.sha256(codex_path.read_bytes()).hexdigest()

        no_process = mock.patch.object(
            backend_module,
            "_run_process",
            side_effect=AssertionError("live Codex process execution is forbidden"),
        )
        with no_process:
            backend = CodexCliBackend(
                codex_path=codex_path,
                model=model,
                qualification_record=record,
            )
        readiness = backend.readiness()
        identity = backend.semantic_identity()
        self.assertEqual(identity["cli_binary_sha256"], expected_hash)
        self.assertEqual(
            identity["cli_binary_identity_scope"], "unexecuted_nofollow_file_object"
        )
        self.assertIsNone(identity["cli_version"])
        self.assertFalse(identity["version_probe_executed"])
        self.assertFalse(readiness["live_dispatch_authorized"])
        self.assertEqual(
            readiness["live_dispatch_blockers"],
            [
                "canonical_inventory_oracle_unavailable",
                "object_bound_version_probe_unavailable",
            ],
        )

        if os.environ.get("LOCAL_ULTRA_REVIEW_RUN_LIVE_CODEX_ENV_PREFLIGHT") == "1":
            scratch = self.required_path("LOCAL_ULTRA_REVIEW_LIVE_PREFLIGHT_SCRATCH")
            real_run = backend_module._run_process
            observed: list[list[str]] = []

            def canary_only(argv, **kwargs):
                rendered = [str(value) for value in argv]
                observed.append(rendered)
                self.assertEqual(Path(rendered[0]).resolve(), Path(sys.executable).resolve())
                self.assertIn("-I", rendered)
                self.assertNotIn("--version", rendered)
                self.assertNotEqual(Path(rendered[0]).resolve(), codex_path)
                return real_run(argv, **kwargs)

            with mock.patch.object(backend_module, "_run_process", side_effect=canary_only):
                evidence = backend.preflight_worker_environment(scratch)
            self.assertEqual(evidence["status"], "passed")
            self.assertTrue(observed)
            self.assertFalse(backend.readiness()["live_dispatch_authorized"])

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        request = EvaluationRequest(
            repo=root / "repo-not-opened",
            base="explicit-base",
            head="explicit-head",
            model=model,
            session_root=root / "session",
        )
        with (
            mock.patch.object(
                backend_module,
                "_run_process",
                side_effect=AssertionError("live Codex process execution is forbidden"),
            ),
            mock.patch.object(backend, "run", wraps=backend.run) as run_worker,
        ):
            outcome = evaluate(request, backend)
        run_worker.assert_not_called()
        self.assertEqual(outcome.diagnostic["status"], "blocked")
        self.assertEqual(outcome.diagnostic_path, (root / "diagnostic.md").resolve())
        self.assertTrue(outcome.diagnostic_path.is_file())
        self.assertFalse(request.session_root.exists())


if __name__ == "__main__":
    unittest.main()
