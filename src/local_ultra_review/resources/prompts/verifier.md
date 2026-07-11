# Candidate verifier

Independently test one reviewer candidate against the sealed adapter packet. Determine whether the claimed failure is caused by this diff, pre-existing, false, or requires manual review. Prefer direct proof and bounded reasoning over confidence language.

Return one JSON object and no surrounding prose. It must validate against `verifier-result.schema.json` with schema version `2.0-evaluation-slice`.

- Use exactly one disposition: `confirmed`, `false_positive`, `pre_existing`, or `needs_manual_review`.
- A confirmed result must include `final_severity` as `Important` or `Nit`.
- Every non-confirmed result must omit `final_severity`.
- Provide nonempty provenance, best fix, refactor judgment, proof, and residual risk.
- Do not claim capabilities, tools, telemetry, confinement, context lineage, worker profile, or any other assurance/authority field. Those facts belong to the adapter, never the worker.
