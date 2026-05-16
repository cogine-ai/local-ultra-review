# local-ultra-review

Local Ultra Review is a portable agent skill for deep, local, read-only code review. It maps cloud Ultra Review mechanics to local primitives: git worktrees, focused reviewer lenses, verifier gating, dedupe, and severity-ranked reports.

Use the skill directly from an agent that supports skills:

```text
/local-ultra-review --base origin/main --mode deep
```

The skill defaults to no network, no secret copying, no product-code edits, and no unverified findings in the main report.

