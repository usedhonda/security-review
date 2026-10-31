# Public release security review (2026-10-31)

This document records a **limited source inspection**, not a security certification.

## Verified properties

- This repository is public. The review tool's Python source, manifest and workflow definitions are therefore visible to everyone.
- API credentials are provided to the manual benchmark job through the GitHub Actions repository secret `OPENAI_API_KEY`. A fork does **not** inherit the upstream repository's Actions secrets.
- The normal push/PR job runs offline unit tests with `contents: read` permissions, without the API secret. The billable benchmark job is manually dispatched and checks that the run uses the default branch.
- The benchmark reads selected files at pinned public Git commits, verifies source digests, does not execute fetched project code and publishes allowlisted metrics rather than the complete model response.
- Generated detailed reports are **not** uploaded as Actions artifacts. Public Actions summaries still disclose case counts, selected code sizes, token consumption, API cost and finding counts.

## Remaining risks and limitations

1. **Repository secrets are not tied to a GitHub repository cryptographically.** A leaked OpenAI key can be used outside GitHub; scope it to a dedicated OpenAI project, set server-side spend controls, rotate if exposure is suspected.
2. **Users with write access can change the workflow or code before dispatching a new run.** The trusted default branch, write access, and merge process are part of the security boundary. Require PR review and protect the branch where appropriate.
3. **Third-party forks** need their own API key, their own review manifest and their own OpenAI account budget. Never tell users that installing or forking the repository automatically grants access to the upstream key.
4. **Public workflow runs** may show numeric findings counts. These can reveal review activity. Do not run the public workflow against private-source samples without independently reviewing the entire workflow and publication policy.
5. **The local $1 budget is per run, not a global/monthly OpenAI billing cap.** Manual repeated invocations add cost. Unknown usage after transport failures cannot be treated as a zero-charge request.
6. **Prompt injection / redaction** are mitigated on a best-effort basis, not eliminated. Review only code you are permitted to send to OpenAI.
7. **No live model review has been verified by this audit.** Passing offline unit tests proves neither API compatibility nor actual detection quality. Manual benchmark execution and inspection of results are required before claiming production readiness.

## Recommended validation prior to broader adoption

- Confirm that a manual `Security review pilot` run succeeds with a dedicated test API key and no secrets in logs.
- Inspect output status, usage telemetry and cost consistency; verify that any API error is reported as incomplete and does not publish model-authored findings.
- Compare reported vulnerabilities against the exact pinned file/line evidence and test reproducibility with human review.
- Do not enable arbitrary PR-triggered billable runs or privileged write access without a separate threat-model review.
