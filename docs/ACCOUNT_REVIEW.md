# One central start point and one result inbox

Use **Review my public repositories**, then this central repository's **Security → Code scanning**. Reading keys, recovery tests and ZIPs are not part of this path. Existing keys and encrypted files are not deleted; the legacy encrypted pilot is optional.

## Authentication

Use the existing `OPENAI_API_KEY` repository Actions Secret. If unavailable, check its name and repository/environment scope—not a GitHub PAT or reading key. The workflow cannot recover secret values or prove a saved key is valid without an actual API call.

No cross-repository write permission, personal access token or GitHub App installation is required in this mode. The ephemeral Actions token has `contents: read` and `security-events: write` in the central repository only. Target metadata/code is read through unauthenticated public endpoints. OpenAI and GitHub writer credentials are exposed to different steps. Fetched source is never executed.

## Discovery, scope and cost

The owner is derived from the central repository. The public owned inventory is paginated; forks, archived/disabled repositories and the central tool itself are excluded. At most three targets are selected per invocation, prioritizing those not previously reviewed under this policy. Completed central analyses record the source commit. Unchanged successful selections are skipped on later invocations. New repositories require no per-repository registration.

Each target selects at most 16 supported source/configuration files and 160 KB. Security-boundary filenames are prioritized. This is a heuristic selection, not a whole-repository audit. Unsupported files, oversized trees, exclusions and deferred targets remain explicit. At most 1,000 inventory entries and 20 target metadata inspections are attempted; incomplete pagination stops rather than claiming complete coverage.

Selected source is pinned to immutable commit/blob hashes and verified by the existing downloader. The CLI rejects incomplete selected inputs before paid generation. Paid calls occur only on `workflow_dispatch`, never push/PR. Push performs API-free inventory and synthetic inbox checks. Model: `gpt-6.1-sol`; at most three generations, USD 1 published-price estimate per invocation. This is not an account/monthly/provider hard limit. There are no automatic paid retries. Inspect ambiguous usage before starting again.

## What the inbox contains

Completed results are uploaded as SARIF to the central repository, not each target repository. The primary displayed location is `docs/RESULTS.md`, a stable inbox anchor. Each finding's text identifies the real target repository, immutable commit, original file/line range, evidence, fix and source link. Native inline target-file annotations and autofix are not provided by this aggregated mode.

A summary entry is informational, not a vulnerability. AI findings are hypotheses; zero findings is not a security guarantee. Incomplete reports do not replace previous complete findings with an empty scan. Delivery is successful only after GitHub reports analysis processing complete.

Detailed findings are not published to logs, artifacts, PR comments or custom check annotations. Public summaries contain fixed statuses, counts, selected sizes, cost estimates and links. The central Security view follows GitHub's repository security permissions, not owner-only access. GitHub runners/OpenAI process plaintext. Malicious maintainers, runner compromise, platform changes and network/delivery failures remain trust boundaries. Full report recovery after runner loss is not guaranteed.

## Verified and not yet verified

On 2026-10-31, `Result inbox readiness` run 41223200066 succeeded using only the central ephemeral token: synthetic SARIF storage, authenticated retrieval, anonymous alert-API denial, and absence of its marker in the inspected public commit checks/annotations. This is a scoped smoke test, not exhaustive verification of every GitHub UI/notification disclosure path.

That run received an empty `OPENAI_API_KEY` environment value. This proves the key was unavailable to that workflow, not where or under which name a user previously saved a key. Actual paid account-review completion remains unverified. Never post a key value to chat, public code or issues.

References: [SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support), [alert permissions](https://docs.github.com/en/code-security/how-tos/manage-security-alerts/manage-code-scanning-alerts/assess-alerts), [GITHUB_TOKEN scope](https://docs.github.com/en/actions/concepts/security/github_token).
