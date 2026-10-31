# Security policy

This is an experimental utility, not a security certification or replacement for CodeQL, dependency/secret scanning or human review.

## Standard account workflow

`Review my public repositories` discovers the central repository owner's public repositories. Its ephemeral Actions token can read contents and write code-scanning results in the central repository only. It does not need a user PAT or write access to target repositories. The OpenAI key is supplied only to the manual key-check and inference steps of this workflow. Automatic pushes run an API-free inventory/storage check, not paid inference.

The separate `Result inbox readiness` workflow checks the presence (not value or validity) of the existing OpenAI Secret and tests synthetic SARIF delivery. It can run on trusted default-branch pushes but never calls OpenAI. Pull-request unit/browser tests do not receive the OpenAI key.

Detailed completed findings are sent to the central repository's Security/Code scanning inbox. Model text, source bodies and SARIF are not logged, uploaded as artifacts or posted as PR comments. The primary location is an aggregation anchor; the actual target repository, commit and source location are in each finding. Users with the applicable security permissions can read results. This is not owner-only access.

GitHub runner/OpenAI process plaintext. Workflow maintainers, repository write access, browser/account security and GitHub's access-control implementation remain trust boundaries. Branch protection has not been enabled by this change. Synthetic public-access tests are scoped checks, not exhaustive verification of all UI/notification paths. Delivery failure or runner loss can lose a report even after an API request has been billed. Never blindly re-run ambiguous attempts.

## Keys and budgets

- Use a dedicated OpenAI project key in the central repository Secret `OPENAI_API_KEY`. Never put it in code, inputs, issues or chat.
- Forks do not inherit upstream Secrets. Each actual AI-review operator supplies their own API key and pays their own API usage. The upstream account is not a shared inference service.
- A leaked API key is not cryptographically restricted to GitHub. Use provider-side project spending controls and rotate on suspected exposure.
- The local USD 1 estimate and three-generation cap apply per invocation, not per account/month. Unresolved usage is not zero cost.
- Target code is text data only; it is not imported/executed and receives neither the GitHub writer token nor execution tools. Redaction and prompt-injection defenses remain best-effort.

## Legacy encrypted reports

The former age-key/ZIP recovery path is optional and remains for existing reports. Existing reading keys are not deleted or reused as API keys. The offline helper remains available; the standard hosted page is now a static start/result launcher with no key inputs, scripts or report decryption.

## Disclosure

Use private vulnerability reporting/security advisories when available. Do not put exploit details, tokens or unredacted findings in public issues. If private reporting is unavailable, request a private contact channel in a minimal issue without sensitive details.

See [account workflow boundaries](docs/ACCOUNT_REVIEW.md) and the historical [implementation audit](docs/SECURITY_AUDIT.md). Supported version during the pilot: current default branch.
