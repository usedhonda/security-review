# Security policy

This is an experimental utility, not a security certification or a replacement for human review, dependency scanning, secret scanning or CodeQL.

## Report vulnerabilities privately

Use GitHub private vulnerability reporting when available. Do not publish exploit details, credentials or unredacted findings in public issues/PRs. If private reporting is unavailable, request a confidential contact channel without including sensitive details.

## Keys and trust boundaries

- Each installation uses its own `OPENAI_API_KEY` repository secret and its own age public recipient in `REVIEW_AGE_RECIPIENT`. Forks must configure both. No upstream API or decryption key is distributed.
- Keep the age **private** identity only on a trusted local machine and secure backup. Never store it in GitHub Secrets, workflow inputs, repository files, artifacts or chat. The public recipient is stored as a Secret as a log-redaction precaution against input mistakes.
- An OpenAI key is not cryptographically confined to a repository. Use a dedicated project and provider-side spending controls; rotate on suspected exposure. The application's $1 estimate cap is per invocation, not a monthly guarantee.
- Workflow/default-branch write access is trusted. A malicious maintainer can exfiltrate plaintext before encryption or change the recipient. Branch protection, environment restrictions and review remain separate controls.
- Both the GitHub runner and OpenAI process plaintext during a review. This feature protects stored report contents from public artifact readers, not from those processors.

## Encrypted recovery policy

Detailed reports may be uploaded **only encrypted with age** to the configured native X25519 public recipient. Public summaries remain allowlisted numeric metrics and fixed statuses. Upload exactly `report.json.age`, never a directory, plaintext, identity, raw API response or downloaded source. Encryption failure has no plaintext fallback. Retention is seven days, not a guarantee of deletion of third-party copies.

The default manual mode is an API-free recovery probe. Paid review requires an explicit acknowledgement that the current key's probe was decrypted locally. This is an accidental-spend guard, not cryptographic proof of possession. Invalid/missing keys fail before API access.

Recovery holds decrypted output in memory until age succeeds, then checks repository/run/attempt/workflow revision and writes fixed filenames privately. It does not execute report content. age encryption is not a sender signature: download only from the intended trusted GitHub run. Compromised keys can expose previously captured ciphertext; key rotation protects future runs only.

A failed model request may still leave a recoverable checkpoint. Runner loss, cancellation or upload failure can still lose a report. Do not equate missing delivery with zero billing or no vulnerabilities; do not retry paid calls blindly. Local cleanup is not guaranteed secure erasure.

See [encrypted recovery](docs/ENCRYPTED_RECOVERY.md) and the [implementation review](docs/SECURITY_AUDIT.md). CI's disposable-key tests do not establish that a user's real key is configured, a real download succeeded, or a live model review is accurate. Supported version: current default branch during the pilot.
