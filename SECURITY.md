# Security policy

This is an experimental security-review utility, **not** an approval authority or a replacement for human security review, dependency scanning, secret scanning, or CodeQL.

## Reporting vulnerabilities

Use GitHub's private vulnerability reporting / security advisory functionality when available. Do not post exploit details, secret values, or unredacted AI findings in public issues or pull requests. If private reporting is unavailable, open a minimal public issue requesting a secure contact channel, without sensitive details.

## Maintainer and user responsibilities

- Use a dedicated, least-privilege OpenAI API key stored as the `OPENAI_API_KEY` Actions secret. Do not commit it, put it in workflow inputs, or paste it into issue discussions.
- Forks **do not inherit** the upstream Actions secrets. Fork users must add their own OpenAI key.
- Do not treat the API key as cryptographically confined to GitHub or this repository. Control usage through the OpenAI project and spending settings as well.
- Review changes to the default branch, workflows, prompts, source selection and pricing data **before** running the manual workflow. Collaborators with write access are in this trust boundary.
- Public Actions summaries publish only allowlisted counts, sizes, token usage and cost. Findings text and full reports are not uploaded, but the metadata is publicly visible.
- The configured application cost guard is per invocation, not an account-wide hard cap.
- Static AI findings are hypotheses, not security guarantees. The source-selection manifest covers only explicitly chosen files.

See [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) for verified properties, remaining risks and recommended validation. Supported version during the pilot: latest default branch.
