# Security policy

This is an experimental review tool. It is not an approval authority or a
replacement for human review, dependency scanning, secret scanning, or CodeQL.

If you find a vulnerability in this tool, use the repository's private security
advisory feature when it is available. Do not include API keys or unredacted
findings from another project in a public issue. If private reporting is not
enabled, open a minimal issue requesting a private reporting channel without
exploit details or credentials.

Supported version: the current default branch during this pilot. Review
maintainer changes to workflows, prompts, manifest files and price tables before
running a workflow with a secret. Public Actions summaries expose only
allowlisted usage, cost, size, coverage and finding-count metrics. Detailed
findings, model-written text and full reports are not uploaded as artifacts.
Use the local CLI to inspect full reports, and review those reports before any
publication. Repository history and existing Actions logs also become public
when converting a private repository to public.

