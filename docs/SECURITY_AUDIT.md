# Implementation security review — 2026-10-31

**Status: public experimental utility, not production-approved and not a security certification.**

The earlier review chiefly documented design intent. This follow-up inspected implementation and reproduced negative cases with offline tests. Base revision: `d1bb6d116c86b15baabdb32214f5a6c90096dfd6`.

## Fixes in this review

| Area | Previous behavior | Corrected behavior |
| --- | --- | --- |
| Billing identity | Accepted arbitrary suffixes after a model name; assumed a missing service tier was standard; did not verify effective reasoning mode | Accept only the requested model or a valid dated snapshot, explicit standard/default service, and explicit standard reasoning mode. Unknown/mismatched billing metadata retains an unresolved reservation and stops subsequent requests. |
| Incomplete source selection | Could pay for a review before deciding that some selected source was omitted | Check all prepared cases before token counting or generation. A truncated/excluded selection prevents any live API request in that invocation. |
| Local file boundaries | Source-root ancestors could contain symlinks; manifest reading loaded the entire file before applying its limit | Walk directory descriptors without following symlinks; reject nonregular files/FIFOs; enforce the byte limit before and during reads. |
| Duplicate local execution | Two invocations could both pass the empty-output check before either wrote a report | Claim the output directory using an exclusive, retained `.run.lock`. This prevents accidental concurrent reuse of the same directory; it is not an account-wide budget. |
| Interrupted preflight | Unexpected token-counter errors could leave an in-progress checkpoint | Record an incomplete, generation-not-sent result and stop. Preserve only fixed numeric HTTP status/phase diagnostics, never API error bodies. |
| Manual paid workflow | Could run a revision without first running its offline tests | Run tests on the exact dispatched revision before making the API secret available to a step. |

Tests include positive controls, omitted/wrong billing fields, a valid dated snapshot, a bogus differently named model, truncated selections, symlink ancestors, FIFOs, oversized manifests, concurrent processes and private report permissions. API responses in these tests are **simulated**, not evidence of live model compatibility or detection quality.

## Trust boundary

- Only the manual workflow receives `OPENAI_API_KEY`; ordinary push/PR tests do not. Fork users supply their own key. Publishing source does not publish the Actions Secret.
- Repository write access is trusted. A maintainer can change code/workflows before dispatch. A default-branch check inside a workflow does not protect against someone who can rewrite that workflow.
- The model receives selected source as text with no execution tools. Fetched target code is not imported or executed. Source redaction is best-effort, not a confidentiality guarantee.
- The local manifest is **trusted configuration**. It can explicitly select a local source root; no-follow file access is not a sandbox that makes arbitrary third-party manifests safe. Inspect root paths and selections before using a key.
- Reports and the run marker use mode `0600`. The output-directory marker is intentionally retained after interruption. Inspect usage before starting a fresh run; do not remove the marker merely to retry automatically.
- API cost uses a dated public rate card. It is an estimate derived from usage, not a provider-enforced billing guarantee. Unexpected usage/conditions stop further calls but cannot undo a request already billed. Configure an OpenAI project hard limit for aggregate spending.

## Unresolved release gates

1. **No live benchmark execution was found at inspection time.** The GitHub `workflow_dispatch` run list was empty. Key registration, paid API compatibility, actual token consumption and finding quality remain unverified.
2. **Public Actions deliberately retain metrics only.** The detailed model report is neither logged nor uploaded and disappears with the runner. This prevents accidental public disclosure but means that the Actions-only path cannot validate finding quality. Use the local CLI in a trusted environment for detailed results; a private/encrypted result channel needs separate design before PR automation.
3. **Repository protection is not enabled.** At inspection, GitHub returned `protected: false` for `main` and no rulesets. This review does not claim to enable branch protection, environment approvals or private vulnerability reporting.
4. **Coverage is selected files only**, not entire repositories. No dynamic exploit validation, full-history secret-scanner certification or cross-account isolation test was performed.
5. **Do not advertise automatic PR review yet.** Reusable workflow integration, safe external-PR handling, quality validation and monthly budget orchestration remain future work.

## Decision

Keeping the code public as an explicitly experimental utility is reasonable after these fixes. Calling it production-ready, claiming that all repositories are protected, or promising that an API key can only be used from this repository is not supported.

## Primary references

- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [OpenAI input token counting](https://developers.openai.com/api/docs/guides/token-counting)
- [OpenAI prompt caching and usage accounting](https://developers.openai.com/api/docs/guides/prompt-caching)
- [OpenAI pricing](https://developers.openai.com/api/docs/pricing)
- [OpenAI spend limits](https://developers.openai.com/api/docs/guides/spend-limits)
