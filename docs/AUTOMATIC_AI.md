# Original AI review on PR and main changes

This is the original `security-review` Responses API engine (`security_review.cli.run_experiment`), not CodeQL. The shared workflow lives in `.github/workflows/ai-review-reusable.yml` and uses an immutable engine commit. Existing manual account review remains available.

## Normal use

After a caller is installed and its key is available, creating/updating a PR to the default branch or pushing to that branch triggers AI automatically. There is no website start button, reading key, ZIP, or repository selection per run. The check is named **Review changed code with AI**.

The caller must have its own `OPENAI_API_KEY` Actions secret. A reusable workflow runs in the caller's context: **the secret saved in `usedhonda/security-review` is not available to `muse-agent-bridge` merely by calling it**. This requirement is verified by the real workflow, not presumed from a previous registration in another repository. Never copy a key into source, logs, a PR, or a chat. New caller repositories are not automatically configured by this change.

## Review behavior

The engine reviews the full current contents of supported source files changed between the event's pinned base and head, not an unrelated three-repository sample. Maximum 16 changed source files and 96 KB; a larger or unsupported source change fails explicitly before inference. Deleted source files currently need separate review; they do not silently receive a clean verdict. Non-source-only changes skip generation and explicitly say **no_supported_source_changes**, not **reviewed**. Base file contents and unchanged caller modules are not supplied, so this is a changed-file snapshot review, not a complete before/after or whole-repository audit.

The pilot supports owner-authored, same-repository PRs in public repositories and pushes to the default branch. Fork/contributor PRs are not authorized to spend the owner's API budget. They fail as unsupported rather than claiming an AI review. No `pull_request_target` or reviewed-code execution is used. Git blobs are verified against the pinned head tree and content hashes. Credentials, links, generated output, and unsafe paths are excluded or rejected.

Default estimated budget is USD 0.50 per event and one generation call. The engine performs token-count preflight and retains its original reservation and unknown-billing handling. This is **not a monthly or account-wide cap**. A PR and its subsequent merge can cause two reviews. There is no automatic retry; blind reruns are refused. Superseded PR/head revisions do not publish a current verdict.

## Result and repair boundary

Public Checks/logs contain only status, counts, costs, and fixed diagnostic labels. Detailed hypotheses, file links, and remediation guidance are stored in this caller repository's authenticated **Security → Code scanning**, under **Security Review AI Changes**. The upload is anchored to the default-branch inbox rather than a PR ref; each message identifies the actual reviewed head commit. This retains the existing restricted report approach rather than exposing detailed findings in public PR comments. Scoped synthetic storage/public-annotation probes run before paid inference; they are not a universal confidentiality guarantee.

High-confidence High/Critical findings fail the Actions check. Incomplete reviews and delivery errors also fail. A successful run is not proof of absence of vulnerabilities. **A failing check does not prohibit merging or direct pushes unless branch rules separately require it.** This change does not alter those rules, create fixes automatically, or grant ChatGPT's connector access to restricted Code scanning APIs. Authorized local development agents can use GitHub's Code scanning API; this change does not export existing private findings to public surfaces.

## Installation state

Check the integration PR and actual run links for verified deployments. Do not treat presence of this reusable workflow as installation in every repository. `muse-agent-bridge`'s integration stays in draft until its missing caller credential is resolved and a real AI run succeeds.

Reference: https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows
