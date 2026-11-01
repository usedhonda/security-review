# GitHub App + Cloudflare Worker pilot (not yet activated)

Architecture: GitHub App (all repositories) -> signed webhook -> Cloudflare Worker -> repository_dispatch in central usedhonda/security-review -> existing bounded OpenAI review -> central Code scanning. No OpenAI key in individual repositories.

This is a **proposed integration**, not a deployed App. Until GitHub App installation and Cloudflare secret configuration, it cannot receive events. It does NOT add required checks in target repositories, automatic fixes, or native target-PR results. Existing per-repo pilot and manual account review are unchanged.

## One-time setup
1. Create a private GitHub App owned by usedhonda, enable webhook events **Pull requests** and **Pushes**. Set repository permissions Contents **read/write** (required to dispatch into central repo), Metadata **read**, Pull requests **read**. Install to **All repositories** and ensure central security-review is included. GitHub App private key and webhook secret must not be committed.
2. Create a free Cloudflare D1 database; execute db/schema.sql once and bind it to the Worker as `DEDUP`. Deploy worker/worker.mjs to a workers.dev route. Set Worker secrets `APP_PRIVATE_KEY`, `APP_ID`, `WEBHOOK_SECRET`, plus plain vars `GITHUB_OWNER=usedhonda`, `CENTRAL_REPO=usedhonda/security-review`.
3. Configure the GitHub App webhook URL to the actual Worker URL and the same webhook secret. Verify ping; then make one owner-authored PR in a noncentral public repository. Verify the central `GitHub App AI security review` Action and the central Code scanning inbox.
4. Confirm Worker D1 dedup by redelivering exactly the same webhook; ensure there is no second paid run. Check actual OpenAI usage and free-tier consumption before enabling routine use.

## Security boundaries
* Worker verifies SHA-256 webhook signature before parsing event data. It accepts only owner-authored same-repo PR changes to default branch and pushes to that branch, public nonfork nonarchived repositories. It restricts destination to the central repository.
* GitHub App private key stays in Worker secrets, OpenAI key stays in central Actions secrets. D1 delivery IDs prevent duplicate dispatches, but do not provide an account-wide monthly API spending cap. The existing max is USD 0.50 estimated per run; repeated legitimate pushes can still incur charges.
* The central workflow checks repository metadata, full commit IDs and current PR head before spending, downloads blobs without executing source, and uploads to **central** Code scanning only.
* Worker returns HTTP 503 on missing setup or dispatch failure; never silently says a review happened. The GitHub App token is short-lived. Never echo it.
* This initial central-inbox approach does **not** post passing/failing checks in each target repository, block merges or create fixes. That requires another verified App-credential path.

## Files
* `worker/worker.mjs`: signed webhook receiver and GitHub App installation token flow
* `db/schema.sql`: dedup table (Cloudflare D1)
* `scripts/app_dispatch.py`: central Actions dispatch handler
* `.github/workflows/app-review.yml`: dispatcher workflow

No GitHub App, D1 resource, API key or Worker has been created by this PR.
