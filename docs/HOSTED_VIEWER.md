# Web entry point

The current GitHub Pages homepage is a static launcher with two buttons: **start the account review** and **read the central Security inbox**. It does not collect keys, upload ZIPs, decrypt reports, store data in the browser or call an API. Keys and report files are no longer part of the normal web flow.

The start button opens `.github/workflows/account-review.yml` in this repository's GitHub Actions. Use `Run workflow` with the default branch; there are no repository-selection, recovery-confirmation or model inputs. The result button opens this central repository's `security/code-scanning` page, subject to GitHub authentication and permissions.

When forked, the Pages build derives both links from `GITHUB_REPOSITORY`. A fork owner uses their own OpenAI repository Secret, Actions and Security inbox. Viewing the upstream website does not grant access to the upstream owner's API key or paid runs.

To host the launcher, choose Settings → Pages → Source → GitHub Actions and let `Report viewer website` deploy the reviewed default branch. Pages is optional: both GitHub Actions and Security links work without it.

For existing encrypted reports only, the separate [offline helper](BROWSER_HELPER.md) and [age recovery documentation](ENCRYPTED_RECOVERY.md) are retained. The former hosted key/ZIP reader has been replaced rather than forcing users through its setup.

See [ACCOUNT_REVIEW.md](ACCOUNT_REVIEW.md) for automated selection, per-run cost bounds, result visibility and limitations. Actual paid review completion is still a release gate.
