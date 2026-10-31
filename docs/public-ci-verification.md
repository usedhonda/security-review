# Public CI verification

This repository uses standard GitHub-hosted runners for public-repository CI.

The `Offline checks` workflow runs unit tests on push and pull requests, without an OpenAI API key or paid inference. The `Security review pilot` is a separate, manual workflow and is never triggered by this documentation update.

This documentation commit also provides a first post-publication check that ordinary CI jobs can start on GitHub-hosted runners. Check the resulting workflow conclusion before assuming the runner is available.
