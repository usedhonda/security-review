#!/usr/bin/env bash
# Run locally on your trusted Mac/Linux machine. Never on GitHub Actions.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  echo "Create the recovery identity locally, not on GitHub Actions." >&2
  exit 1
fi
if ! command -v age-keygen >/dev/null 2>&1; then
  echo "Install age from its official distribution first (macOS/Homebrew: brew install age)." >&2
  exit 1
fi
umask 077
keydir="$HOME/.config/security-review"
identity="$keydir/identity.txt"
mkdir -p "$keydir"
if [[ -e "$identity" || -L "$identity" ]]; then
  echo "An identity already exists. It was not replaced. Back it up safely; never paste it into chat or GitHub." >&2
else
  age-keygen -o "$identity"
fi
echo "Copy ONLY this public key into the repository secret REVIEW_AGE_RECIPIENT:"
age-keygen -y "$identity"
echo "Keep identity.txt local and back it up securely. Do not upload or share it."
