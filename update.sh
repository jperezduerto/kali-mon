#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if [[ -n "$(git -C "$repo_dir" status --porcelain)" ]]; then
  echo "Refusing to update: local changes exist in $repo_dir" >&2
  echo "Commit, stash, or discard them first." >&2
  exit 1
fi

git -C "$repo_dir" pull --ff-only origin main
npm --prefix "$repo_dir" ci --omit=dev
echo "kali-mon is up to date."
