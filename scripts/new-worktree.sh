#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <branch-name>" >&2
  exit 1
fi

BRANCH="$1"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="$(dirname "$REPO_ROOT")/CrabTrap-${BRANCH}"

git -C "$REPO_ROOT" worktree add "$TARGET" -B "$BRANCH"

echo "Copying certs..."
cp -r "$REPO_ROOT/certs" "$TARGET/certs"

echo "Copying data..."
mkdir -p "$TARGET/data/credentials"
cp -r "$REPO_ROOT"/data/credentials/* "$TARGET/data/credentials/"

echo "Copying config/gateway.yaml..."
cp "$REPO_ROOT/config/gateway.yaml" "$TARGET/config/gateway.yaml"

echo ""
echo "Worktree ready at: $TARGET"
echo "Run 'make dev' inside the worktree — Docker will assign a free port automatically."
