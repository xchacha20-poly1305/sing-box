#!/usr/bin/env bash
# Run after a cherry-picked commit lands in HEAD:
# regenerate docs/schema.json, amend it into HEAD if it changed, then compile.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if ! output=$(make schema 2>&1); then
	echo "make schema failed:"
	echo "$output" | tail -20
	exit 1
fi

if git diff --quiet -- docs/schema.json; then
	echo "schema unchanged"
else
	git diff --stat -- docs/schema.json
	git add docs/schema.json
	git commit --amend --no-edit -q
	echo "amended schema into $(git log -1 --format='%h %s')"
fi

go build ./cmd/sing-box
echo "build ok"
