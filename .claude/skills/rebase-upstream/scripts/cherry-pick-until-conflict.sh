#!/usr/bin/env bash
# Cherry-pick commits from stdin, oldest first, one full hash per line.
# Blank lines and lines starting with # are ignored.
# Requires git 2.45+ (--empty=drop).
#
# For each commit that changes HEAD, run after-commit.sh.
# If HEAD does not move, the pick was empty: do not run after-commit.sh,
# or it would amend the previous commit.
#
# Stop at the first conflict or after-commit failure and leave the repo
# in that state. Print one status line per commit to stdout:
#   OK <orig> <new> <subject>
#   EMPTY <orig> <subject>
#   CONFLICT <orig> <subject>
#   AFTER-FAIL <orig> <new> <subject>
# then ALL-DONE on a full run.
# Exit 0 when every commit was picked or dropped, 3 on conflict, 2 on
# after-commit failure, 1 on usage or git errors.
set -u
cd "$(git rev-parse --show-toplevel)"
S="$(cd "$(dirname "$0")" && pwd)/after-commit.sh"

if [[ $# -ne 0 ]]; then
	echo "pass commit hashes on stdin, not as arguments" >&2
	exit 1
fi

while read -r c; do
	[[ -z "$c" || "$c" == \#* ]] && continue
	subj=$(git log -1 --format=%s "$c") || exit 1
	before=$(git rev-parse HEAD)
	if ! git cherry-pick --empty=drop "$c"; then
		echo "CONFLICT $c $subj"
		git status --short
		exit 3
	fi
	after=$(git rev-parse HEAD)
	if [[ "$before" == "$after" ]]; then
		echo "EMPTY $c $subj"
		continue
	fi
	if ! "$S"; then
		echo "AFTER-FAIL $c $(git rev-parse HEAD) $subj"
		exit 2
	fi
	echo "OK $c $(git rev-parse HEAD) $subj"
done
echo "ALL-DONE"
exit 0
