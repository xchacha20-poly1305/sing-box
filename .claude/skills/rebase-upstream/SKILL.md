---
name: rebase-upstream
description: Rebase this sing-box fork's own commits onto a newer upstream (reF1nd/sing-box or SagerNet/sing-box) by cherry-picking them one at a time, regenerating docs/schema.json for every commit, and resolving conflicts — including semantic conflicts where upstream changed an API. Use this whenever the user asks to rebase / 变基 / 重新基于上游, sync with upstream, update to the latest reF1nd or sagernet branch, cherry-pick a range of commits (e.g. `A^..B`), or continue / resolve conflicts in an ongoing cherry-pick or rebase in this repository, even if they don't say "rebase" explicitly.
---

# Rebase onto upstream

This repository is a fork that carries its own commits (mostly by 安容 / xchacha20-poly1305) on top of an upstream branch. Rebasing means replaying those commits onto a newer upstream so each one still means what it originally meant.

## Remotes and picking the upstream

- `reF1nd` — https://github.com/reF1nd/sing-box (branches `reF1nd-testing`, `reF1nd-testing-next`). This is normally the direct upstream.
- `sagernet` — https://github.com/SagerNet/sing-box (`dev-next`, `testing`), upstream of reF1nd.
- `origin` — the user's own fork.

If the user didn't name the target, find the branch the current work is based on: the remote branch with the fewest commits between `git merge-base HEAD <branch>` and `HEAD`. Tell the user which one you picked.

## Which commits to replay

`git log --reverse <merge-base>..<old-tip>` is the old range, not the replay list. Upstream rebases that range too, so most of those commits are already on the new tip under new hashes.

1. `git cherry <upstream> <old-tip>` marks an identical patch `-` and anything else `+`. Drop every `-`.
2. Replay `+` commits authored by this fork (安容 / xchacha20-poly1305).
3. A `+` commit by anyone else usually has a rewritten copy on the new upstream (same subject, different patch). Search `git log <upstream> --grep=<subject> --fixed-strings` and a distinctive added line with `git grep` on the upstream tip. If the change is there, drop the commit. If it is not, ask before replaying it. Replaying it on top of the rewritten copy duplicates or reverts upstream.

`git cherry-pick --empty=drop` also drops a commit whose change is already in the tree. If `HEAD` does not move, do not run `after-commit.sh`. It would amend the previous commit.

## Workflow

1. `git fetch reF1nd && git fetch sagernet`. `git fetch reF1nd sagernet` does not fetch both remotes; git reads `sagernet` as a refspec of `reF1nd`.
2. Point a local backup branch at the old tip, then create or reset the working branch from the new upstream tip. `git checkout -B <branch> <upstream>` also sets that branch's upstream to `<upstream>`; point it back with `git branch --set-upstream-to=origin/<branch>`. Don't reset a branch that has unpushed work you haven't looked at; ask first.
3. Cherry-pick the commits from "Which commits to replay" **one at a time, oldest first**, not as a single range. Picking one at a time lets you regenerate the schema and compile after each commit, so every commit in the result is a valid state. That keeps `git bisect` working and makes later rebases easier.
4. After each commit lands (cleanly or after resolving), run `scripts/after-commit.sh` from this skill's directory. It runs `make schema`, amends the commit if `docs/schema.json` changed, and runs `go build ./cmd/sing-box`.
5. If a commit adds or changes code behind a build tag (`//go:build with_xxx`, e.g. `include/easyconnect.go`), also build those packages with that tag, and `go vet -tags <tag>` them when they have tests. See Verification.
6. At the end, report per commit: new hash, original hash, and what you did (clean / how you resolved it / what you adapted).

Run a batch until the first conflict or failure. Pass the filtered hashes, oldest first, on stdin:

```bash
.claude/skills/rebase-upstream/scripts/cherry-pick-until-conflict.sh < hashes.txt
```

The script prints `OK`, `EMPTY`, `CONFLICT`, or `AFTER-FAIL`, then `ALL-DONE` if it finishes. It stops on conflict (exit 3) or an `after-commit.sh` failure (exit 2) and leaves the repo there. Resume with only the hashes not yet picked.

After resolving a conflict: `git add <files> && GIT_EDITOR=true git cherry-pick --continue`, then run `after-commit.sh` for that commit, then run the script again with the remaining hashes.

## Regenerate the schema for every commit

`docs/schema.json` is generated from the option structs (`make schema`). Never hand-merge its conflict markers:

1. `git checkout --ours docs/schema.json` (or `--theirs`; it doesn't matter),
2. finish resolving the Go files,
3. `make schema`.

Then sanity-check the diff against `HEAD`. It should contain only what the original commit's schema diff contained (`git show <orig> -- docs/schema.json`). An extra difference is usually stale upstream schema. The other direction happens too: the original commit's schema diff may delete fields that the current option structs still have (a stale deletion, such as `udp_gso`). Regeneration puts them back, and the new commit may not touch `docs/schema.json` at all. Both are expected. Mention them in the report.

## Resolving conflicts

Reproduce the original commit's intent on top of the new upstream code. Don't pick one side wholesale. For each conflict:

- Read `git show <orig> -- <file>` to see exactly what the commit changed, and `git diff <file>` to see the conflict.
- Keep upstream's version of everything the commit didn't touch (renamed types, refactored functions, bumped versions), then re-apply only the commit's change to it.
- If the original intent is unclear, or both readings are plausible, ask the user instead of guessing.

Common cases in this repo:

- **Option struct field alignment.** Upstream changed one field's type, gofmt re-aligned the whole block, and the conflict covers every line. Take upstream's block and insert only the fork's new fields. This is why rule 2 below exists.
- **`go.mod` / `go.sum`.** Keep upstream's versions and `replace` targets, and add only the dependency the commit introduced, with its `go.sum` lines. If the commit only moves an existing fork `replace` into the `replace` block, keep that replace. When the conflict includes a `replace` this fork owns (the right-hand side is a fork repo, not an upstream `reF1nd` or `sagernet` pin), fetch that repo and compare the pinned commit with its HEAD. If HEAD is a newer descendant, bump the replace to HEAD in this commit and mention it in the report. If HEAD does not contain the pinned commit, leave the pin and say so. `go get <fork-path>@<commit>` fails when the fork's `go.mod` still declares the upstream module path; the error prints the pseudo-version. Set it with `go mod edit -replace=<module>=<fork>@<pseudo>` and `go get <module>@<pseudo>`. The conflict is often an upstream version bump on a neighboring line (for example `sing-tun`). Taking upstream's hunk and dropping the moved line removes a replace an earlier fork commit added. Check with `go mod tidy -diff` (no output means consistent). Don't run `go mod tidy` to write changes, because it can change unrelated lines.
- **Moved code.** Upstream may have moved a statement (e.g. `defer resp.Body.Close()` moved earlier). Don't re-add it where the commit had it.
- **Imports.** After resolving, remove imports the merged code no longer uses and keep ones it still needs. The compiler will report both cases.

## Semantic conflicts

A commit can apply cleanly, or resolve textually, and still be wrong because upstream changed an API it uses. Examples seen here: upstream's scoped-lifecycle refactor changed `Start(stage)` to `Start(stage, *adapter.Scope)`, removed `Close()`, and removed `adapter.Start(...)`. The fork's endpoints and helpers stopped compiling. Another: a `//go:build with_quic` test still called `ListenHTTP3` without the congestion-control argument upstream had added. `go build ./cmd/sing-box` stayed green because it skips tests and that file's tag. `go vet -tags with_quic` on the package compiled the test and failed.

To port such code:

1. Find the upstream commit that changed the API (`git log -S'<new symbol>' -- adapter/`).
2. Find the closest upstream component it migrated and copy that pattern, e.g. port `protocol/easyconnect` the way upstream ported `protocol/openconnect`.
3. Fold the port into the fork commit that introduced the code, so that commit compiles on its own.
4. If the old function is gone and the replacement is unexported, add a small exported method in the owning package instead of reaching into internals. Name it in the report so the user can review it.

## Fork conventions

1. **Regenerate the schema for every commit** (above).
2. **Separate the fork's options from upstream's with a blank line.** When adding fields to an option struct that upstream also maintains, put them in their own group, after a blank line:

   ```go
   type OutboundTLSOptions struct {
   	Enabled    bool   `json:"enabled,omitempty"`
   	ServerName string `json:"server_name,omitempty"`
   	// ... upstream fields ...
   	Reality *OutboundRealityOptions `json:"reality,omitempty"`

   	JLS *OutboundJLSOptions `json:"jls,omitempty"`
   }
   ```

   gofmt aligns struct tags across consecutive lines only. With a blank line between the groups, a long fork field name doesn't re-indent upstream's lines, and upstream re-aligning its block doesn't touch the fork's lines. Without the blank line, every type change upstream makes conflicts with the whole block. Use this layout when writing new options, when resolving a conflict in such a block, and when amending alignment into the commit that added the field (see Verification).
3. **Document fork features in `README.md`, not in `docs/`.** Unless the user explicitly asks, don't add or edit pages under `docs/` (sing-box's mkdocs documentation) for fork features. Add or update a section in `README.md` instead, matching the existing style: a JSON config example, followed by a short explanation. Upstream rewrites `docs/` often, and the README is the fork's own file, so this avoids recurring conflicts. If an original commit already touched `docs/`, reproduce it as it was. This rule is about new documentation you write.

## Verification

- Verify by compiling: `go build ./cmd/sing-box`, the touched packages, and their build tags. `go build` does not compile `*_test.go`. When a commit adds or changes tests in the main module, `go vet` that package with the same build tags so the tests typecheck. Don't run `go test`.
- Don't modify the separate `test/` Go module, even if a picked commit includes files there. Keep those files as they were picked.
- `go build ./...` has unrelated link failures (e.g. `experimental/boxdd` / `oomprofile`). Don't treat them as caused by the rebase. Build the specific packages instead.
- Before finishing, run `gofmt -l` on every `.go` file in `<new-upstream>..HEAD`, not only files you edited by hand. A clean pick can still carry the original commit's misalignment. Amend the fix into the commit that introduced the field (`git commit --fixup=<commit>`, then `GIT_SEQUENCE_EDITOR=true git rebase -i --autosquash <parent>`). Later commits replay and keep their messages. If the fork field's name or type is longer than the upstream fields in that group, put it in its own group after a blank line (convention 2) so gofmt does not reindent upstream. If it is not longer, gofmt-align it with the existing group and do not add a blank line.

## Commit hygiene

- Keep each original commit's message and authorship. `git cherry-pick --continue` and `git commit --amend --no-edit` do.
- Don't push. Don't force-update a remote branch unless asked.
