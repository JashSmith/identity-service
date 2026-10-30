---
name: git-flow-mr
description: Branching, commit and merge-request workflow for this repository (Git flow, one MR per step, owner approval between steps). Use before creating a branch, committing, pushing or opening a PR/MR.
---

# Git flow and merge requests

The owner reviews every change as its own MR/PR and approves it before the next step starts.

## Branches
- `master`: released code. `develop`: integration branch, the default PR target.
- Work branches start from `develop` (or from the previous unmerged step when stacking):
  `feature/<topic>`, `fix/<topic>`, `refactor/<topic>`, `chore/<topic>`, `docs/<topic>`.
- `release/<x.y>` and `hotfix/<topic>` follow standard Git flow from `develop` / `master`.
- Never commit straight to `master` or `develop`.

## One step = one branch = one MR
1. Keep the change focused: one concern per branch (cleanup, rename, infra, one feature).
2. Build and test before committing: `dotnet build IdentityService.slnx` and
   `dotnet test IdentityService.slnx`. For runtime changes also use the `run-stack` skill.
3. Commit with Conventional Commits in English (`feat:`, `fix:`, `refactor:`, `chore:`, `docs:`,
   `test:`). The body explains why, lists breaking changes and states how it was verified.
4. Push: `git push -u origin <branch>`.
5. Open the PR into `develop` with `gh pr create --base develop` when `gh` is authenticated.
   Otherwise give the owner the link GitHub prints
   (`https://github.com/JashSmith/identity-service/pull/new/<branch>`).
6. When a step depends on an unmerged step, branch from it (stacked) and tell the owner the
   merge order. After the base merges, retarget the next PR to `develop`.
7. Stop and wait for the owner's approval before starting the next step.

## Before pushing, check
- No secrets, no generated files (`bin/`, `obj/`, user secrets), no unrelated changes.
- Line endings preserved (the repo mixes CRLF and LF; edit files without rewriting them wholesale).
